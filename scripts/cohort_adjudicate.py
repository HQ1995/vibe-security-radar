#!/usr/bin/env python3
"""Adjudicate SZZ links with a small model, and measure whether it can be trusted.

SZZ decides that a commit introduced a defect from line overlap alone: the fix
touched lines this commit last wrote.  That inference breaks in ways no rule can
repair, because the information is not in the diff — a fix can add a guard in
the caller, validate earlier, or repair the same bug somewhere with no line
overlap at all.  Judging those needs reading the code, which is what a model is
for.

The model is used as a *calibrator*, not a labeller.  Labelling all 81,894 units
would be expensive and unnecessary; what the analysis needs is the sensitivity
and specificity of SZZ **per exposure arm**, after which the observed rates can
be corrected for measurement error.  That cost scales with the sample, not the
corpus, so a few hundred calls suffice.

Cheap labels are only worth having if they agree with careful ones, so this
tool's first mode is ``--validate``: run the model over pairs that already carry
a hand verdict and report agreement.  A model that disagrees with human judgment
does not become acceptable by being inexpensive — it makes the calibration wrong
in a way that looks precise.

Usage::

    uv run --project cve-analyzer python scripts/cohort_adjudicate.py --sample 5 --dry-run
    uv run --project cve-analyzer python scripts/cohort_adjudicate.py --validate labels.json
    uv run --project cve-analyzer python scripts/cohort_adjudicate.py --sample 200
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import data_refresh_paths

from cohort.repos import discover_local_clones

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent

DEFAULT_ENDPOINT = "http://127.0.0.1:8317/v1/chat/completions"
DEFAULT_MODEL = "gemini-3.5-flash-lite"
DEFAULT_SAMPLE = 200
DEFAULT_WORKERS = 6
DEFAULT_SEED = 42
DEFAULT_MAX_CALLS = 600
DEFAULT_DIFF_CHARS = 6000
COHORT_STATE_RELATIVE = Path(data_refresh_paths.PROJECT_RUNTIME_DIRECTORY) / "state" / "cohort-v1"

SYSTEM_PROMPT = (
    "You judge whether a software fix repairs a defect that a specific earlier "
    "commit introduced. You are given the earlier commit's change and the later "
    "fix's change. Answer strictly as JSON."
)

# The instruction names the failure modes that motivated the whole pass, because
# the interesting cases are exactly the ones line overlap gets wrong.
USER_TEMPLATE = """\
An automated heuristic (SZZ) claims commit A introduced a defect that commit B fixed,
because B modified lines that A last wrote. Judge whether that claim is correct.

Answer "yes" only if B repairs a genuine defect AND the defective logic came from A.

Answer "no" if any of these apply:
- B is a refactor, rename, reformat, dependency bump, test-only or docs-only change
- B changes those lines for an unrelated reason (new feature, style, config)
- the lines B touched were merely moved or reindented by A, not authored by A
- B repairs a defect that predates A, or one introduced elsewhere

Reply with JSON only: {{"verdict": "yes"|"no"|"unclear", "reason": "<=25 words"}}

## Commit A (claimed to introduce), {a_date}
subject: {a_subject}
```diff
{a_diff}
```

## Commit B (the fix), {b_date}
subject: {b_subject}
```diff
{b_diff}
```
"""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--szz-dir", type=Path, default=None)
    parser.add_argument("--endpoint", default=os.environ.get("COHORT_LLM_ENDPOINT", DEFAULT_ENDPOINT))
    parser.add_argument("--api-key", default=os.environ.get("COHORT_LLM_KEY", "sk-ant-grok-4"))
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--sample", type=int, default=DEFAULT_SAMPLE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument(
        "--max-calls",
        type=int,
        default=DEFAULT_MAX_CALLS,
        help=f"hard ceiling on model calls for one run (default: {DEFAULT_MAX_CALLS})",
    )
    parser.add_argument("--diff-chars", type=int, default=DEFAULT_DIFF_CHARS)
    parser.add_argument(
        "--validate",
        type=Path,
        default=None,
        help="JSON file of hand verdicts; report agreement instead of calibrating",
    )
    parser.add_argument(
        "--emit-worksheet",
        type=Path,
        default=None,
        help="write a sample of pairs for hand adjudication, make no model calls",
    )
    parser.add_argument("--dry-run", action="store_true", help="build prompts, call nothing")
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args(argv)


def _latest_szz_dir() -> Path:
    root = _REPO_ROOT / COHORT_STATE_RELATIVE
    candidates = sorted(p for p in root.glob("szz-*") if (p / "szz.jsonl").is_file())
    if not candidates:
        raise SystemExit(f"no szz run under {root}")
    return candidates[-1]


def _run_git(repo: Path, args: list[str], *, timeout: int = 120) -> str:
    env = dict(os.environ)
    env["GIT_NO_LAZY_FETCH"] = "1"
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _commit_view(repo: Path, sha: str, limit: int) -> tuple[str, str, str]:
    """Return (subject, date, truncated diff) for one commit."""

    head = _run_git(repo, ["show", "--no-patch", "--format=%s%x1f%aI", sha])
    subject, _, authored = head.strip().partition("\x1f")
    diff = _run_git(
        repo, ["show", "--unified=3", "--no-color", "--format=", "--diff-filter=M", sha]
    )
    if len(diff) > limit:
        diff = diff[:limit] + "\n...[truncated]"
    return subject.strip(), authored.strip()[:10], diff.strip()


def _build_pairs(
    szz_dir: Path, sample: int, seed: int, diff_chars: int
) -> list[dict[str, Any]]:
    """Draw a per-arm balanced sample of SZZ-flagged links with their diffs."""

    import random

    units = []
    with (szz_dir / "szz.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            unit = json.loads(line)
            if unit.get("szz_defective") and unit.get("szz_fixes"):
                units.append(unit)
    by_route: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for unit in units:
        by_route[unit.get("route", "?")].append(unit)
    rng = random.Random(seed)
    # Balanced across arms on purpose: the question is whether SZZ behaves
    # differently for AI-authored and assistant-authored changes, and a
    # proportional draw would starve the smaller arms.
    per_arm = max(1, sample // max(1, len(by_route)))
    chosen: list[dict[str, Any]] = []
    for route in sorted(by_route):
        members = by_route[route]
        chosen.extend(rng.sample(members, min(per_arm, len(members))))

    repositories, _unresolved = discover_local_clones(_REPO_ROOT)
    pairs: list[dict[str, Any]] = []
    for unit in chosen:
        repo = repositories.get(unit["repository_identity"])
        if repo is None:
            continue
        fix = unit["szz_fixes"][0]
        a_subject, a_date, a_diff = _commit_view(repo, str(unit["sha"]), diff_chars)
        b_subject, b_date, b_diff = _commit_view(repo, str(fix["fix_sha"]), diff_chars)
        if not a_diff or not b_diff:
            continue
        pairs.append(
            {
                "repository_identity": unit["repository_identity"],
                "route": unit.get("route", "?"),
                "a_sha": unit["sha"],
                "a_subject": a_subject,
                "a_date": a_date,
                "a_diff": a_diff,
                "b_sha": fix["fix_sha"],
                "b_subject": b_subject,
                "b_date": b_date,
                "b_diff": b_diff,
                "path": fix.get("path", ""),
                "days": fix.get("days", ""),
            }
        )
    return pairs


def _call_model(
    pair: dict[str, Any], *, endpoint: str, api_key: str, model: str
) -> dict[str, Any]:
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": USER_TEMPLATE.format(
                    a_date=pair["a_date"],
                    a_subject=pair["a_subject"],
                    a_diff=pair["a_diff"],
                    b_date=pair["b_date"],
                    b_subject=pair["b_subject"],
                    b_diff=pair["b_diff"],
                ),
            },
        ],
        "max_tokens": 300,
        "temperature": 0,
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {"verdict": "error", "reason": f"{type(exc).__name__}", "usage": {}}
    content = ""
    try:
        content = payload["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        pass
    verdict, reason = "unparsed", content[:120]
    stripped = content.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
    try:
        parsed = json.loads(stripped.strip())
        if isinstance(parsed, dict):
            candidate = str(parsed.get("verdict", "")).strip().lower()
            if candidate in {"yes", "no", "unclear"}:
                verdict = candidate
                reason = str(parsed.get("reason", ""))[:200]
    except ValueError:
        pass
    return {"verdict": verdict, "reason": reason, "usage": payload.get("usage") or {}}


def _agreement(rows: list[dict[str, Any]], key: str = "hand") -> dict[str, Any]:
    """Model-vs-hand agreement, with Cohen's kappa.

    Raw accuracy alone is misleading when one verdict dominates: a model that
    always says "yes" scores well against a mostly-yes reference while carrying
    no information. Kappa is reported because it is the number that would expose
    that.
    """

    paired = [
        (str(r[key]).lower(), str(r["verdict"]).lower())
        for r in rows
        if r.get(key) and r.get("verdict") in {"yes", "no", "unclear"}
    ]
    if not paired:
        return {"n": 0}
    labels = sorted({v for pair in paired for v in pair})
    agree = sum(1 for a, b in paired if a == b)
    n = len(paired)
    expected = sum(
        (sum(1 for a, _ in paired if a == label) / n)
        * (sum(1 for _, b in paired if b == label) / n)
        for label in labels
    )
    observed = agree / n
    kappa = (observed - expected) / (1 - expected) if expected < 1 else 1.0
    matrix: Counter[str] = Counter(f"hand={a},model={b}" for a, b in paired)
    return {
        "n": n,
        "accuracy": round(observed, 4),
        "cohens_kappa": round(kappa, 4),
        "confusion": dict(matrix.most_common()),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    args.szz_dir = args.szz_dir or _latest_szz_dir()
    pairs = _build_pairs(args.szz_dir, args.sample, args.seed, args.diff_chars)
    print(f"built {len(pairs)} adjudicable pairs from {args.szz_dir}", flush=True)
    by_route = Counter(p["route"] for p in pairs)
    print(f"  by route: {dict(by_route)}", flush=True)

    if args.emit_worksheet:
        args.emit_worksheet.parent.mkdir(parents=True, exist_ok=True)
        args.emit_worksheet.write_text(
            json.dumps(pairs, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"wrote worksheet for hand adjudication: {args.emit_worksheet}")
        return 0

    hand: dict[str, str] = {}
    if args.validate:
        hand = {
            str(k): str(v)
            for k, v in json.loads(args.validate.read_text(encoding="utf-8")).items()
        }
        pairs = [p for p in pairs if f"{p['a_sha']}:{p['b_sha']}" in hand]
        print(f"  validating against {len(pairs)} hand-labelled pairs", flush=True)

    if len(pairs) > args.max_calls:
        print(f"  capping at --max-calls {args.max_calls}", flush=True)
        pairs = pairs[: args.max_calls]
    if args.dry_run:
        example = pairs[0] if pairs else None
        if example:
            prompt = USER_TEMPLATE.format(
                a_date=example["a_date"], a_subject=example["a_subject"],
                a_diff=example["a_diff"], b_date=example["b_date"],
                b_subject=example["b_subject"], b_diff=example["b_diff"],
            )
            print(f"\n--- example prompt ({len(prompt):,} chars) ---\n{prompt[:1200]}\n...")
        print(f"\ndry run: would make {len(pairs)} calls to {args.model}")
        return 0

    started = time.monotonic()
    results: list[dict[str, Any]] = []
    usage = Counter()
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {
            executor.submit(
                _call_model, pair, endpoint=args.endpoint, api_key=args.api_key, model=args.model
            ): pair
            for pair in pairs
        }
        for done, future in enumerate(as_completed(futures), start=1):
            pair = futures[future]
            outcome = future.result()
            for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
                usage[field] += int(outcome.get("usage", {}).get(field) or 0)
            row = {
                "repository_identity": pair["repository_identity"],
                "route": pair["route"],
                "a_sha": pair["a_sha"],
                "b_sha": pair["b_sha"],
                "verdict": outcome["verdict"],
                "reason": outcome["reason"],
            }
            if hand:
                row["hand"] = hand.get(f"{pair['a_sha']}:{pair['b_sha']}", "")
            results.append(row)
            if done % 25 == 0 or done == len(futures):
                print(f"  [{done}/{len(futures)}]", flush=True)
    elapsed = time.monotonic() - started

    verdicts = Counter(r["verdict"] for r in results)
    per_route: dict[str, Counter[str]] = defaultdict(Counter)
    for row in results:
        per_route[row["route"]][row["verdict"]] += 1

    summary: dict[str, Any] = {
        "schema_version": 1,
        "artifact_kind": "cohort_szz_adjudication",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "szz_dir": str(args.szz_dir),
        "model": args.model,
        "calls": len(results),
        "elapsed_seconds": round(elapsed, 1),
        "token_usage": dict(usage),
        "verdicts": dict(verdicts.most_common()),
        "verdicts_by_route": {
            route: dict(counts.most_common()) for route, counts in sorted(per_route.items())
        },
        "szz_precision_estimate": {
            route: (
                round(counts["yes"] / max(counts["yes"] + counts["no"], 1), 4)
                if (counts["yes"] + counts["no"])
                else None
            )
            for route, counts in sorted(per_route.items())
        },
    }
    if hand:
        summary["agreement_with_hand_labels"] = _agreement(results)

    output_dir = args.output_dir or (
        _REPO_ROOT
        / COHORT_STATE_RELATIVE
        / f"adjudication-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "verdicts.jsonl").open("w", encoding="utf-8") as handle:
        for row in results:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print("\n" + "=" * 66)
    print(f"SZZ adjudication — {args.model}")
    print("=" * 66)
    print(f"  calls        : {len(results)}   elapsed {summary['elapsed_seconds']}s")
    print(f"  tokens       : {dict(usage)}")
    print(f"  verdicts     : {dict(verdicts.most_common())}")
    print("\n  SZZ precision by exposure route (yes / (yes+no)):")
    for route, value in summary["szz_precision_estimate"].items():
        counts = per_route[route]
        print(f"    {route:<20} {value}   (yes {counts['yes']}, no {counts['no']}, unclear {counts['unclear']})")
    if hand:
        print(f"\n  agreement with hand labels: {summary['agreement_with_hand_labels']}")
    print(f"\nWrote {output_dir / 'verdicts.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
