#!/usr/bin/env python3
"""Link cohort commits to published advisories, the vulnerability outcome.

SZZ answers "did this change introduce a *defect*".  The study was asked about
*vulnerabilities*, and those are not the same question — most SZZ hits are null
dereferences and off-by-ones, not anything exploitable.  This pass keeps the
original question in view by using the one label nobody has to infer: OSV
records, for many advisories, the exact commit that fixed them.

That makes the outcome definition unusually clean.  Where SZZ has to guess
whether a commit is a fix from its wording, here a human security process
already said so, and said which commit.  The mechanism is otherwise identical —
blame the lines the advisory's fix commit repaired, and see whether they belong
to a cohort commit.

The cost is recall, and it is expected to be severe: advisories are rare next to
ordinary bugs, and only some carry a GIT fix reference. That is measured here
rather than assumed, because "too scarce to use" was an assumption the plan made
without checking, and if a few hundred links do exist they are worth more than
tens of thousands of SZZ hits — they answer the question that was actually asked.

Usage::

    uv run --project cve-analyzer python scripts/cohort_advisory_outcomes.py
    uv run --project cve-analyzer python scripts/cohort_advisory_outcomes.py --index-only
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import data_refresh_paths

from cohort.advisories import index_advisory_fixes as _index_advisory_fixes
from cohort.repos import discover_local_clones

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent

DEFAULT_OSV_DIR = Path.home() / ".cache" / "cve-analyzer" / "osv-bulk"
DEFAULT_CUTOFF = "2024-06-01"
DEFAULT_WINDOW_DAYS = 180
DEFAULT_WORKERS = 12
DEFAULT_REPO_TIMEOUT = 600
COHORT_STATE_RELATIVE = Path(data_refresh_paths.PROJECT_RUNTIME_DIRECTORY) / "state" / "cohort-v1"

_RECORD_SEP = "\x1e"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--outcomes-dir", type=Path, default=None)
    parser.add_argument("--osv-dir", type=Path, default=DEFAULT_OSV_DIR)
    parser.add_argument(
        "--cutoff",
        default=DEFAULT_CUTOFF,
        help=(
            "ignore advisories published before this date; earlier than the"
            " cohort window because a fix can post-date its advisory"
        ),
    )
    parser.add_argument("--window-days", type=int, default=DEFAULT_WINDOW_DAYS)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--repo-timeout", type=int, default=DEFAULT_REPO_TIMEOUT)
    parser.add_argument(
        "--index-only",
        action="store_true",
        help="report how many advisory fix commits reach the cohort, then stop",
    )
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args(argv)


def _latest_outcomes_dir() -> Path:
    root = _REPO_ROOT / COHORT_STATE_RELATIVE
    candidates = sorted(p for p in root.glob("outcomes-*") if (p / "outcomes.jsonl").is_file())
    if not candidates:
        raise SystemExit(f"no outcomes run under {root}")
    return candidates[-1]


def _run_git(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["GIT_NO_LAZY_FETCH"] = "1"
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
    )


def _blame_advisory_fix(
    repo_path: Path, fix_sha: str, *, timeout: int
) -> tuple[set[str], str]:
    """Blame the lines an advisory's fix repaired.  Returns (introducers, error)."""

    import cohort_szz as szz

    diffs, unreadable = szz._deleted_line_ranges_batch(
        repo_path, [fix_sha], timeout=timeout
    )
    if unreadable:
        return set(), "unreadable"
    ranges = diffs.get(fix_sha.lower()) or {}
    if not ranges:
        return set(), "no_modified_lines"
    introducers: set[str] = set()
    for path, spans in list(ranges.items())[:64]:
        introducers |= szz._blame_introducers(
            repo_path, fix_sha, path, spans, timeout=timeout
        )
    return introducers, "" if introducers else "blame_empty"


def _link_repository(
    identity: str,
    repo_path: Path,
    fixes: list[dict[str, str]],
    unit_dates: dict[str, str],
    *,
    window_days: int,
    timeout: int,
) -> tuple[dict[str, list[dict[str, str]]], dict[str, Any]]:
    started = time.monotonic()
    hits: dict[str, list[dict[str, str]]] = defaultdict(list)
    reasons: Counter[str] = Counter()
    for entry in fixes:
        introducers, error = _blame_advisory_fix(
            repo_path, entry["fix_sha"], timeout=timeout
        )
        if error:
            reasons[error] += 1
            continue
        for introducer in introducers & set(unit_dates):
            hits[introducer].append(
                {
                    "advisory": entry["advisory"],
                    "fix_sha": entry["fix_sha"],
                    "published": entry["published"],
                }
            )
    return dict(hits), {
        "repository_identity": identity,
        "advisory_fixes": len(fixes),
        "units_hit": len(hits),
        "reasons": dict(reasons),
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    args.outcomes_dir = args.outcomes_dir or _latest_outcomes_dir()

    units: list[dict[str, Any]] = []
    with (args.outcomes_dir / "outcomes.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            units.append(json.loads(line))
    by_repo_units: dict[str, dict[str, str]] = defaultdict(dict)
    for unit in units:
        by_repo_units[unit["repository_identity"]][str(unit["sha"]).lower()] = str(
            unit.get("authored_date") or ""
        )
    cohort_repos = set(by_repo_units)
    print(f"cohort: {len(units):,} units across {len(cohort_repos):,} repositories", flush=True)

    print(f"scanning OSV archives in {args.osv_dir} (cutoff {args.cutoff})...", flush=True)
    started = time.monotonic()
    fixes_by_repo, index_stats = _index_advisory_fixes(
        args.osv_dir, cohort_repos, args.cutoff
    )
    total_fixes = sum(len(v) for v in fixes_by_repo.values())
    print(
        f"  archives {index_stats.get('archives', 0)},"
        f" records {index_stats.get('records', 0):,},"
        f" in window {index_stats.get('in_window', 0):,},"
        f" with a fix commit {index_stats.get('with_fix_commit', 0):,}",
        flush=True,
    )
    print(
        f"  advisory fix commits landing in cohort repos: {total_fixes:,}"
        f" across {len(fixes_by_repo):,} repositories"
        f"  ({time.monotonic() - started:.0f}s)",
        flush=True,
    )
    if args.index_only or not fixes_by_repo:
        if not fixes_by_repo:
            print("\nNo advisory fix commits reach the cohort — the vulnerability")
            print("outcome is not available from OSV for these repositories.")
        return 0

    repositories, _unresolved = discover_local_clones(_REPO_ROOT)
    results: dict[str, list[dict[str, str]]] = {}
    repo_stats: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {}
        for identity, fixes in sorted(fixes_by_repo.items(), key=lambda kv: -len(kv[1])):
            path = repositories.get(identity)
            if path is None:
                repo_stats.append({"repository_identity": identity, "error": "no_local_clone"})
                continue
            futures[
                executor.submit(
                    _link_repository,
                    identity,
                    path,
                    fixes,
                    by_repo_units[identity],
                    window_days=args.window_days,
                    timeout=args.repo_timeout,
                )
            ] = identity
        for done, future in enumerate(as_completed(futures), start=1):
            identity = futures[future]
            try:
                hits, stats = future.result()
            except Exception as exc:  # noqa: BLE001
                hits, stats = {}, {
                    "repository_identity": identity,
                    "error": f"exception:{type(exc).__name__}",
                }
            results.update(hits)
            repo_stats.append(stats)
            if done % 25 == 0 or done == len(futures):
                print(f"  [{done}/{len(futures)}] {identity}", flush=True)

    by_route: dict[str, Counter[str]] = defaultdict(Counter)
    linked: list[dict[str, Any]] = []
    for unit in units:
        hit = results.get(str(unit["sha"]).lower(), [])
        route = unit.get("route", "?")
        by_route[route]["units"] += 1
        if hit:
            by_route[route]["advisory_linked"] += 1
        linked.append({**unit, "advisory_linked": bool(hit), "advisories": hit[:5]})

    summary = {
        "schema_version": 1,
        "artifact_kind": "cohort_advisory_outcomes",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "outcomes_dir": str(args.outcomes_dir),
        "cutoff": args.cutoff,
        "index_stats": index_stats,
        "advisory_fix_commits_in_cohort": total_fixes,
        "repositories_with_advisory_fixes": len(fixes_by_repo),
        "units_linked": sum(1 for unit in linked if unit["advisory_linked"]),
        "by_route": {
            route: dict(counts) for route, counts in sorted(by_route.items())
        },
        "repository_stats": sorted(
            repo_stats, key=lambda s: -int(s.get("advisory_fixes", 0) or 0)
        )[:30],
        "claim_boundary": (
            "an advisory link is a high-precision, very low-recall outcome; absence"
            " of a link is not evidence a change was safe"
        ),
    }

    output_dir = args.output_dir or (
        _REPO_ROOT
        / COHORT_STATE_RELATIVE
        / f"advisory-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "advisory_outcomes.jsonl").open("w", encoding="utf-8") as handle:
        for unit in linked:
            handle.write(json.dumps(unit, sort_keys=True, ensure_ascii=False) + "\n")
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("\n" + "=" * 66)
    print("Cohort advisory (vulnerability) outcomes")
    print("=" * 66)
    print(f"  advisory fix commits in cohort : {total_fixes:,}")
    print(f"  cohort units linked            : {summary['units_linked']:,}")
    for route, counts in summary["by_route"].items():
        print(
            f"    {route:<20} {counts.get('advisory_linked', 0):>5} / {counts['units']:>7,}"
        )
    print(f"\n  {summary['claim_boundary']}")
    print(f"\nWrote {output_dir / 'advisory_outcomes.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
