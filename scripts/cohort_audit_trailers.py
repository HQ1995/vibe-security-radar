#!/usr/bin/env python3
"""Census every authorship identity in the corpus, and label what Source v3 sees.

The cohort study's exposure variable is "this commit carries an AI attribution",
so a gap in the identity policy is not a missing feature — it is measurement
error in the independent variable, and it is not random.  A sample of 400 clones
showed Claude Code being detected (8,106 commits) while GitHub's own Copilot
coding agent, Copilot Autofix, Roo Code, Devin, ``claude[bot]`` and Gemini were
missed (~2,483 commits), which would have made the "AI" arm a single-vendor
sample wearing a general label.

This script exists so the policy is repaired from a full-population count rather
than from whichever identities happened to land in that sample.  It reads local
git history only — no API calls, no network, no writes to any clone.

Output is deliberately raw: every identity and its count is written out, and the
AI-candidate list is a *triage* view over that raw data, never a filter applied
before counting.  A vendor nobody has thought of yet is still in the artifact.

Usage::

    uv run --project cve-analyzer python scripts/cohort_audit_trailers.py
    uv run --project cve-analyzer python scripts/cohort_audit_trailers.py --sample 400
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import data_refresh_paths

from cohort.repos import discover_local_clones

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent

DEFAULT_WORKERS = 24
DEFAULT_SINCE = "2025-01-01"
DEFAULT_MIN_COUNT = 3
DEFAULT_VOLUME_FLOOR = 20
DEFAULT_REPO_TIMEOUT = 300
COHORT_STATE_RELATIVE = Path(data_refresh_paths.PROJECT_RUNTIME_DIRECTORY) / "state" / "cohort-v1"

_RECORD_SEP = "\x1e"
_FIELD_SEP = "\x1f"
_LOG_FORMAT = f"{_RECORD_SEP}%an <%ae>{_FIELD_SEP}%ad{_FIELD_SEP}%B"

# A git trailer is ``Key: value``.  Every key is counted so the artifact can
# answer "which trailer keys carry attribution" from data instead of from a
# guess, but identities are only extracted from the attribution-bearing keys.
_TRAILER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]*(\S.*?)[ \t]*$")
_MAILBOX_RE = re.compile(r"^(?P<name>.*?)[ \t]*<(?P<email>[^<>]+)>$")

ATTRIBUTION_KEYS = frozenset(
    {
        "co-authored-by",
        "coauthored-by",
        "co-developed-by",
        "assisted-by",
        "ai-assisted-by",
        "generated-by",
        "written-by",
        "authored-by",
    }
)

# Known model families.  Short and stable *by design*: harness names are
# unbounded (`avom-custom-harness`, `kres`, `sashiko`, `gkh_clanker_2000` were
# all found in real trailers and none could have been guessed), but the model
# behind them comes from a handful of vendors.  Matching the model rather than
# the harness is what makes the census robust to tools nobody has heard of yet.
MODEL_FAMILY_RE = re.compile(
    r"\b(?:claude|gpt|codex|gemini|glm|deepseek|qwen|llama|mistral|kimi|grok|"
    r"phi|command-r|nova|sonnet|opus|haiku|o[34](?:-mini)?)\b[-.\d]*",
    re.IGNORECASE,
)

# A GitHub App/bot account.  Structural, not a vocabulary: any automation gets
# this suffix whether or not it is an AI and whether or not anyone has heard of it.
BOT_ACCOUNT_RE = re.compile(r"\[bot\]|\bbot\b", re.IGNORECASE)


def _tool_vocabulary() -> re.Pattern[str]:
    """Build the triage vocabulary from ``AiTool``, not from a hand-written list.

    The gap this whole script exists to close was created by a hand-maintained
    identity list falling behind reality.  Writing a *second* hand-maintained
    list here would reproduce that failure one layer up, so the vocabulary is
    derived from the enum the rest of the codebase already keeps current
    (63 tools), with each ``snake_case`` name also accepted spelled with a
    space, a hyphen, a dot or nothing between its words.
    """

    from cve_analyzer.models import AiTool

    alternatives: set[str] = set()
    for tool in AiTool:
        words = [word for word in str(tool.value).split("_") if word and word != "ai"]
        if not words:
            continue
        # "google_gemini" also has to match a bare "gemini": vendor prefixes are
        # dropped in real trailers about as often as they are kept.
        for chosen in ({tuple(words), tuple(words[1:])} if len(words) > 1 else {tuple(words)}):
            if not chosen or (len(chosen) == 1 and len(chosen[0]) < 3):
                continue
            alternatives.add(r"[ _.\-]?".join(re.escape(word) for word in chosen))
    ordered = sorted(alternatives, key=len, reverse=True)
    return re.compile(r"(?<![a-z0-9])(?:" + "|".join(ordered) + r")(?![a-z0-9])", re.IGNORECASE)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument(
        "--since",
        default=DEFAULT_SINCE,
        help=f"earliest authored date to census (default: {DEFAULT_SINCE})",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=0,
        help="census a deterministic sample of N repositories (0 = all)",
    )
    parser.add_argument(
        "--min-count",
        type=int,
        default=DEFAULT_MIN_COUNT,
        help=(
            "identities below this count are aggregated away in the artifact"
            f" (default: {DEFAULT_MIN_COUNT}); AI candidates are kept regardless"
        ),
    )
    parser.add_argument(
        "--repo-timeout",
        type=int,
        default=DEFAULT_REPO_TIMEOUT,
        help=f"per-repository git log timeout in seconds (default: {DEFAULT_REPO_TIMEOUT})",
    )
    parser.add_argument(
        "--volume-floor",
        type=int,
        default=DEFAULT_VOLUME_FLOOR,
        help=(
            "list every unmatched identity at or above this commit count regardless"
            f" of any heuristic (default: {DEFAULT_VOLUME_FLOOR})"
        ),
    )
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args(argv)


def _split_mailbox(value: str) -> tuple[str, str] | None:
    """Split ``Name <email>`` into its parts, or ``None`` when it is not one."""

    match = _MAILBOX_RE.match(value)
    if match is None:
        return None
    email = match.group("email").strip()
    if not email or " " in email:
        return None
    return match.group("name").strip(), email


class RepoCensus:
    """Per-repository counts, kept small so 8,900 of them can be merged."""

    __slots__ = ("authors", "trailer_keys", "trailer_identities", "latest_date", "commits")

    def __init__(self) -> None:
        self.authors: Counter[str] = Counter()
        self.trailer_keys: Counter[str] = Counter()
        self.trailer_identities: Counter[str] = Counter()
        self.latest_date: dict[str, str] = {}
        self.commits = 0

    def note_date(self, identity: str, day: str) -> None:
        # The matcher gates each identity on an earliest plausible date, so the
        # probe has to use a date the identity was actually seen on — otherwise
        # a real signal looks like a policy miss.
        if day and self.latest_date.get(identity, "") < day:
            self.latest_date[identity] = day


def _census_one(repo_path: Path, since: str, timeout: int) -> tuple[RepoCensus, str]:
    """Census one repository.  Returns (counts, error) — never raises."""

    census = RepoCensus()
    command = [
        "git",
        "-C",
        str(repo_path),
        "log",
        "--all",
        f"--since={since}",
        "--date=short",
        f"--format={_LOG_FORMAT}",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return census, "timeout"
    except (OSError, subprocess.SubprocessError) as exc:
        return census, f"exception:{type(exc).__name__}"
    if completed.returncode != 0:
        return census, f"git_log_nonzero:{completed.returncode}"

    for record in (completed.stdout or "").split(_RECORD_SEP):
        if not record.strip():
            continue
        fields = record.split(_FIELD_SEP, 2)
        if len(fields) < 3:
            continue
        author, day, message = fields[0].strip(), fields[1].strip(), fields[2]
        census.commits += 1
        if author:
            census.authors[author] += 1
            census.note_date(author, day)
        # A trailer identity is counted once per commit: a PR that names the
        # same agent in three sub-commit trailers is one exposed commit, and
        # counting it three times would overstate that agent's prevalence.
        seen: set[str] = set()
        for line in message.splitlines():
            match = _TRAILER_RE.match(line)
            if match is None:
                continue
            key = match.group(1).casefold()
            census.trailer_keys[key] += 1
            if key not in ATTRIBUTION_KEYS:
                continue
            identity = match.group(2).strip()
            token = f"{key}\x00{identity}"
            if token in seen:
                continue
            seen.add(token)
            census.trailer_identities[token] += 1
            census.note_date(token, day)
    return census, ""


def _source_v3_probe() -> Any:
    """Return ``(identity, day, is_trailer) -> matched tools``, using the real matcher.

    Labelling identities by hand is how the current gap was created.  This asks
    ``source_matcher`` itself, so the artifact's verdict column cannot drift
    from what the pipeline actually detects.
    """

    from cve_analyzer.models import CommitInfo
    from cve_analyzer.source_matcher import matches_for_commit

    def probe(identity: str, day: str, trailer_key: str) -> list[str]:
        parts = _split_mailbox(identity)
        name, email = parts if parts else (identity, "")
        if trailer_key:
            # Probe with the identity's *own* trailer key.  Testing every
            # identity as Co-authored-by would report the whole
            # ``Assisted-by: Tool:model`` convention as missed even where
            # explicit-attribution matching already covers it.
            commit = CommitInfo(
                sha="0" * 40,
                author_name="Probe Human",
                author_email="probe@example.invalid",
                committer_name="Probe Human",
                committer_email="probe@example.invalid",
                message=f"probe subject\n\n{trailer_key}: {identity}\n",
                authored_date=day or "2026-01-01",
            )
        else:
            commit = CommitInfo(
                sha="0" * 40,
                author_name=name,
                author_email=email,
                committer_name=name,
                committer_email=email,
                message="probe subject\n",
                authored_date=day or "2026-01-01",
            )
        return sorted({match.tool for match in matches_for_commit(commit)})

    return probe


def _triage_reasons(identity: str, trailer_key: str, vocabulary: re.Pattern[str]) -> list[str]:
    """Why this identity deserves review.  Four independent rules, three of which
    need no vendor vocabulary at all — so a tool nobody has heard of still surfaces.
    """

    reasons: list[str] = []
    if vocabulary.search(identity):
        reasons.append("known_tool_name")
    if MODEL_FAMILY_RE.search(identity):
        reasons.append("model_family")
    if BOT_ACCOUNT_RE.search(identity):
        reasons.append("bot_account")
    # `Assisted-by:` / `Generated-by:` exist in order to credit non-human help.
    # Every identity under one is worth a look on the strength of the key alone.
    if trailer_key and trailer_key != "co-authored-by" and trailer_key != "coauthored-by":
        reasons.append(f"attribution_key:{trailer_key}")
    return reasons


def _rank(
    counts: Counter[str],
    latest: dict[str, str],
    probe: Any,
    vocabulary: re.Pattern[str],
    *,
    is_trailer: bool,
    min_count: int,
    volume_floor: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """Rank identities; split off both heuristic and volume-based review lists."""

    ranked: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    by_volume: list[dict[str, Any]] = []
    totals = Counter({"identities": 0, "commits": 0, "below_min_count": 0})
    for token, count in counts.most_common():
        key, _, identity = token.partition("\x00") if is_trailer else ("", "", token)
        day = latest.get(token, "")
        tools = probe(identity, day, key)
        reasons = _triage_reasons(identity, key, vocabulary)
        totals["identities"] += 1
        totals["commits"] += count
        row: dict[str, Any] = {
            "identity": identity,
            "commits": count,
            "latest_authored_day": day,
            "source_v3_tools": tools,
        }
        if is_trailer:
            row["trailer_key"] = key
        if not tools:
            if reasons:
                unmatched.append({**row, "triage_reasons": reasons})
            # The vocabulary-free safety net.  Any unmatched identity above the
            # volume floor is listed whether or not a heuristic liked it, so a
            # high-volume vendor cannot hide behind a gap in the word list —
            # only genuinely rare identities fall off the end.
            if count >= volume_floor:
                by_volume.append({**row, "triage_reasons": reasons})
        if count < min_count:
            totals["below_min_count"] += 1
            continue
        ranked.append(row)
    return ranked, unmatched, by_volume, dict(totals)


def _print_report(summary: dict[str, Any]) -> None:
    print()
    print("=" * 78)
    print("Authorship identity census")
    print("=" * 78)
    print(f"  repositories censused : {summary['repositories_censused']}")
    print(f"  repositories failed   : {summary['repositories_failed']}")
    print(f"  commits read          : {summary['commits_read']:,}")
    print(f"  elapsed               : {summary['elapsed_seconds']}s")
    for label, key in (
        ("trailer identities", "trailer_identity_totals"),
        ("author identities", "author_identity_totals"),
    ):
        totals = summary[key]
        print(
            f"  {label:<21}: {totals['identities']:,} distinct,"
            f" {totals['commits']:,} commits"
        )
    print("\n  top attribution trailer keys:")
    for key, count in list(summary["trailer_key_counts"].items())[:10]:
        print(f"    {key:<24} {count:>9,}")
    for label, key in (
        ("TRAILER identities Source v3 misses — triaged", "unmatched_trailer_candidates"),
        ("AUTHOR identities Source v3 misses — triaged", "unmatched_author_candidates"),
        (
            f"TRAILER identities Source v3 misses — ALL >= {summary['volume_floor']} commits,"
            " no heuristic applied",
            "unmatched_trailer_by_volume",
        ),
        (
            f"AUTHOR identities Source v3 misses — ALL >= {summary['volume_floor']} commits,"
            " no heuristic applied",
            "unmatched_author_by_volume",
        ),
    ):
        rows = summary[key]
        print(f"\n  {label} ({len(rows)} total, top 40):")
        for row in rows[:40]:
            reasons = ",".join(row.get("triage_reasons") or []) or "-"
            print(f"    {row['commits']:>7,}  {row['identity'][:58]:<58} {reasons[:30]}")
    if summary["failures"]:
        print("\n  failures (top 10):")
        for entry in summary["failures"][:10]:
            print(f"    {entry['error']:<24} {entry['repo_path']}")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workers = max(1, args.workers)
    os.environ.setdefault("CVE_GIT_CONCURRENCY", str(workers))
    os.environ.setdefault("CVE_ANALYZER_FROZEN_LOCAL_SOURCES", "1")

    probe = _source_v3_probe()

    print("Discovering local clones...", flush=True)
    repositories, unresolved = discover_local_clones(_REPO_ROOT)
    targets = sorted(repositories.items())
    if args.sample > 0:
        # Deterministic stride rather than random sampling: reproducible without
        # carrying a seed, and it spreads across the identity-sorted population.
        stride = max(1, len(targets) // args.sample)
        targets = targets[::stride][: args.sample]
    if not targets:
        print("No repositories to census.")
        return 1
    print(
        f"  {len(targets)} repositories to census"
        f" ({len(unresolved)} cache dirs without a usable origin)",
        flush=True,
    )

    authors: Counter[str] = Counter()
    trailer_identities: Counter[str] = Counter()
    trailer_keys: Counter[str] = Counter()
    latest: dict[str, str] = {}
    failures: list[dict[str, str]] = []
    commits_read = 0

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_census_one, path, args.since, args.repo_timeout): (identity, path)
            for identity, path in targets
        }
        for done, future in enumerate(as_completed(futures), start=1):
            identity, path = futures[future]
            census, error = future.result()
            if error:
                failures.append({"repository_identity": identity, "repo_path": str(path), "error": error})
            authors.update(census.authors)
            trailer_identities.update(census.trailer_identities)
            trailer_keys.update(census.trailer_keys)
            for token, day in census.latest_date.items():
                if latest.get(token, "") < day:
                    latest[token] = day
            commits_read += census.commits
            if done % 250 == 0 or done == len(targets):
                print(
                    f"  [{done}/{len(targets)}] {commits_read:,} commits,"
                    f" {len(trailer_identities):,} trailer identities,"
                    f" {len(failures)} failures",
                    flush=True,
                )
    elapsed = time.monotonic() - started

    vocabulary = _tool_vocabulary()
    trailer_ranked, trailer_unmatched, trailer_by_volume, trailer_totals = _rank(
        trailer_identities,
        latest,
        probe,
        vocabulary,
        is_trailer=True,
        min_count=args.min_count,
        volume_floor=args.volume_floor,
    )
    author_ranked, author_unmatched, author_by_volume, author_totals = _rank(
        authors,
        latest,
        probe,
        vocabulary,
        is_trailer=False,
        min_count=args.min_count,
        volume_floor=args.volume_floor,
    )

    summary: dict[str, Any] = {
        "schema_version": 1,
        "artifact_kind": "cohort_trailer_census",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "since": args.since,
        "min_count": args.min_count,
        "elapsed_seconds": round(elapsed, 1),
        "repositories_censused": len(targets),
        "repositories_failed": len(failures),
        "unresolved_cache_dirs": len(unresolved),
        "commits_read": commits_read,
        "trailer_identity_totals": trailer_totals,
        "author_identity_totals": author_totals,
        "trailer_key_counts": dict(trailer_keys.most_common()),
        "volume_floor": args.volume_floor,
        "unmatched_trailer_candidates": trailer_unmatched,
        "unmatched_author_candidates": author_unmatched,
        "unmatched_trailer_by_volume": trailer_by_volume,
        "unmatched_author_by_volume": author_by_volume,
        "trailer_identities": trailer_ranked,
        "author_identities": author_ranked,
        "failures": failures,
    }

    output_dir = args.output_dir or (_REPO_ROOT / COHORT_STATE_RELATIVE)
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = output_dir / f"trailer-census-{stamp}.json"
    path.write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    _print_report(summary)
    print(f"\nWrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
