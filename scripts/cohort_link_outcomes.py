#!/usr/bin/env python3
"""Link cohort units to the outcomes their repository states outright.

This covers the two high-precision outcomes — a later commit reverting the unit,
or naming it in a ``Fixes:`` trailer.  Both are read from local history, cost no
API call and need no blame, so they run over the whole cohort in minutes.  SZZ,
the primary outcome, is a separate and far more expensive pass.

The direction matters for cost.  Rather than asking of each unit "was this ever
reverted", each repository is indexed once — every revert and every ``Fixes:``
trailer it contains — and the cohort is then joined against that index.  Work
scales with the number of repositories, not with the number of units.

Two things this deliberately reports rather than hides:

  * ``Fixes:`` is a project habit, not a convention.  A repository that writes
    it diligently will look buggier than one that does not, which is
    differential ascertainment and would be read as a real effect.  Per
    repository usage rates are in the summary so the analysis can condition on
    them, and this outcome stays tertiary.
  * An outcome landing outside the follow-up window is not an outcome.  Counting
    late reverts for old commits while young commits cannot have any is exactly
    the bias the fixed window exists to prevent.

Usage::

    uv run --project cve-analyzer python scripts/cohort_link_outcomes.py
    uv run --project cve-analyzer python scripts/cohort_link_outcomes.py \
        --repo github.com/mlflow/mlflow
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import data_refresh_paths

from cohort.outcomes import fixes_trailer_shas, reverted_shas
from cohort.populations import (
    PopulationContractError,
    load_exposure_population_contract,
    sha256_file,
)
from cohort.repos import discover_local_clones

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent

DEFAULT_WORKERS = 16
DEFAULT_WINDOW_DAYS = 180
DEFAULT_REPO_TIMEOUT = 600
COHORT_STATE_RELATIVE = Path(data_refresh_paths.PROJECT_RUNTIME_DIRECTORY) / "state" / "cohort-v1"

_RECORD_SEP = "\x1e"
_FIELD_SEP = "\x1f"
_LOG_FORMAT = f"{_RECORD_SEP}%H{_FIELD_SEP}%aI{_FIELD_SEP}%B"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--exposure-dir", type=Path, default=None)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument(
        "--window-days",
        type=int,
        default=DEFAULT_WINDOW_DAYS,
        help=f"outcomes must land within this many days (default: {DEFAULT_WINDOW_DAYS})",
    )
    parser.add_argument("--repo", action="append", default=[])
    parser.add_argument("--limit-repos", type=int, default=0)
    parser.add_argument("--repo-timeout", type=int, default=DEFAULT_REPO_TIMEOUT)
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args(argv)


def _latest_exposure_dir() -> Path:
    root = _REPO_ROOT / COHORT_STATE_RELATIVE
    candidates = sorted(p for p in root.glob("exposure-*") if (p / "exposure.jsonl").is_file())
    if not candidates:
        raise SystemExit(f"no exposure run with exposure.jsonl under {root}")
    return candidates[-1]


def _run_git(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
    )


def _resolve_abbrevs(
    repo_path: Path, abbrevs: set[str], *, timeout: int
) -> dict[str, str]:
    """Expand abbreviated SHAs to full ones, dropping any that stay ambiguous.

    ``Fixes:`` trailers are conventionally written with 12 hex characters, which
    is not a commit id until the repository resolves it.  An abbreviation that
    matches nothing (the culprit lives in a tree this clone does not have) or
    more than one object is dropped rather than guessed at.
    """

    resolved: dict[str, str] = {}
    ordered = sorted(abbrevs)
    for start in range(0, len(ordered), 500):
        chunk = ordered[start : start + 500]
        payload = "".join(f"{value}^{{commit}}\n" for value in chunk)
        try:
            completed = subprocess.run(
                ["git", "-C", str(repo_path), "cat-file", "--batch-check"],
                input=payload,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        for abbrev, line in zip(chunk, (completed.stdout or "").splitlines()):
            fields = line.split()
            if len(fields) >= 2 and fields[1] == "commit":
                resolved[abbrev] = fields[0].lower()
    return resolved


def _index_repository(
    identity: str, repo_path: Path, *, timeout: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Index every revert and ``Fixes:`` trailer in one repository."""

    started = time.monotonic()
    stats: dict[str, Any] = {"repository_identity": identity, "error": ""}
    reverts: dict[str, list[dict[str, str]]] = defaultdict(list)
    fixes: dict[str, list[dict[str, str]]] = defaultdict(list)
    pending: dict[str, list[tuple[str, str]]] = defaultdict(list)
    commits_scanned = 0

    try:
        completed = _run_git(
            [
                "git",
                "-C",
                str(repo_path),
                "log",
                "--all",
                "--extended-regexp",
                "--regexp-ignore-case",
                "--grep=^[ \t]*This reverts commit|^[ \t]*Fixes:[ \t]+[0-9a-f]{7,}",
                f"--format={_LOG_FORMAT}",
            ],
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        stats["error"] = "timeout"
        return {"reverts": {}, "fixes": {}}, stats
    except (OSError, subprocess.SubprocessError) as exc:
        stats["error"] = f"exception:{type(exc).__name__}"
        return {"reverts": {}, "fixes": {}}, stats
    if completed.returncode != 0:
        stats["error"] = f"git_log_nonzero:{completed.returncode}"
        return {"reverts": {}, "fixes": {}}, stats

    for record in (completed.stdout or "").split(_RECORD_SEP):
        if not record.strip():
            continue
        fields = record.split(_FIELD_SEP, 2)
        if len(fields) < 3:
            continue
        sha, authored, message = fields[0].strip(), fields[1].strip(), fields[2]
        commits_scanned += 1
        for target in reverted_shas(message):
            reverts[target].append({"sha": sha, "authored_date": authored})
        for abbrev in fixes_trailer_shas(message):
            pending[abbrev].append((sha, authored))

    if pending:
        for abbrev, full in _resolve_abbrevs(repo_path, set(pending), timeout=timeout).items():
            for sha, authored in pending[abbrev]:
                fixes[full].append({"sha": sha, "authored_date": authored})

    stats.update(
        {
            "commits_scanned": commits_scanned,
            "revert_targets": len(reverts),
            "fixes_targets": len(fixes),
            "fixes_abbrevs_seen": len(pending),
            "fixes_abbrevs_resolved": sum(len(v) for v in fixes.values()),
            "elapsed_seconds": round(time.monotonic() - started, 2),
        }
    )
    return {"reverts": dict(reverts), "fixes": dict(fixes)}, stats


def _within_window(unit_date: str, outcome_date: str, window_days: int) -> bool:
    """Whether an outcome landed inside the unit's fixed follow-up window."""

    try:
        start = date.fromisoformat(unit_date[:10])
        landed = date.fromisoformat(outcome_date[:10])
    except (ValueError, IndexError):
        return False
    delta = (landed - start).days
    return 0 <= delta <= window_days


def _load_units(exposure_dir: Path, wanted: set[str]) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    with (exposure_dir / "exposure.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            unit = json.loads(line)
            if wanted and unit["repository_identity"] not in wanted:
                continue
            units.append(unit)
    return units


def _summarise(
    units: list[dict[str, Any]],
    repo_stats: list[dict[str, Any]],
    elapsed: float,
    args: argparse.Namespace,
    population_contract: dict[str, object],
) -> dict[str, Any]:
    outcomes: Counter[str] = Counter()
    by_route: dict[str, Counter[str]] = defaultdict(Counter)
    repo_fixes_usage: Counter[str] = Counter()
    repo_units: Counter[str] = Counter()
    for unit in units:
        route = unit.get("route", "?")
        repo_units[unit["repository_identity"]] += 1
        by_route[route]["units"] += 1
        if unit.get("reverted"):
            outcomes["reverted"] += 1
            by_route[route]["reverted"] += 1
        if unit.get("fixes_referenced"):
            outcomes["fixes_referenced"] += 1
            by_route[route]["fixes_referenced"] += 1
            repo_fixes_usage[unit["repository_identity"]] += 1
        if unit.get("reverted") or unit.get("fixes_referenced"):
            outcomes["any_stated_outcome"] += 1

    # Differential ascertainment check: if `Fixes:` usage clusters in a few
    # repositories, a cross-repository comparison of it measures the habit.
    repos_using = sum(1 for count in repo_fixes_usage.values() if count)
    return {
        "schema_version": 1,
        "artifact_kind": "cohort_stated_outcomes",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "exposure_dir": str(args.exposure_dir),
        "exposure_summary_sha256": sha256_file(args.exposure_dir / "summary.json"),
        "population_contract": population_contract,
        "window_days": args.window_days,
        "elapsed_seconds": round(elapsed, 1),
        "units": len(units),
        "outcome_counts": dict(outcomes.most_common()),
        "outcome_rate": {
            name: round(count / len(units), 6) if units else None
            for name, count in outcomes.items()
        },
        "by_route": {
            route: {
                **dict(counts),
                "revert_rate": (
                    round(counts["reverted"] / counts["units"], 6) if counts["units"] else None
                ),
            }
            for route, counts in sorted(by_route.items())
        },
        "fixes_ascertainment": {
            "repositories_with_units": len(repo_units),
            "repositories_using_fixes_trailer": repos_using,
            "share_of_repositories": (
                round(repos_using / len(repo_units), 4) if repo_units else None
            ),
            "top_repositories": dict(repo_fixes_usage.most_common(20)),
        },
        "repositories_indexed": len(repo_stats),
        "repositories_failed": sum(1 for s in repo_stats if s.get("error")),
        "repository_stats": sorted(
            repo_stats, key=lambda s: -int(s.get("revert_targets", 0) or 0)
        )[:30],
    }


def _print_report(summary: dict[str, Any]) -> None:
    print()
    print("=" * 72)
    print("Cohort stated outcomes")
    print("=" * 72)
    print(f"  units                  : {summary['units']:,}")
    print(f"  window                 : {summary['window_days']} days")
    print(f"  repositories indexed   : {summary['repositories_indexed']:,}"
          f" ({summary['repositories_failed']} failed)")
    print(f"  elapsed                : {summary['elapsed_seconds']}s")
    print("\n  outcomes:")
    for name, count in summary["outcome_counts"].items():
        rate = summary["outcome_rate"].get(name)
        print(f"    {name:<24} {count:>8,}   {100 * rate:.3f}%" if rate else
              f"    {name:<24} {count:>8,}")
    print("\n  revert rate by exposure route:")
    for route, counts in summary["by_route"].items():
        rate = counts.get("revert_rate")
        print(
            f"    {route:<24} {counts.get('reverted', 0):>6,} / {counts['units']:>7,}"
            f"   {(('%.3f%%' % (100 * rate)) if rate is not None else 'n/a')}"
        )
    asc = summary["fixes_ascertainment"]
    print("\n  Fixes: trailer ascertainment (a habit, not a convention):")
    print(f"    repositories with units      {asc['repositories_with_units']:,}")
    print(f"    repositories using Fixes:    {asc['repositories_using_fixes_trailer']:,}"
          f"  ({100 * (asc['share_of_repositories'] or 0):.1f}%)")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workers = max(1, args.workers)
    args.exposure_dir = args.exposure_dir or _latest_exposure_dir()
    try:
        population_contract = load_exposure_population_contract(args.exposure_dir)
    except PopulationContractError as exc:
        raise SystemExit(f"population contract failed: {exc}") from exc

    wanted = {identity.strip() for identity in args.repo}
    print(f"Reading {args.exposure_dir / 'exposure.jsonl'}...", flush=True)
    units = _load_units(args.exposure_dir, wanted)
    if not units:
        print("No units to link.")
        return 1
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for unit in units:
        by_repo[unit["repository_identity"]].append(unit)
    print(f"  {len(units):,} units across {len(by_repo):,} repositories", flush=True)

    repositories, _unresolved = discover_local_clones(_REPO_ROOT)
    targets = sorted(by_repo, key=lambda name: (-len(by_repo[name]), name))
    if args.limit_repos > 0:
        targets = targets[: args.limit_repos]

    started = time.monotonic()
    repo_stats: list[dict[str, Any]] = []
    linked: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        for identity in targets:
            path = repositories.get(identity)
            if path is None:
                repo_stats.append({"repository_identity": identity, "error": "no_local_clone"})
                linked.extend(by_repo[identity])
                continue
            futures[
                executor.submit(_index_repository, identity, path, timeout=args.repo_timeout)
            ] = identity
        for done, future in enumerate(as_completed(futures), start=1):
            identity = futures[future]
            try:
                index, stats = future.result()
            except Exception as exc:  # noqa: BLE001 - one repo must not stop the sweep
                index, stats = (
                    {"reverts": {}, "fixes": {}},
                    {"repository_identity": identity, "error": f"exception:{type(exc).__name__}"},
                )
            repo_stats.append(stats)
            for unit in by_repo[identity]:
                sha = str(unit["sha"]).lower()
                authored = str(unit.get("authored_date") or "")
                revert_hits = [
                    hit
                    for hit in index["reverts"].get(sha, [])
                    if _within_window(authored, hit["authored_date"], args.window_days)
                ]
                fixes_hits = [
                    hit
                    for hit in index["fixes"].get(sha, [])
                    if _within_window(authored, hit["authored_date"], args.window_days)
                ]
                linked.append(
                    {
                        **unit,
                        "reverted": bool(revert_hits),
                        "revert_commits": [hit["sha"] for hit in revert_hits],
                        "fixes_referenced": bool(fixes_hits),
                        "fixes_commits": [hit["sha"] for hit in fixes_hits],
                    }
                )
            if done % 100 == 0 or done == len(futures):
                print(f"  [{done}/{len(futures)}] indexed {identity}", flush=True)
    elapsed = time.monotonic() - started

    linked.sort(key=lambda unit: (unit["repository_identity"], str(unit["sha"])))
    summary = _summarise(linked, repo_stats, elapsed, args, population_contract)

    output_dir = args.output_dir or (
        _REPO_ROOT
        / COHORT_STATE_RELATIVE
        / f"outcomes-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    units_path = output_dir / "outcomes.jsonl"
    with units_path.open("w", encoding="utf-8") as handle:
        for unit in linked:
            handle.write(json.dumps(unit, sort_keys=True, ensure_ascii=False) + "\n")
    summary_path = output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    _print_report(summary)
    print(f"\nWrote {units_path}")
    print(f"Wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
