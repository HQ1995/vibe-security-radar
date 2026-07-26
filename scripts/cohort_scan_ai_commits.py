#!/usr/bin/env python3
"""Enumerate AI-attributed commits across every locally cloned repository.

This is the entry point for the forward cohort study: instead of walking
CVEs backwards through blame, it walks forwards from the (small, cheap to
enumerate) population of commits that carry an AI attribution signature.
The output corpus is the denominator that the CVE-first pipeline could
never produce.

Detection itself is not reimplemented here.  Each repository is handed to
``provenance.scan_repo_ai_commit_index``, the same Source v3 scanner the
analyzer already uses, so this script and the analyzer always agree on what
counts as an AI-attributed commit.

Usage::

    uv run --project cve-analyzer python scripts/cohort_scan_ai_commits.py
    uv run --project cve-analyzer python scripts/cohort_scan_ai_commits.py \
        --repo git.kernel.org/pub/scm/linux/kernel/git/stable/linux
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import data_refresh_paths

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent

DEFAULT_WORKERS = 8
COHORT_STATE_RELATIVE = Path(data_refresh_paths.PROJECT_RUNTIME_DIRECTORY) / "state" / "cohort-v1"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"concurrent repository scans (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--repo",
        action="append",
        default=[],
        metavar="IDENTITY",
        help="only scan this canonical repository identity (repeatable)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="scan at most N repositories (0 = no limit)",
    )
    parser.add_argument(
        "--since",
        default=None,
        help="earliest authored date to scan (default: analyzer DEFAULT_PROVENANCE_SINCE)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="write artifacts here instead of a timestamped cohort-v1 directory",
    )
    return parser.parse_args(argv)


def _discover_repositories(canonical_repository_identity, run_git) -> tuple[
    dict[str, Path], list[dict[str, str]]
]:
    """Map canonical identity -> repo path, preferring the project-local cache.

    The campaign cache and the older home cache hold overlapping clones; the
    project-local one is the durable root the analyzer now writes to, so it
    wins whenever both hold the same identity.
    """

    from cve_analyzer.git_ops import CACHE_DIR

    roots = [
        ("project", data_refresh_paths.shared_analyzer_cache_root(_REPO_ROOT) / "repos"),
        ("home", CACHE_DIR),
    ]
    resolved: dict[str, Path] = {}
    unresolved: list[dict[str, str]] = []
    for root_name, root in roots:
        if not root.is_dir():
            continue
        for entry in sorted(root.iterdir()):
            if not entry.name.startswith("v2_") or not entry.is_dir():
                continue
            identity = _origin_identity(entry, canonical_repository_identity, run_git)
            if not identity:
                unresolved.append({"path": str(entry), "root": root_name})
                continue
            resolved.setdefault(identity, entry)
    return resolved, unresolved


def _origin_identity(repo_dir: Path, canonical_repository_identity, run_git) -> str:
    """Return the canonical identity from the clone's own origin, or ``""``."""

    try:
        completed = run_git(
            ["git", "-C", str(repo_dir), "config", "--get", "remote.origin.url"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except Exception:
        return ""
    if completed.returncode != 0:
        return ""
    return canonical_repository_identity(completed.stdout.strip())


def _scan_one(
    identity: str,
    repo_path: Path,
    since: str | None,
    scan_repo_ai_commit_index,
) -> dict[str, Any]:
    """Scan one repository; a failure is recorded, never raised."""

    started = time.monotonic()
    kwargs = {"since": since} if since else {}
    try:
        payload = scan_repo_ai_commit_index(repo_path, identity, **kwargs)
    except Exception as exc:  # noqa: BLE001 - one bad clone must not stop the sweep
        return {
            "repository_identity": identity,
            "repo_path": str(repo_path),
            "complete": False,
            "error": f"scan_exception:{type(exc).__name__}",
            "commits": [],
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    return {
        "repository_identity": identity,
        "repo_path": str(repo_path),
        "complete": bool(payload.get("complete")),
        "error": str(payload.get("error") or ""),
        "commits": payload.get("commits") or [],
        "tool_commit_counts": payload.get("tool_commit_counts") or {},
        "source_module_commit_counts": payload.get("source_module_commit_counts") or {},
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def _commit_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten one repository's matched commits into corpus rows."""

    rows: list[dict[str, Any]] = []
    for commit in result["commits"]:
        matches = commit.get("source_matches") or []
        authored = str(commit.get("authored_date") or "")
        rows.append(
            {
                "repository_identity": result["repository_identity"],
                "sha": commit.get("sha"),
                "authored_date": authored,
                "year": authored[:4],
                "tools": sorted({str(m.get("tool")) for m in matches if m.get("tool")}),
                "source_modules": sorted(
                    {str(m.get("source_module")) for m in matches if m.get("source_module")}
                ),
                "signal_types": sorted(
                    {str(m.get("signal_type")) for m in matches if m.get("signal_type")}
                ),
                "changed_files": commit.get("changed_files") or [],
            }
        )
    return rows


def _build_summary(
    results: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    unresolved: list[dict[str, str]],
    elapsed: float,
    since: str,
) -> dict[str, Any]:
    tools: Counter[str] = Counter()
    modules: Counter[str] = Counter()
    signal_types: Counter[str] = Counter()
    years: Counter[str] = Counter()
    per_repo: Counter[str] = Counter()
    for row in rows:
        for tool in row["tools"]:
            tools[tool] += 1
        for module in row["source_modules"]:
            modules[module] += 1
        for signal_type in row["signal_types"]:
            signal_types[signal_type] += 1
        if row["year"]:
            years[row["year"]] += 1
        per_repo[row["repository_identity"]] += 1

    incomplete = [
        {
            "repository_identity": result["repository_identity"],
            "error": result["error"],
            "elapsed_seconds": result["elapsed_seconds"],
        }
        for result in results
        if not result["complete"]
    ]
    return {
        "schema_version": 1,
        "artifact_kind": "cohort_ai_commit_scan",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "since": since,
        "elapsed_seconds": round(elapsed, 1),
        "repositories_scanned": len(results),
        "repositories_complete": sum(1 for r in results if r["complete"]),
        "repositories_incomplete": len(incomplete),
        "repositories_with_ai_commits": sum(1 for count in per_repo.values() if count),
        "unresolved_cache_dirs": len(unresolved),
        "ai_commit_count": len(rows),
        "tool_commit_counts": dict(tools.most_common()),
        "source_module_commit_counts": dict(modules.most_common()),
        "signal_type_commit_counts": dict(signal_types.most_common()),
        "commits_by_year": dict(sorted(years.items())),
        "top_repositories": dict(per_repo.most_common(30)),
        "incomplete_repositories": incomplete,
    }


def _print_report(summary: dict[str, Any]) -> None:
    print()
    print("=" * 62)
    print("AI-attributed commit corpus")
    print("=" * 62)
    print(f"  repositories scanned : {summary['repositories_scanned']}")
    print(
        f"  complete / incomplete: {summary['repositories_complete']}"
        f" / {summary['repositories_incomplete']}"
    )
    print(f"  repos with AI commits: {summary['repositories_with_ai_commits']}")
    print(f"  AI commits found     : {summary['ai_commit_count']}")
    print(f"  elapsed              : {summary['elapsed_seconds']}s")
    for title, key in (
        ("by tool", "tool_commit_counts"),
        ("by source module", "source_module_commit_counts"),
        ("by year", "commits_by_year"),
    ):
        counts = summary[key]
        if not counts:
            continue
        print(f"\n  {title}:")
        for name, count in counts.items():
            print(f"    {name:<28} {count:>7}")
    top = summary["top_repositories"]
    if top:
        print("\n  top repositories:")
        for name, count in list(top.items())[:15]:
            print(f"    {name:<52} {count:>6}")
    if summary["incomplete_repositories"]:
        print("\n  incomplete (rescan these):")
        for entry in summary["incomplete_repositories"][:15]:
            print(f"    {entry['repository_identity']:<52} {entry['error']}")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workers = max(1, args.workers)

    # git_ops binds the throttle singleton at import time, so resizing it
    # afterwards has no effect — the env var is the only knob that reaches it.
    os.environ.setdefault("CVE_GIT_CONCURRENCY", str(workers))
    # Nothing here should ever reach the network: the scan reads local refs
    # only, and lazy promisor fetches are what made the CVE-first pipeline
    # time out on partial clones.
    os.environ.setdefault("CVE_ANALYZER_FROZEN_LOCAL_SOURCES", "1")

    from cve_analyzer.git_ops import run_git
    from cve_analyzer.models import canonical_repository_identity
    from cve_analyzer.provenance import DEFAULT_PROVENANCE_SINCE, scan_repo_ai_commit_index

    since = args.since or DEFAULT_PROVENANCE_SINCE

    print("Discovering local clones...", flush=True)
    repositories, unresolved = _discover_repositories(canonical_repository_identity, run_git)
    if args.repo:
        wanted = {identity.strip().casefold() for identity in args.repo}
        repositories = {k: v for k, v in repositories.items() if k.casefold() in wanted}
        missing = wanted - {k.casefold() for k in repositories}
        for identity in sorted(missing):
            print(f"  WARNING: no local clone for {identity}", file=sys.stderr)
    targets = sorted(repositories.items())
    if args.limit > 0:
        targets = targets[: args.limit]
    if not targets:
        print("No repositories to scan.", file=sys.stderr)
        return 1
    print(
        f"  {len(targets)} repositories to scan"
        f" ({len(unresolved)} cache dirs without a usable origin)",
        flush=True,
    )

    started = time.monotonic()
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_scan_one, identity, path, args.since, scan_repo_ai_commit_index): identity
            for identity, path in targets
        }
        for done, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            results.append(result)
            status = "ok" if result["complete"] else f"INCOMPLETE ({result['error']})"
            print(
                f"  [{done}/{len(targets)}] {result['repository_identity']}"
                f" — {len(result['commits'])} AI commits,"
                f" {result['elapsed_seconds']}s {status}",
                flush=True,
            )
    elapsed = time.monotonic() - started

    results.sort(key=lambda item: item["repository_identity"])
    rows = [row for result in results for row in _commit_rows(result)]
    rows.sort(key=lambda row: (row["repository_identity"], str(row["sha"])))
    summary = _build_summary(results, rows, unresolved, elapsed, since)

    output_dir = args.output_dir or (
        _REPO_ROOT
        / COHORT_STATE_RELATIVE
        / f"scan-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    commits_path = output_dir / "commits.jsonl"
    with commits_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    summary_path = output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    _print_report(summary)
    print(f"\nWrote {commits_path}")
    print(f"Wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
