#!/usr/bin/env python3
"""Assign each cohort commit an AI exposure dose, decomposing squash merges.

The cohort compares changes by how much of them an AI wrote, so every unit
needs a ratio rather than a yes/no.  Three of the four routes need no work at
all, which is a measured result and not an optimisation: over the analysis set
(>=180 days of follow-up) only 11,578 of 91,190 units are an assistant-authored
squash merge whose composition is actually unknown.

    autonomous_agent   49,373   the bot opened the PR and wrote all of it, so
                                the dose is 1.0 by construction and there is
                                nothing to decompose
    assistant, direct  29,199   one commit carrying its own attribution
    assistant, squash  11,578   composition unknown -> decompose (this script)
    security_autofix    1,040   AI-written *fixes*; kept as its own stratum
                                because they appear in security contexts by
                                construction and would bias the outcome

Decomposition is done from local git, not the GitHub API.  Every squash merge
in the corpus is on github.com and carries a PR number, and GitHub publishes
each PR's tip as ``refs/pull/<n>/head`` to anonymous clients — so fetching the
refs we need in batches costs no token and hits no rate limit, and the member
set is then a local ``rev-list``.  ``pr_enrichment.decompose_squash_signals``
is deliberately not reused here: it is shaped around GitHub API payloads and
one REST call per sub-commit, which is the cost this route exists to avoid.

Sub-commit detection calls ``source_matcher.matches_for_commit``, the same
matcher the corpus scan used, so a commit cannot count as AI in one stage and
human in the other.

Usage::

    uv run --project cve-analyzer python scripts/cohort_classify_exposure.py
    uv run --project cve-analyzer python scripts/cohort_classify_exposure.py \
        --repo github.com/mlflow/mlflow --no-fetch
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import data_refresh_paths

from cohort.repos import discover_local_clones
from cohort.populations import (
    ESTIMATION_POPULATION,
    POPULATION_ROLES,
    PopulationContractError,
    build_exposure_population_contract,
    validate_population_parameters,
)
from cohort.pull_refs import MAX_PR_MEMBERS, fetch_pull_refs, pull_members

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent

DEFAULT_WORKERS = 12
DEFAULT_MIN_FOLLOWUP_DAYS = 180
DEFAULT_FETCH_BATCH = 150
DEFAULT_REPO_TIMEOUT = 900
COHORT_STATE_RELATIVE = Path(data_refresh_paths.PROJECT_RUNTIME_DIRECTORY) / "state" / "cohort-v1"

TIER_NO_DECOMPOSITION = "A_no_decomposition_needed"
TIER_DECOMPOSED = "B_decomposed"
TIER_UNRESOLVED = "C_unresolved"
# Distinct from Tier C.  Tier C is "the dose could not be measured", which is a
# threat to validity and has to be reported as one.  A 600- to 1,700-commit
# integration branch is measurable and simply is not the same kind of object as
# a reviewable change, so pooling the two would overstate the measurement
# failure and understate the exclusion.
TIER_NOT_REVIEWABLE = "D_not_a_reviewable_unit"

ROUTE_AUTONOMOUS = "autonomous_agent"
ROUTE_ASSISTANT_DIRECT = "assistant_direct"
ROUTE_ASSISTANT_SQUASH = "assistant_squash"
ROUTE_SECURITY_AUTOFIX = "security_autofix"

_RECORD_SEP = "\x1e"
_FIELD_SEP = "\x1f"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scan-dir", type=Path, default=None, help="scan directory (default: latest)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument(
        "--min-followup-days",
        type=int,
        default=DEFAULT_MIN_FOLLOWUP_DAYS,
        help=(
            "only classify commits with at least this much follow-up"
            f" (default: {DEFAULT_MIN_FOLLOWUP_DAYS}; 0 = all)"
        ),
    )
    parser.add_argument(
        "--population-role",
        choices=POPULATION_ROLES,
        default=ESTIMATION_POPULATION,
        help=(
            "scientific role for this slice; all_age_discovery requires zero follow-up,"
            " while the default mature_outcome_estimation requires a positive threshold"
        ),
    )
    parser.add_argument("--as-of", default=None, help="follow-up reference date (default: today)")
    parser.add_argument("--repo", action="append", default=[], help="restrict to this identity")
    parser.add_argument(
        "--frame",
        type=Path,
        default=None,
        help="advisory repo frame used to choose a canonical home for duplicate SHAs",
    )
    parser.add_argument("--limit-repos", type=int, default=0, help="decompose at most N repositories")
    parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="never touch the network; only decompose PRs whose refs are already local",
    )
    parser.add_argument("--fetch-batch", type=int, default=DEFAULT_FETCH_BATCH)
    parser.add_argument("--repo-timeout", type=int, default=DEFAULT_REPO_TIMEOUT)
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args(argv)


def _latest_scan_dir() -> Path:
    root = _REPO_ROOT / COHORT_STATE_RELATIVE
    candidates = sorted(p for p in root.glob("scan-*") if (p / "commits.jsonl").is_file())
    if not candidates:
        raise SystemExit(f"no scan with commits.jsonl under {root}")
    return candidates[-1]


def _route(row: dict[str, Any]) -> str:
    """Decide how a corpus row's exposure has to be established."""

    kinds = set(row.get("agent_kinds") or ())
    # Autonomous first: when a bot authored the change and also credited an
    # assistant, the bot still wrote all of it.
    if ROUTE_AUTONOMOUS in kinds:
        return ROUTE_AUTONOMOUS
    if kinds == {ROUTE_SECURITY_AUTOFIX}:
        return ROUTE_SECURITY_AUTOFIX
    if row.get("merge_topology") == "squash" and row.get("pr_number"):
        return ROUTE_ASSISTANT_SQUASH
    return ROUTE_ASSISTANT_DIRECT


def _followup_days(authored_date: str, as_of: date) -> int | None:
    try:
        return (as_of - date.fromisoformat(str(authored_date)[:10])).days
    except ValueError:
        return None


def _run_git(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
    )


def _commit_records(repo_path: Path, shas: list[str], *, timeout: int) -> dict[str, Any]:
    """Return sha -> CommitInfo for a batch of sub-commits."""

    from cve_analyzer.models import CommitInfo

    records: dict[str, Any] = {}
    fmt = f"{_RECORD_SEP}%H{_FIELD_SEP}%an{_FIELD_SEP}%ae{_FIELD_SEP}%aI{_FIELD_SEP}%B"
    for start in range(0, len(shas), 200):
        chunk = shas[start : start + 200]
        try:
            completed = _run_git(
                ["git", "-C", str(repo_path), "show", "--no-patch", f"--format={fmt}", *chunk],
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if completed.returncode != 0:
            continue
        for record in (completed.stdout or "").split(_RECORD_SEP):
            if not record.strip():
                continue
            fields = record.split(_FIELD_SEP, 4)
            if len(fields) < 5:
                continue
            sha, name, email, authored, message = fields
            records[sha.strip()] = CommitInfo(
                sha=sha.strip(),
                author_name=name,
                author_email=email,
                committer_name=name,
                committer_email=email,
                message=message,
                authored_date=authored.strip(),
            )
    return records


def _decompose_repository(
    identity: str,
    repo_path: Path,
    units: list[dict[str, Any]],
    *,
    no_fetch: bool,
    fetch_batch: int,
    timeout: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Decompose one repository's squash merges.  Never raises."""

    from cve_analyzer.source_matcher import matches_for_commit

    started = time.monotonic()
    stats: dict[str, Any] = {
        "repository_identity": identity,
        "units": len(units),
        "refs_fetched": 0,
        "fetch_error": "",
    }
    pr_numbers = sorted({int(unit["pr_number"]) for unit in units})
    if not no_fetch:
        fetched, error = fetch_pull_refs(
            repo_path, pr_numbers, batch=fetch_batch, timeout=timeout
        )
        stats["refs_fetched"] = fetched
        stats["fetch_error"] = error

    results: list[dict[str, Any]] = []
    for unit in units:
        members = pull_members(
            repo_path, str(unit["sha"]), int(unit["pr_number"]), timeout=timeout
        )
        if members is None:
            results.append({**unit, "tier": TIER_UNRESOLVED, "unresolved_reason": "no_pr_ref"})
            continue
        if len(members) > MAX_PR_MEMBERS:
            results.append(
                {
                    **unit,
                    "tier": TIER_NOT_REVIEWABLE,
                    "unresolved_reason": "integration_branch",
                    "n_members_at_least": len(members),
                }
            )
            continue
        records = _commit_records(repo_path, members, timeout=timeout)
        if len(records) < len(members):
            results.append(
                {**unit, "tier": TIER_UNRESOLVED, "unresolved_reason": "member_read_incomplete"}
            )
            continue
        ai_member_shas: list[str] = []
        member_ai_tools: dict[str, list[str]] = {}
        member_tools: set[str] = set()
        for sha in members:
            matched = matches_for_commit(records[sha])
            if matched:
                ai_member_shas.append(sha)
                tools = sorted({match.tool for match in matched})
                member_ai_tools[sha] = tools
                member_tools.update(tools)
        results.append(
            {
                **unit,
                "tier": TIER_DECOMPOSED,
                "n_members": len(members),
                "n_ai_members": len(ai_member_shas),
                "ai_ratio": round(len(ai_member_shas) / len(members), 6),
                "member_shas": members,
                "ai_member_shas": ai_member_shas,
                "member_ai_tools": member_ai_tools,
                "member_tools": sorted(member_tools),
                # The squash was credited to an AI but no member commit carries
                # the attribution — the trailer was added when the PR was
                # merged, not when the code was written.  Verified by hand on
                # mlflow#18122.  A member-level dose of 0.0 here does not mean
                # "no AI": it means the dose could not be localised, and
                # letting it pass as a plain 0.0 would file an exposed change
                # among the controls.
                "squash_attribution_only": not ai_member_shas,
            }
        )
    stats["elapsed_seconds"] = round(time.monotonic() - started, 2)
    stats["decomposed"] = sum(1 for r in results if r["tier"] == TIER_DECOMPOSED)
    stats["unresolved"] = sum(1 for r in results if r["tier"] == TIER_UNRESOLVED)
    return results, stats


def _frame_identities(frame_path: Path | None = None) -> set[str]:
    """Repositories that earned their way into the sampling frame."""

    explicit = frame_path is not None
    frame_path = frame_path or (
        _REPO_ROOT / COHORT_STATE_RELATIVE / "advisory-repos-since-2025-05-01.json"
    )
    try:
        payload = json.loads(frame_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        if explicit:
            raise SystemExit(f"cannot read frame {frame_path}: {exc}") from exc
        return set()
    repositories = payload.get("repositories") if isinstance(payload, dict) else None
    if payload.get("artifact_kind") != "cohort_advisory_repo_index" or not isinstance(
        repositories, dict
    ):
        if explicit:
            raise SystemExit(f"invalid cohort frame: {frame_path}")
        return set()
    return set(repositories)


def _canonical_repositories(
    scan_dir: Path, frame_path: Path | None = None
) -> tuple[dict[str, str], int]:
    """Pick one home repository per commit SHA.

    Forks and vendor mirrors republish the same commits verbatim: cal.com and
    cal.diy share 4,246 of them, mlflow and a personal fork share 1,641, and the
    Linux kernel's commits reappear in the Android and CodeLinaro trees.  7.8% of
    corpus rows are a SHA already counted somewhere else.  Left alone, one
    commit becomes several units, within-repo matching pairs it against a
    different control in each copy, and the standard errors treat those as
    independent observations when they are one event.

    The choice of home is deterministic and prefers a repository that is in the
    sampling frame, then the one with the larger corpus (upstream is almost
    always the busier tree), then lexicographic order so that reruns agree.
    """

    frame = _frame_identities(frame_path)
    sha_repos: dict[str, set[str]] = defaultdict(set)
    repo_size: Counter[str] = Counter()
    with (scan_dir / "commits.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            identity = row["repository_identity"]
            sha_repos[str(row["sha"])].add(identity)
            repo_size[identity] += 1
    canonical: dict[str, str] = {}
    duplicated = 0
    for sha, identities in sha_repos.items():
        if len(identities) == 1:
            canonical[sha] = next(iter(identities))
            continue
        duplicated += 1
        canonical[sha] = max(
            identities,
            key=lambda name: (name in frame, repo_size[name], name),
        )
    return canonical, duplicated


def _load_units(
    scan_dir: Path,
    min_followup_days: int,
    as_of: date,
    wanted: set[str],
    canonical: dict[str, str],
) -> tuple[list[dict[str, Any]], Counter[str]]:
    """Read the corpus and keep the analysis-set fields the cohort needs."""

    units: list[dict[str, Any]] = []
    dropped: Counter[str] = Counter()
    with (scan_dir / "commits.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            # One commit, one unit — see _canonical_repositories.
            home = canonical.get(str(row["sha"]))
            if home is not None and home != row["repository_identity"]:
                dropped["duplicate_of_another_repository"] += 1
                continue
            if wanted and row["repository_identity"] not in wanted:
                dropped["not_selected"] += 1
                continue
            followup = _followup_days(row.get("authored_date") or "", as_of)
            if followup is None:
                dropped["unparsable_date"] += 1
                continue
            if followup < min_followup_days:
                dropped["insufficient_followup"] += 1
                continue
            units.append(
                {
                    "repository_identity": row["repository_identity"],
                    "sha": row["sha"],
                    "authored_date": row["authored_date"],
                    "followup_days": followup,
                    "merge_topology": row.get("merge_topology"),
                    "pr_number": row.get("pr_number"),
                    "agent_kinds": row.get("agent_kinds") or [],
                    "tools": row.get("tools") or [],
                    "files_changed": len(row.get("changed_files") or []),
                    "route": _route(row),
                }
            )
    return units, dropped


def _summarise(
    units: list[dict[str, Any]],
    dropped: Counter[str],
    repo_stats: list[dict[str, Any]],
    elapsed: float,
    args: argparse.Namespace,
) -> dict[str, Any]:
    tiers: Counter[str] = Counter()
    routes: Counter[str] = Counter()
    unresolved_reasons: Counter[str] = Counter()
    dose_bins: Counter[str] = Counter()
    members_by_route: Counter[str] = Counter()
    for unit in units:
        tiers[unit["tier"]] += 1
        routes[unit["route"]] += 1
        if unit["tier"] == TIER_UNRESOLVED:
            unresolved_reasons[unit.get("unresolved_reason", "unknown")] += 1
            continue
        ratio = unit.get("ai_ratio")
        if ratio is None:
            continue
        if ratio >= 1.0:
            dose_bins["1.0 (all AI)"] += 1
        elif ratio >= 0.5:
            dose_bins["0.5-0.99"] += 1
        elif ratio > 0.0:
            dose_bins["0.01-0.49"] += 1
        else:
            dose_bins["0.0 (no AI member)"] += 1
        members_by_route[unit["route"]] += unit.get("n_members", 1)

    squash = [
        u
        for u in units
        if u["route"] == ROUTE_ASSISTANT_SQUASH and u["tier"] != TIER_NOT_REVIEWABLE
    ]
    resolved = [u for u in squash if u["tier"] == TIER_DECOMPOSED]
    unresolved = [u for u in squash if u["tier"] == TIER_UNRESOLVED]

    def _mean(values: list[float]) -> float | None:
        return round(sum(values) / len(values), 3) if values else None

    return {
        "schema_version": 1,
        "artifact_kind": "cohort_exposure_classification",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scan_dir": str(args.scan_dir),
        "min_followup_days": args.min_followup_days,
        "population_contract": args.population_contract,
        "as_of": str(args.as_of),
        "fetch_disabled": bool(args.no_fetch),
        "elapsed_seconds": round(elapsed, 1),
        "units": len(units),
        "dropped": dict(dropped),
        "duplicate_shas_collapsed": dropped.get("duplicate_of_another_repository", 0),
        "not_reviewable_units": sum(
            1 for unit in units if unit["tier"] == TIER_NOT_REVIEWABLE
        ),
        "route_counts": dict(routes.most_common()),
        "tier_counts": dict(tiers.most_common()),
        "unresolved_reasons": dict(unresolved_reasons.most_common()),
        "dose_distribution": dict(dose_bins.most_common()),
        # Credited at merge time only, so the dose is unlocalised rather than
        # zero.  These must not be pooled with the controls.
        "squash_attribution_only": sum(
            1 for unit in units if unit.get("squash_attribution_only")
        ),
        "member_counts_by_route": dict(members_by_route),
        # Tier C is not allowed to be a silent hole: report how much of the
        # decomposable population it is, and whether what fell out differs from
        # what resolved.  A Tier C that looks systematically different from the
        # main sample is a threat to validity, not just missing rows.
        "tier_c_report": {
            "decomposable_units": len(squash),
            "resolved": len(resolved),
            "unresolved": len(unresolved),
            "unresolved_share": (
                round(len(unresolved) / len(squash), 4) if squash else None
            ),
            "mean_files_changed_resolved": _mean([u["files_changed"] for u in resolved]),
            "mean_files_changed_unresolved": _mean([u["files_changed"] for u in unresolved]),
            "mean_followup_days_resolved": _mean([u["followup_days"] for u in resolved]),
            "mean_followup_days_unresolved": _mean([u["followup_days"] for u in unresolved]),
            "distinct_repos_resolved": len({u["repository_identity"] for u in resolved}),
            "distinct_repos_unresolved": len({u["repository_identity"] for u in unresolved}),
        },
        "repositories_decomposed": len(repo_stats),
        "repository_stats": sorted(
            repo_stats, key=lambda item: -int(item.get("units", 0))
        )[:50],
    }


def _print_report(summary: dict[str, Any]) -> None:
    print()
    print("=" * 72)
    print("Cohort exposure classification")
    print("=" * 72)
    print(f"  units (>= {summary['min_followup_days']}d follow-up): {summary['units']:,}")
    print(f"  elapsed                        : {summary['elapsed_seconds']}s")
    for title, key in (
        ("by route", "route_counts"),
        ("by tier", "tier_counts"),
        ("dose distribution", "dose_distribution"),
        ("unresolved reasons", "unresolved_reasons"),
    ):
        counts = summary[key]
        if not counts:
            continue
        print(f"\n  {title}:")
        for name, count in counts.items():
            print(f"    {name:<32} {count:>9,}")
    ambiguous = summary["squash_attribution_only"]
    if ambiguous:
        print(
            f"\n  credited at merge only (dose unlocalised, NOT a control): {ambiguous:,}"
        )
    report = summary["tier_c_report"]
    print("\n  Tier C (unresolved) check:")
    print(f"    decomposable units             {report['decomposable_units']:>9,}")
    print(f"    resolved / unresolved          {report['resolved']:,} / {report['unresolved']:,}")
    share = report["unresolved_share"]
    print(f"    unresolved share               {('%.2f%%' % (100 * share)) if share is not None else 'n/a':>9}")
    print(
        f"    mean files changed  res/unres  {report['mean_files_changed_resolved']}"
        f" / {report['mean_files_changed_unresolved']}"
    )
    print(
        f"    mean follow-up days res/unres  {report['mean_followup_days_resolved']}"
        f" / {report['mean_followup_days_unresolved']}"
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workers = max(1, args.workers)
    os.environ.setdefault("CVE_GIT_CONCURRENCY", str(workers))

    args.scan_dir = args.scan_dir or _latest_scan_dir()
    as_of = date.fromisoformat(args.as_of) if args.as_of else datetime.now(timezone.utc).date()
    args.as_of = as_of
    try:
        validate_population_parameters(args.population_role, args.min_followup_days)
        args.population_contract = build_exposure_population_contract(
            args.scan_dir,
            role=args.population_role,
            min_followup_days=args.min_followup_days,
        )
    except PopulationContractError as exc:
        raise SystemExit(f"population contract failed: {exc}") from exc

    wanted = {identity.strip() for identity in args.repo}
    print(f"Reading {args.scan_dir / 'commits.jsonl'}...", flush=True)
    canonical, duplicated = _canonical_repositories(args.scan_dir, args.frame)
    print(f"  {duplicated:,} commit SHAs live in more than one repository", flush=True)
    units, dropped = _load_units(
        args.scan_dir, args.min_followup_days, as_of, wanted, canonical
    )
    print(f"  {len(units):,} units in the analysis set", flush=True)
    if not units:
        print("Nothing to classify.")
        return 1

    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    classified: list[dict[str, Any]] = []
    for unit in units:
        route = unit["route"]
        if route == ROUTE_ASSISTANT_SQUASH:
            by_repo[unit["repository_identity"]].append(unit)
            continue
        # Everything else already knows its own dose: the unit is a single
        # commit that carries the attribution, or a bot that wrote all of it.
        classified.append(
            {**unit, "tier": TIER_NO_DECOMPOSITION, "n_members": 1, "n_ai_members": 1, "ai_ratio": 1.0}
        )

    targets = sorted(by_repo.items(), key=lambda item: (-len(item[1]), item[0]))
    if args.limit_repos > 0:
        targets = targets[: args.limit_repos]
    print(
        f"  {sum(len(v) for v in by_repo.values()):,} squash units to decompose"
        f" across {len(by_repo):,} repositories"
        + (f" (limited to {len(targets)})" if args.limit_repos else ""),
        flush=True,
    )

    repositories, _unresolved_dirs = discover_local_clones(_REPO_ROOT)
    started = time.monotonic()
    repo_stats: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        for identity, repo_units in targets:
            path = repositories.get(identity)
            if path is None:
                classified.extend(
                    {**u, "tier": TIER_UNRESOLVED, "unresolved_reason": "no_local_clone"}
                    for u in repo_units
                )
                continue
            futures[
                executor.submit(
                    _decompose_repository,
                    identity,
                    path,
                    repo_units,
                    no_fetch=args.no_fetch,
                    fetch_batch=args.fetch_batch,
                    timeout=args.repo_timeout,
                )
            ] = identity
        for done, future in enumerate(as_completed(futures), start=1):
            identity = futures[future]
            try:
                results, stats = future.result()
            except Exception as exc:  # noqa: BLE001 - one repo must not stop the sweep
                results = [
                    {**u, "tier": TIER_UNRESOLVED, "unresolved_reason": f"exception:{type(exc).__name__}"}
                    for u in by_repo[identity]
                ]
                stats = {"repository_identity": identity, "units": len(results), "error": str(exc)}
            classified.extend(results)
            repo_stats.append(stats)
            if done % 25 == 0 or done == len(futures):
                print(
                    f"  [{done}/{len(futures)}] {identity} —"
                    f" {stats.get('decomposed', 0)} decomposed,"
                    f" {stats.get('unresolved', 0)} unresolved",
                    flush=True,
                )
    elapsed = time.monotonic() - started

    # Squash units in repositories skipped by --limit-repos never got a tier.
    seen = {(u["repository_identity"], u["sha"]) for u in classified}
    for identity, repo_units in by_repo.items():
        for unit in repo_units:
            if (unit["repository_identity"], unit["sha"]) not in seen:
                classified.append(
                    {**unit, "tier": TIER_UNRESOLVED, "unresolved_reason": "not_attempted"}
                )

    classified.sort(key=lambda unit: (unit["repository_identity"], str(unit["sha"])))
    summary = _summarise(classified, dropped, repo_stats, elapsed, args)
    if args.frame is not None:
        summary["frame_path"] = str(args.frame)
        summary["frame_sha256"] = hashlib.sha256(args.frame.read_bytes()).hexdigest()

    output_dir = args.output_dir or (
        _REPO_ROOT
        / COHORT_STATE_RELATIVE
        / f"exposure-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    units_path = output_dir / "exposure.jsonl"
    with units_path.open("w", encoding="utf-8") as handle:
        for unit in classified:
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
