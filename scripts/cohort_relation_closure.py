#!/usr/bin/env python3
"""Expand landed-squash advisory candidates back to every PR-head member."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import data_refresh_paths

from cohort.advisory_candidates import build_routing_manifest
from cohort.pull_refs import MAX_PR_MEMBERS, fetch_pull_refs, pull_members
from cohort.relations import (
    build_pull_relation_inventory,
    canonical_repository_identity,
    expand_candidate_edges,
    normalize_repository_aliases,
)
from cohort.repos import discover_local_clones


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
DEFAULT_REPOSITORY_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"
DEFAULT_FETCH_BATCH = 50
DEFAULT_REPO_TIMEOUT = 300
COHORT_STATE_RELATIVE = (
    Path(data_refresh_paths.PROJECT_RUNTIME_DIRECTORY) / "state" / "cohort-v1"
)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--candidate-dir", type=Path, default=None)
    parser.add_argument("--outcomes-dir", type=Path, default=None)
    parser.add_argument(
        "--repository-aliases", type=Path, default=DEFAULT_REPOSITORY_ALIASES
    )
    parser.add_argument("--repository", action="append", default=[])
    parser.add_argument("--no-fetch", action="store_true")
    parser.add_argument("--fetch-batch", type=int, default=DEFAULT_FETCH_BATCH)
    parser.add_argument("--repo-timeout", type=int, default=DEFAULT_REPO_TIMEOUT)
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args(argv)


def _latest_artifact_dir(prefix: str, required_file: str) -> Path:
    root = _REPO_ROOT / COHORT_STATE_RELATIVE
    candidates = sorted(
        path
        for path in root.glob(f"{prefix}*")
        if (path / required_file).is_file()
    )
    if not candidates:
        raise SystemExit(f"no {prefix} run under {root}")
    return candidates[-1]


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain an object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        handle = path.open(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    with handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise SystemExit(f"malformed {path}:{line_number}: {exc}") from exc
            if not isinstance(row, dict):
                raise SystemExit(f"{path}:{line_number} is not an object")
            rows.append(row)
    return rows


def _load_aliases(path: Path) -> dict[str, str]:
    payload = _load_json(path)
    if payload.get("schema_version") != 1 or not isinstance(payload.get("aliases"), list):
        raise SystemExit("repository alias ledger must use schema_version 1")
    try:
        return normalize_repository_aliases(payload["aliases"])
    except ValueError as exc:
        raise SystemExit(f"invalid repository alias ledger: {exc}") from exc


def _group_units(
    rows: Sequence[Mapping[str, object]], aliases: Mapping[str, str]
) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for raw in rows:
        observed = str(raw.get("repository_identity") or "").strip().lower()
        identity = canonical_repository_identity(observed, aliases)
        row = dict(raw)
        row["repository_identity"] = identity
        if identity != observed:
            row["observed_repository_identity"] = observed
        grouped[identity].append(row)
    return dict(grouped)


def _canonical_clone_paths(
    rows: Mapping[str, Path], aliases: Mapping[str, str]
) -> dict[str, Path]:
    resolved: dict[str, tuple[bool, Path]] = {}
    for observed, path in sorted(rows.items()):
        identity = canonical_repository_identity(observed, aliases)
        candidate = (observed.strip().lower() == identity, path)
        if identity not in resolved or candidate[0] > resolved[identity][0]:
            resolved[identity] = candidate
    return {identity: item[1] for identity, item in resolved.items()}


def _target_landed_shas(
    candidate_edges: Sequence[Mapping[str, object]],
    units_by_repo: Mapping[str, Sequence[Mapping[str, object]]],
) -> dict[str, set[str]]:
    candidate_shas: dict[str, set[str]] = defaultdict(set)
    for edge in candidate_edges:
        if edge.get("relation") != "reachable_ancestor":
            continue
        identity = str(edge.get("repository_identity") or "").strip().lower()
        candidate_shas[identity].add(str(edge.get("candidate_sha") or "").lower())

    targets: dict[str, set[str]] = defaultdict(set)
    for identity, shas in candidate_shas.items():
        units = units_by_repo.get(identity)
        if units is None:
            raise ValueError(f"candidate repository absent from outcomes: {identity}")
        by_sha = {str(unit.get("sha") or "").lower(): unit for unit in units}
        missing = sorted(shas - set(by_sha))
        if missing:
            raise ValueError(f"candidate SHA absent from outcomes: {identity}@{missing[0]}")
        for sha in shas:
            unit = by_sha[sha]
            if unit.get("merge_topology") == "squash" and isinstance(
                unit.get("pr_number"), int
            ):
                targets[identity].add(sha)
    return dict(targets)


def build_relation_campaign(
    candidate_edges: Sequence[Mapping[str, object]],
    units_by_repo: Mapping[str, Sequence[Mapping[str, object]]],
    pull_results_by_repo: Mapping[int | str, object] | Mapping[
        str, Mapping[int, Mapping[str, object]]
    ],
) -> dict[str, object]:
    """Build conserved direct + composite artifacts from explicit PR evidence."""

    targets = _target_landed_shas(candidate_edges, units_by_repo)
    relations: list[dict[str, object]] = []
    relation_roots: list[dict[str, object]] = []
    inventory_hashes: list[str] = []
    for identity in sorted(targets):
        raw_results = pull_results_by_repo.get(identity, {})
        if not isinstance(raw_results, Mapping):
            raise ValueError(f"pull results for {identity} are malformed")
        inventory = build_pull_relation_inventory(
            identity,
            units_by_repo[identity],
            raw_results,
            landed_candidate_shas=targets[identity],
        )
        relations.extend(dict(row) for row in inventory["relations"])
        relation_roots.extend(dict(row) for row in inventory["pull_roots"])
        inventory_hashes.append(str(inventory["inventory_sha256"]))

    relations.sort(key=lambda row: str(row["relation_id"]))
    relation_roots.sort(key=lambda row: str(row["root_id"]))
    expanded = expand_candidate_edges(candidate_edges, relations)
    routing = build_routing_manifest(expanded)
    routes = routing["routes"]
    assert isinstance(routes, list)
    root_counts = Counter(str(root.get("status") or "") for root in relation_roots)
    route_conservation = routing["conservation"]
    assert isinstance(route_conservation, Mapping)
    summary: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "forward_cohort_compositional_relation_campaign",
        "relation_coverage_complete": root_counts["BLOCKED"] == 0,
        "direct_candidate_edge_count": len(candidate_edges),
        "expanded_candidate_edge_count": len(expanded),
        "composite_edge_count": len(expanded) - len(candidate_edges),
        "relation_count": len(relations),
        "relation_root_count": len(relation_roots),
        "resolved_relation_root_count": root_counts["RESOLVED"],
        "blocked_relation_root_count": root_counts["BLOCKED"],
        "relations_sha256": _sha256_json(relations),
        "relation_roots_sha256": _sha256_json(relation_roots),
        "expanded_candidates_sha256": _sha256_json(expanded),
        "relation_inventories_sha256": _sha256_json(inventory_hashes),
        "blocked_relation_root_reasons": dict(
            sorted(
                Counter(
                    str(root.get("reason") or "unspecified")
                    for root in relation_roots
                    if root.get("status") == "BLOCKED"
                ).items()
            )
        ),
        "conservation": {
            "relation_root_count": len(relation_roots),
            "resolved_relation_root_count": root_counts["RESOLVED"],
            "blocked_relation_root_count": root_counts["BLOCKED"],
            "relation_roots_conserved": (
                len(relation_roots)
                == root_counts["RESOLVED"] + root_counts["BLOCKED"]
            ),
            "candidate_edge_count": len(expanded),
            "candidate_edges_conserved": (
                route_conservation.get("candidate_edges_conserved") is True
            ),
        },
        "model_api_calls": 0,
        "model_input_tokens": 0,
        "model_output_tokens": 0,
        "model_cost_usd": 0.0,
    }
    if not summary["conservation"]["relation_roots_conserved"]:
        raise ValueError("relation roots are not conserved")
    summary["summary_sha256"] = _sha256_json(summary)
    return {
        "relations": relations,
        "relation_roots": relation_roots,
        "candidates_expanded": expanded,
        "routing_expanded": routes,
        "summary": summary,
    }


def _pull_results_for_targets(
    targets: Mapping[str, set[str]],
    units_by_repo: Mapping[str, Sequence[Mapping[str, object]]],
    repositories: Mapping[str, Path],
    *,
    fetch: bool,
    fetch_batch: int,
    timeout: int,
) -> tuple[dict[str, dict[int, dict[str, object]]], list[dict[str, object]]]:
    results: dict[str, dict[int, dict[str, object]]] = {}
    fetch_stats: list[dict[str, object]] = []
    for identity, shas in sorted(targets.items()):
        by_sha = {str(unit.get("sha") or "").lower(): unit for unit in units_by_repo[identity]}
        landed_units = [by_sha[sha] for sha in sorted(shas)]
        pr_numbers = sorted({int(unit["pr_number"]) for unit in landed_units})
        repo_path = repositories.get(identity)
        repo_results: dict[int, dict[str, object]] = {}
        if repo_path is None:
            repo_results.update(
                {
                    number: {
                        "status": "BLOCKED",
                        "members": [],
                        "reason": "no_local_clone",
                    }
                    for number in pr_numbers
                }
            )
            results[identity] = repo_results
            fetch_stats.append(
                {
                    "repository_identity": identity,
                    "requested_pr_refs": len(pr_numbers),
                    "refs_fetched": 0,
                    "fetch_error": "no_local_clone",
                }
            )
            continue

        fetched, fetch_error = (0, "")
        if fetch:
            fetched, fetch_error = fetch_pull_refs(
                repo_path, pr_numbers, batch=fetch_batch, timeout=timeout
            )
        for unit in landed_units:
            pr_number = int(unit["pr_number"])
            members = pull_members(
                repo_path,
                str(unit["sha"]),
                pr_number,
                timeout=timeout,
            )
            if members is None:
                repo_results[pr_number] = {
                    "status": "BLOCKED",
                    "members": [],
                    "reason": "no_pr_ref",
                }
            elif len(members) > MAX_PR_MEMBERS:
                repo_results[pr_number] = {
                    "status": "BLOCKED",
                    "members": members,
                    "reason": "integration_branch",
                }
            else:
                repo_results[pr_number] = {
                    "status": "RESOLVED",
                    "members": members,
                    "reason": "",
                }
        results[identity] = repo_results
        fetch_stats.append(
            {
                "repository_identity": identity,
                "requested_pr_refs": len(pr_numbers),
                "refs_fetched": fetched,
                "fetch_error": fetch_error,
            }
        )
    return results, fetch_stats


def _atomic_write_jsonl(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_write_json(path: Path, value: Mapping[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.fetch_batch < 1 or args.repo_timeout < 1:
        raise SystemExit("fetch-batch and repo-timeout must be positive")
    candidate_dir = args.candidate_dir or _latest_artifact_dir(
        "advisory-candidates-", "candidates.jsonl"
    )
    outcomes_dir = args.outcomes_dir or _latest_artifact_dir("outcomes-", "outcomes.jsonl")
    aliases = _load_aliases(args.repository_aliases)
    units_by_repo = _group_units(_load_jsonl(outcomes_dir / "outcomes.jsonl"), aliases)
    candidate_edges = _load_jsonl(candidate_dir / "candidates.jsonl")

    requested = {
        canonical_repository_identity(identity, aliases)
        for identity in args.repository
        if identity.strip()
    }
    if requested:
        candidate_edges = [
            edge
            for edge in candidate_edges
            if str(edge.get("repository_identity") or "").lower() in requested
        ]
    for edge in candidate_edges:
        identity = str(edge.get("repository_identity") or "").strip().lower()
        if canonical_repository_identity(identity, aliases) != identity:
            raise SystemExit(
                "candidate inventory predates repository canonicalization; regenerate it"
            )

    targets = _target_landed_shas(candidate_edges, units_by_repo)
    repositories, unresolved_clones = discover_local_clones(_REPO_ROOT)
    repositories = _canonical_clone_paths(repositories, aliases)
    pull_results, fetch_stats = _pull_results_for_targets(
        targets,
        units_by_repo,
        repositories,
        fetch=not args.no_fetch,
        fetch_batch=args.fetch_batch,
        timeout=args.repo_timeout,
    )
    artifacts = build_relation_campaign(candidate_edges, units_by_repo, pull_results)
    summary = dict(artifacts["summary"])
    summary.pop("summary_sha256", None)
    summary.update(
        {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "candidate_dir": str(candidate_dir),
            "candidates_sha256": _sha256_file(candidate_dir / "candidates.jsonl"),
            "outcomes_path": str(outcomes_dir / "outcomes.jsonl"),
            "outcomes_sha256": _sha256_file(outcomes_dir / "outcomes.jsonl"),
            "repository_aliases_path": str(args.repository_aliases),
            "repository_aliases_sha256": _sha256_file(args.repository_aliases),
            "selected_repositories": sorted(requested),
            "fetch_enabled": not args.no_fetch,
            "fetch_stats": fetch_stats,
            "unresolved_clone_directories": len(unresolved_clones),
            "claim_boundary": (
                "relations retain every PR-head member behind a landed-squash ancestry"
                " edge; cohort-observed origins carry metadata while unobserved origins"
                " remain conservative candidates; BLOCKED pull roots remain unknown and"
                " no direct candidate edge is removed"
            ),
        }
    )
    summary["summary_sha256"] = _sha256_json(summary)

    output_dir = args.output_dir or (
        _REPO_ROOT
        / COHORT_STATE_RELATIVE
        / f"relation-closure-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    _atomic_write_jsonl(output_dir / "relations.jsonl", artifacts["relations"])
    _atomic_write_jsonl(
        output_dir / "relation_roots.jsonl", artifacts["relation_roots"]
    )
    _atomic_write_jsonl(
        output_dir / "candidates_expanded.jsonl", artifacts["candidates_expanded"]
    )
    _atomic_write_jsonl(
        output_dir / "routing_expanded.jsonl", artifacts["routing_expanded"]
    )
    _atomic_write_json(output_dir / "summary.json", summary)

    print("\nCompositional recall closure")
    print(f"  direct edges     : {summary['direct_candidate_edge_count']:,}")
    print(f"  composite added  : {summary['composite_edge_count']:,}")
    print(f"  relation roots   : {summary['relation_root_count']:,}")
    print(f"  blocked roots    : {summary['blocked_relation_root_count']:,}")
    print("  model/API cost   : $0.00")
    print(f"  output           : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
