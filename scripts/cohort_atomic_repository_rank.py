#!/usr/bin/env python3
"""Rank uncovered repositories by active CVE/GHSA classes with direct AI ancestors."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path

from cohort.root_adjudication import canonical_sha256
from cohort_atomic_same_file_screen import _atomic_json, _atomic_jsonl, _jsonl


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alias-classes", type=Path, required=True)
    parser.add_argument("--ai-commits", type=Path, required=True)
    parser.add_argument("--expanded-candidates", type=Path, required=True)
    parser.add_argument("--fix-source-observations", type=Path, required=True)
    parser.add_argument(
        "--exclude-repositories", type=Path, action="append", default=[]
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def rank_repositories(
    aliases: Iterable[Mapping[str, object]],
    ai_commits: Iterable[Mapping[str, object]],
    candidates: Iterable[Mapping[str, object]],
    fix_observations: Iterable[Mapping[str, object]],
    *,
    excluded: set[str],
) -> list[dict[str, object]]:
    alias_by_id = {
        str(public_id).upper(): str(row["class_id"])
        for row in aliases
        if any(
            str(public_id).upper().startswith(("CVE-", "GHSA-"))
            for public_id in row.get("member_ids", [])
        )
        for public_id in row.get("member_ids", [])
    }
    public_exact = {
        (
            str(row.get("repository_identity") or ""),
            alias_by_id[str(row.get("advisory") or "").upper()],
            str(row.get("fix_sha") or "").lower(),
        )
        for row in fix_observations
        if row.get("resolution_status") == "RESOLVED"
        and row.get("evidence_kind") == "public_exact"
        and str(row.get("advisory") or "").upper() in alias_by_id
    }
    direct_units: set[tuple[str, str]] = set()
    paths: defaultdict[str, set[str]] = defaultdict(set)
    for row in ai_commits:
        identity = str(row.get("repository_identity") or "")
        sha = str(row.get("sha") or "").lower()
        if (
            identity in excluded
            or row.get("merge_topology") != "direct"
            or not row.get("signal_types")
            or not sha
        ):
            continue
        direct_units.add((identity, sha))
        paths[identity].update(
            str(value) for value in row.get("observed_in_clone_paths", []) if str(value)
        )

    classes: defaultdict[str, set[str]] = defaultdict(set)
    shas: defaultdict[str, set[str]] = defaultdict(set)
    fixes: defaultdict[str, set[str]] = defaultdict(set)
    edges: defaultdict[str, int] = defaultdict(int)
    for row in candidates:
        identity = str(row.get("repository_identity") or "")
        sha = str(row.get("candidate_sha") or "").lower()
        fix_sha = str(row.get("fix_sha") or "").lower()
        if (
            row.get("relation") != "reachable_ancestor"
            or (identity, sha) not in direct_units
        ):
            continue
        class_ids = {
            alias_by_id[str(advisory.get("id") or "").upper()]
            for advisory in row.get("advisories", [])
            if isinstance(advisory, Mapping)
            and str(advisory.get("id") or "").upper() in alias_by_id
        }
        class_ids = {
            class_id
            for class_id in class_ids
            if (identity, class_id, fix_sha) in public_exact
        }
        if not class_ids:
            continue
        classes[identity].update(class_ids)
        shas[identity].add(sha)
        fixes[identity].add(fix_sha)
        edges[identity] += 1

    rows = [
        {
            "repository_identity": identity,
            "repository_paths": sorted(paths[identity]),
            "alias_class_count": len(class_ids),
            "direct_ai_candidate_count": len(shas[identity]),
            "fix_count": len(fixes[identity]),
            "source_edge_count": edges[identity],
        }
        for identity, class_ids in classes.items()
    ]
    rows.sort(
        key=lambda row: (
            -int(row["alias_class_count"]),
            -int(row["direct_ai_candidate_count"]),
            str(row["repository_identity"]),
        )
    )
    for rank, row in enumerate(rows, start=1):
        row["rank"] = rank
    return rows


def main() -> int:
    args = _parse_args()
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    excluded = {
        str(row["repository_identity"])
        for source in args.exclude_repositories
        for row in json.loads(source.read_text(encoding="utf-8"))
    }
    rows = rank_repositories(
        _jsonl(args.alias_classes),
        _jsonl(args.ai_commits),
        _jsonl(args.expanded_candidates),
        _jsonl(args.fix_source_observations),
        excluded=excluded,
    )
    args.output_dir.mkdir(parents=True)
    _atomic_jsonl(args.output_dir / "repositories.jsonl", rows)
    summary = {
        "schema_version": 1,
        "artifact_kind": "uncovered_direct_ai_repository_ranking",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "excluded_repository_count": len(excluded),
        "ranked_repository_count": len(rows),
        "alias_class_sum_before_cross_repository_deduplication": sum(
            int(row["alias_class_count"]) for row in rows
        ),
        "repositories_sha256": canonical_sha256(rows),
        "claim_boundary": "selection ranking only; repository classes and candidates remain unadjudicated",
    }
    _atomic_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
