#!/usr/bin/env python3
"""Verify recovered squash members and route exact-fix same-file pairs."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path

from cohort.relations import COMPOSITE_RELATION
from cohort.repos import discover_local_clones
from cohort.root_adjudication import canonical_sha256
from cohort_atomic_same_file_screen import _atomic_json, _atomic_jsonl, _jsonl
from cohort_origin_squash_expand import _commit_records, _diff_metadata, _member_metadata


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alias-classes", type=Path, required=True)
    parser.add_argument("--fix-source-observations", type=Path, required=True)
    parser.add_argument("--relation-dir", type=Path, required=True)
    parser.add_argument("--repositories", type=Path)
    parser.add_argument("--repo-timeout", type=int, default=120)
    parser.add_argument("--multi-member-only", action="store_true")
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def _repository_paths(path: Path) -> dict[str, Path]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise SystemExit("repositories must be a JSON array")
    result: dict[str, Path] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise SystemExit("repository row is malformed")
        identity = str(row.get("repository_identity") or "")
        repo = Path(str(row.get("repository_path") or ""))
        if not identity or not (repo / ".git").is_dir() or identity in result:
            raise SystemExit(f"invalid repository row: {identity}")
        result[identity] = repo
    return result


def screen_rows(
    candidates: Iterable[Mapping[str, object]],
    *,
    relations: Mapping[str, Mapping[str, object]],
    roots: Mapping[tuple[str, str], Mapping[str, object]],
    aliases_by_id: Mapping[str, str],
    alias_rows: Mapping[str, Mapping[str, object]],
    public_exact: set[tuple[str, str, str]],
    member_metadata: Mapping[tuple[str, str], Mapping[str, object]],
    diff_metadata: Mapping[tuple[str, str], Mapping[str, object]],
    multi_member_only: bool = False,
) -> tuple[list[dict[str, object]], Counter[str]]:
    rows: dict[tuple[str, str, str], dict[str, object]] = {}
    excluded: Counter[str] = Counter()
    for edge in candidates:
        if edge.get("relation") != COMPOSITE_RELATION:
            continue
        identity = str(edge.get("repository_identity") or "")
        candidate_sha = str(edge.get("candidate_sha") or "").lower()
        fix_sha = str(edge.get("fix_sha") or "").lower()
        landed_sha = str(edge.get("landed_sha") or "").lower()
        relation_id = str(edge.get("origin_relation_id") or "")
        relation = relations.get(relation_id)
        root = roots.get((identity, landed_sha))
        eligible_origin_count = root.get("eligible_origin_count") if root else None
        expected_member_count = (
            isinstance(eligible_origin_count, int)
            and (eligible_origin_count > 1 if multi_member_only else eligible_origin_count == 1)
        )
        if (
            relation is None
            or relation.get("repository_identity") != identity
            or relation.get("origin_sha") != candidate_sha
            or relation.get("landed_sha") != landed_sha
            or root is None
            or root.get("status") != "RESOLVED"
            or not expected_member_count
        ):
            scope = "multi" if multi_member_only else "single"
            excluded[f"relation_not_{scope}_member_resolved"] += 1
            continue
        member = member_metadata.get((identity, candidate_sha))
        member_diff = diff_metadata.get((identity, candidate_sha))
        fix_diff = diff_metadata.get((identity, fix_sha))
        if member is None or member.get("observed_ai_unit") is not True:
            excluded["member_has_no_direct_ai_signal"] += 1
            continue
        if member_diff is None or fix_diff is None:
            excluded["diff_metadata_missing"] += 1
            continue
        candidate_files = sorted(str(value) for value in member_diff.get("changed_files", []))
        fix_files = sorted(str(value) for value in fix_diff.get("changed_files", []))
        overlap = sorted(set(candidate_files) & set(fix_files))
        if not overlap:
            excluded["no_same_file_overlap"] += 1
            continue
        advisory_ids = sorted(
            {
                str(row.get("id") or "").upper()
                for row in edge.get("advisories", [])
                if isinstance(row, Mapping) and row.get("id")
            }
        )
        class_ids = sorted(
            {
                aliases_by_id[public_id]
                for public_id in advisory_ids
                if public_id in aliases_by_id
                and (identity, aliases_by_id[public_id], fix_sha) in public_exact
            }
        )
        for class_id in class_ids:
            alias = alias_rows[class_id]
            key = (class_id, fix_sha, candidate_sha)
            rows[key] = {
                "class_id": class_id,
                "analysis_subject": alias["analysis_subject"],
                "member_ids": alias["member_ids"],
                "advisory_ids_on_edge": advisory_ids,
                "repository_identity": identity,
                "fix_sha": fix_sha,
                "fix_changed_files": fix_files,
                "candidate_sha": candidate_sha,
                "candidate_changed_files": candidate_files,
                "overlapping_files": overlap,
                "ai_signal_types": member.get("signal_types", []),
                "ai_tools": member.get("tools", []),
                "relation": COMPOSITE_RELATION,
                "landed_squash_sha": landed_sha,
                "relation_pr_number": relation.get("pr_number"),
                "origin_relation_id": relation_id,
                "source_edge_id": edge.get("edge_id"),
                "claim_boundary": (
                    "verified direct AI signal on a recovered PR member plus "
                    "same-file public-exact fix overlap; mechanism review still required"
                ),
            }
    return [rows[key] for key in sorted(rows)], excluded


def carrier_same_file_rows(
    candidates: Iterable[Mapping[str, object]],
    diff_metadata: Mapping[tuple[str, str], Mapping[str, object]],
) -> tuple[list[Mapping[str, object]], Counter[str], list[dict[str, str]]]:
    """Apply a lossless necessary condition before reading every PR member."""

    rows: list[Mapping[str, object]] = []
    excluded: Counter[str] = Counter()
    blocked: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in candidates:
        if row.get("relation") != COMPOSITE_RELATION:
            continue
        identity = str(row.get("repository_identity") or "")
        landed_sha = str(row.get("landed_sha") or "").lower()
        fix_sha = str(row.get("fix_sha") or "").lower()
        carrier = diff_metadata.get((identity, landed_sha))
        fix = diff_metadata.get((identity, fix_sha))
        if carrier is None or fix is None:
            excluded["carrier_or_fix_diff_metadata_missing"] += 1
            blocked[(identity, landed_sha, fix_sha)] = {
                "repository_identity": identity,
                "landed_sha": landed_sha,
                "fix_sha": fix_sha,
                "reason": "carrier_or_fix_diff_metadata_missing",
            }
            continue
        if set(carrier.get("changed_files", [])) & set(fix.get("changed_files", [])):
            rows.append(row)
        else:
            excluded["carrier_has_no_same_file_overlap"] += 1
    return rows, excluded, [blocked[key] for key in sorted(blocked)]


def main() -> int:
    args = _parse_args()
    if args.output_dir.exists() or args.repo_timeout < 1:
        raise SystemExit("output directory must be new and timeout positive")
    if args.repositories:
        repositories = _repository_paths(args.repositories)
    else:
        repositories, _ = discover_local_clones(Path(__file__).resolve().parents[1])
    alias_rows = {str(row["class_id"]): row for row in _jsonl(args.alias_classes)}
    aliases_by_id = {
        str(public_id).upper(): class_id
        for class_id, row in alias_rows.items()
        for public_id in row.get("member_ids", [])
    }
    public_exact = {
        (
            str(row.get("repository_identity") or ""),
            aliases_by_id[str(row.get("advisory") or "").upper()],
            str(row.get("fix_sha") or "").lower(),
        )
        for row in _jsonl(args.fix_source_observations)
        if row.get("resolution_status") == "RESOLVED"
        and row.get("evidence_kind") == "public_exact"
        and str(row.get("advisory") or "").upper() in aliases_by_id
    }
    candidates = list(_jsonl(args.relation_dir / "candidates_expanded.jsonl"))
    relations = {
        str(row["relation_id"]): row
        for row in _jsonl(args.relation_dir / "relations.jsonl")
    }
    roots = {
        (str(row["repository_identity"]), str(row["landed_sha"]).lower()): row
        for row in _jsonl(args.relation_dir / "relation_roots.jsonl")
    }
    carrier_required: defaultdict[str, set[str]] = defaultdict(set)
    for row in candidates:
        if row.get("relation") != COMPOSITE_RELATION:
            continue
        identity = str(row.get("repository_identity") or "")
        carrier_required[identity].update(
            (str(row.get("landed_sha") or "").lower(), str(row.get("fix_sha") or "").lower())
        )

    diff_metadata: dict[tuple[str, str], dict[str, object]] = {}
    blocked_repositories: dict[str, str] = {}
    for identity in sorted(carrier_required):
        repo = repositories.get(identity)
        if repo is None:
            blocked_repositories[identity] = "no_repository_path"
            continue
        for sha, value in _diff_metadata(
            repo, sorted(carrier_required[identity]), timeout=args.repo_timeout
        ).items():
            diff_metadata[(identity, sha)] = value

    routed_candidates, prefilter_exclusions, prefilter_blocked = carrier_same_file_rows(
        candidates, diff_metadata
    )
    required: defaultdict[str, set[str]] = defaultdict(set)
    for row in routed_candidates:
        identity = str(row.get("repository_identity") or "")
        required[identity].update(
            (str(row.get("candidate_sha") or "").lower(), str(row.get("fix_sha") or "").lower())
        )

    member_metadata: dict[tuple[str, str], dict[str, object]] = {}
    for identity in sorted(required):
        repo = repositories.get(identity)
        if repo is None:
            continue
        member_shas = sorted(
            {
                str(row.get("candidate_sha") or "").lower()
                for row in routed_candidates
                if row.get("repository_identity") == identity
            }
        )
        records = _commit_records(repo, member_shas, timeout=args.repo_timeout)
        metadata = _diff_metadata(repo, member_shas, timeout=args.repo_timeout)
        for sha, record in records.items():
            member = _member_metadata(record)
            member["message"] = record.message
            member_metadata[(identity, sha)] = member
        for sha, value in metadata.items():
            diff_metadata[(identity, sha)] = value

    rows, exclusions = screen_rows(
        routed_candidates,
        relations=relations,
        roots=roots,
        aliases_by_id=aliases_by_id,
        alias_rows=alias_rows,
        public_exact=public_exact,
        member_metadata=member_metadata,
        diff_metadata=diff_metadata,
        multi_member_only=args.multi_member_only,
    )
    exclusions.update(prefilter_exclusions)
    selected_shas = {(row["repository_identity"], row["candidate_sha"]) for row in rows}
    units = [
        {
            **dict(member_metadata[(identity, sha)]),
            **dict(diff_metadata[(identity, sha)]),
            "repository_identity": identity,
            "sha": sha,
            "origin_kind": "pull_request_member",
        }
        for identity, sha in sorted(selected_shas)
    ]
    args.output_dir.mkdir(parents=True)
    _atomic_json(
        args.output_dir / "repositories.json",
        [
            {
                "repository_identity": identity,
                "repository_path": str(path),
                "slug": f"repo-{index}",
            }
            for index, (identity, path) in enumerate(sorted(repositories.items()), start=1)
            if identity in required
        ],
    )
    _atomic_jsonl(args.output_dir / "same-file-candidates.jsonl", rows)
    _atomic_jsonl(args.output_dir / "atomic-ai-units.jsonl", units)
    _atomic_jsonl(args.output_dir / "carrier-prefilter-blocked.jsonl", prefilter_blocked)
    summary = {
        "schema_version": 1,
        "artifact_kind": "verified_atomic_squash_member_same_file_screen",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "repository_count": len(required),
        "blocked_repositories": blocked_repositories,
        "composite_candidate_edge_count": sum(
            row.get("relation") == COMPOSITE_RELATION for row in candidates
        ),
        "carrier_same_file_edge_count": len(routed_candidates),
        "carrier_prefilter_blocked_pair_count": len(prefilter_blocked),
        "verified_member_count": len(member_metadata),
        "direct_ai_member_count": sum(
            row.get("observed_ai_unit") is True for row in member_metadata.values()
        ),
        "same_file_candidate_count": len(rows),
        "same_file_alias_class_count": len({row["class_id"] for row in rows}),
        "same_file_member_count": len(selected_shas),
        "member_scope": "multi_member_only" if args.multi_member_only else "single_member_only",
        "exclusion_counts": dict(sorted(exclusions.items())),
        "same_file_candidates_sha256": canonical_sha256(rows),
        "atomic_ai_units_sha256": canonical_sha256(units),
        "claim_boundary": (
            "every retained origin is a recovered PR member and carries its own "
            "direct AI signal; same-file overlap is routing evidence, not causality"
        ),
    }
    _atomic_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
