#!/usr/bin/env python3
"""Route advisory edges to explicitly AI-attributed atomic commits in the same file."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path

from cohort.fix_manifest import normalize_fix_manifest
from cohort.root_adjudication import canonical_sha256
from cve_analyzer.git_ops import run_git


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alias-classes", type=Path, required=True)
    parser.add_argument("--fix-roots", type=Path, required=True)
    parser.add_argument("--fix-source-observations", type=Path, required=True)
    parser.add_argument("--ai-commits", type=Path, required=True)
    parser.add_argument("--expanded-candidates", type=Path, required=True)
    parser.add_argument("--relations", type=Path, required=True)
    parser.add_argument("--repository-identity", required=True)
    parser.add_argument("--repository-path", type=Path, required=True)
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--frozen-at", required=True)
    parser.add_argument("--repo-timeout", type=int, default=30)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def _jsonl(path: Path) -> Iterable[dict[str, object]]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise SystemExit(f"{path}:{line_number} is not an object")
            yield row


def _atomic_json(path: Path, value: object) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _atomic_jsonl(path: Path, rows: Iterable[Mapping[str, object]]) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _fix_files(repo: Path, sha: str, *, timeout: int) -> tuple[str, ...]:
    completed = run_git(
        ["git", "-C", str(repo), "diff", "--name-only", f"{sha}^", sha],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        no_lazy_fetch=True,
    )
    if completed.returncode != 0:
        raise ValueError(str(completed.stderr or "git diff failed").strip()[:300])
    return tuple(sorted({line.strip() for line in completed.stdout.splitlines() if line.strip()}))


def build_same_file_rows(
    edges: Iterable[Mapping[str, object]],
    *,
    repository_identity: str,
    aliases_by_id: Mapping[str, str],
    alias_rows: Mapping[str, Mapping[str, object]],
    ai_units: Mapping[str, Mapping[str, object]],
    relations_by_id: Mapping[str, Mapping[str, object]],
    fix_files: Mapping[str, tuple[str, ...]],
    allowed_class_fixes: set[tuple[str, str]],
) -> list[dict[str, object]]:
    """Keep only atomic AI commits with a source edge and a changed-file overlap."""

    rows: dict[tuple[str, str, str, str], dict[str, object]] = {}
    composite_relation = "pull_request_member_landed_as_squash_then_reachable_ancestor"
    for edge in edges:
        if edge.get("repository_identity") != repository_identity:
            continue
        candidate_sha = str(edge.get("candidate_sha") or "").lower()
        fix_sha = str(edge.get("fix_sha") or "").lower()
        unit = ai_units.get(candidate_sha)
        if unit is None or fix_sha not in fix_files:
            continue
        relation = str(edge.get("relation") or "")
        relation_id = str(edge.get("origin_relation_id") or "")
        landed_sha = ""
        if relation == "reachable_ancestor":
            if unit.get("merge_topology") != "direct":
                continue
        elif relation == composite_relation:
            origin_relation = relations_by_id.get(relation_id)
            if (
                origin_relation is None
                or origin_relation.get("origin_sha") != candidate_sha
                or origin_relation.get("origin_observed_in_cohort") is not True
            ):
                continue
            landed_sha = str(origin_relation.get("landed_sha") or "").lower()
        else:
            continue

        candidate_files = tuple(sorted(str(value) for value in unit.get("changed_files", [])))
        overlap = tuple(sorted(set(candidate_files) & set(fix_files[fix_sha])))
        if not overlap:
            continue
        advisory_ids = sorted(
            {
                str(item.get("id") or "").upper()
                for item in edge.get("advisories", [])
                if isinstance(item, Mapping) and item.get("id")
            }
        )
        class_ids = sorted(
            {aliases_by_id[value] for value in advisory_ids if value in aliases_by_id}
        )
        for class_id in class_ids:
            if (class_id, fix_sha) not in allowed_class_fixes:
                continue
            alias = alias_rows[class_id]
            key = (class_id, fix_sha, candidate_sha, landed_sha)
            rows[key] = {
                "class_id": class_id,
                "analysis_subject": alias["analysis_subject"],
                "member_ids": alias["member_ids"],
                "advisory_ids_on_edge": advisory_ids,
                "repository_identity": repository_identity,
                "fix_sha": fix_sha,
                "fix_changed_files": list(fix_files[fix_sha]),
                "candidate_sha": candidate_sha,
                "candidate_changed_files": list(candidate_files),
                "overlapping_files": list(overlap),
                "ai_signal_types": unit.get("signal_types", []),
                "ai_tools": unit.get("tools", []),
                "relation": relation,
                "landed_squash_sha": landed_sha,
                "relation_pr_number": edge.get("relation_pr_number"),
                "origin_relation_id": relation_id,
                "source_edge_id": edge.get("edge_id"),
                "claim_boundary": "same-file routing evidence only; not a causal adjudication",
            }
    return [rows[key] for key in sorted(rows)]


def main() -> int:
    args = _parse_args()
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if args.repo_timeout < 1:
        raise SystemExit("repo-timeout must be positive")
    if not (args.repository_path / ".git").is_dir():
        raise SystemExit("repository-path is not a Git checkout")

    alias_rows = {str(row["class_id"]): row for row in _jsonl(args.alias_classes)}
    aliases_by_id = {
        str(public_id).upper(): class_id
        for class_id, row in alias_rows.items()
        for public_id in row.get("member_ids", [])
    }
    ai_units = {
        str(row["sha"]).lower(): row
        for row in _jsonl(args.ai_commits)
        if row.get("repository_identity") == args.repository_identity
        and row.get("merge_topology") == "direct"
        and row.get("signal_types")
    }
    relations_by_id = {
        str(row["relation_id"]): row
        for row in _jsonl(args.relations)
        if row.get("repository_identity") == args.repository_identity
    }

    manifest_rows: set[tuple[str, str, str]] = set()
    unmatched_ids: set[str] = set()
    status_counts: Counter[str] = Counter()
    for root in _jsonl(args.fix_roots):
        if root.get("repository_identity") != args.repository_identity:
            continue
        status = str(root.get("status") or "")
        status_counts[status] += 1
        ids = {
            str(item.get("id") or "").upper()
            for item in root.get("advisories", [])
            if isinstance(item, Mapping) and item.get("id")
        }
        unmatched_ids.update(value for value in ids if value not in aliases_by_id)

    exact_observation_count = 0
    for observation in _jsonl(args.fix_source_observations):
        if (
            observation.get("repository_identity") != args.repository_identity
            or observation.get("resolution_status") != "RESOLVED"
            or observation.get("evidence_kind") != "public_exact"
        ):
            continue
        exact_observation_count += 1
        public_id = str(observation.get("advisory") or "").upper()
        if public_id not in aliases_by_id:
            unmatched_ids.add(public_id)
            continue
        manifest_rows.add(
            (
                aliases_by_id[public_id],
                args.repository_identity,
                str(observation["fix_sha"]).lower(),
            )
        )

    manifest = normalize_fix_manifest(
        {
            "schema_version": 1,
            "artifact_kind": "sealed_fix_manifest",
            "split_id": args.split_id,
            "frozen_at": args.frozen_at,
            "fixes": [
                {"advisory": advisory, "repository_identity": identity, "fix_sha": fix_sha}
                for advisory, identity, fix_sha in sorted(manifest_rows)
            ],
        },
        {},
    )
    files_by_fix: dict[str, tuple[str, ...]] = {}
    blocked_fixes: dict[str, str] = {}
    for _, _, fix_sha in sorted(manifest_rows):
        if fix_sha in files_by_fix or fix_sha in blocked_fixes:
            continue
        try:
            files_by_fix[fix_sha] = _fix_files(
                args.repository_path, fix_sha, timeout=args.repo_timeout
            )
        except (OSError, ValueError) as exc:
            blocked_fixes[fix_sha] = str(exc)

    rows = build_same_file_rows(
        _jsonl(args.expanded_candidates),
        repository_identity=args.repository_identity,
        aliases_by_id=aliases_by_id,
        alias_rows=alias_rows,
        ai_units=ai_units,
        relations_by_id=relations_by_id,
        fix_files=files_by_fix,
        allowed_class_fixes={
            (class_id, fix_sha) for class_id, _, fix_sha in manifest_rows
        },
    )
    args.output_dir.mkdir(parents=True)
    units = [ai_units[sha] for sha in sorted(ai_units)]
    _atomic_json(args.output_dir / "fix-manifest.json", manifest)
    _atomic_jsonl(args.output_dir / "atomic-ai-units.jsonl", units)
    _atomic_jsonl(args.output_dir / "same-file-candidates.jsonl", rows)
    summary = {
        "schema_version": 1,
        "artifact_kind": "atomic_ai_same_file_advisory_screen",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "split_id": args.split_id,
        "repository_identity": args.repository_identity,
        "fix_root_status_counts": dict(sorted(status_counts.items())),
        "public_exact_fix_observation_count": exact_observation_count,
        "manifest_row_count": len(manifest["fixes"]),
        "resolved_unique_fix_count": len(files_by_fix),
        "blocked_fix_file_inventory": blocked_fixes,
        "unmatched_public_ids": sorted(unmatched_ids),
        "atomic_ai_unit_count": len(units),
        "resolved_relation_count": len(relations_by_id),
        "same_file_candidate_count": len(rows),
        "same_file_alias_class_count": len({row["class_id"] for row in rows}),
        "same_file_fix_count": len({row["fix_sha"] for row in rows}),
        "same_file_ai_unit_count": len({row["candidate_sha"] for row in rows}),
        "fix_manifest_sha256": canonical_sha256(manifest),
        "atomic_ai_units_sha256": canonical_sha256(units),
        "same_file_candidates_sha256": canonical_sha256(rows),
        "claim_boundary": (
            "Only direct commits with an explicit AI signal are treated as atomic AI units. "
            "Squash carriers are excluded; their observed AI PR members enter only through "
            "a resolved pull-member relation. Same-file overlap is routing evidence, not causality."
        ),
    }
    _atomic_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
