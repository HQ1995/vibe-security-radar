#!/usr/bin/env python3
"""Rank direct AI ancestors that can bridge to a public fix across files."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path

from cohort.origin_packets import fold_candidate_fix_pairs, packetize_candidate_units
from cohort.root_adjudication import canonical_sha256
from cohort_atomic_mechanism_review import _FEATURE_SUBJECT_RE, _is_code_path
from cohort_atomic_same_file_screen import (
    _atomic_json,
    _atomic_jsonl,
    _fix_files,
    _jsonl,
)
from cve_analyzer.git_ops import run_git


_GENERIC_TOKENS = {
    "api",
    "app",
    "apps",
    "client",
    "common",
    "core",
    "index",
    "internal",
    "lib",
    "main",
    "package",
    "packages",
    "pkg",
    "server",
    "source",
    "src",
}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repositories", type=Path, required=True)
    parser.add_argument("--partitioned-dir", type=Path, required=True)
    parser.add_argument("--same-file-dir", type=Path, required=True)
    parser.add_argument("--alias-classes", type=Path, required=True)
    parser.add_argument("--max-candidates-per-class", type=int, default=4)
    parser.add_argument("--repo-timeout", type=int, default=60)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def _tokens(values: Iterable[str]) -> set[str]:
    return {
        token
        for value in values
        for token in re.findall(r"[a-z0-9]+", value.lower())
        if len(token) > 2 and token not in _GENERIC_TOKENS
    }


def _timestamp(value: object) -> float:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def rank_cross_file_rows(
    edges: Iterable[Mapping[str, object]],
    *,
    repository_identity: str,
    aliases_by_id: Mapping[str, str],
    allowed_class_fixes: set[tuple[str, str]],
    units: Mapping[str, Mapping[str, object]],
    fix_files: Mapping[str, tuple[str, ...]],
    fix_subjects: Mapping[str, str],
    max_per_class: int,
) -> list[dict[str, object]]:
    """Keep bounded feature/path bridges without treating them as findings."""

    grouped: defaultdict[tuple[str, str], dict[str, dict[str, object]]] = defaultdict(
        dict
    )
    for edge in edges:
        if (
            edge.get("repository_identity") != repository_identity
            or edge.get("relation") != "reachable_ancestor"
        ):
            continue
        candidate_sha = str(edge.get("candidate_sha") or "").lower()
        fix_sha = str(edge.get("fix_sha") or "").lower()
        unit = units.get(candidate_sha)
        if (
            unit is None
            or unit.get("merge_topology") != "direct"
            or not unit.get("signal_types")
        ):
            continue
        candidate_files = sorted(
            path
            for path in {str(value) for value in unit.get("changed_files", [])}
            if _is_code_path(path)
        )
        fixed_files = sorted(
            path for path in fix_files.get(fix_sha, ()) if _is_code_path(path)
        )
        if (
            not candidate_files
            or not fixed_files
            or set(candidate_files) & set(fixed_files)
        ):
            continue
        subject = str(unit.get("message") or "").partition("\n")[0]
        feature = bool(_FEATURE_SUBJECT_RE.match(subject))
        path_bridge = _tokens(candidate_files) & _tokens(fixed_files)
        subject_bridge = _tokens([subject]) & _tokens(
            [*fixed_files, fix_subjects.get(fix_sha, "")]
        )
        if not (feature or path_bridge or subject_bridge):
            continue
        class_ids = {
            aliases_by_id[str(item.get("id") or "").upper()]
            for item in edge.get("advisories", [])
            if isinstance(item, Mapping)
            and str(item.get("id") or "").upper() in aliases_by_id
        }
        signals = ["observed_ai_reachable_ancestor"]
        if feature:
            signals.append("feature_introduction")
        if path_bridge:
            signals.append("cross_file_path_token_bridge")
        if subject_bridge:
            signals.append("cross_file_subject_bridge")
        score = (
            3 * feature + 4 * min(3, len(path_bridge)) + 2 * min(3, len(subject_bridge))
        )
        for class_id in class_ids:
            if (class_id, fix_sha) not in allowed_class_fixes:
                continue
            grouped[(class_id, fix_sha)][candidate_sha] = {
                "advisory": class_id,
                "repository_identity": repository_identity,
                "fix_sha": fix_sha,
                "sha": candidate_sha,
                "retained": True,
                "observed_ai_unit": True,
                "ancestry_certificate": "reachable_ancestor_from_source_edge",
                "materialization": "bounded_cross_file_feature_or_path_bridge",
                "signals": signals,
                "fix_file_overlap": [],
                "fix_file_overlap_count": 0,
                "priority_score": score,
                "candidate_path_tokens": sorted(path_bridge),
                "candidate_subject_tokens": sorted(subject_bridge),
                "authored_date": unit.get("authored_date", ""),
                "changed_files": candidate_files,
                "code_files_changed": len(candidate_files),
                "commit_subject": subject,
                "merge_topology": "direct",
                "pr_number": unit.get("pr_number"),
                "signal_types": unit.get("signal_types", []),
                "source_modules": unit.get("source_modules", []),
                "agent_kinds": unit.get("agent_kinds", []),
                "tools": unit.get("tools", []),
            }

    rows: list[dict[str, object]] = []
    for key in sorted(grouped):
        candidates = sorted(
            grouped[key].values(),
            key=lambda row: (
                -int(row["priority_score"]),
                -_timestamp(row["authored_date"]),
                str(row["sha"]),
            ),
        )[:max_per_class]
        for priority_rank, row in enumerate(candidates, start=1):
            row["priority_rank"] = priority_rank
            rows.append(row)
    return rows


def _fix_subject(repo: Path, sha: str, timeout: int) -> str:
    result = run_git(
        ["git", "-C", str(repo), "show", "-s", "--format=%s", sha],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        no_lazy_fetch=True,
    )
    if result.returncode != 0:
        raise ValueError(str(result.stderr or "git show failed").strip()[:300])
    return str(result.stdout or "").strip()


def main() -> int:
    args = _parse_args()
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if min(args.max_candidates_per_class, args.repo_timeout) < 1:
        raise SystemExit("bounds must be positive")
    repositories = json.loads(args.repositories.read_text(encoding="utf-8"))
    alias_rows = list(_jsonl(args.alias_classes))
    aliases_by_id = {
        str(value).upper(): str(row["class_id"])
        for row in alias_rows
        for value in row.get("member_ids", [])
    }
    candidate_rows: list[dict[str, object]] = []
    fix_rows: dict[tuple[str, str, str], dict[str, object]] = {}
    blocked_fixes: dict[str, str] = {}
    source_edge_count = 0
    for metadata in repositories:
        slug = str(metadata["slug"])
        identity = str(metadata["repository_identity"])
        repo = Path(str(metadata["repository_path"]))
        same_dir = args.same_file_dir / slug
        if not same_dir.is_dir() or not (repo / ".git").is_dir():
            continue
        manifest = json.loads(
            (same_dir / "fix-manifest.json").read_text(encoding="utf-8")
        )
        allowed = {
            (str(row["advisory"]), str(row["fix_sha"])) for row in manifest["fixes"]
        }
        files_by_fix: dict[str, tuple[str, ...]] = {}
        subjects_by_fix: dict[str, str] = {}
        for _, fix_sha in sorted(allowed):
            if fix_sha in files_by_fix or fix_sha in blocked_fixes:
                continue
            try:
                files_by_fix[fix_sha] = _fix_files(
                    repo, fix_sha, timeout=args.repo_timeout
                )
                subjects_by_fix[fix_sha] = _fix_subject(
                    repo, fix_sha, args.repo_timeout
                )
            except (OSError, ValueError) as exc:
                blocked_fixes[f"{identity}@{fix_sha}"] = str(exc)
        units = {
            str(row["sha"]): row for row in _jsonl(same_dir / "atomic-ai-units.jsonl")
        }
        edge_path = args.partitioned_dir / slug / "expanded-candidates.jsonl"
        edges = list(_jsonl(edge_path))
        source_edge_count += len(edges)
        ranked = rank_cross_file_rows(
            edges,
            repository_identity=identity,
            aliases_by_id=aliases_by_id,
            allowed_class_fixes=allowed,
            units=units,
            fix_files=files_by_fix,
            fix_subjects=subjects_by_fix,
            max_per_class=args.max_candidates_per_class,
        )
        candidate_rows.extend(ranked)
        for row in ranked:
            key = (str(row["advisory"]), identity, str(row["fix_sha"]))
            fix_rows[key] = {
                "advisory": key[0],
                "repository_identity": identity,
                "fix_sha": key[2],
                "repository_path": str(repo),
                "status": "RESOLVED",
                "reason": "",
            }

    candidate_rows.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["advisory"]),
            str(row["fix_sha"]),
            int(row["priority_rank"]),
            str(row["sha"]),
        )
    )
    fixes = [fix_rows[key] for key in sorted(fix_rows)]
    generated_dir = args.output_dir / "generated"
    packet_dir = args.output_dir / "packets"
    generated_dir.mkdir(parents=True)
    packet_dir.mkdir()
    summary = {
        "schema_version": 1,
        "artifact_kind": "atomic_ai_cross_file_candidate_ranking",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_edge_count": source_edge_count,
        "candidate_pair_count": len(candidate_rows),
        "candidate_class_count": len({row["advisory"] for row in candidate_rows}),
        "candidate_repository_count": len(
            {row["repository_identity"] for row in candidate_rows}
        ),
        "fix_count": len(fixes),
        "blocked_fixes": blocked_fixes,
        "max_candidates_per_class": args.max_candidates_per_class,
        "candidate_rows_sha256": canonical_sha256(candidate_rows),
        "fix_rows_sha256": canonical_sha256(fixes),
        "claim_boundary": (
            "bounded direct-AI cross-file ranking only; unselected source edges remain DEFER, "
            "squash carriers are excluded, and model promotion is not final causality"
        ),
    }
    _atomic_jsonl(generated_dir / "candidates.jsonl", candidate_rows)
    _atomic_jsonl(generated_dir / "fixes.jsonl", fixes)
    _atomic_json(generated_dir / "summary.json", summary)
    units = fold_candidate_fix_pairs(candidate_rows)
    packets = packetize_candidate_units(
        units, max_candidates=args.max_candidates_per_class
    )
    packet_summary = {
        "schema_version": 2,
        "artifact_kind": "lossless_origin_candidate_packets",
        "parent_generation_sha256": canonical_sha256(summary),
        "candidate_inventory_sha256": canonical_sha256(candidate_rows),
        "candidate_fix_pair_count": len(candidate_rows),
        "candidate_unit_count": len(units),
        "packet_count": len(packets),
        "max_candidates_per_packet": args.max_candidates_per_class,
        "candidate_units_sha256": canonical_sha256(units),
        "packets_sha256": canonical_sha256(packets),
        "all_fix_edges_conserved": sum(int(row["fix_edge_count"]) for row in units)
        == len(candidate_rows),
        "all_candidate_units_assigned_once": sum(
            int(row["candidate_count"]) for row in packets
        )
        == len(units),
        "negative_disposition": "DEFER_not_delete",
        "missing_response_disposition": "BLOCKED_split_and_retry",
        "squash_relation_closure_applied": False,
    }
    _atomic_jsonl(packet_dir / "candidate_units.jsonl", units)
    _atomic_jsonl(packet_dir / "packets.jsonl", packets)
    _atomic_json(packet_dir / "summary.json", packet_summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
