#!/usr/bin/env python3
"""Freeze semantic packets for selected direct merge-member repair leads."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from pathlib import Path

from cohort_coolify_exact_delta_review_packet import (
    _atomic_json,
    _load_json,
    _load_jsonl,
    _sha256,
    build_packet,
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--topology-overlay-dir", type=Path, required=True)
    parser.add_argument(
        "--edge",
        action="append",
        required=True,
        help="candidate-prefix:member-prefix; repeat to preserve review order",
    )
    parser.add_argument("--context-lines", type=int, default=5)
    parser.add_argument("--max-paths", type=int, default=3)
    parser.add_argument("--max-hunks-per-patch", type=int, default=3)
    parser.add_argument("--max-patch-chars", type=int, default=6_000)
    parser.add_argument("--max-stat-chars", type=int, default=1_500)
    parser.add_argument("--max-focal-lines", type=int, default=8)
    parser.add_argument("--repo-timeout", type=int, default=120)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _resolve_member_edges(
    specifications: Sequence[str], rows: Sequence[Mapping[str, object]]
) -> list[Mapping[str, object]]:
    selected: list[Mapping[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for specification in specifications:
        if specification.count(":") != 1:
            raise ValueError(f"malformed --edge: {specification}")
        candidate_prefix, member_prefix = specification.split(":", 1)
        if len(candidate_prefix) < 7 or len(member_prefix) < 7:
            raise ValueError("edge prefixes must contain at least seven characters")
        matches = [
            row
            for row in rows
            if str(row.get("candidate_sha") or "").startswith(candidate_prefix)
            and str(row.get("member_fix_sha") or "").startswith(member_prefix)
        ]
        if len(matches) != 1:
            raise ValueError(
                f"--edge {specification} resolved to {len(matches)} member rows"
            )
        row = matches[0]
        edge = (str(row["candidate_sha"]), str(row["member_fix_sha"]))
        if edge in seen:
            raise ValueError(f"duplicate --edge: {specification}")
        if row.get("member_topology_class") != "T0_DIRECT_MEMBER_AFTER_CANDIDATE":
            raise ValueError(f"--edge {specification} is not a direct descendant pair")
        if row.get("retained") is not True:
            raise ValueError(f"--edge {specification} is not retained")
        seen.add(edge)
        selected.append(row)
    return selected


def _as_exact_bridge_row(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "candidate_sha": row["candidate_sha"],
        "fix_sha": row["member_fix_sha"],
        "retained": True,
        "delta_bridge_tier": 0,
        "delta_bridge_class": "MERGE_MEMBER_EXACT_REVERSAL",
        "delta_bridge_rank": row.get("topology_review_rank"),
        "source_priority_class": row.get("member_topology_class"),
        "source_pair_sha256": None,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    limits = (
        args.context_lines,
        args.max_paths,
        args.max_hunks_per_patch,
        args.max_patch_chars,
        args.max_stat_chars,
        args.max_focal_lines,
        args.repo_timeout,
    )
    if min(limits) < 1:
        raise SystemExit("packet limits must be positive")
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    overlay_dir = args.topology_overlay_dir.resolve()
    summary_path = overlay_dir / "summary.json"
    queue_path = overlay_dir / "exact_member_topology_queue.jsonl"
    ai_path = args.ai_scan_dir.resolve() / "commits.jsonl"
    summary = _load_json(summary_path)
    rows = _load_jsonl(queue_path)
    ai_rows = _load_jsonl(ai_path)
    if summary.get("all_exact_pairs_conserved") is not True:
        raise SystemExit("topology overlay is not lossless")
    if summary.get("hard_filter_count") != 0:
        raise SystemExit("topology overlay used a hard filter")
    raw_artifacts = summary.get("output_artifacts")
    expected_digest = (
        raw_artifacts.get("exact_member_topology_queue", {}).get("sha256")
        if isinstance(raw_artifacts, Mapping)
        and isinstance(raw_artifacts.get("exact_member_topology_queue"), Mapping)
        else None
    )
    if expected_digest != _sha256(queue_path):
        raise SystemExit("topology overlay queue checksum drift")
    try:
        selected = _resolve_member_edges(args.edge, rows)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    selected_bridge_rows = [_as_exact_bridge_row(row) for row in selected]
    observed_ai_shas = {str(row.get("sha") or "") for row in ai_rows}
    payload = build_packet(
        repository,
        selected_rows=selected_bridge_rows,
        observed_ai_shas=observed_ai_shas,
        context_lines=args.context_lines,
        max_paths=args.max_paths,
        max_hunks=args.max_hunks_per_patch,
        max_patch_chars=args.max_patch_chars,
        max_stat_chars=args.max_stat_chars,
        max_focal_lines=args.max_focal_lines,
        timeout=args.repo_timeout,
    )
    by_edge = {
        (str(row["candidate_sha"]), str(row["member_fix_sha"])): row
        for row in selected
    }
    for case in payload["case_results"]:
        source = by_edge[(str(case["candidate_sha"]), str(case["fix_sha"]))]
        case["merge_member_provenance"] = {
            "member_topology_class": source.get("member_topology_class"),
            "member_kind": source.get("member_kind"),
            "merge_carrier_shas": source.get("merge_carrier_shas"),
            "semantic_lanes": source.get("semantic_lanes"),
            "review_priority_score_v2": source.get("review_priority_score_v2"),
            "topology_review_rank": source.get("topology_review_rank"),
        }
    payload["packet_variant"] = "merge_member_direct_exact_reversal"
    payload["configuration"] = {
        "requested_edges": list(args.edge),
        "context_lines": args.context_lines,
        "max_paths": args.max_paths,
        "max_hunks_per_patch": args.max_hunks_per_patch,
        "max_patch_chars": args.max_patch_chars,
        "max_stat_chars": args.max_stat_chars,
        "max_focal_lines": args.max_focal_lines,
        "repo_timeout_seconds": args.repo_timeout,
    }
    payload["source_artifacts"] = {
        "ai_commits": {"path": str(ai_path), "sha256": _sha256(ai_path)},
        "topology_overlay_summary": {
            "path": str(summary_path),
            "sha256": _sha256(summary_path),
        },
        "topology_overlay_queue": {
            "path": str(queue_path),
            "sha256": _sha256(queue_path),
        },
    }
    payload["claim_boundary"] = (
        "The packet proves that each observed-AI candidate strictly precedes a "
        "retained merge member with exact same-path reverse lines. It does not turn "
        "a broad refactor, rollback, or shared line into a causal defect label. "
        "Negative semantic reviews remain scheduling evidence and never delete a pair."
    )
    if payload["packet_passed"] is not True:
        failed = [row["key"] for row in payload["case_results"] if not row["passed"]]
        raise SystemExit(f"merge-member review packet failed: {failed}")
    _atomic_json(args.output.resolve(), payload)
    print("Coolify merge-member semantic review packet frozen")
    print(f"  cases          : {payload['summary']['case_count']}")
    print(f"  unique AI      : {payload['summary']['unique_candidate_count']}")
    print(f"  exact reversals: {payload['summary']['forward_exact_reversal_count'] + payload['summary']['reverse_exact_reversal_count']}")
    print(f"  output         : {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
