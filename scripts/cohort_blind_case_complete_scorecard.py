#!/usr/bin/env python3
"""Score frozen blind cases without allowing cross-fix rank credit."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from pathlib import Path

from cohort.root_adjudication import canonical_sha256
from cohort_candidate_unit_scorecard import (
    _atomic_json,
    _edge_key,
    _file_sha256,
    _index_schedule,
    _normalize_budgets,
    _read_json,
    _read_jsonl,
)


GROUND_TRUTH_KIND = "prospective_origin_recall_v5_blind_ground_truth"


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generated-dir", type=Path, required=True)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--packet-summary", type=Path, required=True)
    parser.add_argument("--expected-ground-truth-sha256", required=True)
    parser.add_argument("--primary-budget", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _full_sha(value: object, field: str) -> str:
    sha = str(value or "").strip().lower()
    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        raise SystemExit(f"{field} must be a full SHA")
    return sha


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    if _file_sha256(args.ground_truth) != args.expected_ground_truth_sha256:
        raise SystemExit("ground-truth file digest mismatch")

    summary_path = args.generated_dir / "summary.json"
    schedule_path = args.generated_dir / "schedule.jsonl"
    summary = _read_json(summary_path)
    schedule = _read_jsonl(schedule_path)
    if summary.get("artifact_kind") != "frozen_candidate_unit_schedule":
        raise SystemExit("case scorecard requires a frozen schedule")
    if summary.get("generation_process_boundary") != (
        "frozen_candidate_units_no_label_or_adjudication_ledger_read"
    ):
        raise SystemExit("schedule crossed the label boundary")
    if summary.get("conservation", {}).get("passed") is not True:
        raise SystemExit("schedule conservation failed")
    if canonical_sha256(schedule) != summary.get("schedule_rows_sha256"):
        raise SystemExit("schedule canonical digest mismatch")
    if _file_sha256(schedule_path) != summary.get("schedule_file_sha256"):
        raise SystemExit("schedule file digest mismatch")
    units, schedule_edges, _ = _index_schedule(schedule)

    packet_summary = _read_json(args.packet_summary)
    if packet_summary.get("artifact_kind") != "lossless_origin_candidate_packets":
        raise SystemExit("packet summary artifact kind is invalid")
    if packet_summary.get("all_fix_edges_conserved") is not True:
        raise SystemExit("packet summary did not conserve fix edges")
    if packet_summary.get("all_candidate_units_assigned_once") is not True:
        raise SystemExit("packet summary did not conserve units")
    blocked_roots = int(packet_summary.get("blocked_squash_relation_root_count") or 0)

    ground_truth = _read_json(args.ground_truth)
    if ground_truth.get("artifact_kind") != GROUND_TRUTH_KIND:
        raise SystemExit("ground-truth artifact kind is invalid")
    raw_cases = ground_truth.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise SystemExit("ground truth has no cases")
    expected_by_case: dict[tuple[str, str, str], set[tuple[str, str, str, str]]] = {}
    strata: dict[tuple[str, str, str], str] = {}
    for raw in raw_cases:
        if not isinstance(raw, Mapping):
            raise SystemExit("ground truth contains a non-object case")
        repository = str(raw.get("repository") or "").strip().lower()
        advisory = str(raw.get("case_id") or "").strip()
        fix_sha = _full_sha(raw.get("fix_sha"), "case fix_sha")
        case_key = (repository, advisory, fix_sha)
        subjects = raw.get("accepted_ai_causal_subject_shas")
        if not repository or not advisory or not isinstance(subjects, list) or not subjects:
            raise SystemExit("ground truth contains an incomplete case")
        if case_key in expected_by_case:
            raise SystemExit(f"ground truth repeats case: {advisory}")
        expected_by_case[case_key] = {
            (repository, advisory, _full_sha(sha, "candidate sha"), fix_sha)
            for sha in subjects
        }
        if len(expected_by_case[case_key]) != len(subjects):
            raise SystemExit(f"ground truth repeats an edge: {advisory}")
        strata[case_key] = str(raw.get("stratum") or "")

    expected_edges = set().union(*expected_by_case.values())
    truth_summary = ground_truth.get("summary")
    if not isinstance(truth_summary, Mapping):
        raise SystemExit("ground-truth summary is missing")
    if truth_summary.get("confirmed_positive_case_count") != len(expected_by_case):
        raise SystemExit("ground-truth case count mismatch")
    if truth_summary.get("accepted_exact_edge_count") != len(expected_edges):
        raise SystemExit("ground-truth edge count mismatch")

    budgets = _normalize_budgets(
        ground_truth.get("evaluation_contract", {}).get("budgets", [])  # type: ignore[union-attr]
    )
    if args.primary_budget not in budgets:
        raise SystemExit("primary budget is absent from frozen ground truth")

    unit_edges: dict[str, set[tuple[str, str, str, str]]] = {}
    unit_fix_edges: dict[tuple[str, str], set[tuple[str, str, str, str]]] = {}
    positions: dict[tuple[str, str, str, str], int] = {}
    for unit_id, row in units.items():
        edges: set[tuple[str, str, str, str]] = set()
        for raw_edge in row["fix_edges"]:  # type: ignore[union-attr]
            assert isinstance(raw_edge, Mapping)
            edge = _edge_key(row, raw_edge)
            edges.add(edge)
            unit_fix_edges.setdefault((unit_id, edge[3]), set()).add(edge)
            positions[edge] = int(raw_edge["frozen_fix_position"])
        unit_edges[unit_id] = edges

    inventory_missing = expected_edges - schedule_edges
    evaluations: list[dict[str, object]] = []
    for budget in budgets:
        selected_memberships = {
            (unit_id, edge[3])
            for unit_id, edges in unit_edges.items()
            for edge in edges
            if positions[edge] <= budget
        }
        same_fix_edges = set().union(
            *(unit_fix_edges[membership] for membership in selected_memberships),
            set(),
        )
        selected_units = {unit_id for unit_id, _ in selected_memberships}
        global_carried_edges = set().union(
            *(unit_edges[unit_id] for unit_id in selected_units), set()
        )
        case_rows: list[dict[str, object]] = []
        for case_key, expected in expected_by_case.items():
            strict_missing = expected - same_fix_edges
            operational_missing = expected - global_carried_edges
            case_rows.append(
                {
                    "case_id": case_key[1],
                    "repository_identity": case_key[0],
                    "fix_sha": case_key[2],
                    "stratum": strata[case_key],
                    "expected_edge_count": len(expected),
                    "strict_same_fix_covered_edge_count": len(expected - strict_missing),
                    "strict_same_fix_any": len(strict_missing) < len(expected),
                    "strict_same_fix_complete": not strict_missing,
                    "strict_same_fix_missing_candidate_shas": sorted(
                        edge[2] for edge in strict_missing
                    ),
                    "operational_global_unit_complete": not operational_missing,
                }
            )
        strict_complete = sum(row["strict_same_fix_complete"] is True for row in case_rows)
        evaluations.append(
            {
                "budget_per_fix": budget,
                "selected_fix_membership_count": len(selected_memberships),
                "selected_unique_unit_count": len(selected_units),
                "strict_same_fix_covered_edge_count": len(
                    expected_edges & same_fix_edges
                ),
                "strict_same_fix_edge_recall": len(expected_edges & same_fix_edges)
                / len(expected_edges),
                "strict_same_fix_case_any_count": sum(
                    row["strict_same_fix_any"] is True for row in case_rows
                ),
                "strict_same_fix_case_complete_count": strict_complete,
                "strict_same_fix_case_complete_recall": strict_complete
                / len(case_rows),
                "operational_global_unit_case_complete_count": sum(
                    row["operational_global_unit_complete"] is True
                    for row in case_rows
                ),
                "cases": case_rows,
            }
        )

    primary = next(
        row for row in evaluations if row["budget_per_fix"] == args.primary_budget
    )
    gate_passed = (
        not inventory_missing
        and blocked_roots == 0
        and primary["strict_same_fix_case_complete_count"] == len(expected_by_case)
    )
    artifact = {
        "schema_version": 1,
        "artifact_kind": "prospective_origin_recall_v5_case_complete_scorecard",
        "source_artifacts": {
            "schedule_summary": {
                "path": str(summary_path),
                "sha256": _file_sha256(summary_path),
            },
            "schedule": {
                "path": str(schedule_path),
                "sha256": _file_sha256(schedule_path),
            },
            "packet_summary": {
                "path": str(args.packet_summary),
                "sha256": _file_sha256(args.packet_summary),
            },
            "ground_truth": {
                "path": str(args.ground_truth),
                "sha256": _file_sha256(args.ground_truth),
            },
        },
        "summary": {
            "confirmed_positive_case_count": len(expected_by_case),
            "accepted_exact_edge_count": len(expected_edges),
            "full_inventory_missing_edge_count": len(inventory_missing),
            "full_inventory_missing_case_ids": sorted(
                {edge[1] for edge in inventory_missing}
            ),
            "blocked_squash_relation_root_count": blocked_roots,
            "primary_budget_per_fix": args.primary_budget,
            "primary_case_complete_count": primary[
                "strict_same_fix_case_complete_count"
            ],
            "primary_gate_passed": gate_passed,
        },
        "budget_evaluations": evaluations,
        "claim_boundary": (
            "The primary gate credits a unit only within the same fix prefix that "
            "selected it. Operational global-unit credit is diagnostic only. This "
            "is recall on dual-reviewed frozen cases, not population recall."
        ),
    }
    _atomic_json(args.output, artifact)
    print("Blind case-complete scorecard written")
    print(f"  cases : {len(expected_by_case)}")
    print(f"  edges : {len(expected_edges)}")
    print(f"  gate  : {'PASS' if gate_passed else 'FAIL'}")
    print(f"  output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
