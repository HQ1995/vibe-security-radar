#!/usr/bin/env python3
"""Score frozen blind cases without allowing cross-fix rank credit."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from pathlib import Path

from cohort.root_adjudication import canonical_sha256
from cohort_candidate_unit_scorecard import (
    CARRIER_BUDGET_UNIT,
    _atomic_json,
    _budget_selection,
    _file_sha256,
    _index_schedule,
    _normalize_budgets,
    _packet_surface_counts,
    _read_json,
    _read_jsonl,
    _rebuild_schedule,
    _schedule_budget_unit,
    _validate_schedule_mode,
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


def _sha256_digest(value: object, field: str) -> str:
    digest = value if isinstance(value, str) else ""
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise SystemExit(f"{field} must be a lowercase SHA-256 digest")
    return digest


def _bind_packet_summary(
    schedule_summary: Mapping[str, object], packet_summary_path: Path
) -> dict[str, object]:
    source_artifacts = schedule_summary.get("source_artifacts")
    if not isinstance(source_artifacts, Mapping):
        raise SystemExit("schedule source_artifacts is missing")
    frozen_packet_summary = source_artifacts.get("packet_summary")
    if not isinstance(frozen_packet_summary, Mapping):
        raise SystemExit("schedule packet-summary provenance is missing")
    expected_file_sha256 = _sha256_digest(
        frozen_packet_summary.get("sha256"),
        "schedule packet-summary sha256",
    )
    expected_canonical_sha256 = _sha256_digest(
        frozen_packet_summary.get("canonical_sha256"),
        "schedule packet-summary canonical_sha256",
    )
    packet_summary = _read_json(packet_summary_path)
    if _file_sha256(packet_summary_path) != expected_file_sha256:
        raise SystemExit("packet-summary file digest mismatch")
    if canonical_sha256(packet_summary) != expected_canonical_sha256:
        raise SystemExit("packet-summary canonical digest mismatch")
    return packet_summary


def _bind_schedule_to_candidate_units(
    schedule_summary: Mapping[str, object],
    packet_summary: Mapping[str, object],
    packet_summary_path: Path,
    schedule: Sequence[Mapping[str, object]],
    budget_unit: str,
) -> None:
    source_artifacts = schedule_summary.get("source_artifacts")
    if not isinstance(source_artifacts, Mapping):
        raise SystemExit("schedule source_artifacts is missing")
    frozen_candidate_units = source_artifacts.get("candidate_units")
    if not isinstance(frozen_candidate_units, Mapping):
        raise SystemExit("schedule candidate-units provenance is missing")
    expected_file_sha256 = _sha256_digest(
        frozen_candidate_units.get("sha256"),
        "schedule candidate-units sha256",
    )
    expected_canonical_sha256 = _sha256_digest(
        frozen_candidate_units.get("canonical_sha256"),
        "schedule candidate-units canonical_sha256",
    )
    packet_candidate_units_sha256 = _sha256_digest(
        packet_summary.get("candidate_units_sha256"),
        "packet summary candidate_units_sha256",
    )
    candidate_units_path = packet_summary_path.parent / "candidate_units.jsonl"
    raw_units = _read_jsonl(candidate_units_path)
    if _file_sha256(candidate_units_path) != expected_file_sha256:
        raise SystemExit("candidate-units file digest mismatch")
    raw_units_sha256 = canonical_sha256(raw_units)
    if raw_units_sha256 != expected_canonical_sha256:
        raise SystemExit("candidate-units canonical digest mismatch")
    if raw_units_sha256 != packet_candidate_units_sha256:
        raise SystemExit("packet summary candidate-unit digest mismatch")

    units, rebuilt_schedule = _rebuild_schedule(raw_units, budget_unit)
    candidate_unit_count = packet_summary.get("candidate_unit_count")
    if (
        not isinstance(candidate_unit_count, int)
        or isinstance(candidate_unit_count, bool)
        or candidate_unit_count != len(units)
    ):
        raise SystemExit("packet summary candidate-unit count mismatch")
    candidate_fix_pair_count = packet_summary.get("candidate_fix_pair_count")
    rebuilt_edge_count = sum(int(unit["fix_edge_count"]) for unit in units)
    if (
        not isinstance(candidate_fix_pair_count, int)
        or isinstance(candidate_fix_pair_count, bool)
        or candidate_fix_pair_count != rebuilt_edge_count
    ):
        raise SystemExit("packet summary candidate fix-edge count mismatch")
    rebuilt_schedule_sha256 = canonical_sha256(rebuilt_schedule)
    schedule_sha256 = canonical_sha256(schedule)
    rows_match = len(rebuilt_schedule) == len(schedule) and all(
        rebuilt_row == schedule_row
        for rebuilt_row, schedule_row in zip(rebuilt_schedule, schedule)
    )
    if rebuilt_schedule_sha256 != schedule_sha256:
        raise SystemExit("schedule canonical digest does not match candidate units")
    if not rows_match:
        raise SystemExit("schedule rows do not match candidate units")


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
    budget_unit = _schedule_budget_unit(summary)
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
    _validate_schedule_mode(schedule, budget_unit)

    packet_summary = _bind_packet_summary(summary, args.packet_summary)
    if packet_summary.get("artifact_kind") != "lossless_origin_candidate_packets":
        raise SystemExit("packet summary artifact kind is invalid")
    if packet_summary.get("all_fix_edges_conserved") is not True:
        raise SystemExit("packet summary did not conserve fix edges")
    if packet_summary.get("all_candidate_units_assigned_once") is not True:
        raise SystemExit("packet summary did not conserve units")
    (
        blocked_roots,
        candidate_uncovered,
        carrier_only_roots,
        atomic_gaps,
        has_new_surface,
    ) = _packet_surface_counts(packet_summary, budget_unit)
    _bind_schedule_to_candidate_units(
        summary,
        packet_summary,
        args.packet_summary,
        schedule,
        budget_unit,
    )

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
        if (
            not repository
            or not advisory
            or not isinstance(subjects, list)
            or not subjects
        ):
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

    inventory_missing = expected_edges - schedule_edges
    evaluations: list[dict[str, object]] = []
    for budget in budgets:
        (
            selected_memberships,
            selected_units,
            same_fix_edges,
            global_carried_edges,
        ) = _budget_selection(units, budget, budget_unit)
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
                    "strict_same_fix_covered_edge_count": len(
                        expected - strict_missing
                    ),
                    "strict_same_fix_any": len(strict_missing) < len(expected),
                    "strict_same_fix_complete": not strict_missing,
                    "strict_same_fix_missing_candidate_shas": sorted(
                        edge[2] for edge in strict_missing
                    ),
                    "operational_global_unit_complete": not operational_missing,
                }
            )
        strict_complete = sum(
            row["strict_same_fix_complete"] is True for row in case_rows
        )
        evaluation = {
            "budget_per_fix": budget,
            "selected_fix_membership_count": len(selected_memberships),
            "selected_unique_unit_count": len(selected_units),
            "strict_same_fix_covered_edge_count": len(expected_edges & same_fix_edges),
            "strict_same_fix_edge_recall": len(expected_edges & same_fix_edges)
            / len(expected_edges),
            "strict_same_fix_case_any_count": sum(
                row["strict_same_fix_any"] is True for row in case_rows
            ),
            "strict_same_fix_case_complete_count": strict_complete,
            "strict_same_fix_case_complete_recall": strict_complete / len(case_rows),
            "operational_global_unit_case_complete_count": sum(
                row["operational_global_unit_complete"] is True for row in case_rows
            ),
            "cases": case_rows,
        }
        if budget_unit == CARRIER_BUDGET_UNIT:
            evaluation.update(
                {
                    "budget_unit": CARRIER_BUDGET_UNIT,
                    "triggered_carrier_fix_membership_count": len(selected_memberships),
                    "triggered_unique_carrier_group_count": len(
                        {
                            (repository, advisory, group_id)
                            for repository, advisory, group_id, _ in selected_memberships
                        }
                    ),
                    "expanded_atomic_unit_count": len(selected_units),
                    "same_fix_carried_atomic_edge_count": len(same_fix_edges),
                }
            )
        evaluations.append(evaluation)

    primary = next(
        row for row in evaluations if row["budget_per_fix"] == args.primary_budget
    )
    gate_passed = (
        not inventory_missing
        and candidate_uncovered == 0
        and primary["strict_same_fix_case_complete_count"] == len(expected_by_case)
    )
    claim_boundary = (
        "Carrier credit is same-fix only; cross-fix carried review is diagnostic. "
        "This is frozen-case recall, not population recall or atomic provenance."
        if budget_unit == CARRIER_BUDGET_UNIT
        else (
            "The primary gate credits a unit only within the same fix prefix that "
            "selected it. Operational global-unit credit is diagnostic only. This "
            "is recall on dual-reviewed frozen cases, not population recall."
        )
    )
    artifact = {
        "schema_version": 2 if budget_unit == CARRIER_BUDGET_UNIT else 1,
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
        "claim_boundary": claim_boundary,
    }
    if budget_unit == CARRIER_BUDGET_UNIT:
        artifact_summary = artifact["summary"]
        assert isinstance(artifact_summary, dict)
        artifact_summary["budget_unit"] = CARRIER_BUDGET_UNIT
    if has_new_surface:
        artifact_summary = artifact["summary"]
        assert isinstance(artifact_summary, dict)
        artifact_summary.update(
            {
                "candidate_surface_uncovered_count": candidate_uncovered,
                "candidate_surface_coverage_complete": packet_summary.get(
                    "candidate_surface_coverage_complete"
                ),
                "carrier_only_squash_relation_root_count": carrier_only_roots,
                "atomic_provenance_gap_count": atomic_gaps,
            }
        )
    _atomic_json(args.output, artifact)
    print("Blind case-complete scorecard written")
    print(f"  cases : {len(expected_by_case)}")
    print(f"  edges : {len(expected_edges)}")
    print(f"  gate  : {'PASS' if gate_passed else 'FAIL'}")
    print(f"  output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
