"""Tests for strict same-fix blind case recall."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cohort.root_adjudication import canonical_sha256
from cohort_blind_case_complete_scorecard import _bind_packet_summary, main
from cohort_candidate_unit_scorecard import (
    ATOMIC_BUDGET_UNIT,
    CARRIER_BUDGET_UNIT,
    _validate_schedule_mode,
    main as schedule_main,
)


def _sha(character: str) -> str:
    return character * 40


def _write(path: Path, value: object, *, jsonl: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = value if isinstance(value, list) else [value]
    text = (
        "".join(json.dumps(row) + "\n" for row in rows) if jsonl else json.dumps(value)
    )
    path.write_text(text, encoding="utf-8")


def _unit(
    unit_id: str,
    candidate: str,
    edges: list[tuple[str, int]],
    *,
    squash_group_ids: list[str] | None = None,
) -> dict[str, object]:
    unit: dict[str, object] = {
        "unit_id": unit_id,
        "repository_identity": "github.com/example/repo",
        "advisory": "CVE-2099-0001",
        "candidate_sha": candidate,
        "fix_edges": [
            {"fix_sha": fix_sha, "priority_rank": rank, "signals": ["signal"]}
            for fix_sha, rank in edges
        ],
        "fix_edge_count": len(edges),
        "best_priority_rank": min(rank for _, rank in edges),
        "signals": ["signal"],
        "retained": True,
    }
    if squash_group_ids is not None:
        unit["squash_group_ids"] = squash_group_ids
    return unit


def _write_packet_artifact(
    packet_dir: Path,
    units: list[dict[str, object]],
    *,
    packet_size: int = 25,
) -> dict[str, object]:
    packets = [
        {
            "packet_id": f"packet-{offset // packet_size + 1}",
            "candidate_unit_ids": [
                str(unit["unit_id"]) for unit in units[offset : offset + packet_size]
            ],
            "candidate_count": len(units[offset : offset + packet_size]),
        }
        for offset in range(0, len(units), packet_size)
    ]
    summary = {
        "schema_version": 1,
        "artifact_kind": "lossless_origin_candidate_packets",
        "candidate_fix_pair_count": sum(int(unit["fix_edge_count"]) for unit in units),
        "candidate_unit_count": len(units),
        "packet_count": len(packets),
        "candidate_units_sha256": canonical_sha256(units),
        "packets_sha256": canonical_sha256(packets),
        "all_fix_edges_conserved": True,
        "all_candidate_units_assigned_once": True,
        "blocked_squash_relation_root_count": 0,
        "carrier_only_squash_relation_root_count": 0,
        "atomic_provenance_gap_count": 0,
        "candidate_surface_uncovered_count": 0,
        "candidate_surface_coverage_complete": True,
        "squash_relation_closure_applied": True,
    }
    _write(packet_dir / "candidate_units.jsonl", units, jsonl=True)
    _write(packet_dir / "packets.jsonl", packets, jsonl=True)
    _write(packet_dir / "summary.json", summary)
    return summary


def _rewrite_frozen_schedule(
    generated_dir: Path, rows: list[dict[str, object]]
) -> None:
    schedule_path = generated_dir / "schedule.jsonl"
    _write(schedule_path, rows, jsonl=True)
    summary_path = generated_dir / "summary.json"
    summary = json.loads(summary_path.read_text())
    summary["schedule_rows_sha256"] = canonical_sha256(rows)
    summary["schedule_file_sha256"] = hashlib.sha256(
        schedule_path.read_bytes()
    ).hexdigest()
    _write(summary_path, summary)


def _write_single_case_truth(
    path: Path,
    *,
    fix_sha: str,
    candidate_sha: str,
    budgets: list[int],
) -> None:
    _write(
        path,
        {
            "artifact_kind": "prospective_origin_recall_v5_blind_ground_truth",
            "cases": [
                {
                    "case_id": "CVE-2099-0001",
                    "repository": "github.com/example/repo",
                    "fix_sha": fix_sha,
                    "stratum": "direct",
                    "accepted_ai_causal_subject_shas": [candidate_sha],
                }
            ],
            "evaluation_contract": {"budgets": budgets},
            "summary": {
                "confirmed_positive_case_count": 1,
                "accepted_exact_edge_count": 1,
            },
        },
    )


def test_packet_summary_binding_requires_frozen_provenance_structure(
    tmp_path: Path,
) -> None:
    packet_summary = tmp_path / "summary.json"
    _write(packet_summary, {"artifact_kind": "lossless_origin_candidate_packets"})

    with pytest.raises(SystemExit, match="packet-summary provenance is missing"):
        _bind_packet_summary(
            {"source_artifacts": {"packet_summary": []}}, packet_summary
        )


def test_blind_rejects_self_signed_atomic_rank_forgery(tmp_path: Path) -> None:
    fix_sha = _sha("1")
    candidate_a, candidate_b = _sha("a"), _sha("b")
    packets = tmp_path / "atomic-packets"
    _write_packet_artifact(
        packets,
        [
            _unit("unit-a", candidate_a, [(fix_sha, 1)]),
            _unit("unit-b", candidate_b, [(fix_sha, 2)]),
        ],
    )
    generated = tmp_path / "atomic-schedule"
    assert (
        schedule_main(
            [
                "generate",
                "--packets-dir",
                str(packets),
                "--output-dir",
                str(generated),
                "--budget",
                "1",
                "--budget",
                "2",
            ]
        )
        == 0
    )
    rows = [
        json.loads(line)
        for line in (generated / "schedule.jsonl").read_text().splitlines()
    ]
    by_id = {row["unit_id"]: row for row in rows}
    first_edge = by_id["unit-a"]["fix_edges"][0]
    second_edge = by_id["unit-b"]["fix_edges"][0]
    first_edge["source_priority_rank"], second_edge["source_priority_rank"] = (
        second_edge["source_priority_rank"],
        first_edge["source_priority_rank"],
    )
    first_edge["frozen_fix_position"], second_edge["frozen_fix_position"] = (
        second_edge["frozen_fix_position"],
        first_edge["frozen_fix_position"],
    )
    _validate_schedule_mode(rows, ATOMIC_BUDGET_UNIT)
    _rewrite_frozen_schedule(generated, rows)

    truth = tmp_path / "atomic-truth.json"
    _write_single_case_truth(
        truth,
        fix_sha=fix_sha,
        candidate_sha=candidate_a,
        budgets=[1, 2],
    )
    with pytest.raises(
        SystemExit, match="schedule canonical digest does not match candidate units"
    ):
        main(
            [
                "--generated-dir",
                str(generated),
                "--ground-truth",
                str(truth),
                "--packet-summary",
                str(packets / "summary.json"),
                "--expected-ground-truth-sha256",
                hashlib.sha256(truth.read_bytes()).hexdigest(),
                "--primary-budget",
                "2",
                "--output",
                str(tmp_path / "atomic-result.json"),
            ]
        )


def test_blind_rejects_self_signed_carrier_provenance_forgery(
    tmp_path: Path,
) -> None:
    repository = "github.com/example/repo"
    advisory = "CVE-2099-0001"
    fix_sha = _sha("2")
    candidate_a, candidate_b = _sha("c"), _sha("d")
    packets = tmp_path / "carrier-packets"
    _write_packet_artifact(
        packets,
        [
            _unit("unit-a", candidate_a, [(fix_sha, 1)], squash_group_ids=[]),
            _unit(
                "unit-b",
                candidate_b,
                [(fix_sha, 2)],
                squash_group_ids=[candidate_a],
            ),
        ],
    )
    generated = tmp_path / "carrier-schedule"
    assert (
        schedule_main(
            [
                "generate",
                "--packets-dir",
                str(packets),
                "--output-dir",
                str(generated),
                "--budget-unit",
                "carrier",
                "--budget",
                "1",
                "--budget",
                "2",
            ]
        )
        == 0
    )
    rows = [
        json.loads(line)
        for line in (generated / "schedule.jsonl").read_text().splitlines()
    ]
    by_id = {row["unit_id"]: row for row in rows}
    for position, (unit_id, candidate_sha) in enumerate(
        (("unit-a", candidate_a), ("unit-b", candidate_b)), start=1
    ):
        row = by_id[unit_id]
        row["carrier_connector_provenance"]["squash_group_ids"] = []
        digest = hashlib.sha256(
            "\0".join((repository, advisory, candidate_sha)).encode()
        ).hexdigest()
        row["carrier_group_id"] = f"carrier-group-{digest}"
        row["fix_edges"][0]["frozen_carrier_fix_position"] = position
    _validate_schedule_mode(rows, CARRIER_BUDGET_UNIT)
    _rewrite_frozen_schedule(generated, rows)

    truth = tmp_path / "carrier-truth.json"
    _write_single_case_truth(
        truth,
        fix_sha=fix_sha,
        candidate_sha=candidate_b,
        budgets=[1, 2],
    )
    with pytest.raises(
        SystemExit, match="schedule canonical digest does not match candidate units"
    ):
        main(
            [
                "--generated-dir",
                str(generated),
                "--ground-truth",
                str(truth),
                "--packet-summary",
                str(packets / "summary.json"),
                "--expected-ground-truth-sha256",
                hashlib.sha256(truth.read_bytes()).hexdigest(),
                "--primary-budget",
                "2",
                "--output",
                str(tmp_path / "carrier-result.json"),
            ]
        )


def test_primary_gate_is_case_complete_same_fix_and_fail_closed(tmp_path: Path) -> None:
    multi_fix, trigger_fix, target_fix, missing_fix = map(_sha, "1234")
    candidate_a, candidate_b, candidate_c, candidate_d, missing = map(_sha, "abcde")
    units = [
        _unit("unit-a", candidate_a, [(multi_fix, 1)]),
        _unit("unit-b", candidate_b, [(multi_fix, 2)]),
        _unit("unit-c", candidate_c, [(trigger_fix, 1), (target_fix, 2)]),
        _unit("unit-d", candidate_d, [(target_fix, 1)]),
    ]
    packets = tmp_path / "packets"
    packet_summary = {
        "schema_version": 1,
        "artifact_kind": "lossless_origin_candidate_packets",
        "candidate_fix_pair_count": 5,
        "candidate_unit_count": 4,
        "candidate_units_sha256": canonical_sha256(units),
        "all_fix_edges_conserved": True,
        "all_candidate_units_assigned_once": True,
        "blocked_squash_relation_root_count": 1,
    }
    _write(packets / "candidate_units.jsonl", units, jsonl=True)
    _write(packets / "summary.json", packet_summary)
    generated = tmp_path / "schedule"
    assert (
        schedule_main(
            [
                "generate",
                "--packets-dir",
                str(packets),
                "--output-dir",
                str(generated),
                "--budget",
                "1",
                "--budget",
                "2",
            ]
        )
        == 0
    )

    cases = [
        {
            "case_id": "CVE-2099-0001",
            "repository": "github.com/example/repo",
            "fix_sha": multi_fix,
            "stratum": "direct",
            "accepted_ai_causal_subject_shas": [candidate_a, candidate_b],
        },
        {
            "case_id": "CVE-2099-0001",
            "repository": "github.com/example/repo",
            "fix_sha": target_fix,
            "stratum": "direct",
            "accepted_ai_causal_subject_shas": [candidate_c],
        },
        {
            "case_id": "CVE-2099-0001",
            "repository": "github.com/example/repo",
            "fix_sha": missing_fix,
            "stratum": "direct",
            "accepted_ai_causal_subject_shas": [missing],
        },
    ]

    def score(
        selected_cases: list[dict[str, object]],
        name: str,
        *,
        generated_dir: Path = generated,
    ) -> dict[str, object]:
        truth = tmp_path / f"truth-{name}.json"
        _write(
            truth,
            {
                "artifact_kind": "prospective_origin_recall_v5_blind_ground_truth",
                "cases": selected_cases,
                "evaluation_contract": {"budgets": [1, 2]},
                "summary": {
                    "confirmed_positive_case_count": len(selected_cases),
                    "accepted_exact_edge_count": sum(
                        len(case["accepted_ai_causal_subject_shas"])  # type: ignore[arg-type]
                        for case in selected_cases
                    ),
                },
            },
        )
        digest = hashlib.sha256(truth.read_bytes()).hexdigest()
        output = tmp_path / f"result-{name}.json"
        assert (
            main(
                [
                    "--generated-dir",
                    str(generated_dir),
                    "--ground-truth",
                    str(truth),
                    "--packet-summary",
                    str(packets / "summary.json"),
                    "--expected-ground-truth-sha256",
                    digest,
                    "--primary-budget",
                    "2",
                    "--output",
                    str(output),
                ]
            )
            == 0
        )
        return json.loads(output.read_text(encoding="utf-8"))

    failed = score(cases, "failed")
    budget_one = failed["budget_evaluations"][0]
    multi_case, cross_fix_case, _ = budget_one["cases"]
    assert multi_case["strict_same_fix_any"] is True
    assert multi_case["strict_same_fix_complete"] is False
    assert cross_fix_case["operational_global_unit_complete"] is True
    assert cross_fix_case["strict_same_fix_complete"] is False
    assert failed["summary"]["full_inventory_missing_edge_count"] == 1
    assert failed["summary"]["blocked_squash_relation_root_count"] == 1
    assert failed["summary"]["primary_gate_passed"] is False

    packet_summary["blocked_squash_relation_root_count"] = 0
    _write(packets / "summary.json", packet_summary)
    with pytest.raises(SystemExit, match="packet-summary file digest mismatch"):
        score(cases[:2], "stale-packet-summary")

    passed_generated = tmp_path / "passed-schedule"
    assert (
        schedule_main(
            [
                "generate",
                "--packets-dir",
                str(packets),
                "--output-dir",
                str(passed_generated),
                "--budget",
                "1",
                "--budget",
                "2",
            ]
        )
        == 0
    )
    passed = score(cases[:2], "passed", generated_dir=passed_generated)
    assert passed["summary"]["primary_case_complete_count"] == 2
    assert passed["summary"]["primary_gate_passed"] is True

    for malformed_blocked, name in ((True, "bool"), (-1, "negative")):
        packet_summary["blocked_squash_relation_root_count"] = malformed_blocked
        _write(packets / "summary.json", packet_summary)
        malformed_generated = tmp_path / f"malformed-blocked-{name}-schedule"
        with pytest.raises(
            SystemExit,
            match="blocked_squash_relation_root_count must be a non-negative integer",
        ):
            schedule_main(
                [
                    "generate",
                    "--packets-dir",
                    str(packets),
                    "--output-dir",
                    str(malformed_generated),
                    "--budget",
                    "1",
                    "--budget",
                    "2",
                ]
            )


def test_carrier_gate_covers_101st_member_without_cross_fix_credit(
    tmp_path: Path,
) -> None:
    main_fix = _sha("e")
    target_fix = _sha("f")
    candidates = [f"{index:040x}" for index in range(1, 102)]
    units: list[dict[str, object]] = []
    for index, candidate in enumerate(candidates):
        group_ids = (
            [] if index == 0 else [candidates[0] if index != 2 else candidates[1]]
        )
        edges = [(main_fix, index + 1)]
        if index == 0:
            edges.append((target_fix, 2))
        units.append(
            _unit(
                f"carrier-member-{index + 1}",
                candidate,
                edges,
                squash_group_ids=group_ids,
            )
        )
    direct_candidate = f"{1000:040x}"
    units.append(
        _unit(
            "direct-singleton",
            direct_candidate,
            [(target_fix, 1)],
        )
    )
    packets = tmp_path / "carrier-packets"
    packet_summary = _write_packet_artifact(packets, units)
    packet_summary.update(
        {
            "carrier_only_squash_relation_root_count": 7,
            "atomic_provenance_gap_count": 7,
            "candidate_surface_uncovered_count": 0,
            "candidate_surface_coverage_complete": True,
        }
    )
    _write(packets / "summary.json", packet_summary)
    generated = tmp_path / "carrier-schedule"
    assert (
        schedule_main(
            [
                "generate",
                "--packets-dir",
                str(packets),
                "--output-dir",
                str(generated),
                "--budget-unit",
                "carrier",
                "--budget",
                "1",
                "--budget",
                "2",
            ]
        )
        == 0
    )

    schedule = [
        json.loads(line)
        for line in (generated / "schedule.jsonl").read_text().splitlines()
    ]
    last = next(row for row in schedule if row["unit_id"] == "carrier-member-101")
    last_main_edge = next(
        edge for edge in last["fix_edges"] if edge["fix_sha"] == main_fix
    )
    assert last_main_edge["frozen_fix_position"] == 101
    assert last_main_edge["frozen_carrier_fix_position"] == 1

    cases = [
        {
            "case_id": "CVE-2099-0001",
            "repository": "github.com/example/repo",
            "fix_sha": main_fix,
            "stratum": "squash",
            "accepted_ai_causal_subject_shas": [candidates[-1]],
        },
        {
            "case_id": "CVE-2099-0001",
            "repository": "github.com/example/repo",
            "fix_sha": target_fix,
            "stratum": "direct",
            "accepted_ai_causal_subject_shas": [candidates[0], direct_candidate],
        },
    ]
    truth = tmp_path / "carrier-truth.json"
    _write(
        truth,
        {
            "artifact_kind": "prospective_origin_recall_v5_blind_ground_truth",
            "cases": cases,
            "evaluation_contract": {"budgets": [1, 2]},
            "summary": {
                "confirmed_positive_case_count": 2,
                "accepted_exact_edge_count": 3,
            },
        },
    )
    output = tmp_path / "carrier-result.json"
    assert (
        main(
            [
                "--generated-dir",
                str(generated),
                "--ground-truth",
                str(truth),
                "--packet-summary",
                str(packets / "summary.json"),
                "--expected-ground-truth-sha256",
                hashlib.sha256(truth.read_bytes()).hexdigest(),
                "--primary-budget",
                "2",
                "--output",
                str(output),
            ]
        )
        == 0
    )

    result = json.loads(output.read_text())
    budget_one, budget_two = result["budget_evaluations"]
    main_case, cross_fix_case = budget_one["cases"]
    assert main_case["strict_same_fix_complete"] is True
    assert cross_fix_case["strict_same_fix_any"] is True
    assert cross_fix_case["strict_same_fix_complete"] is False
    assert cross_fix_case["strict_same_fix_missing_candidate_shas"] == [candidates[0]]
    assert cross_fix_case["operational_global_unit_complete"] is True
    assert budget_one["triggered_carrier_fix_membership_count"] == 2
    assert budget_one["triggered_unique_carrier_group_count"] == 2
    assert budget_one["expanded_atomic_unit_count"] == 102
    assert budget_one["same_fix_carried_atomic_edge_count"] == 102
    assert budget_two["strict_same_fix_case_complete_count"] == 2
    assert result["summary"]["primary_gate_passed"] is True
    assert result["summary"]["carrier_only_squash_relation_root_count"] == 7
    assert result["summary"]["atomic_provenance_gap_count"] == 7
    assert result["claim_boundary"] == (
        "Carrier credit is same-fix only; cross-fix carried review is diagnostic. "
        "This is frozen-case recall, not population recall or atomic provenance."
    )

    packet_summary["candidate_surface_uncovered_count"] = 1
    packet_summary["candidate_surface_coverage_complete"] = False
    packet_summary["blocked_squash_relation_root_count"] = 1
    packet_summary["atomic_provenance_gap_count"] = 8
    _write(packets / "summary.json", packet_summary)
    uncovered_output = tmp_path / "carrier-uncovered-result.json"
    with pytest.raises(SystemExit, match="packet-summary file digest mismatch"):
        main(
            [
                "--generated-dir",
                str(generated),
                "--ground-truth",
                str(truth),
                "--packet-summary",
                str(packets / "summary.json"),
                "--expected-ground-truth-sha256",
                hashlib.sha256(truth.read_bytes()).hexdigest(),
                "--primary-budget",
                "2",
                "--output",
                str(uncovered_output),
            ]
        )

    uncovered_generated = tmp_path / "carrier-uncovered-schedule"
    assert (
        schedule_main(
            [
                "generate",
                "--packets-dir",
                str(packets),
                "--output-dir",
                str(uncovered_generated),
                "--budget-unit",
                "carrier",
                "--budget",
                "1",
                "--budget",
                "2",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "--generated-dir",
                str(uncovered_generated),
                "--ground-truth",
                str(truth),
                "--packet-summary",
                str(packets / "summary.json"),
                "--expected-ground-truth-sha256",
                hashlib.sha256(truth.read_bytes()).hexdigest(),
                "--primary-budget",
                "2",
                "--output",
                str(uncovered_output),
            ]
        )
        == 0
    )
    uncovered = json.loads(uncovered_output.read_text())
    assert uncovered["summary"]["primary_case_complete_count"] == 2
    assert uncovered["summary"]["primary_gate_passed"] is False

    for field in (
        "candidate_surface_uncovered_count",
        "candidate_surface_coverage_complete",
        "carrier_only_squash_relation_root_count",
        "atomic_provenance_gap_count",
    ):
        packet_summary.pop(field)
    _write(packets / "summary.json", packet_summary)
    frozen_summary_path = uncovered_generated / "summary.json"
    frozen_summary = json.loads(frozen_summary_path.read_text())
    frozen_packet = frozen_summary["source_artifacts"]["packet_summary"]
    frozen_packet["sha256"] = hashlib.sha256(
        (packets / "summary.json").read_bytes()
    ).hexdigest()
    frozen_packet["canonical_sha256"] = canonical_sha256(packet_summary)
    _write(frozen_summary_path, frozen_summary)
    with pytest.raises(
        SystemExit,
        match="candidate_surface_uncovered_count must be a non-negative integer",
    ):
        main(
            [
                "--generated-dir",
                str(uncovered_generated),
                "--ground-truth",
                str(truth),
                "--packet-summary",
                str(packets / "summary.json"),
                "--expected-ground-truth-sha256",
                hashlib.sha256(truth.read_bytes()).hexdigest(),
                "--primary-budget",
                "2",
                "--output",
                str(tmp_path / "carrier-missing-surface-result.json"),
            ]
        )


@pytest.mark.parametrize(
    ("summary_updates", "error"),
    [
        (
            {
                "candidate_surface_uncovered_count": -1,
                "candidate_surface_coverage_complete": False,
            },
            "candidate_surface_uncovered_count must be a non-negative integer",
        ),
        (
            {
                "candidate_surface_uncovered_count": True,
                "candidate_surface_coverage_complete": False,
            },
            "candidate_surface_uncovered_count must be a non-negative integer",
        ),
        (
            {
                "candidate_surface_uncovered_count": 0,
                "candidate_surface_coverage_complete": False,
            },
            "candidate_surface_coverage_complete contradicts",
        ),
        (
            {"candidate_surface_uncovered_count": None},
            "candidate_surface_uncovered_count must be a non-negative integer",
        ),
        (
            {
                "candidate_surface_uncovered_count": 0,
                "candidate_surface_coverage_complete": True,
                "carrier_only_squash_relation_root_count": True,
            },
            "carrier_only_squash_relation_root_count must be a non-negative integer",
        ),
        (
            {
                "candidate_surface_uncovered_count": 0,
                "candidate_surface_coverage_complete": True,
                "carrier_only_squash_relation_root_count": -1,
            },
            "carrier_only_squash_relation_root_count must be a non-negative integer",
        ),
        (
            {
                "candidate_surface_uncovered_count": 0,
                "candidate_surface_coverage_complete": True,
                "atomic_provenance_gap_count": "0",
            },
            "atomic_provenance_gap_count must be a non-negative integer",
        ),
        (
            {
                "candidate_surface_uncovered_count": 0,
                "candidate_surface_coverage_complete": True,
                "atomic_provenance_gap_count": -1,
            },
            "atomic_provenance_gap_count must be a non-negative integer",
        ),
    ],
)
def test_new_packet_surface_fields_fail_closed(
    tmp_path: Path,
    summary_updates: dict[str, object],
    error: str,
) -> None:
    fix_sha = _sha("8")
    candidate = _sha("9")
    packets = tmp_path / "packets"
    packet_summary = _write_packet_artifact(
        packets,
        [_unit("unit", candidate, [(fix_sha, 1)])],
    )
    generated = tmp_path / "schedule"
    assert (
        schedule_main(
            [
                "generate",
                "--packets-dir",
                str(packets),
                "--output-dir",
                str(generated),
                "--budget",
                "1",
            ]
        )
        == 0
    )

    packet_summary.update(summary_updates)
    _write(packets / "summary.json", packet_summary)
    frozen_summary_path = generated / "summary.json"
    frozen_summary = json.loads(frozen_summary_path.read_text())
    frozen_packet = frozen_summary["source_artifacts"]["packet_summary"]
    frozen_packet["sha256"] = hashlib.sha256(
        (packets / "summary.json").read_bytes()
    ).hexdigest()
    frozen_packet["canonical_sha256"] = canonical_sha256(packet_summary)
    _write(frozen_summary_path, frozen_summary)

    truth = tmp_path / "truth.json"
    _write(
        truth,
        {
            "artifact_kind": "prospective_origin_recall_v5_blind_ground_truth",
            "cases": [
                {
                    "case_id": "CVE-2099-0001",
                    "repository": "github.com/example/repo",
                    "fix_sha": fix_sha,
                    "stratum": "direct",
                    "accepted_ai_causal_subject_shas": [candidate],
                }
            ],
            "evaluation_contract": {"budgets": [1]},
            "summary": {
                "confirmed_positive_case_count": 1,
                "accepted_exact_edge_count": 1,
            },
        },
    )
    with pytest.raises(SystemExit, match=error):
        main(
            [
                "--generated-dir",
                str(generated),
                "--ground-truth",
                str(truth),
                "--packet-summary",
                str(packets / "summary.json"),
                "--expected-ground-truth-sha256",
                hashlib.sha256(truth.read_bytes()).hexdigest(),
                "--primary-budget",
                "1",
                "--output",
                str(tmp_path / "result.json"),
            ]
        )
