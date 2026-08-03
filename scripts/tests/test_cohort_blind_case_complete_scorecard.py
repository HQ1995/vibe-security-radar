"""Tests for strict same-fix blind case recall."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cohort.root_adjudication import canonical_sha256
from cohort_blind_case_complete_scorecard import main
from cohort_candidate_unit_scorecard import main as schedule_main


def _sha(character: str) -> str:
    return character * 40


def _write(path: Path, value: object, *, jsonl: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = value if isinstance(value, list) else [value]
    text = (
        "".join(json.dumps(row) + "\n" for row in rows)
        if jsonl
        else json.dumps(value)
    )
    path.write_text(text, encoding="utf-8")


def _unit(
    unit_id: str, candidate: str, edges: list[tuple[str, int]]
) -> dict[str, object]:
    return {
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
    assert schedule_main(
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
    ) == 0

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

    def score(selected_cases: list[dict[str, object]], name: str) -> dict[str, object]:
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
        assert main(
            [
                "--generated-dir",
                str(generated),
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
        ) == 0
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
    passed = score(cases[:2], "passed")
    assert passed["summary"]["primary_case_complete_count"] == 2
    assert passed["summary"]["primary_gate_passed"] is True
