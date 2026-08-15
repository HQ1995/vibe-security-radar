"""Tests for blinded selection, hard cost reservation, and safe routing."""

from __future__ import annotations

import pytest

from cohort.routing_pilot import (
    RoutingPilotContractError,
    build_budget_contract,
    evaluate_pilot_results,
    select_blind_pilot_edges,
)


REPOSITORY = "github.com/example/project"
FIX = "f" * 40


def _edge(index: int) -> dict[str, object]:
    return {
        "edge_id": f"edge-{index}",
        "repository_identity": REPOSITORY,
        "candidate_sha": f"{index:x}" * 40,
        "fix_sha": FIX,
        "relation": "reachable_ancestor",
        "authored_date": f"2026-01-{index + 1:02d}T00:00:00+00:00",
    }


def test_selection_keeps_control_and_same_fix_comparators() -> None:
    edges = [_edge(index) for index in range(4)]
    controls = [
        {
            "advisory": "CVE-2026-1000",
            "repository_identity": REPOSITORY,
            "atomic_origin_sha": "0" * 40,
            "fix_sha": FIX,
            "expected_relation": "reachable_ancestor",
        }
    ]

    selected = select_blind_pilot_edges(edges, controls, comparators_per_control=2)

    assert len(selected) == 3
    assert sum(row["evaluation_role"] == "control" for row in selected) == 1
    assert all(row["edge"]["fix_sha"] == FIX for row in selected)


def test_sparse_control_is_kept_when_fewer_comparators_are_allowed() -> None:
    controls = [
        {
            "advisory": "CVE-2026-1000",
            "repository_identity": REPOSITORY,
            "atomic_origin_sha": "0" * 40,
            "fix_sha": FIX,
            "expected_relation": "reachable_ancestor",
        }
    ]

    selected = select_blind_pilot_edges(
        [_edge(0)],
        controls,
        comparators_per_control=3,
        require_full_comparators=False,
    )

    assert len(selected) == 1
    assert selected[0]["evaluation_role"] == "control"


def test_zero_comparators_selects_only_the_control() -> None:
    controls = [
        {
            "advisory": "CVE-2026-1000",
            "repository_identity": REPOSITORY,
            "atomic_origin_sha": "0" * 40,
            "fix_sha": FIX,
            "expected_relation": "reachable_ancestor",
        }
    ]

    selected = select_blind_pilot_edges(
        [_edge(0)], controls, comparators_per_control=0
    )

    assert len(selected) == 1
    assert selected[0]["evaluation_role"] == "control"


def test_shared_fix_controls_are_reserved_before_comparator_selection() -> None:
    controls = [
        {
            "advisory": "CVE-2026-1000:target-obligation-01",
            "repository_identity": REPOSITORY,
            "atomic_origin_sha": "0" * 40,
            "fix_sha": FIX,
            "expected_relation": "reachable_ancestor",
        },
        {
            "advisory": "CVE-2026-1000:target-obligation-02",
            "repository_identity": REPOSITORY,
            "atomic_origin_sha": "1" * 40,
            "fix_sha": FIX,
            "expected_relation": "reachable_ancestor",
        },
    ]
    edges = [_edge(index) for index in range(4)]

    selected = select_blind_pilot_edges(
        edges,
        controls,
        comparators_per_control=1,
    )

    control_candidates = {
        row["edge"]["candidate_sha"]
        for row in selected
        if row["evaluation_role"] == "control"
    }
    comparator_candidates = {
        row["edge"]["candidate_sha"]
        for row in selected
        if row["evaluation_role"] == "unlabeled_comparator"
    }
    assert control_candidates == {"0" * 40, "1" * 40}
    assert comparator_candidates == {"2" * 40, "3" * 40}
    assert control_candidates.isdisjoint(comparator_candidates)


def test_budget_fails_before_calls_when_worst_case_exceeds_cap() -> None:
    prompts = [
        {"pilot_item_id": "one", "system_prompt": "s" * 1000, "user_prompt": "u" * 1000}
    ]
    contract = build_budget_contract(
        prompts,
        input_usd_per_million="0.2",
        output_usd_per_million="1.2",
        max_output_tokens=1000,
        max_cost_usd="0.01",
    )
    assert contract["worst_case_reservation_microusd"] <= 10_000

    with pytest.raises(RoutingPilotContractError, match="exceeds cap"):
        build_budget_contract(
            prompts,
            input_usd_per_million="0.2",
            output_usd_per_million="1.2",
            max_output_tokens=1000,
            max_cost_usd="0.0001",
        )


def test_low_score_defers_and_errors_block_without_deletion() -> None:
    items = [
        {"pilot_item_id": "a", "evaluation_role": "control", "edge": _edge(0)},
        {
            "pilot_item_id": "b",
            "evaluation_role": "unlabeled_comparator",
            "edge": _edge(1),
        },
        {
            "pilot_item_id": "c",
            "evaluation_role": "unlabeled_comparator",
            "edge": _edge(2),
        },
    ]
    evaluated = evaluate_pilot_results(
        items,
        [
            {"pilot_item_id": "a", "result_status": "completed", "causality": "possible"},
            {"pilot_item_id": "b", "result_status": "completed", "causality": "unlikely"},
            {"pilot_item_id": "c", "result_status": "parse_error", "causality": ""},
        ],
    )

    assert evaluated["counts"] == {"PROMOTE": 1, "DEFER": 1, "BLOCKED": 1}
    assert evaluated["routing_conserved"] is True
    assert evaluated["scale_gate_passed"] is True
