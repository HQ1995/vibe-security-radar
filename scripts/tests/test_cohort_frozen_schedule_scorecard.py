"""Tests for leakage-free evaluation of a frozen candidate schedule."""

from __future__ import annotations

import pytest

from cohort_frozen_schedule_scorecard import (
    FrozenScheduleError,
    build_scorecard,
)


def _sha(character: str) -> str:
    return character * 40


def _schedule_row(candidate: str, fix: str, rank: int) -> dict[str, object]:
    return {
        "candidate_sha": candidate,
        "fix_sha": fix,
        "delta_bridge_rank": rank,
        "delta_bridge_class": "B0_CANDIDATE_ADDITION_EXACTLY_REMOVED",
        "source_review_priority_rank": rank,
    }


def _ledger(rows: list[dict[str, object]]) -> dict[str, object]:
    return {
        "edge_ledger": rows,
        "conservation": {"passed": True, "hard_delete_count": 0},
    }


def _edge(candidate: str, fix: str, status: str) -> dict[str, object]:
    return {
        "candidate_sha": candidate,
        "fix_sha": fix,
        "status": status,
    }


def test_scorecard_keeps_schedule_frozen_while_labels_advance() -> None:
    candidate_a = _sha("a")
    candidate_b = _sha("b")
    candidate_c = _sha("c")
    candidate_d = _sha("d")
    schedule = [
        _schedule_row(candidate_a, _sha("1"), 2),
        _schedule_row(candidate_b, _sha("2"), 7),
        _schedule_row(candidate_c, _sha("3"), 11),
        _schedule_row(candidate_d, _sha("4"), 20),
    ]
    baseline = _ledger(
        [
            _edge(candidate_a, _sha("9"), "CONFIRMED_TRUE_POSITIVE"),
        ]
    )
    evaluation = _ledger(
        [
            _edge(candidate_a, _sha("9"), "CONFIRMED_TRUE_POSITIVE"),
            _edge(candidate_b, _sha("2"), "CONFIRMED_TRUE_POSITIVE"),
            _edge(candidate_c, _sha("3"), "REJECTED_NONCAUSAL"),
        ]
    )

    result = build_scorecard(
        schedule=schedule,
        baseline_ledger=baseline,
        evaluation_ledger=evaluation,
        budgets=[1, 2],
    )

    assert result["summary"] == {
        "frozen_schedule_candidate_count": 4,
        "baseline_global_confirmed_candidate_count": 1,
        "evaluation_global_confirmed_candidate_count": 2,
        "baseline_confirmed_candidate_in_schedule_count": 1,
        "evaluation_confirmed_candidate_in_schedule_count": 2,
        "newly_confirmed_candidate_in_schedule_count": 1,
        "newly_confirmed_edge_count": 1,
        "newly_rejected_edge_count": 1,
        "newly_adjudicated_edge_count": 2,
        "new_edge_true_positive_yield": 0.5,
        "transition_counts": {
            "NOT_EXPLICITLY_LEDGERED->CONFIRMED_TRUE_POSITIVE": 1,
            "NOT_EXPLICITLY_LEDGERED->REJECTED_NONCAUSAL": 1,
        },
    }
    assert result["recall_at_budget"] == [
        {
            "budget": 1,
            "scheduled_unique_candidate_count": 1,
            "baseline_known_confirmed_candidate_count": 1,
            "evaluation_known_confirmed_candidate_count": 1,
            "newly_confirmed_candidate_count": 0,
            "newly_confirmed_edge_count": 0,
            "newly_rejected_edge_count": 0,
            "newly_adjudicated_edge_count": 0,
            "evaluation_known_recall_within_frozen_schedule": 0.5,
            "evaluation_known_recall_against_global_ledger": 0.5,
            "new_confirmed_candidate_capture": 0.0,
        },
        {
            "budget": 2,
            "scheduled_unique_candidate_count": 2,
            "baseline_known_confirmed_candidate_count": 1,
            "evaluation_known_confirmed_candidate_count": 2,
            "newly_confirmed_candidate_count": 1,
            "newly_confirmed_edge_count": 1,
            "newly_rejected_edge_count": 0,
            "newly_adjudicated_edge_count": 1,
            "evaluation_known_recall_within_frozen_schedule": 1.0,
            "evaluation_known_recall_against_global_ledger": 1.0,
            "new_confirmed_candidate_capture": 1.0,
        },
        {
            "budget": 4,
            "scheduled_unique_candidate_count": 4,
            "baseline_known_confirmed_candidate_count": 1,
            "evaluation_known_confirmed_candidate_count": 2,
            "newly_confirmed_candidate_count": 1,
            "newly_confirmed_edge_count": 1,
            "newly_rejected_edge_count": 1,
            "newly_adjudicated_edge_count": 2,
            "evaluation_known_recall_within_frozen_schedule": 1.0,
            "evaluation_known_recall_against_global_ledger": 1.0,
            "new_confirmed_candidate_capture": 1.0,
        },
    ]
    assert result["conservation"] == {
        "schedule_order_recomputed": False,
        "schedule_row_count": 4,
        "unique_candidate_count": 4,
        "hard_filter_count": 0,
        "baseline_confirmed_labels_preserved": True,
        "passed": True,
    }


def test_scorecard_rejects_duplicate_candidates_and_label_regression() -> None:
    candidate = _sha("a")
    duplicate_schedule = [
        _schedule_row(candidate, _sha("1"), 1),
        _schedule_row(candidate, _sha("2"), 2),
    ]
    empty = _ledger([])

    with pytest.raises(FrozenScheduleError, match="repeats candidate"):
        build_scorecard(
            schedule=duplicate_schedule,
            baseline_ledger=empty,
            evaluation_ledger=empty,
            budgets=[1],
        )

    schedule = [_schedule_row(candidate, _sha("1"), 1)]
    baseline = _ledger([_edge(candidate, _sha("1"), "CONFIRMED_TRUE_POSITIVE")])
    evaluation = _ledger([_edge(candidate, _sha("1"), "REJECTED_NONCAUSAL")])
    with pytest.raises(FrozenScheduleError, match="regressed a confirmed"):
        build_scorecard(
            schedule=schedule,
            baseline_ledger=baseline,
            evaluation_ledger=evaluation,
            budgets=[1],
        )


def test_scorecard_requires_lossless_ledgers_and_monotonic_rank() -> None:
    schedule = [
        _schedule_row(_sha("a"), _sha("1"), 5),
        _schedule_row(_sha("b"), _sha("2"), 4),
    ]
    empty = _ledger([])
    with pytest.raises(FrozenScheduleError, match="strictly increasing"):
        build_scorecard(
            schedule=schedule,
            baseline_ledger=empty,
            evaluation_ledger=empty,
            budgets=[1],
        )

    bad = {
        "edge_ledger": [],
        "conservation": {"passed": True, "hard_delete_count": 1},
    }
    with pytest.raises(FrozenScheduleError, match="hard deletions"):
        build_scorecard(
            schedule=[_schedule_row(_sha("a"), _sha("1"), 1)],
            baseline_ledger=bad,
            evaluation_ledger=empty,
            budgets=[1],
        )
