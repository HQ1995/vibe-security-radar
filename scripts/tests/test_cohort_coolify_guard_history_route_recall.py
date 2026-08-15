"""Tests for label-neutral guard-history recall scoring."""

from __future__ import annotations

import cohort_coolify_guard_history_route_recall as recall


def test_route_score_treats_defer_as_retained_miss_not_negative_truth() -> None:
    edge_a = ("a" * 40, "1" * 40)
    edge_b = ("b" * 40, "1" * 40)
    route = {
        edge_a: {"disposition": "PROMOTE", "causality": "likely"},
        edge_b: {"disposition": "DEFER", "causality": "unlikely"},
    }

    score = recall._score_route(route, {edge_a, edge_b})

    assert score["known_control_edge_recall"] == 0.5
    assert score["known_control_promoted_count"] == 1
    assert score["known_control_missed_count"] == 1
    assert score["known_control_disposition_counts"] == {
        "DEFER": 1,
        "PROMOTE": 1,
    }
    assert score["missed_known_control_edges"][0]["candidate_sha"] == "b" * 40


def test_prompt_leak_detector_includes_soft_p5_signal() -> None:
    assert recall._prompt_leaks(
        [{"user_prompt": "Signals: guard_surface_history"}]
    ) == []
    assert recall._prompt_leaks(
        [{"user_prompt": "Signals: p5_already_confirmed_candidate_coverage"}]
    ) == ["p5_already_confirmed_candidate_coverage"]


def test_compatibility_activation_rescue_is_narrow_and_fix_edge_specific() -> None:
    candidate_sha = "a" * 40
    controller_edge = (candidate_sha, "1" * 40)
    route_edge = (candidate_sha, "2" * 40)
    unrelated_edge = ("b" * 40, "3" * 40)
    candidates = {
        controller_edge: {
            "commit_subject": (
                "fix: rename validate() to validateToken() to avoid parent method conflict"
            ),
            "signals": ["guard_method_history"],
        },
        route_edge: {
            "commit_subject": (
                "fix: rename validate() to validateToken() to avoid parent method conflict"
            ),
            "signals": ["guard_surface_history"],
        },
        unrelated_edge: {
            "commit_subject": "fix: rename helper for readability",
            "signals": ["guard_method_history"],
        },
    }

    assert recall._compatibility_activation_rescue_edges(candidates) == {
        controller_edge,
        route_edge,
    }
