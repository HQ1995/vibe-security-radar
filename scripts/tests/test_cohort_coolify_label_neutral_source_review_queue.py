"""Tests for the lossless Coolify source-review queue."""

from __future__ import annotations

from cohort_coolify_label_neutral_source_review_queue import (
    _round_robin,
    _route_lanes,
    _structural_lanes,
)


def test_removed_control_and_additive_method_get_independent_lanes() -> None:
    method = {
        "delta_kind": "ADD_METHOD_TO_EXISTING_FILE",
        "candidate_removed_control_line_count": 2,
        "candidate_removed_reachability_gate": True,
        "candidate_added_sink_line_count": 0,
        "candidate_novel_sink_line_count": 0,
    }

    lanes = _structural_lanes([method], [])

    assert "removed_control_or_reachability_gate" in lanes
    assert "additive_method_or_file" in lanes
    assert "same_method_guard_history" in lanes


def test_surface_exposure_is_not_hidden_behind_same_method_history() -> None:
    surface = {
        "delta_kind": "MODIFY_EXISTING_RUNTIME_FILE",
        "candidate_exposure_line_count": 2,
    }

    lanes = _structural_lanes([], [surface])

    assert lanes == {"new_sink_or_exposure"}


def test_strict_only_promotion_survives_contributor_union() -> None:
    strict_only = ("a" * 40, "1" * 40)
    contributor_only = ("b" * 40, "1" * 40)
    rescued = ("c" * 40, "1" * 40)
    strict = {strict_only}
    contributor = {contributor_only}
    rescue = {rescued}

    assert _route_lanes(
        strict_only,
        strict_promoted=strict,
        contributor_promoted=contributor,
        activation_rescued=rescue,
    ) == {"strict_only_promotion"}
    assert strict | contributor | rescue == {
        strict_only,
        contributor_only,
        rescued,
    }


def test_round_robin_conserves_edges_and_prevents_lane_starvation() -> None:
    edge_a = ("a" * 40, "1" * 40)
    edge_b = ("b" * 40, "1" * 40)
    edge_c = ("c" * 40, "1" * 40)
    edge_d = ("d" * 40, "1" * 40)
    universe = {edge_a, edge_b, edge_c, edge_d}
    lanes = {
        "removed": [edge_a, edge_b, edge_c],
        "additive": [edge_d],
    }

    order = _round_robin(("removed", "additive"), lanes, universe)

    assert order[:2] == [edge_a, edge_d]
    assert len(order) == len(set(order)) == len(universe)
    assert set(order) == universe


def test_round_robin_appends_edges_without_a_specialized_lane() -> None:
    edge_a = ("a" * 40, "1" * 40)
    edge_b = ("b" * 40, "1" * 40)

    order = _round_robin(("removed",), {"removed": [edge_a]}, {edge_a, edge_b})

    assert order == [edge_a, edge_b]
