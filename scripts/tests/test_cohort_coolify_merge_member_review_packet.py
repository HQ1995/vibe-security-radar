"""Tests for merge-member semantic packet selection."""

from __future__ import annotations

import pytest

from cohort_coolify_merge_member_review_packet import (
    _as_exact_bridge_row,
    _resolve_member_edges,
)


def test_member_edge_selection_is_unique_direct_and_lossless() -> None:
    direct = {
        "candidate_sha": "a" * 40,
        "member_fix_sha": "b" * 40,
        "member_topology_class": "T0_DIRECT_MEMBER_AFTER_CANDIDATE",
        "retained": True,
        "topology_review_rank": 7,
    }
    selected = _resolve_member_edges([f"{'a' * 8}:{'b' * 8}"], [direct])
    assert selected == [direct]
    adapted = _as_exact_bridge_row(selected[0])
    assert adapted["fix_sha"] == "b" * 40
    assert adapted["delta_bridge_tier"] == 0
    assert adapted["retained"] is True


def test_member_edge_selection_refuses_non_direct_pair() -> None:
    row = {
        "candidate_sha": "a" * 40,
        "member_fix_sha": "b" * 40,
        "member_topology_class": "T1_MEMBER_LANDED_ON_CANDIDATE_FIRST_PARENT",
        "retained": True,
    }
    with pytest.raises(ValueError, match="not a direct descendant"):
        _resolve_member_edges([f"{'a' * 8}:{'b' * 8}"], [row])
