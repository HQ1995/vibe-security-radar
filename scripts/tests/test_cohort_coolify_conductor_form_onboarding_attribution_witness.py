"""Tests for deterministic Coolify form/onboarding attribution helpers."""

from __future__ import annotations

import pytest

import cohort_coolify_conductor_form_onboarding_attribution_witness as witness


def test_added_lines_excludes_patch_headers() -> None:
    assert witness._added_lines("+++ b/file\n+new\n context\n-old") == ("new",)


def test_position_before_requires_both_markers_in_order() -> None:
    assert witness._position_before("button then input", "button", "input") is True
    assert witness._position_before("input then button", "button", "input") is False
    assert witness._position_before("button only", "button", "input") is False


def test_bridge_edge_requires_one_exact_edge() -> None:
    rows = [
        {
            "candidate_sha": "a" * 40,
            "fix_sha": "b" * 40,
            "retained": True,
            "delta_bridge_tier": 0,
            "delta_bridge_class": "B0_CANDIDATE_ADDITION_EXACTLY_REMOVED",
        }
    ]

    assert witness._bridge_edge(rows, "a" * 40, "b" * 40) == rows[0]
    with pytest.raises(ValueError, match="resolved to 0"):
        witness._bridge_edge(rows, "c" * 40, "d" * 40)


def test_result_keeps_rejected_candidate_and_accepts_replacement() -> None:
    row = {
        "retained": True,
        "delta_bridge_tier": 0,
        "delta_bridge_class": "B0_CANDIDATE_ADDITION_EXACTLY_REMOVED",
        "source_pair_sha256": "f" * 64,
    }
    replacement = {
        "candidate_sha": "c" * 40,
        "fix_sha": "d" * 40,
        "adjudication": "CONFIRMED_DIRECT_AI_EXAMPLE",
    }

    result = witness._result(
        key="example",
        candidate_sha="a" * 40,
        fix_sha="b" * 40,
        disposition="REJECTED_WRONG_ORIGIN",
        reason="the actual origin is later",
        bridge_row=row,
        checks={"preimage_proves_wrong_origin": True},
        replacement=replacement,
    )

    assert result["candidate_retained"] is True
    assert result["replacement"] == replacement
    assert result["witness_passed"] is True


def test_result_fails_closed_when_any_causal_check_fails() -> None:
    row = {
        "retained": True,
        "delta_bridge_tier": 0,
        "delta_bridge_class": "B0_CANDIDATE_ADDITION_EXACTLY_REMOVED",
    }

    result = witness._result(
        key="example",
        candidate_sha="a" * 40,
        fix_sha="b" * 40,
        disposition="REJECTED_WRONG_ORIGIN",
        reason="missing preimage",
        bridge_row=row,
        checks={"preimage_proves_wrong_origin": False},
        replacement=None,
    )

    assert result["witness_passed"] is False
