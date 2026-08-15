"""Tests for lossless candidate-level repair dossiers."""

from __future__ import annotations

import pytest

from cohort_coolify_candidate_repair_dossiers import (
    CandidateDossierError,
    build_dossiers,
)


def _sha(character: str) -> str:
    return character * 40


def _edge(
    candidate: str,
    fix: str,
    rank: int,
    *,
    status: str = "NEW_SOURCE_OWNER_EDGE",
) -> dict[str, object]:
    return {
        "candidate_sha": candidate,
        "candidate_subject": "AI candidate",
        "candidate_authored_at": "2026-01-01T00:00:00Z",
        "fix_sha": fix,
        "fix_subject": "repair",
        "fix_authored_at": "2026-01-02T00:00:00Z",
        "delta_bridge_rank": rank,
        "delta_bridge_tier": 0,
        "delta_bridge_class": "B0_CANDIDATE_ADDITION_EXACTLY_REMOVED",
        "delta_bridge_score": 1_000 - rank,
        "source_review_priority_rank": rank,
        "source_priority_class": "P0_DIRECT_RUNTIME_PREIMAGE_OWNER",
        "ledger_edge_status": status,
        "meaningful_exact_same_path_delta_count": 1,
        "control_like_exact_same_path_delta_count": 1,
        "delta_match_counts": {"candidate_added_fix_removed:exact_same_path": 1},
        "source_addition_match_counts": {"direct_preimage:exact_same_path": 1},
        "source_pair_sha256": fix,
        "retained": True,
    }


def test_dossier_keeps_secondary_edges_and_expands_top_k() -> None:
    candidate_a = _sha("a")
    candidate_b = _sha("b")
    rows = [
        _edge(candidate_a, _sha("1"), 1),
        _edge(candidate_b, _sha("4"), 2, status="CONFIRMED_TRUE_POSITIVE"),
        _edge(candidate_a, _sha("2"), 3),
        _edge(candidate_a, _sha("3"), 9),
        _edge(candidate_b, _sha("5"), 10),
    ]

    result = build_dossiers(rows, expanded_edges_per_candidate=2)

    assert result["summary"] == {
        "retained_input_edge_count": 5,
        "retained_output_edge_count": 5,
        "candidate_dossier_count": 2,
        "active_candidate_dossier_count": 2,
        "fully_adjudicated_candidate_dossier_count": 0,
        "expanded_edges_per_candidate_limit": 2,
        "edge_lane_counts": {
            "adjudicated_reference": 1,
            "compact_rescue": 1,
            "expanded_review": 3,
        },
        "multi_edge_candidate_dossier_count": 2,
        "active_multi_edge_candidate_dossier_count": 1,
        "max_retained_repair_edges_per_candidate": 3,
    }
    first = result["dossiers"][0]
    assert first["candidate_sha"] == candidate_a
    assert [row["review_expansion_lane"] for row in first["repair_edges"]] == [
        "expanded_review",
        "expanded_review",
        "compact_rescue",
    ]
    assert result["conservation"] == {
        "all_input_edges_represented_once": True,
        "hard_filter_count": 0,
        "compact_rescue_edges_retained": True,
        "adjudicated_edges_retained_as_references": True,
        "passed": True,
    }


def test_fully_adjudicated_candidate_is_retained_after_active_dossiers() -> None:
    active = _sha("a")
    done = _sha("b")
    result = build_dossiers(
        [
            _edge(done, _sha("1"), 1, status="REJECTED_NONCAUSAL"),
            _edge(active, _sha("2"), 2),
        ],
        expanded_edges_per_candidate=3,
    )

    assert [row["candidate_sha"] for row in result["dossiers"]] == [
        active,
        done,
    ]
    assert (
        result["dossiers"][1]["repair_edges"][0]["review_expansion_lane"]
        == "adjudicated_reference"
    )
    assert result["summary"]["fully_adjudicated_candidate_dossier_count"] == 1


def test_dossier_rejects_duplicate_or_nonretained_edges() -> None:
    row = _edge(_sha("a"), _sha("1"), 1)
    with pytest.raises(CandidateDossierError, match="duplicate input edge"):
        build_dossiers([row, row], expanded_edges_per_candidate=1)

    nonretained = dict(row)
    nonretained["retained"] = False
    with pytest.raises(CandidateDossierError, match="is not retained"):
        build_dossiers([nonretained], expanded_edges_per_candidate=1)

    with pytest.raises(CandidateDossierError, match="must be positive"):
        build_dossiers([row], expanded_edges_per_candidate=0)
