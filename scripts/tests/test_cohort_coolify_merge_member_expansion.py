"""Tests for lossless merge-member repair expansion."""

from __future__ import annotations

from cohort_coolify_merge_member_expansion import (
    ExactDeltaIndex,
    ExactLineFact,
    build_merge_member_expansion,
)


def _fact(path: str, digest: str) -> ExactLineFact:
    return ExactLineFact(path, digest, "unsafe();", True, False)


def test_atomic_member_exact_reversal_is_attributed_without_dropping_universe() -> None:
    candidate = "a" * 40
    merge = "b" * 40
    member = "c" * 40
    key = ("app/a.php", "d" * 64)
    candidate_index = ExactDeltaIndex({key: _fact(*key)}, {}, 1)
    merge_index = ExactDeltaIndex({}, {key: _fact(*key)}, 2)
    member_index = ExactDeltaIndex({}, {key: _fact(*key)}, 1)
    source = {
        "candidate_sha": candidate,
        "candidate_subject": "AI change",
        "fix_sha": merge,
        "fix_subject": "Merge fix",
        "delta_bridge_rank": 1,
        "delta_bridge_class": "B0_CANDIDATE_ADDITION_EXACTLY_REMOVED",
        "delta_bridge_score": 100,
        "retained": True,
    }

    payload = build_merge_member_expansion(
        bridge_summary={
            "repository_identity": "github.com/coollabsio/coolify",
            "all_source_owner_pairs_conserved": True,
            "hard_filter_count": 0,
            "retained_delta_bridge_pair_count": 1,
        },
        source_pairs=[source],
        member_inventory=[
            {
                "merge_sha": merge,
                "member_shas": [member],
                "member_count": 1,
                "range_complete": True,
            }
        ],
        candidate_indexes={candidate: candidate_index},
        fix_indexes={merge: merge_index},
        member_indexes={member: member_index},
        member_metadata={member: {"message": "fix unsafe\n\nDetails."}},
        split_id="test-v1",
    )

    assert payload["summary"]["compressed_unique_candidate_member_pair_count"] == 1
    assert payload["summary"]["exact_attributed_candidate_member_pair_count"] == 1
    assert payload["edge_rows"][0]["member_attribution_class"] == (
        "M0_ATOMIC_MEMBER_EXACT_REVERSAL"
    )
    assert payload["exact_queue"][0]["member_fix_sha"] == member
    assert payload["exact_queue"][0]["candidate_subject"] == "AI change"
    assert payload["exact_queue"][0]["member_fix_subject"] == "fix unsafe"
    assert payload["summary"]["all_source_merge_edges_conserved"] is True


def test_unattributed_exact_reversal_remains_resolution_only() -> None:
    candidate = "a" * 40
    merge = "b" * 40
    member = "c" * 40
    key = ("app/a.php", "d" * 64)
    payload = build_merge_member_expansion(
        bridge_summary={
            "all_source_owner_pairs_conserved": True,
            "hard_filter_count": 0,
            "retained_delta_bridge_pair_count": 1,
        },
        source_pairs=[
            {
                "candidate_sha": candidate,
                "fix_sha": merge,
                "retained": True,
            }
        ],
        member_inventory=[
            {
                "merge_sha": merge,
                "member_shas": [member],
                "member_count": 1,
                "range_complete": True,
            }
        ],
        candidate_indexes={
            candidate: ExactDeltaIndex({key: _fact(*key)}, {}, 1)
        },
        fix_indexes={merge: ExactDeltaIndex({}, {key: _fact(*key)}, 2)},
        member_indexes={member: ExactDeltaIndex({}, {}, 1)},
        member_metadata={},
        split_id="test-v1",
    )

    assert payload["exact_queue"] == []
    assert payload["edge_rows"][0]["member_attribution_class"] == (
        "M2_MERGE_RESOLUTION_EXACT_REVERSAL"
    )
    assert payload["edge_rows"][0]["retained"] is True
