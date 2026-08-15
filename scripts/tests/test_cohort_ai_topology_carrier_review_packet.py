"""Tests for topology-carrier semantic review packet helpers."""

from __future__ import annotations

import pytest

from cohort_ai_topology_carrier_review_packet import _carrier_chain


def test_carrier_chain_requires_patch_parent_to_match_focal_parent() -> None:
    candidate_parent = "a" * 40
    other_parent = "b" * 40
    carrier = "c" * 40
    patch_id = "d" * 40
    row = {
        "strict_ancestor_carriers": [
            {
                "carrier_sha": carrier,
                "shared_patch_ids": [patch_id],
                "candidate_parent_evidence": {patch_id: [candidate_parent]},
                "carrier_parent_evidence": {patch_id: ["e" * 40]},
            }
        ]
    }

    chain = _carrier_chain(
        row,
        {
            "candidate_parent_sha": candidate_parent,
            "matching_strict_ancestor_carriers": [carrier],
        },
    )

    assert chain["patch_id"] == patch_id
    assert chain["carrier_sha"] == carrier
    with pytest.raises(ValueError, match="no carrier relation"):
        _carrier_chain(
            row,
            {
                "candidate_parent_sha": other_parent,
                "matching_strict_ancestor_carriers": [carrier],
            },
        )
