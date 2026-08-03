"""Tests for lossless origin work-unit packetization."""

from __future__ import annotations

import pytest

from cohort.origin_packets import (
    OriginPacketContractError,
    fold_candidate_fix_pairs,
    packetize_candidate_units,
)


def _pair(candidate: str, fix: str, rank: int) -> dict[str, object]:
    return {
        "advisory": "CVE-2099-0001",
        "repository_identity": "github.com/example/repo",
        "sha": candidate,
        "fix_sha": fix,
        "priority_rank": rank,
        "signals": ["affected_file_history"],
        "materialization": "structural_signal",
        "retained": True,
    }


def test_multiple_fix_edges_fold_without_losing_relations() -> None:
    candidate = "a" * 40
    rows = [
        _pair(candidate, "1" * 40, 3),
        _pair(candidate, "2" * 40, 7),
        _pair("b" * 40, "1" * 40, 2),
    ]

    units = fold_candidate_fix_pairs(rows)

    assert len(units) == 2
    folded = next(unit for unit in units if unit["candidate_sha"] == candidate)
    assert folded["fix_edge_count"] == 2
    assert folded["best_priority_rank"] == 3
    assert {edge["fix_sha"] for edge in folded["fix_edges"]} == {
        "1" * 40,
        "2" * 40,
    }
    assert sum(unit["fix_edge_count"] for unit in units) == len(rows)


def test_packet_membership_is_bounded_and_conserved() -> None:
    rows = [_pair(f"{index:040x}", "1" * 40, index) for index in range(1, 6)]
    units = fold_candidate_fix_pairs(rows)

    packets = packetize_candidate_units(units, max_candidates=2)

    assert [packet["candidate_count"] for packet in packets] == [2, 2, 1]
    assert sum(packet["candidate_count"] for packet in packets) == len(units)
    assert len(
        {unit_id for packet in packets for unit_id in packet["candidate_unit_ids"]}
    ) == len(units)


def test_duplicate_fix_pair_fails_closed() -> None:
    row = _pair("a" * 40, "1" * 40, 1)

    with pytest.raises(OriginPacketContractError, match="duplicate candidate pair"):
        fold_candidate_fix_pairs([row, row])


def test_squash_relation_provenance_survives_folding() -> None:
    row = _pair("a" * 40, "1" * 40, 1)
    row.update(
        {
            "merge_topology": "pull_request_member",
            "origin_observed_in_cohort": False,
            "ai_exposure_supported": True,
            "ai_exposure_basis": "ai_attributed_landed_squash",
            "signal_inheritance": "landed_squash_candidate_edge",
            "relation_evidence": [
                {
                    "relation": (
                        "pull_request_member_landed_as_squash_then_reachable_ancestor"
                    ),
                    "landed_sha": "b" * 40,
                    "relation_pr_number": 7,
                }
            ],
            "ancestry_certificate": (
                "pull_request_member_landed_as_squash_then_reachable_ancestor"
            ),
            "parent_priority_rank": 4,
            "squash_internal_blame_evidence": [
                {
                    "path": "src/server.py",
                    "pull_head_line": 10,
                    "content_sha256": "0" * 64,
                }
            ],
            "squash_internal_blame_line_count": 1,
            "squash_internal_blame_paths": ["src/server.py"],
        }
    )

    unit = fold_candidate_fix_pairs([row])[0]

    assert unit["merge_topology"] == "pull_request_member"
    assert unit["ai_exposure_supported"] is True
    assert unit["origin_observed_in_cohort"] is False
    edge = unit["fix_edges"][0]
    assert edge["relation_evidence"][0]["relation_pr_number"] == 7
    assert edge["parent_priority_rank"] == 4
    assert edge["squash_internal_blame_line_count"] == 1
    assert edge["squash_internal_blame_paths"] == ["src/server.py"]
