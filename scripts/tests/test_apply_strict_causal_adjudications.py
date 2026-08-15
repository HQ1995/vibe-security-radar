from __future__ import annotations

import pytest

from apply_strict_causal_adjudications import (
    _filter_edges,
    _validate_partition,
    _validate_source_edge,
)
from merge_strict_ai_causal_supplement import (
    CONTRIBUTION_KINDS,
    _apply_alias_amendments,
)


def test_causal_partition_is_exhaustive_and_disjoint() -> None:
    _validate_partition({"a", "b", "c"}, ["a"], ["b"], ["c"])
    with pytest.raises(SystemExit, match="overlap"):
        _validate_partition({"a", "b"}, ["a"], ["a"], ["b"])
    with pytest.raises(SystemExit, match="do not cover"):
        _validate_partition({"a", "b"}, ["a"], [], [])


def test_squash_member_requires_distinct_carrier() -> None:
    edge = {
        "candidate_sha": "a" * 40,
        "carrier_sha": "c" * 40,
        "fix_sha": "f" * 40,
        "origin_kind": "squash_member",
        "ai_signal": "Co-Authored-By: Claude <noreply@anthropic.com>",
    }
    assert _validate_source_edge(edge, "component")["candidate_sha"] == "a" * 40
    edge.pop("carrier_sha")
    with pytest.raises(SystemExit, match="malformed source edge"):
        _validate_source_edge(edge, "component")


def test_incomplete_hardening_is_never_a_positive_contribution_kind() -> None:
    assert "incomplete_hardening_contributor" not in CONTRIBUTION_KINDS


def test_rejected_edge_is_removed_exactly_once() -> None:
    def edge(candidate: str, fix: str) -> dict[str, str]:
        return {
            "candidate_sha": candidate * 40,
            "fix_sha": fix * 40,
            "origin_kind": "direct_commit",
            "ai_signal": "Co-Authored-By: Claude <noreply@anthropic.com>",
        }

    row = {
        "component_id": "component",
        "evidence": [{"accepted_edges": [edge("a", "f"), edge("b", "e")]}],
    }
    filtered, remaining = _filter_edges(row, {("a" * 40, "f" * 40)})
    assert [value["candidate_sha"] for value in remaining] == ["b" * 40]
    assert len(filtered["evidence"][0]["accepted_edges"]) == 1
    with pytest.raises(SystemExit, match="not removed exactly once"):
        _filter_edges(row, {("c" * 40, "d" * 40)})


def test_first_party_alias_amendment_updates_existing_component() -> None:
    ledger = [
        {
            "component_id": "component",
            "public_ids": ["CVE-2026-10000"],
            "evidence": [],
        }
    ]
    count = _apply_alias_amendments(
        ledger,
        [
            {
                "component_id": "component",
                "public_id": "GHSA-AAAA-BBBB-CCCC",
                "relationship": "first_party_cve_alias",
                "evidence": "Published repository advisory names the CVE.",
                "source": "https://github.com/example/repo/security/advisories/GHSA-aaaa-bbbb-cccc",
            }
        ],
    )
    assert count == 1
    assert ledger[0]["public_ids"] == [
        "CVE-2026-10000",
        "GHSA-AAAA-BBBB-CCCC",
    ]
    assert ledger[0]["evidence"][0]["kind"] == "public_id_alias_amendment"
