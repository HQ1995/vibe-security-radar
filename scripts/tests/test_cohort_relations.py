"""Contract tests for repository and atomic-to-landed relation closure."""

from __future__ import annotations

import pytest

from cohort.relations import (
    RelationContractError,
    build_pull_relation_inventory,
    canonical_repository_identity,
    expand_candidate_edges,
    normalize_repository_aliases,
)


OLD_REPOSITORY = "github.com/old/project"
REPOSITORY = "github.com/new/project"
ORIGIN = "1" * 40
HUMAN = "2" * 40
LANDED = "3" * 40
FIX = "4" * 40


def _unit(sha: str, *, squash: bool = False) -> dict:
    return {
        "repository_identity": REPOSITORY,
        "sha": sha,
        "authored_date": "2026-02-01" if squash else "2026-01-01",
        "merge_topology": "squash" if squash else "direct",
        "pr_number": 7 if squash else None,
        "tools": ["landed"] if squash else ["origin"],
    }


def test_repository_aliases_are_transitive_and_acyclic() -> None:
    aliases = normalize_repository_aliases(
        [
            {"alias": "github.com/old/project", "canonical": "github.com/mid/project"},
            {"alias": "github.com/mid/project", "canonical": REPOSITORY},
        ]
    )

    assert canonical_repository_identity(OLD_REPOSITORY, aliases) == REPOSITORY
    assert canonical_repository_identity(REPOSITORY, aliases) == REPOSITORY

    with pytest.raises(RelationContractError, match="cycle"):
        normalize_repository_aliases(
            [
                {"alias": OLD_REPOSITORY, "canonical": REPOSITORY},
                {"alias": REPOSITORY, "canonical": OLD_REPOSITORY},
            ]
        )


def test_pull_relation_inventory_keeps_every_pr_member_for_recall() -> None:
    inventory = build_pull_relation_inventory(
        REPOSITORY,
        [_unit(ORIGIN), _unit(LANDED, squash=True)],
        {
            7: {
                "status": "RESOLVED",
                "members": [HUMAN, ORIGIN],
                "reason": "",
            }
        },
    )

    assert inventory["coverage_complete"] is True
    assert inventory["conservation"]["pull_roots_conserved"] is True
    root = inventory["pull_roots"][0]
    assert root["eligible_origin_count"] == 2
    assert root["observed_origin_count"] == 1
    assert root["unobserved_origin_count"] == 1
    relations = {row["origin_sha"]: row for row in inventory["relations"]}
    assert set(relations) == {ORIGIN, HUMAN}
    assert relations[ORIGIN] == {
            "relation_id": relations[ORIGIN]["relation_id"],
            "repository_identity": REPOSITORY,
            "origin_sha": ORIGIN,
            "landed_sha": LANDED,
            "pr_number": 7,
            "relation": "pull_request_member_landed_as_squash",
            "origin_observed_in_cohort": True,
            "origin_unit": {
                "authored_date": "2026-01-01",
                "merge_topology": "direct",
                "pr_number": None,
                "tools": ["origin"],
            },
            "landed_unit": {
                "authored_date": "2026-02-01",
                "merge_topology": "squash",
                "pr_number": 7,
                "tools": ["landed"],
            },
        }
    assert relations[HUMAN] == {
            "relation_id": relations[HUMAN]["relation_id"],
            "repository_identity": REPOSITORY,
            "origin_sha": HUMAN,
            "landed_sha": LANDED,
            "pr_number": 7,
            "relation": "pull_request_member_landed_as_squash",
            "origin_observed_in_cohort": False,
            "origin_unit": {},
            "landed_unit": {
                "authored_date": "2026-02-01",
                "merge_topology": "squash",
                "pr_number": 7,
                "tools": ["landed"],
            },
        }


def test_missing_pull_ref_is_blocked_without_fabricating_a_relation() -> None:
    inventory = build_pull_relation_inventory(
        REPOSITORY,
        [_unit(ORIGIN), _unit(LANDED, squash=True)],
        {7: {"status": "BLOCKED", "members": [], "reason": "no_pr_ref"}},
    )

    assert inventory["relations"] == []
    assert inventory["coverage_complete"] is False
    assert inventory["pull_roots"][0]["status"] == "BLOCKED"
    assert inventory["pull_roots"][0]["reason"] == "no_pr_ref"


def test_ambiguous_pr_mapping_fans_out_without_losing_members() -> None:
    other_landed = "6" * 40
    other = _unit(other_landed, squash=True)

    inventory = build_pull_relation_inventory(
        REPOSITORY,
        [_unit(LANDED, squash=True), other],
        {7: {"status": "RESOLVED", "members": [ORIGIN], "reason": ""}},
        landed_candidate_shas=[LANDED, other_landed],
    )

    assert len(inventory["relations"]) == 2
    assert inventory["coverage_complete"] is True
    assert inventory["conservation"] == {
        "pull_root_count": 2,
        "resolved_pull_root_count": 2,
        "blocked_pull_root_count": 0,
        "pull_roots_conserved": True,
    }
    assert {root["landed_sha"] for root in inventory["pull_roots"]} == {
        LANDED,
        other_landed,
    }
    assert {root["reason"] for root in inventory["pull_roots"]} == {
        "ambiguous_pr_fanout"
    }
    assert all(root["ambiguous_pr_fanout"] for root in inventory["pull_roots"])
    assert {row["origin_sha"] for row in inventory["relations"]} == {ORIGIN}
    assert {row["landed_sha"] for row in inventory["relations"]} == {
        LANDED,
        other_landed,
    }
    assert all(row["ambiguous_pr_fanout"] for row in inventory["relations"])


def test_relation_inventory_attempts_only_landed_candidates() -> None:
    unrelated_landed = "5" * 40
    unrelated = _unit(unrelated_landed, squash=True)
    unrelated["pr_number"] = 8

    inventory = build_pull_relation_inventory(
        REPOSITORY,
        [_unit(ORIGIN), _unit(LANDED, squash=True), unrelated],
        {7: {"status": "RESOLVED", "members": [ORIGIN], "reason": ""}},
        landed_candidate_shas=[LANDED],
    )

    assert [root["pr_number"] for root in inventory["pull_roots"]] == [7]
    assert inventory["conservation"]["pull_root_count"] == 1


def test_landed_ancestry_edge_expands_to_atomic_compositional_edge() -> None:
    direct = {
        "edge_id": "cohort-edge-" + "a" * 64,
        "repository_identity": REPOSITORY,
        "candidate_sha": LANDED,
        "fix_sha": FIX,
        "relation": "reachable_ancestor",
        "advisories": [{"id": "CVE-2026-1000", "published": ""}],
        "initial_status": "DEFER",
        "initial_reason": "awaiting_screening",
        "root_coverage_status": "RESOLVED",
        "root_coverage_reason": "",
    }
    relation_inventory = build_pull_relation_inventory(
        REPOSITORY,
        [_unit(ORIGIN), _unit(LANDED, squash=True)],
        {7: {"status": "RESOLVED", "members": [ORIGIN], "reason": ""}},
    )

    expanded = expand_candidate_edges([direct], relation_inventory["relations"])

    assert len(expanded) == 2
    composite = next(edge for edge in expanded if edge["candidate_sha"] == ORIGIN)
    assert composite["landed_sha"] == LANDED
    assert composite["fix_sha"] == FIX
    assert composite["relation"] == (
        "pull_request_member_landed_as_squash_then_reachable_ancestor"
    )
    assert composite["initial_status"] == "DEFER"
    assert composite["relation_path"] == [
        "pull_request_member_landed_as_squash",
        "reachable_ancestor",
    ]
    assert composite["authored_date"] == "2026-01-01"
    assert composite["tools"] == ["origin"]
    assert composite["merge_topology"] == "direct"
    assert composite["pr_number"] is None
    assert composite["relation_pr_number"] == 7
    assert composite["landed_unit"]["authored_date"] == "2026-02-01"
