"""Contract tests for the recall-first forward-cohort candidate inventory."""

from __future__ import annotations

import pytest

from cohort.advisory_candidates import (
    CandidateContractError,
    build_blocked_repository_inventory,
    build_bidirectional_ledger,
    build_campaign_artifacts,
    build_repository_inventory,
    build_routing_manifest,
)


REPOSITORY = "github.com/example/project"
ROOT = "1" * 40
FIRST = "2" * 40
SECOND = "3" * 40
FIX = "4" * 40
UNRELATED = "5" * 40
MEMBER_AI = "6" * 40
MEMBER_UNKNOWN = "7" * 40


def _unit(sha: str, *, route: str = "assistant_direct") -> dict:
    return {
        "repository_identity": REPOSITORY,
        "sha": sha,
        "authored_date": "2025-06-01T00:00:00+00:00",
        "route": route,
        "tier": "A_no_decomposition_needed",
        "tools": ["claude_code"],
    }


def _fixes() -> list[dict[str, str]]:
    return [
        {
            "advisory": "GHSA-aaaa-bbbb-cccc",
            "fix_sha": FIX,
            "published": "2026-01-02T00:00:00Z",
        },
        {
            "advisory": "CVE-2026-1000",
            "fix_sha": FIX,
            "published": "2026-01-01T00:00:00Z",
        },
        # Repeated OSV references must not duplicate an edge or advisory.
        {
            "advisory": "CVE-2026-1000",
            "fix_sha": FIX,
            "published": "2026-01-01T00:00:00Z",
        },
    ]


def _parent_index() -> dict:
    return {
        "schema_version": 1,
        "artifact_kind": "repo_commit_parent_index",
        "repository_identity": REPOSITORY,
        "since": "2024-01-01",
        "complete": True,
        "error": "",
        "roots": [FIX],
        "refs_view": {"shallow_commits": []},
        "commits": [
            {"sha": FIX, "parents": [SECOND], "cutoff_boundary": False},
            {"sha": SECOND, "parents": [FIRST], "cutoff_boundary": False},
            {"sha": FIRST, "parents": [ROOT], "cutoff_boundary": False},
            {"sha": ROOT, "parents": [], "cutoff_boundary": False},
            {"sha": UNRELATED, "parents": [], "cutoff_boundary": False},
        ],
    }


def test_inventory_is_uncapped_alias_deduplicated_and_reachability_only() -> None:
    inventory = build_repository_inventory(
        REPOSITORY,
        [_unit(UNRELATED), _unit(FIX), _unit(SECOND), _unit(FIRST)],
        _fixes(),
        _parent_index(),
    )

    assert inventory["coverage_complete"] is True
    assert inventory["conservation"] == {
        "fix_root_count": 1,
        "resolved_fix_root_count": 1,
        "blocked_fix_root_count": 0,
        "fix_roots_conserved": True,
    }
    assert {edge["candidate_sha"] for edge in inventory["candidate_edges"]} == {
        FIRST,
        SECOND,
    }
    assert all(edge["relation"] == "reachable_ancestor" for edge in inventory["candidate_edges"])
    assert all(edge["initial_status"] == "DEFER" for edge in inventory["candidate_edges"])
    assert len({edge["edge_id"] for edge in inventory["candidate_edges"]}) == 2

    root = inventory["fix_roots"][0]
    assert root["status"] == "RESOLVED"
    assert root["candidate_edge_count"] == 2
    assert [item["id"] for item in root["advisories"]] == [
        "CVE-2026-1000",
        "GHSA-aaaa-bbbb-cccc",
    ]


def test_inventory_identity_is_stable_under_input_order() -> None:
    units = [_unit(FIRST), _unit(SECOND), _unit(UNRELATED)]
    first = build_repository_inventory(REPOSITORY, units, _fixes(), _parent_index())
    second = build_repository_inventory(
        REPOSITORY,
        list(reversed(units)),
        list(reversed(_fixes())),
        {**_parent_index(), "commits": list(reversed(_parent_index()["commits"]))},
    )

    assert first == second


def test_reachable_squash_carrier_expands_all_members_without_losing_carrier() -> None:
    unit = {
        **_unit(FIRST, route="assistant_squash"),
        "tier": "B_decomposed",
        "member_shas": [MEMBER_UNKNOWN, MEMBER_AI],
        "ai_member_shas": [MEMBER_AI],
        "member_ai_tools": {MEMBER_AI: ["claude_code"]},
    }

    inventory = build_repository_inventory(
        REPOSITORY, [unit], _fixes(), _parent_index()
    )

    edges = inventory["candidate_edges"]
    assert {(edge["candidate_sha"], edge["relation"]) for edge in edges} == {
        (FIRST, "reachable_ancestor"),
        (MEMBER_AI, "squash_pr_member"),
        (MEMBER_UNKNOWN, "squash_pr_member"),
    }
    member_edges = {
        edge["candidate_sha"]: edge
        for edge in edges
        if edge["relation"] == "squash_pr_member"
    }
    assert member_edges[MEMBER_AI]["member_ai_attributed"] is True
    assert member_edges[MEMBER_AI]["tools"] == ["claude_code"]
    assert member_edges[MEMBER_UNKNOWN]["member_ai_attributed"] is False
    assert member_edges[MEMBER_UNKNOWN]["tools"] == []
    assert all(edge["carrier_shas"] == [FIRST] for edge in member_edges.values())


@pytest.mark.parametrize(
    ("parent_index", "reason", "expected_candidates"),
    [
        (
            {
                **_parent_index(),
                "complete": False,
                "error": "root_objects_unavailable",
                "commits": [],
            },
            "root_objects_unavailable",
            set(),
        ),
        (
            {
                **_parent_index(),
                "refs_view": {"shallow_commits": [FIRST]},
            },
            "shallow_history_boundary",
            {FIRST, SECOND},
        ),
    ],
)
def test_incomplete_history_blocks_the_fix_but_keeps_proven_positive_edges(
    parent_index: dict, reason: str, expected_candidates: set[str]
) -> None:
    inventory = build_repository_inventory(
        REPOSITORY,
        [_unit(FIRST), _unit(SECOND)],
        _fixes(),
        parent_index,
    )

    assert inventory["coverage_complete"] is False
    assert {
        edge["candidate_sha"] for edge in inventory["candidate_edges"]
    } == expected_candidates
    assert all(
        edge["root_coverage_status"] == "BLOCKED"
        for edge in inventory["candidate_edges"]
    )
    assert inventory["fix_roots"][0]["status"] == "BLOCKED"
    assert inventory["fix_roots"][0]["reason"] == reason
    assert inventory["fix_roots"][0]["candidate_unit_count"] == 2
    assert inventory["conservation"]["fix_roots_conserved"] is True


def test_cutoff_boundary_is_complete_for_the_same_or_later_cohort_window() -> None:
    parent_index = _parent_index()
    parent_index["commits"] = [
        {"sha": FIX, "parents": [SECOND], "cutoff_boundary": False},
        {"sha": SECOND, "parents": [FIRST], "cutoff_boundary": False},
        # Its unlisted parents predate the shared cohort/index cutoff.
        {"sha": FIRST, "parents": [ROOT], "cutoff_boundary": True},
    ]

    inventory = build_repository_inventory(
        REPOSITORY,
        [_unit(FIRST), _unit(SECOND)],
        _fixes(),
        parent_index,
    )

    assert inventory["coverage_complete"] is True
    assert {edge["candidate_sha"] for edge in inventory["candidate_edges"]} == {
        FIRST,
        SECOND,
    }


def test_routing_manifest_conserves_every_edge_exactly_once() -> None:
    inventory = build_repository_inventory(
        REPOSITORY,
        [_unit(FIRST), _unit(SECOND)],
        _fixes(),
        _parent_index(),
    )
    edge_ids = [edge["edge_id"] for edge in inventory["candidate_edges"]]

    routing = build_routing_manifest(
        inventory["candidate_edges"],
        promoted_edge_ids=[edge_ids[0]],
        blocked_edges={edge_ids[1]: "screening_response_unavailable"},
    )

    assert routing["counts"] == {"PROMOTE": 1, "DEFER": 0, "BLOCKED": 1}
    assert routing["conservation"]["candidate_edges_conserved"] is True
    assert {route["edge_id"] for route in routing["routes"]} == set(edge_ids)


def test_model_negative_means_defer_not_drop() -> None:
    inventory = build_repository_inventory(
        REPOSITORY,
        [_unit(FIRST), _unit(SECOND)],
        _fixes(),
        _parent_index(),
    )

    routing = build_routing_manifest(inventory["candidate_edges"])

    assert routing["counts"] == {"PROMOTE": 0, "DEFER": 2, "BLOCKED": 0}
    assert {route["status"] for route in routing["routes"]} == {"DEFER"}


@pytest.mark.parametrize("unknown_channel", ["promote", "block"])
def test_routing_rejects_unknown_model_edge_ids(unknown_channel: str) -> None:
    inventory = build_repository_inventory(
        REPOSITORY,
        [_unit(FIRST)],
        _fixes(),
        _parent_index(),
    )
    unknown = "edge-" + "f" * 64

    with pytest.raises(CandidateContractError, match="unknown edge"):
        build_routing_manifest(
            inventory["candidate_edges"],
            promoted_edge_ids=[unknown] if unknown_channel == "promote" else [],
            blocked_edges={unknown: "failed"} if unknown_channel == "block" else {},
        )


def test_routing_rejects_overlapping_dispositions() -> None:
    inventory = build_repository_inventory(
        REPOSITORY,
        [_unit(FIRST)],
        _fixes(),
        _parent_index(),
    )
    edge_id = inventory["candidate_edges"][0]["edge_id"]

    with pytest.raises(CandidateContractError, match="both PROMOTE and BLOCKED"):
        build_routing_manifest(
            inventory["candidate_edges"],
            promoted_edge_ids=[edge_id],
            blocked_edges={edge_id: "failed"},
        )


def test_unresolvable_fix_reference_is_preserved_as_blocked() -> None:
    short_fix = FIX[:12]
    inventory = build_blocked_repository_inventory(
        REPOSITORY,
        [_unit(FIRST), _unit(SECOND)],
        [
            {"advisory": "CVE-2026-1000", "fix_sha": short_fix, "published": ""},
            {"advisory": "CVE-2026-1000", "fix_sha": short_fix, "published": ""},
        ],
        reason="fix_object_unavailable_or_ambiguous",
    )

    assert inventory["candidate_edges"] == []
    assert inventory["coverage_complete"] is False
    assert inventory["fix_roots"][0]["fix_ref"] == short_fix
    assert inventory["fix_roots"][0]["status"] == "BLOCKED"
    assert inventory["fix_roots"][0]["candidate_unit_count"] == 2
    assert inventory["conservation"]["fix_roots_conserved"] is True


def test_campaign_artifacts_conserve_resolved_and_blocked_roots_and_edges() -> None:
    resolved = build_repository_inventory(
        REPOSITORY,
        [_unit(FIRST), _unit(SECOND)],
        _fixes(),
        _parent_index(),
    )
    blocked = build_blocked_repository_inventory(
        "github.com/example/missing",
        [
            {
                **_unit(FIRST),
                "repository_identity": "github.com/example/missing",
            }
        ],
        [
            {
                "advisory": "CVE-2026-2000",
                "fix_sha": "a" * 12,
                "published": "",
            }
        ],
        reason="no_local_clone",
    )

    artifacts = build_campaign_artifacts([resolved, blocked])

    assert artifacts["summary"]["coverage_complete"] is False
    assert artifacts["summary"]["conservation"] == {
        "fix_root_count": 2,
        "resolved_fix_root_count": 1,
        "blocked_fix_root_count": 1,
        "fix_roots_conserved": True,
        "candidate_edge_count": 2,
        "promoted_edge_count": 0,
        "deferred_edge_count": 2,
        "blocked_edge_count": 0,
        "candidate_edges_conserved": True,
    }
    assert artifacts["routing"]["counts"] == {
        "PROMOTE": 0,
        "DEFER": 2,
        "BLOCKED": 0,
    }


def test_bidirectional_ledger_conserves_both_single_end_lanes() -> None:
    units = [_unit(FIRST), _unit(SECOND), _unit(UNRELATED)]
    inventory = build_repository_inventory(
        REPOSITORY, units, _fixes(), _parent_index()
    )
    introductions = {
        REPOSITORY: [
            {
                "introduced_sha": FIRST,
                "record_id": "GHSA-aaaa-bbbb-cccc",
                "public_ids": ["CVE-2026-1000", "GHSA-AAAA-BBBB-CCCC"],
                "published": "2026-01-01T00:00:00Z",
            },
            {
                "introduced_sha": UNRELATED,
                "record_id": "CVE-2026-2000",
                "public_ids": ["CVE-2026-2000"],
                "published": "2026-02-01T00:00:00Z",
            },
        ]
    }

    artifacts = build_bidirectional_ledger(
        inventory["candidate_edges"], {REPOSITORY: units}, introductions
    )

    assert artifacts["summary"]["status_counts"] == {
        "AI_END_ONLY": 1,
        "BOTH_ENDS": 2,
        "FIX_END_ONLY": 2,
    }
    assert artifacts["summary"]["conservation"] == {
        "forward_advisory_edge_count": 4,
        "reverse_exact_pair_count": 3,
        "reverse_pairs_with_forward_count": 2,
        "reverse_pairs_without_forward_count": 1,
        "ledger_row_count": 5,
        "ledger_rows_conserved": True,
        "forward_rows_conserved": True,
        "reverse_pairs_conserved": True,
    }
