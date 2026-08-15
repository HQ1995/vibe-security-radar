"""Campaign tests for compositional candidate relation closure."""

from __future__ import annotations

import cohort_relation_closure as closure


REPOSITORY = "github.com/example/project"
ORIGIN = "1" * 40
LANDED = "3" * 40
FIX = "4" * 40


def _units() -> dict[str, list[dict[str, object]]]:
    return {
        REPOSITORY: [
            {
                "repository_identity": REPOSITORY,
                "sha": ORIGIN,
                "merge_topology": "direct",
                "pr_number": None,
            },
            {
                "repository_identity": REPOSITORY,
                "sha": LANDED,
                "merge_topology": "squash",
                "pr_number": 7,
            },
        ]
    }


def _edge() -> dict[str, object]:
    return {
        "edge_id": "cohort-edge-" + "a" * 64,
        "repository_identity": REPOSITORY,
        "candidate_sha": LANDED,
        "fix_sha": FIX,
        "relation": "reachable_ancestor",
        "advisories": [{"id": "CVE-2026-1000", "published": ""}],
        "initial_status": "DEFER",
        "initial_reason": "awaiting_screening",
    }


def test_campaign_expands_only_candidate_landed_squashes() -> None:
    artifacts = closure.build_relation_campaign(
        [_edge()],
        _units(),
        {
            REPOSITORY: {
                7: {"status": "RESOLVED", "members": [ORIGIN], "reason": ""}
            }
        },
    )

    assert len(artifacts["relations"]) == 1
    assert len(artifacts["candidates_expanded"]) == 2
    assert artifacts["summary"]["composite_edge_count"] == 1
    assert artifacts["summary"]["conservation"]["candidate_edges_conserved"] is True
    assert {row["status"] for row in artifacts["routing_expanded"]} == {"DEFER"}


def test_missing_pull_result_is_blocked_and_direct_edge_survives() -> None:
    artifacts = closure.build_relation_campaign([_edge()], _units(), {})

    assert artifacts["relations"] == []
    assert artifacts["relation_roots"][0]["status"] == "BLOCKED"
    assert artifacts["relation_roots"][0]["reason"] == "pull_result_missing"
    assert artifacts["candidates_expanded"] == [_edge()]
