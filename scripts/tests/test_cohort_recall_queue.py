"""Tests for the all-commit recall queue contract."""

from __future__ import annotations

import pytest

from cohort.recall_queue import (
    COMMIT_PRIORITIES,
    ROOT_CARRIER,
    ROOT_CORROBORATED,
    ROOT_PRIORITY,
    RecallQueueContractError,
    build_root_priorities,
    commit_priority,
)


def test_root_priorities_retain_selected_corroborated_and_carrier_roots() -> None:
    roots = [
        {
            "root_id": "r1",
            "repository_identity": "github.com/acme/repo",
            "root_sha": "1" * 40,
            "bit_index": 0,
            "status": "RESOLVED",
            "evidence_kinds": ["ranked_search_carrier"],
        },
        {
            "root_id": "r2",
            "repository_identity": "github.com/acme/repo",
            "root_sha": "2" * 40,
            "bit_index": 1,
            "status": "BLOCKED",
            "evidence_kinds": ["repository_reference_carrier"],
        },
        {
            "root_id": "r3",
            "repository_identity": "github.com/acme/repo",
            "root_sha": "3" * 40,
            "bit_index": 2,
            "status": "RESOLVED",
            "evidence_kinds": ["ranked_search_carrier"],
        },
    ]

    rows = build_root_priorities(
        roots,
        {("github.com/acme/repo", "1" * 40): ["model_selected_root"]},
    )

    assert [row["priority_class"] for row in rows] == [
        ROOT_PRIORITY,
        ROOT_CORROBORATED,
        ROOT_CARRIER,
    ]
    assert all(row["retained"] is True for row in rows)
    assert rows[1]["root_coverage_status"] == "BLOCKED"


def test_unknown_priority_root_fails_closed() -> None:
    with pytest.raises(RecallQueueContractError, match="unknown roots"):
        build_root_priorities(
            [], {("github.com/acme/repo", "f" * 40): ["model_selected_root"]}
        )


@pytest.mark.parametrize(
    ("observed_ai", "root_mask", "priority_mask", "expected"),
    [
        (True, 0b01, 0b01, COMMIT_PRIORITIES[0]),
        (False, 0b01, 0b01, COMMIT_PRIORITIES[1]),
        (True, 0b10, 0b01, COMMIT_PRIORITIES[2]),
        (False, 0b10, 0b01, COMMIT_PRIORITIES[3]),
        (True, 0, 0b01, COMMIT_PRIORITIES[4]),
        (False, 0, 0b01, COMMIT_PRIORITIES[5]),
    ],
)
def test_commit_priority_is_total_and_never_drops_fallbacks(
    observed_ai, root_mask, priority_mask, expected
) -> None:
    assert (
        commit_priority(
            observed_ai_unit=observed_ai,
            root_mask=root_mask,
            priority_root_mask=priority_mask,
        )
        == expected
    )
