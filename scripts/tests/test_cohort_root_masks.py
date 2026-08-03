"""Tests for compressed source-root reachability overlays."""

from __future__ import annotations

from cohort.root_masks import build_repository_root_masks


REPOSITORY = "github.com/acme/project"
FIRST = "1" * 40
SECOND = "2" * 40
THIRD = "3" * 40
MISSING = "4" * 40


def _commit(sha: str, parents: list[str]) -> dict[str, object]:
    return {
        "repository_identity": REPOSITORY,
        "sha": sha,
        "parents": parents,
    }


def _observation(sha: str, identifier: str) -> dict[str, object]:
    return {
        "repository_identity": REPOSITORY,
        "advisory": "CVE-1",
        "observation_id": identifier,
        "fix_ref": sha,
        "fix_sha": sha,
        "evidence_kind": "public_exact",
        "resolution_status": "RESOLVED",
        "resolution_reason": "",
    }


def _summary(status: str = "RESOLVED") -> dict[str, object]:
    return {
        "repository_identity": REPOSITORY,
        "universe_id": "universe",
        "status": status,
    }


def test_shared_ancestry_is_one_row_per_commit_with_a_root_bit_mask() -> None:
    result = build_repository_root_masks(
        _summary(),
        [
            _commit(FIRST, []),
            _commit(SECOND, [FIRST]),
            _commit(THIRD, [SECOND]),
        ],
        [_observation(SECOND, "two"), _observation(THIRD, "three")],
    )

    masks = {row["sha"]: row["root_mask_hex"] for row in result["membership_rows"]}
    assert masks == {FIRST: "3", SECOND: "3", THIRD: "2"}
    assert len(result["membership_rows"]) == 3
    assert len(result["root_rows"]) == 2
    assert result["summary"]["fallback_scope_unchanged"] is True


def test_incomplete_universe_keeps_partial_masks_but_blocks_root_coverage() -> None:
    result = build_repository_root_masks(
        _summary("BLOCKED"),
        [_commit(FIRST, []), _commit(SECOND, [FIRST])],
        [_observation(SECOND, "two")],
    )

    assert len(result["membership_rows"]) == 2
    assert result["root_rows"][0]["status"] == "BLOCKED"
    assert result["root_rows"][0]["block_reasons"] == [
        "repository_universe_incomplete"
    ]


def test_root_missing_from_universe_is_blocked_not_dropped() -> None:
    result = build_repository_root_masks(
        _summary(),
        [_commit(FIRST, [])],
        [_observation(MISSING, "missing")],
    )

    assert result["membership_rows"] == []
    assert result["root_rows"][0]["status"] == "BLOCKED"
    assert result["root_rows"][0]["block_reasons"] == [
        "source_root_not_in_commit_universe"
    ]
