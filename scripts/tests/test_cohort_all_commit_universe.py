"""Tests for repository-wide recall-first commit universes."""

from __future__ import annotations

from cohort.all_commit_universe import (
    build_repository_fallbacks,
    build_repository_universe,
)


REPOSITORY = "github.com/acme/project"
FIRST = "1" * 40
SECOND = "2" * 40
MISSING = "3" * 40


def _record(sha: str, parents: list[str], timestamp: int) -> dict[str, object]:
    return {
        "sha": sha,
        "parents": parents,
        "committer_timestamp": timestamp,
    }


def _ai_unit(sha: str) -> dict[str, object]:
    return {
        "repository_identity": REPOSITORY,
        "sha": sha,
        "route": "assistant_direct",
        "tools": ["copilot"],
    }


def test_every_visible_commit_is_retained_and_ai_is_only_an_overlay() -> None:
    result = build_repository_universe(
        REPOSITORY,
        [_record(SECOND, [FIRST], 2), _record(FIRST, [], 1)],
        [_ai_unit(SECOND)],
        expected_ai_unit_count=1,
        refs_sha256="a" * 64,
    )

    assert result["summary"]["status"] == "RESOLVED"
    assert [row["sha"] for row in result["commit_rows"]] == [FIRST, SECOND]
    assert [row["observed_ai_unit"] for row in result["commit_rows"]] == [
        False,
        True,
    ]
    assert result["summary"]["visible_commit_count"] == 2
    assert result["summary"]["observed_ai_unit_count"] == 1


def test_missing_parent_blocks_repository_without_dropping_visible_commit() -> None:
    result = build_repository_universe(
        REPOSITORY,
        [_record(SECOND, [MISSING], 2)],
        [_ai_unit(SECOND)],
        expected_ai_unit_count=1,
        refs_sha256="a" * 64,
    )

    assert result["summary"]["status"] == "BLOCKED"
    assert "parent_closure_incomplete" in result["summary"]["block_reasons"]
    assert len(result["commit_rows"]) == 1
    assert result["blocked_items"] == [
        {
            "repository_identity": REPOSITORY,
            "item_kind": "missing_parent",
            "sha": MISSING,
            "status": "BLOCKED",
            "reason": "parent_not_enumerated_from_local_refs",
        }
    ]


def test_missing_ai_commit_blocks_instead_of_becoming_a_negative() -> None:
    result = build_repository_universe(
        REPOSITORY,
        [_record(FIRST, [], 1)],
        [_ai_unit(MISSING)],
        expected_ai_unit_count=1,
        refs_sha256="a" * 64,
    )

    assert result["summary"]["status"] == "BLOCKED"
    assert result["summary"]["missing_ai_unit_count"] == 1
    assert result["blocked_items"][0]["item_kind"] == "ai_unit"
    assert result["blocked_items"][0]["status"] == "BLOCKED"


def test_fallback_is_one_compressed_reference_not_commit_cartesian_rows() -> None:
    built = build_repository_universe(
        REPOSITORY,
        [_record(SECOND, [FIRST], 2), _record(FIRST, [], 1)],
        [_ai_unit(SECOND)],
        expected_ai_unit_count=1,
        refs_sha256="a" * 64,
    )
    selected = [
        {
            "repository_identity": REPOSITORY,
            "advisory": "CVE-1",
            "source_class": "association_only",
        }
    ]
    fallbacks = build_repository_fallbacks(
        selected, {REPOSITORY: built["summary"]}
    )

    assert len(fallbacks) == 1
    assert fallbacks[0]["candidate_commit_count"] == 2
    assert fallbacks[0]["materialization"] == (
        "compressed_repository_universe_reference"
    )
