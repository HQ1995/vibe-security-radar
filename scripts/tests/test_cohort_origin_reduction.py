"""Tests for proof-carrying origin candidate reduction."""

from __future__ import annotations

import pytest

from cohort.origin_reduction import (
    OriginReductionContractError,
    reduce_origin_candidates,
)


def _row(sha: str, **extra: object) -> dict[str, object]:
    return {"sha": sha, **extra}


def test_complete_observation_uses_exact_ai_ancestor_intersection() -> None:
    ancestor_a = "a" * 40
    ancestor_b = "b" * 40
    ancestor_c = "c" * 40
    other_branch = "d" * 40

    result = reduce_origin_candidates(
        [ancestor_a, ancestor_b, ancestor_c],
        [
            _row(
                ancestor_b,
                tools=["claude_code"],
                merge_topology="squash",
                pr_number=17,
                squash_attribution_only=True,
            ),
            _row(other_branch),
        ],
        [_row(ancestor_b, signals=["add_context_blame"], priority_rank=3)],
        observation_complete=True,
    )

    assert [row["sha"] for row in result["candidates"]] == [ancestor_b]
    assert result["certified_non_ancestor_shas"] == [other_branch]
    assert result["unobserved_ancestor_count"] == 2
    assert result["retained_candidate_count"] == 1
    assert result["status"] == "RESOLVED"
    assert result["candidates"][0]["pr_number"] == 17
    assert result["candidates"][0]["squash_attribution_only"] is True


def test_incomplete_observation_fails_open_to_every_ancestor() -> None:
    observed = "a" * 40
    unknown = "b" * 40

    result = reduce_origin_candidates(
        [observed, unknown],
        [_row(observed)],
        [],
        observation_complete=False,
    )

    rows = {str(row["sha"]): row for row in result["candidates"]}
    assert set(rows) == {observed, unknown}
    assert rows[observed]["signals"] == ["ai_ancestry_fallback"]
    assert rows[unknown]["signals"] == ["attribution_unknown_fail_open"]
    assert result["fail_open_candidate_count"] == 1
    assert result["status"] == "BLOCKED"


def test_structural_signals_rank_without_deleting_ai_fallback() -> None:
    signaled = "a" * 40
    fallback = "b" * 40

    result = reduce_origin_candidates(
        [signaled, fallback],
        [_row(signaled), _row(fallback)],
        [_row(signaled, signals=["szz_copy_aware"])],
        observation_complete=True,
    )

    rows = result["candidates"]
    assert [row["sha"] for row in rows] == [signaled, fallback]
    assert rows[0]["priority_class"] == "P0_OBSERVED_AI_CAUSAL_SIGNAL"
    assert rows[1]["priority_class"] == "P4_OBSERVED_AI_ANCESTRY_FALLBACK"
    assert all(row["retained"] is True for row in rows)


def test_structural_signal_outside_ancestry_fails_closed() -> None:
    with pytest.raises(OriginReductionContractError, match="escaped pre-fix ancestry"):
        reduce_origin_candidates(
            ["a" * 40],
            [],
            [_row("b" * 40, signals=["affected_file_history"])],
            observation_complete=True,
        )
