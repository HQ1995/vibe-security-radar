"""Tests for exact-delta rescue over every topology-residual pair."""

from __future__ import annotations

from cohort_ai_topology_residual_exact_delta import build_delta_overlay
from cohort_coolify_preimage_exact_delta_bridge import CommitDelta, DeltaLine


def _sha(character: str) -> str:
    return character * 40


def _delta(
    sha: str,
    *,
    additions: tuple[DeltaLine, ...] = (),
    removals: tuple[DeltaLine, ...] = (),
) -> CommitDelta:
    parent = "f" * 40
    return CommitDelta(
        sha=sha,
        parents=(parent,),
        compared_parents=(parent,),
        additions=additions,
        removals=removals,
    )


def test_reverse_delta_promotes_and_no_match_pair_remains_retained() -> None:
    candidate = _sha("a")
    exact_fix = _sha("1")
    residual_fix = _sha("2")
    parent = "f" * 40
    line = DeltaLine(parent, "app/Panel.php", "dangerous($input);")
    pairs = [
        {
            "candidate_sha": candidate,
            "fix_sha": exact_fix,
            "exact_path_overlap_count": 1,
            "review_priority_score": 100,
            "retained": True,
        },
        {
            "candidate_sha": candidate,
            "fix_sha": residual_fix,
            "exact_path_overlap_count": 0,
            "review_priority_score": 0,
            "retained": True,
        },
    ]
    artifacts = build_delta_overlay(
        overlap_summary={
            "repository_identity": "github.com/acme/repo",
            "all_residual_pairs_conserved": True,
            "hard_filter_count": 0,
            "retained_residual_pair_count": 2,
        },
        pair_rows=pairs,
        deltas={
            candidate: _delta(candidate, additions=(line,)),
            exact_fix: _delta(exact_fix, removals=(line,)),
            residual_fix: _delta(residual_fix),
        },
        split_id="test-v1",
    )
    by_fix = {row["fix_sha"]: row for row in artifacts["delta_pairs"]}
    summary = artifacts["summary"]

    assert by_fix[exact_fix]["delta_class"] == (
        "D0_CANDIDATE_ADDITION_EXACTLY_REMOVED"
    )
    assert by_fix[exact_fix]["meaningful_reversal_match_count"] == 1
    assert by_fix[residual_fix]["delta_class"] == "D5_TOPOLOGY_ONLY_RETAINED"
    assert by_fix[residual_fix]["retained"] is True
    assert summary["retained_residual_pair_count"] == 2
    assert summary["exact_or_normalized_reversal_pair_count"] == 1
    assert summary["all_residual_pairs_conserved"] is True


def test_cached_indexes_preserve_normalized_and_cross_path_rescue() -> None:
    candidate = _sha("a")
    fix = _sha("1")
    parent = "f" * 40
    candidate_lines = (
        DeltaLine(parent, "app/Panel.php", "  dangerous($input);"),
        DeltaLine(parent, "app/Old.php", "moved_guard();"),
    )
    fix_lines = (
        DeltaLine(parent, "app/Panel.php", "dangerous($input);"),
        DeltaLine(parent, "app/New.php", "moved_guard();"),
    )
    artifacts = build_delta_overlay(
        overlap_summary={
            "repository_identity": "github.com/acme/repo",
            "all_residual_pairs_conserved": True,
            "hard_filter_count": 0,
            "retained_residual_pair_count": 1,
        },
        pair_rows=[
            {
                "candidate_sha": candidate,
                "fix_sha": fix,
                "exact_path_overlap_count": 1,
                "review_priority_score": 0,
                "retained": True,
            }
        ],
        deltas={
            candidate: _delta(candidate, additions=candidate_lines),
            fix: _delta(fix, removals=fix_lines),
        },
        split_id="test-v1",
    )
    row = artifacts["delta_pairs"][0]

    assert row["delta_class"] == "D1_WHITESPACE_NORMALIZED_REVERSAL"
    assert row["normalized_same_path_reversal_match_count"] == 1
    assert row["exact_cross_path_reversal_match_count"] == 1
