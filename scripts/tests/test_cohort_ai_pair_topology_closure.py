"""Tests for the lossless observed-AI full topology pair closure."""

from __future__ import annotations

from cohort.root_adjudication import canonical_sha256
from cohort_ai_pair_topology_closure import build_topology_closure


def _sha(character: str) -> str:
    return character * 40


def test_full_cartesian_partition_keeps_every_incomparable_pair() -> None:
    base = _sha("1")
    ai_one = _sha("2")
    direct_fix = _sha("3")
    other = _sha("4")
    ai_two = _sha("5")
    squash = _sha("6")
    ai_shas = sorted([ai_one, ai_two])
    ai_positions = {sha: index for index, sha in enumerate(ai_shas)}
    width = 1
    rows = [
        {
            "repository_identity": "github.com/acme/repo",
            "sha": base,
            "parents": [],
            "graph_order": 1,
            "subject": "base",
            "topology_kind": "single_parent_or_root",
            "route": "nonancestral_topology_fallback",
            "strict_ai_ancestor_count": 0,
        },
        {
            "repository_identity": "github.com/acme/repo",
            "sha": ai_one,
            "parents": [base],
            "graph_order": 2,
            "subject": "AI one",
            "topology_kind": "single_parent_or_root",
            "route": "nonancestral_topology_fallback",
            "strict_ai_ancestor_count": 0,
        },
        {
            "repository_identity": "github.com/acme/repo",
            "sha": direct_fix,
            "parents": [ai_one],
            "graph_order": 3,
            "subject": "fix direct",
            "topology_kind": "single_parent_or_root",
            "route": "direct_ai_ancestry",
            "strict_ai_ancestor_count": 1,
            "ai_ancestor_bitset_hex": format(1 << ai_positions[ai_one], "01x"),
        },
        {
            "repository_identity": "github.com/acme/repo",
            "sha": other,
            "parents": [base],
            "graph_order": 4,
            "subject": "other branch",
            "topology_kind": "single_parent_or_root",
            "route": "nonancestral_topology_fallback",
            "strict_ai_ancestor_count": 0,
        },
        {
            "repository_identity": "github.com/acme/repo",
            "sha": ai_two,
            "parents": [other],
            "graph_order": 5,
            "subject": "AI two",
            "topology_kind": "single_parent_or_root",
            "route": "nonancestral_topology_fallback",
            "strict_ai_ancestor_count": 0,
        },
        {
            "repository_identity": "github.com/acme/repo",
            "sha": squash,
            "parents": [other],
            "graph_order": 6,
            "subject": "landed squash",
            "topology_kind": "single_parent_or_root",
            "route": "nonancestral_topology_fallback",
            "strict_ai_ancestor_count": 0,
        },
    ]
    index = {
        "ai_shas": ai_shas,
        "bitset_hex_width": width,
    }
    summary = {
        "repository_identity": "github.com/acme/repo",
        "all_ref_commit_count": len(rows),
        "direct_ancestry_pair_count": 1,
        "all_commit_rows_sha256": canonical_sha256(rows),
        "ancestor_index_sha256": canonical_sha256(index),
    }

    artifacts = build_topology_closure(
        census_summary=summary,
        ancestor_index=index,
        commit_rows=rows,
        split_id="test-v1",
    )
    result = artifacts["summary"]
    by_sha = {row["sha"]: row for row in artifacts["partition_rows"]}

    assert result["full_cartesian_pair_count"] == 12
    assert result["strict_ai_ancestor_pair_count"] == 1
    assert result["fix_strictly_precedes_ai_pair_count"] == 3
    assert result["identity_pair_count"] == 2
    assert result["incomparable_residual_pair_count"] == 6
    assert result["pair_partition_conserved"] is True
    assert by_sha[squash]["incomparable_residual_count"] == 2
    assert int(by_sha[squash]["incomparable_residual_bitset_hex"], 16) == 3
    assert by_sha[direct_fix]["strict_ai_ancestor_count"] == 1
    assert by_sha[direct_fix]["incomparable_residual_count"] == 1
