"""Tests for lossless ranking of Git-incomparable observed-AI pairs."""

from __future__ import annotations

from cohort.root_adjudication import canonical_sha256
from cohort_ai_topology_residual_overlap import build_overlap_overlay


def _sha(character: str) -> str:
    return character * 40


def test_overlap_overlay_ranks_but_never_drops_no_overlap_pairs() -> None:
    ai_one = _sha("a")
    ai_two = _sha("b")
    fix = _sha("1")
    ai_shas = [ai_one, ai_two]
    commit_rows = [
        {
            "repository_identity": "github.com/acme/repo",
            "sha": fix,
            "graph_order": 1,
            "route": "nonancestral_topology_fallback",
            "topology_kind": "single_parent_or_root",
            "authored_at": "2026-02-01T00:00:00+00:00",
            "subject": "repair panel",
            "changed_paths": ["app/Panel.php"],
        }
    ]
    partition_rows = [
        {
            "sha": fix,
            "incomparable_residual_count": 2,
            "incomparable_residual_bitset_hex": "3",
        }
    ]
    ai_rows = [
        {
            "sha": ai_one,
            "authored_date": "2026-01-01T00:00:00+00:00",
            "message": "change panel",
            "changed_files": ["app/Panel.php"],
        },
        {
            "sha": ai_two,
            "authored_date": "2026-01-02T00:00:00+00:00",
            "message": "change worker",
            "changed_files": ["app/Worker.php"],
        },
    ]
    census_summary = {"all_commit_rows_sha256": canonical_sha256(commit_rows)}

    artifacts = build_overlap_overlay(
        closure_summary={
            "repository_identity": "github.com/acme/repo",
            "pair_partition_conserved": True,
            "model_labels_used_for_membership": 0,
            "hard_heuristic_filter_count": 0,
            "incomparable_residual_pair_count": 2,
        },
        closure_index={"ai_shas": ai_shas, "bitset_hex_width": 1},
        partition_rows=partition_rows,
        census_summary=census_summary,
        commit_rows=commit_rows,
        ai_scan_summary={"ai_commit_count": 2},
        ai_rows=ai_rows,
        split_id="test-v1",
    )
    pairs = {row["candidate_sha"]: row for row in artifacts["pairs"]}
    summary = artifacts["summary"]

    assert summary["retained_residual_pair_count"] == 2
    assert summary["all_residual_pairs_conserved"] is True
    assert pairs[ai_one]["priority_class"] == "T1_EXACT_RUNTIME_PATH_OVERLAP"
    assert pairs[ai_two]["priority_class"] == "T4_TOPOLOGY_ONLY_RETAINED"
    assert pairs[ai_two]["retained"] is True
