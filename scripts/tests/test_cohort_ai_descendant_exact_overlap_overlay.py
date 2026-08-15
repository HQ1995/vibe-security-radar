"""Tests for the lossless AI-descendant exact-path overlap overlay."""

from __future__ import annotations

from cohort_ai_descendant_exact_overlap_overlay import (
    _path_class,
    _review_priority,
    build_exact_overlap_overlay,
)


def _ai(sha: str, path: str, subject: str) -> dict[str, object]:
    return {
        "sha": sha,
        "authored_date": "2026-01-01T00:00:00Z",
        "changed_files": [path],
        "message": subject,
    }


def test_path_class_keeps_runtime_views_in_production() -> None:
    assert _path_class("app/Models/App.php") == "production"
    assert _path_class("resources/views/livewire/app.blade.php") == "production"
    assert _path_class("tests/Feature/AppTest.php") == "test"
    assert _path_class("README.md") == "nonproduction"


def test_review_priority_downranks_merge_carrier_direct_parent_without_filtering() -> None:
    candidate_sha = "a" * 40
    candidate = _ai(candidate_sha, "app/a.php", "fix: validate input")
    ordinary_root = {
        "review_score": 100,
        "review_lane": "added_check_or_guard",
        "strict_ai_ancestor_count": 2,
        "changed_paths": ["app/a.php"],
        "authored_at": "2026-02-01T00:00:00Z",
        "parents": ["b" * 40],
        "topology_kind": "direct_commit",
    }
    merge_root = {
        **ordinary_root,
        "parents": [candidate_sha, "b" * 40],
        "topology_kind": "merge_carrier",
    }
    ordinary_score, _ = _review_priority(
        root=ordinary_root,
        candidate=candidate,
        production_paths=["app/a.php"],
        test_paths=[],
        nonproduction_paths=[],
        confirmed_edge=False,
        confirmed_candidate=False,
    )
    merge_score, merge_reasons = _review_priority(
        root=merge_root,
        candidate=candidate,
        production_paths=["app/a.php"],
        test_paths=[],
        nonproduction_paths=[],
        confirmed_edge=False,
        confirmed_candidate=False,
    )

    assert ordinary_score - merge_score == 960
    assert "merge_carrier_penalty:260" in merge_reasons
    assert "candidate_is_direct_parent_penalty:700" in merge_reasons


def test_overlay_materializes_overlap_and_conserves_cross_file_pairs() -> None:
    ai_a = "a" * 40
    ai_b = "b" * 40
    fix_c = "c" * 40
    fix_d = "d" * 40
    artifacts = build_exact_overlap_overlay(
        census_summary={
            "repository_identity": "github.com/acme/repo",
            "direct_ancestry_pair_count": 3,
        },
        ancestor_index={
            "ai_shas": [ai_a, ai_b],
            "bitset_hex_width": 1,
        },
        commit_rows=[
            {
                "sha": fix_c,
                "route": "direct_ai_ancestry",
                "strict_ai_ancestor_count": 2,
                "ai_ancestor_bitset_hex": "3",
                "changed_paths": ["app/a.php", "tests/A.php"],
                "authored_at": "2026-02-01T00:00:00Z",
                "subject": "add validation",
                "review_lane": "added_check_or_guard",
                "review_tier": 2,
                "review_score": 100,
                "review_signals": ["added_input_validation"],
            },
            {
                "sha": fix_d,
                "route": "direct_ai_ancestry",
                "strict_ai_ancestor_count": 1,
                "ai_ancestor_bitset_hex": "1",
                "changed_paths": ["app/unrelated.php"],
                "authored_at": "2026-03-01T00:00:00Z",
                "subject": "cross-file repair",
                "review_lane": "repair_action_subject",
                "review_tier": 3,
                "review_score": 50,
                "review_signals": [],
            },
        ],
        ai_rows=[
            _ai(ai_a, "app/a.php", "fix: secure runtime"),
            _ai(ai_b, "tests/A.php", "test behavior"),
        ],
        ledger={
            "edge_ledger": [
                {
                    "candidate_sha": ai_a,
                    "fix_sha": fix_c,
                    "status": "CONFIRMED_TRUE_POSITIVE",
                }
            ]
        },
        split_id="test-v1",
    )

    summary = artifacts["summary"]
    pairs = artifacts["pairs"]
    frontier = artifacts["candidate_frontier"]
    assert summary["source_direct_ancestry_pair_count"] == 3
    assert summary["materialized_exact_path_pair_count"] == 2
    assert summary["compressed_cross_file_pair_count"] == 1
    assert summary["pair_class_counts"] == {
        "exact_production_overlap": 1,
        "exact_test_only_overlap": 1,
    }
    assert summary["all_source_pairs_conserved"] is True
    assert summary["hard_filter_count"] == 0
    assert pairs[0]["candidate_sha"] == ai_b
    assert pairs[1]["already_confirmed_edge"] is True
    assert [row["candidate_sha"] for row in frontier] == [ai_b]


def test_overlay_rejects_ai_index_drift() -> None:
    try:
        build_exact_overlap_overlay(
            census_summary={"direct_ancestry_pair_count": 0},
            ancestor_index={"ai_shas": ["a" * 40], "bitset_hex_width": 1},
            commit_rows=[],
            ai_rows=[_ai("b" * 40, "app/a.php", "feature")],
            ledger={"edge_ledger": []},
            split_id="test-v1",
        )
    except ValueError as exc:
        assert "disagree" in str(exc)
    else:
        raise AssertionError("expected AI index drift failure")
