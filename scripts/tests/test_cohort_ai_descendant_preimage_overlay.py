"""Tests for the lossless all-graph fix-preimage source-owner overlay."""

from __future__ import annotations

from pathlib import Path

import pytest

import cohort_ai_descendant_preimage_overlay as overlay
from cohort.origin_signals import OriginHunk
from cohort_ai_descendant_preimage_overlay import build_preimage_overlay
from cohort_coolify_fix_preimage_lineage import (
    BlameLine,
    FixEvidence,
    HunkContext,
)


def _ai(sha: str, subject: str) -> dict[str, object]:
    return {
        "sha": sha,
        "authored_date": "2026-01-01T00:00:00Z",
        "changed_files": ["app/Panel.php"],
        "message": subject,
    }


def test_overlay_promotes_source_owners_and_conserves_every_other_pair() -> None:
    ai_direct = "a" * 40
    ai_method = "b" * 40
    selected_fix = "c" * 40
    unprocessed_fix = "d" * 40
    hunk = OriginHunk(
        parent_path="app/Panel.php",
        path="app/Panel.php",
        old_start=5,
        old_count=1,
        new_start=5,
        new_count=2,
        added_lines=("authorize();", "dangerous($input);"),
    )
    evidence = FixEvidence(
        fix_sha=selected_fix,
        parent_sha="e" * 40,
        hunks=(
            HunkContext(
                index=0,
                hunk=hunk,
                direct_lines=(5,),
                method_signature_lines=(3,),
                nearby_lines=(4,),
            ),
        ),
        local_blame={
            "app/Panel.php": {
                3: BlameLine(ai_method, 3, "public function mutate($input)"),
                4: BlameLine("f" * 40, 4, "{"),
                5: BlameLine(ai_direct, 5, "dangerous($input);"),
            }
        },
        copy_blame={},
        coverage_gaps=(),
    )
    artifacts = build_preimage_overlay(
        census_summary={
            "repository_identity": "github.com/acme/repo",
            "direct_ancestry_pair_count": 3,
            "all_commit_route_counts": {"nonancestral_topology_fallback": 7},
        },
        ancestor_index={
            "ai_shas": [ai_direct, ai_method],
            "bitset_hex_width": 1,
        },
        commit_rows=[
            {
                "sha": selected_fix,
                "route": "direct_ai_ancestry",
                "review_lane": "explicit_security_or_regression",
                "review_score": 100,
                "review_signals": ["explicit_security_subject"],
                "strict_ai_ancestor_count": 2,
                "ai_ancestor_bitset_hex": "3",
                "subject": "fix: authorize mutation",
            },
            {
                "sha": unprocessed_fix,
                "route": "direct_ai_ancestry",
                "review_lane": "added_check_or_guard",
                "review_score": 80,
                "review_signals": ["added_guard_clause"],
                "strict_ai_ancestor_count": 1,
                "ai_ancestor_bitset_hex": "1",
                "subject": "add validation",
            },
        ],
        ai_rows=[_ai(ai_direct, "introduce sink"), _ai(ai_method, "add method")],
        ledger={"edge_ledger": []},
        evidence_by_fix={selected_fix: evidence},
        evidence_errors={},
        selected_lanes={"explicit_security_or_regression"},
        split_id="test-v1",
    )

    pairs = {
        row["candidate_sha"]: row for row in artifacts["source_owner_pairs"]
    }
    summary = artifacts["summary"]
    assert pairs[ai_direct]["priority_class"] == (
        "P0_DIRECT_RUNTIME_PREIMAGE_OWNER"
    )
    assert pairs[ai_method]["priority_class"] == (
        "P1_GUARD_ENCLOSING_METHOD_OWNER"
    )
    assert summary["strict_source_owner_pair_count"] == 2
    assert summary["processed_pairs_without_source_owner_count"] == 0
    assert summary["unprocessed_direct_ancestry_pair_count"] == 1
    assert summary["source_topology_fallback_root_count"] == 7
    assert summary["all_source_pairs_conserved"] is True
    assert summary["hard_filter_count"] == 0
    assert len(artifacts["candidate_frontier"]) == 2


def test_evidence_failure_is_fail_open_and_remains_in_conservation() -> None:
    ai_sha = "a" * 40
    fix_sha = "c" * 40
    artifacts = build_preimage_overlay(
        census_summary={
            "repository_identity": "github.com/acme/repo",
            "direct_ancestry_pair_count": 1,
            "all_commit_route_counts": {"nonancestral_topology_fallback": 0},
        },
        ancestor_index={"ai_shas": [ai_sha], "bitset_hex_width": 1},
        commit_rows=[
            {
                "sha": fix_sha,
                "route": "direct_ai_ancestry",
                "review_lane": "explicit_security_or_regression",
                "strict_ai_ancestor_count": 1,
                "ai_ancestor_bitset_hex": "1",
            }
        ],
        ai_rows=[_ai(ai_sha, "candidate")],
        ledger={"edge_ledger": []},
        evidence_by_fix={},
        evidence_errors={fix_sha: "synthetic blame failure"},
        selected_lanes={"explicit_security_or_regression"},
        split_id="test-v1",
    )

    summary = artifacts["summary"]
    assert summary["fixes_with_coverage_gaps"] == 1
    assert summary["processed_pairs_without_source_owner_count"] == 1
    assert summary["all_source_pairs_conserved"] is True
    assert artifacts["root_evidence"][0]["retained_for_retry"] is True


def test_commit_assignment_unions_nonnested_repositories(monkeypatch) -> None:
    project = Path("/tmp/project-clone")
    home = Path("/tmp/home-clone")
    shared = "a" * 40
    project_only = "b" * 40
    home_only = "c" * 40

    def fake_git_text(
        repository: Path, arguments: list[str], *, timeout: int
    ) -> str:
        assert timeout == 7
        assert arguments[:2] == ["cat-file", "-e"]
        sha = arguments[2].split("^", 1)[0]
        available = {
            project: {shared, project_only},
            home: {shared, home_only},
        }
        if sha not in available[repository]:
            raise overlay.LineageEvidenceError("missing object")
        return ""

    monkeypatch.setattr(overlay, "_git_text", fake_git_text)
    assignments = overlay._commit_repository_assignments(
        [project, home],
        [shared, project_only, home_only],
        timeout=7,
    )

    assert assignments == {
        shared: project,
        project_only: project,
        home_only: home,
    }


def test_blame_cutoff_unions_timestamp_groups(monkeypatch) -> None:
    project = Path("/tmp/project-clone")
    home = Path("/tmp/home-clone")
    project_sha = "a" * 40
    home_sha = "b" * 40

    def fake_git_text(
        repository: Path, arguments: list[str], *, timeout: int
    ) -> str:
        assert timeout == 9
        assert arguments[0] == "show"
        sha = arguments[-1]
        timestamp = (
            "2025-10-20T12:00:00+00:00"
            if repository == project
            else "2025-10-10T12:00:00+00:00"
        )
        return f"{sha}\t{timestamp}\t{timestamp}\n"

    monkeypatch.setattr(overlay, "_git_text", fake_git_text)

    cutoff = overlay._observed_ai_blame_cutoff(
        {project_sha: project, home_sha: home}, timeout=9
    )

    assert cutoff == "2025-10-09T12:00:00+00:00"


def test_declared_repositories_must_cover_census_clone_union() -> None:
    project = Path("/tmp/project-clone").resolve()
    home = Path("/tmp/home-clone").resolve()
    summary = {
        "repository_clone_coverage": [
            {"repository_path": str(project)},
            {"repository_path": str(home)},
        ]
    }

    overlay._validate_declared_repositories(summary, [project, home])
    with pytest.raises(overlay.PreimageOverlayError, match="missing="):
        overlay._validate_declared_repositories(summary, [project])
