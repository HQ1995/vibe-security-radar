"""Tests for the lossless Coolify guard-history route inventory."""

from __future__ import annotations

from pathlib import Path

import cohort_coolify_guard_history_route_inventory as inventory


CANDIDATE = "a" * 40
FIX = "b" * 40


def _payload(kind: str, rows: list[dict[str, object]]) -> dict[str, object]:
    return {
        "artifact_kind": kind,
        "repository_identity": "github.com/coollabsio/coolify",
        "rows": rows,
    }


def _row(*, path: str, confirmed: bool, priority: int) -> dict[str, object]:
    return {
        "candidate_sha": CANDIDATE,
        "candidate_subject": "AI candidate",
        "candidate_authored_date": "2026-01-01T00:00:00+00:00",
        "candidate_merge_topology": "direct",
        "candidate_confirmed_anywhere": confirmed,
        "input_edge_status": (
            "CONFIRMED_TRUE_POSITIVE" if confirmed else "DEFERRED_REVIEW_BACKLOG"
        ),
        "candidate_exposure_line_count": 1,
        "fix_sha": FIX,
        "fix_subject": "security repair",
        "path": path,
        "priority_tier": priority,
        "priority_class": f"P{priority}_TEST",
        "retained_for_review": True,
    }


def test_duplicate_lane_rows_fold_without_losing_source_membership() -> None:
    method = _payload(
        "coolify_guard_method_history_review_schedule",
        [_row(path="app/Livewire/Panel.php", confirmed=False, priority=3)],
    )
    surface = _payload(
        "coolify_guard_surface_history_review_schedule",
        [_row(path="routes/web.php", confirmed=False, priority=1)],
    )

    candidates, fixes, metadata = inventory._build_inventory(
        [("method.json", method), ("surface.json", surface)],
        repository=Path("/repo"),
    )

    assert len(candidates) == 1
    assert len(fixes) == 1
    assert candidates[0]["priority_rank"] == 2
    assert candidates[0]["fix_file_overlap"] == [
        "app/Livewire/Panel.php",
        "routes/web.php",
    ]
    assert candidates[0]["guard_history_lanes"] == [
        "guard_method_history",
        "guard_surface_history",
    ]
    assert candidates[0]["guard_history_source_row_count"] == 2
    assert metadata["conservation"]["duplicate_lane_or_hunk_row_count"] == 1
    assert metadata["conservation"]["passed"] is True


def test_known_candidate_edges_are_retained_without_prompt_label_leakage() -> None:
    surface = _payload(
        "coolify_guard_surface_history_review_schedule",
        [_row(path="routes/api.php", confirmed=True, priority=5)],
    )

    candidates, _, metadata = inventory._build_inventory(
        [("surface.json", surface)],
        repository=Path("/repo"),
    )

    assert candidates[0]["retained"] is True
    assert candidates[0]["candidate_confirmed_anywhere"] is True
    assert candidates[0]["input_edge_status"] == "CONFIRMED_TRUE_POSITIVE"
    assert "known_candidate_positive_control" not in candidates[0]["signals"]
    conservation = metadata["conservation"]
    assert conservation["known_candidate_coverage_pair_count"] == 1
    assert conservation["candidate_not_yet_confirmed_pair_count"] == 0
    assert conservation["exact_input_edge_status_counts"] == {
        "CONFIRMED_TRUE_POSITIVE": 1
    }
    assert conservation["hard_delete_count"] == 0


def test_label_neutral_inventory_removes_all_adjudication_derived_features() -> None:
    surface = _payload(
        "coolify_guard_surface_history_review_schedule",
        [_row(path="routes/api.php", confirmed=True, priority=5)],
    )

    candidates, _, metadata = inventory._build_inventory(
        [("surface.json", surface)],
        repository=Path("/repo"),
        label_neutral=True,
    )

    candidate = candidates[0]
    assert candidate["retained"] is True
    assert candidate["priority_rank"] == 1
    assert "priority_class" not in candidate
    assert "candidate_confirmed_anywhere" not in candidate
    assert "input_edge_status" not in candidate
    assert candidate["signals"] == [
        "candidate_exposure_delta",
        "guard_surface_history",
    ]
    assert metadata["conservation"]["known_candidate_coverage_pair_count"] == 1
