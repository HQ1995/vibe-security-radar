"""Tests for the Coolify non-method guard-surface scheduler."""

from __future__ import annotations

from cohort_coolify_guard_surface_history_schedule import _file_delta, _priority


def test_file_delta_detects_public_surface_added_to_existing_file() -> None:
    parent = "<?php class Demo {}"
    candidate = "<?php class Demo { public string $token = ''; }"

    delta = _file_delta(
        parent_sources=[parent], candidate_source=candidate
    )

    assert delta is not None
    assert delta["delta_kind"] == "MODIFY_EXISTING_RUNTIME_FILE"
    assert delta["candidate_exposure_line_count"] == 1


def test_file_delta_ignores_merge_carrier_equal_to_any_parent() -> None:
    candidate = "<?php class Demo { public string $token = ''; }"

    assert (
        _file_delta(
            parent_sources=["<?php class Demo {}", candidate],
            candidate_source=candidate,
        )
        is None
    )


def test_explicit_locked_repair_and_public_delta_get_top_priority() -> None:
    priority = _priority(
        delta_kind="MODIFY_EXISTING_RUNTIME_FILE",
        repair_lines=["#[Locked]"],
        exposure_count=1,
        carrier_risk=False,
        confirmed_anywhere=False,
    )

    assert priority == (
        0,
        "P0_EXPOSURE_DELTA_BEFORE_EXPLICIT_SURFACE_CONTROL",
    )


def test_explicit_surface_control_stays_high_without_candidate_exposure_regex() -> None:
    priority = _priority(
        delta_kind="MODIFY_EXISTING_RUNTIME_FILE",
        repair_lines=["use AuthorizesRequests;"],
        exposure_count=0,
        carrier_risk=False,
        confirmed_anywhere=False,
    )

    assert priority[0] == 1


def test_confirmed_candidate_is_coverage_only() -> None:
    priority = _priority(
        delta_kind="ADD_RUNTIME_FILE",
        repair_lines=["#[Locked]"],
        exposure_count=2,
        carrier_risk=False,
        confirmed_anywhere=True,
    )

    assert priority == (5, "P5_ALREADY_CONFIRMED_CANDIDATE_COVERAGE")
