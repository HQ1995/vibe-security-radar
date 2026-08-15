"""Tests for the AI single-select datalist binding-origin witness."""

from __future__ import annotations

from cohort_coolify_datalist_binding_origin_witness import (
    CANDIDATE_BINDING,
    REPAIR_BINDING,
    _evaluate_versions,
)


def test_datalist_origin_requires_new_wrong_binding_and_exact_repair() -> None:
    baseline = "Single Selection Mode (Standard HTML5 Datalist)"
    baseline_terminal = "<x-forms.select />"
    candidate = "\n".join(
        (
            "Single Selection Mode with Alpine.js",
            CANDIDATE_BINDING,
            "selectOption(value) { this.selected = value; }",
        )
    )
    candidate_terminal = "<x-forms.datalist />"
    repair = "\n".join(
        (
            "Single Selection Mode with Alpine.js",
            REPAIR_BINDING,
            "selectOption(value) { this.selected = value; }",
        )
    )

    assert all(
        _evaluate_versions(
            baseline,
            baseline_terminal,
            candidate,
            candidate_terminal,
            repair,
        ).values()
    )


def test_datalist_origin_fails_if_candidate_already_uses_model_binding() -> None:
    result = _evaluate_versions(
        "Single Selection Mode (Standard HTML5 Datalist)",
        "<x-forms.select />",
        "Single Selection Mode with Alpine.js\n"
        f"{REPAIR_BINDING}\n"
        "selectOption(value) { this.selected = value; }",
        "<x-forms.datalist />",
        "Single Selection Mode with Alpine.js\n"
        f"{REPAIR_BINDING}\n"
        "selectOption(value) { this.selected = value; }",
    )

    assert result["candidate_single_select_fallback_binds_component_id"] is False
