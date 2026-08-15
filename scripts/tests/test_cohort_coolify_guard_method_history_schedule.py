"""Tests for the Coolify guard method-history review scheduler."""

from __future__ import annotations

from cohort_coolify_guard_method_history_schedule import (
    _method_at_line,
    _method_delta,
    _novel_sink_lines,
    _priority,
    _removed_control_lines,
    _revision_parents,
)


def test_method_at_line_uses_next_method_as_boundary() -> None:
    source = """<?php
class Demo {
    public function first()
    {
        return true;
    }

    private static function second()
    {
        return false;
    }
}
"""

    assert _method_at_line(source, 5) == "first"
    assert _method_at_line(source, 10) == "second"
    assert _method_at_line(source, 1) is None


def test_method_delta_distinguishes_new_file_method_and_new_sink() -> None:
    candidate = """
public function saveValue()
{
    $this->settings->value = $this->value;
    $this->settings->save();
}
"""
    delta = _method_delta(
        parent_sources=[None], candidate_source=candidate, method="saveValue"
    )

    assert delta is not None
    assert delta["delta_kind"] == "ADD_METHOD_WITH_FILE"
    assert delta["candidate_added_sink_line_count"] == 2
    assert delta["candidate_novel_sink_line_count"] == 2
    assert delta["candidate_removed_line_count"] == 0


def test_rewritten_call_is_not_treated_as_a_novel_sink() -> None:
    added = [
        'instant_remote_process(["docker network rm {$safe}"], $server);'
    ]
    removed = [
        'instant_remote_process(["docker network rm $network"], $server);'
    ]

    assert _novel_sink_lines(added, removed) == []


def test_import_alias_rewrite_is_not_treated_as_a_novel_static_sink() -> None:
    added = ["ValidateServer::dispatch($server);"]
    removed = [r"\App\Actions\Server\ValidateServer::dispatch($server);"]

    assert _novel_sink_lines(added, removed) == []


def test_new_model_field_assignment_is_a_novel_sink() -> None:
    added = [
        "$this->settings->is_wire_navigate_enabled = "
        "$this->is_wire_navigate_enabled;"
    ]

    assert _novel_sink_lines(added, []) == added


def test_removed_early_return_becomes_reachability_lane() -> None:
    removed = [
        "if (app()->isDownForMaintenance()) {",
        "Storage::disk('webhooks-during-maintenance')->put('install', $json);",
        "return;",
        "}",
    ]

    lines, reachability_gate = _removed_control_lines(removed)

    assert reachability_gate is True
    assert "if (app()->isDownForMaintenance()) {" in lines
    assert "return;" in lines


def test_method_delta_retains_deletion_only_control_change() -> None:
    parent = """
public function install()
{
    if (app()->isDownForMaintenance()) {
        return;
    }
    $this->settings->save();
}
"""
    candidate = """
public function install()
{
    $this->settings->save();
}
"""

    delta = _method_delta(
        parent_sources=[parent], candidate_source=candidate, method="install"
    )

    assert delta is not None
    assert delta["candidate_added_line_count"] == 0
    assert delta["candidate_removed_line_count"] == 3
    assert delta["candidate_removed_control_line_count"] == 2
    assert delta["candidate_removed_reachability_gate"] is True


def test_unchanged_method_is_not_scheduled() -> None:
    source = "public function submit() { $this->settings->save(); }"

    assert (
        _method_delta(
            parent_sources=[source], candidate_source=source, method="submit"
        )
        is None
    )


def test_method_delta_does_not_absorb_following_static_method_change() -> None:
    parent = """
public function first()
{
    return true;
}

public static function second()
{
    return false;
}
"""
    candidate = parent.replace("return false;", "return true;")

    assert (
        _method_delta(
            parent_sources=[parent], candidate_source=candidate, method="first"
        )
        is None
    )


def test_method_delta_ignores_merge_carrier_from_any_parent() -> None:
    original = "public function submit() { $this->settings->save(); }"
    other_parent = "public function submit() { return; }"

    assert (
        _method_delta(
            parent_sources=[other_parent, original],
            candidate_source=original,
            method="submit",
        )
        is None
    )


def test_revision_parents_come_from_git_object_line() -> None:
    commit = "a" * 40
    first_parent = "b" * 40
    second_parent = "c" * 40

    assert _revision_parents(
        f"{commit} {first_parent} {second_parent}\n", commit
    ) == [first_parent, second_parent]


def test_new_sink_delta_ranks_before_other_method_edits() -> None:
    sink = _priority(
        delta_kind="MODIFY_EXISTING_METHOD",
        sink_count=1,
        removed_control_count=0,
        carrier_risk=False,
        confirmed_anywhere=False,
    )
    other = _priority(
        delta_kind="MODIFY_EXISTING_METHOD",
        sink_count=0,
        removed_control_count=0,
        carrier_risk=False,
        confirmed_anywhere=False,
    )

    assert sink[0] < other[0]


def test_removed_control_is_not_demoted_when_candidate_is_already_known() -> None:
    priority = _priority(
        delta_kind="MODIFY_EXISTING_METHOD",
        sink_count=0,
        removed_control_count=2,
        carrier_risk=False,
        confirmed_anywhere=True,
    )

    assert priority == (0, "P0_REMOVED_CONTROL_OR_REACHABILITY_GATE")
