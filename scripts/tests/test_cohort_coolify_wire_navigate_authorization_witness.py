"""Tests for the Coolify AI wire-navigate authorization path witness."""

from __future__ import annotations

from cohort_coolify_wire_navigate_authorization_witness import _evaluate_versions


def test_wire_navigate_path_requires_new_sink_and_later_authorization() -> None:
    baseline_component = """
public function mount() {}
public function instantSave() { $this->settings->save(); }
"""
    baseline_model = "protected function casts(): array { return []; }"
    baseline_view = "<div></div>"
    candidate_component = """
public bool $is_wire_navigate_enabled;
protected function rules() { return ['is_wire_navigate_enabled' => 'boolean']; }
public function mount() {
    if (! isInstanceAdmin()) { return redirect()->route('dashboard'); }
    $this->is_wire_navigate_enabled = $this->settings->is_wire_navigate_enabled ?? true;
}
public function instantSave() {
    $this->settings->is_wire_navigate_enabled = $this->is_wire_navigate_enabled;
    $this->settings->save();
}
"""
    candidate_model = "'is_wire_navigate_enabled' => 'boolean'"
    candidate_view = (
        '<x-forms.checkbox instantSave id="is_wire_navigate_enabled" />'
    )
    candidate_migration = (
        "$table->boolean('is_wire_navigate_enabled')->default(true);"
    )
    repair_component = """
public function instantSave() {
    $this->authorize('update', $this->settings);
    $this->settings->is_wire_navigate_enabled = $this->is_wire_navigate_enabled;
    $this->settings->save();
}
"""

    assert all(
        _evaluate_versions(
            baseline_component,
            baseline_model,
            baseline_view,
            candidate_component,
            candidate_model,
            candidate_view,
            candidate_migration,
            repair_component,
        ).values()
    )


def test_existing_method_without_new_state_is_not_a_path_extension() -> None:
    evaluation = _evaluate_versions(
        "public function instantSave() { $this->settings->save(); }",
        "",
        "",
        """
public bool $is_wire_navigate_enabled;
protected function rules() { return ['is_wire_navigate_enabled' => 'boolean']; }
public function mount() {
    if (! isInstanceAdmin()) { return redirect()->route('dashboard'); }
    $this->is_wire_navigate_enabled = $this->settings->is_wire_navigate_enabled ?? true;
}
public function instantSave() {
    $this->settings->save();
}
""",
        "'is_wire_navigate_enabled' => 'boolean'",
        '<x-forms.checkbox instantSave id="is_wire_navigate_enabled" />',
        "$table->boolean('is_wire_navigate_enabled')->default(true);",
        """
public function instantSave() {
    $this->authorize('update', $this->settings);
    $this->settings->is_wire_navigate_enabled = $this->is_wire_navigate_enabled;
    $this->settings->save();
}
""",
    )

    assert evaluation["candidate_persists_new_state_in_public_action"] is False
