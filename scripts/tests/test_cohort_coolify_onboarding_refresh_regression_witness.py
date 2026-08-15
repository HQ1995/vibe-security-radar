"""Tests for the Coolify onboarding refresh regression predicates."""

from __future__ import annotations

from cohort_coolify_onboarding_refresh_regression_witness import (
    _evaluate_versions,
)


def test_url_state_requires_project_reload_on_refresh() -> None:
    baseline = """
public string $currentState = 'welcome';
public function mount() {}
"""
    candidate = r"""
#[\Livewire\Attributes\Url(as: 'step', history: true)]
public string $currentState = 'welcome';
public function mount() {
    if (! isset($this->projects)) {
        $this->projects = collect();
    }
    if ($this->selectedProject) {
        $this->projects = Project::ownedByCurrentTeam(['name'])->get();
    }
}
"""
    repair = r"""
#[\Livewire\Attributes\Url(as: 'step', history: true)]
public string $currentState = 'welcome';
public function mount() {
    if (! isset($this->projects)) {
        $this->projects = collect();
    }
    if ($this->selectedProject) {
        $this->projects = Project::ownedByCurrentTeam(['name'])->get();
    }
    if ($this->currentState === 'create-project' && $this->projects->isEmpty()) {
        $this->projects = Project::ownedByCurrentTeam(['name'])->get();
    }
}
"""

    assert all(_evaluate_versions(baseline, candidate, repair).values())
