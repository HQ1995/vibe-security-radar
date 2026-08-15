"""Tests for the Coolify AI project-scope hardening witness."""

from __future__ import annotations

from pathlib import Path

from cohort_coolify_project_scope_hardening_witness import (
    RESOURCE_PATHS,
    _evaluate_destination_scope,
    _evaluate_onboarding,
)


def test_onboarding_null_transition_requires_direct_regression_and_repair() -> None:
    baseline = """
public function selectExistingProject() {
    $this->createdProject = Project::find($this->selectedProject);
    $this->currentState = 'create-resource';
}
public function showNewResource() {}
"""
    candidate = """
public function selectExistingProject() {
    $this->createdProject = Project::ownedByCurrentTeam()->find($this->selectedProject);
    $this->currentState = 'create-resource';
}
public function showNewResource() {
    use($this->createdProject->uuid);
    use($this->createdProject->environments->first()->uuid);
}
"""
    repair = """
public function selectExistingProject() {
    $this->createdProject = Project::ownedByCurrentTeam()->find($this->selectedProject);
    if (! $this->createdProject) {
        return $this->dispatch('error', 'Project not found.');
    }
    $this->currentState = 'create-resource';
}
public function showNewResource() {}
"""
    candidate_test = """
test('boarding selectExistingProject cannot load project from another team', function () {
    expect($component->get('createdProject'))->toBeNull();
});
test('boarding selectExistingProject can load own team project', function () {});
"""
    repair_test = """
test('boarding selectExistingProject cannot load project from another team', function () {
    expect($component->get('createdProject'))->toBeNull();
    $component->assertDispatched('error');
});
test('boarding selectExistingProject can load own team project', function () {});
"""

    assert all(
        _evaluate_onboarding(
            baseline, candidate, repair, candidate_test, repair_test
        ).values()
    )


def test_onboarding_candidate_with_null_guard_is_not_the_regression() -> None:
    baseline = """
public function selectExistingProject() {
    $this->createdProject = Project::find($this->selectedProject);
}
public function showNewResource() {}
"""
    candidate = """
public function selectExistingProject() {
    $this->createdProject = Project::ownedByCurrentTeam()->find($this->selectedProject);
    if (! $this->createdProject) { return; }
    $this->currentState = 'create-resource';
}
public function showNewResource() {
    use($this->createdProject->uuid);
    use($this->createdProject->environments->first()->uuid);
}
"""
    repair = """
public function selectExistingProject() {
    $this->createdProject = Project::ownedByCurrentTeam()->find($this->selectedProject);
    if (! $this->createdProject) {
        return $this->dispatch('error', 'Project not found.');
    }
    $this->currentState = 'create-resource';
}
public function showNewResource() {}
"""
    candidate_test = """
test('boarding selectExistingProject cannot load project from another team', function () {
    expect($component->get('createdProject'))->toBeNull();
});
test('boarding selectExistingProject can load own team project', function () {});
"""
    repair_test = candidate_test.replace(
        "expect($component->get('createdProject'))->toBeNull();",
        "expect($component->get('createdProject'))->toBeNull();\n"
        "    $component->assertDispatched('error');",
    )

    evaluation = _evaluate_onboarding(
        baseline, candidate, repair, candidate_test, repair_test
    )

    assert evaluation["candidate_has_no_null_guard_before_state_transition"] is False


def _resource_sources() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    baseline_method = """
public function submit() {
    $project = Project::where('uuid', $project_uuid)->first();
    $destination = StandaloneDocker::where('uuid', $destination_uuid)->first();
    if (! $destination) {
        $destination = SwarmDocker::where('uuid', $destination_uuid)->first();
    }
    Application::create(['destination_id' => $destination->id]);
}
"""
    candidate_method = baseline_method.replace(
        "Project::where('uuid', $project_uuid)->first();",
        "Project::ownedByCurrentTeam()->where('uuid', $project_uuid)->first();",
    )
    repair_method = """
public function submit() {
    $project = Project::ownedByCurrentTeam()->where('uuid', $project_uuid)->firstOrFail();
    $environment = $project->environments()->where('uuid', $environment_uuid)->firstOrFail();
    $destination = find_destination_for_current_team($destination_uuid);
    Application::create(['destination_id' => $destination->id]);
}
"""
    return (
        {path: baseline_method for path in RESOURCE_PATHS},
        {path: candidate_method for path in RESOURCE_PATHS},
        {path: repair_method for path in RESOURCE_PATHS},
    )


def _destination_test() -> str:
    return "\n".join(
        (
            "describe('SimpleDockerfile destination team scope'",
            "describe('DockerImage destination team scope'",
            "describe('DockerCompose destination + server_id team scope'",
            "describe('PublicGitRepository destination team scope'",
            "describe('GithubPrivateRepository destination team scope'",
            "describe('GithubPrivateRepositoryDeployKey destination team scope'",
            "find_destination_for_current_team($this->destinationB->uuid)",
            "Destination not found.",
        )
    )


def _resource_proof_test() -> str:
    return """
test('unscoped StandaloneDocker lookup returns another teams destination', function () {
    $dest = StandaloneDocker::where('uuid', $this->destinationB->uuid)->first();
});
test('Team A can create Application in Team B environment via unscoped lookups', function () {
    Application::create(['destination_id' => $destination->id]);
});
"""


def test_destination_scope_requires_six_incomplete_flows_and_repair_tests() -> None:
    baseline, candidate, repair = _resource_sources()

    evaluation = _evaluate_destination_scope(
        baseline,
        candidate,
        repair,
        _destination_test(),
        _resource_proof_test(),
    )

    assert all(evaluation.values())


def test_already_scoped_candidate_destination_is_not_incomplete_hardening() -> None:
    baseline, candidate, repair = _resource_sources()
    first_path = RESOURCE_PATHS[0]
    candidate[first_path] = candidate[first_path].replace(
        "StandaloneDocker::where('uuid', $destination_uuid)->first();",
        "find_destination_for_current_team($destination_uuid);",
    )

    evaluation = _evaluate_destination_scope(
        baseline,
        candidate,
        repair,
        _destination_test(),
        _resource_proof_test(),
    )

    key = f"{Path(first_path).stem}_candidate_retains_unscoped_destination_lookup"
    assert evaluation[key] is False
