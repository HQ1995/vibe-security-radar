"""Tests for the Coolify onboarding URL IDOR path-extension witness."""

from __future__ import annotations

import cohort_coolify_onboarding_url_idor_path_extension_witness as witness


def _source(*, url_state: bool, mount_scoped: bool) -> str:
    annotation = "#[\\Livewire\\Attributes\\Url(keep: true)]\n    " if url_state else ""
    server_mount = (
        "Server::ownedByCurrentTeam()->find($this->selectedExistingServer)"
        if mount_scoped
        else "Server::find($this->selectedExistingServer)"
    )
    project_mount = (
        "Project::ownedByCurrentTeam()->find($this->selectedProject)"
        if mount_scoped
        else "Project::find($this->selectedProject)"
    )
    mount_body = (
        f"$this->createdServer = {server_mount};\n"
        f"        $this->createdProject = {project_mount};"
        if url_state
        else "$this->projects = collect();"
    )
    return f"""<?php
class Index
{{
    {annotation}public ?int $selectedExistingServer = null;
    {annotation}public ?int $selectedProject = null;

    public function mount()
    {{
        {mount_body}
    }}

    public function selectExistingServer()
    {{
        $this->createdServer = Server::find($this->selectedExistingServer);
    }}

    public function selectExistingProject()
    {{
        $this->createdProject = Project::find($this->selectedProject);
    }}
}}
"""


def test_baseline_has_mechanism_but_not_url_mount_path() -> None:
    result = witness._evaluate_source(_source(url_state=False, mount_scoped=False))

    assert result["underlying_unscoped_public_method_mechanism_present"] is True
    assert result["url_mount_cross_team_path_active"] is False
    assert result["url_mount_cross_team_path_blocked"] is False


def test_ai_delta_adds_url_mount_path_without_claiming_earliest_root() -> None:
    result = witness._evaluate_source(_source(url_state=True, mount_scoped=False))

    assert all(result["url_state"].values())
    assert result["url_mount_cross_team_path_active"] is True
    assert result["underlying_unscoped_public_method_mechanism_present"] is True


def test_repair_scopes_url_mount_path() -> None:
    result = witness._evaluate_source(_source(url_state=True, mount_scoped=True))

    assert result["url_mount_cross_team_path_active"] is False
    assert result["url_mount_cross_team_path_blocked"] is True


def test_repair_contract_binds_ghsa_cross_team_and_positive_controls() -> None:
    source = """
describe('Boarding Server IDOR (GHSA-qfcc-2fm3-9q42)', function () {
    // Attacker: Team A
    // Victim: Team B
    test('boarding mount cannot load server from another team via selectedExistingServer', function () {
        'selectedExistingServer' => $this->serverB->id,
        expect($component->get('createdServer'))->toBeNull();
    });
    test('boarding mount can load own team server via selectedExistingServer', function () {});
    test('boarding mount cannot load project from another team via selectedProject', function () {
        'selectedProject' => $this->projectB->id,
        expect($component->get('createdProject'))->toBeNull();
    });
    test('boarding selectExistingProject can load own team project', function () {});
});
"""

    assert all(witness._repair_test_contract(source).values())


def test_claude_signal_is_explicit() -> None:
    assert witness._explicit_claude_signal(
        "Andras Bacsai",
        "andras@example.com",
        "Generated with [Claude Code]\n"
        "Co-Authored-By: Claude <noreply@anthropic.com>",
    )
    assert not witness._explicit_claude_signal(
        "Andras Bacsai", "andras@example.com", "redesign onboarding"
    )
