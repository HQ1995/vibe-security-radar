"""Tests for the Coolify PostgreSQL query IDOR path-extension witness."""

from __future__ import annotations

import cohort_coolify_postgresql_query_idor_path_extension_witness as witness


def _source(*, query_branch: bool, scoped: bool) -> str:
    project_lookup = (
        "Project::ownedByCurrentTeam()->whereUuid($projectUuid)->firstOrFail()"
        if scoped
        else "Project::whereUuid($projectUuid)->firstOrFail()"
    )
    server_lookup = (
        "Server::ownedByCurrentTeam()->find($queryServerId)"
        if scoped
        else "Server::find($queryServerId)"
    )
    query_state = (
        """
        'type' => ['except' => ''],
        'destination_uuid' => ['except' => '', 'as' => 'destination'],
"""
        if query_branch
        else ""
    )
    branch = (
        f"""
        $queryType = request()->query('type');
        $queryServerId = request()->query('server_id');
        $queryDestination = request()->query('destination');
        if ($queryType === 'postgresql' && $queryServerId !== null && $queryDestination) {{
            $this->type = $queryType;
            $this->server_id = $queryServerId;
            $this->destination_uuid = $queryDestination;
            $this->server = {server_lookup};
            $this->current_step = 'select-postgresql-type';
        }}
"""
        if query_branch
        else ""
    )
    return f"""<?php
class Select
{{
    protected $queryString = [
        'server_id',
        {query_state}
    ];

    public function mount()
    {{
        $project = {project_lookup};
        {branch}
    }}

    public function setPostgresqlType(string $type)
    {{
        return redirect()->route('project.resource.create', [
            'destination' => $this->destination_uuid,
            'server_id' => $this->server_id,
            'database_image' => $this->postgresql_type,
        ]);
    }}
}}
"""


def test_baseline_has_redirect_but_not_query_driven_server_load() -> None:
    result = witness._evaluate_source(_source(query_branch=False, scoped=False))

    assert result["query_driven_unscoped_server_load_active"] is False
    assert result["transition_contract"][
        "preexisting_version_selection_redirect_propagates_ids"
    ]


def test_ai_delta_adds_query_driven_unscoped_server_load() -> None:
    result = witness._evaluate_source(_source(query_branch=True, scoped=False))

    assert all(result["query_contract"].values())
    assert result["lookup_contract"]["unscoped_server_find"] is True
    assert result["query_driven_unscoped_server_load_active"] is True
    assert result["query_driven_server_load_team_scoped"] is False


def test_repair_scopes_the_query_driven_server_load() -> None:
    result = witness._evaluate_source(_source(query_branch=True, scoped=True))

    assert result["query_driven_unscoped_server_load_active"] is False
    assert result["query_driven_server_load_team_scoped"] is True
    assert result["lookup_contract"]["team_scoped_project_lookup"] is True


def test_repair_contract_binds_ghsa_cross_team_server_threat_model() -> None:
    source = """
describe('GlobalSearch Server IDOR (GHSA-qfcc-2fm3-9q42)', function () {
    // Attacker: Team A
    // Victim: Team B
    test('loadDestinations cannot access server from another team', function () {
        $component->set('selectedServerId', $this->serverB->id);
    });
    test('boarding mount can load own team server via selectedExistingServer', function () {});
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
        "Andras Bacsai", "andras@example.com", "fix PostgreSQL redirect"
    )
