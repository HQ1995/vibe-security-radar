"""Tests for evidence-backed Coolify non-causal candidate adjudications."""

from __future__ import annotations

import cohort_coolify_noncausal_ai_candidate_witness as witness


def test_added_lines_excludes_patch_headers() -> None:
    assert witness._added_lines("+++ b/file\n+new line\n context\n-old") == [
        "new line"
    ]


def test_unchanged_context_is_not_mistaken_for_causal_delta() -> None:
    lookup = (
        "$project = Project::where('uuid', "
        "$this->parameters['project_uuid'])->first();"
    )
    scoped = (
        "$project = Project::ownedByCurrentTeam()->where('uuid', "
        "$this->parameters['project_uuid'])->first();"
    )
    result = witness._evaluate_unchanged_context(
        lookup,
        f"validateDockerComposeForInjection($this->dockerComposeRaw);\n{lookup}",
        scoped,
        "+validateDockerComposeForInjection($this->dockerComposeRaw);\n context",
    )

    assert result["baseline_unscoped_lookup_present"] is True
    assert result["candidate_unscoped_lookup_present"] is True
    assert result["repair_scoped_lookup_present"] is True
    assert result["candidate_adds_pre_save_command_injection_validation"] is True
    assert result["candidate_adds_or_changes_project_lookup"] is False


def _global_search_source(*, scoped: bool) -> str:
    server = (
        "Server::ownedByCurrentTeam()->find($this->selectedServerId)"
        if scoped
        else "Server::find($this->selectedServerId)"
    )
    project = (
        "Project::ownedByCurrentTeam()->where('uuid', "
        "$this->selectedProjectUuid)->first()"
        if scoped
        else "Project::where('uuid', $this->selectedProjectUuid)->first()"
    )
    return f"""<?php
private function navigateToResourceCreation($type) {{ return $type; }}
public function loadDestinations() {{ $server = {server}; }}
public function loadEnvironments() {{ $project = {project}; }}
"""


def test_equivalent_ui_alias_does_not_change_security_methods() -> None:
    baseline = _global_search_source(scoped=False)
    candidate = _global_search_source(scoped=False)
    repair = _global_search_source(scoped=True)
    baseline_view = """
'new docker image', 'new image'
const itemSearchText = `new ${item.name}`.toLowerCase();
return itemSearchText === trimmed;
"""
    candidate_view = baseline_view + (
        "item.quickcommand && item.quickcommand.toLowerCase().includes(trimmed)"
    )
    result = witness._evaluate_ui_alias(
        baseline,
        candidate,
        repair,
        baseline_view,
        candidate_view,
        "+$this->searchQuery = '';",
    )

    assert result["preexisting_equivalent_docker_image_command"] is True
    assert result["preexisting_name_based_command_resolution"] is True
    assert result["candidate_adds_new_image_quickcommand_resolution"] is True
    assert result["destinations_method_unchanged"] is True
    assert result["environments_method_unchanged"] is True
    assert result["candidate_adds_server_or_project_lookup"] is False
    assert result["repair_scopes_server_lookup"] is True
    assert result["repair_scopes_project_lookup"] is True
