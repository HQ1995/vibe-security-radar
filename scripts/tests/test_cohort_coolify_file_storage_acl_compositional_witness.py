"""Tests for the Coolify mixed-origin file-storage ACL witness."""

from __future__ import annotations

import cohort_coolify_file_storage_acl_compositional_witness as witness


def _component(ability: str) -> str:
    return f"""<?php
class FileStorage
{{
    public ?string $content = null;

    public function syncData(bool $toModel = false): void
    {{
        if (!$toModel) {{
            $this->content = $this->fileStorage->content;
        }}
    }}

    public function loadStorageOnServer()
    {{
        $this->authorize('{ability}', $this->resource);
        $this->fileStorage->loadStorageOnServer();
        $this->syncData();
    }}
}}
"""


def _blade(ability: str | None) -> str:
    button = ""
    if ability is not None:
        button = f"""
        @can('{ability}', $resource)
            <button wire:click=\"loadStorageOnServer\">Load</button>
        @endcan
"""
    return f"""
<div>
    {witness.READ_ONLY_SECTION}
    {button}
</div>
"""


VOLUME = r"""<?php
class LocalFileVolume
{
    public function loadStorageOnServer()
    {
        $content = instant_remote_process(["cat {$escapedPath}"], $server, false);
        $this->content = $content;
    }
}
"""


PERMISSIVE_RESOURCE_POLICY = """<?php
class ServiceApplicationPolicy
{
    public function view(User $user, ServiceApplication $serviceApplication): bool
    {
        return Gate::allows('view', $serviceApplication->service);
    }

    public function update(User $user, ServiceApplication $serviceApplication): bool
    {
        // return Gate::allows('update', $serviceApplication->service);
        return true;
    }
}
"""


DELEGATING_RESOURCE_POLICY = PERMISSIVE_RESOURCE_POLICY.replace(
    "// return Gate::allows('update', $serviceApplication->service);\n"
    "        return true;",
    "return Gate::allows('update', $serviceApplication->service);",
)


PERMISSIVE_SERVICE_POLICY = """<?php
class ServicePolicy
{
    public function view(User $user, Service $service): bool
    {
        return true;
    }

    public function update(User $user, Service $service): bool
    {
        // return $user->isAdmin();
        return true;
    }
}
"""


SEPARATED_SERVICE_POLICY = """<?php
class ServicePolicy
{
    public function view(User $user, Service $service): bool
    {
        $teamId = $this->getTeamId($service);
        return $teamId !== null && $user->teams->contains('id', $teamId);
    }

    public function update(User $user, Service $service): bool
    {
        $teamId = $this->getTeamId($service);
        return $teamId !== null && $user->isAdminOfTeam($teamId);
    }
}
"""


AUTH_PROVIDER = """<?php
protected $policies = [
    \\App\\Models\\ServiceApplication::class => \\App\\Policies\\ServiceApplicationPolicy::class,
];
"""


def _evaluate(
    *,
    component_ability: str,
    button_ability: str | None,
    separated: bool,
) -> dict[str, object]:
    return witness._evaluate_sources(
        _component(component_ability),
        _blade(button_ability),
        VOLUME,
        DELEGATING_RESOURCE_POLICY if separated else PERMISSIVE_RESOURCE_POLICY,
        SEPARATED_SERVICE_POLICY if separated else PERMISSIVE_SERVICE_POLICY,
        AUTH_PROVIDER,
    )


def test_ai_change_is_latent_while_view_and_update_are_both_permissive() -> None:
    result = _evaluate(
        component_ability="view",
        button_ability="view",
        separated=False,
    )

    assert result["same_team_non_admin_permissions"] == {
        "view": True,
        "update": True,
    }
    assert result["same_team_non_admin_remote_content_exposure_path"] is True
    assert result["view_update_roles_are_separated"] is False
    assert result["least_privilege_violation_active"] is False


def test_human_policy_activation_makes_the_latent_view_gate_differential() -> None:
    result = _evaluate(
        component_ability="view",
        button_ability="view",
        separated=True,
    )

    assert result["same_team_non_admin_permissions"] == {
        "view": True,
        "update": False,
    }
    assert result["same_team_non_admin_method_allowed"] is True
    assert result["same_team_non_admin_button_visible"] is True
    assert result["storage_flow"]["remote_file_reaches_public_component_property"] is True
    assert result["least_privilege_violation_active"] is True


def test_repair_restores_update_gate_and_blocks_non_admin_member() -> None:
    result = _evaluate(
        component_ability="update",
        button_ability="update",
        separated=True,
    )

    assert result["same_team_non_admin_method_allowed"] is False
    assert result["same_team_non_admin_button_visible"] is False
    assert result["same_team_non_admin_remote_content_exposure_path"] is False
    assert result["least_privilege_violation_active"] is False


def test_pre_ai_read_only_branch_has_no_load_button() -> None:
    result = _evaluate(
        component_ability="update",
        button_ability=None,
        separated=False,
    )

    assert result["read_only_load_button_ability"] is None
    assert result["same_team_non_admin_button_visible"] is False
    assert result["same_team_non_admin_remote_content_exposure_path"] is False


def test_claude_signal_requires_explicit_commit_metadata() -> None:
    assert witness._explicit_claude_signal(
        "Andras Bacsai",
        "andras@example.com",
        "Generated with [Claude Code]\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
    )
    assert not witness._explicit_claude_signal(
        "Andras Bacsai",
        "andras@example.com",
        "fix(auth): enforce authorization checks",
    )


def test_cve_64420_boundary_is_frozen_to_last_officially_affected_tag() -> None:
    assert witness.CVE_64420_AFFECTED_BOUNDARY == "v4.0.0-beta.434"
    assert witness.CVE_64420_ADVISORY_URL.endswith("GHSA-qwxj-qch7-whpc")
