"""Tests for the Coolify dev-helper action authorization witness."""

from __future__ import annotations

import cohort_coolify_dev_helper_action_witness as witness


def _source(*, action: bool, authorized: bool) -> str:
    action_source = ""
    if action:
        authorization = (
            "$this->authorize('update', $this->settings);" if authorized else ""
        )
        action_source = f"""
public function buildHelperImage()
{{
    {authorization}
    if (! isDev()) {{ return; }}
    $command = "docker build -t ghcr.io/coollabsio/coolify-helper:tag -f Dockerfile .";
    remote_process(command: [$command], server: $this->server);
}}
"""
    return f"""<?php
class Index {{
public function mount()
{{
    if (! isInstanceAdmin()) {{ return redirect()->route('dashboard'); }}
}}
{action_source}
}}
"""


def test_baseline_has_mount_gate_but_no_action() -> None:
    result = witness._evaluate(_source(action=False, authorized=False), "")

    assert result["mount_has_instance_admin_redirect"] is True
    assert result["public_build_helper_action"] is False
    assert result["view_invokes_action"] is False


def test_ai_delta_adds_dev_limited_unguarded_host_action() -> None:
    view = '@if(isDev()) <button wire:click="buildHelperImage">Build</button> @endif'
    result = witness._evaluate(_source(action=True, authorized=False), view)

    assert result["public_build_helper_action"] is True
    assert result["action_is_dev_limited"] is True
    assert result["action_invokes_remote_process"] is True
    assert result["action_builds_host_helper_image"] is True
    assert result["action_has_update_authorization"] is False
    assert result["view_invokes_action"] is True
    assert result["view_action_is_dev_limited"] is True


def test_repair_adds_method_policy_authorization() -> None:
    result = witness._evaluate(_source(action=True, authorized=True), "")
    policy = witness._evaluate_policy(
        """<?php class InstanceSettingsPolicy {
        public function update(User $user, InstanceSettings $settings): bool {
            return isInstanceAdmin();
        }}"""
    )

    assert result["action_has_update_authorization"] is True
    assert policy["update_policy_present"] is True
    assert policy["update_requires_instance_admin"] is True
