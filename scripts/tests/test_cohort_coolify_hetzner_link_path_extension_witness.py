"""Tests for the Coolify Hetzner manual-link path-extension witness."""

from __future__ import annotations

import cohort_coolify_hetzner_link_path_extension_witness as witness


def _source(*, link: bool, controls_scoped: bool) -> str:
    link_method = ""
    if link:
        link_method = """
public function searchHetznerServer(): void
{
    $this->authorize('update', $this->server);
}
public function linkToHetzner()
{
    $this->authorize('update', $this->server);
    $this->server->update([
        'cloud_provider_token_id' => $this->selectedHetznerTokenId,
        'hetzner_server_id' => $this->matchedHetznerServer['id'],
    ]);
}
"""
    start_auth = (
        "$this->authorize('update', $this->server);" if controls_scoped else ""
    )
    status_auth = (
        "$this->authorize('view', $this->server);" if controls_scoped else ""
    )
    return f"""<?php
class Show {{
public function checkHetznerServerStatus(bool $manual = false)
{{
    {status_auth}
    $service->getServer($this->server->hetzner_server_id);
}}
public function startHetznerServer()
{{
    {start_auth}
    if (!$this->server->hetzner_server_id || !$this->server->cloudProviderToken) return;
    $service->powerOnServer($this->server->hetzner_server_id);
}}
{link_method}
}}
"""


def test_baseline_has_power_control_but_no_manual_link_path() -> None:
    result = witness._evaluate_source(_source(link=False, controls_scoped=False))

    assert result["link_contract"]["manual_link_method_present"] is False
    assert result["control_contract"]["start_calls_hetzner_power_on"] is True
    assert result["manual_link_to_unguarded_power_control_path_active"] is False


def test_ai_delta_links_manual_server_into_unguarded_power_path() -> None:
    result = witness._evaluate_source(_source(link=True, controls_scoped=False))

    assert all(result["link_contract"].values())
    assert result["manual_link_to_unguarded_power_control_path_active"] is True
    assert result["manual_link_power_control_path_authorized"] is False


def test_repair_authorizes_power_and_status_controls() -> None:
    result = witness._evaluate_source(_source(link=True, controls_scoped=True))

    assert result["manual_link_to_unguarded_power_control_path_active"] is False
    assert result["manual_link_power_control_path_authorized"] is True
