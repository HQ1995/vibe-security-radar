"""Tests for the Coolify Sentinel instant-save path witness."""

from __future__ import annotations

import cohort_coolify_sentinel_instant_save_path_witness as witness


def _component(*, instant_save: bool, safe: bool) -> str:
    validation = (
        "#[Validate(['required', 'string', 'max:500', "
        "'regex:/\\A[a-zA-Z0-9._\\-+=\\/]+\\z/'])]"
        if safe
        else "#[Validate(['required'])]"
    )
    action = ""
    if instant_save:
        action = """
public function instantSave() {
    $this->syncData(true);
    $this->restartSentinel();
}
"""
    return f"""<?php class Sentinel {{
{validation}
public string $sentinelToken;
public function syncData(bool $toModel = false) {{
    $this->authorize('update', $this->server);
    $this->validate();
    $this->server->settings->sentinel_token = $this->sentinelToken;
    $this->server->settings->save();
}}
public function restartSentinel() {{
    $this->server->restartSentinel($customImage);
}}
{action}
}}"""


def test_candidate_adds_persist_then_restart_action() -> None:
    baseline = witness._evaluate_component(
        _component(instant_save=False, safe=False)
    )
    candidate = witness._evaluate_component(
        _component(instant_save=True, safe=False)
    )

    assert baseline["instant_save_method_exists"] is False
    assert candidate["instant_save_method_exists"] is True
    assert candidate["instant_save_persists_all_state"] is True
    assert candidate["instant_save_explicitly_restarts_sentinel"] is True
    assert candidate["token_has_required_only_validation"] is True
    assert candidate["token_has_safe_character_validation"] is False


def test_repaired_component_constrains_token() -> None:
    repaired = witness._evaluate_component(
        _component(instant_save=True, safe=True)
    )

    assert repaired["token_has_required_only_validation"] is False
    assert repaired["token_has_safe_character_validation"] is True


def test_view_exposes_token_and_existing_instant_save_trigger() -> None:
    view = """
<x-forms.checkbox instantSave id="isMetricsEnabled" />
<x-forms.checkbox instantSave id="isSentinelDebugEnabled" />
<x-forms.input type="password" id="sentinelToken" />
"""

    assert all(witness._evaluate_view(view).values())
