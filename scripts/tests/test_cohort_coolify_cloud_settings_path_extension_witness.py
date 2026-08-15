"""Tests for the Coolify cloud-settings authorization path witness."""

from __future__ import annotations

import cohort_coolify_cloud_settings_path_extension_witness as witness


def _updates(*, cloud_skip: bool, repaired: bool) -> str:
    server_property = (
        "public ?Server $server = null;" if cloud_skip else "public Server $server;"
    )
    server_load = (
        "if (! isCloud()) { $this->server = Server::findOrFail(0); }"
        if cloud_skip
        else "$this->server = Server::findOrFail(0);"
    )
    gate = (
        "if (! isInstanceAdmin()) { return redirect()->route('dashboard'); }"
        if repaired
        else ""
    )
    trait = "use AuthorizesRequests;" if repaired else ""
    auth = "$this->authorize('update', $this->settings);" if repaired else ""
    return f"""<?php class Updates {{
{trait}
{server_property}
public function mount() {{ {gate} {server_load} }}
public function instantSave() {{
    {auth}
    $this->settings->is_auto_update_enabled = $this->is_auto_update_enabled;
    $this->settings->save();
}}
public function submit() {{ {auth} $this->instantSave(); }}
public function checkManually() {{
    {auth}
    CheckForUpdatesJob::dispatchSync();
}}
}}"""


def test_candidate_removes_cloud_failure_gate_without_admin_gate() -> None:
    baseline = witness._evaluate_updates(
        _updates(cloud_skip=False, repaired=False)
    )
    candidate = witness._evaluate_updates(
        _updates(cloud_skip=True, repaired=False)
    )

    assert baseline["mount_unconditionally_requires_server_zero"] is True
    assert baseline["mount_skips_server_zero_on_cloud"] is False
    assert candidate["mount_unconditionally_requires_server_zero"] is False
    assert candidate["mount_skips_server_zero_on_cloud"] is True
    assert candidate["mount_has_instance_admin_gate"] is False
    assert candidate["instant_save_mutates_instance_settings"] is True
    assert candidate["instant_save_authorizes_update"] is False


def test_repair_adds_route_and_action_level_authorization() -> None:
    repaired = witness._evaluate_updates(
        _updates(cloud_skip=True, repaired=True)
    )

    assert repaired["mount_has_instance_admin_gate"] is True
    assert repaired["uses_authorization_trait"] is True
    assert repaired["instant_save_authorizes_update"] is True
    assert repaired["submit_authorizes_update"] is True
    assert repaired["manual_check_authorizes_update"] is True


def test_route_neighbor_and_policy_contracts() -> None:
    routes = """
Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/settings/updates', SettingsUpdates::class)->name('settings.updates');
});
"""
    neighbor = """<?php class Index {
public function mount() {
    if (! isInstanceAdmin()) { return redirect()->route('dashboard'); }
}
} """
    policy = """<?php class InstanceSettingsPolicy {
public function update(User $user, InstanceSettings $settings): bool {
    return isInstanceAdmin();
}
} """

    assert all(witness._evaluate_routes(routes).values())
    assert all(witness._evaluate_neighbor_index(neighbor).values())
    assert all(witness._evaluate_policy(policy).values())
