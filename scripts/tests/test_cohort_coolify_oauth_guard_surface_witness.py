"""Tests for the Coolify OAuth guard-surface witness."""

from __future__ import annotations

import cohort_coolify_oauth_guard_surface_witness as witness


def _destination(*, oauth_helper: bool, authorized: bool) -> str:
    confirmation = (
        "if (! verifyPasswordConfirmation($password, $this)) { return; }"
        if oauth_helper
        else "if (! Hash::check($password, Auth::user()->password)) { return; }"
    )
    authorization = (
        "$this->authorize('update', $this->resource);" if authorized else ""
    )
    return f"""<?php class Destination {{
public function removeServer(int $network_id, int $server_id, $password) {{
    {authorization}
    {confirmation}
    $server = Server::ownedByCurrentTeam()->findOrFail($server_id);
    StopApplicationOneServer::run($this->resource, $server);
    $this->resource->additional_networks()->detach(
        $network_id, ['server_id' => $server_id]
    );
}}
}}"""


def _advanced(*, oauth_helper: bool, authorized: bool) -> str:
    confirmation = (
        "if (! verifyPasswordConfirmation($password, $this)) { return false; }"
        if oauth_helper
        else "if (! Hash::check($password, Auth::user()->password)) { return false; }"
    )
    authorization = (
        "$this->authorize('update', $this->settings);" if authorized else ""
    )
    return f"""<?php class Advanced {{
public function mount() {{
    if (! isInstanceAdmin()) {{ return redirect()->route('dashboard'); }}
}}
public function toggleTwoStepConfirmation($password): bool {{
    {authorization}
    {confirmation}
    $this->settings->disable_two_step_confirmation = $this->disable_two_step_confirmation = true;
    $this->settings->save();
    return true;
}}
}}"""


def test_destination_distinguishes_oauth_extension_and_repair_guard() -> None:
    baseline = witness._evaluate_destination(
        _destination(oauth_helper=False, authorized=False)
    )
    candidate = witness._evaluate_destination(
        _destination(oauth_helper=True, authorized=False)
    )
    repair = witness._evaluate_destination(
        _destination(oauth_helper=True, authorized=True)
    )

    assert baseline["uses_direct_password_hash_check"] is True
    assert candidate["uses_oauth_aware_password_helper"] is True
    assert candidate["authorizes_application_update"] is False
    assert candidate["stops_application_on_selected_server"] is True
    assert candidate["detaches_selected_additional_network"] is True
    assert repair["authorizes_application_update"] is True


def test_advanced_preexisting_mount_gate_matches_repair_policy() -> None:
    candidate = witness._evaluate_advanced(
        _advanced(oauth_helper=True, authorized=False)
    )
    repair = witness._evaluate_advanced(
        _advanced(oauth_helper=True, authorized=True)
    )
    policy = witness._evaluate_instance_settings_policy(
        """<?php class InstanceSettingsPolicy {
        public function update(User $user, InstanceSettings $settings): bool {
            return isInstanceAdmin();
        }}"""
    )

    assert candidate["mount_rejects_non_instance_admin"] is True
    assert candidate["mount_redirects_rejected_user"] is True
    assert candidate["authorizes_instance_settings_update"] is False
    assert repair["authorizes_instance_settings_update"] is True
    assert policy["update_requires_instance_admin"] is True


def test_application_policy_and_negative_test_are_detected() -> None:
    permissive = witness._evaluate_application_policy(
        """<?php class ApplicationPolicy {
        public function update(User $user, Application $application): Response {
            return Response::allow();
        }}"""
    )
    repaired = witness._evaluate_application_policy(
        """<?php class ApplicationPolicy {
        public function update(User $user, Application $application): Response {
            $teamId = $this->getTeamId($application);
            if ($user->isAdminOfTeam($teamId)) { return Response::allow(); }
            return Response::deny('You need admin or owner permissions');
        }}"""
    )
    tests = witness._evaluate_application_policy_test(
        """
it('allows team admin to update their own team application', function () {
    $user->shouldReceive('isAdminOfTeam')->with(1)->andReturn(true);
});
it('denies team member to update their own team application', function () {
    $user->shouldReceive('isAdminOfTeam')->with(1)->andReturn(false);
    expect($policy->update($user, $application)->allowed())->toBeFalse();
});
"""
    )

    assert permissive["unconditionally_allows_update"] is True
    assert repaired["requires_team_admin_or_owner"] is True
    assert repaired["denies_non_admin_update"] is True
    assert all(tests.values())
