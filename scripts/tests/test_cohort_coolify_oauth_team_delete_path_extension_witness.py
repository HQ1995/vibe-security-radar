"""Tests for the Coolify OAuth team-deletion path-extension witness."""

from __future__ import annotations

import cohort_coolify_oauth_team_delete_path_extension_witness as witness


def _navbar(*, oauth_helper: bool, authorized: bool) -> str:
    confirmation = (
        "if (! verifyPasswordConfirmation($password, $this)) { return; }"
        if oauth_helper
        else "if (! Hash::check($password, Auth::user()->password)) { return; }"
    )
    authorization = "$this->authorize('delete', $currentTeam);" if authorized else ""
    return f"""<?php class NavbarDeleteTeam {{
public function delete($password) {{
    {confirmation}
    $currentTeam = currentTeam();
    {authorization}
    $currentTeam->delete();
}}
}}"""


def test_baseline_password_check_does_not_authorize_team_delete() -> None:
    result = witness._evaluate_navbar(_navbar(oauth_helper=False, authorized=False))

    assert result["uses_direct_password_hash_check"] is True
    assert result["deletes_current_team"] is True
    assert result["has_team_delete_authorization"] is False


def test_ai_helper_skips_frontend_and_backend_password_for_oauth() -> None:
    helper = """<?php
function shouldSkipPasswordConfirmation(): bool {
    if (! Auth::user()?->hasPassword()) { return true; }
    return false;
}
function verifyPasswordConfirmation($password): bool {
    if (shouldSkipPasswordConfirmation()) { return true; }
    return Hash::check($password, Auth::user()->password);
}
"""
    modal = """
$skipPasswordConfirmation = shouldSkipPasswordConfirmation();
finalStep: $confirmWithPassword && !$skipPasswordConfirmation
params.push(this.confirmWithPassword ? this.password : '');
"""

    assert all(witness._evaluate_helper(helper).values())
    assert all(witness._evaluate_modal(modal).values())


def test_repair_authorizes_and_tests_member_negative_case() -> None:
    navbar = witness._evaluate_navbar(_navbar(oauth_helper=True, authorized=True))
    policy = witness._evaluate_policy(
        """<?php class TeamPolicy {
        public function delete(User $user, Team $team): bool {
            if (! $user->teams->contains('id', $team->id)) { return false; }
            return $user->isAdmin() || $user->isOwner();
        }}"""
    )
    repair_test = witness._evaluate_repair_test(
        """
test('owner can delete team via navbar', function () {});
test('member cannot delete team via navbar', function () {
    $this->actingAs($this->member);
    Livewire::test(NavbarDeleteTeam::class)
        ->call('delete', 'password');
    expect(Team::find($this->teamToDelete->id))->not->toBeNull();
});
"""
    )

    assert navbar["has_team_delete_authorization"] is True
    assert all(policy.values())
    assert all(repair_test.values())
