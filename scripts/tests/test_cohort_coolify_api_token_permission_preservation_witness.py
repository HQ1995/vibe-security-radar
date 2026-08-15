"""Tests for the Coolify API-token permission preservation witness."""

from __future__ import annotations

import cohort_coolify_api_token_permission_preservation_witness as witness


def _component(*, expiration: bool, repaired: bool) -> str:
    expiration_property = "public ?int $expiresInDays = 30;" if expiration else ""
    locked = "#[Locked]\n    " if repaired else ""
    root_check = (
        "! auth()->user()->can('useRootPermissions', PersonalAccessToken::class)"
        if repaired
        else "! $this->canUseRootPermissions"
    )
    write_check = (
        "! auth()->user()->can('useWritePermissions', PersonalAccessToken::class)"
        if repaired
        else "! $this->canUseWritePermissions"
    )
    expiration_validation = (
        "'expiresInDays' => 'nullable|integer|in:7,30,60,90,365';\n"
        "$expiresAt = $this->expiresInDays ? now()->addDays("
        "$this->expiresInDays) : null;"
        if expiration
        else ""
    )
    sink = (
        "createToken($this->description, array_values($this->permissions), "
        "$expiresAt);"
        if expiration
        else "createToken($this->description, array_values($this->permissions));"
    )
    return f"""<?php class ApiTokens {{
public array $permissions = ['read'];
{expiration_property}
{locked}public bool $canUseRootPermissions = false;
{locked}public bool $canUseWritePermissions = false;
public function updatedPermissions($permissionToUpdate) {{
    if ($permissionToUpdate == 'root' && {root_check}) {{ return; }}
    if ($permissionToUpdate == 'write' && {write_check}) {{ return; }}
}}
public function addNewToken() {{
    if (in_array('root', $this->permissions) && {root_check}) {{ return; }}
    if (array_intersect(['write'], $this->permissions) && {write_check}) {{ return; }}
    {expiration_validation}
    $token = auth()->user()->{sink}
}}
}}"""


def test_candidate_rewrites_sink_but_preserves_cached_permission_checks() -> None:
    baseline = witness._evaluate_component(
        _component(expiration=False, repaired=False)
    )
    candidate = witness._evaluate_component(
        _component(expiration=True, repaired=False)
    )

    assert baseline["issues_mutable_permissions_without_expiration"] is True
    assert candidate["issues_mutable_permissions_with_expiration"] is True
    assert candidate["adds_expiration_state_and_validation"] is True
    assert candidate["issuance_root_check_uses_cached_public_flag"] is True
    assert candidate["issuance_root_check_uses_fresh_policy"] is False
    assert candidate["root_capability_is_locked"] is False


def test_repair_locks_flags_and_rechecks_policy_at_issuance() -> None:
    repaired = witness._evaluate_component(
        _component(expiration=True, repaired=True)
    )

    assert repaired["root_capability_is_locked"] is True
    assert repaired["write_capability_is_locked"] is True
    assert repaired["issuance_root_check_uses_cached_public_flag"] is False
    assert repaired["issuance_write_check_uses_cached_public_flag"] is False
    assert repaired["issuance_root_check_uses_fresh_policy"] is True
    assert repaired["issuance_write_check_uses_fresh_policy"] is True
    assert repaired["issues_mutable_permissions_with_expiration"] is True


def test_candidate_and_repair_test_contracts_are_distinct() -> None:
    candidate_test = """
Livewire::test(ApiTokens::class)
    ->set('permissions', ['read'])
    ->call('addNewToken');
expect($token->expires_at)->not->toBeNull();
"""
    repair_test = """
test('api token permission flags are locked', fn () => true);
test('member cannot tamper with root permission flag', function () {
    Livewire::test(ApiTokens::class)->set('canUseRootPermissions', true);
});
test('member cannot create root token through tampered permissions payload', function () {
    Livewire::test(ApiTokens::class)->set('permissions', ['root']);
    expect($member->tokens()->count())->toBe(0);
});
"""

    assert all(witness._evaluate_candidate_tests(candidate_test).values())
    assert all(witness._evaluate_repair_tests(repair_test).values())
