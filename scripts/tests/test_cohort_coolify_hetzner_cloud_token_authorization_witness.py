"""Tests for the Coolify Hetzner stored-credential authorization witness."""

from __future__ import annotations

import cohort_coolify_hetzner_cloud_token_authorization_witness as witness


ROUTES = """<?php
Route::group(['prefix' => 'v1'], function () {
    Route::get('/hetzner/locations', [HetznerController::class, 'locations'])
        ->middleware(['api.ability:read']);
    Route::get('/hetzner/server-types', [HetznerController::class, 'serverTypes'])
        ->middleware(['api.ability:read']);
    Route::get('/hetzner/images', [HetznerController::class, 'images'])
        ->middleware(['api.ability:read']);
    Route::get('/hetzner/ssh-keys', [HetznerController::class, 'sshKeys'])
        ->middleware(['api.ability:read']);
    Route::post('/cloud-tokens/{uuid}/validate', [CloudProviderTokensController::class, 'validateToken'])
        ->middleware(['api.ability:read']);
});
"""


def _hetzner_method(name: str, provider_method: str, *, repaired: bool) -> str:
    authorization = "$this->authorize('view', $token);" if repaired else ""
    return f"""
    public function {name}(Request $request)
    {{
        $teamId = getTeamIdFromToken();
        $token = CloudProviderToken::whereTeamId($teamId)
            ->whereUuid($request->cloud_provider_token_id)
            ->where('provider', 'hetzner')
            ->first();
        {authorization}
        $hetznerService = new HetznerService($token->token);
        $value = $hetznerService->{provider_method}();
        return response()->json($value);
    }}
"""


def _hetzner_controller(*, repaired: bool) -> str:
    methods = [
        _hetzner_method("locations", "getLocations", repaired=repaired),
        _hetzner_method("serverTypes", "getServerTypes", repaired=repaired),
        _hetzner_method("images", "getImages", repaired=repaired),
        _hetzner_method("sshKeys", "getSshKeys", repaired=repaired),
    ]
    return "<?php\nclass HetznerController\n{\n" + "".join(methods) + "}\n"


def _token_controller(*, repaired: bool) -> str:
    authorization = "$this->authorize('view', $cloudToken);" if repaired else ""
    method_name = "validateToken" if repaired else "validate"
    return f"""<?php
class CloudProviderTokensController
{{
    public function {method_name}(Request $request)
    {{
        $teamId = getTeamIdFromToken();
        $cloudToken = CloudProviderToken::whereTeamId($teamId)->whereUuid($request->uuid)->first();
        {authorization}
        $response = Http::withHeaders([
            'Authorization' => 'Bearer '.$cloudToken->token,
        ])->get('https://api.hetzner.cloud/v1/servers');
        return response()->json(['valid' => $response->successful()]);
    }}
}}
"""


CLOUD_POLICY = """<?php
class CloudProviderTokenPolicy
{
    public function view(User $user, CloudProviderToken $token): bool
    {
        return $user->isAdmin();
    }
}
"""


API_POLICY = """<?php
class ApiTokenPolicy
{
    public function create(User $user): bool
    {
        return true;
    }

    public function useWritePermissions(User $user): bool
    {
        // return $user->isAdmin();
        return true;
    }
}
"""


AUTH_PROVIDER = """<?php
protected $policies = [
    CloudProviderToken::class => CloudProviderTokenPolicy::class,
];
"""


def _evaluate(*, repaired: bool) -> dict[str, object]:
    return witness._evaluate_sources(
        ROUTES,
        _hetzner_controller(repaired=repaired),
        _token_controller(repaired=repaired),
        CLOUD_POLICY,
        API_POLICY,
        AUTH_PROVIDER,
    )


def test_ai_origin_allows_member_to_use_stored_provider_credential() -> None:
    result = _evaluate(repaired=False)

    assert all(result["read_routes"].values())
    assert result["api_token_policy"] == {
        "authenticated_member_can_create_token": True,
        "candidate_member_can_request_write_ability": True,
    }
    assert all(result["same_team_member_external_calls"].values())
    assert result["same_team_member_token_validation_call"] is True
    assert result["same_team_member_stored_credential_use_active"] is True


def test_repair_applies_admin_policy_before_external_provider_call() -> None:
    result = _evaluate(repaired=True)

    assert result["cloud_token_policy"]["view_requires_admin"] is True
    assert result["same_team_member_view_policy_allowed"] is False
    assert not any(result["same_team_member_external_calls"].values())
    assert result["same_team_member_token_validation_call"] is False
    assert result["same_team_member_stored_credential_use_active"] is False


def test_missing_read_ability_keeps_endpoint_out_of_member_path() -> None:
    result = witness._evaluate_sources(
        ROUTES.replace("api.ability:read", "api.ability:write", 1),
        _hetzner_controller(repaired=False),
        _token_controller(repaired=False),
        CLOUD_POLICY,
        API_POLICY,
        AUTH_PROVIDER,
    )

    assert result["read_routes"]["locations"] is False
    assert result["same_team_member_external_calls"]["locations"] is False


def test_repair_contract_requires_403_before_external_http() -> None:
    source = """
test('member read token cannot use a stored cloud provider token', function () {
    $this->team->members()->attach($member->id, ['role' => 'member']);
    $memberToken = $member->createToken('member-read', ['read'])->plainTextToken;
    $response = $this->getJson(
        '/api/v1/hetzner/locations?cloud_provider_token_id='.$this->hetznerToken->uuid
    );
    $response->assertForbidden();
    Http::assertNothingSent();
});
"""

    assert all(witness._repair_test_contract(source).values())


def test_claude_signal_requires_explicit_commit_metadata() -> None:
    assert witness._explicit_claude_signal(
        "Andras Bacsai",
        "andras@example.com",
        "Generated with [Claude Code]\n\n"
        "Co-Authored-By: Claude <noreply@anthropic.com>",
    )
    assert not witness._explicit_claude_signal(
        "Andras Bacsai",
        "andras@example.com",
        "fix(security): enforce team access on mutable actions",
    )
