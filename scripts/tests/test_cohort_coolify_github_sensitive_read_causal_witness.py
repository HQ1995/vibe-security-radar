"""Tests for the Coolify GitHub Apps sensitive-read causal witness."""

from __future__ import annotations

from cohort_coolify_github_sensitive_read_causal_witness import (
    _evaluate_candidate,
    _evaluate_fix_parent,
    _evaluate_parent,
    _evaluate_repair,
)


ROUTES_WITH_CONTRACT = """
Route::group([
    'middleware' => ['auth:sanctum', ApiAllowed::class, 'api.sensitive'],
], function () {
    Route::get('/github-apps', [GithubController::class, 'list_github_apps'])->middleware(['api.ability:read']);
});
"""

ROUTES_BEFORE_CANDIDATE = """
Route::group([
    'middleware' => ['auth:sanctum', ApiAllowed::class, 'api.sensitive'],
], function () {});
"""

MIDDLEWARE_WITH_CONTRACT = """
public function handle(Request $request, Closure $next)
{
    $token = $request->user()->currentAccessToken();
    $request->attributes->add([
        'can_read_sensitive' => $token->can('root') || $token->can('read:sensitive'),
    ]);
    return $next($request);
}
"""

CANDIDATE_CONTROLLER = """
class GithubController {
private function removeSensitiveData($githubApp)
{
    $githubApp->makeHidden([
        'client_secret',
        'webhook_secret',
    ]);
    return serializeApiResponse($githubApp);
}
public function list_github_apps(Request $request)
{
    $githubApps = $githubApps->map(function ($app) {
        return $this->removeSensitiveData($app);
    });
}
}
"""

CANDIDATE_TESTS = """
$this->token = $this->user->createToken('test-token', ['*'], $this->team->id);
test('does not return sensitive data', function () {
    expect($json[0])->not->toHaveKey('client_secret');
    expect($json[0])->not->toHaveKey('webhook_secret');
});
"""

REPAIRED_CONTROLLER = """
class GithubController {
private function removeSensitiveData($githubApp)
{
    if (request()->attributes->get('can_read_sensitive', false) === true) {
        $githubApp->makeVisible([
            'client_secret',
            'webhook_secret',
        ]);
    } else {
        $githubApp->makeHidden([
            'client_secret',
            'webhook_secret',
        ]);
    }
    return serializeApiResponse($githubApp);
}
public function list_github_apps(Request $request)
{
    $githubApps = $githubApps->map(function ($app) {
        return $this->removeSensitiveData($app);
    });
}
}
"""

REPAIR_TESTS = """
test('does not return sensitive data for read tokens', function () {
    $readToken = createGithubAppsApiToken($this, ['read']);
    expect($json[0])->not->toHaveKey('client_secret');
    expect($json[0])->not->toHaveKey('webhook_secret');
});
test('returns sensitive data for read sensitive tokens', function () {
    $sensitiveToken = createGithubAppsApiToken($this, ['read', 'read:sensitive']);
    $response->assertJsonFragment([
        'client_secret' => 'secret-should-be-visible',
        'webhook_secret' => 'webhook-secret-should-be-visible',
    ]);
});
"""


def test_parent_has_sensitive_contract_but_no_list_endpoint() -> None:
    checks = _evaluate_parent(
        "class GithubController {}",
        ROUTES_BEFORE_CANDIDATE,
        MIDDLEWARE_WITH_CONTRACT,
    )

    assert all(checks.values())


def test_candidate_ignores_preexisting_sensitive_capability() -> None:
    checks = _evaluate_candidate(
        CANDIDATE_CONTROLLER,
        ROUTES_WITH_CONTRACT,
        MIDDLEWARE_WITH_CONTRACT,
        CANDIDATE_TESTS,
    )

    assert all(checks.values())


def test_fix_parent_requires_exact_survival_and_no_positive_case() -> None:
    checks = _evaluate_fix_parent(
        CANDIDATE_CONTROLLER,
        CANDIDATE_CONTROLLER,
        CANDIDATE_TESTS,
    )

    assert all(checks.values())


def test_repair_uses_permission_aware_visibility_with_dual_tests() -> None:
    checks = _evaluate_repair(REPAIRED_CONTROLLER, REPAIR_TESTS)

    assert all(checks.values())


def test_candidate_is_not_accepted_if_it_already_honors_capability() -> None:
    checks = _evaluate_candidate(
        REPAIRED_CONTROLLER,
        ROUTES_WITH_CONTRACT,
        MIDDLEWARE_WITH_CONTRACT,
        CANDIDATE_TESTS,
    )

    assert checks["candidate_helper_unconditionally_hides_both_secrets"] is True
    assert checks["candidate_helper_ignores_sensitive_capability"] is False
