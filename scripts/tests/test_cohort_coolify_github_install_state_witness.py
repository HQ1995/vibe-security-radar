"""Tests for the Coolify GitHub App install-state witness predicates."""

from __future__ import annotations

from cohort_coolify_github_install_state_witness import (
    _evaluate_candidate,
    _evaluate_repair,
)


def test_candidate_detects_source_uuid_install_binding() -> None:
    controller = """
public function install(Request $request) {
    $source = (string) $request->query('source', '');
    $github_app = GithubApp::ownedByCurrentTeam()->where('uuid', $source)->firstOrFail();
    $this->githubInstallationBelongsToApp($github_app, $installation_id);
    $github_app->installation_id = $installation_id;
    $github_app->save();
}
private function consumeGithubAppSetupState($request, $state, $action) {
    Cache::pull($this->githubAppSetupStateCacheKey($state));
    data_get($payload, 'action') === $action;
    data_get($payload, 'team_id') === $team_id;
}
"""
    helper = 'return "$github->html_url/$installation_path/$name/installations/new";'
    view = "setup_url: `/source/github/install?source=${uuid}`"
    tests = "/webhooks/source/github/install?source=" * 4

    assert all(_evaluate_candidate(controller, helper, view, tests).values())


def test_repair_requires_random_bound_state_and_replay_test() -> None:
    controller = """
public function install(Request $request) {
    $github_app = $this->consumeGithubAppSetupState(
        state: (string) $request->query('state', ''),
        action: 'install',
    );
}
"""
    helper = """
$state = Str::random(64);
Cache::put('github-app-setup-state:'.hash('sha256', $state), [
    'action' => 'install',
    'github_app_id' => $github->id,
    'team_id' => $github->team_id,
]);
http_build_query(['state' => $state]);
"""
    view = "setup_url: `${webhookBaseUrl}/source/github/install`"
    tests = "\n".join(
        (
            "rejects github app install callbacks with an app uuid as state",
            "rejects github app setup states for the wrong callback action",
            "rejects github app setup states from another team",
            "rejects replayed github app install states",
            "sets installation id when github confirms it belongs to the app",
            "cacheGithubAppSetupState('valid-install-state', 'install'",
            "installation_id)->toBe(123456)",
        )
    )

    assert all(_evaluate_repair(controller, helper, view, tests).values())
