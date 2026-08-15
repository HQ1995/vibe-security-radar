"""Tests for the GitHub install maintenance-state witness predicates."""

from __future__ import annotations

from cohort_coolify_github_install_maintenance_activation_witness import (
    _evaluate_candidate,
    _evaluate_parent,
    _evaluate_repair,
)


def test_parent_has_maintenance_short_circuit_before_vulnerable_write() -> None:
    controller = """
public function install(Request $request) {
    $installation_id = $request->get('installation_id');
    if (app()->isDownForMaintenance()) {
        Storage::disk('webhooks-during-maintenance')->put('install', 'request');
        return;
    }
    $source = $request->get('source');
    $github_app->installation_id = $installation_id;
}
"""
    assert all(_evaluate_parent(controller).values())


def test_candidate_removes_gate_but_retains_unverified_write() -> None:
    controller = """
public function install(Request $request) {
    $installation_id = $request->get('installation_id');
    $source = $request->get('source');
    $github_app = GithubApp::where('uuid', $source)->firstOrFail();
    $github_app->installation_id = $installation_id;
    $github_app->save();
}
"""
    assert all(_evaluate_candidate(controller).values())


def test_repair_scopes_and_verifies_before_persistence() -> None:
    controller = """
public function install(Request $request) {
    $github_app = GithubApp::ownedByCurrentTeam()->where('uuid', $source)->firstOrFail();
    abort_unless(ctype_digit($installation_id), 422);
    $this->githubInstallationBelongsToApp($github_app, $installation_id);
    $github_app->installation_id = $installation_id;
}
"""
    routes = """
Route::middleware(['web', 'auth', 'throttle:30,1'])->group(function () {
    Route::get('/source/github/install', [Github::class, 'install']);
});
"""
    assert all(_evaluate_repair(controller, routes).values())
