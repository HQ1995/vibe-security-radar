"""Tests for the Coolify upgrade-status authentication witness."""

from __future__ import annotations

import cohort_coolify_upgrade_status_auth_witness as witness


UNGUARDED_ROUTES = """<?php
Route::get('/health', [OtherController::class, 'healthcheck']);
Route::get('/upgrade-status', [OtherController::class, 'upgradeStatus']);
Route::group([
    'prefix' => 'v1',
], function () {
    Route::get('/health', [OtherController::class, 'healthcheck']);
    Route::get('/upgrade-status', [OtherController::class, 'upgradeStatus']);
});
"""


GUARDED_ROUTES = """<?php
Route::group([
    'middleware' => ['web', 'auth'],
], function () {
    Route::get('/upgrade-status', [OtherController::class, 'upgradeStatus']);
});
Route::group([
    'middleware' => ['web', 'auth'],
    'prefix' => 'v1',
], function () {
    Route::get('/upgrade-status', [OtherController::class, 'upgradeStatus']);
});
"""


UNGUARDED_CONTROLLER = """<?php
class OtherController
{
    public function upgradeStatus(Request $request)
    {
        $statusFile = '/data/coolify/source/.upgrade-status';
        $content = trim(file_get_contents($statusFile));
        [$step, $message, $timestamp] = explode('|', $content);
        return response()->json(['message' => $message]);
    }
}
"""


GUARDED_CONTROLLER = """<?php
class OtherController
{
    public function upgradeStatus(Request $request)
    {
        $user = auth()->user();
        if (! $user || $user->currentTeam()->id !== 0) {
            return response()->json(['message' => 'Forbidden'], 403);
        }
        $statusFile = '/data/coolify/source/.upgrade-status';
        $content = trim(file_get_contents($statusFile));
        [$step, $message, $timestamp] = explode('|', $content);
        return response()->json(['message' => $message]);
    }
}
"""


def test_unguarded_routes_and_controller_form_disclosure_path() -> None:
    result = witness._evaluate_sources(UNGUARDED_CONTROLLER, UNGUARDED_ROUTES)

    assert result["route_security"]["route_count"] == 2
    assert result["route_security"]["unprotected_route_count"] == 2
    assert result["controller_root_team_guard_present"] is False
    assert result["unauthenticated_upgrade_status_disclosure_path"] is True


def test_route_middleware_and_root_guard_close_disclosure_path() -> None:
    result = witness._evaluate_sources(GUARDED_CONTROLLER, GUARDED_ROUTES)

    assert result["route_security"]["route_count"] == 2
    assert result["route_security"]["unprotected_route_count"] == 0
    assert result["route_security"]["all_upgrade_status_routes_authenticated"] is True
    assert result["controller_root_team_guard_present"] is True
    assert result["unauthenticated_upgrade_status_disclosure_path"] is False


def test_controller_guard_closes_path_even_if_route_is_unprotected() -> None:
    result = witness._evaluate_sources(GUARDED_CONTROLLER, UNGUARDED_ROUTES)

    assert result["route_security"]["unprotected_route_count"] == 2
    assert result["controller_root_team_guard_present"] is True
    assert result["unauthenticated_upgrade_status_disclosure_path"] is False


def test_route_auth_closes_path_even_before_controller_guard() -> None:
    result = witness._evaluate_sources(UNGUARDED_CONTROLLER, GUARDED_ROUTES)

    assert result["route_security"]["all_upgrade_status_routes_authenticated"] is True
    assert result["controller_root_team_guard_present"] is False
    assert result["unauthenticated_upgrade_status_disclosure_path"] is False


def test_claude_signal_requires_explicit_commit_metadata() -> None:
    assert witness._explicit_claude_signal(
        "Andras Bacsai",
        "andras@example.com",
        "Generated with [Claude Code]\n\n"
        "Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
    )
    assert not witness._explicit_claude_signal(
        "Andras Bacsai",
        "andras@example.com",
        "Restrict upgrade-status endpoint",
    )
