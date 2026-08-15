#!/usr/bin/env python3
"""Freeze the Coolify GitHub App install-state causal witness."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


AI_SECURITY_SHA = "5a7408a919e1128e75f23c2598926814685928f6"
FOLLOWUP_REPAIR_SHA = "858b1906ec34e76950262e18135c0ecc5d22eb15"

CONTROLLER_PATH = "app/Http/Controllers/Webhook/Github.php"
HELPER_PATH = "bootstrap/helpers/github.php"
VIEW_PATH = "resources/views/livewire/source/github/change.blade.php"
TEST_PATH = "tests/Feature/Security/GithubAppSetupCallbackTest.php"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_record(repository: Path, revision: str, source_path: str) -> dict[str, str]:
    blob = _git_blob(repository, revision, source_path)
    return {
        "revision": revision,
        "path": source_path,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _nth_line(source: str, marker: str, occurrence: int = 1) -> int:
    matches = [
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if occurrence < 1 or len(matches) < occurrence:
        raise SystemExit(
            f"expected marker {marker!r} occurrence {occurrence}, found {matches}"
        )
    return matches[occurrence - 1]


def _evaluate_candidate(
    controller: str,
    helper: str,
    view: str,
    tests: str,
) -> dict[str, bool]:
    install = _php_method_region(controller, "install")
    consume_state = _php_method_region(controller, "consumeGithubAppSetupState")
    return {
        "install_accepts_predictable_source_uuid": all(
            marker in install
            for marker in (
                "$source = (string) $request->query('source', '')",
                "GithubApp::ownedByCurrentTeam()->where('uuid', $source)",
            )
        ),
        "install_does_not_consume_one_time_state": (
            "consumeGithubAppSetupState" not in install
            and "$request->query('state'" not in install
        ),
        "install_persists_verified_installation_id": all(
            marker in install
            for marker in (
                "$this->githubInstallationBelongsToApp($github_app, $installation_id)",
                "$github_app->installation_id = $installation_id",
                "$github_app->save()",
            )
        ),
        "security_commit_already_has_state_primitive_elsewhere": all(
            marker in consume_state
            for marker in (
                "Cache::pull($this->githubAppSetupStateCacheKey($state))",
                "data_get($payload, 'action') === $action",
                "data_get($payload, 'team_id') === $team_id",
            )
        ),
        "manifest_setup_url_uses_source_uuid": (
            "/source/github/install?source=${uuid}" in view
        ),
        "installation_path_has_no_state": (
            'return "$github->html_url/$installation_path/$name/installations/new";'
            in helper
            and "'action' => 'install'" not in helper
        ),
        "candidate_tests_exercise_source_uuid_contract": (
            tests.count("/webhooks/source/github/install?source=") >= 4
        ),
        "candidate_tests_do_not_cover_install_state_replay": (
            "rejects replayed github app install states" not in tests
        ),
    }


def _evaluate_repair(
    controller: str,
    helper: str,
    view: str,
    tests: str,
) -> dict[str, bool]:
    install = _php_method_region(controller, "install")
    return {
        "install_consumes_action_bound_state": all(
            marker in install
            for marker in (
                "$github_app = $this->consumeGithubAppSetupState(",
                "state: (string) $request->query('state', '')",
                "action: 'install'",
            )
        ),
        "install_no_longer_selects_app_by_source_uuid": (
            "$request->query('source'" not in install
            and "where('uuid', $source)" not in install
        ),
        "installation_path_mints_random_state": all(
            marker in helper
            for marker in (
                "$state = Str::random(64)",
                "Cache::put('github-app-setup-state:'.hash('sha256', $state)",
                "'action' => 'install'",
                "'github_app_id' => $github->id",
                "'team_id' => $github->team_id",
                "http_build_query(['state' => $state])",
            )
        ),
        "manifest_setup_url_drops_predictable_source": (
            "/source/github/install?source=${uuid}" not in view
            and "setup_url: `${webhookBaseUrl}/source/github/install`" in view
        ),
        "repair_tests_reject_uuid_wrong_action_and_replay": all(
            marker in tests
            for marker in (
                "rejects github app install callbacks with an app uuid as state",
                "rejects github app setup states for the wrong callback action",
                "rejects github app setup states from another team",
                "rejects replayed github app install states",
            )
        ),
        "repair_tests_keep_verified_success_path": all(
            marker in tests
            for marker in (
                "sets installation id when github confirms it belongs to the app",
                "cacheGithubAppSetupState('valid-install-state', 'install'",
                "installation_id)->toBe(123456)",
            )
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    candidate_sources = {
        source_path: _text_blob(repository, AI_SECURITY_SHA, source_path)
        for source_path in (CONTROLLER_PATH, HELPER_PATH, VIEW_PATH, TEST_PATH)
    }
    repair_sources = {
        source_path: _text_blob(repository, FOLLOWUP_REPAIR_SHA, source_path)
        for source_path in (CONTROLLER_PATH, HELPER_PATH, VIEW_PATH, TEST_PATH)
    }
    candidate_evaluation = _evaluate_candidate(
        candidate_sources[CONTROLLER_PATH],
        candidate_sources[HELPER_PATH],
        candidate_sources[VIEW_PATH],
        candidate_sources[TEST_PATH],
    )
    repair_evaluation = _evaluate_repair(
        repair_sources[CONTROLLER_PATH],
        repair_sources[HELPER_PATH],
        repair_sources[VIEW_PATH],
        repair_sources[TEST_PATH],
    )
    metadata = _commit_metadata(repository, AI_SECURITY_SHA)
    ancestry = _is_ancestor(repository, AI_SECURITY_SHA, FOLLOWUP_REPAIR_SHA)

    origin_specs = {
        "candidate_source_uuid_lookup": (
            AI_SECURITY_SHA,
            CONTROLLER_PATH,
            candidate_sources[CONTROLLER_PATH],
            "$source = (string) $request->query('source', '')",
            "AI install callback source UUID lookup",
        ),
        "preexisting_source_uuid_setup_url": (
            AI_SECURITY_SHA,
            VIEW_PATH,
            candidate_sources[VIEW_PATH],
            "/source/github/install?source=${uuid}",
            "preexisting predictable installation association URL",
        ),
        "repair_random_install_state": (
            FOLLOWUP_REPAIR_SHA,
            HELPER_PATH,
            repair_sources[HELPER_PATH],
            "$state = Str::random(64)",
            "repair random installation state",
        ),
        "repair_install_state_consumption": (
            FOLLOWUP_REPAIR_SHA,
            CONTROLLER_PATH,
            repair_sources[CONTROLLER_PATH],
            "action: 'install'",
            "repair action-bound installation state",
        ),
        "repair_replay_test": (
            FOLLOWUP_REPAIR_SHA,
            TEST_PATH,
            repair_sources[TEST_PATH],
            "rejects replayed github app install states",
            "repair install-state replay regression test",
        ),
    }
    line_origins = {
        key: _blame_line(
            repository,
            revision,
            source_path,
            _nth_line(source, marker),
            label,
        )
        for key, (
            revision,
            source_path,
            source,
            marker,
            label,
        ) in origin_specs.items()
    }
    expected_origins = {
        key: revision
        for key, (revision, _source_path, _source, _marker, _label) in origin_specs.items()
    }
    expected_origins["preexisting_source_uuid_setup_url"] = (
        "f73c74bd4409d94f5b07b25a93baaffabd0e21fa"
    )

    witness_passed = bool(
        metadata["explicit_claude_signal"] is True
        and ancestry
        and all(candidate_evaluation.values())
        and all(repair_evaluation.values())
        and all(
            line_origins[key]["origin_sha"] == expected
            for key, expected in expected_origins.items()
        )
    )
    source_pairs = [
        *[(AI_SECURITY_SHA, source_path) for source_path in candidate_sources],
        *[(FOLLOWUP_REPAIR_SHA, source_path) for source_path in repair_sources],
    ]
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_github_install_state_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_SECURITY_SHA,
        "fix_sha": FOLLOWUP_REPAIR_SHA,
        "candidate_metadata": metadata,
        "ancestry": ancestry,
        "candidate_evaluation": candidate_evaluation,
        "repair_evaluation": repair_evaluation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, revision, source_path)
            for revision, source_path in source_pairs
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_AI_INCOMPLETE_GITHUB_INSTALL_STATE_BINDING"
        ),
        "mechanism_group": "github_app_install_callback_state_binding",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The predictable source-UUID setup URL predated the Claude commit. The "
            "Claude security fix introduced a one-time, action- and team-bound state "
            "primitive for GitHub App manifest conversion, but rebuilt the install "
            "callback around that older predictable UUID instead of the available "
            "state primitive. GitHub app-id verification remained useful but did not "
            "bind the installation callback to the initiating browser transaction. The follow-up "
            "routes installation through a random 64-character cached state, consumes "
            "it once, binds it to install/app/team, rejects UUID-as-state and wrong-action "
            "inputs, and adds an explicit replay test. This establishes an incomplete "
            "security-fix edge; no exploit reproduction or unique advisory is asserted."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify GitHub install-state witness failed")

    print("Coolify GitHub install-state witness frozen")
    print(f"  candidate: {AI_SECURITY_SHA}")
    print(f"  repair   : {FOLLOWUP_REPAIR_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
