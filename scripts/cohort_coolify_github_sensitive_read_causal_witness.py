#!/usr/bin/env python3
"""Freeze the Coolify GitHub Apps sensitive-read causal witness."""

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


REPOSITORY_IDENTITY = "github.com/coollabsio/coolify"
CANDIDATE_SHA = "802569bf636b8172385981e8a52e312745f826cc"
CANDIDATE_PARENT_SHA = "473c32270d72252ee6753afc35c3ea4360d169e0"
FIX_SHA = "6871160623ae5a42a3b1581de4ca4bccf78f0603"
FIX_PARENT_SHA = "f5ecdfa4ce2bfb9a40d8c90ea7b6b5334dcbe3c2"
PREEXISTING_SENSITIVE_CONTRACT_SHA = "3fa7d03db729143db26b629dbd8d3acb5a78f25e"

CONTROLLER_PATH = "app/Http/Controllers/Api/GithubController.php"
ROUTES_PATH = "routes/api.php"
MIDDLEWARE_PATH = "app/Http/Middleware/ApiSensitiveData.php"
CANDIDATE_TEST_PATH = "tests/Feature/GithubAppsListApiTest.php"
FIX_TEST_PATH = "tests/Feature/Api/GithubAppsListApiTest.php"

CONDUCTOR_MARKER = "Changes auto-committed by Conductor"
SENSITIVE_ROUTE_MIDDLEWARE = (
    "'middleware' => ['auth:sanctum', ApiAllowed::class, 'api.sensitive']"
)
SENSITIVE_ATTRIBUTE = (
    "'can_read_sensitive' => $token->can('root') || $token->can('read:sensitive')"
)
LIST_ROUTE = (
    "Route::get('/github-apps', "
    "[GithubController::class, 'list_github_apps'])"
    "->middleware(['api.ability:read']);"
)
PERMISSION_GATE = "request()->attributes->get('can_read_sensitive', false) === true"


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


def _line_number(source: str, marker: str) -> int:
    matches = [
        index + 1 for index, line in enumerate(source.splitlines()) if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one marker {marker!r}, found {matches}")
    return matches[0]


def _line_in_method(source: str, method_name: str, marker: str) -> int:
    method = _php_method_region(source, method_name)
    method_offset = source.index(method)
    return source[:method_offset].count("\n") + _line_number(method, marker)


def _has_sensitive_fields(source: str) -> bool:
    return "'client_secret'" in source and "'webhook_secret'" in source


def _evaluate_parent(
    controller: str,
    routes: str,
    middleware: str,
) -> dict[str, bool]:
    return {
        "list_helper_absent_before_candidate": (
            "function removeSensitiveData" not in controller
        ),
        "list_method_absent_before_candidate": (
            "function list_github_apps" not in controller
        ),
        "list_route_absent_before_candidate": LIST_ROUTE not in routes,
        "sensitive_route_middleware_preexists": (SENSITIVE_ROUTE_MIDDLEWARE in routes),
        "sensitive_capability_attribute_preexists": (SENSITIVE_ATTRIBUTE in middleware),
    }


def _evaluate_candidate(
    controller: str,
    routes: str,
    middleware: str,
    tests: str,
) -> dict[str, bool]:
    helper = _php_method_region(controller, "removeSensitiveData")
    listing = _php_method_region(controller, "list_github_apps")
    return {
        "candidate_route_uses_preexisting_sensitive_middleware_group": (
            SENSITIVE_ROUTE_MIDDLEWARE in routes and LIST_ROUTE in routes
        ),
        "candidate_time_contract_computes_sensitive_capability": (
            SENSITIVE_ATTRIBUTE in middleware
        ),
        "candidate_list_maps_every_app_through_helper": (
            "$githubApps->map(function ($app)" in listing
            and "$this->removeSensitiveData($app)" in listing
        ),
        "candidate_helper_unconditionally_hides_both_secrets": (
            "$githubApp->makeHidden([" in helper
            and _has_sensitive_fields(helper)
            and helper.count("makeHidden(") == 1
        ),
        "candidate_helper_ignores_sensitive_capability": (
            "can_read_sensitive" not in helper and "makeVisible(" not in helper
        ),
        "candidate_test_uses_wildcard_token": (
            "createToken('test-token', ['*'], $this->team->id)" in tests
        ),
        "candidate_test_asserts_only_unconditional_hiding": all(
            marker in tests
            for marker in (
                "test('does not return sensitive data'",
                "not->toHaveKey('client_secret')",
                "not->toHaveKey('webhook_secret')",
            )
        )
        and "returns sensitive data for read sensitive tokens" not in tests,
    }


def _evaluate_fix_parent(
    candidate_controller: str,
    fix_parent_controller: str,
    fix_parent_tests: str,
) -> dict[str, bool]:
    candidate_helper = _php_method_region(candidate_controller, "removeSensitiveData")
    surviving_helper = _php_method_region(fix_parent_controller, "removeSensitiveData")
    return {
        "candidate_helper_survives_exactly_to_fix_parent": (
            candidate_helper == surviving_helper
        ),
        "fix_parent_still_unconditionally_hides_both_secrets": (
            "$githubApp->makeHidden([" in surviving_helper
            and _has_sensitive_fields(surviving_helper)
            and "can_read_sensitive" not in surviving_helper
            and "makeVisible(" not in surviving_helper
        ),
        "fix_parent_tests_still_lack_sensitive_reader_positive_case": (
            "test('does not return sensitive data'" in fix_parent_tests
            and "returns sensitive data for read sensitive tokens"
            not in fix_parent_tests
        ),
    }


def _evaluate_repair(controller: str, tests: str) -> dict[str, bool]:
    helper = _php_method_region(controller, "removeSensitiveData")
    listing = _php_method_region(controller, "list_github_apps")
    return {
        "repair_keeps_list_endpoint_scoped_to_same_helper": (
            "$this->removeSensitiveData($app)" in listing
        ),
        "repair_uses_precomputed_sensitive_capability": (PERMISSION_GATE in helper),
        "repair_makes_both_secrets_visible_for_sensitive_reader": (
            "$githubApp->makeVisible([" in helper
            and _has_sensitive_fields(
                helper[
                    helper.index("$githubApp->makeVisible([") : helper.index("} else {")
                ]
            )
        ),
        "repair_keeps_both_secrets_hidden_without_capability": (
            "} else {" in helper
            and "$githubApp->makeHidden([" in helper
            and _has_sensitive_fields(helper[helper.index("} else {") :])
        ),
        "repair_tests_read_token_negative_case": all(
            marker in tests
            for marker in (
                "does not return sensitive data for read tokens",
                "createGithubAppsApiToken($this, ['read'])",
                "not->toHaveKey('client_secret')",
                "not->toHaveKey('webhook_secret')",
            )
        ),
        "repair_tests_sensitive_token_positive_case": all(
            marker in tests
            for marker in (
                "returns sensitive data for read sensitive tokens",
                "createGithubAppsApiToken($this, ['read', 'read:sensitive'])",
                "'client_secret' => 'secret-should-be-visible'",
                "'webhook_secret' => 'webhook-secret-should-be-visible'",
            )
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    parent_sources = {
        CONTROLLER_PATH: _text_blob(repository, CANDIDATE_PARENT_SHA, CONTROLLER_PATH),
        ROUTES_PATH: _text_blob(repository, CANDIDATE_PARENT_SHA, ROUTES_PATH),
        MIDDLEWARE_PATH: _text_blob(repository, CANDIDATE_PARENT_SHA, MIDDLEWARE_PATH),
    }
    candidate_sources = {
        CONTROLLER_PATH: _text_blob(repository, CANDIDATE_SHA, CONTROLLER_PATH),
        ROUTES_PATH: _text_blob(repository, CANDIDATE_SHA, ROUTES_PATH),
        MIDDLEWARE_PATH: _text_blob(repository, CANDIDATE_SHA, MIDDLEWARE_PATH),
        CANDIDATE_TEST_PATH: _text_blob(repository, CANDIDATE_SHA, CANDIDATE_TEST_PATH),
    }
    fix_parent_sources = {
        CONTROLLER_PATH: _text_blob(repository, FIX_PARENT_SHA, CONTROLLER_PATH),
        FIX_TEST_PATH: _text_blob(repository, FIX_PARENT_SHA, FIX_TEST_PATH),
    }
    fix_sources = {
        CONTROLLER_PATH: _text_blob(repository, FIX_SHA, CONTROLLER_PATH),
        FIX_TEST_PATH: _text_blob(repository, FIX_SHA, FIX_TEST_PATH),
    }

    evaluations = {
        "candidate_parent": _evaluate_parent(
            parent_sources[CONTROLLER_PATH],
            parent_sources[ROUTES_PATH],
            parent_sources[MIDDLEWARE_PATH],
        ),
        "candidate": _evaluate_candidate(
            candidate_sources[CONTROLLER_PATH],
            candidate_sources[ROUTES_PATH],
            candidate_sources[MIDDLEWARE_PATH],
            candidate_sources[CANDIDATE_TEST_PATH],
        ),
        "fix_parent": _evaluate_fix_parent(
            candidate_sources[CONTROLLER_PATH],
            fix_parent_sources[CONTROLLER_PATH],
            fix_parent_sources[FIX_TEST_PATH],
        ),
        "repair": _evaluate_repair(
            fix_sources[CONTROLLER_PATH],
            fix_sources[FIX_TEST_PATH],
        ),
    }

    metadata = {
        CANDIDATE_SHA: _commit_metadata(repository, CANDIDATE_SHA),
        FIX_SHA: _commit_metadata(repository, FIX_SHA),
    }
    ancestry = {
        "candidate_parent_is_exact": (
            metadata[CANDIDATE_SHA]["parents"] == [CANDIDATE_PARENT_SHA]
        ),
        "fix_parent_is_exact": metadata[FIX_SHA]["parents"] == [FIX_PARENT_SHA],
        "candidate_strictly_precedes_fix_parent": _is_ancestor(
            repository, CANDIDATE_SHA, FIX_PARENT_SHA
        ),
        "fix_parent_immediately_precedes_fix": _is_ancestor(
            repository, FIX_PARENT_SHA, FIX_SHA
        ),
        "fix_does_not_precede_candidate": not _is_ancestor(
            repository, FIX_SHA, CANDIDATE_SHA
        ),
    }

    line_origins = {
        "preexisting_sensitive_route_middleware": _blame_line(
            repository,
            CANDIDATE_SHA,
            ROUTES_PATH,
            _line_number(candidate_sources[ROUTES_PATH], SENSITIVE_ROUTE_MIDDLEWARE),
            "preexisting api.sensitive route-group middleware",
        ),
        "preexisting_sensitive_capability_attribute": _blame_line(
            repository,
            CANDIDATE_SHA,
            MIDDLEWARE_PATH,
            _line_number(candidate_sources[MIDDLEWARE_PATH], SENSITIVE_ATTRIBUTE),
            "preexisting root/read:sensitive capability contract",
        ),
        "candidate_list_route": _blame_line(
            repository,
            CANDIDATE_SHA,
            ROUTES_PATH,
            _line_number(candidate_sources[ROUTES_PATH], LIST_ROUTE),
            "candidate GitHub Apps list route",
        ),
        "candidate_unconditional_hide": _blame_line(
            repository,
            CANDIDATE_SHA,
            CONTROLLER_PATH,
            _line_in_method(
                candidate_sources[CONTROLLER_PATH],
                "removeSensitiveData",
                "$githubApp->makeHidden([",
            ),
            "candidate unconditional GitHub secret hiding",
        ),
        "candidate_unconditional_hide_test": _blame_line(
            repository,
            CANDIDATE_SHA,
            CANDIDATE_TEST_PATH,
            _line_number(
                candidate_sources[CANDIDATE_TEST_PATH],
                "test('does not return sensitive data'",
            ),
            "candidate unconditional hiding test",
        ),
        "fix_parent_surviving_unconditional_hide": _blame_line(
            repository,
            FIX_PARENT_SHA,
            CONTROLLER_PATH,
            _line_in_method(
                fix_parent_sources[CONTROLLER_PATH],
                "removeSensitiveData",
                "$githubApp->makeHidden([",
            ),
            "candidate hide surviving unchanged to fix parent",
        ),
        "repair_permission_gate": _blame_line(
            repository,
            FIX_SHA,
            CONTROLLER_PATH,
            _line_in_method(
                fix_sources[CONTROLLER_PATH],
                "removeSensitiveData",
                PERMISSION_GATE,
            ),
            "repair permission-aware visibility gate",
        ),
        "repair_sensitive_visibility": _blame_line(
            repository,
            FIX_SHA,
            CONTROLLER_PATH,
            _line_in_method(
                fix_sources[CONTROLLER_PATH],
                "removeSensitiveData",
                "$githubApp->makeVisible([",
            ),
            "repair sensitive-reader makeVisible branch",
        ),
        "repair_read_token_negative_test": _blame_line(
            repository,
            FIX_SHA,
            FIX_TEST_PATH,
            _line_number(
                fix_sources[FIX_TEST_PATH],
                "does not return sensitive data for read tokens",
            ),
            "repair ordinary-read negative test",
        ),
        "repair_sensitive_token_positive_test": _blame_line(
            repository,
            FIX_SHA,
            FIX_TEST_PATH,
            _line_number(
                fix_sources[FIX_TEST_PATH],
                "returns sensitive data for read sensitive tokens",
            ),
            "repair read:sensitive positive test",
        ),
    }
    expected_origins = {
        "preexisting_sensitive_route_middleware": PREEXISTING_SENSITIVE_CONTRACT_SHA,
        "preexisting_sensitive_capability_attribute": (
            PREEXISTING_SENSITIVE_CONTRACT_SHA
        ),
        "candidate_list_route": CANDIDATE_SHA,
        "candidate_unconditional_hide": CANDIDATE_SHA,
        "candidate_unconditional_hide_test": CANDIDATE_SHA,
        "fix_parent_surviving_unconditional_hide": CANDIDATE_SHA,
        "repair_permission_gate": FIX_SHA,
        "repair_sensitive_visibility": FIX_SHA,
        "repair_read_token_negative_test": FIX_SHA,
        "repair_sensitive_token_positive_test": FIX_SHA,
    }
    provenance_checks = {
        key: line_origins[key]["origin_sha"] == origin
        for key, origin in expected_origins.items()
    }

    witness_passed = bool(
        metadata[CANDIDATE_SHA]["explicit_claude_signal"] is True
        and metadata[CANDIDATE_SHA]["message"] == CONDUCTOR_MARKER
        and str(metadata[FIX_SHA]["message"]).startswith(
            "fix(api): gate sensitive storage and GitHub fields"
        )
        and all(ancestry.values())
        and all(
            result is True
            for section in evaluations.values()
            for result in section.values()
        )
        and all(provenance_checks.values())
    )
    if not witness_passed:
        failed = {
            section: [name for name, passed in checks.items() if not passed]
            for section, checks in {
                **evaluations,
                "ancestry": ancestry,
                "provenance": provenance_checks,
            }.items()
            if not all(checks.values())
        }
        raise SystemExit(f"GitHub sensitive-read causal witness failed: {failed}")

    source_pairs = [
        *[
            (CANDIDATE_PARENT_SHA, source_path)
            for source_path in (CONTROLLER_PATH, ROUTES_PATH, MIDDLEWARE_PATH)
        ],
        *[(CANDIDATE_SHA, source_path) for source_path in candidate_sources],
        (FIX_PARENT_SHA, CONTROLLER_PATH),
        (FIX_PARENT_SHA, FIX_TEST_PATH),
        (FIX_SHA, CONTROLLER_PATH),
        (FIX_SHA, FIX_TEST_PATH),
    ]
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_github_sensitive_read_causal_witness",
        "repository_identity": REPOSITORY_IDENTITY,
        "candidate_sha": CANDIDATE_SHA,
        "fix_sha": FIX_SHA,
        "commit_metadata": metadata,
        "ancestry": ancestry,
        "evaluations": evaluations,
        "line_origins": line_origins,
        "provenance_checks": provenance_checks,
        "source_blobs": [
            _blob_record(repository, revision, source_path)
            for revision, source_path in source_pairs
        ],
        "confirmed_edges": [
            {
                "candidate_sha": CANDIDATE_SHA,
                "fix_sha": FIX_SHA,
                "causal_role": "DIRECT_AI_ORIGIN",
            }
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_DIRECT_AI_GITHUB_SENSITIVE_READ_SUPPRESSION"
        ),
        "mechanism_group": "github_apps_list_ignored_read_sensitive_capability",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Conductor candidate directly adds the GitHub Apps list route and "
            "helper. The route already runs behind api.sensitive, whose preexisting "
            "middleware computes can_read_sensitive from root or read:sensitive, "
            "but the candidate helper ignores that contract and unconditionally "
            "hides client_secret and webhook_secret. That exact helper survives to "
            "the fix parent. The repair makes the same list helper expose both "
            "fields only for a sensitive-capable token, retain hiding for an "
            "ordinary read token, and adds tests for both branches. This claim is "
            "limited to the GitHub Apps list endpoint capability suppression. It "
            "does not attribute the same repair commit's storage changes, other "
            "GitHub create/update URL defects, a runtime exploit, or an advisory."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify GitHub sensitive-read causal witness frozen")
    print(f"  candidate: {CANDIDATE_SHA}")
    print(f"  repair   : {FIX_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
