#!/usr/bin/env python3
"""Freeze the Coolify AI TrustHosts negative-cache causal origin."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
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
CANDIDATE_SHA = "922884e6d3e913883000f8e4bfe1a979daad3aca"
CANDIDATE_PARENT_SHA = "eecf22f6a5d4a927f9d0c6eaf84e7757077e8c50"
FIX_SHA = "5ce0670ca4ee5744da5b8d5e5248df8b95c79f83"
COLD_CACHE_CANDIDATE_SHA = "e1fe58639756cf7b232458eddd6978e4ed0031f5"
COLD_CACHE_FIX_SHA = "e1d4b4682efc898ba5aa3751b2da2072f89c7e24"

SOURCE_PATH = "app/Http/Middleware/TrustHosts.php"
TEST_PATH = "tests/Feature/TrustHostsMiddlewareTest.php"
COMPOSER_LOCK_PATH = "composer.lock"
METHOD_NAME = "hosts"

REMEMBER_CALL = (
    "$fqdnHost = Cache::remember('instance_settings_fqdn_host', 300, function () {"
)
CANDIDATE_HOST_FALLBACK = "return $host ?: null;"
CANDIDATE_NEGATIVE_RETURN = "return null;"
FIX_HOST_FALLBACK = "return $host ?: '';"
FIX_NEGATIVE_RETURN = "return '';"
FIX_SENTINEL_CONSUMPTION = "$fqdnHost = $fqdnHost !== '' ? $fqdnHost : null;"
FALLBACK_TRUST_PATTERN = "$this->allSubdomainsOfApplicationUrl();"
POSITIVE_CACHE_TEST = (
    "it('caches trusted hosts to avoid database queries on every request'"
)
NEGATIVE_CACHE_TEST = "it('caches negative results when no FQDN is configured'"
NEGATIVE_CACHE_HAS_ASSERTION = (
    "expect(Cache::has('instance_settings_fqdn_host'))->toBeTrue();"
)
NEGATIVE_CACHE_VALUE_ASSERTION = (
    "expect(Cache::get('instance_settings_fqdn_host'))->toBe('');"
)

COLD_CACHE_READ = "$fqdnHost = Cache::get('instance_settings_fqdn_host');"
COLD_CACHE_EARLY_RETURN = "if ($fqdnHost === '' || $fqdnHost === null) {"
COLD_CACHE_EAGER_POPULATION = "$this->hosts();"

LARAVEL_FRAMEWORK_VERSION = "v12.21.0"
LARAVEL_FRAMEWORK_REFERENCE = "ac8c4e73bf1b5387b709f7736d41427e6af1c93b"
LARAVEL_CACHE_SOURCE_URL = (
    "https://raw.githubusercontent.com/laravel/framework/"
    f"{LARAVEL_FRAMEWORK_REFERENCE}/src/Illuminate/Cache/Repository.php"
)
LARAVEL_CACHE_SOURCE_SHA256 = (
    "cb1784edf751cfa5fef220124c7a665d282cc945542abeeff57fc7061406a364"
)
LARAVEL_HAS_SOURCE_LINES = [88, 90]
LARAVEL_REMEMBER_SOURCE_LINES = [420, 435]

NEGATIVE_CACHE_MECHANISM = "trust_hosts_null_negative_cache_requery"
COLD_CACHE_MECHANISM = "trust_hosts_cold_cache_validation_bypass"

CLAIM_BOUNDARY = (
    "The Claude-authored candidate introduces a five-minute Cache::remember "
    "optimization but returns null for an absent or unavailable FQDN. In the exact "
    "locked Laravel version, null is indistinguishable from a cache miss, so each "
    "within-TTL hosts() call re-executes the settings lookup. The direct child fix "
    "uses an empty-string sentinel and converts it back to null before consumption, "
    "preserving the trusted-host result while preventing repeated negative lookups. "
    "This is an incomplete optimization contract, not an increase over the parent's "
    "pre-existing query frequency, not a host-validation or account-takeover flaw, "
    "and not the later cold-cache validation bypass. The shared sentinel is retained "
    "in that later edge but does not merge the two mechanism counts."
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(
    repository: Path,
    revision: str,
    source_path: str = SOURCE_PATH,
) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_record(
    repository: Path,
    revision: str,
    source_path: str,
) -> dict[str, str]:
    blob = _git_blob(repository, revision, source_path)
    return {
        "revision": revision,
        "path": source_path,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _line_number(source: str, marker: str) -> int:
    matches = [
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one {marker!r} line, found {matches}")
    return matches[0]


def _framework_lock_proof(composer_lock: bytes) -> dict[str, object]:
    try:
        lock = json.loads(composer_lock)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid composer.lock: {exc}") from exc
    packages = [
        package
        for package in lock.get("packages", [])
        if package.get("name") == "laravel/framework"
    ]
    if len(packages) != 1:
        raise SystemExit(
            f"expected one laravel/framework package, found {len(packages)}"
        )
    package = packages[0]
    source = package.get("source", {})
    checks = {
        "framework_version_is_exact": (
            package.get("version") == LARAVEL_FRAMEWORK_VERSION
        ),
        "framework_source_reference_is_exact": (
            source.get("reference") == LARAVEL_FRAMEWORK_REFERENCE
        ),
        "framework_source_is_official_repository": (
            source.get("url") == "https://github.com/laravel/framework.git"
        ),
    }
    return {
        "checks": checks,
        "package": {
            "name": package.get("name"),
            "version": package.get("version"),
            "source": source,
        },
        "composer_lock_sha256": hashlib.sha256(composer_lock).hexdigest(),
        "cache_repository_source": {
            "url": LARAVEL_CACHE_SOURCE_URL,
            "sha256": LARAVEL_CACHE_SOURCE_SHA256,
            "has_contract_line_span": LARAVEL_HAS_SOURCE_LINES,
            "remember_contract_line_span": LARAVEL_REMEMBER_SOURCE_LINES,
            "contract": {
                "has_treats_null_as_absent": True,
                "remember_returns_cached_value_only_when_non_null": True,
                "remember_executes_callback_when_cached_value_is_null": True,
            },
        },
    }


def _simulate_remember(
    callback_value: str | None,
    *,
    invocation_count: int = 3,
) -> dict[str, object]:
    stored_value: str | None = None
    callback_count = 0
    returned_values: list[str | None] = []
    for _ in range(invocation_count):
        value = stored_value
        if value is None:
            callback_count += 1
            value = callback_value
            stored_value = value
        returned_values.append(value)
    return {
        "invocation_count_within_ttl": invocation_count,
        "callback_count": callback_count,
        "stored_value": stored_value,
        "framework_has_returns_true": stored_value is not None,
        "returned_values": returned_values,
    }


def _behavior_matrix() -> dict[str, dict[str, object]]:
    candidate_negative = _simulate_remember(None)
    fix_negative = _simulate_remember("")
    positive = _simulate_remember("coolify.example.com")
    return {
        "candidate_negative_null": {
            **candidate_negative,
            "consumer_value": candidate_negative["stored_value"],
            "trusted_fqdn_added": False,
        },
        "fix_negative_empty_string_sentinel": {
            **fix_negative,
            "consumer_value": None,
            "trusted_fqdn_added": False,
        },
        "positive_fqdn_control": {
            **positive,
            "consumer_value": positive["stored_value"],
            "trusted_fqdn_added": True,
        },
    }


def _evaluate_behavior(
    matrix: dict[str, dict[str, object]],
) -> dict[str, bool]:
    candidate = matrix["candidate_negative_null"]
    fix = matrix["fix_negative_empty_string_sentinel"]
    positive = matrix["positive_fqdn_control"]
    return {
        "candidate_null_reexecutes_lookup_on_every_within_ttl_call": (
            candidate["callback_count"] == candidate["invocation_count_within_ttl"] == 3
            and candidate["framework_has_returns_true"] is False
        ),
        "fix_sentinel_executes_lookup_once_within_ttl": (
            fix["callback_count"] == 1
            and fix["invocation_count_within_ttl"] == 3
            and fix["framework_has_returns_true"] is True
        ),
        "sentinel_conversion_preserves_negative_consumer_result": (
            candidate["consumer_value"] is None
            and fix["consumer_value"] is None
            and candidate["trusted_fqdn_added"] is False
            and fix["trusted_fqdn_added"] is False
        ),
        "positive_fqdn_is_cached_and_preserved": (
            positive["callback_count"] == 1
            and positive["framework_has_returns_true"] is True
            and positive["consumer_value"] == "coolify.example.com"
            and positive["trusted_fqdn_added"] is True
        ),
    }


def _evaluate_versions(
    baseline: str,
    candidate: str,
    candidate_tests: str,
    fix: str,
    fix_tests: str,
) -> dict[str, bool]:
    baseline_hosts = _php_method_region(baseline, METHOD_NAME)
    candidate_hosts = _php_method_region(candidate, METHOD_NAME)
    fix_hosts = _php_method_region(fix, METHOD_NAME)
    return {
        "baseline_queries_settings_without_cache_contract": (
            "InstanceSettings::get();" in baseline_hosts
            and REMEMBER_CALL not in baseline_hosts
        ),
        "candidate_introduces_five_minute_remember_contract": (
            REMEMBER_CALL in candidate_hosts
        ),
        "candidate_negative_paths_return_null": (
            CANDIDATE_HOST_FALLBACK in candidate_hosts
            and CANDIDATE_NEGATIVE_RETURN in candidate_hosts
            and FIX_SENTINEL_CONSUMPTION not in candidate_hosts
        ),
        "candidate_only_tests_positive_cache_result": (
            POSITIVE_CACHE_TEST in candidate_tests
            and NEGATIVE_CACHE_TEST not in candidate_tests
        ),
        "fix_uses_non_null_sentinel_on_both_negative_paths": (
            FIX_HOST_FALLBACK in fix_hosts
            and FIX_NEGATIVE_RETURN in fix_hosts
            and CANDIDATE_HOST_FALLBACK not in fix_hosts
            and CANDIDATE_NEGATIVE_RETURN not in fix_hosts
        ),
        "fix_converts_sentinel_before_trusted_host_consumption": (
            FIX_SENTINEL_CONSUMPTION in fix_hosts
            and fix_hosts.index(FIX_SENTINEL_CONSUMPTION)
            < fix_hosts.index("if ($fqdnHost) {")
        ),
        "fix_preserves_fallback_trust_pattern": (
            FALLBACK_TRUST_PATTERN in candidate_hosts
            and FALLBACK_TRUST_PATTERN in fix_hosts
        ),
        "fix_adds_exact_negative_cache_regression_test": (
            NEGATIVE_CACHE_TEST in fix_tests
            and NEGATIVE_CACHE_HAS_ASSERTION in fix_tests
            and NEGATIVE_CACHE_VALUE_ASSERTION in fix_tests
        ),
    }


def _evaluate_mechanism_separation(
    candidate: str,
    fix: str,
    cold_candidate: str,
    cold_fix: str,
) -> dict[str, bool]:
    cold_candidate_handle = _php_method_region(cold_candidate, "handle")
    cold_fix_handle = _php_method_region(cold_fix, "handle")
    cold_candidate_hosts = _php_method_region(cold_candidate, METHOD_NAME)
    cold_fix_hosts = _php_method_region(cold_fix, METHOD_NAME)
    return {
        "negative_cache_edge_does_not_define_handle_override": (
            "public function handle(" not in candidate
            and "public function handle(" not in fix
        ),
        "cold_cache_candidate_reads_cache_before_validation": (
            COLD_CACHE_READ in cold_candidate_handle
            and COLD_CACHE_EARLY_RETURN in cold_candidate_handle
            and COLD_CACHE_EAGER_POPULATION not in cold_candidate_handle
        ),
        "cold_cache_fix_eagerly_populates_before_read": (
            COLD_CACHE_EAGER_POPULATION in cold_fix_handle
            and COLD_CACHE_READ in cold_fix_handle
            and cold_fix_handle.index(COLD_CACHE_EAGER_POPULATION)
            < cold_fix_handle.index(COLD_CACHE_READ)
        ),
        "negative_cache_sentinel_is_preserved_across_cold_cache_edge": (
            FIX_NEGATIVE_RETURN in cold_candidate_hosts
            and FIX_SENTINEL_CONSUMPTION in cold_candidate_hosts
            and FIX_NEGATIVE_RETURN in cold_fix_hosts
            and FIX_SENTINEL_CONSUMPTION in cold_fix_hosts
        ),
        "mechanism_identifiers_are_distinct": (
            NEGATIVE_CACHE_MECHANISM != COLD_CACHE_MECHANISM
        ),
    }


def _changed_paths(repository: Path, revision: str) -> list[str]:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            revision,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise SystemExit(f"cannot inspect changed paths for {revision}")
    return [line for line in completed.stdout.splitlines() if line]


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline = _text_blob(repository, CANDIDATE_PARENT_SHA)
    candidate = _text_blob(repository, CANDIDATE_SHA)
    candidate_tests = _text_blob(repository, CANDIDATE_SHA, TEST_PATH)
    fix = _text_blob(repository, FIX_SHA)
    fix_tests = _text_blob(repository, FIX_SHA, TEST_PATH)
    cold_candidate = _text_blob(repository, COLD_CACHE_CANDIDATE_SHA)
    cold_fix = _text_blob(repository, COLD_CACHE_FIX_SHA)
    composer_lock = _git_blob(repository, CANDIDATE_SHA, COMPOSER_LOCK_PATH)

    candidate_metadata = _commit_metadata(repository, CANDIDATE_SHA)
    fix_metadata = _commit_metadata(repository, FIX_SHA)
    framework_proof = _framework_lock_proof(composer_lock)
    evaluation = _evaluate_versions(
        baseline,
        candidate,
        candidate_tests,
        fix,
        fix_tests,
    )
    behavior_matrix = _behavior_matrix()
    behavior_checks = _evaluate_behavior(behavior_matrix)
    mechanism_separation = _evaluate_mechanism_separation(
        candidate,
        fix,
        cold_candidate,
        cold_fix,
    )

    ancestry = {
        "candidate_parent_is_exact": (
            candidate_metadata["parents"] == [CANDIDATE_PARENT_SHA]
        ),
        "fix_directly_follows_candidate": (fix_metadata["parents"] == [CANDIDATE_SHA]),
        "candidate_strictly_precedes_fix": _is_ancestor(
            repository, CANDIDATE_SHA, FIX_SHA
        ),
        "negative_cache_fix_precedes_cold_cache_candidate": _is_ancestor(
            repository, FIX_SHA, COLD_CACHE_CANDIDATE_SHA
        ),
        "cold_cache_candidate_precedes_its_fix": _is_ancestor(
            repository, COLD_CACHE_CANDIDATE_SHA, COLD_CACHE_FIX_SHA
        ),
    }
    line_origins = {
        "candidate_remember_contract": _blame_line(
            repository,
            CANDIDATE_SHA,
            SOURCE_PATH,
            _line_number(candidate, REMEMBER_CALL),
            "candidate five-minute cache contract",
        ),
        "candidate_null_negative_result": _blame_line(
            repository,
            CANDIDATE_SHA,
            SOURCE_PATH,
            _line_number(candidate, CANDIDATE_NEGATIVE_RETURN),
            "candidate null negative cache value",
        ),
        "fix_empty_string_sentinel": _blame_line(
            repository,
            FIX_SHA,
            SOURCE_PATH,
            _line_number(fix, FIX_NEGATIVE_RETURN),
            "fix non-null negative cache sentinel",
        ),
        "fix_sentinel_consumption": _blame_line(
            repository,
            FIX_SHA,
            SOURCE_PATH,
            _line_number(fix, FIX_SENTINEL_CONSUMPTION),
            "fix sentinel conversion before consumption",
        ),
        "fix_negative_cache_test": _blame_line(
            repository,
            FIX_SHA,
            TEST_PATH,
            _line_number(fix_tests, NEGATIVE_CACHE_TEST),
            "fix negative-cache regression test",
        ),
        "sentinel_survives_to_cold_cache_candidate": _blame_line(
            repository,
            COLD_CACHE_CANDIDATE_SHA,
            SOURCE_PATH,
            _line_number(cold_candidate, FIX_SENTINEL_CONSUMPTION),
            "sentinel preserved into later cold-cache edge",
        ),
    }
    changed_paths = {
        "candidate": _changed_paths(repository, CANDIDATE_SHA),
        "fix": _changed_paths(repository, FIX_SHA),
    }

    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and "99.9% reduction in DB queries" in str(candidate_metadata["message"])
        and fix_metadata["explicit_claude_signal"] is True
        and "negative cache results" in str(fix_metadata["message"])
        and all(framework_proof["checks"].values())
        and all(evaluation.values())
        and all(behavior_checks.values())
        and all(mechanism_separation.values())
        and all(ancestry.values())
        and changed_paths["fix"] == [SOURCE_PATH, TEST_PATH]
        and line_origins["candidate_remember_contract"]["origin_sha"] == CANDIDATE_SHA
        and line_origins["candidate_null_negative_result"]["origin_sha"]
        == CANDIDATE_SHA
        and line_origins["fix_empty_string_sentinel"]["origin_sha"] == FIX_SHA
        and line_origins["fix_sentinel_consumption"]["origin_sha"] == FIX_SHA
        and line_origins["fix_negative_cache_test"]["origin_sha"] == FIX_SHA
        and line_origins["sentinel_survives_to_cold_cache_candidate"]["origin_sha"]
        == FIX_SHA
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_trust_hosts_negative_cache_origin_witness",
        "repository_identity": REPOSITORY_IDENTITY,
        "candidate_sha": CANDIDATE_SHA,
        "fix_sha": FIX_SHA,
        "candidate_metadata": candidate_metadata,
        "fix_metadata": fix_metadata,
        "framework_contract_proof": framework_proof,
        "ancestry": ancestry,
        "changed_paths": changed_paths,
        "evaluation": evaluation,
        "behavior_matrix": behavior_matrix,
        "behavior_checks": behavior_checks,
        "mechanism_separation": mechanism_separation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, CANDIDATE_PARENT_SHA, SOURCE_PATH),
            _blob_record(repository, CANDIDATE_SHA, SOURCE_PATH),
            _blob_record(repository, CANDIDATE_SHA, TEST_PATH),
            _blob_record(repository, CANDIDATE_SHA, COMPOSER_LOCK_PATH),
            _blob_record(repository, FIX_SHA, SOURCE_PATH),
            _blob_record(repository, FIX_SHA, TEST_PATH),
            _blob_record(repository, COLD_CACHE_CANDIDATE_SHA, SOURCE_PATH),
            _blob_record(repository, COLD_CACHE_FIX_SHA, SOURCE_PATH),
        ],
        "confirmed_edges": [
            {
                "candidate_sha": CANDIDATE_SHA,
                "fix_sha": FIX_SHA,
                "causal_role": "DIRECT_AI_INCOMPLETE_CACHE_ORIGIN",
            }
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_INCOMPLETE_CACHE_ORIGIN",
        "mechanism_group": NEGATIVE_CACHE_MECHANISM,
        "mechanism_counting": {
            "this_mechanism_group": NEGATIVE_CACHE_MECHANISM,
            "separate_later_mechanism_group": COLD_CACHE_MECHANISM,
            "shared_implementation_state": "empty-string negative sentinel",
            "duplicate_mechanism_count": 0,
        },
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": CLAIM_BOUNDARY,
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify TrustHosts negative-cache witness failed")
    print("Coolify TrustHosts negative-cache origin witness frozen")
    print(f"  candidate: {CANDIDATE_SHA}")
    print(f"  repair   : {FIX_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
