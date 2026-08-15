"""Tests for the TrustHosts negative-cache causal witness."""

from __future__ import annotations

import json

from cohort_coolify_trust_hosts_negative_cache_origin_witness import (
    CANDIDATE_HOST_FALLBACK,
    CANDIDATE_NEGATIVE_RETURN,
    CLAIM_BOUNDARY,
    COLD_CACHE_EAGER_POPULATION,
    COLD_CACHE_EARLY_RETURN,
    COLD_CACHE_READ,
    FALLBACK_TRUST_PATTERN,
    FIX_HOST_FALLBACK,
    FIX_NEGATIVE_RETURN,
    FIX_SENTINEL_CONSUMPTION,
    LARAVEL_FRAMEWORK_REFERENCE,
    LARAVEL_FRAMEWORK_VERSION,
    NEGATIVE_CACHE_HAS_ASSERTION,
    NEGATIVE_CACHE_TEST,
    NEGATIVE_CACHE_VALUE_ASSERTION,
    POSITIVE_CACHE_TEST,
    REMEMBER_CALL,
    _behavior_matrix,
    _evaluate_behavior,
    _evaluate_mechanism_separation,
    _evaluate_versions,
    _framework_lock_proof,
    _simulate_remember,
)


def _source(hosts_body: str, handle_body: str | None = None) -> str:
    handle = ""
    if handle_body is not None:
        handle = f"public function handle($request, $next) {{\n{handle_body}\n}}\n"
    return (
        "<?php\nclass TrustHosts {\n"
        f"{handle}"
        "public function hosts(): array {\n"
        f"{hosts_body}\n"
        "}\n"
        "}\n"
    )


def _version_fixtures() -> tuple[str, str, str, str, str]:
    baseline = _source("InstanceSettings::get();\n" + FALLBACK_TRUST_PATTERN)
    candidate = _source(
        "\n".join(
            (
                REMEMBER_CALL,
                CANDIDATE_HOST_FALLBACK,
                CANDIDATE_NEGATIVE_RETURN,
                "});",
                "if ($fqdnHost) { $trustedHosts[] = $fqdnHost; }",
                FALLBACK_TRUST_PATTERN,
            )
        )
    )
    fix = _source(
        "\n".join(
            (
                REMEMBER_CALL,
                FIX_HOST_FALLBACK,
                FIX_NEGATIVE_RETURN,
                "});",
                FIX_SENTINEL_CONSUMPTION,
                "if ($fqdnHost) { $trustedHosts[] = $fqdnHost; }",
                FALLBACK_TRUST_PATTERN,
            )
        )
    )
    candidate_tests = POSITIVE_CACHE_TEST
    fix_tests = "\n".join(
        (
            POSITIVE_CACHE_TEST,
            NEGATIVE_CACHE_TEST,
            NEGATIVE_CACHE_HAS_ASSERTION,
            NEGATIVE_CACHE_VALUE_ASSERTION,
        )
    )
    return baseline, candidate, candidate_tests, fix, fix_tests


def test_versions_require_null_negative_path_and_exact_sentinel_fix() -> None:
    assert all(_evaluate_versions(*_version_fixtures()).values())


def test_versions_fail_if_candidate_already_uses_sentinel() -> None:
    baseline, _candidate, tests, fix, fix_tests = _version_fixtures()

    result = _evaluate_versions(baseline, fix, tests, fix, fix_tests)

    assert result["candidate_negative_paths_return_null"] is False


def test_laravel_null_miss_contract_reexecutes_only_null_callback() -> None:
    null_result = _simulate_remember(None)
    sentinel_result = _simulate_remember("")
    positive_result = _simulate_remember("coolify.example.com")

    assert null_result["callback_count"] == 3
    assert null_result["framework_has_returns_true"] is False
    assert sentinel_result["callback_count"] == 1
    assert sentinel_result["framework_has_returns_true"] is True
    assert positive_result["callback_count"] == 1


def test_behavior_matrix_preserves_output_while_reducing_negative_queries() -> None:
    matrix = _behavior_matrix()

    assert all(_evaluate_behavior(matrix).values())
    assert matrix["candidate_negative_null"]["consumer_value"] is None
    assert matrix["fix_negative_empty_string_sentinel"]["consumer_value"] is None


def test_framework_lock_proof_requires_exact_laravel_reference() -> None:
    lock = {
        "packages": [
            {
                "name": "laravel/framework",
                "version": LARAVEL_FRAMEWORK_VERSION,
                "source": {
                    "url": "https://github.com/laravel/framework.git",
                    "reference": LARAVEL_FRAMEWORK_REFERENCE,
                },
            }
        ]
    }

    proof = _framework_lock_proof(json.dumps(lock).encode())

    assert all(proof["checks"].values())
    assert proof["cache_repository_source"]["contract"] == {
        "has_treats_null_as_absent": True,
        "remember_returns_cached_value_only_when_non_null": True,
        "remember_executes_callback_when_cached_value_is_null": True,
    }


def test_mechanism_separation_requires_distinct_handle_repair() -> None:
    _baseline, candidate, _tests, fix, _fix_tests = _version_fixtures()
    cold_candidate = _source(
        "\n".join((FIX_NEGATIVE_RETURN, FIX_SENTINEL_CONSUMPTION)),
        "\n".join(
            (
                COLD_CACHE_READ,
                COLD_CACHE_EARLY_RETURN,
                "return $next($request);",
                "}",
            )
        ),
    )
    cold_fix = _source(
        "\n".join((FIX_NEGATIVE_RETURN, FIX_SENTINEL_CONSUMPTION)),
        "\n".join(
            (
                COLD_CACHE_EAGER_POPULATION,
                COLD_CACHE_READ,
                COLD_CACHE_EARLY_RETURN,
                "return $next($request);",
                "}",
            )
        ),
    )

    assert all(
        _evaluate_mechanism_separation(
            candidate,
            fix,
            cold_candidate,
            cold_fix,
        ).values()
    )


def test_claim_boundary_excludes_regression_security_and_duplicate_claims() -> None:
    assert "not an increase over the parent's" in CLAIM_BOUNDARY
    assert "not a host-validation or account-takeover flaw" in CLAIM_BOUNDARY
    assert "not the later cold-cache validation bypass" in CLAIM_BOUNDARY
    assert "does not merge the two mechanism counts" in CLAIM_BOUNDARY
