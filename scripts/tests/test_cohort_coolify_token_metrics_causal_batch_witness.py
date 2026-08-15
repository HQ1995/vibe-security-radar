"""Tests for the deterministic Coolify token/metrics causal witness."""

from __future__ import annotations

import pytest

import cohort_coolify_token_metrics_causal_batch_witness as witness


def test_resolve_census_row_requires_unique_full_sha_and_subject() -> None:
    full_sha = "a" * 40
    rows = [{"sha": full_sha, "subject": "expected"}]

    assert (
        witness._resolve_census_row(
            rows,
            "aaaa",
            expected_subject="expected",
        )["sha"]
        == full_sha
    )

    with pytest.raises(ValueError, match="resolved to 0 rows"):
        witness._resolve_census_row(rows, "bbbb", expected_subject="expected")

    with pytest.raises(ValueError, match="full SHA"):
        witness._resolve_census_row(
            [{"sha": "aaaa", "subject": "expected"}],
            "aaaa",
            expected_subject="expected",
        )


def test_token_error_semantics_distinguish_helper_and_endpoint_contracts() -> None:
    result = witness._token_error_semantics()

    assert result["passed"] is True
    assert all(result["checks"].values())
    assert result["helper_error"] == result["fixed_endpoint_error"]
    assert result["candidate_endpoint_error"] != result["helper_error"]
    assert result["candidate_endpoint_error"] != result["parent_endpoint_error"]


def test_cpu_metrics_semantics_are_scoped_to_get_cpu_metrics() -> None:
    parent_method = """
    private function getCpuMetrics()
    {
        return collect($cpu)->map(function ($metric) {
            return $metric;
        });
    }
    """
    candidate_method = """
    private function getCpuMetrics()
    {
        $metrics = collect($cpu)->map(function ($metric) {
            return $metric;
        })->toArray();
        return $metrics;
    }
    """
    fixed_method = candidate_method.replace(
        "return $metrics;", "return collect($metrics);"
    )

    result = witness._cpu_metrics_contract_semantics(
        parent_method,
        candidate_method,
        fixed_method,
    )

    assert result["passed"] is True
    assert all(result["checks"].values())
    assert result["scope"] == "Server::getCpuMetrics only"

    unrepaired = witness._cpu_metrics_contract_semantics(
        parent_method,
        candidate_method,
        candidate_method,
    )
    assert unrepaired["checks"]["fix_restores_collection_wrapper"] is False
    assert unrepaired["passed"] is False


def test_independence_checks_require_distinct_edges() -> None:
    cases = [
        {
            "candidate_sha": "a" * 40,
            "fix_sha": "b" * 40,
            "mechanism_group": witness.TOKEN_MECHANISM,
            "failure_surface": "cloud_token_validation_response_contract",
        },
        {
            "candidate_sha": "c" * 40,
            "fix_sha": "d" * 40,
            "mechanism_group": witness.METRICS_MECHANISM,
            "failure_surface": "server_cpu_metrics_return_type_contract",
        },
    ]

    assert all(witness._independence_checks(cases).values())

    cases[1]["mechanism_group"] = witness.TOKEN_MECHANISM
    checks = witness._independence_checks(cases)
    assert checks["two_distinct_mechanism_groups"] is False


def test_candidate_ai_checks_require_frozen_scan_and_census_provenance() -> None:
    candidate_sha = "a" * 40
    ai_row = {
        "sha": candidate_sha,
        "source_modules": ["coauthor_trailer"],
        "tools": ["claude_code"],
        "message": (
            "Generated with [Claude Code]\n\n"
            "Co-Authored-By: Claude <noreply@anthropic.com>"
        ),
    }
    census_row = {"sha": candidate_sha, "observed_ai_commit": True}

    assert all(witness._candidate_ai_checks(candidate_sha, ai_row, census_row).values())

    census_row["observed_ai_commit"] = False
    checks = witness._candidate_ai_checks(candidate_sha, ai_row, census_row)
    assert checks["candidate_is_observed_ai_in_census"] is False

    census_row["observed_ai_commit"] = True
    ai_row["tools"] = []
    checks = witness._candidate_ai_checks(candidate_sha, ai_row, census_row)
    assert checks["candidate_tool_is_claude_code"] is False
