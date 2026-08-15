#!/usr/bin/env python3
"""Freeze two deterministic Coolify direct-AI repair witnesses."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _is_ancestor,
    _php_method_region,
)


TOKEN_CANDIDATE_PREFIX = "596b1cb7"
TOKEN_FIX_SHA = "56394ba093ca82d99f9847edfbbaafe55d34a140"
TOKEN_SOURCE_PATH = "app/Http/Controllers/Api/CloudProviderTokensController.php"
TOKEN_TEST_PATH = "tests/Feature/CloudProviderTokenApiTest.php"
TOKEN_MECHANISM = "cloud_token_validation_error_contract_discard"

METRICS_CANDIDATE_PREFIX = "f199b6bf"
METRICS_FIX_SHA = "0e9dbc362574d24316642adfc0364512902b2674"
METRICS_SOURCE_PATH = "app/Models/Server.php"
METRICS_TEST_PATH = "tests/Unit/ServerMetricsDownsamplingTest.php"
METRICS_MECHANISM = "server_cpu_metrics_collection_contract_regression"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--census-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_jsonl(source_path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with source_path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(
                        f"{source_path}:{line_number} is not a JSON object"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load {source_path}: {exc}") from exc
    return rows


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(source_path: Path) -> str:
    return _sha256_bytes(source_path.read_bytes())


def _git_text(repository: Path, arguments: Sequence[str]) -> str:
    value = _git(repository, list(arguments), text=True)
    assert isinstance(value, str)
    return value


def _git_bytes(repository: Path, arguments: Sequence[str]) -> bytes:
    value = _git(repository, list(arguments))
    assert isinstance(value, bytes)
    return value


def _first_parent(repository: Path, revision: str) -> str:
    return _git_text(repository, ("rev-parse", f"{revision}^1")).strip()


def _path_exists(repository: Path, revision: str, source_path: str) -> bool:
    return bool(
        _git_text(
            repository,
            ("ls-tree", "--name-only", revision, "--", source_path),
        ).strip()
    )


def _blob(repository: Path, revision: str, source_path: str) -> str:
    if not _path_exists(repository, revision, source_path):
        raise ValueError(f"missing Git path: {revision}:{source_path}")
    return _git_text(repository, ("show", f"{revision}:{source_path}"))


def _blob_record(
    repository: Path, revision: str, source_path: str
) -> dict[str, object]:
    content = _git_bytes(repository, ("show", f"{revision}:{source_path}"))
    return {
        "revision": revision,
        "path": source_path,
        "git_blob_oid": _git_text(
            repository, ("rev-parse", f"{revision}:{source_path}")
        ).strip(),
        "byte_count": len(content),
        "sha256": _sha256_bytes(content),
    }


def _diff(
    repository: Path,
    before: str,
    after: str,
    source_paths: Sequence[str],
) -> bytes:
    return _git_bytes(
        repository,
        (
            "diff",
            "--full-index",
            "--no-color",
            "--no-ext-diff",
            "--no-renames",
            before,
            after,
            "--",
            *source_paths,
        ),
    )


def _diff_record(
    repository: Path,
    before: str,
    after: str,
    source_paths: Sequence[str],
) -> dict[str, object]:
    value = _diff(repository, before, after, source_paths)
    return {
        "before_revision": before,
        "after_revision": after,
        "paths": list(source_paths),
        "byte_count": len(value),
        "sha256": _sha256_bytes(value),
    }


def _resolve_census_row(
    rows: Sequence[Mapping[str, object]],
    prefix: str,
    *,
    expected_subject: str,
) -> Mapping[str, object]:
    matches = [
        row
        for row in rows
        if isinstance(row.get("sha"), str)
        and str(row["sha"]).startswith(prefix)
        and row.get("subject") == expected_subject
    ]
    if len(matches) != 1:
        raise ValueError(
            f"census prefix {prefix} with subject {expected_subject!r} "
            f"resolved to {len(matches)} rows"
        )
    sha = str(matches[0]["sha"])
    if len(sha) != 40:
        raise ValueError(f"census row did not provide a full SHA: {sha}")
    return matches[0]


def _single_sha_row(
    rows: Sequence[Mapping[str, object]], sha: str
) -> Mapping[str, object]:
    matches = [row for row in rows if row.get("sha") == sha]
    if len(matches) != 1:
        raise ValueError(f"{sha} resolved to {len(matches)} rows")
    return matches[0]


def _line_origin(
    repository: Path,
    revision: str,
    source_path: str,
    marker: str,
    *,
    occurrence: int = 1,
) -> dict[str, object]:
    source = _blob(repository, revision, source_path)
    matches = [
        index + 1 for index, line in enumerate(source.splitlines()) if marker in line
    ]
    if occurrence < 1 or len(matches) < occurrence:
        raise ValueError(
            f"expected occurrence {occurrence} of {marker!r} at "
            f"{revision}:{source_path}; found {matches}"
        )
    line_number = matches[occurrence - 1]
    value = _git_text(
        repository,
        (
            "blame",
            "--line-porcelain",
            "-L",
            f"{line_number},{line_number}",
            revision,
            "--",
            source_path,
        ),
    )
    return {
        "revision": revision,
        "path": source_path,
        "line": line_number,
        "marker": marker,
        "origin_sha": value.split(None, 1)[0].lstrip("^"),
    }


def _candidate_ai_checks(
    candidate_sha: str,
    ai_row: Mapping[str, object],
    census_row: Mapping[str, object],
) -> dict[str, bool]:
    source_modules = ai_row.get("source_modules")
    tools = ai_row.get("tools")
    message = str(ai_row.get("message") or "")
    return {
        "candidate_is_in_frozen_ai_scan": ai_row.get("sha") == candidate_sha,
        "candidate_is_observed_ai_in_census": (
            census_row.get("sha") == candidate_sha
            and census_row.get("observed_ai_commit") is True
        ),
        "candidate_has_coauthor_trailer_source": (
            isinstance(source_modules, list) and "coauthor_trailer" in source_modules
        ),
        "candidate_tool_is_claude_code": (
            isinstance(tools, list) and "claude_code" in tools
        ),
        "candidate_message_has_claude_provenance": (
            "Generated with" in message
            and "Claude Code" in message
            and "Co-Authored-By: Claude" in message
        ),
    }


def _token_error_semantics() -> dict[str, object]:
    helper_error = "Invalid hetzner token. Please check your API token."
    parent_endpoint = "Token is invalid."
    candidate_endpoint = "Failed to validate token."
    fixed_endpoint = helper_error
    checks = {
        "helper_error_is_more_specific_than_parent_contract": (
            helper_error != parent_endpoint and "hetzner" in helper_error
        ),
        "candidate_discards_helper_error": candidate_endpoint != helper_error,
        "candidate_also_breaks_parent_test_contract": (
            candidate_endpoint != parent_endpoint
        ),
        "fix_returns_helper_error_exactly": fixed_endpoint == helper_error,
    }
    return {
        "helper_error": helper_error,
        "parent_endpoint_error": parent_endpoint,
        "candidate_endpoint_error": candidate_endpoint,
        "fixed_endpoint_error": fixed_endpoint,
        "checks": checks,
        "passed": all(checks.values()),
    }


def _cpu_metrics_contract_semantics(
    parent_method: str,
    candidate_method: str,
    fixed_method: str,
) -> dict[str, object]:
    checks = {
        "parent_cpu_getter_returns_collection": (
            "return collect($cpu)->map(function ($metric)" in parent_method
        ),
        "candidate_materializes_internal_array": (")->toArray();" in candidate_method),
        "candidate_cpu_getter_returns_bare_array": (
            "return $metrics;" in candidate_method
            and "return collect($metrics);" not in candidate_method
        ),
        "fix_restores_collection_wrapper": (
            "return collect($metrics);" in fixed_method
        ),
    }
    return {
        "scope": "Server::getCpuMetrics only",
        "parent_contract": "Illuminate\\Support\\Collection",
        "candidate_contract": "array",
        "fixed_contract": "Illuminate\\Support\\Collection",
        "checks": checks,
        "passed": all(checks.values()),
    }


def _token_case(
    repository: Path,
    *,
    candidate_sha: str,
    candidate_census: Mapping[str, object],
    fix_census: Mapping[str, object],
    ai_row: Mapping[str, object],
) -> dict[str, object]:
    candidate_parent = _first_parent(repository, candidate_sha)
    fix_parent = _first_parent(repository, TOKEN_FIX_SHA)
    parent_source = _blob(repository, candidate_parent, TOKEN_SOURCE_PATH)
    candidate_source = _blob(repository, candidate_sha, TOKEN_SOURCE_PATH)
    fixed_source = _blob(repository, TOKEN_FIX_SHA, TOKEN_SOURCE_PATH)
    parent_test = _blob(repository, candidate_parent, TOKEN_TEST_PATH)
    candidate_test = _blob(repository, candidate_sha, TOKEN_TEST_PATH)
    fixed_test = _blob(repository, TOKEN_FIX_SHA, TOKEN_TEST_PATH)
    candidate_patch = _diff(
        repository,
        candidate_parent,
        candidate_sha,
        (TOKEN_SOURCE_PATH, TOKEN_TEST_PATH),
    ).decode("utf-8", errors="strict")
    fix_patch = _diff(
        repository,
        fix_parent,
        TOKEN_FIX_SHA,
        (TOKEN_SOURCE_PATH, TOKEN_TEST_PATH),
    ).decode("utf-8", errors="strict")
    candidate_metadata = _commit_metadata(repository, candidate_sha)
    fix_metadata = _commit_metadata(repository, TOKEN_FIX_SHA)
    ai_checks = _candidate_ai_checks(candidate_sha, ai_row, candidate_census)
    semantics = _token_error_semantics()
    parent_expectation = (
        "$response->assertJson(['valid' => false, 'message' => 'Token is invalid.']);"
    )
    fixed_expectation = (
        "$response->assertJson(['valid' => false, 'message' => "
        "'Invalid hetzner token. Please check your API token.']);"
    )
    helper_error = (
        "return ['valid' => false, 'error' => \"Invalid {$provider} token. "
        'Please check your API token."];'
    )
    candidate_generic = (
        "'message' => $validation['valid'] ? 'Token is valid.' : "
        "'Failed to validate token.',"
    )
    fixed_specific = (
        "'message' => $validation['valid'] ? 'Token is valid.' : $validation['error'],"
    )
    line_origins = {
        "candidate_helper_error": _line_origin(
            repository, candidate_sha, TOKEN_SOURCE_PATH, helper_error
        ),
        "candidate_generic_endpoint": _line_origin(
            repository, candidate_sha, TOKEN_SOURCE_PATH, candidate_generic
        ),
        "fixed_specific_endpoint": _line_origin(
            repository, TOKEN_FIX_SHA, TOKEN_SOURCE_PATH, fixed_specific
        ),
    }
    checks = {
        **ai_checks,
        "census_parent_matches_git_parent": (
            candidate_census.get("parents") == [candidate_parent]
            and candidate_metadata.get("parents") == [candidate_parent]
        ),
        "fix_is_direct_child_of_candidate": (
            fix_parent == candidate_sha and fix_census.get("parents") == [candidate_sha]
        ),
        "candidate_is_ancestor_of_fix": _is_ancestor(
            repository, candidate_sha, TOKEN_FIX_SHA
        ),
        "candidate_parent_has_no_validation_helper": (
            "private function validateProviderToken" not in parent_source
        ),
        "candidate_introduces_specific_helper_contract": (
            helper_error not in parent_source
            and helper_error in candidate_patch
            and helper_error in candidate_source
        ),
        "candidate_introduces_generic_endpoint_discard": (
            candidate_generic not in parent_source
            and candidate_generic in candidate_patch
            and candidate_generic in candidate_source
        ),
        "candidate_preserves_old_test_expectation_but_breaks_it": (
            parent_expectation in parent_test
            and parent_expectation in candidate_test
            and "'Failed to validate token.'" in candidate_source
        ),
        "fault_persists_to_fix_parent": (
            fix_parent == candidate_sha and candidate_generic in candidate_source
        ),
        "fix_returns_helper_error_and_updates_test": (
            fixed_specific not in candidate_source
            and fixed_specific in fix_patch
            and fixed_specific in fixed_source
            and candidate_generic not in fixed_source
            and fixed_expectation not in candidate_test
            and fixed_expectation in fix_patch
            and fixed_expectation in fixed_test
        ),
        "fix_message_names_specific_error_repair": (
            "Return the specific error from validateProviderToken()"
            in str(fix_metadata.get("message") or "")
        ),
        "candidate_and_fix_line_origins_are_exact": (
            line_origins["candidate_helper_error"]["origin_sha"] == candidate_sha
            and line_origins["candidate_generic_endpoint"]["origin_sha"]
            == candidate_sha
            and line_origins["fixed_specific_endpoint"]["origin_sha"] == TOKEN_FIX_SHA
        ),
        "semantic_contract_witness_passes": semantics["passed"] is True,
    }
    return {
        "key": "cloud_token_validation_error_contract",
        "candidate_sha": candidate_sha,
        "fix_sha": TOKEN_FIX_SHA,
        "candidate_parent_sha": candidate_parent,
        "fix_parent_sha": fix_parent,
        "adjudication": "CONFIRMED_DIRECT_AI_TOKEN_ERROR_CONTRACT_DISCARD",
        "causal_role": "DIRECT_ORIGIN",
        "mechanism_group": TOKEN_MECHANISM,
        "failure_surface": "cloud_token_validation_response_contract",
        "claim": (
            "the AI refactor introduced a provider-validation helper with a specific "
            "error contract but discarded that error at the validation endpoint, "
            "while leaving the old endpoint test expectation unchanged; its direct "
            "child returns the helper error and updates the endpoint contract test"
        ),
        "checks": checks,
        "semantic_witness": semantics,
        "line_origins": line_origins,
        "state_records": {
            "candidate_parent_source": _blob_record(
                repository, candidate_parent, TOKEN_SOURCE_PATH
            ),
            "candidate_source": _blob_record(
                repository, candidate_sha, TOKEN_SOURCE_PATH
            ),
            "fix_parent_source": _blob_record(
                repository, fix_parent, TOKEN_SOURCE_PATH
            ),
            "fixed_source": _blob_record(repository, TOKEN_FIX_SHA, TOKEN_SOURCE_PATH),
            "candidate_test": _blob_record(repository, candidate_sha, TOKEN_TEST_PATH),
            "fixed_test": _blob_record(repository, TOKEN_FIX_SHA, TOKEN_TEST_PATH),
            "candidate_delta": _diff_record(
                repository,
                candidate_parent,
                candidate_sha,
                (TOKEN_SOURCE_PATH, TOKEN_TEST_PATH),
            ),
            "fix_delta": _diff_record(
                repository,
                fix_parent,
                TOKEN_FIX_SHA,
                (TOKEN_SOURCE_PATH, TOKEN_TEST_PATH),
            ),
        },
        "passed": all(checks.values()),
    }


def _metrics_case(
    repository: Path,
    *,
    candidate_sha: str,
    candidate_census: Mapping[str, object],
    fix_census: Mapping[str, object],
    ai_row: Mapping[str, object],
) -> dict[str, object]:
    candidate_parent = _first_parent(repository, candidate_sha)
    fix_parent = _first_parent(repository, METRICS_FIX_SHA)
    parent_source = _blob(repository, candidate_parent, METRICS_SOURCE_PATH)
    candidate_source = _blob(repository, candidate_sha, METRICS_SOURCE_PATH)
    fixed_source = _blob(repository, METRICS_FIX_SHA, METRICS_SOURCE_PATH)
    candidate_test = _blob(repository, candidate_sha, METRICS_TEST_PATH)
    fixed_test = _blob(repository, METRICS_FIX_SHA, METRICS_TEST_PATH)
    parent_method = _php_method_region(parent_source, "getCpuMetrics")
    candidate_method = _php_method_region(candidate_source, "getCpuMetrics")
    fixed_method = _php_method_region(fixed_source, "getCpuMetrics")
    candidate_patch = _diff(
        repository,
        candidate_parent,
        candidate_sha,
        (METRICS_SOURCE_PATH, METRICS_TEST_PATH),
    ).decode("utf-8", errors="strict")
    fix_patch = _diff(
        repository,
        fix_parent,
        METRICS_FIX_SHA,
        (METRICS_SOURCE_PATH, METRICS_TEST_PATH),
    ).decode("utf-8", errors="strict")
    candidate_metadata = _commit_metadata(repository, candidate_sha)
    fix_metadata = _commit_metadata(repository, METRICS_FIX_SHA)
    ai_checks = _candidate_ai_checks(candidate_sha, ai_row, candidate_census)
    semantics = _cpu_metrics_contract_semantics(
        parent_method, candidate_method, fixed_method
    )
    line_origins = {
        "candidate_cpu_array_return": _line_origin(
            repository,
            candidate_sha,
            METRICS_SOURCE_PATH,
            "return $metrics;",
            occurrence=1,
        ),
        "fixed_cpu_collection_return": _line_origin(
            repository,
            METRICS_FIX_SHA,
            METRICS_SOURCE_PATH,
            "return collect($metrics);",
            occurrence=1,
        ),
    }
    checks = {
        **ai_checks,
        "census_parent_matches_git_parent": (
            candidate_census.get("parents") == [candidate_parent]
            and candidate_metadata.get("parents") == [candidate_parent]
        ),
        "fix_is_direct_child_of_candidate": (
            fix_parent == candidate_sha and fix_census.get("parents") == [candidate_sha]
        ),
        "candidate_is_ancestor_of_fix": _is_ancestor(
            repository, candidate_sha, METRICS_FIX_SHA
        ),
        "candidate_parent_cpu_contract_is_collection": (
            semantics["checks"]["parent_cpu_getter_returns_collection"] is True
        ),
        "candidate_introduces_cpu_array_contract": (
            "return collect($cpu)->map(function ($metric)" in candidate_patch
            and "return $metrics;" in candidate_patch
            and semantics["checks"]["candidate_cpu_getter_returns_bare_array"] is True
        ),
        "fault_persists_to_fix_parent": (
            fix_parent == candidate_sha
            and "return $metrics;" in candidate_method
            and "return collect($metrics);" not in candidate_method
        ),
        "fix_restores_cpu_collection_contract": (
            "return collect($metrics);" in fix_patch
            and semantics["checks"]["fix_restores_collection_wrapper"] is True
        ),
        "candidate_adds_mirrored_lttb_test": (
            not _path_exists(repository, candidate_parent, METRICS_TEST_PATH)
            and "function downsampleLTTB(array $data, int $threshold): array"
            in candidate_test
            and "This mirrors the implementation" in candidate_test
        ),
        "fix_tests_actual_lttb_method_deterministically": (
            "use App\\Models\\Server;" in fixed_test
            and "new ReflectionClass($server)" in fixed_test
            and "$reflection->getMethod('downsampleLTTB')" in fixed_test
            and "mt_srand(42);" in fixed_test
            and "function downsampleLTTB(" not in fixed_test
        ),
        "fix_message_names_collection_compatibility": (
            "Wrap return values in collect() to maintain Collection compatibility"
            in str(fix_metadata.get("message") or "")
        ),
        "candidate_and_fix_line_origins_are_exact": (
            line_origins["candidate_cpu_array_return"]["origin_sha"] == candidate_sha
            and line_origins["fixed_cpu_collection_return"]["origin_sha"]
            == METRICS_FIX_SHA
        ),
        "semantic_contract_witness_passes": semantics["passed"] is True,
    }
    return {
        "key": "server_cpu_metrics_collection_contract",
        "candidate_sha": candidate_sha,
        "fix_sha": METRICS_FIX_SHA,
        "candidate_parent_sha": candidate_parent,
        "fix_parent_sha": fix_parent,
        "adjudication": "CONFIRMED_DIRECT_AI_METRICS_COLLECTION_CONTRACT_REGRESSION",
        "causal_role": "DIRECT_ORIGIN",
        "mechanism_group": METRICS_MECHANISM,
        "failure_surface": "server_cpu_metrics_return_type_contract",
        "claim": (
            "the AI LTTB implementation changed Server::getCpuMetrics from its "
            "pre-existing Collection return contract to a bare array; its direct "
            "child restores the Collection wrapper and replaces a mirrored test "
            "implementation with deterministic reflection calls to the real LTTB method"
        ),
        "checks": checks,
        "semantic_witness": semantics,
        "test_boundary": (
            "the repaired tests execute the real private LTTB algorithm but do not "
            "directly invoke getCpuMetrics; return-contract closure is proved by the "
            "parent/candidate/fix source delta and the explicit repair message"
        ),
        "line_origins": line_origins,
        "state_records": {
            "candidate_parent_source": _blob_record(
                repository, candidate_parent, METRICS_SOURCE_PATH
            ),
            "candidate_source": _blob_record(
                repository, candidate_sha, METRICS_SOURCE_PATH
            ),
            "fix_parent_source": _blob_record(
                repository, fix_parent, METRICS_SOURCE_PATH
            ),
            "fixed_source": _blob_record(
                repository, METRICS_FIX_SHA, METRICS_SOURCE_PATH
            ),
            "candidate_test": _blob_record(
                repository, candidate_sha, METRICS_TEST_PATH
            ),
            "fixed_test": _blob_record(repository, METRICS_FIX_SHA, METRICS_TEST_PATH),
            "candidate_delta": _diff_record(
                repository,
                candidate_parent,
                candidate_sha,
                (METRICS_SOURCE_PATH, METRICS_TEST_PATH),
            ),
            "fix_delta": _diff_record(
                repository,
                fix_parent,
                METRICS_FIX_SHA,
                (METRICS_SOURCE_PATH, METRICS_TEST_PATH),
            ),
        },
        "passed": all(checks.values()),
    }


def _independence_checks(
    case_results: Sequence[Mapping[str, object]],
) -> dict[str, bool]:
    candidate_shas = [str(row.get("candidate_sha") or "") for row in case_results]
    fix_shas = [str(row.get("fix_sha") or "") for row in case_results]
    mechanisms = [str(row.get("mechanism_group") or "") for row in case_results]
    surfaces = [str(row.get("failure_surface") or "") for row in case_results]
    return {
        "exactly_two_cases": len(case_results) == 2,
        "two_distinct_ai_candidates": (
            len(set(candidate_shas)) == len(candidate_shas) == 2
        ),
        "two_distinct_fix_commits": len(set(fix_shas)) == len(fix_shas) == 2,
        "two_distinct_mechanism_groups": (len(set(mechanisms)) == len(mechanisms) == 2),
        "two_distinct_failure_surfaces": (len(set(surfaces)) == len(surfaces) == 2),
        "token_claim_is_endpoint_error_contract_only": any(
            row.get("mechanism_group") == TOKEN_MECHANISM
            and row.get("failure_surface") == "cloud_token_validation_response_contract"
            for row in case_results
        ),
        "metrics_claim_is_cpu_getter_only": any(
            row.get("mechanism_group") == METRICS_MECHANISM
            and row.get("failure_surface") == "server_cpu_metrics_return_type_contract"
            for row in case_results
        ),
    }


def build_witness(
    repository: Path,
    *,
    ai_rows: Sequence[Mapping[str, object]],
    census_rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    token_candidate_census = _resolve_census_row(
        census_rows,
        TOKEN_CANDIDATE_PREFIX,
        expected_subject="refactor: extract token validation into reusable method",
    )
    metrics_candidate_census = _resolve_census_row(
        census_rows,
        METRICS_CANDIDATE_PREFIX,
        expected_subject=(
            "fix(metrics): prevent page freeze with 30-day server metrics interval "
            "using LTTB downsampling"
        ),
    )
    token_candidate_sha = str(token_candidate_census["sha"])
    metrics_candidate_sha = str(metrics_candidate_census["sha"])
    token_fix_census = _single_sha_row(census_rows, TOKEN_FIX_SHA)
    metrics_fix_census = _single_sha_row(census_rows, METRICS_FIX_SHA)
    case_results = [
        _token_case(
            repository,
            candidate_sha=token_candidate_sha,
            candidate_census=token_candidate_census,
            fix_census=token_fix_census,
            ai_row=_single_sha_row(ai_rows, token_candidate_sha),
        ),
        _metrics_case(
            repository,
            candidate_sha=metrics_candidate_sha,
            candidate_census=metrics_candidate_census,
            fix_census=metrics_fix_census,
            ai_row=_single_sha_row(ai_rows, metrics_candidate_sha),
        ),
    ]
    independence = _independence_checks(case_results)
    confirmed_cases = [row for row in case_results if row.get("passed") is True]
    witness_passed = all(row.get("passed") is True for row in case_results) and all(
        independence.values()
    )
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_token_metrics_causal_batch_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_resolution": {
            TOKEN_CANDIDATE_PREFIX: token_candidate_sha,
            METRICS_CANDIDATE_PREFIX: metrics_candidate_sha,
        },
        "candidates": [
            _commit_metadata(repository, token_candidate_sha),
            _commit_metadata(repository, metrics_candidate_sha),
        ],
        "repair_commits": [
            _commit_metadata(repository, TOKEN_FIX_SHA),
            _commit_metadata(repository, METRICS_FIX_SHA),
        ],
        "confirmed_edges": [
            {
                "candidate_sha": row["candidate_sha"],
                "fix_sha": row["fix_sha"],
                "adjudication": row["adjudication"],
                "causal_role": row["causal_role"],
                "mechanism_group": row["mechanism_group"],
            }
            for row in confirmed_cases
        ],
        "case_results": case_results,
        "independence_checks": independence,
        "summary": {
            "confirmed_edge_count": len(confirmed_cases),
            "unique_candidate_count": len(
                {str(row["candidate_sha"]) for row in case_results}
            ),
            "mechanism_group_count": len(
                {str(row["mechanism_group"]) for row in case_results}
            ),
            "failed_case_count": sum(
                row.get("passed") is not True for row in case_results
            ),
        },
        "witness_passed": witness_passed,
        "claim_boundary": (
            "The token edge proves an AI-created helper/endpoint contract mismatch "
            "and its direct repair; it does not assert that a provider-specific error "
            "was externally visible before the candidate. The metrics edge proves "
            "only the Server::getCpuMetrics Collection-to-array contract change and "
            "direct restoration; getMemoryMetrics is outside that origin claim. Its "
            "tests execute the real LTTB implementation but do not directly test the "
            "getter return wrapper. Both are causal repair edges, not security "
            "vulnerabilities, field incidents, or unique advisory increments."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    ai_path = args.ai_scan_dir.resolve() / "commits.jsonl"
    census_path = args.census_dir.resolve() / "review_schedule.jsonl"
    try:
        payload = build_witness(
            repository,
            ai_rows=_load_jsonl(ai_path),
            census_rows=_load_jsonl(census_path),
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    payload["source_artifacts"] = {
        "ai_commits": {"path": str(ai_path), "sha256": _sha256_file(ai_path)},
        "repair_census": {
            "path": str(census_path),
            "sha256": _sha256_file(census_path),
        },
    }
    if payload["witness_passed"] is not True:
        failed = [
            str(row["key"])
            for row in payload["case_results"]
            if row.get("passed") is not True
        ]
        raise SystemExit(f"token/metrics causal witness failed: {failed}")

    output_path = args.output.resolve()
    _atomic_json(output_path, payload)
    print("Coolify token/metrics causal batch witness frozen")
    print(f"  confirmed edges  : {payload['summary']['confirmed_edge_count']}")
    print(f"  unique candidates: {payload['summary']['unique_candidate_count']}")
    print(f"  mechanisms       : {payload['summary']['mechanism_group_count']}")
    print(f"  output SHA256     : {_sha256_file(output_path)}")
    print(f"  output            : {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
