#!/usr/bin/env python3
"""Freeze the Coolify AI Sentinel restart activation causal witness."""

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
from cohort_coolify_sentinel_command_injection_witness import _blame_line


BASELINE_SHA = "23c1184e86c44f10b32f86666a373414615771b9"
AI_ACTIVATION_SHA = "e04b9cd07c11b79d4fcd62d8dca441d8571e4086"
SECURITY_REPAIR_SHA = "096d4369e59b3db7ace2db3ca42588c41b9b6019"

SETTING_PATH = "app/Models/ServerSetting.php"
SERVER_PATH = "app/Models/Server.php"
UI_PATH = "app/Livewire/Server/Show.php"
START_PATH = "app/Actions/Server/StartSentinel.php"
ACTIVATION_TEST_PATH = "tests/Feature/ServerSettingSentinelRestartTest.php"
REPAIR_TEST_PATH = "tests/Feature/SentinelTokenValidationTest.php"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_record(
    repository: Path, revision: str, source_path: str
) -> dict[str, str]:
    blob = _git_blob(repository, revision, source_path)
    return {
        "revision": revision,
        "path": source_path,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _line_number(source: str, marker: str, occurrence: int = 1) -> int:
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


def _evaluate_setting_trigger(source: str) -> dict[str, bool]:
    return {
        "uses_post_update_is_dirty_for_token": (
            "$settings->isDirty('sentinel_token')" in source
        ),
        "uses_post_update_was_changed_for_token": (
            "$settings->wasChanged('sentinel_token')" in source
        ),
        "changed_token_dispatches_restart": (
            "$settings->server->restartSentinel();" in source
        ),
    }


def _evaluate_ui_write(source: str) -> dict[str, bool]:
    sync_data = _php_method_region(source, "syncData")
    return {
        "token_is_public_livewire_state": "public string $sentinelToken;" in source,
        "token_validation_is_required_only": (
            "'sentinelToken' => 'required'" in source
        ),
        "validated_state_is_written_to_setting": all(
            marker in sync_data
            for marker in (
                "$this->validate();",
                "$this->server->settings->sentinel_token = $this->sentinelToken;",
                "$this->server->settings->save();",
            )
        ),
    }


def _evaluate_restart_dispatch(source: str) -> dict[str, bool]:
    restart = _php_method_region(source, "restartSentinel")
    return {
        "restart_dispatches_start_sentinel": (
            "StartSentinel::dispatch($this, true" in restart
        ),
        "restart_can_run_start_sentinel_synchronously": (
            "StartSentinel::run($this, true" in restart
        ),
    }


def _evaluate_start_sink(source: str) -> dict[str, bool]:
    handle = _php_method_region(source, "handle")
    return {
        "reads_persisted_token": (
            "$token = data_get($server, 'settings.sentinel_token');" in handle
        ),
        "places_token_in_environment": "'TOKEN' => $token" in handle,
        "builds_double_quoted_environment_without_shell_escaping": (
            "$dockerEnvironments = '-e \"'.implode('\" -e \"'" in handle
            and "escapeshellarg" not in handle
        ),
        "executes_composed_docker_command": all(
            marker in handle
            for marker in ("$dockerCommand", "instant_remote_process(")
        ),
        "validates_token_before_sink": (
            "ServerSetting::isValidSentinelToken($token)" in handle
        ),
        "shell_quotes_environment": "escapeshellarg(\"$key=$value\")" in handle,
    }


def _evaluate_activation_test(source: str) -> dict[str, bool]:
    return {
        "names_was_changed_token_case": (
            "detects sentinel_token changes with wasChanged" in source
        ),
        "writes_and_saves_new_token": all(
            marker in source
            for marker in (
                "$settings->sentinel_token = 'new-token-value';",
                "$settings->save();",
            )
        ),
        "asserts_change_detected": "expect($changeDetected)->toBeTrue();" in source,
    }


def _evaluate_repair(source: str, start: str, test: str) -> dict[str, bool]:
    return {
        "adds_safe_token_validator": all(
            marker in source
            for marker in (
                "function isValidSentinelToken",
                "preg_match('/\\A[a-zA-Z0-9._\\-+=\\/]+\\z/'",
            )
        ),
        "validates_before_start_sink": (
            "ServerSetting::isValidSentinelToken($token)" in start
        ),
        "shell_quotes_environment": "escapeshellarg(\"$key=$value\")" in start,
        "tests_reported_command_injection_poc": all(
            marker in test
            for marker in (
                "rejects the reported PoC payload",
                "id >/tmp/coolify_poc_sentinel",
            )
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_setting = _text_blob(repository, BASELINE_SHA, SETTING_PATH)
    candidate_setting = _text_blob(repository, AI_ACTIVATION_SHA, SETTING_PATH)
    candidate_server = _text_blob(repository, AI_ACTIVATION_SHA, SERVER_PATH)
    candidate_ui = _text_blob(repository, AI_ACTIVATION_SHA, UI_PATH)
    candidate_start = _text_blob(repository, AI_ACTIVATION_SHA, START_PATH)
    candidate_test = _text_blob(
        repository, AI_ACTIVATION_SHA, ACTIVATION_TEST_PATH
    )
    repair_setting = _text_blob(repository, SECURITY_REPAIR_SHA, SETTING_PATH)
    repair_start = _text_blob(repository, SECURITY_REPAIR_SHA, START_PATH)
    repair_test = _text_blob(repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH)

    evaluations = {
        "baseline_setting_trigger": _evaluate_setting_trigger(baseline_setting),
        "candidate_setting_trigger": _evaluate_setting_trigger(candidate_setting),
        "candidate_ui_write": _evaluate_ui_write(candidate_ui),
        "candidate_restart_dispatch": _evaluate_restart_dispatch(candidate_server),
        "candidate_start_sink": _evaluate_start_sink(candidate_start),
        "candidate_activation_test": _evaluate_activation_test(candidate_test),
        "security_repair": _evaluate_repair(
            repair_setting, repair_start, repair_test
        ),
    }
    line_specs = {
        "candidate_token_change_trigger": (
            AI_ACTIVATION_SHA,
            SETTING_PATH,
            candidate_setting,
            "$settings->wasChanged('sentinel_token')",
            "AI replacement makes saved token changes trigger restart",
        ),
        "candidate_activation_test": (
            AI_ACTIVATION_SHA,
            ACTIVATION_TEST_PATH,
            candidate_test,
            "detects sentinel_token changes with wasChanged",
            "AI regression test for effective saved-change detection",
        ),
        "preexisting_ui_token_write": (
            AI_ACTIVATION_SHA,
            UI_PATH,
            candidate_ui,
            "$this->server->settings->sentinel_token = $this->sentinelToken;",
            "pre-existing public token write",
        ),
        "preexisting_restart_dispatch": (
            AI_ACTIVATION_SHA,
            SERVER_PATH,
            candidate_server,
            "StartSentinel::dispatch($this, true",
            "pre-existing restart dispatch",
        ),
        "preexisting_unescaped_start_sink": (
            AI_ACTIVATION_SHA,
            START_PATH,
            candidate_start,
            "$dockerEnvironments = '-e \"'.implode",
            "pre-existing unescaped Sentinel environment construction",
        ),
        "repair_start_validation": (
            SECURITY_REPAIR_SHA,
            START_PATH,
            repair_start,
            "ServerSetting::isValidSentinelToken($token)",
            "repair validates token before command construction",
        ),
        "repair_reported_poc_test": (
            SECURITY_REPAIR_SHA,
            REPAIR_TEST_PATH,
            repair_test,
            "rejects the reported PoC payload",
            "repair regression test names reported PoC",
        ),
    }
    line_origins = {
        key: _blame_line(
            repository,
            revision,
            source_path,
            _line_number(source, marker),
            label,
        )
        for key, (revision, source_path, source, marker, label) in line_specs.items()
    }

    candidate_metadata = _commit_metadata(repository, AI_ACTIVATION_SHA)
    repair_metadata = _commit_metadata(repository, SECURITY_REPAIR_SHA)
    ancestry = {
        "baseline_to_candidate": _is_ancestor(
            repository, BASELINE_SHA, AI_ACTIVATION_SHA
        ),
        "candidate_to_security_repair": _is_ancestor(
            repository, AI_ACTIVATION_SHA, SECURITY_REPAIR_SHA
        ),
    }
    baseline_trigger = evaluations["baseline_setting_trigger"]
    candidate_trigger = evaluations["candidate_setting_trigger"]
    candidate_sink = evaluations["candidate_start_sink"]
    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"] == [BASELINE_SHA]
        and "isDirty() always returns false in updated() hook"
        in str(candidate_metadata["message"])
        and "Sentinel restart now triggers on config changes"
        in str(candidate_metadata["message"])
        and all(ancestry.values())
        and baseline_trigger["uses_post_update_is_dirty_for_token"] is True
        and baseline_trigger["uses_post_update_was_changed_for_token"] is False
        and candidate_trigger["uses_post_update_is_dirty_for_token"] is False
        and candidate_trigger["uses_post_update_was_changed_for_token"] is True
        and candidate_trigger["changed_token_dispatches_restart"] is True
        and all(evaluations["candidate_ui_write"].values())
        and all(evaluations["candidate_restart_dispatch"].values())
        and candidate_sink["reads_persisted_token"] is True
        and candidate_sink["places_token_in_environment"] is True
        and candidate_sink[
            "builds_double_quoted_environment_without_shell_escaping"
        ]
        is True
        and candidate_sink["executes_composed_docker_command"] is True
        and candidate_sink["validates_token_before_sink"] is False
        and candidate_sink["shell_quotes_environment"] is False
        and all(evaluations["candidate_activation_test"].values())
        and all(evaluations["security_repair"].values())
        and line_origins["candidate_token_change_trigger"]["origin_sha"]
        == AI_ACTIVATION_SHA
        and line_origins["candidate_activation_test"]["origin_sha"]
        == AI_ACTIVATION_SHA
        and all(
            line_origins[key]["origin_sha"] != AI_ACTIVATION_SHA
            for key in (
                "preexisting_ui_token_write",
                "preexisting_restart_dispatch",
                "preexisting_unescaped_start_sink",
            )
        )
        and line_origins["repair_start_validation"]["origin_sha"]
        == SECURITY_REPAIR_SHA
        and line_origins["repair_reported_poc_test"]["origin_sha"]
        == SECURITY_REPAIR_SHA
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_sentinel_restart_activation_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_ACTIVATION_SHA,
        "fix_sha": SECURITY_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluations": evaluations,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, BASELINE_SHA, SETTING_PATH),
            _blob_record(repository, AI_ACTIVATION_SHA, SETTING_PATH),
            _blob_record(repository, AI_ACTIVATION_SHA, UI_PATH),
            _blob_record(repository, AI_ACTIVATION_SHA, SERVER_PATH),
            _blob_record(repository, AI_ACTIVATION_SHA, START_PATH),
            _blob_record(repository, AI_ACTIVATION_SHA, ACTIVATION_TEST_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, SETTING_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, START_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH),
        ],
        "confirmed_edge": {
            "adjudication": "CONFIRMED_AI_SHELL_TRIGGER_ACTIVATION_CONTRIBUTOR",
            "candidate_sha": AI_ACTIVATION_SHA,
            "fix_sha": SECURITY_REPAIR_SHA,
            "mechanism_group": "sentinel_setting_updated_restart_command_injection",
        },
        "counting": {
            "candidate_level_true_positive_count": 1,
            "earliest_mechanism_root_is_ai_not_asserted": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude commit did not originate the editable Sentinel token or the "
            "unsafe StartSentinel shell construction. It replaced ineffective "
            "post-update isDirty checks with wasChanged and explicitly tested that "
            "saved Sentinel-token changes are now detected; the unchanged callback "
            "then dispatches StartSentinel, whose persisted token entered an "
            "unescaped Docker command. The later repair validates and shell-quotes "
            "that token and names the reported command-injection PoC in tests. This "
            "therefore confirms an AI-created automatic trigger/path extension, not "
            "the earliest command-injection origin or a locally executed exploit."
        ),
        "witness_passed": witness_passed,
    }
    _atomic_json(args.output, payload)
    print("Coolify Sentinel restart activation witness frozen")
    print(f"  witness passed: {witness_passed}")
    print(f"  output        : {args.output}")
    return 0 if witness_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
