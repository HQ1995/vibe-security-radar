#!/usr/bin/env python3
"""Freeze the Coolify AI Sentinel instant-save shell-path witness."""

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
from cohort_coolify_sentinel_command_injection_witness import (
    _blame_line,
    _evaluate_repair_test,
    _evaluate_start_sentinel,
)


BASELINE_SHA = "f77a2674fc2338e50773dc8b4fa832fcb096a43e"
AI_INSTANT_SAVE_SHA = "f995426fb32d810577dad5d46f275cc4a6e5c38d"
SECURITY_REPAIR_SHA = "096d4369e59b3db7ace2db3ca42588c41b9b6019"

COMPONENT_PATH = "app/Livewire/Server/Sentinel.php"
VIEW_PATH = "resources/views/livewire/server/sentinel.blade.php"
START_PATH = "app/Actions/Server/StartSentinel.php"
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


def _method_line(source: str, method_name: str, marker: str) -> int:
    method = _php_method_region(source, method_name)
    offset = method.find(marker)
    if offset < 0:
        raise SystemExit(f"missing marker {marker!r} in {method_name}")
    method_offset = source.find(method)
    return source[: method_offset + offset].count("\n") + 1


def _evaluate_component(source: str) -> dict[str, bool]:
    sync = _php_method_region(source, "syncData")
    restart = _php_method_region(source, "restartSentinel")
    has_instant_save = "public function instantSave()" in source
    instant_save = (
        _php_method_region(source, "instantSave") if has_instant_save else ""
    )
    return {
        "token_is_public_livewire_state": "public string $sentinelToken;" in source,
        "token_has_required_only_validation": (
            "#[Validate(['required'])]" in source
        ),
        "token_has_safe_character_validation": "regex:/\\A" in source,
        "sync_true_authorizes_and_validates": all(
            marker in sync
            for marker in (
                "$this->authorize('update', $this->server);",
                "$this->validate();",
            )
        ),
        "sync_true_persists_token_and_saves": all(
            marker in sync
            for marker in (
                "$this->server->settings->sentinel_token = $this->sentinelToken;",
                "$this->server->settings->save();",
            )
        ),
        "instant_save_method_exists": has_instant_save,
        "instant_save_persists_all_state": "$this->syncData(true);" in instant_save,
        "instant_save_explicitly_restarts_sentinel": (
            "$this->restartSentinel();" in instant_save
        ),
        "restart_dispatches_server_restart": (
            "$this->server->restartSentinel($customImage);" in restart
        ),
    }


def _evaluate_view(source: str) -> dict[str, bool]:
    return {
        "checkboxes_invoke_instant_save": (
            source.count("instantSave") >= 2
            and 'id="isMetricsEnabled"' in source
        ),
        "token_input_is_bound_to_public_state": (
            'id="sentinelToken"' in source and 'type="password"' in source
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_component = _text_blob(repository, BASELINE_SHA, COMPONENT_PATH)
    candidate_component = _text_blob(
        repository, AI_INSTANT_SAVE_SHA, COMPONENT_PATH
    )
    candidate_view = _text_blob(repository, AI_INSTANT_SAVE_SHA, VIEW_PATH)
    candidate_start = _text_blob(repository, AI_INSTANT_SAVE_SHA, START_PATH)
    repaired_component = _text_blob(
        repository, SECURITY_REPAIR_SHA, COMPONENT_PATH
    )
    repaired_start = _text_blob(repository, SECURITY_REPAIR_SHA, START_PATH)
    repair_test = _text_blob(repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH)

    evaluations = {
        "baseline_component": _evaluate_component(baseline_component),
        "candidate_component": _evaluate_component(candidate_component),
        "candidate_view": _evaluate_view(candidate_view),
        "candidate_start_sink": _evaluate_start_sentinel(candidate_start),
        "repaired_component": _evaluate_component(repaired_component),
        "repaired_start_sink": _evaluate_start_sentinel(repaired_start),
        "repair_test": _evaluate_repair_test(repair_test),
    }
    line_specs = {
        "candidate_instant_save_method": (
            AI_INSTANT_SAVE_SHA,
            COMPONENT_PATH,
            candidate_component,
            "public function instantSave()",
            None,
            "AI introduces public instant-save action",
        ),
        "candidate_instant_save_restart": (
            AI_INSTANT_SAVE_SHA,
            COMPONENT_PATH,
            candidate_component,
            "$this->restartSentinel();",
            "instantSave",
            "AI instant-save action explicitly restarts Sentinel",
        ),
        "preexisting_token_input": (
            AI_INSTANT_SAVE_SHA,
            VIEW_PATH,
            candidate_view,
            'id="sentinelToken"',
            None,
            "pre-existing editable Sentinel token input",
        ),
        "preexisting_instant_save_trigger": (
            AI_INSTANT_SAVE_SHA,
            VIEW_PATH,
            candidate_view,
            'id="isMetricsEnabled"',
            None,
            "pre-existing checkbox wired to instant-save action",
        ),
        "preexisting_unvalidated_start_sink": (
            AI_INSTANT_SAVE_SHA,
            START_PATH,
            candidate_start,
            "$dockerEnvironments = '-e \"'.implode",
            None,
            "pre-existing unvalidated shell environment construction",
        ),
        "repair_ui_token_regex": (
            SECURITY_REPAIR_SHA,
            COMPONENT_PATH,
            repaired_component,
            "regex:/\\A[a-zA-Z0-9._\\-+=\\/]+\\z/",
            None,
            "repair constrains token at Livewire boundary",
        ),
        "repair_start_validation": (
            SECURITY_REPAIR_SHA,
            START_PATH,
            repaired_start,
            "ServerSetting::isValidSentinelToken($token)",
            "handle",
            "repair validates token at shell sink",
        ),
        "repair_reported_poc_test": (
            SECURITY_REPAIR_SHA,
            REPAIR_TEST_PATH,
            repair_test,
            "rejects the reported PoC payload",
            None,
            "repair regression test names reported PoC",
        ),
    }
    line_origins = {}
    for key, (
        revision,
        source_path,
        source,
        marker,
        method,
        label,
    ) in line_specs.items():
        line = (
            _method_line(source, method, marker)
            if method is not None
            else _line_number(source, marker)
        )
        line_origins[key] = _blame_line(
            repository, revision, source_path, line, label
        )

    candidate_metadata = _commit_metadata(repository, AI_INSTANT_SAVE_SHA)
    repair_metadata = _commit_metadata(repository, SECURITY_REPAIR_SHA)
    ancestry = {
        "baseline_to_candidate": _is_ancestor(
            repository, BASELINE_SHA, AI_INSTANT_SAVE_SHA
        ),
        "candidate_to_security_repair": _is_ancestor(
            repository, AI_INSTANT_SAVE_SHA, SECURITY_REPAIR_SHA
        ),
    }
    baseline = evaluations["baseline_component"]
    candidate = evaluations["candidate_component"]
    candidate_start_eval = evaluations["candidate_start_sink"]
    repaired = evaluations["repaired_component"]
    repaired_start_eval = evaluations["repaired_start_sink"]
    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"] == [BASELINE_SHA]
        and "Add missing instantSave method" in str(candidate_metadata["message"])
        and "saves settings and restarts Sentinel in one action"
        in str(candidate_metadata["message"])
        and all(ancestry.values())
        and baseline["instant_save_method_exists"] is False
        and candidate["token_is_public_livewire_state"] is True
        and candidate["token_has_required_only_validation"] is True
        and candidate["token_has_safe_character_validation"] is False
        and candidate["sync_true_authorizes_and_validates"] is True
        and candidate["sync_true_persists_token_and_saves"] is True
        and candidate["instant_save_method_exists"] is True
        and candidate["instant_save_persists_all_state"] is True
        and candidate["instant_save_explicitly_restarts_sentinel"] is True
        and candidate["restart_dispatches_server_restart"] is True
        and all(evaluations["candidate_view"].values())
        and candidate_start_eval["reads_stored_token"] is True
        and candidate_start_eval["token_reaches_docker_environment"] is True
        and candidate_start_eval["docker_command_executes"] is True
        and candidate_start_eval["validates_token"] is False
        and candidate_start_eval["shell_quotes_environment"] is False
        and repaired["token_has_safe_character_validation"] is True
        and repaired_start_eval["validates_token"] is True
        and repaired_start_eval["shell_quotes_environment"] is True
        and all(evaluations["repair_test"].values())
        and line_origins["candidate_instant_save_method"]["origin_sha"]
        == AI_INSTANT_SAVE_SHA
        and line_origins["candidate_instant_save_restart"]["origin_sha"]
        == AI_INSTANT_SAVE_SHA
        and all(
            line_origins[key]["origin_sha"] != AI_INSTANT_SAVE_SHA
            for key in (
                "preexisting_token_input",
                "preexisting_instant_save_trigger",
                "preexisting_unvalidated_start_sink",
            )
        )
        and all(
            line_origins[key]["origin_sha"] == SECURITY_REPAIR_SHA
            for key in (
                "repair_ui_token_regex",
                "repair_start_validation",
                "repair_reported_poc_test",
            )
        )
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_sentinel_instant_save_path_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_INSTANT_SAVE_SHA,
        "fix_sha": SECURITY_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluations": evaluations,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, BASELINE_SHA, COMPONENT_PATH),
            _blob_record(repository, AI_INSTANT_SAVE_SHA, COMPONENT_PATH),
            _blob_record(repository, AI_INSTANT_SAVE_SHA, VIEW_PATH),
            _blob_record(repository, AI_INSTANT_SAVE_SHA, START_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, COMPONENT_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, START_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH),
        ],
        "confirmed_edge": {
            "adjudication": "CONFIRMED_DIRECT_AI_SHELL_TRIGGER_PATH_EXTENSION",
            "candidate_sha": AI_INSTANT_SAVE_SHA,
            "fix_sha": SECURITY_REPAIR_SHA,
            "mechanism_group": "sentinel_instant_save_restart_command_injection",
        },
        "counting": {
            "candidate_level_true_positive_count": 1,
            "earliest_mechanism_root_is_ai_not_asserted": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude commit did not originate the editable Sentinel token, the "
            "checkbox markup, or the unsafe StartSentinel shell sink. It introduced "
            "the previously missing public instantSave action, and that exact method "
            "persists all current Livewire state including the required-only token "
            "before explicitly restarting Sentinel. The later repair constrains the "
            "token at the component boundary, validates and quotes it at the sink, "
            "and tests the reported command-injection payload. This confirms an "
            "AI-created shell-trigger path extension, not the earliest vulnerability "
            "origin or a locally executed exploit."
        ),
        "witness_passed": witness_passed,
    }
    _atomic_json(args.output, payload)
    print("Coolify Sentinel instant-save path witness frozen")
    print(f"  witness passed: {witness_passed}")
    print(f"  output        : {args.output}")
    return 0 if witness_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
