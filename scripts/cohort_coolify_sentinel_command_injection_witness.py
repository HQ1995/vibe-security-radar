#!/usr/bin/env python3
"""Freeze two AI preservation contributors to Coolify Sentinel command injection."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)


UI_BASELINE_SHA = "2c04336d7a12f5c8c8299fc4c6e2e2543712e5a6"
UI_AI_PRESERVATION_SHA = "9675d74360c9057fe78682dccc263580b870904e"
METRICS_BASELINE_SHA = "8be1a9b5de3aa287cebf705ed7bd39400d4f7291"
METRICS_AI_PRESERVATION_SHA = "a8aa4524751d1530031f6134d49474d254bbab72"
SECURITY_REPAIR_SHA = "096d4369e59b3db7ace2db3ca42588c41b9b6019"

LEGACY_UI_SOURCE_PATH = "app/Livewire/Server/Show.php"
LEGACY_UI_VIEW_PATH = "resources/views/livewire/server/show.blade.php"
SENTINEL_SOURCE_PATH = "app/Livewire/Server/Sentinel.php"
SENTINEL_VIEW_PATH = "resources/views/livewire/server/sentinel.blade.php"
ROUTES_PATH = "routes/web.php"
LEGACY_METRICS_PATH = "app/Models/Server.php"
METRICS_TRAIT_PATH = "app/Traits/HasMetrics.php"
START_SENTINEL_PATH = "app/Actions/Server/StartSentinel.php"
SERVER_SETTING_PATH = "app/Models/ServerSetting.php"
REPAIR_TEST_PATH = "tests/Feature/SentinelTokenValidationTest.php"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _evaluate_ui(source: str, view: str) -> dict[str, bool]:
    sync_data = _php_method_region(source, "syncData")
    token_property_offset = source.find("public string $sentinelToken;")
    token_validation_prefix = (
        source[max(0, token_property_offset - 300) : token_property_offset]
        if token_property_offset >= 0
        else ""
    )
    return {
        "public_token_property": "public string $sentinelToken;" in source,
        "required_only_token_validation": bool(
            "'sentinelToken' => 'required'" in source
            or re.search(
                r"#\[Validate\(\['required'\]\)\]\s*"
                r"public string \$sentinelToken;",
                source,
            )
        ),
        "safe_character_validation": "regex:/" in token_validation_prefix,
        "sync_validates_public_state": "$this->validate();" in sync_data,
        "sync_has_server_update_authorization": (
            "$this->authorize('update', $this->server)" in sync_data
        ),
        "sync_persists_token": (
            "$this->server->settings->sentinel_token = $this->sentinelToken;"
            in sync_data
        ),
        "view_binds_token_input": bool(
            re.search(r"<x-forms\.input[^>]*id=\"sentinelToken\"", view)
        ),
        "view_submits_component": bool(
            "wire:submit.prevent='submit'" in view
            or "wire:submit='submit'" in view
        ),
    }


def _evaluate_metrics(source: str) -> dict[str, bool]:
    return {
        "shell_executes_metrics_curl": bool(
            "instant_remote_process(" in source
            and "docker exec coolify-sentinel sh -c" in source
            and "Authorization: Bearer" in source
        ),
        "directly_interpolates_stored_token": bool(
            "{$server->settings->sentinel_token}" in source
            or "{$this->settings->sentinel_token}" in source
        ),
        "validates_stored_token": (
            "ServerSetting::isValidSentinelToken($token)" in source
        ),
        "uses_validated_token_variable": "Authorization: Bearer {$token}" in source,
    }


def _evaluate_start_sentinel(source: str) -> dict[str, bool]:
    handle = _php_method_region(source, "handle")
    return {
        "reads_stored_token": (
            "$token = data_get($server, 'settings.sentinel_token');" in handle
        ),
        "token_reaches_docker_environment": "'TOKEN' => $token" in handle,
        "docker_command_executes": bool(
            "$dockerCommand" in handle and "instant_remote_process(" in handle
        ),
        "validates_token": "ServerSetting::isValidSentinelToken($token)" in handle,
        "shell_quotes_environment": "escapeshellarg(\"$key=$value\")" in handle,
    }


def _evaluate_setting_event(source: str) -> dict[str, bool]:
    return {
        "token_change_triggers_restart": bool(
            "$settings->wasChanged('sentinel_token')" in source
            and "$settings->server->restartSentinel();" in source
        )
    }


def _evaluate_repair_test(source: str) -> dict[str, bool]:
    return {
        "reported_poc_case_present": "rejects the reported PoC payload" in source,
        "poc_contains_shell_metacharacters": (
            "id >/tmp/coolify_poc_sentinel" in source
        ),
        "command_substitution_case_present": "abc$(whoami)" in source,
        "quote_case_present": "abc\" ; id ; echo \"" in source,
        "safe_base64_case_present": "abc+def/ghi=" in source,
    }


def _line_in_method(source: str, method_name: str, marker: str) -> int:
    lines = source.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if re.search(
            rf"(?:public|private|protected) function {re.escape(method_name)}\s*\(",
            line,
        )
    ]
    if len(starts) != 1:
        raise SystemExit(f"expected one method {method_name}, found {starts}")
    start = starts[0]
    end = next(
        (
            index
            for index, line in enumerate(lines[start + 1 :], start=start + 1)
            if re.search(r"(?:public|private|protected) function \w+\s*\(", line)
        ),
        len(lines),
    )
    matches = [
        index + 1
        for index, line in enumerate(lines[start:end], start=start)
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected one {marker!r} in {method_name}, found {matches}"
        )
    return matches[0]


def _line_number(source: str, marker: str) -> int:
    matches = [
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one marker {marker!r}, found {matches}")
    return matches[0]


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
        "path": source_path,
        "line": line,
        "marker": marker,
        "origin_sha": value.split(None, 1)[0].lstrip("^"),
    }


def _blob_record(repository: Path, revision: str, source_path: str) -> dict[str, str]:
    blob = _git_blob(repository, revision, source_path)
    return {
        "path": source_path,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    legacy_ui_source = _git_blob(
        repository, UI_BASELINE_SHA, LEGACY_UI_SOURCE_PATH
    ).decode("utf-8")
    legacy_ui_view = _git_blob(
        repository, UI_BASELINE_SHA, LEGACY_UI_VIEW_PATH
    ).decode("utf-8")
    ai_ui_source = _git_blob(
        repository, UI_AI_PRESERVATION_SHA, SENTINEL_SOURCE_PATH
    ).decode("utf-8")
    ai_ui_view = _git_blob(
        repository, UI_AI_PRESERVATION_SHA, SENTINEL_VIEW_PATH
    ).decode("utf-8")
    ai_routes = _git_blob(repository, UI_AI_PRESERVATION_SHA, ROUTES_PATH).decode(
        "utf-8"
    )
    repair_ui_source = _git_blob(
        repository, SECURITY_REPAIR_SHA, SENTINEL_SOURCE_PATH
    ).decode("utf-8")
    repair_ui_view = _git_blob(
        repository, SECURITY_REPAIR_SHA, SENTINEL_VIEW_PATH
    ).decode("utf-8")

    legacy_metrics_source = _git_blob(
        repository, METRICS_BASELINE_SHA, LEGACY_METRICS_PATH
    ).decode("utf-8")
    ai_metrics_source = _git_blob(
        repository, METRICS_AI_PRESERVATION_SHA, METRICS_TRAIT_PATH
    ).decode("utf-8")
    repair_metrics_source = _git_blob(
        repository, SECURITY_REPAIR_SHA, METRICS_TRAIT_PATH
    ).decode("utf-8")
    pre_repair_start = _git_blob(
        repository, f"{SECURITY_REPAIR_SHA}^", START_SENTINEL_PATH
    ).decode("utf-8")
    repair_start = _git_blob(
        repository, SECURITY_REPAIR_SHA, START_SENTINEL_PATH
    ).decode("utf-8")
    setting_source = _git_blob(
        repository, UI_AI_PRESERVATION_SHA, SERVER_SETTING_PATH
    ).decode("utf-8")
    repair_test_source = _git_blob(
        repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH
    ).decode("utf-8")

    evaluations = {
        "legacy_ui_baseline": _evaluate_ui(legacy_ui_source, legacy_ui_view),
        "ai_dedicated_ui": _evaluate_ui(ai_ui_source, ai_ui_view),
        "repaired_ui": _evaluate_ui(repair_ui_source, repair_ui_view),
        "legacy_metrics_baseline": _evaluate_metrics(legacy_metrics_source),
        "ai_metrics_trait": _evaluate_metrics(ai_metrics_source),
        "repaired_metrics_trait": _evaluate_metrics(repair_metrics_source),
        "pre_repair_start_sentinel": _evaluate_start_sentinel(pre_repair_start),
        "repaired_start_sentinel": _evaluate_start_sentinel(repair_start),
        "setting_event": _evaluate_setting_event(setting_source),
        "repair_test": _evaluate_repair_test(repair_test_source),
        "dedicated_route_present": (
            "Route::get('/sentinel', ServerSentinel::class)->name('server.sentinel')"
            in ai_routes
        ),
    }
    line_origins = {
        "ui_candidate_token_property": _blame_line(
            repository,
            UI_AI_PRESERVATION_SHA,
            SENTINEL_SOURCE_PATH,
            _line_number(ai_ui_source, "public string $sentinelToken;"),
            "public string $sentinelToken;",
        ),
        "ui_candidate_token_persistence": _blame_line(
            repository,
            UI_AI_PRESERVATION_SHA,
            SENTINEL_SOURCE_PATH,
            _line_in_method(
                ai_ui_source,
                "syncData",
                "$this->server->settings->sentinel_token = $this->sentinelToken;",
            ),
            "$this->server->settings->sentinel_token = $this->sentinelToken;",
        ),
        "metrics_candidate_shell_sink": _blame_line(
            repository,
            METRICS_AI_PRESERVATION_SHA,
            METRICS_TRAIT_PATH,
            _line_number(
                ai_metrics_source,
                '["docker exec coolify-sentinel sh -c \'curl -H \\"Authorization: Bearer {$server->settings->sentinel_token}\\" {$endpoint}\'"]',
            ),
            "direct sentinel_token shell interpolation",
        ),
        "repair_ui_regex": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            SENTINEL_SOURCE_PATH,
            _line_number(
                repair_ui_source,
                "#[Validate(['required', 'string', 'max:500', 'regex:/\\A[a-zA-Z0-9._\\-+=\\/]+\\z/'])]",
            ),
            "sentinel token safe-character validation",
        ),
        "repair_metrics_validation": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            METRICS_TRAIT_PATH,
            _line_in_method(
                repair_metrics_source,
                "getMetrics",
                "ServerSetting::isValidSentinelToken($token)",
            ),
            "ServerSetting::isValidSentinelToken($token)",
        ),
        "repair_start_validation": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            START_SENTINEL_PATH,
            _line_in_method(
                repair_start,
                "handle",
                "ServerSetting::isValidSentinelToken($token)",
            ),
            "ServerSetting::isValidSentinelToken($token)",
        ),
        "repair_reported_poc_test": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            REPAIR_TEST_PATH,
            _line_number(repair_test_source, "rejects the reported PoC payload"),
            "rejects the reported PoC payload",
        ),
    }
    ui_metadata = _commit_metadata(repository, UI_AI_PRESERVATION_SHA)
    metrics_metadata = _commit_metadata(repository, METRICS_AI_PRESERVATION_SHA)
    legacy_ui = evaluations["legacy_ui_baseline"]
    ai_ui = evaluations["ai_dedicated_ui"]
    repaired_ui = evaluations["repaired_ui"]
    legacy_metrics = evaluations["legacy_metrics_baseline"]
    ai_metrics = evaluations["ai_metrics_trait"]
    repaired_metrics = evaluations["repaired_metrics_trait"]
    pre_start = evaluations["pre_repair_start_sentinel"]
    repaired_start = evaluations["repaired_start_sentinel"]
    witness_passed = bool(
        ui_metadata["explicit_claude_signal"] is True
        and ui_metadata["parents"] == [UI_BASELINE_SHA]
        and metrics_metadata["explicit_claude_signal"] is True
        and metrics_metadata["parents"] == [METRICS_BASELINE_SHA]
        and _is_ancestor(repository, UI_AI_PRESERVATION_SHA, SECURITY_REPAIR_SHA)
        and _is_ancestor(
            repository, METRICS_AI_PRESERVATION_SHA, SECURITY_REPAIR_SHA
        )
        and legacy_ui["public_token_property"] is True
        and legacy_ui["required_only_token_validation"] is True
        and legacy_ui["safe_character_validation"] is False
        and legacy_ui["sync_persists_token"] is True
        and ai_ui["public_token_property"] is True
        and ai_ui["required_only_token_validation"] is True
        and ai_ui["safe_character_validation"] is False
        and ai_ui["sync_persists_token"] is True
        and ai_ui["view_binds_token_input"] is True
        and evaluations["dedicated_route_present"] is True
        and repaired_ui["safe_character_validation"] is True
        and legacy_metrics["directly_interpolates_stored_token"] is True
        and ai_metrics["directly_interpolates_stored_token"] is True
        and ai_metrics["validates_stored_token"] is False
        and repaired_metrics["directly_interpolates_stored_token"] is False
        and repaired_metrics["validates_stored_token"] is True
        and repaired_metrics["uses_validated_token_variable"] is True
        and pre_start["token_reaches_docker_environment"] is True
        and pre_start["validates_token"] is False
        and repaired_start["validates_token"] is True
        and repaired_start["shell_quotes_environment"] is True
        and all(evaluations["setting_event"].values())
        and all(evaluations["repair_test"].values())
        and all(
            value["origin_sha"] == UI_AI_PRESERVATION_SHA
            for key, value in line_origins.items()
            if key.startswith("ui_candidate_")
        )
        and line_origins["metrics_candidate_shell_sink"]["origin_sha"]
        == METRICS_AI_PRESERVATION_SHA
        and all(
            value["origin_sha"] == SECURITY_REPAIR_SHA
            for key, value in line_origins.items()
            if key.startswith("repair_")
        )
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_sentinel_command_injection_compositional_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "fix_sha": SECURITY_REPAIR_SHA,
        "candidate_edges": [
            {
                "candidate_sha": UI_AI_PRESERVATION_SHA,
                "causal_adjudication": "CONFIRMED_AI_UI_PRESERVATION_CONTRIBUTOR",
                "causal_role": "dedicated_editable_sentinel_token_surface",
            },
            {
                "candidate_sha": METRICS_AI_PRESERVATION_SHA,
                "causal_adjudication": "CONFIRMED_AI_SHELL_SINK_PRESERVATION_CONTRIBUTOR",
                "causal_role": "centralized_unvalidated_metrics_shell_interpolation",
            },
        ],
        "candidate_metadata": {
            UI_AI_PRESERVATION_SHA: ui_metadata,
            METRICS_AI_PRESERVATION_SHA: metrics_metadata,
        },
        "line_origins": line_origins,
        "evaluations": evaluations,
        "source_blobs": [
            _blob_record(repository, UI_BASELINE_SHA, LEGACY_UI_SOURCE_PATH),
            _blob_record(repository, UI_AI_PRESERVATION_SHA, SENTINEL_SOURCE_PATH),
            _blob_record(repository, METRICS_BASELINE_SHA, LEGACY_METRICS_PATH),
            _blob_record(
                repository, METRICS_AI_PRESERVATION_SHA, METRICS_TRAIT_PATH
            ),
            _blob_record(repository, SECURITY_REPAIR_SHA, SENTINEL_SOURCE_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, METRICS_TRAIT_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, START_SENTINEL_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH),
        ],
        "witness_passed": witness_passed,
        "mechanism_group": "sentinel_token_command_injection",
        "counting": {
            "candidate_level_true_positive_count": 2,
            "mechanism_level_true_positive": True,
            "earliest_mechanism_root_is_ai_not_asserted": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The first Claude refactor relocates an already editable Sentinel token "
            "into a new dedicated Livewire component and route while preserving only "
            "required validation. The second Claude refactor centralizes an already "
            "unsafe metrics curl shell interpolation into a new HasMetrics trait. "
            "The later security repair changes both AI-owned surfaces: it adds a "
            "safe-character regex to the token property and validates the trait's "
            "stored token before shell execution. It also validates and shell-quotes "
            "the pre-existing StartSentinel sink and includes the reported command-"
            "injection PoC payload in tests. Both AI commits are preservation "
            "contributors, not the earliest mechanism origin. This is a source and "
            "repair-test witness, not a locally executed host-command PoC."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify Sentinel command-injection witness frozen")
    print(f"  UI preservation       : {ai_ui['required_only_token_validation']}")
    print(f"  metrics sink preserved: {ai_metrics['directly_interpolates_stored_token']}")
    print(f"  repaired validation   : {repaired_metrics['validates_stored_token']}")
    print(f"  witness               : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output                : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
