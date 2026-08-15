#!/usr/bin/env python3
"""Freeze two recovered Coolify authorization/data-exposure AI path witnesses."""

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


SECURITY_REPAIR_SHA = "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e"

LOG_BASELINE_SHA = "bbb2aa9ad4e0c14517d32272b5e6d83318fde493"
LOG_AI_ORIGIN_SHA = "a980fd460a2ef7ce7766171d034a8c645322299b"
LOG_SOURCE_PATH = "app/Livewire/Project/Application/Deployment/Show.php"
LOG_VIEW_PATH = "resources/views/livewire/project/application/deployment/show.blade.php"

ENV_BASELINE_SHA = "3dfef0b53ad20e6a50b1e0ae96ca63634e748adf"
ENV_AI_PATH_EXTENSION_SHA = "78031b991ac3d1fa8579ef9256ef0e43d79a79b7"
ENV_SOURCE_PATH = "app/Http/Controllers/Api/ApplicationsController.php"
ENV_REPAIR_TEST_PATH = (
    "tests/Feature/Authorization/EnvironmentVariableValueHidingTest.php"
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _optional_method(source: str, method_name: str) -> str | None:
    try:
        return _php_method_region(source, method_name)
    except ValueError:
        return None


def _evaluate_log_export(source: str, view: str) -> dict[str, bool]:
    method = _optional_method(source, "downloadAllLogs")
    return {
        "public_download_all_logs_method": bool(
            method is not None
            and re.search(r"public function downloadAllLogs\s*\(", method)
        ),
        "exports_include_all_log_rows": bool(
            method is not None and "includeAll: true" in method
        ),
        "explicitly_serializes_hidden_debug_rows": bool(
            method is not None
            and "if ($line['hidden'])" in method
            and "[DEBUG]" in method
        ),
        "method_has_update_authorization": bool(
            method is not None
            and "$this->authorize('update', $this->application)" in method
        ),
        "view_calls_download_all_logs": "$wire.downloadAllLogs()" in view,
        "view_has_update_gate": bool(
            re.search(
                r"@can\('update',\s*\$application\).*?"
                r"\$wire\.downloadAllLogs\(\).*?@endcan",
                view,
                re.DOTALL,
            )
        ),
    }


def _evaluate_env_api(source: str) -> dict[str, bool]:
    update_method = _php_method_region(source, "update_env_by_uuid")
    create_method = _php_method_region(source, "create_env")
    bulk_method = _php_method_region(source, "create_bulk_envs")
    envs_method = _php_method_region(source, "envs")
    sensitive_method = _php_method_region(source, "removeSensitiveData")
    allowed_marker = "'is_multiline', 'is_shown_once', 'is_runtime', 'is_buildtime'"
    shown_once_hide = bool(
        re.search(
            r"if\s*\(\s*\$application->is_shown_once\s*\?\?\s*false\s*\)"
            r"\s*\{[^}]*makeHidden\(\['value',\s*'real_value'\]\)",
            sensitive_method,
            re.DOTALL,
        )
    )
    return {
        "update_api_accepts_shown_once": allowed_marker in update_method,
        "create_api_accepts_shown_once": allowed_marker in create_method,
        "bulk_api_accepts_shown_once": allowed_marker in bulk_method,
        "api_assigns_shown_once": "'is_shown_once' => $request->is_shown_once" in create_method,
        "env_list_uses_sensitive_serializer": (
            "return $this->removeSensitiveData($env)" in envs_method
        ),
        "serializer_hides_values_only_without_sensitive_permission": (
            "can_read_sensitive" in sensitive_method
            and "makeHidden" in sensitive_method
        ),
        "serializer_always_hides_shown_once_values": shown_once_hide,
    }


def _repair_test_contract(source: str) -> dict[str, bool]:
    return {
        "locked_env_fixture_present": (
            "'is_shown_once' => true" in source
            and "'value' => 'secret-locked-value'" in source
        ),
        "read_sensitive_case_present": (
            "API hides locked env value even with read:sensitive token" in source
        ),
        "root_token_case_present": (
            "API hides locked env value with root token" in source
        ),
        "value_and_real_value_absent": (
            "expect($locked)->not->toHaveKey('value')" in source
            and "expect($locked)->not->toHaveKey('real_value')" in source
        ),
        "unlocked_positive_control_present": (
            "expect($unlocked)->toHaveKey('value')" in source
        ),
    }


def _line_in_method(source: str, method_name: str, marker: str) -> int:
    lines = source.splitlines()
    method_starts = [
        index
        for index, line in enumerate(lines)
        if re.search(
            rf"(?:public|private|protected) function {re.escape(method_name)}\s*\(",
            line,
        )
    ]
    if len(method_starts) != 1:
        raise SystemExit(
            f"expected one method marker for {method_name}, found {method_starts}"
        )
    start = method_starts[0]
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


def _run_state(
    repository: Path,
    *,
    label: str,
    revision: str,
    source_path: str,
    evaluator: object,
    extra_path: str | None = None,
) -> dict[str, object]:
    source_blob = _git_blob(repository, revision, source_path)
    if extra_path is None:
        evaluation = evaluator(source_blob.decode("utf-8"))
        blob_sha256: object = hashlib.sha256(source_blob).hexdigest()
    else:
        extra_blob = _git_blob(repository, revision, extra_path)
        evaluation = evaluator(
            source_blob.decode("utf-8"), extra_blob.decode("utf-8")
        )
        blob_sha256 = {
            source_path: hashlib.sha256(source_blob).hexdigest(),
            extra_path: hashlib.sha256(extra_blob).hexdigest(),
        }
    return {
        "label": label,
        "revision": revision,
        "blob_sha256": blob_sha256,
        "evaluation": evaluation,
    }


def _log_case(repository: Path) -> dict[str, object]:
    runs = [
        _run_state(
            repository,
            label="baseline",
            revision=LOG_BASELINE_SHA,
            source_path=LOG_SOURCE_PATH,
            extra_path=LOG_VIEW_PATH,
            evaluator=_evaluate_log_export,
        ),
        _run_state(
            repository,
            label="direct_ai_origin",
            revision=LOG_AI_ORIGIN_SHA,
            source_path=LOG_SOURCE_PATH,
            extra_path=LOG_VIEW_PATH,
            evaluator=_evaluate_log_export,
        ),
        _run_state(
            repository,
            label="security_repair",
            revision=SECURITY_REPAIR_SHA,
            source_path=LOG_SOURCE_PATH,
            extra_path=LOG_VIEW_PATH,
            evaluator=_evaluate_log_export,
        ),
    ]
    evaluations = {str(run["label"]): run["evaluation"] for run in runs}
    candidate_source = _git_blob(
        repository, LOG_AI_ORIGIN_SHA, LOG_SOURCE_PATH
    ).decode("utf-8")
    candidate_view = _git_blob(
        repository, LOG_AI_ORIGIN_SHA, LOG_VIEW_PATH
    ).decode("utf-8")
    repair_source = _git_blob(
        repository, SECURITY_REPAIR_SHA, LOG_SOURCE_PATH
    ).decode("utf-8")
    line_origins = {
        "candidate_method": _blame_line(
            repository,
            LOG_AI_ORIGIN_SHA,
            LOG_SOURCE_PATH,
            _line_in_method(
                candidate_source,
                "downloadAllLogs",
                "public function downloadAllLogs(): string",
            ),
            "public function downloadAllLogs(): string",
        ),
        "candidate_view_call": _blame_line(
            repository,
            LOG_AI_ORIGIN_SHA,
            LOG_VIEW_PATH,
            _line_number(candidate_view, "$wire.downloadAllLogs().then(logs => {"),
            "$wire.downloadAllLogs().then(logs => {",
        ),
        "repair_authorization": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            LOG_SOURCE_PATH,
            _line_in_method(
                repair_source,
                "downloadAllLogs",
                "$this->authorize('update', $this->application)",
            ),
            "$this->authorize('update', $this->application)",
        ),
    }
    metadata = _commit_metadata(repository, LOG_AI_ORIGIN_SHA)
    baseline = evaluations["baseline"]
    candidate = evaluations["direct_ai_origin"]
    repair = evaluations["security_repair"]
    passed = bool(
        metadata["explicit_claude_signal"] is True
        and metadata["parents"] == [LOG_BASELINE_SHA]
        and _is_ancestor(repository, LOG_AI_ORIGIN_SHA, SECURITY_REPAIR_SHA)
        and baseline["public_download_all_logs_method"] is False
        and baseline["view_calls_download_all_logs"] is False
        and candidate["public_download_all_logs_method"] is True
        and candidate["exports_include_all_log_rows"] is True
        and candidate["explicitly_serializes_hidden_debug_rows"] is True
        and candidate["method_has_update_authorization"] is False
        and candidate["view_calls_download_all_logs"] is True
        and candidate["view_has_update_gate"] is False
        and repair["method_has_update_authorization"] is True
        and repair["view_has_update_gate"] is True
        and line_origins["candidate_method"]["origin_sha"] == LOG_AI_ORIGIN_SHA
        and line_origins["candidate_view_call"]["origin_sha"] == LOG_AI_ORIGIN_SHA
        and line_origins["repair_authorization"]["origin_sha"]
        == SECURITY_REPAIR_SHA
    )
    return {
        "candidate_sha": LOG_AI_ORIGIN_SHA,
        "fix_sha": SECURITY_REPAIR_SHA,
        "candidate_metadata": metadata,
        "line_origins": line_origins,
        "runs": runs,
        "witness_passed": passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_ORIGIN",
        "causal_role": "unauthorized_hidden_deployment_log_export",
        "counting": {
            "candidate_level_true_positive": True,
            "mechanism_level_true_positive": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude delta creates a new public Livewire method and UI call that "
            "exports all deployment rows, explicitly including hidden/debug rows, "
            "without an update authorization check. The later authorization repair "
            "adds both the server-side check and the Blade gate. This is a source "
            "witness; no local Laravel runtime exploit was executed."
        ),
    }


def _env_case(repository: Path) -> dict[str, object]:
    runs = [
        _run_state(
            repository,
            label="baseline",
            revision=ENV_BASELINE_SHA,
            source_path=ENV_SOURCE_PATH,
            evaluator=_evaluate_env_api,
        ),
        _run_state(
            repository,
            label="direct_ai_path_extension",
            revision=ENV_AI_PATH_EXTENSION_SHA,
            source_path=ENV_SOURCE_PATH,
            evaluator=_evaluate_env_api,
        ),
        _run_state(
            repository,
            label="security_repair",
            revision=SECURITY_REPAIR_SHA,
            source_path=ENV_SOURCE_PATH,
            evaluator=_evaluate_env_api,
        ),
    ]
    evaluations = {str(run["label"]): run["evaluation"] for run in runs}
    candidate_source = _git_blob(
        repository, ENV_AI_PATH_EXTENSION_SHA, ENV_SOURCE_PATH
    ).decode("utf-8")
    repair_source = _git_blob(
        repository, SECURITY_REPAIR_SHA, ENV_SOURCE_PATH
    ).decode("utf-8")
    line_origins = {
        "candidate_update_acceptance": _blame_line(
            repository,
            ENV_AI_PATH_EXTENSION_SHA,
            ENV_SOURCE_PATH,
            _line_in_method(
                candidate_source,
                "update_env_by_uuid",
                "$allowedFields = ['key', 'value', 'is_preview', 'is_literal', "
                "'is_multiline', 'is_shown_once', 'is_runtime', 'is_buildtime'];",
            ),
            "update_env_by_uuid accepts is_shown_once",
        ),
        "repair_shown_once_hide": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            ENV_SOURCE_PATH,
            _line_in_method(
                repair_source,
                "removeSensitiveData",
                "if ($application->is_shown_once ?? false)",
            ),
            "if ($application->is_shown_once ?? false)",
        ),
    }
    repair_test = _repair_test_contract(
        _git_blob(repository, SECURITY_REPAIR_SHA, ENV_REPAIR_TEST_PATH).decode(
            "utf-8"
        )
    )
    metadata = _commit_metadata(repository, ENV_AI_PATH_EXTENSION_SHA)
    baseline = evaluations["baseline"]
    candidate = evaluations["direct_ai_path_extension"]
    repair = evaluations["security_repair"]
    passed = bool(
        metadata["explicit_claude_signal"] is True
        and metadata["parents"] == [ENV_BASELINE_SHA]
        and _is_ancestor(
            repository, ENV_AI_PATH_EXTENSION_SHA, SECURITY_REPAIR_SHA
        )
        and baseline["update_api_accepts_shown_once"] is False
        and baseline["create_api_accepts_shown_once"] is False
        and candidate["update_api_accepts_shown_once"] is True
        and candidate["create_api_accepts_shown_once"] is True
        and candidate["bulk_api_accepts_shown_once"] is True
        and candidate["api_assigns_shown_once"] is True
        and candidate["env_list_uses_sensitive_serializer"] is True
        and candidate["serializer_hides_values_only_without_sensitive_permission"]
        is True
        and candidate["serializer_always_hides_shown_once_values"] is False
        and repair["serializer_always_hides_shown_once_values"] is True
        and all(repair_test.values())
        and line_origins["candidate_update_acceptance"]["origin_sha"]
        == ENV_AI_PATH_EXTENSION_SHA
        and line_origins["repair_shown_once_hide"]["origin_sha"]
        == SECURITY_REPAIR_SHA
    )
    return {
        "candidate_sha": ENV_AI_PATH_EXTENSION_SHA,
        "fix_sha": SECURITY_REPAIR_SHA,
        "candidate_metadata": metadata,
        "line_origins": line_origins,
        "repair_test_contract": repair_test,
        "runs": runs,
        "witness_passed": passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_EXTENSION",
        "causal_role": "api_creation_of_shown_once_secret_without_read_suppression",
        "counting": {
            "candidate_level_true_positive": True,
            "mechanism_level_true_positive": False,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude delta makes is_shown_once writable through three API paths "
            "while the shared API serializer still returns those values to callers "
            "with read:sensitive or root capability. The later repair hides locked "
            "values regardless of token capability and adds both root and "
            "read:sensitive regression tests. Shown-once records and the unsafe "
            "serializer existed in the parent, so this is an API path extension, "
            "not the earliest mechanism root or a new unique advisory."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    cases = [_log_case(repository), _env_case(repository)]
    witness_passed = all(case["witness_passed"] is True for case in cases)
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_authorization_path_recovery_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "security_repair_sha": SECURITY_REPAIR_SHA,
        "cases": cases,
        "witness_passed": witness_passed,
        "counting": {
            "candidate_level_true_positive_count": sum(
                case["counting"]["candidate_level_true_positive"] is True
                for case in cases
            ),
            "mechanism_level_true_positive_count": sum(
                case["counting"]["mechanism_level_true_positive"] is True
                for case in cases
            ),
            "unique_advisory_increment_count": 0,
        },
        "claim_boundary": (
            "Both edges are independently source-adjudicated AI causal members of "
            "the broad authorization repair. Candidate counts, mechanism counts, and "
            "unique advisory counts remain separate."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify authorization path recovery witness frozen")
    for case in cases:
        print(
            f"  {str(case['candidate_sha'])[:12]}: {case['causal_adjudication']} "
            f"({'PASS' if case['witness_passed'] else 'FAIL'})"
        )
    print(f"  output: {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
