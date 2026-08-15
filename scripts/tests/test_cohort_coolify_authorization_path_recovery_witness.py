"""Tests for recovered Coolify authorization/data-exposure path witnesses."""

from __future__ import annotations

import cohort_coolify_authorization_path_recovery_witness as witness


def _log_source(*, method: bool, authorized: bool) -> str:
    body = ""
    if method:
        authorization = (
            "$this->authorize('update', $this->application);"
            if authorized
            else ""
        )
        body = f"""
public function downloadAllLogs(): string
{{
    {authorization}
    $logs = decode_remote_command_output($queue, includeAll: true);
    if ($line['hidden']) {{ $prefix = '[DEBUG] '; }}
}}
"""
    return f"<?php class Show {{ {body} }}"


def test_log_export_baseline_candidate_and_repair_states() -> None:
    baseline = witness._evaluate_log_export(_log_source(method=False, authorized=False), "")
    candidate = witness._evaluate_log_export(
        _log_source(method=True, authorized=False),
        "$wire.downloadAllLogs()",
    )
    repair = witness._evaluate_log_export(
        _log_source(method=True, authorized=True),
        "@can('update', $application) $wire.downloadAllLogs() @endcan",
    )

    assert baseline["public_download_all_logs_method"] is False
    assert candidate["exports_include_all_log_rows"] is True
    assert candidate["explicitly_serializes_hidden_debug_rows"] is True
    assert candidate["method_has_update_authorization"] is False
    assert repair["method_has_update_authorization"] is True
    assert repair["view_has_update_gate"] is True


def _env_source(*, accepts: bool, hides: bool) -> str:
    allowed = (
        "$allowedFields = ['key', 'value', 'is_preview', 'is_literal', "
        "'is_multiline', 'is_shown_once', 'is_runtime', 'is_buildtime'];"
        if accepts
        else "$allowedFields = ['key', 'value', 'is_preview', 'is_literal'];"
    )
    hide = (
        "if ($application->is_shown_once ?? false) { "
        "$application->makeHidden(['value', 'real_value']); }"
        if hides
        else ""
    )
    return f"""<?php
class ApplicationsController {{
private function removeSensitiveData($application) {{
    if (request()->attributes->get('can_read_sensitive', false) === false) {{
        $application->makeHidden(['value', 'real_value']);
    }}
    {hide}
}}
public function envs(Request $request) {{
    return $this->removeSensitiveData($env);
}}
public function update_env_by_uuid(Request $request) {{ {allowed} }}
public function create_bulk_envs(Request $request) {{ {allowed} }}
public function create_env(Request $request) {{
    {allowed}
    $env = $application->environment_variables()->create([
        'is_shown_once' => $request->is_shown_once ?? false,
    ]);
}}
}}
"""


def test_env_api_baseline_candidate_and_repair_states() -> None:
    baseline = witness._evaluate_env_api(_env_source(accepts=False, hides=False))
    candidate = witness._evaluate_env_api(_env_source(accepts=True, hides=False))
    repair = witness._evaluate_env_api(_env_source(accepts=True, hides=True))

    assert baseline["update_api_accepts_shown_once"] is False
    assert candidate["update_api_accepts_shown_once"] is True
    assert candidate["create_api_accepts_shown_once"] is True
    assert candidate["bulk_api_accepts_shown_once"] is True
    assert candidate["serializer_always_hides_shown_once_values"] is False
    assert repair["serializer_always_hides_shown_once_values"] is True


def test_repair_test_contract_requires_locked_and_unlocked_cases() -> None:
    source = """
'is_shown_once' => true,
'value' => 'secret-locked-value',
test('API hides locked env value even with read:sensitive token', function () {});
test('API hides locked env value with root token', function () {});
expect($locked)->not->toHaveKey('value');
expect($locked)->not->toHaveKey('real_value');
expect($unlocked)->toHaveKey('value');
"""

    assert all(witness._repair_test_contract(source).values())
