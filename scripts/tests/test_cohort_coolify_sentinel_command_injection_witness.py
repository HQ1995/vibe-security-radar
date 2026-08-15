"""Tests for the Coolify Sentinel command-injection witness."""

from __future__ import annotations

import cohort_coolify_sentinel_command_injection_witness as witness


def _ui(*, safe: bool) -> str:
    validation = (
        "#[Validate(['required', 'string', 'max:500', "
        "'regex:/\\A[a-zA-Z0-9._\\-+=\\/]+\\z/'])]"
        if safe
        else "#[Validate(['required'])]"
    )
    return f"""<?php class Sentinel {{
{validation}
public string $sentinelToken;
public function syncData(bool $toModel = false) {{
    $this->authorize('update', $this->server);
    $this->validate();
    $this->server->settings->sentinel_token = $this->sentinelToken;
}}
}}"""


def test_ui_preservation_and_repair_contract() -> None:
    view = """<form wire:submit.prevent='submit'>
    <x-forms.input id="sentinelToken" />
</form>"""
    candidate = witness._evaluate_ui(_ui(safe=False), view)
    repair = witness._evaluate_ui(_ui(safe=True), view)

    assert candidate["required_only_token_validation"] is True
    assert candidate["safe_character_validation"] is False
    assert candidate["sync_persists_token"] is True
    assert candidate["view_binds_token_input"] is True
    assert repair["safe_character_validation"] is True


def test_metrics_sink_preservation_and_repair_contract() -> None:
    unsafe = """
instant_remote_process(
    ["docker exec coolify-sentinel sh -c 'curl -H \\"Authorization: Bearer {$server->settings->sentinel_token}\\" {$endpoint}'"],
    $server,
);
"""
    safe = """
$token = $server->settings->sentinel_token;
if (! ServerSetting::isValidSentinelToken($token)) { throw new Exception(); }
instant_remote_process(
    ["docker exec coolify-sentinel sh -c 'curl -H \\"Authorization: Bearer {$token}\\" {$endpoint}'"],
    $server,
);
"""
    candidate = witness._evaluate_metrics(unsafe)
    repair = witness._evaluate_metrics(safe)

    assert candidate["directly_interpolates_stored_token"] is True
    assert candidate["validates_stored_token"] is False
    assert repair["directly_interpolates_stored_token"] is False
    assert repair["validates_stored_token"] is True
    assert repair["uses_validated_token_variable"] is True


def test_start_sink_and_reported_poc_contract() -> None:
    source = """<?php class StartSentinel {
public function handle() {
    $token = data_get($server, 'settings.sentinel_token');
    if (! ServerSetting::isValidSentinelToken($token)) { throw new Exception(); }
    $environments = ['TOKEN' => $token];
    $dockerEnvironments = escapeshellarg("$key=$value");
    $dockerCommand = "docker run $dockerEnvironments";
    instant_remote_process([$dockerCommand], $server);
}}
}"""
    repair_test = """
it('rejects tokens with double quotes', fn () => 'abc" ; id ; echo "');
it('rejects tokens with dollar sign command substitution', fn () => 'abc$(whoami)');
it('accepts tokens with base64 characters', fn () => 'abc+def/ghi=');
it('rejects the reported PoC payload', fn () => 'id >/tmp/coolify_poc_sentinel');
"""

    assert all(witness._evaluate_start_sentinel(source).values())
    assert all(witness._evaluate_repair_test(repair_test).values())
