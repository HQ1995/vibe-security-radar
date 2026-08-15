"""Tests for the Coolify Sentinel restart activation witness."""

from __future__ import annotations

import cohort_coolify_sentinel_restart_activation_witness as witness


def test_trigger_contract_distinguishes_ineffective_and_effective_hooks() -> None:
    baseline = """
static::updated(function ($settings) {
    if ($settings->isDirty('sentinel_token')) {
        $settings->server->restartSentinel();
    }
});
"""
    candidate = baseline.replace("isDirty", "wasChanged")

    before = witness._evaluate_setting_trigger(baseline)
    after = witness._evaluate_setting_trigger(candidate)

    assert before["uses_post_update_is_dirty_for_token"] is True
    assert before["uses_post_update_was_changed_for_token"] is False
    assert after["uses_post_update_is_dirty_for_token"] is False
    assert after["uses_post_update_was_changed_for_token"] is True
    assert after["changed_token_dispatches_restart"] is True


def test_ui_write_contract_requires_validation_persistence_and_save() -> None:
    source = """<?php class Show {
public string $sentinelToken;
protected function rules() { return ['sentinelToken' => 'required']; }
public function syncData(bool $toModel = false) {
    $this->validate();
    $this->server->settings->sentinel_token = $this->sentinelToken;
    $this->server->settings->save();
}
} """

    assert all(witness._evaluate_ui_write(source).values())


def test_start_sink_contract_distinguishes_unsafe_and_repaired_forms() -> None:
    unsafe = """<?php class StartSentinel {
public function handle() {
    $token = data_get($server, 'settings.sentinel_token');
    $environments = ['TOKEN' => $token];
    $dockerEnvironments = '-e "'.implode('" -e "', $environments).'"';
    $dockerCommand = "docker run $dockerEnvironments";
    instant_remote_process([$dockerCommand], $server);
}
} """
    repaired = unsafe.replace(
        "$environments = ['TOKEN' => $token];",
        "if (! ServerSetting::isValidSentinelToken($token)) { throw new Exception(); }\n"
        "    $environments = ['TOKEN' => $token];\n"
        '    $quoted = escapeshellarg("$key=$value");',
    )

    before = witness._evaluate_start_sink(unsafe)
    after = witness._evaluate_start_sink(repaired)

    assert before["builds_double_quoted_environment_without_shell_escaping"] is True
    assert before["validates_token_before_sink"] is False
    assert after["validates_token_before_sink"] is True
    assert after["shell_quotes_environment"] is True


def test_activation_and_security_repair_tests_are_explicit() -> None:
    activation = """
it('detects sentinel_token changes with wasChanged', function () {
    $settings->sentinel_token = 'new-token-value';
    $settings->save();
    expect($changeDetected)->toBeTrue();
});
"""
    repair_setting = """
public static function isValidSentinelToken(string $token): bool {
    return (bool) preg_match('/\\A[a-zA-Z0-9._\\-+=\\/]+\\z/', $token);
}
"""
    repair_start = """
ServerSetting::isValidSentinelToken($token);
$quoted = escapeshellarg("$key=$value");
"""
    repair_test = """
it('rejects the reported PoC payload', fn () =>
    'abc" ; id >/tmp/coolify_poc_sentinel ; echo "');
"""

    assert all(witness._evaluate_activation_test(activation).values())
    assert all(
        witness._evaluate_repair(
            repair_setting, repair_start, repair_test
        ).values()
    )
