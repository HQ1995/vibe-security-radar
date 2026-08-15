"""Tests for topology-carrier causal mechanism predicates."""

from __future__ import annotations

from cohort_ai_topology_carrier_causal_batch_witness import _semantic_checks


def test_missing_job_argument_predicate_requires_constructor_and_repair() -> None:
    candidate = "+                CheckTraefikVersionForServerJob::dispatch($this->server);"
    fixed = """-                CheckTraefikVersionForServerJob::dispatch($this->server);
+                CheckTraefikVersionForServerJob::dispatch($this->server, get_traefik_versions());
"""
    state = """public function __construct(
public Server $server,
public array $traefikVersions
"""

    checks = _semantic_checks(
        "traefik_restart_job_missing_versions_argument",
        candidate_diff=candidate,
        carrier_diff=candidate,
        fix_diff=fixed,
        carrier_state=state,
    )

    assert all(checks.values())


def test_unscoped_delete_predicate_requires_grouping_repair() -> None:
    candidate = """$application->environment_variables()
->where('key', 'LIKE', 'SERVICE_FQDN_%')
->orWhere('key', 'LIKE', 'SERVICE_URL_%')
->delete();
"""
    fixed = """+                        ->where(function ($q)
+                                ->orWhere('key', 'LIKE', 'SERVICE_URL_%');
+                        ->where(function ($q)
"""
    state = """morphMany(EnvironmentVariable::class, 'resourceable')
->where('is_preview', false)
->where('is_preview', true)
"""

    checks = _semantic_checks(
        "application_env_cleanup_unscoped_or_where",
        candidate_diff=candidate,
        carrier_diff=candidate,
        fix_diff=fixed,
        carrier_state=state,
    )

    assert all(checks.values())
