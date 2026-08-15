"""Tests for the recovered Conductor TrustHosts cold-cache bypass witness."""

from __future__ import annotations

from cohort_coolify_conductor_trust_hosts_origin_witness import (
    CACHE_GET,
    CACHE_REMEMBER,
    EARLY_RETURN,
    POPULATE_CALL,
    _evaluate_versions,
)


def _source(handle: str, hosts: str, extra: str = "") -> str:
    return (
        "<?php\nclass TrustHosts {\n"
        f"public function handle($request, $next) {{\n{handle}\n}}\n"
        f"public function hosts(): array {{\n{hosts}\n}}\n"
        f"{extra}\n"
        "}\n"
    )


def test_versions_require_candidate_cold_cache_bypass_and_exact_repair() -> None:
    baseline = _source(
        "return parent::handle($request, $next);",
        f"$fqdnHost = {CACHE_REMEMBER}, fn () => '');",
    )
    candidate = _source(
        f"{CACHE_GET}\n{EARLY_RETURN} return $next($request); }}\n"
        "return parent::handle($request, $next);",
        f"$fqdnHost = {CACHE_REMEMBER}, fn () => '');",
    )
    fix = _source(
        f"{POPULATE_CALL}\n{CACHE_GET}\n{EARLY_RETURN} return $next($request); }}\n"
        "return response('Bad Host', 400);",
        f"$fqdnHost = {CACHE_REMEMBER}, fn () => '');",
        "protected function isHostTrusted() {}\n// X-Forwarded-Host",
    )

    assert all(_evaluate_versions(baseline, candidate, candidate, fix).values())


def test_versions_fail_when_candidate_populates_cache_before_read() -> None:
    baseline = _source(
        "return parent::handle($request, $next);",
        f"$fqdnHost = {CACHE_REMEMBER}, fn () => '');",
    )
    already_safe = _source(
        f"{POPULATE_CALL}\n{CACHE_GET}\n{EARLY_RETURN} return $next($request); }}\n"
        "return parent::handle($request, $next);",
        f"$fqdnHost = {CACHE_REMEMBER}, fn () => '');",
    )
    result = _evaluate_versions(baseline, already_safe, already_safe, already_safe)

    assert result["candidate_reads_cold_cache_before_parent_validation"] is False
