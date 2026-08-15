"""Tests for the Coolify updateCompose map-style causal witness."""

from __future__ import annotations

import cohort_coolify_update_compose_map_style_origin_witness as witness


def test_candidate_underaccepts_map_style_while_fix_accepts_both_formats() -> None:
    result = witness._semantic_witness()

    assert result["passed"] is True
    assert all(result["checks"].values())
    assert result["candidate_map_extraction"] == []
    assert result["fixed_map_extraction"] == [
        "SERVICE_URL_TRIGGER_3000",
        "SERVICE_FQDN_DB",
    ]
    assert result["candidate_list_extraction"] == result["fixed_list_extraction"]


def test_map_values_that_reference_service_urls_are_not_promoted() -> None:
    environment = {
        "SERVICE_URL_APP_3000": "",
        "NEXT_PUBLIC_URL": "${SERVICE_URL_APP_3000}",
        "API_ENDPOINT": "${SERVICE_URL_API}",
    }

    assert witness._candidate_extract_template_names(environment) == []
    assert witness._fixed_extract_template_names(environment) == [
        "SERVICE_URL_APP_3000"
    ]


def test_source_predicates_bind_origin_repair_templates_and_tests() -> None:
    baseline = """
$serviceName = str($resource->name)->upper();
->where('key', 'LIKE', "SERVICE_URL_{$serviceName}%");
->where('key', 'LIKE', "SERVICE_FQDN_{$serviceName}%");
"""
    candidate = """
$environment = data_get($serviceConfig, 'environment', []);
$templateVariableNames = [];
foreach ($environment as $envVar) {
    if (is_string($envVar)) {
        $templateVariableNames[] = $envVarName->value();
    }
}
"""
    repair = """
foreach ($environment as $key => $value) {
    if (is_int($key) && is_string($value)) {
    } elseif (is_string($key)) {
        $envVarName = str($key);
    }
}
"""
    fix_tests = "\n".join(witness.FIX_TEST_NAMES)
    template_versions = {
        path: (marker, marker, marker)
        for path, marker in witness.MAP_TEMPLATE_MARKERS.items()
    }

    checks = witness._evaluate_sources(
        baseline,
        candidate,
        repair,
        "candidate list-only tests",
        fix_tests,
        template_versions,
    )

    assert all(checks.values())
