"""Tests for the ChurchCRM mixed-origin setup-password witness."""

from __future__ import annotations

import cohort_churchcrm_setup_password_compositional_witness as witness


TEMPLATE = """<?php
$sPASSWORD = '||DB_PASSWORD||';
"""


STRICT_ROUTE = r"""
if (!isset($setupData['DB_PASSWORD'])) {
    $errors['DB_PASSWORD'] = 'Missing DB_PASSWORD';
} elseif (!is_valid_db_field($setupData['DB_PASSWORD'])) {
    $errors['DB_PASSWORD'] = 'Invalid DB_PASSWORD';
}
$dbPassword = $setupData['DB_PASSWORD'];
$template = str_replace('||DB_PASSWORD||', $dbPassword, $template);
function is_valid_db_field($value)
{
    return preg_match('/^[a-zA-Z0-9_\-\.:\@]+$/', $value);
}
function is_valid_db_password($value)
{
    return strlen($value) > 0;
}
"""


ACTIVATED_ROUTE = STRICT_ROUTE.replace(
    "!is_valid_db_field($setupData['DB_PASSWORD'])",
    "!is_valid_db_password($setupData['DB_PASSWORD'])",
)


def test_latent_helper_does_not_make_the_strict_route_vulnerable() -> None:
    result = witness._evaluate_source(STRICT_ROUTE, TEMPLATE)

    assert result["permissive_password_helper_present"] is True
    assert result["permissive_password_helper_accepts_witness"] is True
    assert result["selected_password_validator"] == "is_valid_db_field"
    assert result["selected_validator_accepts_witness"] is False
    assert result["harmless_php_statement_emitted"] is False


def test_missing_old_validator_is_recorded_as_broken_not_as_accepting() -> None:
    missing_old_helper = STRICT_ROUTE.replace(
        "function is_valid_db_field($value)\n"
        "{\n"
        "    return preg_match('/^[a-zA-Z0-9_\\-\\.:\\@]+$/', $value);\n"
        "}\n",
        "",
    )

    result = witness._evaluate_source(missing_old_helper, TEMPLATE)

    assert result["selected_password_validator"] == "is_valid_db_field"
    assert result["selected_validator_present"] is False
    assert result["selected_validator_outcome"] == "missing_function_runtime_error"
    assert result["permissive_password_helper_accepts_witness"] is True
    assert result["harmless_php_statement_emitted"] is False


def test_human_selection_of_latent_helper_reaches_quoted_php_template() -> None:
    result = witness._evaluate_source(ACTIVATED_ROUTE, TEMPLATE)

    assert result["selected_password_validator"] == "is_valid_db_password"
    assert result["selected_validator_accepts_witness"] is True
    assert result["raw_password_reaches_template"] is True
    assert result["harmless_php_statement_emitted"] is True
    assert result["rendered_password_line"] == (
        "$sPASSWORD = 'test123'; $AI_SLOP_WITNESS='reachable'; //';"
    )


def test_sanitized_assignment_is_not_treated_as_raw_template_reachability() -> None:
    sanitized = ACTIVATED_ROUTE.replace(
        "$dbPassword = $setupData['DB_PASSWORD'];",
        "$dbPassword = sanitize_db_field($setupData['DB_PASSWORD']);",
    )

    result = witness._evaluate_source(sanitized, TEMPLATE)

    assert result["selected_validator_accepts_witness"] is True
    assert result["password_assignment"] == "sanitize_db_field"
    assert result["raw_password_reaches_template"] is False
    assert result["harmless_php_statement_emitted"] is False
