"""Tests for the Conductor healthcheck-removal reset origin witness."""

from __future__ import annotations

from cohort_coolify_conductor_healthcheck_reset_origin_witness import (
    ABSENT_DOCKERFILE,
    ACTIVE_DOCKERFILE,
    ASSIGNED_SUBSTRING_PREDICATE,
    CLAIM_BOUNDARY,
    COMMENT_ONLY_DOCKERFILE,
    COMMENT_TEST_MARKER,
    FIX_COMMENT_SKIP,
    FIX_DIRECTIVE_MATCH,
    INLINE_SUBSTRING_PREDICATE,
    MID_LINE_DOCKERFILE,
    MID_LINE_TEST_MARKER,
    RESET_GATE,
    RESET_MARKERS,
    TEST_HELPER_MARKER,
    _behavior_case,
    _behavior_matrix,
    _evaluate_behavior,
    _evaluate_versions,
)


def _source(body: str) -> str:
    return (
        "<?php\nclass Application {\n"
        "public function parseHealthcheckFromDockerfile($dockerfile) {\n"
        f"{body}\n"
        "}\n"
        "public function nextMethod() {}\n"
        "}\n"
    )


def _reset_body() -> str:
    return "\n".join((RESET_GATE, *RESET_MARKERS, "}"))


def _valid_versions() -> tuple[str, str, str, str, str, str]:
    baseline = _source(f"{INLINE_SUBSTRING_PREDICATE} true) {{ return; }}")
    candidate = _source(
        "\n".join(
            (
                ASSIGNED_SUBSTRING_PREDICATE,
                "if ($hasHealthcheck) { return; } else" + _reset_body(),
            )
        )
    )
    fix_parent = _source("\n".join((ASSIGNED_SUBSTRING_PREDICATE, _reset_body())))
    fix = _source(
        "\n".join(
            (
                "$hasHealthcheck = false;",
                "foreach ($dockerfile as $line) {",
                "$trimmedLine = trim($line);",
                FIX_COMMENT_SKIP,
                "continue;",
                "}",
                FIX_DIRECTIVE_MATCH,
                "$hasHealthcheck = true;",
                "break;",
                "}",
                "}",
                _reset_body(),
            )
        )
    )
    fix_parent_tests = ASSIGNED_SUBSTRING_PREDICATE
    fix_tests = "\n".join(
        (COMMENT_TEST_MARKER, MID_LINE_TEST_MARKER, TEST_HELPER_MARKER)
    )
    return baseline, candidate, fix_parent, fix, fix_parent_tests, fix_tests


def test_versions_require_preexisting_predicate_new_reset_and_exact_fix() -> None:
    assert all(_evaluate_versions(*_valid_versions()).values())


def test_versions_fail_if_reset_feature_already_exists_in_baseline() -> None:
    versions = list(_valid_versions())
    versions[0] = _source(
        "\n".join(
            (
                ASSIGNED_SUBSTRING_PREDICATE,
                _reset_body(),
            )
        )
    )

    result = _evaluate_versions(*versions)

    assert result["baseline_has_no_removal_reset_feature"] is False


def test_versions_fail_if_fix_keeps_substring_detection() -> None:
    versions = list(_valid_versions())
    versions[3] = versions[2]

    result = _evaluate_versions(*versions)

    assert result["fix_replaces_substring_with_linewise_detection"] is False


def test_comment_only_input_exposes_candidate_failure_and_fix_recovery() -> None:
    result = _behavior_case(COMMENT_ONLY_DOCKERFILE)

    assert result == {
        "substring_has_healthcheck": True,
        "linewise_has_uncommented_healthcheck": False,
        "candidate_reset_executes": False,
        "fix_reset_executes": True,
    }


def test_behavior_matrix_keeps_positive_and_negative_controls() -> None:
    matrix = _behavior_matrix()

    assert all(_evaluate_behavior(matrix).values())
    assert _behavior_case(MID_LINE_DOCKERFILE)["fix_reset_executes"] is True
    assert _behavior_case(ACTIVE_DOCKERFILE)["fix_reset_executes"] is False
    assert _behavior_case(ABSENT_DOCKERFILE)["candidate_reset_executes"] is True


def test_claim_boundary_does_not_claim_general_parser_origin() -> None:
    assert "does not originate Coolify's general substring" in CLAIM_BOUNDARY
    assert "human 2024 parser commit" in CLAIM_BOUNDARY
    assert "not counted as a second candidate or edge" in CLAIM_BOUNDARY
