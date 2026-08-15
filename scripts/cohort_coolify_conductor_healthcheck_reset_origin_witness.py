#!/usr/bin/env python3
"""Freeze the Conductor healthcheck-removal reset causal origin."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


REPOSITORY_IDENTITY = "github.com/coollabsio/coolify"
PREEXISTING_PREDICATE_ORIGIN_SHA = "16278f36ec69f55b3f1de9fb754eac9678f40b68"
CANDIDATE_SHA = "51bada187192d8a21aae7a7709bb0409da473ff1"
CANDIDATE_PARENT_SHA = "1a7671f66d64c6ede948704456120080f3b3106d"
INTEGRATION_MERGE_SHA = "cb5462abfd89fde22a5088ce628ca9e2616907a3"
RESET_REWORK_SHA = "466772f61ac58679d7ae3920b3b486cb3b64a753"
FIX_PARENT_SHA = "587517394b05e249bf56107f7f8a9822d53fa23e"
FIX_SHA = "670c9dab0dceecdda6ac1858e2a4b65317ac8088"

SOURCE_PATH = "app/Models/Application.php"
TEST_PATH = "tests/Unit/ApplicationHealthcheckRemovalTest.php"
METHOD_NAME = "parseHealthcheckFromDockerfile"
CONDUCTOR_MARKER = "Changes auto-committed by Conductor"

INLINE_SUBSTRING_PREDICATE = "if (str($dockerfile)->contains('HEALTHCHECK') &&"
ASSIGNED_SUBSTRING_PREDICATE = (
    "$hasHealthcheck = str($dockerfile)->contains('HEALTHCHECK');"
)
RESET_GATE = "if (! $hasHealthcheck && $this->custom_healthcheck_found) {"
RESET_MARKERS = (
    "$this->custom_healthcheck_found = false;",
    "$this->health_check_interval = 5;",
    "$this->health_check_timeout = 5;",
    "$this->health_check_retries = 10;",
    "$this->health_check_start_period = 5;",
    "$this->save();",
)
FIX_COMMENT_SKIP = "if (empty($trimmedLine) || str_starts_with($trimmedLine, '#')) {"
FIX_DIRECTIVE_MATCH = "if (str_starts_with($trimmedLine, 'HEALTHCHECK')) {"
COMMENT_TEST_MARKER = "it('ignores commented HEALTHCHECK in dockerfile'"
MID_LINE_TEST_MARKER = "it('ignores HEALTHCHECK in middle of line (must be at start)'"
TEST_HELPER_MARKER = "function hasUncommentedHealthcheck(string $dockerfile)"

COMMENT_ONLY_DOCKERFILE = (
    "FROM nginx:latest\n  # HEALTHCHECK --interval=30s CMD curl\nEXPOSE 80"
)
MID_LINE_DOCKERFILE = "FROM nginx:latest\nRUN echo HEALTHCHECK\nEXPOSE 80"
ACTIVE_DOCKERFILE = (
    "FROM nginx:latest\n  HEALTHCHECK --interval=30s CMD curl\nEXPOSE 80"
)
ABSENT_DOCKERFILE = "FROM nginx:latest\nCOPY . /app\nEXPOSE 80"

CLAIM_BOUNDARY = (
    "The exact Conductor commit does not originate Coolify's general substring "
    "HEALTHCHECK parser: blame traces that pre-existing predicate to the human "
    "2024 parser commit. It does, however, first connect the predicate to a new "
    "automatic reset path for removed Dockerfile healthchecks. A comment-only "
    "directive therefore remains substring-present and blocks the new reset. The "
    "same candidate-authored predicate survives to the repair parent; the repair "
    "replaces it with line-by-line detection that skips comments and adds explicit "
    "comment and mid-line regression tests. The later Conductor reset rework is a "
    "non-originating carrier and is not counted as a second candidate or edge."
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(
    repository: Path,
    revision: str,
    source_path: str = SOURCE_PATH,
) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_record(
    repository: Path,
    revision: str,
    source_path: str,
) -> dict[str, str]:
    blob = _git_blob(repository, revision, source_path)
    return {
        "revision": revision,
        "path": source_path,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _line_number(source: str, marker: str) -> int:
    matches = [
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one {marker!r} line, found {matches}")
    return matches[0]


def _substring_has_healthcheck(dockerfile: str) -> bool:
    return "HEALTHCHECK" in dockerfile


def _linewise_has_uncommented_healthcheck(dockerfile: str) -> bool:
    for line in dockerfile.splitlines():
        trimmed_line = line.strip()
        if not trimmed_line or trimmed_line.startswith("#"):
            continue
        if trimmed_line.startswith("HEALTHCHECK"):
            return True
    return False


def _behavior_case(dockerfile: str) -> dict[str, bool]:
    substring_has_healthcheck = _substring_has_healthcheck(dockerfile)
    linewise_has_healthcheck = _linewise_has_uncommented_healthcheck(dockerfile)
    return {
        "substring_has_healthcheck": substring_has_healthcheck,
        "linewise_has_uncommented_healthcheck": linewise_has_healthcheck,
        "candidate_reset_executes": not substring_has_healthcheck,
        "fix_reset_executes": not linewise_has_healthcheck,
    }


def _behavior_matrix() -> dict[str, dict[str, bool]]:
    return {
        "comment_only": _behavior_case(COMMENT_ONLY_DOCKERFILE),
        "healthcheck_in_middle_of_line": _behavior_case(MID_LINE_DOCKERFILE),
        "active_directive": _behavior_case(ACTIVE_DOCKERFILE),
        "directive_absent": _behavior_case(ABSENT_DOCKERFILE),
    }


def _evaluate_behavior(
    matrix: dict[str, dict[str, bool]],
) -> dict[str, bool]:
    comment_only = matrix["comment_only"]
    middle = matrix["healthcheck_in_middle_of_line"]
    active = matrix["active_directive"]
    absent = matrix["directive_absent"]
    return {
        "comment_only_is_false_positive_for_candidate_predicate": (
            comment_only["substring_has_healthcheck"]
            and not comment_only["linewise_has_uncommented_healthcheck"]
        ),
        "comment_only_blocks_candidate_reset_but_fix_resets": (
            not comment_only["candidate_reset_executes"]
            and comment_only["fix_reset_executes"]
        ),
        "mid_line_token_blocks_candidate_reset_but_fix_resets": (
            not middle["candidate_reset_executes"] and middle["fix_reset_executes"]
        ),
        "active_directive_remains_present_without_reset": (
            active["substring_has_healthcheck"]
            and active["linewise_has_uncommented_healthcheck"]
            and not active["candidate_reset_executes"]
            and not active["fix_reset_executes"]
        ),
        "absent_directive_resets_in_both_versions": (
            not absent["substring_has_healthcheck"]
            and not absent["linewise_has_uncommented_healthcheck"]
            and absent["candidate_reset_executes"]
            and absent["fix_reset_executes"]
        ),
    }


def _evaluate_versions(
    baseline: str,
    candidate: str,
    fix_parent: str,
    fix: str,
    fix_parent_tests: str,
    fix_tests: str,
) -> dict[str, bool]:
    baseline_method = _php_method_region(baseline, METHOD_NAME)
    candidate_method = _php_method_region(candidate, METHOD_NAME)
    fix_parent_method = _php_method_region(fix_parent, METHOD_NAME)
    fix_method = _php_method_region(fix, METHOD_NAME)

    return {
        "baseline_has_preexisting_substring_predicate": (
            INLINE_SUBSTRING_PREDICATE in baseline_method
        ),
        "baseline_has_no_removal_reset_feature": (
            RESET_GATE not in baseline_method
            and not any(marker in baseline_method for marker in RESET_MARKERS[:-1])
        ),
        "candidate_reuses_substring_predicate": (
            ASSIGNED_SUBSTRING_PREDICATE in candidate_method
        ),
        "candidate_first_connects_predicate_to_removal_reset": (
            RESET_GATE in candidate_method
            and all(marker in candidate_method for marker in RESET_MARKERS)
            and candidate_method.index(ASSIGNED_SUBSTRING_PREDICATE)
            < candidate_method.index(RESET_GATE)
        ),
        "fix_parent_preserves_candidate_substring_predicate": (
            ASSIGNED_SUBSTRING_PREDICATE in fix_parent_method
        ),
        "fix_parent_preserves_removal_reset_feature": (
            RESET_GATE in fix_parent_method
            and all(marker in fix_parent_method for marker in RESET_MARKERS)
        ),
        "fix_parent_tests_only_cover_naive_substring_cases": (
            ASSIGNED_SUBSTRING_PREDICATE in fix_parent_tests
            and COMMENT_TEST_MARKER not in fix_parent_tests
            and MID_LINE_TEST_MARKER not in fix_parent_tests
        ),
        "fix_replaces_substring_with_linewise_detection": (
            ASSIGNED_SUBSTRING_PREDICATE not in fix_method
            and FIX_COMMENT_SKIP in fix_method
            and FIX_DIRECTIVE_MATCH in fix_method
            and fix_method.index(FIX_COMMENT_SKIP)
            < fix_method.index(FIX_DIRECTIVE_MATCH)
            < fix_method.index(RESET_GATE)
        ),
        "fix_preserves_removal_reset_feature": (
            RESET_GATE in fix_method
            and all(marker in fix_method for marker in RESET_MARKERS)
        ),
        "fix_adds_comment_and_mid_line_regression_tests": (
            COMMENT_TEST_MARKER in fix_tests
            and MID_LINE_TEST_MARKER in fix_tests
            and TEST_HELPER_MARKER in fix_tests
        ),
    }


def _commit_distance(repository: Path) -> int:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "rev-list",
            "--count",
            f"{CANDIDATE_SHA}..{FIX_SHA}",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise SystemExit("cannot count candidate-to-fix commits")
    return int(completed.stdout.strip())


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline = _text_blob(repository, CANDIDATE_PARENT_SHA)
    candidate = _text_blob(repository, CANDIDATE_SHA)
    reset_rework = _text_blob(repository, RESET_REWORK_SHA)
    fix_parent = _text_blob(repository, FIX_PARENT_SHA)
    fix = _text_blob(repository, FIX_SHA)
    fix_parent_tests = _text_blob(repository, FIX_PARENT_SHA, TEST_PATH)
    fix_tests = _text_blob(repository, FIX_SHA, TEST_PATH)

    evaluation = _evaluate_versions(
        baseline,
        candidate,
        fix_parent,
        fix,
        fix_parent_tests,
        fix_tests,
    )
    behavior_matrix = _behavior_matrix()
    behavior_checks = _evaluate_behavior(behavior_matrix)

    preexisting_metadata = _commit_metadata(
        repository, PREEXISTING_PREDICATE_ORIGIN_SHA
    )
    candidate_metadata = _commit_metadata(repository, CANDIDATE_SHA)
    merge_metadata = _commit_metadata(repository, INTEGRATION_MERGE_SHA)
    rework_metadata = _commit_metadata(repository, RESET_REWORK_SHA)
    fix_parent_metadata = _commit_metadata(repository, FIX_PARENT_SHA)
    fix_metadata = _commit_metadata(repository, FIX_SHA)

    ancestry = {
        "preexisting_predicate_origin_precedes_candidate": _is_ancestor(
            repository, PREEXISTING_PREDICATE_ORIGIN_SHA, CANDIDATE_SHA
        ),
        "candidate_parent_is_exact": (
            candidate_metadata["parents"] == [CANDIDATE_PARENT_SHA]
        ),
        "integration_merge_contains_candidate": (
            merge_metadata["parents"] == [CANDIDATE_PARENT_SHA, CANDIDATE_SHA]
        ),
        "reset_rework_follows_integration_merge": (
            rework_metadata["parents"] == [INTEGRATION_MERGE_SHA]
        ),
        "fix_parent_follows_reset_rework": (
            fix_parent_metadata["parents"] == [RESET_REWORK_SHA]
        ),
        "fix_parent_is_exact": fix_metadata["parents"] == [FIX_PARENT_SHA],
        "candidate_strictly_precedes_fix": _is_ancestor(
            repository, CANDIDATE_SHA, FIX_SHA
        ),
        "fix_does_not_precede_candidate": not _is_ancestor(
            repository, FIX_SHA, CANDIDATE_SHA
        ),
        "rework_strictly_precedes_fix": _is_ancestor(
            repository, RESET_REWORK_SHA, FIX_SHA
        ),
    }

    line_origins = {
        "preexisting_inline_substring_predicate": _blame_line(
            repository,
            CANDIDATE_PARENT_SHA,
            SOURCE_PATH,
            _line_number(baseline, INLINE_SUBSTRING_PREDICATE),
            "pre-existing general substring predicate",
        ),
        "candidate_substring_assignment": _blame_line(
            repository,
            CANDIDATE_SHA,
            SOURCE_PATH,
            _line_number(candidate, ASSIGNED_SUBSTRING_PREDICATE),
            "candidate extraction of substring predicate",
        ),
        "candidate_removal_reset_gate": _blame_line(
            repository,
            CANDIDATE_SHA,
            SOURCE_PATH,
            _line_number(candidate, RESET_GATE),
            "candidate connection to new removal-reset feature",
        ),
        "fix_parent_substring_assignment": _blame_line(
            repository,
            FIX_PARENT_SHA,
            SOURCE_PATH,
            _line_number(fix_parent, ASSIGNED_SUBSTRING_PREDICATE),
            "candidate predicate surviving to fix parent",
        ),
        "fix_parent_reset_gate": _blame_line(
            repository,
            FIX_PARENT_SHA,
            SOURCE_PATH,
            _line_number(fix_parent, RESET_GATE),
            "later rework of the surviving removal-reset gate",
        ),
        "fix_linewise_comment_skip": _blame_line(
            repository,
            FIX_SHA,
            SOURCE_PATH,
            _line_number(fix, FIX_COMMENT_SKIP),
            "fix line-by-line comment exclusion",
        ),
        "fix_comment_regression_test": _blame_line(
            repository,
            FIX_SHA,
            TEST_PATH,
            _line_number(fix_tests, COMMENT_TEST_MARKER),
            "fix comment-only regression test",
        ),
    }

    carrier_checks = {
        "reset_rework_keeps_candidate_substring_predicate": (
            ASSIGNED_SUBSTRING_PREDICATE
            in _php_method_region(reset_rework, METHOD_NAME)
        ),
        "fix_parent_source_equals_reset_rework_source": (
            _git_blob(repository, FIX_PARENT_SHA, SOURCE_PATH)
            == _git_blob(repository, RESET_REWORK_SHA, SOURCE_PATH)
        ),
        "fix_parent_tests_equal_reset_rework_tests": (
            _git_blob(repository, FIX_PARENT_SHA, TEST_PATH)
            == _git_blob(repository, RESET_REWORK_SHA, TEST_PATH)
        ),
    }
    commit_distance_including_fix = _commit_distance(repository)

    witness_passed = bool(
        preexisting_metadata["explicit_claude_signal"] is False
        and preexisting_metadata["sha"] == PREEXISTING_PREDICATE_ORIGIN_SHA
        and candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["message"] == CONDUCTOR_MARKER
        and rework_metadata["explicit_claude_signal"] is True
        and rework_metadata["message"] == CONDUCTOR_MARKER
        and "properly ignore commented lines" in str(fix_metadata["message"])
        and all(ancestry.values())
        and all(evaluation.values())
        and all(behavior_checks.values())
        and all(carrier_checks.values())
        and line_origins["preexisting_inline_substring_predicate"]["origin_sha"]
        == PREEXISTING_PREDICATE_ORIGIN_SHA
        and line_origins["candidate_substring_assignment"]["origin_sha"]
        == CANDIDATE_SHA
        and line_origins["candidate_removal_reset_gate"]["origin_sha"] == CANDIDATE_SHA
        and line_origins["fix_parent_substring_assignment"]["origin_sha"]
        == CANDIDATE_SHA
        and line_origins["fix_parent_reset_gate"]["origin_sha"] == RESET_REWORK_SHA
        and line_origins["fix_linewise_comment_skip"]["origin_sha"] == FIX_SHA
        and line_origins["fix_comment_regression_test"]["origin_sha"] == FIX_SHA
        and commit_distance_including_fix == 4
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": ("coolify_conductor_healthcheck_reset_origin_witness"),
        "repository_identity": REPOSITORY_IDENTITY,
        "candidate_sha": CANDIDATE_SHA,
        "fix_sha": FIX_SHA,
        "preexisting_predicate_origin_sha": (PREEXISTING_PREDICATE_ORIGIN_SHA),
        "noncanonical_reset_rework_sha": RESET_REWORK_SHA,
        "preexisting_predicate_metadata": preexisting_metadata,
        "candidate_metadata": candidate_metadata,
        "integration_merge_metadata": merge_metadata,
        "reset_rework_metadata": rework_metadata,
        "fix_parent_metadata": fix_parent_metadata,
        "fix_metadata": fix_metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "behavior_matrix": behavior_matrix,
        "behavior_checks": behavior_checks,
        "line_origins": line_origins,
        "carrier_checks": carrier_checks,
        "candidate_to_fix_commit_count_including_fix": (commit_distance_including_fix),
        "intervening_commit_count": commit_distance_including_fix - 1,
        "source_blobs": [
            _blob_record(repository, CANDIDATE_PARENT_SHA, SOURCE_PATH),
            _blob_record(repository, CANDIDATE_SHA, SOURCE_PATH),
            _blob_record(repository, RESET_REWORK_SHA, SOURCE_PATH),
            _blob_record(repository, FIX_PARENT_SHA, SOURCE_PATH),
            _blob_record(repository, FIX_PARENT_SHA, TEST_PATH),
            _blob_record(repository, FIX_SHA, SOURCE_PATH),
            _blob_record(repository, FIX_SHA, TEST_PATH),
        ],
        "confirmed_edges": [
            {
                "candidate_sha": CANDIDATE_SHA,
                "fix_sha": FIX_SHA,
                "causal_role": "DIRECT_AI_COMPOSITIONAL_ORIGIN",
            }
        ],
        "non_counted_related_commits": [
            {
                "sha": PREEXISTING_PREDICATE_ORIGIN_SHA,
                "reason": (
                    "human origin of the general substring parser; not an AI candidate"
                ),
            },
            {
                "sha": RESET_REWORK_SHA,
                "reason": (
                    "moves the reset branch without changing comment-only "
                    "behavior; not a second causal origin"
                ),
            },
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": ("CONFIRMED_DIRECT_AI_COMPOSITIONAL_ORIGIN"),
        "mechanism_group": "commented_healthcheck_blocks_removal_reset",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": CLAIM_BOUNDARY,
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify Conductor healthcheck reset witness failed")
    print("Coolify Conductor healthcheck reset origin witness frozen")
    print(f"  candidate: {CANDIDATE_SHA}")
    print(f"  repair   : {FIX_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
