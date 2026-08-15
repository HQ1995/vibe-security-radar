"""Tests for exact-preimage Coolify recovery witness predicates."""

from __future__ import annotations

from cohort_coolify_exact_preimage_recovery_witness import (
    _evaluate_compose_rewrite,
    _evaluate_git_sha_regex,
)


def test_compose_rewrite_requires_behavioral_regression_and_repair_tests() -> None:
    candidate_job = """
if (! str_contains($build_command, '--env-file')) {
    $build_command = str_replace(
        'docker compose',
        'docker compose --env-file /artifacts/build-time.env',
        $build_command
    );
}
"""
    candidate_test = "str_replace replaces ALL occurrences, which is acceptable"
    repair_job = """
// Auto-inject -f (compose file) and --env-file flags using helper function
$build_command = injectDockerComposeFlags($command, $compose, $env);
"""
    repair_helper = r"""
/(?:^|\s)(?:-f(?:[=\s]|\S)|--file(?:=|\s))/
/(?:^|\s)--env-file(?:=|\s)/
return preg_replace('/docker\s+compose/', $dockerComposeReplacement, $command, 1);
"""
    repair_test = "\n".join(
        (
            "only replaces first docker compose occurrence in chained commands",
            "does not modify docker compose string in echo statements",
            "does not modify docker compose string in bash comments",
            "detects -f flag with equals sign format (bypass vector)",
            "detects --env-file flag with tab character whitespace (bypass vector)",
        )
    )

    assert all(
        _evaluate_compose_rewrite(
            candidate_job,
            candidate_test,
            repair_job,
            repair_helper,
            repair_test,
        ).values()
    )


def test_git_sha_regex_catches_long_object_id_suffix_and_uppercase_gap() -> None:
    candidate = (
        "preg_match('/([0-9a-f]{40})\\s*\\t/', $output, $matches);"
    )
    repair = (
        "preg_match('/\\b([0-9a-fA-F]{40})(?=\\s*\\t)/', $output, $matches);"
    )

    assert all(_evaluate_git_sha_regex(candidate, repair).values())
