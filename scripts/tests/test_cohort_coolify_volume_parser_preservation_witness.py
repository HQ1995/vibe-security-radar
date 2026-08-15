"""Tests for the AI canonical-volume-parser preservation witness."""

from __future__ import annotations

from cohort_coolify_volume_parser_preservation_witness import _evaluate_versions


def test_volume_parser_preservation_requires_delegate_gap_and_exact_repair() -> None:
    baseline = """
function validateVolumeStringForInjection(string $volumeString): void {
    $parts = explode(':', $volumeString);
}
function parseDockerVolumeString(string $volumeString): array { return []; }
"""
    candidate = """
function validateVolumeStringForInjection(string $volumeString): void {
    parseDockerVolumeString($volumeString);
}
function parseDockerVolumeString(string $volumeString): array {
    $isSimpleEnvVar = preg_match('/simple/', $sourceStr);
    if (! $isSimpleEnvVar) { validateShellSafePath($sourceStr); }
}
"""
    repair = """
function validateVolumeStringForInjection(string $volumeString): void {
    parseDockerVolumeString($volumeString);
}
function parseDockerVolumeString(string $volumeString): array {
    $isSimpleEnvVar = preg_match('/simple/', $sourceStr);
    $isEnvVarWithPath = preg_match('/path/', $sourceStr);
    if (! $isSimpleEnvVar && ! $isEnvVarWithPath) { validateShellSafePath($sourceStr); }
}
"""
    candidate_tests = """
validateVolumeStringForInjection correctly handles Windows paths
validateDockerComposeForInjection rejects Windows paths with injection
"""
    array_tests = """
array-format with environment variable and path concatenation
${VOLUMES_PATH}/mysql
"""
    volume_tests = (
        "parseDockerVolumeString accepts environment variables with path concatenation"
    )

    assert all(
        _evaluate_versions(
            baseline,
            candidate,
            candidate_tests,
            repair,
            array_tests,
            volume_tests,
        ).values()
    )


def test_volume_parser_preservation_fails_if_candidate_already_has_path_rule() -> None:
    baseline = """
function validateVolumeStringForInjection(string $volumeString): void {
    $parts = explode(':', $volumeString);
}
function parseDockerVolumeString(string $volumeString): array { return []; }
"""
    candidate = """
function validateVolumeStringForInjection(string $volumeString): void {
    parseDockerVolumeString($volumeString);
}
function parseDockerVolumeString(string $volumeString): array {
    $isSimpleEnvVar = preg_match('/simple/', $sourceStr);
    $isEnvVarWithPath = preg_match('/path/', $sourceStr);
    if (! $isSimpleEnvVar) { validateShellSafePath($sourceStr); }
}
"""

    result = _evaluate_versions(
        baseline,
        candidate,
        "validateVolumeStringForInjection correctly handles Windows paths\n"
        "validateDockerComposeForInjection rejects Windows paths with injection",
        candidate,
        "array-format with environment variable and path concatenation\n"
        "${VOLUMES_PATH}/mysql",
        "parseDockerVolumeString accepts environment variables with path concatenation",
    )

    assert (
        result[
            "candidate_canonical_parser_only_exempts_simple_environment_reference"
        ]
        is False
    )
