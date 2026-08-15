#!/usr/bin/env python3
"""Freeze the Coolify AI canonical-volume-parser preservation witness."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


AI_CANDIDATE_SHA = "a219f2e80e42c14d5d59a3e6816fcb91b771e4a9"
FOLLOWUP_REPAIR_SHA = "468d5fe7d77dfe1f1f34770a81e45062c272c92d"
PARSER_PATH = "bootstrap/helpers/parsers.php"
CANDIDATE_TEST_PATH = "tests/Unit/WindowsPathVolumeTest.php"
REPAIR_ARRAY_TEST_PATH = "tests/Unit/VolumeArrayFormatSecurityTest.php"
REPAIR_VOLUME_TEST_PATH = "tests/Unit/VolumeSecurityTest.php"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_record(
    repository: Path, revision: str, source_path: str
) -> dict[str, str]:
    blob = _git_blob(repository, revision, source_path)
    return {
        "revision": revision,
        "path": source_path,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _function_region(source: str, function_name: str) -> str:
    lines = source.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if re.search(rf"^function\s+{re.escape(function_name)}\s*\(", line)
    ]
    if len(starts) != 1:
        raise ValueError(f"expected one function {function_name}, found {starts}")
    start = starts[0]
    end = next(
        (
            index
            for index, line in enumerate(lines[start + 1 :], start=start + 1)
            if re.search(r"^function\s+\w+\s*\(", line)
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def _line_in_function(source: str, function_name: str, marker: str) -> int:
    lines = source.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if re.search(rf"^function\s+{re.escape(function_name)}\s*\(", line)
    ]
    if len(starts) != 1:
        raise SystemExit(f"expected one function {function_name}, found {starts}")
    start = starts[0]
    end = next(
        (
            index
            for index, line in enumerate(lines[start + 1 :], start=start + 1)
            if re.search(r"^function\s+\w+\s*\(", line)
        ),
        len(lines),
    )
    matches = [
        index + 1
        for index, line in enumerate(lines[start:end], start=start)
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected one {marker!r} in {function_name}, found {matches}"
        )
    return matches[0]


def _evaluate_versions(
    baseline_parser: str,
    candidate_parser: str,
    candidate_tests: str,
    repair_parser: str,
    repair_array_tests: str,
    repair_volume_tests: str,
) -> dict[str, bool]:
    baseline_validator = _function_region(
        baseline_parser, "validateVolumeStringForInjection"
    )
    candidate_validator = _function_region(
        candidate_parser, "validateVolumeStringForInjection"
    )
    candidate_canonical_parser = _function_region(
        candidate_parser, "parseDockerVolumeString"
    )
    repair_validator = _function_region(
        repair_parser, "validateVolumeStringForInjection"
    )
    repair_canonical_parser = _function_region(
        repair_parser, "parseDockerVolumeString"
    )
    path_rule = "$isEnvVarWithPath = preg_match("
    return {
        "baseline_validator_uses_manual_colon_split": (
            "explode(':', $volumeString)" in baseline_validator
        ),
        "baseline_validator_does_not_delegate_to_canonical_parser": (
            "parseDockerVolumeString($volumeString);" not in baseline_validator
        ),
        "candidate_replaces_manual_validator_with_canonical_delegate": (
            "parseDockerVolumeString($volumeString);" in candidate_validator
            and "explode(':', $volumeString)" not in candidate_validator
        ),
        "candidate_canonical_parser_only_exempts_simple_environment_reference": (
            "$isSimpleEnvVar = preg_match(" in candidate_canonical_parser
            and "if (! $isSimpleEnvVar)" in candidate_canonical_parser
            and path_rule not in candidate_canonical_parser
        ),
        "candidate_tests_windows_path_delegation": all(
            marker in candidate_tests
            for marker in (
                "validateVolumeStringForInjection correctly handles Windows paths",
                "validateDockerComposeForInjection rejects Windows paths with injection",
            )
        ),
        "repair_retains_candidate_canonical_delegate": (
            "parseDockerVolumeString($volumeString);" in repair_validator
        ),
        "repair_extends_canonical_parser_for_env_path_concatenation": (
            path_rule in repair_canonical_parser
            and "if (! $isSimpleEnvVar && ! $isEnvVarWithPath)"
            in repair_canonical_parser
        ),
        "repair_tests_reported_array_format_env_path": all(
            marker in repair_array_tests
            for marker in (
                "array-format with environment variable and path concatenation",
                "${VOLUMES_PATH}/mysql",
            )
        ),
        "repair_tests_canonical_parser_env_path": (
            "parseDockerVolumeString accepts environment variables with path concatenation"
            in repair_volume_tests
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_revision = f"{AI_CANDIDATE_SHA}^"
    baseline_parser = _text_blob(repository, baseline_revision, PARSER_PATH)
    candidate_parser = _text_blob(repository, AI_CANDIDATE_SHA, PARSER_PATH)
    candidate_tests = _text_blob(
        repository, AI_CANDIDATE_SHA, CANDIDATE_TEST_PATH
    )
    repair_parser = _text_blob(repository, FOLLOWUP_REPAIR_SHA, PARSER_PATH)
    repair_array_tests = _text_blob(
        repository, FOLLOWUP_REPAIR_SHA, REPAIR_ARRAY_TEST_PATH
    )
    repair_volume_tests = _text_blob(
        repository, FOLLOWUP_REPAIR_SHA, REPAIR_VOLUME_TEST_PATH
    )
    evaluation = _evaluate_versions(
        baseline_parser,
        candidate_parser,
        candidate_tests,
        repair_parser,
        repair_array_tests,
        repair_volume_tests,
    )
    candidate_metadata = _commit_metadata(repository, AI_CANDIDATE_SHA)
    repair_metadata = _commit_metadata(repository, FOLLOWUP_REPAIR_SHA)
    line_origins = {
        "candidate_canonical_delegate": _blame_line(
            repository,
            AI_CANDIDATE_SHA,
            PARSER_PATH,
            _line_in_function(
                candidate_parser,
                "validateVolumeStringForInjection",
                "parseDockerVolumeString($volumeString);",
            ),
            "AI canonical-volume-parser delegation",
        ),
        "repair_env_path_rule": _blame_line(
            repository,
            FOLLOWUP_REPAIR_SHA,
            PARSER_PATH,
            _line_in_function(
                repair_parser,
                "parseDockerVolumeString",
                "$isEnvVarWithPath = preg_match(",
            ),
            "follow-up environment-variable path acceptance rule",
        ),
    }
    ancestry = {
        "candidate_parent_to_candidate": _is_ancestor(
            repository, baseline_revision, AI_CANDIDATE_SHA
        ),
        "candidate_to_repair": _is_ancestor(
            repository, AI_CANDIDATE_SHA, FOLLOWUP_REPAIR_SHA
        ),
    }
    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"]
        == [_commit_metadata(repository, baseline_revision)["sha"]]
        and "single source of truth" in str(candidate_metadata["message"])
        and "docker compose validation" in str(repair_metadata["message"])
        and all(ancestry.values())
        and all(evaluation.values())
        and line_origins["candidate_canonical_delegate"]["origin_sha"]
        == AI_CANDIDATE_SHA
        and line_origins["repair_env_path_rule"]["origin_sha"]
        == FOLLOWUP_REPAIR_SHA
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_volume_parser_preservation_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_CANDIDATE_SHA,
        "fix_sha": FOLLOWUP_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, baseline_revision, PARSER_PATH),
            _blob_record(repository, AI_CANDIDATE_SHA, PARSER_PATH),
            _blob_record(repository, AI_CANDIDATE_SHA, CANDIDATE_TEST_PATH),
            _blob_record(repository, FOLLOWUP_REPAIR_SHA, PARSER_PATH),
            _blob_record(
                repository, FOLLOWUP_REPAIR_SHA, REPAIR_ARRAY_TEST_PATH
            ),
            _blob_record(
                repository, FOLLOWUP_REPAIR_SHA, REPAIR_VOLUME_TEST_PATH
            ),
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_AI_CANONICAL_VOLUME_VALIDATION_PRESERVATION_CONTRIBUTOR"
        ),
        "mechanism_group": "docker_compose_volume_validation_underacceptance",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude commit did not originate the older rejection of "
            "environment-variable-plus-path volume sources. It materially replaced "
            "the public volume validation function with a canonical-parser "
            "delegation, advertised that parser as the single source of truth, and "
            "left the canonical parser accepting only a bare environment reference. "
            "The later repair preserves that delegation and extends the exact parser "
            "contract to accept safe ${VAR}/path sources, with regression tests. This "
            "counts a preservation/rewrite contributor to the existing "
            "underacceptance mechanism, not a new security advisory or root origin."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify volume-parser preservation witness failed")
    print("Coolify volume-parser preservation witness frozen")
    print(f"  candidate: {AI_CANDIDATE_SHA}")
    print(f"  repair   : {FOLLOWUP_REPAIR_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
