#!/usr/bin/env python3
"""Freeze the Coolify incomplete AI volume shell-hardening witness."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


AI_HARDENING_SHA = "d2064dd4998694cda2eabd00149f7c4d1e94c699"
FOLLOWUP_REPAIR_SHA = "410a9a6195a2b939d4a429f6c464ff56e61177f8"
PREVIEW_PATH = "app/Models/ApplicationPreview.php"
PATTERNS_PATH = "app/Support/ValidationPatterns.php"
TEST_PATH = "tests/Unit/PersistentVolumeSecurityTest.php"


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


def _nth_line(source: str, marker: str, occurrence: int = 1) -> int:
    matches = [
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if occurrence < 1 or len(matches) < occurrence:
        raise SystemExit(
            f"expected marker {marker!r} occurrence {occurrence}, found {matches}"
        )
    return matches[occurrence - 1]


def _evaluate_versions(
    baseline_preview: str,
    candidate_preview: str,
    candidate_patterns: str,
    candidate_tests: str,
    repair_preview: str,
    repair_tests: str,
) -> dict[str, bool]:
    regular_unescaped = (
        'instant_remote_process(["docker volume rm -f $storage->name"]'
    )
    regular_escaped = (
        "instant_remote_process(['docker volume rm -f '."
        "escapeshellarg($storage->name)]"
    )
    compose_volume_unescaped = (
        'instant_remote_process(["docker volume rm -f $key"]'
    )
    compose_network_disconnect_unescaped = (
        'instant_remote_process(["docker network disconnect $key coolify-proxy"]'
    )
    compose_network_remove_unescaped = (
        'instant_remote_process(["docker network rm $key"]'
    )
    return {
        "baseline_regular_volume_cleanup_is_unescaped": (
            regular_unescaped in baseline_preview
        ),
        "candidate_escapes_regular_volume_cleanup": (
            regular_escaped in candidate_preview
            and regular_unescaped not in candidate_preview
        ),
        "candidate_introduces_volume_name_validation_contract": all(
            marker in candidate_patterns
            for marker in (
                "public const VOLUME_NAME_PATTERN",
                "public static function volumeNameRules",
            )
        ),
        "candidate_tests_shell_metacharacter_volume_names": all(
            marker in candidate_tests
            for marker in (
                "Persistent Volume Security Tests",
                "rejects volume names with shell metacharacters",
                "escapeshellarg neutralizes injection in docker volume rm command",
            )
        ),
        "candidate_leaves_compose_volume_cleanup_unescaped": (
            compose_volume_unescaped in candidate_preview
        ),
        "candidate_leaves_compose_network_disconnect_unescaped": (
            compose_network_disconnect_unescaped in candidate_preview
        ),
        "candidate_leaves_compose_network_remove_unescaped": (
            compose_network_remove_unescaped in candidate_preview
        ),
        "repair_validates_compose_volume_key": (
            "preg_match(ValidationPatterns::VOLUME_NAME_PATTERN, $key)"
            in repair_preview
        ),
        "repair_escapes_compose_volume_key": (
            "'docker volume rm -f '.escapeshellarg($key)" in repair_preview
            and compose_volume_unescaped not in repair_preview
        ),
        "repair_validates_compose_network_key": (
            "preg_match(ValidationPatterns::DOCKER_NETWORK_PATTERN, $key)"
            in repair_preview
        ),
        "repair_escapes_compose_network_key_once_for_both_commands": all(
            marker in repair_preview
            for marker in (
                "$k = escapeshellarg($key);",
                '"docker network disconnect {$k} coolify-proxy"',
                '"docker network rm {$k}"',
            )
        ),
        "repair_adds_compose_volume_and_network_escape_tests": all(
            marker in repair_tests
            for marker in (
                "escapeshellarg neutralizes injection in docker volume create command",
                "escapeshellarg neutralizes injection in docker network disconnect command",
                "escapeshellarg neutralizes injection in docker network rm command",
            )
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_revision = f"{AI_HARDENING_SHA}^"
    baseline_preview = _text_blob(repository, baseline_revision, PREVIEW_PATH)
    candidate_preview = _text_blob(repository, AI_HARDENING_SHA, PREVIEW_PATH)
    candidate_patterns = _text_blob(repository, AI_HARDENING_SHA, PATTERNS_PATH)
    candidate_tests = _text_blob(repository, AI_HARDENING_SHA, TEST_PATH)
    repair_preview = _text_blob(repository, FOLLOWUP_REPAIR_SHA, PREVIEW_PATH)
    repair_tests = _text_blob(repository, FOLLOWUP_REPAIR_SHA, TEST_PATH)

    evaluation = _evaluate_versions(
        baseline_preview,
        candidate_preview,
        candidate_patterns,
        candidate_tests,
        repair_preview,
        repair_tests,
    )
    candidate_metadata = _commit_metadata(repository, AI_HARDENING_SHA)
    repair_metadata = _commit_metadata(repository, FOLLOWUP_REPAIR_SHA)
    ancestry = {
        "candidate_parent_to_candidate": _is_ancestor(
            repository, baseline_revision, AI_HARDENING_SHA
        ),
        "candidate_to_repair": _is_ancestor(
            repository, AI_HARDENING_SHA, FOLLOWUP_REPAIR_SHA
        ),
    }

    line_specs = {
        "candidate_regular_cleanup_escape": (
            AI_HARDENING_SHA,
            PREVIEW_PATH,
            candidate_preview,
            "escapeshellarg($storage->name)",
            "AI regular persistent-volume cleanup escape",
        ),
        "candidate_volume_pattern": (
            AI_HARDENING_SHA,
            PATTERNS_PATH,
            candidate_patterns,
            "public const VOLUME_NAME_PATTERN",
            "AI Docker volume-name validation contract",
        ),
        "repair_compose_volume_escape": (
            FOLLOWUP_REPAIR_SHA,
            PREVIEW_PATH,
            repair_preview,
            "escapeshellarg($key)",
            "follow-up Compose preview volume cleanup escape",
        ),
        "repair_compose_network_escape": (
            FOLLOWUP_REPAIR_SHA,
            PREVIEW_PATH,
            repair_preview,
            "$k = escapeshellarg($key);",
            "follow-up Compose preview network cleanup escape",
        ),
    }
    line_origins = {
        key: _blame_line(
            repository,
            revision,
            source_path,
            _nth_line(source, marker),
            label,
        )
        for key, (
            revision,
            source_path,
            source,
            marker,
            label,
        ) in line_specs.items()
    }
    expected_origins = {
        "candidate_regular_cleanup_escape": AI_HARDENING_SHA,
        "candidate_volume_pattern": AI_HARDENING_SHA,
        "repair_compose_volume_escape": FOLLOWUP_REPAIR_SHA,
        "repair_compose_network_escape": FOLLOWUP_REPAIR_SHA,
    }

    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"] == [
            _commit_metadata(repository, baseline_revision)["sha"]
        ]
        and "escapeshellarg for volume names" in str(candidate_metadata["message"])
        and "escape shell args" in str(repair_metadata["message"])
        and all(ancestry.values())
        and all(evaluation.values())
        and all(
            line_origins[key]["origin_sha"] == expected
            for key, expected in expected_origins.items()
        )
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_incomplete_ai_volume_shell_hardening_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_HARDENING_SHA,
        "fix_sha": FOLLOWUP_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, baseline_revision, PREVIEW_PATH),
            _blob_record(repository, AI_HARDENING_SHA, PREVIEW_PATH),
            _blob_record(repository, AI_HARDENING_SHA, PATTERNS_PATH),
            _blob_record(repository, AI_HARDENING_SHA, TEST_PATH),
            _blob_record(repository, FOLLOWUP_REPAIR_SHA, PREVIEW_PATH),
            _blob_record(repository, FOLLOWUP_REPAIR_SHA, TEST_PATH),
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_AI_INCOMPLETE_VOLUME_SHELL_HARDENING"
        ),
        "mechanism_group": "compose_preview_volume_network_cleanup_shell_escape",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude commit explicitly hardened persistent-volume names, added a "
            "volume-name validation contract and tests, and changed the regular "
            "ApplicationPreview cleanup branch to use escapeshellarg. In the same "
            "forceDeleting callback it left the Docker Compose preview volume and "
            "network keys directly interpolated into shell commands. The follow-up "
            "repair validates and escapes those sibling cleanup paths. This counts "
            "the AI commit as an incomplete security-hardening contributor; it does "
            "not claim that the AI commit originally introduced the older cleanup "
            "paths or that an exploit was reproduced."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify volume shell-hardening witness failed")

    print("Coolify volume shell-hardening witness frozen")
    print(f"  candidate: {AI_HARDENING_SHA}")
    print(f"  repair   : {FOLLOWUP_REPAIR_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
