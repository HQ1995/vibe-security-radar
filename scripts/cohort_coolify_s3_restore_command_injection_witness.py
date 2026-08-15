#!/usr/bin/env python3
"""Freeze the Coolify AI S3-restore command-injection witness."""

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
from cohort_coolify_security_frontier_preservation_witness import (
    _blame_line,
    _line_in_method,
)


AI_REWRITE_SHA = "94560ea6c7a841840638e7c73a4b5d6da2afe713"
AI_PATH_STATE_SHA = "875351188fbdcbb8b4405fe30274eaff9c657824"
COMMAND_REPAIR_SHA = "9113ed714f46d836bbc6389287f40dc4e2064f9f"
IMPORT_PATH = "app/Livewire/Project/Database/Import.php"
CANDIDATE_SECURITY_TEST_PATH = "tests/Unit/S3RestoreSecurityTest.php"
CANDIDATE_PATH_TEST_PATH = "tests/Unit/PathTraversalSecurityTest.php"
REPAIR_TEST_PATH = "tests/Unit/Project/Database/ImportCheckFileButtonTest.php"
PROBE_MARKER = "__AI_SLOP_S3_PROBE_EXECUTED__"
PROBE_PATH = "backup.sql; ai_slop_s3_probe"


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


def _shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _s3_stat_command(bucket: str, path: str, *, repaired: bool) -> str:
    source = f"s3temp/{bucket}/{path}"
    if repaired:
        source = _shell_single_quote(source)
    return f"docker exec helper mc stat {source}"


def _run_shell_probe(*, repaired: bool) -> dict[str, object]:
    command = _s3_stat_command("valid-bucket", PROBE_PATH, repaired=repaired)
    harness = r'''ai_slop_s3_probe() {
    printf '__AI_SLOP_S3_PROBE_EXECUTED__\n'
}
docker() {
    printf 'DOCKER_ARG<%s>\n' "$@"
}
export -f ai_slop_s3_probe docker
'''
    completed = subprocess.run(
        ["/bin/bash", "-c", harness + command],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    expected_argument = f"DOCKER_ARG<s3temp/valid-bucket/{PROBE_PATH}>"
    return {
        "path": PROBE_PATH,
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "probe_executed": PROBE_MARKER in completed.stdout,
        "source_preserved_as_one_docker_argument": (
            expected_argument in completed.stdout
        ),
    }


def _evaluate_versions(
    parent: str,
    candidate: str,
    candidate_security_test: str,
    candidate_path_test: str,
    intermediate: str,
    repair: str,
    repair_test: str,
    unsafe_probe: dict[str, object],
    repaired_probe: dict[str, object],
) -> dict[str, bool]:
    parent_download = _php_method_region(parent, "downloadFromS3")
    candidate_restore = _php_method_region(candidate, "restoreFromS3")
    intermediate_restore = _php_method_region(intermediate, "restoreFromS3")
    repair_restore = _php_method_region(repair, "restoreFromS3")
    repair_check = _php_method_region(repair, "checkS3File")
    return {
        "parent_has_preexisting_raw_mc_cp_sink": (
            'mc cp temporary/{$bucket}/{$cleanPath} {$downloadPath}'
            in parent_download
            and "mc stat" not in parent_download
        ),
        "candidate_rewrites_download_as_atomic_restore": (
            "public function downloadFromS3" not in candidate
            and "public function restoreFromS3" in candidate
            and "S3RestoreJobFinished" in candidate_restore
            and "S3DownloadFinished" not in candidate
        ),
        "candidate_adds_raw_mc_stat_sink": (
            'mc stat s3temp/{$bucket}/{$cleanPath}' in candidate_restore
        ),
        "candidate_reauthors_raw_mc_cp_sink": (
            'mc cp s3temp/{$bucket}/{$cleanPath} {$helperTmpPath}'
            in candidate_restore
        ),
        "candidate_partially_escapes_neighboring_s3_inputs": all(
            marker in candidate_restore
            for marker in (
                "$escapedEndpoint = escapeshellarg($endpoint);",
                "$escapedKey = escapeshellarg($key);",
                "$escapedSecret = escapeshellarg($secret);",
                "mc alias set s3temp {$escapedEndpoint} {$escapedKey} {$escapedSecret}",
            )
        ),
        "candidate_omits_bucket_and_path_shell_boundary": (
            "validateBucketName" not in candidate_restore
            and "validateS3Path" not in candidate_restore
            and "$escapedS3Source" not in candidate_restore
        ),
        "candidate_security_tests_cover_neighbors_but_miss_source": (
            "mc alias set" in candidate_security_test
            and all(
                marker in candidate_security_test
                for marker in ("$endpoint", "$key", "$secret")
            )
            and "mc stat" not in candidate_security_test
            and "$bucket" not in candidate_security_test
            and "$cleanPath" not in candidate_security_test
            and "command injection" not in candidate_path_test.casefold()
        ),
        "intermediate_only_resets_path_validation_state": (
            "public function updatedS3Path($value)" in intermediate
            and "$this->s3FileSize = null;" in intermediate
            and "str($value)->trim()->start('/')->value()" in intermediate
            and 'mc stat s3temp/{$bucket}/{$cleanPath}'
            in intermediate_restore
            and "validateS3Path" not in intermediate_restore
        ),
        "repair_validates_bucket_and_path_before_check_and_restore": (
            "private function validateBucketName" in repair
            and "private function validateS3Path" in repair
            and "if (! $this->validateS3Path($cleanPath))" in repair_check
            and "if (! $this->validateBucketName($s3Storage->bucket))"
            in repair_check
            and "if (! $this->validateBucketName($bucket))" in repair_restore
            and "if (! $this->validateS3Path($cleanPath))" in repair_restore
        ),
        "repair_quotes_combined_s3_source_at_both_sinks": (
            '$escapedS3Source = escapeshellarg("s3temp/{$bucket}/{$cleanPath}");'
            in repair_restore
            and "mc stat {$escapedS3Source}" in repair_restore
            and "mc cp {$escapedS3Source} {$escapedHelperTmpPath}"
            in repair_restore
        ),
        "repair_tests_exact_command_injection_classes": all(
            marker in repair_test
            for marker in (
                "bucket;rm -rf /",
                "bucket$(whoami)",
                "path;rm -rf /",
                "path$(whoami)",
                "path`id`",
            )
        ),
        "candidate_shell_probe_executes_injected_command": (
            unsafe_probe["returncode"] == 0
            and unsafe_probe["probe_executed"] is True
            and unsafe_probe["source_preserved_as_one_docker_argument"] is False
        ),
        "repair_shell_probe_preserves_inert_source_argument": (
            repaired_probe["returncode"] == 0
            and repaired_probe["probe_executed"] is False
            and repaired_probe["source_preserved_as_one_docker_argument"] is True
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    parent_revision = f"{AI_REWRITE_SHA}^"
    parent = _text_blob(repository, parent_revision, IMPORT_PATH)
    candidate = _text_blob(repository, AI_REWRITE_SHA, IMPORT_PATH)
    candidate_security_test = _text_blob(
        repository, AI_REWRITE_SHA, CANDIDATE_SECURITY_TEST_PATH
    )
    candidate_path_test = _text_blob(
        repository, AI_REWRITE_SHA, CANDIDATE_PATH_TEST_PATH
    )
    intermediate = _text_blob(repository, AI_PATH_STATE_SHA, IMPORT_PATH)
    repair = _text_blob(repository, COMMAND_REPAIR_SHA, IMPORT_PATH)
    repair_test = _text_blob(repository, COMMAND_REPAIR_SHA, REPAIR_TEST_PATH)
    unsafe_probe = _run_shell_probe(repaired=False)
    repaired_probe = _run_shell_probe(repaired=True)
    evaluation = _evaluate_versions(
        parent,
        candidate,
        candidate_security_test,
        candidate_path_test,
        intermediate,
        repair,
        repair_test,
        unsafe_probe,
        repaired_probe,
    )
    metadata = {
        "ai_restore_rewrite": _commit_metadata(repository, AI_REWRITE_SHA),
        "ai_path_state_followup": _commit_metadata(
            repository, AI_PATH_STATE_SHA
        ),
        "command_repair": _commit_metadata(repository, COMMAND_REPAIR_SHA),
    }
    ancestry = {
        "parent_to_ai_rewrite": _is_ancestor(
            repository, parent_revision, AI_REWRITE_SHA
        ),
        "ai_rewrite_to_path_state": _is_ancestor(
            repository, AI_REWRITE_SHA, AI_PATH_STATE_SHA
        ),
        "path_state_to_command_repair": _is_ancestor(
            repository, AI_PATH_STATE_SHA, COMMAND_REPAIR_SHA
        ),
    }
    line_origins = {
        "candidate_partial_endpoint_escape": _blame_line(
            repository,
            AI_REWRITE_SHA,
            IMPORT_PATH,
            _line_in_method(
                candidate,
                "restoreFromS3",
                "$escapedEndpoint = escapeshellarg($endpoint);",
            ),
            "AI partial S3 restore input escaping",
        ),
        "candidate_raw_mc_stat_sink": _blame_line(
            repository,
            AI_REWRITE_SHA,
            IMPORT_PATH,
            _line_in_method(
                candidate,
                "restoreFromS3",
                'mc stat s3temp/{$bucket}/{$cleanPath}',
            ),
            "AI-added raw S3 stat shell sink",
        ),
        "intermediate_preserves_raw_mc_stat_sink": _blame_line(
            repository,
            AI_PATH_STATE_SHA,
            IMPORT_PATH,
            _line_in_method(
                intermediate,
                "restoreFromS3",
                'mc stat s3temp/{$bucket}/{$cleanPath}',
            ),
            "path-state follow-up preserves raw S3 stat sink",
        ),
        "repair_s3_path_validator": _blame_line(
            repository,
            COMMAND_REPAIR_SHA,
            IMPORT_PATH,
            _line_in_method(
                repair,
                "validateS3Path",
                "private function validateS3Path",
            ),
            "repair S3 path validation boundary",
        ),
        "repair_combined_source_escape": _blame_line(
            repository,
            COMMAND_REPAIR_SHA,
            IMPORT_PATH,
            _line_in_method(
                repair,
                "restoreFromS3",
                '$escapedS3Source = escapeshellarg("s3temp/{$bucket}/{$cleanPath}");',
            ),
            "repair combined S3 source shell escaping",
        ),
    }
    expected_origins = {
        "candidate_partial_endpoint_escape": AI_REWRITE_SHA,
        "candidate_raw_mc_stat_sink": AI_REWRITE_SHA,
        "intermediate_preserves_raw_mc_stat_sink": AI_REWRITE_SHA,
        "repair_s3_path_validator": COMMAND_REPAIR_SHA,
        "repair_combined_source_escape": COMMAND_REPAIR_SHA,
    }
    witness_passed = bool(
        metadata["ai_restore_rewrite"]["explicit_claude_signal"] is True
        and metadata["ai_path_state_followup"]["explicit_claude_signal"] is True
        and "single atomic operation"
        in str(metadata["ai_restore_rewrite"]["message"]).casefold()
        and "prevent command injection"
        in str(metadata["command_repair"]["message"]).casefold()
        and all(ancestry.values())
        and all(evaluation.values())
        and all(
            line_origins[key]["origin_sha"] == origin
            for key, origin in expected_origins.items()
        )
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_s3_restore_command_injection_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_REWRITE_SHA,
        "fix_sha": COMMAND_REPAIR_SHA,
        "metadata": metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "shell_probes": {
            "candidate_raw_source": unsafe_probe,
            "repair_quoted_source": repaired_probe,
        },
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, parent_revision, IMPORT_PATH),
            _blob_record(repository, AI_REWRITE_SHA, IMPORT_PATH),
            _blob_record(
                repository, AI_REWRITE_SHA, CANDIDATE_SECURITY_TEST_PATH
            ),
            _blob_record(repository, AI_REWRITE_SHA, CANDIDATE_PATH_TEST_PATH),
            _blob_record(repository, AI_PATH_STATE_SHA, IMPORT_PATH),
            _blob_record(repository, COMMAND_REPAIR_SHA, IMPORT_PATH),
            _blob_record(repository, COMMAND_REPAIR_SHA, REPAIR_TEST_PATH),
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_AI_INCOMPLETE_S3_RESTORE_SHELL_HARDENING"
        ),
        "mechanism_group": "s3_restore_bucket_path_command_injection",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "intermediate_ai_path_state_commit_not_counted": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The older two-step download flow already had an unquoted mc-cp "
            "source, so the Claude-attributed rewrite is not claimed as root "
            "origin. It replaces that flow with an atomic restore, adds a new raw "
            "mc-stat sink, reauthors the raw mc-cp sink, and partially escapes the "
            "neighboring endpoint, key, and secret inputs while its security tests "
            "omit bucket and path. The later repair validates bucket/path at both "
            "check and restore boundaries, quotes the combined S3 source at both "
            "sinks, and adds exact injection regressions. The intermediate AI "
            "commit only resets UI validation state and is retained but not counted "
            "as a causal edge. This is one defective AI security-control edge, not "
            "a full remote exploit, CVE link, or proof that every S3 restore command "
            "is safe after the repair."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify S3 restore command-injection witness failed")
    print("Coolify S3 restore command-injection witness frozen")
    print(f"  candidate : {AI_REWRITE_SHA}")
    print(f"  repair    : {COMMAND_REPAIR_SHA}")
    print(f"  output    : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
