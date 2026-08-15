#!/usr/bin/env python3
"""Freeze the Coolify AI backup-upload validation witness."""

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


AI_VALIDATION_SHA = "af0a8badb3cd9f470cb55c5f714263f63425d40b"
SECURITY_REPAIR_SHA = "2d63d51237c34db29cc9d8dacd81400483f0eb27"
CONTROLLER_PATH = "app/Http/Controllers/UploadController.php"
VALIDATOR_PATH = "app/Support/DatabaseBackupFileValidator.php"
TEST_PATH = "tests/Feature/DatabaseBackupUploadValidationTest.php"


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


def _const_string_array(source: str, name: str) -> tuple[str, ...]:
    match = re.search(
        rf"\bconst\s+{re.escape(name)}\s*=\s*\[(.*?)\];",
        source,
        re.DOTALL,
    )
    if match is None:
        raise ValueError(f"constant array is absent: {name}")
    return tuple(re.findall(r"['\"]([^'\"]+)['\"]", match.group(1)))


def _candidate_extension_for(name: str, allowed: tuple[str, ...]) -> str | None:
    lower = name.lower()
    for extension in sorted(allowed, key=len, reverse=True):
        suffix = f".{extension}"
        if not lower.endswith(suffix):
            continue
        stem = lower[: -len(suffix)]
        return extension if stem and not stem.endswith(".") else None
    return None


def _repaired_extension_for(
    name: str,
    allowed: tuple[str, ...],
    dangerous: tuple[str, ...],
) -> str | None:
    extension = _candidate_extension_for(name, allowed)
    if extension is None:
        return None
    stem = name.lower()[: -(len(extension) + 1)]
    parts = {part for part in stem.split(".") if part}
    return None if parts.intersection(dangerous) else extension


def _marker_line(source: str, marker: str) -> int:
    matches = [
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one {marker!r}, found {matches}")
    return matches[0]


def _evaluate_versions(
    baseline_controller: str,
    candidate_controller: str,
    candidate_test: str,
    repair_controller: str,
    repair_validator: str,
    repair_test: str,
) -> dict[str, bool]:
    candidate_allowed = _const_string_array(
        candidate_controller, "ALLOWED_EXTENSIONS"
    )
    repair_allowed = _const_string_array(repair_validator, "ALLOWED_EXTENSIONS")
    dangerous = _const_string_array(repair_validator, "DANGEROUS_EXTENSIONS")
    return {
        "baseline_has_no_backup_type_or_size_boundary": (
            "MAX_BYTES" not in baseline_controller
            and "ALLOWED_EXTENSIONS" not in baseline_controller
            and "hasAllowedExtension" not in baseline_controller
        ),
        "candidate_introduces_extension_and_size_boundary": (
            "private const MAX_BYTES = 10 * 1024 * 1024 * 1024" in candidate_controller
            and "self::hasAllowedExtension($originalName)" in candidate_controller
            and "$size > self::MAX_BYTES" in candidate_controller
        ),
        "candidate_claims_file_type_validation": (
            "validate database backup upload file type and size" in candidate_controller
            or "hasAllowedExtension" in candidate_controller
        ),
        "candidate_accepts_dangerous_double_extension": (
            _candidate_extension_for("evil.php.sql", candidate_allowed) == "sql"
            and _candidate_extension_for("shell.sh.tar.gz", candidate_allowed)
            == "tar.gz"
        ),
        "candidate_has_no_content_signature_validation": (
            "contentMatchesExtension" not in candidate_controller
            and "file_get_contents" not in candidate_controller
            and "str_starts_with($sample" not in candidate_controller
        ),
        "candidate_test_misses_actual_allowed_suffix_bypass": (
            "shell.php.sql-evil" in candidate_test
            and "evil.php.sql" not in candidate_test
        ),
        "repair_preserves_ai_size_boundary": (
            "private const MAX_BYTES = 10 * 1024 * 1024 * 1024" in repair_controller
        ),
        "repair_delegates_same_upload_validation_boundary": (
            "DatabaseBackupFileValidator::isUploadAllowed($file, self::MAX_BYTES)"
            in repair_controller
            and "DatabaseBackupFileValidator::hasAllowedExtension($name)"
            in repair_controller
        ),
        "repair_rejects_dangerous_double_extensions": (
            _repaired_extension_for("evil.php.sql", repair_allowed, dangerous) is None
            and _repaired_extension_for(
                "shell.sh.tar.gz", repair_allowed, dangerous
            )
            is None
            and _repaired_extension_for(
                "ordinary.backup.sql", repair_allowed, dangerous
            )
            == "sql"
        ),
        "repair_adds_content_signature_validation": (
            "private static function contentMatchesExtension" in repair_validator
            and "return self::contentMatchesExtension($file->getPathname(), $extension);"
            in repair_validator
            and "str_starts_with($sample, \"\\x1f\\x8b\")" in repair_validator
        ),
        "repair_tests_exact_double_extension_and_content_mismatch": (
            "'php sql' => ['evil.php.sql']" in repair_test
            and "makeTemporaryUpload('payload.sql.gz', 'not actually gzip')"
            in repair_test
            and "DatabaseBackupFileValidator::isUploadAllowed" in repair_test
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_revision = f"{AI_VALIDATION_SHA}^"
    baseline_controller = _text_blob(repository, baseline_revision, CONTROLLER_PATH)
    candidate_controller = _text_blob(repository, AI_VALIDATION_SHA, CONTROLLER_PATH)
    candidate_test = _text_blob(repository, AI_VALIDATION_SHA, TEST_PATH)
    repair_controller = _text_blob(repository, SECURITY_REPAIR_SHA, CONTROLLER_PATH)
    repair_validator = _text_blob(repository, SECURITY_REPAIR_SHA, VALIDATOR_PATH)
    repair_test = _text_blob(repository, SECURITY_REPAIR_SHA, TEST_PATH)
    evaluation = _evaluate_versions(
        baseline_controller,
        candidate_controller,
        candidate_test,
        repair_controller,
        repair_validator,
        repair_test,
    )
    candidate_metadata = _commit_metadata(repository, AI_VALIDATION_SHA)
    repair_metadata = _commit_metadata(repository, SECURITY_REPAIR_SHA)
    ancestry = {
        "candidate_parent_to_candidate": _is_ancestor(
            repository, baseline_revision, AI_VALIDATION_SHA
        ),
        "candidate_to_repair": _is_ancestor(
            repository, AI_VALIDATION_SHA, SECURITY_REPAIR_SHA
        ),
    }
    line_origins = {
        "candidate_max_bytes_boundary": _blame_line(
            repository,
            AI_VALIDATION_SHA,
            CONTROLLER_PATH,
            _marker_line(candidate_controller, "private const MAX_BYTES"),
            "AI-authored backup upload size boundary",
        ),
        "candidate_extension_classifier": _blame_line(
            repository,
            AI_VALIDATION_SHA,
            CONTROLLER_PATH,
            _marker_line(
                candidate_controller,
                "private static function hasAllowedExtension",
            ),
            "AI-authored suffix-only backup type classifier",
        ),
        "repair_preserved_max_bytes_boundary": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            CONTROLLER_PATH,
            _marker_line(repair_controller, "private const MAX_BYTES"),
            "repair-preserved AI backup upload size boundary",
        ),
        "repair_upload_validator_delegation": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            CONTROLLER_PATH,
            _marker_line(
                repair_controller,
                "DatabaseBackupFileValidator::isUploadAllowed",
            ),
            "repair replacement at the same upload validation boundary",
        ),
        "repair_dangerous_extension_control": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            VALIDATOR_PATH,
            _marker_line(repair_validator, "private const DANGEROUS_EXTENSIONS"),
            "repair dangerous double-extension control",
        ),
        "repair_content_signature_control": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            VALIDATOR_PATH,
            _marker_line(
                repair_validator,
                "private static function contentMatchesExtension",
            ),
            "repair content-signature control",
        ),
    }
    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and "validate database backup upload file type and size"
        in str(candidate_metadata["message"]).casefold()
        and repair_metadata["explicit_claude_signal"] is False
        and all(ancestry.values())
        and all(evaluation.values())
        and line_origins["candidate_max_bytes_boundary"]["origin_sha"]
        == AI_VALIDATION_SHA
        and line_origins["candidate_extension_classifier"]["origin_sha"]
        == AI_VALIDATION_SHA
        and line_origins["repair_preserved_max_bytes_boundary"]["origin_sha"]
        == AI_VALIDATION_SHA
        and line_origins["repair_upload_validator_delegation"]["origin_sha"]
        == SECURITY_REPAIR_SHA
        and line_origins["repair_dangerous_extension_control"]["origin_sha"]
        == SECURITY_REPAIR_SHA
        and line_origins["repair_content_signature_control"]["origin_sha"]
        == SECURITY_REPAIR_SHA
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_backup_upload_validation_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_VALIDATION_SHA,
        "fix_sha": SECURITY_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, baseline_revision, CONTROLLER_PATH),
            _blob_record(repository, AI_VALIDATION_SHA, CONTROLLER_PATH),
            _blob_record(repository, AI_VALIDATION_SHA, TEST_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, CONTROLLER_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, VALIDATOR_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, TEST_PATH),
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_AI_INCOMPLETE_BACKUP_UPLOAD_FILE_TYPE_VALIDATION"
        ),
        "mechanism_group": "database_backup_upload_validation",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude-attributed commit does not originate the older backup "
            "upload endpoint or every later import-hardening concern. It explicitly "
            "introduces and claims a backup file-type validation boundary, but the "
            "suffix-only classifier accepts dangerous double extensions such as "
            "evil.php.sql and never validates bytes against the claimed type. Its "
            "test checks shell.php.sql-evil, which does not exercise an allowed "
            "suffix. The later repair keeps the AI-authored 10 GiB boundary, replaces "
            "the classifier at the same saveFile gate, rejects dangerous stem "
            "extensions, validates content signatures, and adds exact regression "
            "tests. This counts one defective AI security-control edge, not root "
            "origin of the upload surface, exploit reproduction, CVE linkage, or all "
            "PostgreSQL restore-command hardening in the repair."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify backup upload validation witness failed")
    print("Coolify backup upload validation witness frozen")
    print(f"  candidate: {AI_VALIDATION_SHA}")
    print(f"  repair   : {SECURITY_REPAIR_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
