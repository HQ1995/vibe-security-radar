"""Tests for the Coolify AI backup-upload validation witness."""

from __future__ import annotations

import cohort_coolify_backup_upload_validation_witness as witness


ALLOWED = ("sql", "sql.gz", "gz", "zip", "tar", "tar.gz")
DANGEROUS = ("php", "sh", "exe", "jsp")


def test_candidate_suffix_only_classifier_accepts_dangerous_double_extensions() -> None:
    assert witness._candidate_extension_for("evil.php.sql", ALLOWED) == "sql"
    assert witness._candidate_extension_for("shell.sh.tar.gz", ALLOWED) == "tar.gz"
    assert witness._candidate_extension_for("shell.php.sql-evil", ALLOWED) is None


def test_repair_rejects_dangerous_stems_without_rejecting_ordinary_dots() -> None:
    assert witness._repaired_extension_for("evil.php.sql", ALLOWED, DANGEROUS) is None
    assert (
        witness._repaired_extension_for("shell.sh.tar.gz", ALLOWED, DANGEROUS)
        is None
    )
    assert (
        witness._repaired_extension_for("ordinary.backup.sql", ALLOWED, DANGEROUS)
        == "sql"
    )


def _controller(*, repaired: bool) -> str:
    validator = (
        "if (! DatabaseBackupFileValidator::isUploadAllowed($file, self::MAX_BYTES)) {}\n"
        "return DatabaseBackupFileValidator::hasAllowedExtension($name);"
        if repaired
        else (
            "if (! self::hasAllowedExtension($originalName) || "
            "$size > self::MAX_BYTES) {}"
        )
    )
    allowed = (
        "private const ALLOWED_EXTENSIONS = DatabaseBackupFileValidator::ALLOWED_EXTENSIONS;"
        if repaired
        else "private const ALLOWED_EXTENSIONS = ['sql', 'sql.gz', 'gz', 'zip', 'tar', 'tar.gz'];"
    )
    return f"""
private const MAX_BYTES = 10 * 1024 * 1024 * 1024;
{allowed}
{validator}
"""


VALIDATOR = r'''
public const ALLOWED_EXTENSIONS = ['sql', 'sql.gz', 'gz', 'zip', 'tar', 'tar.gz'];
private const DANGEROUS_EXTENSIONS = ['php', 'sh', 'exe', 'jsp'];
public static function isUploadAllowed($file, int $maxBytes): bool
{
    return self::contentMatchesExtension($file->getPathname(), $extension);
}
private static function contentMatchesExtension(string $path, string $extension): bool
{
    return str_starts_with($sample, "\x1f\x8b");
}
'''


def test_version_evaluation_requires_exact_repair_of_ai_validation_boundary() -> None:
    candidate_test = "shell.php.sql-evil"
    repair_test = """
'php sql' => ['evil.php.sql'];
makeTemporaryUpload('payload.sql.gz', 'not actually gzip');
DatabaseBackupFileValidator::isUploadAllowed($file, 123);
"""
    result = witness._evaluate_versions(
        "class UploadController {}",
        _controller(repaired=False),
        candidate_test,
        _controller(repaired=True),
        VALIDATOR,
        repair_test,
    )

    assert all(result.values())


def test_version_evaluation_fails_when_candidate_test_already_covers_bypass() -> None:
    result = witness._evaluate_versions(
        "class UploadController {}",
        _controller(repaired=False),
        "shell.php.sql-evil and evil.php.sql",
        _controller(repaired=True),
        VALIDATOR,
        """
'php sql' => ['evil.php.sql'];
makeTemporaryUpload('payload.sql.gz', 'not actually gzip');
DatabaseBackupFileValidator::isUploadAllowed($file, 123);
""",
    )

    assert result["candidate_test_misses_actual_allowed_suffix_bypass"] is False
