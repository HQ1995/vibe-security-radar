"""Tests for the Coolify AI S3 restore command-injection witness."""

from __future__ import annotations

import cohort_coolify_s3_restore_command_injection_witness as witness


def test_candidate_s3_source_allows_shell_separator() -> None:
    result = witness._run_shell_probe(repaired=False)

    assert result["returncode"] == 0
    assert result["probe_executed"] is True
    assert result["source_preserved_as_one_docker_argument"] is False


def test_repaired_s3_source_is_one_inert_argument() -> None:
    result = witness._run_shell_probe(repaired=True)

    assert result["returncode"] == 0
    assert result["probe_executed"] is False
    assert result["source_preserved_as_one_docker_argument"] is True


def test_shell_quote_preserves_single_quotes() -> None:
    assert witness._shell_single_quote("a'b") == "'a'\\''b'"


def test_version_evaluation_keeps_preexisting_sink_claim_boundary() -> None:
    parent = r'''
public function downloadFromS3()
{
    $commands[] = "docker exec {$containerName} mc cp temporary/{$bucket}/{$cleanPath} {$downloadPath}";
}
'''
    candidate = r'''
public function restoreFromS3()
{
    $escapedEndpoint = escapeshellarg($endpoint);
    $escapedKey = escapeshellarg($key);
    $escapedSecret = escapeshellarg($secret);
    $commands[] = "docker exec {$containerName} mc alias set s3temp {$escapedEndpoint} {$escapedKey} {$escapedSecret}";
    $commands[] = "docker exec {$containerName} mc stat s3temp/{$bucket}/{$cleanPath}";
    $commands[] = "docker exec {$containerName} mc cp s3temp/{$bucket}/{$cleanPath} {$helperTmpPath}";
    remote_process($commands, callEventOnFinish: 'S3RestoreJobFinished');
}
'''
    intermediate = candidate + r'''
public function updatedS3Path($value)
{
    $this->s3FileSize = null;
    $this->s3Path = str($value)->trim()->start('/')->value();
}
'''
    repair = r'''
private function validateBucketName(string $bucket): bool
{
    return true;
}
private function validateS3Path(string $path): bool
{
    return true;
}
public function checkS3File()
{
    if (! $this->validateS3Path($cleanPath)) {}
    if (! $this->validateBucketName($s3Storage->bucket)) {}
}
public function restoreFromS3()
{
    if (! $this->validateBucketName($bucket)) {}
    if (! $this->validateS3Path($cleanPath)) {}
    $escapedS3Source = escapeshellarg("s3temp/{$bucket}/{$cleanPath}");
    $commands[] = "docker exec {$containerName} mc stat {$escapedS3Source}";
    $commands[] = "docker exec {$containerName} mc cp {$escapedS3Source} {$escapedHelperTmpPath}";
}
'''
    candidate_security_test = r'''
$endpoint = 'endpoint';
$key = 'key';
$secret = 'secret';
$command = "mc alias set {$endpoint} {$key} {$secret}";
'''
    candidate_path_test = "path traversal cleanup only"
    repair_test = " ".join(
        (
            "bucket;rm -rf /",
            "bucket$(whoami)",
            "path;rm -rf /",
            "path$(whoami)",
            "path`id`",
        )
    )

    evaluation = witness._evaluate_versions(
        parent,
        candidate,
        candidate_security_test,
        candidate_path_test,
        intermediate,
        repair,
        repair_test,
        witness._run_shell_probe(repaired=False),
        witness._run_shell_probe(repaired=True),
    )

    assert all(evaluation.values())
