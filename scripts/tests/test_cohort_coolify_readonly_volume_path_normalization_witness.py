"""Tests for the Coolify read-only volume normalization witness."""

from __future__ import annotations

import pytest

import cohort_coolify_readonly_volume_path_normalization_witness as witness


def test_path_normalization_semantics_close_only_slash_drift() -> None:
    result = witness._path_normalization_semantics()

    assert result["passed"] is True
    assert all(result["checks"].values())
    by_key = {row["key"]: row for row in result["cases"]}
    assert by_key["stored_mount_missing_leading_slash"]["candidate_matches"] is False
    assert by_key["stored_mount_missing_leading_slash"]["fixed_matches"] is True
    assert by_key["different_paths_remain_distinct"]["fixed_matches"] is False


def test_method_contract_distinguishes_literal_and_normalized_branches() -> None:
    candidate = """
    public function isReadOnlyVolume(): bool
    {
        if ($containerPath === $this->mount_path) { return $options === 'ro'; }
        elseif (is_array($volume)) {
            $containerPath = data_get($volume, 'target');
            $readOnly = data_get($volume, 'read_only', false);
            if ($containerPath === $this->mount_path) { return $readOnly === true; }
        }
    }
    """
    fixed = """
    public function isReadOnlyVolume(): bool
    {
        $mountPath = str($this->mount_path)->ltrim('/')->toString();
        $containerPathClean = str($containerPath)->ltrim('/')->toString();
        if ($mountPath === $containerPathClean || $this->mount_path === $containerPath) {}
        elseif (is_array($volume)) {
            $containerPath = data_get($volume, 'target');
            $readOnly = data_get($volume, 'read_only', false);
            $mountPath = str($this->mount_path)->ltrim('/')->toString();
            $containerPathClean = str($containerPath)->ltrim('/')->toString();
            if ($mountPath === $containerPathClean || $this->mount_path === $containerPath) {}
        }
    }
    """

    candidate_contract = witness._method_contract(candidate)
    fixed_contract = witness._method_contract(fixed)

    assert candidate_contract["handles_long_form_array"] is True
    assert candidate_contract["literal_compare_count"] == 2
    assert candidate_contract["mount_normalization_count"] == 0
    assert fixed_contract["literal_compare_count"] == 0
    assert fixed_contract["mount_normalization_count"] == 2
    assert fixed_contract["target_normalization_count"] == 2
    assert fixed_contract["normalized_compare_count"] == 2


def test_test_contract_exposes_mirrored_helper_blind_spot() -> None:
    blind_test = """
    // This mirrors the logic in LocalFileVolume::isReadOnlyVolume()
    if ($containerPath === $mountPath) {}
    expect(isVolumeReadOnly($compose, 'app', '/etc/config'))->toBeTrue();
    """
    mismatch_test = (
        blind_test
        + """
    expect(isVolumeReadOnly($compose, 'app', 'etc/config'))->toBeTrue();
    """
    )

    blind_contract = witness._test_contract(blind_test)
    mismatch_contract = witness._test_contract(mismatch_test)

    assert blind_contract["mirrors_production_logic"] is True
    assert blind_contract["helper_has_no_path_normalization"] is True
    assert blind_contract["all_mount_arguments_have_leading_slash"] is True
    assert blind_contract["has_leading_slash_mismatch_case"] is False
    assert mismatch_contract["all_mount_arguments_have_leading_slash"] is False
    assert mismatch_contract["has_leading_slash_mismatch_case"] is True


def test_ai_provenance_requires_scan_census_and_claude_markers() -> None:
    sha = "a" * 40
    ai_row = {
        "sha": sha,
        "source_modules": ["coauthor_trailer"],
        "tools": ["claude_code"],
        "message": (
            "Generated with [Claude Code]\n\n"
            "Co-Authored-By: Claude <noreply@anthropic.com>"
        ),
    }
    census_row = {"sha": sha, "observed_ai_commit": True}

    assert all(witness._ai_provenance_checks(sha, ai_row, census_row).values())

    ai_row["tools"] = []
    checks = witness._ai_provenance_checks(sha, ai_row, census_row)
    assert checks["claude_code_tool_present"] is False


def test_single_sha_row_fails_closed_on_missing_or_duplicate_rows() -> None:
    sha = "a" * 40
    row = {"sha": sha}

    assert witness._single_sha_row([row], sha) is row
    with pytest.raises(ValueError, match="resolved to 0 rows"):
        witness._single_sha_row([], sha)
    with pytest.raises(ValueError, match="resolved to 2 rows"):
        witness._single_sha_row([row, dict(row)], sha)
