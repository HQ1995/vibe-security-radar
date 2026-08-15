"""Tests for the deterministic Coolify deployment rollback causal witness."""

from __future__ import annotations

from pathlib import Path

import cohort_coolify_deployment_rollback_causal_batch_witness as witness


def test_image_identity_semantics_separate_same_commit_configurations() -> None:
    result = witness._image_identity_semantics()

    assert result["passed"] is True
    assert all(result["checks"].values())
    assert result["candidate_tags"][0] == result["candidate_tags"][1]
    assert result["fixed_tags"][0] != result["fixed_tags"][1]


def test_legacy_env_symlink_semantics_prove_overwrite_and_unlink_repair(
    tmp_path: Path,
) -> None:
    result = witness._simulate_legacy_env_symlink(tmp_path)

    assert result["passed"] is True
    assert all(result["checks"].values())
    assert (
        result["candidate_snapshot_after_write_sha256"]
        != result["fixed_snapshot_after_write_sha256"]
    )


def test_historical_environment_semantics_distinguish_current_state() -> None:
    result = witness._historical_environment_semantics()

    assert result["passed"] is True
    assert all(result["checks"].values())
    assert (
        result["historical_environment_sha256"] != result["current_environment_sha256"]
    )
    assert "rollback_deployment_uuid" not in result["candidate_queue_fields"]
    assert "rollback_deployment_uuid" in result["fixed_queue_fields"]


def test_independence_checks_require_three_distinct_mechanisms_and_surfaces() -> None:
    cases = [
        {
            "candidate_sha": witness.CANDIDATE_SHA,
            "fix_sha": witness.IMAGE_IDENTITY_FIX_SHA,
            "mechanism_group": witness.IMAGE_MECHANISM,
            "failure_surface": "built_image_identity",
        },
        {
            "candidate_sha": witness.CANDIDATE_SHA,
            "fix_sha": witness.SYMLINK_FIX_SHA,
            "mechanism_group": witness.SYMLINK_MECHANISM,
            "failure_surface": "snapshot_file_integrity",
        },
        {
            "candidate_sha": witness.CANDIDATE_SHA,
            "fix_sha": witness.HISTORICAL_ENV_FIX_SHA,
            "mechanism_group": witness.HISTORICAL_ENV_MECHANISM,
            "failure_surface": "rollback_rebuild_input_state",
        },
    ]

    assert all(witness._independence_checks(cases).values())

    cases[2]["mechanism_group"] = witness.SYMLINK_MECHANISM
    checks = witness._independence_checks(cases)
    assert checks["three_distinct_mechanism_groups"] is False


def test_candidate_ai_checks_require_scan_and_explicit_claude_provenance() -> None:
    row = {
        "sha": witness.CANDIDATE_SHA,
        "source_modules": ["coauthor_trailer"],
        "message": (
            "Implement rollback\n\n"
            "Generated with [Claude Code]\n\n"
            "Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
        ),
    }

    assert all(witness._candidate_ai_checks(row).values())

    row["source_modules"] = []
    checks = witness._candidate_ai_checks(row)
    assert checks["candidate_has_coauthor_trailer_source"] is False
