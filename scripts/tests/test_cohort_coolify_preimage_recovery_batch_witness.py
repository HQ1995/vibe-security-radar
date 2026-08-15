"""Tests for exact causal witnesses recovered by the preimage overlay."""

from __future__ import annotations

import subprocess
from pathlib import Path

from cohort_coolify_preimage_recovery_batch_witness import RepairCase, build_witness


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", "-A")
    _git(
        repository,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        message,
    )
    return _git(repository, "rev-parse", "HEAD")


def test_witness_requires_ai_delta_persistence_and_exact_repair(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    source = repository / "Policy.php"
    source.write_text("<?php\nreturn true;\n", encoding="utf-8")
    _commit(repository, "baseline")
    source.write_text("<?php\nreturn activeRole();\n", encoding="utf-8")
    candidate = _commit(repository, "AI incomplete repair")
    (repository / "README.md").write_text("followup\n", encoding="utf-8")
    _commit(repository, "unrelated followup")
    source.write_text("<?php\nreturn targetRole($team);\n", encoding="utf-8")
    fix = _commit(repository, "bind role to target")
    case = RepairCase(
        key="synthetic_target_context",
        candidate_sha=candidate,
        fix_sha=fix,
        path="Policy.php",
        adjudication="CONFIRMED_DIRECT_AI_INCOMPLETE_AUTHORIZATION_REPAIR",
        mechanism_group="synthetic_target_context",
        claim="synthetic exact repair",
        candidate_added=("return activeRole();",),
        candidate_absent=("targetRole",),
        pre_fix_present=("return activeRole();",),
        pre_fix_absent=("targetRole",),
        fix_removed=("return activeRole();",),
        fix_added=("return targetRole($team);",),
    )

    payload = build_witness(
        repository,
        observed_ai_shas={candidate},
        overlay_edges={(candidate, fix)},
        cases=[case],
    )

    assert payload["witness_passed"] is True
    assert payload["summary"] == {
        "confirmed_edge_count": 1,
        "unique_candidate_count": 1,
        "mechanism_group_count": 1,
        "failed_case_count": 0,
    }
    assert all(payload["case_results"][0]["checks"].values())


def test_missing_overlay_edge_fails_closed(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    source = repository / "job.txt"
    source.write_text("safe\n", encoding="utf-8")
    _commit(repository, "baseline")
    source.write_text("unsafe\n", encoding="utf-8")
    candidate = _commit(repository, "candidate")
    source.write_text("guarded\n", encoding="utf-8")
    fix = _commit(repository, "fix")
    case = RepairCase(
        key="synthetic_guard",
        candidate_sha=candidate,
        fix_sha=fix,
        path="job.txt",
        adjudication="CONFIRMED_DIRECT_AI_FUNCTIONAL_REGRESSION",
        mechanism_group="synthetic_guard",
        claim="synthetic",
        candidate_added=("unsafe",),
        candidate_absent=("guarded",),
        pre_fix_present=("unsafe",),
        pre_fix_absent=("guarded",),
        fix_removed=("unsafe",),
        fix_added=("guarded",),
    )

    payload = build_witness(
        repository,
        observed_ai_shas={candidate},
        overlay_edges=set(),
        cases=[case],
    )

    assert payload["witness_passed"] is False
    checks = payload["case_results"][0]["checks"]
    assert checks["edge_recovered_by_preimage_overlay"] is False
