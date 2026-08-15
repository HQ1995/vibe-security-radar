"""Tests for semantic, add-only repair-chain expansion."""

from __future__ import annotations

import subprocess
from pathlib import Path

from cohort_expand_repair_chain import (
    expand_repair_chain,
    repair_review_lane,
    repair_review_score,
    repair_signals,
)


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def test_repair_signals_only_read_added_lines() -> None:
    patch = """diff --git a/x.php b/x.php
--- a/x.php
+++ b/x.php
@@ -1 +1 @@
-$this->authorize('view', $token);
+$value = 1;
"""
    assert repair_signals(patch) == []
    assert repair_signals(
        "@@ -1 +1 @@\n-old\n+$this->authorize('view', $token);\n"
    ) == ["resource_authorization"]


def test_review_lanes_prioritize_tests_without_dropping_noisy_signals() -> None:
    assert repair_review_lane([], already_in_seed_manifest=True) == (
        0,
        "sealed_seed_fix",
    )
    assert repair_review_lane(
        ["cross_tenant_regression", "team_scope"],
        already_in_seed_manifest=False,
    ) == (1, "explicit_security_regression")
    assert repair_review_lane(
        ["team_scope"], already_in_seed_manifest=False
    ) == (2, "authorization_or_tenant_scope")
    assert repair_review_lane(
        ["sensitive_default_hiding"], already_in_seed_manifest=False
    ) == (3, "authentication_or_sensitive_data_boundary")
    assert repair_review_lane(
        ["command_input_validation"], already_in_seed_manifest=False
    ) == (4, "command_input_validation")
    assert repair_review_lane([], already_in_seed_manifest=False) == (
        5,
        "recall_fallback",
    )

    neutral_score, neutral_features = repair_review_score(
        ["team_scope"],
        subject="feat: add project picker",
        shared_paths=["app/Picker.php"],
    )
    regression_score, regression_features = repair_review_score(
        ["team_scope"],
        subject="fix(auth): enforce project scope",
        shared_paths=["app/Picker.php", "tests/Feature/ProjectScopeTest.php"],
    )
    assert regression_score > neutral_score
    assert neutral_features == []
    assert regression_features == [
        "regression_test_path",
        "security_specific_subject",
        "repair_action_subject",
    ]


def test_expansion_recovers_neutral_subject_repair_without_dropping_seed(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "Test")
    _git(repository, "config", "user.email", "test@example.com")

    source = repository / "Index.php"
    source.write_text(
        "<?php\n$project = Project::find($selectedProject);\n",
        encoding="utf-8",
    )
    _commit(repository, "initial feature")
    source.write_text(
        "<?php\n$project = Project::ownedByCurrentTeam()->find($selectedProject);\n",
        encoding="utf-8",
    )
    repair_sha = _commit(repository, "refactor: scope project query")
    source.write_text(
        source.read_text(encoding="utf-8")
        + "$this->authorize('view', $project);\n",
        encoding="utf-8",
    )
    seed_sha = _commit(repository, "fix(security): enforce access")

    manifest = {
        "schema_version": 1,
        "artifact_kind": "sealed_fix_manifest",
        "split_id": "seed-v1",
        "frozen_at": "2026-08-01T00:00:00Z",
        "fixes": [
            {
                "advisory": "GHSA-test",
                "repository_identity": "github.com/acme/repo",
                "fix_sha": seed_sha,
            }
        ],
    }
    expanded, provenance = expand_repair_chain(
        manifest,
        {"github.com/acme/repo": repository},
        split_id="expanded-v1",
        frozen_at="2026-08-01T00:00:00Z",
    )
    expanded_shas = {row["fix_sha"] for row in expanded["fixes"]}

    assert expanded_shas == {repair_sha, seed_sha}
    assert provenance["all_seed_fixes_retained"] is True
    assert provenance["seed_fix_count"] == 1
    assert provenance["added_fix_count"] == 1
    assert provenance["repair_schedule_conserves_all_fixes"] is True
    assert len(provenance["repair_schedule"]) == len(expanded["fixes"])
    assert sum(provenance["repair_schedule_lane_counts"].values()) == len(
        expanded["fixes"]
    )
    assert [row["review_lane"] for row in provenance["repair_schedule"]] == [
        "sealed_seed_fix",
        "authorization_or_tenant_scope",
    ]
    assert [row["priority_rank"] for row in provenance["repair_schedule"]] == [
        1,
        2,
    ]
    repair = next(
        row
        for row in provenance["repair_evidence"]
        if row["repair_sha"] == repair_sha
    )
    assert repair["signals"] == ["team_scope"]
    assert repair["source_seed_shas"] == [seed_sha]
