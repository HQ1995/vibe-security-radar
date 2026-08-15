"""Tests for the lossless AI-descendant repair census."""

from __future__ import annotations

import subprocess
from pathlib import Path

from cohort_ai_descendant_repair_census import (
    added_repair_signals,
    build_repair_census,
    classify_review_lane,
)


IDENTITY = "github.com/acme/repo"


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _commit(repository: Path, path: str, text: str, subject: str) -> str:
    target = repository / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    _git(repository, "add", path)
    _git(repository, "commit", "-m", subject)
    return _git(repository, "rev-parse", "HEAD")


def _ai_row(sha: str) -> dict[str, object]:
    return {
        "repository_identity": IDENTITY,
        "sha": sha,
        "signal_types": ["co_author_trailer"],
        "tools": ["claude_code"],
    }


def test_added_repair_signals_recognize_neutral_guard_addition() -> None:
    patch = """@@ -1 +1,3 @@
-old
+if (! hash_equals($expected, $actual)) {
+    abort(403);
+}
"""
    assert added_repair_signals(patch) == [
        "added_guard_clause",
        "added_secure_comparison",
    ]


def test_structural_ai_proximity_promotes_message_neutral_repairs() -> None:
    tier, lane, score, signals = classify_review_lane(
        subject="Add config hash to image tags",
        changed_paths=["app/Jobs/Deployment.php"],
        patch_signals=[],
        is_merge=False,
        observed_ai_commit=False,
        direct_parent_is_observed_ai=True,
        already_in_parent_manifest=False,
        outside_parent_root_ancestry=True,
    )

    assert (tier, lane) == (3, "direct_ai_repair_proximity")
    assert score == 80
    assert "direct_child_of_observed_ai" in signals


def test_added_guard_lane_stays_high_when_structural_proximity_also_matches() -> None:
    tier, lane, score, signals = classify_review_lane(
        subject="Changes auto-committed by Conductor",
        changed_paths=["app/Service.php", "tests/Feature/ServiceTest.php"],
        patch_signals=["added_guard_clause"],
        is_merge=False,
        observed_ai_commit=True,
        direct_parent_is_observed_ai=True,
        already_in_parent_manifest=False,
        outside_parent_root_ancestry=False,
    )

    assert (tier, lane) == (2, "added_check_or_guard")
    assert score > 100
    assert "observed_ai_descendant_commit" in signals
    assert "direct_child_of_observed_ai" in signals


def test_census_retains_ai_repairs_merges_and_nonancestral_fallback(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "Test")
    _git(repository, "config", "user.email", "test@example.com")

    base = _commit(repository, "base.txt", "base\n", "base")
    _git(repository, "branch", "side", base)
    ai_one = _commit(repository, "app.php", "<?php\n$a = 1;\n", "AI feature one")
    ai_two = _commit(repository, "app.php", "<?php\n$a = 2;\n", "AI feature two")
    repair = _commit(
        repository,
        "app.php",
        "<?php\nif (! hash_equals($expected, $actual)) { abort(403); }\n",
        "adjust comparison",
    )

    _git(repository, "checkout", "side")
    side_fix = _commit(repository, "side.txt", "safe\n", "fix(security): side")
    _git(repository, "checkout", "main")
    _git(repository, "merge", "--no-ff", "side", "-m", "merge side")
    merge_sha = _git(repository, "rev-parse", "HEAD")

    parent_manifest = {
        "schema_version": 1,
        "artifact_kind": "sealed_fix_manifest",
        "split_id": "parent-v1",
        "frozen_at": "2026-08-01T00:00:00Z",
        "fixes": [
            {
                "advisory": "GHSA-existing",
                "repository_identity": IDENTITY,
                "fix_sha": side_fix,
            }
        ],
    }
    artifacts = build_repair_census(
        repository=repository,
        repository_identity=IDENTITY,
        ai_rows=[_ai_row(ai_one), _ai_row(ai_two)],
        parent_manifest=parent_manifest,
        advisory="AI-DESCENDANT-CENSUS",
        split_id="census-v1",
        frozen_at="2026-08-01T00:00:00Z",
        git_timeout=30,
    )

    summary = artifacts["summary"]
    rows = {row["sha"]: row for row in artifacts["all_commits"]}
    manifest_shas = {row["fix_sha"] for row in artifacts["manifest"]["fixes"]}
    scheduled_shas = {row["sha"] for row in artifacts["review_schedule"]}

    assert summary["all_ref_commit_count"] == 6
    assert summary["direct_ancestry_root_count"] == 3
    assert summary["direct_ancestry_pair_count"] == 5
    assert summary["all_commits_retained_once"] is True
    assert summary["hard_root_deletes"] == 0
    assert rows[ai_two]["strict_ai_ancestor_count"] == 1
    assert rows[ai_two]["route"] == "direct_ai_ancestry"
    assert rows[ai_two]["review_lane"] == "direct_ai_repair_proximity"
    assert rows[repair]["strict_ai_ancestor_count"] == 2
    assert rows[repair]["review_lane"] == "added_check_or_guard"
    assert "direct_child_of_observed_ai" in rows[repair]["review_signals"]
    assert rows[side_fix]["route"] == "sealed_parent_root_without_direct_ancestry"
    assert rows[merge_sha]["topology_kind"] == "merge_carrier"
    assert rows[merge_sha]["route"] == "direct_ai_ancestry"
    assert rows[base]["route"] == "nonancestral_topology_fallback"
    assert manifest_shas == {ai_two, repair, side_fix, merge_sha}
    assert scheduled_shas == manifest_shas


def test_census_unions_non_nested_duplicate_clone_graphs(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    primary.mkdir()
    _git(primary, "init", "-b", "main")
    _git(primary, "config", "user.name", "Test")
    _git(primary, "config", "user.email", "test@example.com")
    base = _commit(primary, "base.txt", "base\n", "base")

    secondary = tmp_path / "secondary"
    _git(tmp_path, "clone", str(primary), str(secondary))
    _git(secondary, "config", "user.name", "Test")
    _git(secondary, "config", "user.email", "test@example.com")

    primary_ai = _commit(primary, "primary.txt", "primary\n", "primary AI")
    secondary_ai = _commit(secondary, "secondary.txt", "secondary\n", "secondary AI")
    parent_manifest = {
        "schema_version": 1,
        "artifact_kind": "sealed_fix_manifest",
        "split_id": "parent-v1",
        "frozen_at": "2026-08-01T00:00:00Z",
        "fixes": [
            {
                "advisory": "EXISTING",
                "repository_identity": IDENTITY,
                "fix_sha": base,
            }
        ],
    }

    artifacts = build_repair_census(
        repository=[primary, secondary],
        repository_identity=IDENTITY,
        ai_rows=[_ai_row(primary_ai), _ai_row(secondary_ai)],
        parent_manifest=parent_manifest,
        advisory="AI-DESCENDANT-CENSUS",
        split_id="census-union-v1",
        frozen_at="2026-08-01T00:00:00Z",
        git_timeout=30,
    )

    summary = artifacts["summary"]
    rows = {row["sha"]: row for row in artifacts["all_commits"]}
    assert summary["all_ref_commit_count"] == 3
    assert summary["observed_ai_commit_count"] == 2
    assert summary["repository_clone_count"] == 2
    assert summary["repository_clone_coverage"][0]["new_union_commit_count"] == 2
    assert summary["repository_clone_coverage"][1]["new_union_commit_count"] == 1
    assert set(rows) == {base, primary_ai, secondary_ai}
