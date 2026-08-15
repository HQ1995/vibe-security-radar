"""Tests for the lossless Coolify cross-file dependency bridge scheduler."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import cohort_coolify_dependency_bridge_schedule as bridge
from cohort.root_adjudication import canonical_sha256


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        message,
    )
    return _git(repo, "rev-parse", "HEAD")


def _write_reduction(
    directory: Path, candidates: list[dict[str, object]], fix_sha: str
) -> None:
    directory.mkdir()
    fixes = [
        {
            "advisory": "TEST",
            "repository_identity": "github.com/example/repo",
            "fix_sha": fix_sha,
        }
    ]
    summary = {
        "artifact_kind": "proof_carrying_origin_candidate_reduction",
        "candidate_rows_sha256": canonical_sha256(candidates),
        "fix_rows_sha256": canonical_sha256(fixes),
    }
    (directory / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    (directory / "candidates.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in candidates), encoding="utf-8"
    )
    (directory / "fixes.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in fixes), encoding="utf-8"
    )


def test_dependency_tokens_keep_internal_fqcn_and_drop_generic_symbol() -> None:
    fqcns, symbols = bridge._dependency_tokens(
        "namespace App\\Livewire\\Notifications;\n"
        "use App\\Models\\WebhookNotificationSettings;\n"
        "use App\\Models\\User;\n"
    )

    assert "app\\models\\webhooknotificationsettings" in fqcns
    assert "webhooknotificationsettings" in symbols
    assert "app\\livewire\\notifications" not in fqcns
    assert "app\\models\\user" not in fqcns
    assert "user" not in symbols


def test_cli_promotes_cross_file_dependency_without_dropping_edges(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    (repo / "app/Livewire").mkdir(parents=True)
    (repo / "app/Providers").mkdir(parents=True)
    component = repo / "app/Livewire/SecretPanel.php"
    provider = repo / "app/Providers/AuthServiceProvider.php"
    component.write_text(
        "<?php\nuse App\\Models\\SecretNotificationSettings;\n"
        "class SecretPanel { public function syncData() { expose($this->settings); } }\n",
        encoding="utf-8",
    )
    provider.write_text("<?php\nreturn [];\n", encoding="utf-8")
    baseline = _commit(repo, "baseline")

    provider.write_text(
        "<?php\nreturn [\\App\\Models\\SecretNotificationSettings::class => Policy::class];\n",
        encoding="utf-8",
    )
    dependency_candidate = _commit(repo, "wire policy")
    (repo / "unrelated.php").write_text("<?php\nhelper();\n", encoding="utf-8")
    unrelated_candidate = _commit(repo, "unrelated")
    component.write_text(
        "<?php\nuse App\\Models\\SecretNotificationSettings;\n"
        "class SecretPanel { public function syncData() { if (canUpdate()) { expose($this->settings); } } }\n",
        encoding="utf-8",
    )
    fix_sha = _commit(repo, "protect secret")

    candidates = [
        {
            "advisory": "TEST",
            "repository_identity": "github.com/example/repo",
            "fix_sha": fix_sha,
            "sha": baseline,
            "priority_rank": 1,
            "priority_class": "P0_OBSERVED_AI_CAUSAL_SIGNAL",
            "signals": ["szz_file_local"],
            "materialization": "structural_signal",
            "retained": True,
        },
        {
            "advisory": "TEST",
            "repository_identity": "github.com/example/repo",
            "fix_sha": fix_sha,
            "sha": dependency_candidate,
            "priority_rank": 2,
            "priority_class": "P4_OBSERVED_AI_ANCESTRY_FALLBACK",
            "signals": ["ai_ancestry_fallback"],
            "materialization": "exact_ai_ancestry_fallback",
            "retained": True,
        },
        {
            "advisory": "TEST",
            "repository_identity": "github.com/example/repo",
            "fix_sha": fix_sha,
            "sha": unrelated_candidate,
            "priority_rank": 3,
            "priority_class": "P4_OBSERVED_AI_ANCESTRY_FALLBACK",
            "signals": ["ai_ancestry_fallback"],
            "materialization": "exact_ai_ancestry_fallback",
            "retained": True,
        },
    ]
    reduction = tmp_path / "reduction"
    _write_reduction(reduction, candidates, fix_sha)
    output = tmp_path / "schedule.json"

    assert (
        bridge.main(
            [
                "--reduction-dir",
                str(reduction),
                "--repository",
                str(repo),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    rows = {row["candidate_sha"]: row for row in payload["edge_schedule"]}

    assert payload["conservation"]["passed"] is True
    assert payload["conservation"]["output_edge_count"] == 3
    assert rows[dependency_candidate]["dependency_priority_class"] == (
        "P1_EXACT_INTERNAL_DEPENDENCY_FQCN"
    )
    assert rows[dependency_candidate]["within_fix_review_rank"] == 2
    assert rows[unrelated_candidate]["dependency_priority_class"] == (
        "P4_AI_ANCESTRY_FALLBACK"
    )
    assert rows[unrelated_candidate]["candidate_retained"] is True
