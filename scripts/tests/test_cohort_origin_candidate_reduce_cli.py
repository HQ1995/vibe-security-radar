"""End-to-end contract test for origin candidate reduction."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from cohort.root_adjudication import canonical_sha256
from cohort_origin_candidate_reduce import (
    _load_structural_inputs,
    _pre_fix_ancestry,
    main,
)


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _commit(repo: Path, message: str, content: str) -> str:
    (repo / "app.py").write_text(content, encoding="utf-8")
    _git(repo, "add", "app.py")
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


def _json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


@pytest.mark.parametrize("gate_status", ["BLOCKED", "READY_WITH_GAPS", None])
def test_structural_inputs_require_ready_gate(
    tmp_path: Path, gate_status: str | None
) -> None:
    structural_dir = tmp_path / "structural"
    candidates: list[dict[str, object]] = []
    fixes: list[dict[str, object]] = []
    _jsonl(structural_dir / "candidates.jsonl", candidates)
    _jsonl(structural_dir / "fixes.jsonl", fixes)
    _json(
        structural_dir / "summary.json",
        {
            "generation_process_boundary": "sealed_fix_only_no_golden_ledger_read",
            "gate_status": gate_status,
            "candidate_rows_sha256": canonical_sha256(candidates),
            "fix_rows_sha256": canonical_sha256(fixes),
        },
    )

    with pytest.raises(SystemExit, match="structural input is not ready"):
        _load_structural_inputs([structural_dir])


def test_pre_fix_ancestry_uses_complete_local_graph_behind_shallow_marker(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "shallow-marked-repo"
    repo.mkdir()
    _git(repo, "init")
    first = _commit(repo, "first", "value = 1\n")
    parent = _commit(repo, "parent", "value = 2\n")
    fix = _commit(repo, "fix", "value = 3\n")

    # Simulate a cache that was hydrated without removing its old shallow
    # boundary. Plain `git rev-list` would stop at `parent` even though the
    # complete object graph is locally available.
    (repo / ".git" / "shallow").write_text(parent + "\n", encoding="ascii")

    parents, ancestors = _pre_fix_ancestry(repo, fix, timeout=30)

    assert parents == [parent]
    assert ancestors == {first, parent}


def test_generate_then_evaluate_conserves_observed_ai_scope(tmp_path: Path) -> None:
    identity = "github.com/example/repo"
    advisory = "CVE-2099-0001"
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "remote", "add", "origin", "https://github.com/example/repo")
    _commit(repo, "initial", "unsafe = False\n")
    origin = _commit(
        repo,
        "introduce unsafe path\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        "unsafe = True\n",
    )
    _commit(repo, "unrelated", "unsafe = True\nother = 1\n")
    fix = _commit(repo, "fix unsafe path", "unsafe = False\nother = 1\n")
    future_ai = _commit(
        repo,
        "future AI work\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        "unsafe = False\nother = 2\n",
    )

    manifest = {
        "schema_version": 1,
        "artifact_kind": "sealed_fix_manifest",
        "split_id": "toy-reduction-v1",
        "frozen_at": "2099-01-01T00:00:00Z",
        "fixes": [
            {
                "advisory": advisory,
                "repository_identity": identity,
                "fix_sha": fix,
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    _json(manifest_path, manifest)
    aliases_path = tmp_path / "aliases.json"
    _json(aliases_path, {"schema_version": 1, "aliases": []})

    structural_dir = tmp_path / "structural"
    structural_candidates = [
        {
            "advisory": advisory,
            "repository_identity": identity,
            "fix_sha": fix,
            "sha": origin,
            "signals": ["add_context_blame"],
            "priority_rank": 1,
            "retained": True,
        }
    ]
    structural_fixes = [
        {
            "advisory": advisory,
            "repository_identity": identity,
            "fix_sha": fix,
            "repository_path": str(repo),
            "status": "RESOLVED",
            "ancestor_fallback_candidate_count": 3,
        }
    ]
    _jsonl(structural_dir / "candidates.jsonl", structural_candidates)
    _jsonl(structural_dir / "fixes.jsonl", structural_fixes)
    _json(
        structural_dir / "summary.json",
        {
            "generation_process_boundary": "sealed_fix_only_no_golden_ledger_read",
            "gate_status": "READY_FOR_SEPARATE_EVALUATION",
            "candidate_rows_sha256": canonical_sha256(structural_candidates),
            "fix_rows_sha256": canonical_sha256(structural_fixes),
        },
    )

    scan_dir = tmp_path / "scan"
    scan_rows = [
        {"repository_identity": identity, "sha": origin, "tools": ["claude_code"]},
        {
            "repository_identity": identity,
            "sha": future_ai,
            "tools": ["claude_code"],
        },
    ]
    _jsonl(scan_dir / "commits.jsonl", scan_rows)
    _json(
        scan_dir / "summary.json",
        {
            "artifact_kind": "cohort_ai_commit_scan",
            "ai_commit_count": 2,
            "since": "1970-01-01",
            "complete_repository_identities": [identity],
        },
    )

    generated_dir = tmp_path / "reduced"
    assert main(
        [
            "generate",
            "--fix-manifest",
            str(manifest_path),
            "--structural-dir",
            str(structural_dir),
            "--ai-scan-dir",
            str(scan_dir),
            "--repository-path",
            f"{identity}={repo}",
            "--aliases",
            str(aliases_path),
            "--output-dir",
            str(generated_dir),
        ]
    ) == 0
    generated_summary = json.loads(
        (generated_dir / "summary.json").read_text(encoding="utf-8")
    )
    assert generated_summary["ancestor_pair_count"] == 3
    assert generated_summary["candidate_count"] == 1
    assert generated_summary["certified_non_ancestor_count"] == 1
    candidate = json.loads(
        (generated_dir / "candidates.jsonl").read_text(encoding="utf-8")
    )
    assert candidate["sha"] == origin

    controls_path = tmp_path / "controls.json"
    _json(
        controls_path,
        {
            "controls": [
                {
                    "advisory": advisory,
                    "repository_identity": identity,
                    "fix_sha": fix,
                    "atomic_origin_sha": origin,
                    "expected_relation": "reachable_ancestor",
                }
            ]
        },
    )
    evaluation_path = generated_dir / "evaluation.json"
    assert main(
        [
            "evaluate",
            "--generated-dir",
            str(generated_dir),
            "--controls",
            str(controls_path),
            "--output",
            str(evaluation_path),
        ]
    ) == 0
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
    assert evaluation["gate_status"] == "PASS_ZERO_CONTROL_MISSES"
    assert evaluation["retained_control_count"] == 1
