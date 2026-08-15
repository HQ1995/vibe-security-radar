"""Tests for the lossless fix-preimage lineage scheduling lane."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import cohort_coolify_fix_preimage_lineage as lineage


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


def _commit_index(repo: Path, message: str) -> str:
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


def _edge(candidate: str, fix: str, status: str) -> dict[str, object]:
    return {
        "repository_identity": "github.com/example/repo",
        "candidate_sha": candidate,
        "fix_sha": fix,
        "status": status,
        "adjudication": "UNADJUDICATED_RETAINED",
        "candidate_retained": True,
    }


def test_method_signature_parser_finds_php_python_rust_go_and_typescript() -> None:
    lines = [
        "class Example {",
        "    public function update($value)",
        "    {",
        "        mutate($value);",
        "    }",
        "}",
        "def validate(value):",
        "    return value",
        "pub async fn persist(value: String) {",
        "}",
        "func (s *Server) Delete() {",
        "}",
        "export async function authorize(input: string) {",
        "    return input;",
        "}",
        "export const normalize = (input: string) => input.trim();",
    ]

    assert lineage._method_signature_lines(lines, [4, 8, 10, 12, 14, 16]) == (
        2,
        7,
        9,
        11,
        13,
        16,
    )


def test_test_only_direct_lineage_cannot_receive_runtime_p0() -> None:
    tier, priority = lineage._priority(
        evidence_rows=[
            {
                "line_kind": "direct_preimage",
                "guard_like_hunk": True,
                "path_kind": "test",
            }
        ],
        coverage_incomplete=False,
    )

    assert (tier, priority) == (6, "P6_NON_RUNTIME_LINEAGE_ONLY")


def test_fix_evidence_records_gitlinks_as_not_blameable_without_coverage_gap(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    gitlink_path = ".workspaces/example"
    first_target = "a" * 40
    second_target = "b" * 40
    _git(
        repo,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{first_target},{gitlink_path}",
    )
    _commit_index(repo, "add workspace gitlink")
    _git(
        repo,
        "update-index",
        "--cacheinfo",
        f"160000,{second_target},{gitlink_path}",
    )
    fix_sha = _commit_index(repo, "update workspace gitlink")

    evidence = lineage._fix_evidence(
        repo,
        fix_sha,
        context_radius=12,
        copy_aware_enabled=False,
        timeout=30,
    )

    assert evidence.coverage_gaps == ()
    assert evidence.local_blame == {}
    assert evidence.skipped_parent_entries == (
        {
            "path": gitlink_path,
            "reason": "non_blob_parent_entry",
            "mode": "160000",
            "object_type": "commit",
            "object_sha": first_target,
        },
    )


def test_cli_keeps_every_edge_and_surfaces_direct_and_add_only_owners(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")

    source = repo / "Panel.php"
    source.write_text(
        "<?php\nclass Panel\n{\n    public function mutate($input)\n"
        "    {\n        dangerous('constant');\n    }\n}\n",
        encoding="utf-8",
    )
    baseline = _commit(repo, "baseline")

    source.write_text(
        "<?php\nclass Panel\n{\n    public function mutate($input)\n"
        "    {\n        dangerous($input);\n    }\n}\n",
        encoding="utf-8",
    )
    direct_candidate = _commit(repo, "introduce direct line")
    source.write_text(
        "<?php\nclass Panel\n{\n    public function mutate($input)\n"
        "    {\n        dangerous(escape($input));\n    }\n}\n",
        encoding="utf-8",
    )
    direct_fix = _commit(repo, "repair direct line")

    helper = repo / "DeletePanel.php"
    helper.write_text(
        "<?php\nclass DeletePanel\n{\n    public function delete()\n"
        "    {\n        destroy();\n    }\n}\n",
        encoding="utf-8",
    )
    method_candidate = _commit(repo, "add sensitive method")
    (repo / "README.md").write_text("unrelated\n", encoding="utf-8")
    _commit(repo, "unrelated followup")
    helper.write_text(
        "<?php\nclass DeletePanel\n{\n    public function delete()\n"
        "    {\n        authorize();\n        destroy();\n    }\n}\n",
        encoding="utf-8",
    )
    method_fix = _commit(repo, "add authorization check")

    edges = [
        _edge(direct_candidate, direct_fix, "DEFERRED_REVIEW_BACKLOG"),
        _edge(baseline, direct_fix, "MODEL_PROMOTED_REVIEW_REQUIRED"),
        _edge(method_candidate, method_fix, "DEFERRED_REVIEW_BACKLOG"),
        _edge(baseline, method_fix, "DEFERRED_REVIEW_BACKLOG"),
    ]
    ledger = tmp_path / "ledger.json"
    ledger.write_text(
        json.dumps(
            {
                "artifact_kind": "test_recall_ledger",
                "repository_identity": "github.com/example/repo",
                "summary": {"finite_edge_count": len(edges)},
                "edge_ledger": edges,
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "lineage.json"

    assert (
        lineage.main(
            [
                "--ledger",
                str(ledger),
                "--repository",
                str(repo),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    rows = {
        (row["candidate_sha"], row["fix_sha"]): row
        for row in payload["edge_lineage"]
    }

    assert payload["conservation"]["passed"] is True
    assert payload["conservation"]["output_edge_count"] == len(edges)
    assert rows[(direct_candidate, direct_fix)]["priority_class"] == (
        "P0_DIRECT_FIX_PREIMAGE_OWNER"
    )
    assert rows[(method_candidate, method_fix)]["priority_class"] == (
        "P1_ADD_CHECK_ENCLOSING_METHOD_OWNER"
    )
    assert rows[(baseline, direct_fix)]["candidate_retained"] is True
    assert rows[(baseline, method_fix)]["candidate_retained"] is True
    assert payload["review_schedule"][0]["candidate_sha"] == direct_candidate
