"""End-to-end proof that real PR members enter the latest origin inventory."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from cohort.root_adjudication import canonical_sha256
import cohort_origin_squash_expand
from cohort_origin_squash_expand import (
    _commit_records,
    _git_output,
    _single_diff_metadata,
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
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_git_output_rejects_successful_partial_blame(
    monkeypatch, tmp_path: Path
) -> None:
    def partial_git(*args, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout="a" * 40 + " 1 1 1\n\tunchanged baseline\n",
            stderr="error: Could not read " + "b" * 40 + "\n",
        )

    monkeypatch.setattr(cohort_origin_squash_expand.subprocess, "run", partial_git)

    assert _git_output(tmp_path, ["blame", "HEAD", "--", "app.py"], timeout=30) == ""


def test_diff_metadata_falls_back_to_tree_paths(monkeypatch, tmp_path: Path) -> None:
    def partial_numstat(arguments, **kwargs):
        if "--numstat" in arguments:
            return SimpleNamespace(
                returncode=128,
                stdout="",
                stderr="fatal: unable to read " + "b" * 40 + "\n",
            )
        return SimpleNamespace(
            returncode=0,
            stdout="README.md\nsrc/app.py\n",
            stderr="",
        )

    monkeypatch.setattr(cohort_origin_squash_expand.subprocess, "run", partial_numstat)

    assert _single_diff_metadata(tmp_path, "a" * 40, timeout=30) == {
        "changed_files": ["README.md", "src/app.py"],
        "code_files_changed": ["src/app.py"],
        "empty_commit": False,
    }


def test_commit_record_batch_failure_isolated_per_sha(
    monkeypatch, tmp_path: Path
) -> None:
    good = ["a" * 40, "c" * 40]
    bad = "b" * 40

    def poisoned_batch(repo, arguments, *, timeout):
        shas = arguments[3:]
        if len(shas) != 1 or shas[0] == bad:
            return ""
        sha = shas[0]
        return (
            f"\x1e{sha}\x1fAuthor\x1fa@example.com\x1fCommitter"
            "\x1fc@example.com\x1f2026-01-01T00:00:00+00:00\x1fsubject"
        )

    monkeypatch.setattr(cohort_origin_squash_expand, "_git_output", poisoned_batch)

    assert set(_commit_records(tmp_path, [*good, bad], timeout=30)) == set(good)


def test_cli_hydrates_pr_number_and_keeps_ai_and_unattributed_members(
    monkeypatch, tmp_path: Path,
) -> None:
    identity = "github.com/example/repo"
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "remote", "add", "origin", "https://github.com/example/repo")
    _commit(repo, "base", "value = 0\n")
    _git(repo, "switch", "-c", "pull-7")
    member_ai = _commit(
        repo,
        "introduce path\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        "value = 1\n",
    )
    member_unattributed = _commit(repo, "wire path", "value = 2\n")
    _git(repo, "update-ref", "refs/cohort/pull/7", member_unattributed)
    _git(repo, "switch", "main")
    _git(repo, "merge", "--squash", "pull-7")
    landed = _commit(repo, "land feature (#7)", "value = 2\n")
    fix = _commit(repo, "fix feature", "value = 0\n")

    scan_rows = [
        {
            "repository_identity": identity,
            "sha": landed,
            "authored_date": "2099-01-03T00:00:00+00:00",
            "merge_topology": "squash",
            "pr_number": 7,
            "agent_kinds": ["assistant"],
            "signal_types": ["co_author_trailer"],
            "source_modules": ["coauthor_trailer"],
            "tools": ["claude_code"],
        }
    ]
    scan_dir = tmp_path / "scan"
    _jsonl(scan_dir / "commits.jsonl", scan_rows)

    candidates = [
        {
            "advisory": "CVE-2099-0001",
            "repository_identity": identity,
            "fix_sha": fix,
            "sha": landed,
            "signals": ["affected_file_history"],
            "priority_rank": 1,
            "materialization": "structural_signal",
            "observed_ai_unit": True,
            "merge_topology": "squash",
            "retained": True,
        }
    ]
    fixes = [
        {
            "advisory": "CVE-2099-0001",
            "repository_identity": identity,
            "fix_sha": fix,
            "repository_path": str(repo),
            "status": "RESOLVED",
        }
    ]
    generated = tmp_path / "generated"
    _jsonl(generated / "candidates.jsonl", candidates)
    _jsonl(generated / "fixes.jsonl", fixes)
    _json(
        generated / "summary.json",
        {
            "schema_version": 1,
            "artifact_kind": "proof_carrying_origin_candidate_reduction",
            "split_id": "toy-squash-v1",
            "candidate_rows_sha256": canonical_sha256(candidates),
            "fix_rows_sha256": canonical_sha256(fixes),
            "ai_scan_inputs": [
                {
                    "directory": str(scan_dir),
                    "commit_rows_sha256": canonical_sha256(scan_rows),
                }
            ],
        },
    )

    real_commit_records = cohort_origin_squash_expand._commit_records
    real_diff_metadata = cohort_origin_squash_expand._diff_metadata

    def incomplete_commit_records(repo, shas, *, timeout):
        records = real_commit_records(repo, shas, timeout=timeout)
        records.pop(member_unattributed)
        return records

    def incomplete_diff_metadata(repo, shas, *, timeout):
        metadata = real_diff_metadata(repo, shas, timeout=timeout)
        metadata.pop(member_unattributed)
        return metadata

    monkeypatch.setattr(
        cohort_origin_squash_expand,
        "_materialize_member_parents",
        lambda repo, shas, timeout: {member_unattributed},
    )
    monkeypatch.setattr(
        cohort_origin_squash_expand, "_commit_records", incomplete_commit_records
    )
    monkeypatch.setattr(
        cohort_origin_squash_expand, "_diff_metadata", incomplete_diff_metadata
    )

    output = tmp_path / "expanded"
    assert (
        main(
            [
                "--generated-dir",
                str(generated),
                "--no-fetch",
                "--output-dir",
                str(output),
            ]
        )
        == 0
    )

    expanded = [
        json.loads(line)
        for line in (output / "candidates.jsonl").read_text().splitlines()
    ]
    rows = {row["sha"]: row for row in expanded}
    assert set(rows) == {landed, member_ai, member_unattributed}
    assert rows[member_ai]["observed_ai_unit"] is True
    assert rows[member_unattributed]["observed_ai_unit"] is False
    assert rows[member_unattributed]["member_attribution_status"] == (
        "UNKNOWN_MEMBER_METADATA"
    )
    assert rows[member_unattributed]["member_parent_metadata_complete"] is False
    assert rows[member_unattributed]["member_record_metadata_complete"] is False
    assert rows[member_unattributed]["member_diff_metadata_complete"] is False
    assert rows[member_unattributed]["retained"] is True
    assert rows[member_unattributed]["squash_internal_blame_line_count"] >= 1
    assert "squash_internal_fix_context_blame" in rows[member_unattributed]["signals"]
    summary = json.loads((output / "summary.json").read_text())
    assert summary["resolved_squash_relation_root_count"] == 1
    assert summary["blocked_squash_relation_root_count"] == 0
    assert summary["recovered_atomic_member_count"] == 2
    assert summary["member_level_ai_signal_count"] == 1
    assert summary["atomic_member_pairs_with_internal_fix_context_blame"] >= 1
    assert summary["all_parent_candidates_retained"] is True
    root = json.loads((output / "relation_roots.jsonl").read_text())
    assert root["status"] == "RESOLVED"
    assert set(root["reason"].split(";")) == {
        "member_parent_metadata_incomplete_fail_open",
        "member_read_metadata_incomplete_fail_open",
        "member_diff_metadata_incomplete_fail_open",
    }
    assert root["member_parent_metadata_gap_shas"] == [member_unattributed]
    assert root["member_record_metadata_gap_shas"] == [member_unattributed]
    assert root["member_diff_metadata_gap_shas"] == [member_unattributed]


def test_cli_recursively_expands_nested_squash_and_blocks_at_depth_limit(
    tmp_path: Path,
) -> None:
    identity = "github.com/example/repo"
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "remote", "add", "origin", "https://github.com/example/repo")
    _commit(repo, "base", "value = 0\n")

    _git(repo, "switch", "-c", "pull-8")
    nested_ai = _commit(
        repo,
        "introduce nested bug\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        "value = 1\n",
    )
    _git(repo, "update-ref", "refs/cohort/pull/8", nested_ai)

    _git(repo, "switch", "main")
    _git(repo, "switch", "-c", "inner-integration")
    _git(repo, "merge", "--squash", "pull-8")
    nested_landed = _commit(repo, "land nested feature (#8)", "value = 1\n")
    _git(repo, "update-ref", "refs/cohort/pull/7", nested_landed)

    _git(repo, "switch", "main")
    _git(repo, "merge", "--squash", "inner-integration")
    outer_landed = _commit(repo, "land outer feature (#7)", "value = 1\n")
    fix = _commit(repo, "fix feature", "value = 0\n")

    scan_rows = [
        {
            "repository_identity": identity,
            "sha": outer_landed,
            "authored_date": "2099-01-03T00:00:00+00:00",
            "merge_topology": "squash",
            "pr_number": 7,
            "agent_kinds": ["assistant"],
            "signal_types": ["co_author_trailer"],
            "source_modules": ["coauthor_trailer"],
            "tools": ["claude_code"],
        }
    ]
    scan_dir = tmp_path / "scan"
    _jsonl(scan_dir / "commits.jsonl", scan_rows)
    candidates = [
        {
            "advisory": "CVE-2099-0002",
            "repository_identity": identity,
            "fix_sha": fix,
            "sha": outer_landed,
            "signals": ["affected_file_history"],
            "priority_rank": 1,
            "materialization": "structural_signal",
            "observed_ai_unit": True,
            "merge_topology": "squash",
            "retained": True,
        }
    ]
    fixes = [
        {
            "advisory": "CVE-2099-0002",
            "repository_identity": identity,
            "fix_sha": fix,
            "repository_path": str(repo),
            "status": "RESOLVED",
        }
    ]
    generated = tmp_path / "generated"
    _jsonl(generated / "candidates.jsonl", candidates)
    _jsonl(generated / "fixes.jsonl", fixes)
    _json(
        generated / "summary.json",
        {
            "schema_version": 1,
            "artifact_kind": "proof_carrying_origin_candidate_reduction",
            "split_id": "toy-recursive-squash-v1",
            "candidate_rows_sha256": canonical_sha256(candidates),
            "fix_rows_sha256": canonical_sha256(fixes),
            "ai_scan_inputs": [
                {
                    "directory": str(scan_dir),
                    "commit_rows_sha256": canonical_sha256(scan_rows),
                }
            ],
        },
    )

    limited = tmp_path / "limited"
    assert (
        main(
            [
                "--generated-dir",
                str(generated),
                "--no-fetch",
                "--max-squash-depth",
                "1",
                "--output-dir",
                str(limited),
            ]
        )
        == 0
    )
    limited_gaps = [
        json.loads(line)
        for line in (limited / "scope_gaps.jsonl").read_text().splitlines()
    ]
    assert len(limited_gaps) == 1
    assert limited_gaps[0]["candidate_sha"] == nested_landed
    assert limited_gaps[0]["gap_type"] == "nested_squash_depth_limit"
    assert limited_gaps[0]["status"] == "BLOCKED"

    output = tmp_path / "expanded"
    assert (
        main(
            [
                "--generated-dir",
                str(generated),
                "--no-fetch",
                "--max-squash-depth",
                "2",
                "--output-dir",
                str(output),
            ]
        )
        == 0
    )
    expanded = [
        json.loads(line)
        for line in (output / "candidates.jsonl").read_text().splitlines()
    ]
    rows = {row["sha"]: row for row in expanded}
    assert set(rows) == {outer_landed, nested_landed, nested_ai}
    assert rows[nested_ai]["observed_ai_unit"] is True
    assert rows[nested_ai]["squash_relation_depth"] == 2
    assert rows[nested_ai]["squash_group_ids"] == sorted(
        [outer_landed, nested_landed]
    )
    assert rows[nested_ai]["relation_evidence"][0]["relation_path"] == [
        "pull_request_member_landed_as_squash",
        "pull_request_member_landed_as_squash",
        "reachable_ancestor",
    ]
    summary = json.loads((output / "summary.json").read_text())
    assert summary["expanded_squash_depth_count"] == 2
    assert summary["squash_relation_root_count"] == 2
    assert summary["nested_squash_depth_limit_gap_count"] == 0
    assert summary["member_level_ai_signal_count"] == 1


def test_cli_expands_prospective_signal_carrier_without_carrier_ai_label(
    tmp_path: Path,
) -> None:
    identity = "github.com/example/repo"
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "remote", "add", "origin", "https://github.com/example/repo")
    base = _commit(repo, "base", "value = 0\n")
    _git(repo, "switch", "-c", "pull-7")
    member_ai = _commit(
        repo,
        "introduce path\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        "value = 1\n",
    )
    member_unattributed = _commit(repo, "wire path", "value = 2\n")
    _git(repo, "update-ref", "refs/cohort/pull/7", member_unattributed)
    _git(repo, "switch", "main")
    _git(repo, "merge", "--squash", "pull-7")
    landed = _commit(repo, "land feature (#7)", "value = 2\n")
    fix = _commit(repo, "fix feature", "value = 0\n")

    candidates = [
        {
            "ai_routes": [],
            "ai_tools": [],
            "observed_ai_unit": False,
            "priority_class": "P1_CAUSAL_SIGNAL",
            "priority_rank": 1,
            "primary_lane": "affected_file_history",
            "retained": True,
            "sha": landed,
            "signals": ["affected_file_history"],
            "subject": "land feature (#7)",
            "within_priority_class_rank": 1,
        },
        {
            "ai_routes": [],
            "ai_tools": [],
            "observed_ai_unit": False,
            "priority_class": "P3_AFFECTED_FILE_HISTORY",
            "priority_rank": 2,
            "primary_lane": "affected_file_history",
            "retained": True,
            "sha": member_unattributed,
            "signals": ["affected_file_history"],
            "subject": "wire path",
            "within_priority_class_rank": 1,
        },
    ]
    signal_dir = tmp_path / "signal"
    _jsonl(signal_dir / "candidates.jsonl", candidates)
    _json(
        signal_dir / "summary.json",
        {
            "schema_version": 2,
            "artifact_kind": "recall_first_origin_signal_pilot",
            "advisory": "CVE-2099-0001",
            "repository_identity": identity,
            "fix_sha": fix,
            "fix_root_role": "source_qualified_public_exact_fix",
            "root_eligibility": "target_source_qualified_public_exact",
            "coverage_status": "COMPLETE",
            "candidate_rows_sha256": canonical_sha256(candidates),
        },
    )
    universe_rows = [
        {
            "repository_identity": identity,
            "sha": base,
            "parents": [],
            "observed_ai_unit": False,
        },
        {
            "repository_identity": identity,
            "sha": landed,
            "parents": [base],
            "observed_ai_unit": False,
        },
        {
            "repository_identity": identity,
            "sha": member_unattributed,
            "parents": [member_ai],
            "observed_ai_unit": False,
        },
        {
            "repository_identity": identity,
            "sha": fix,
            "parents": [landed],
            "observed_ai_unit": False,
        },
    ]
    universe_dir = tmp_path / "universe"
    _jsonl(universe_dir / "commit_universe.jsonl", universe_rows)
    _json(
        universe_dir / "summary.json",
        {
            "schema_version": 1,
            "artifact_kind": "prospective_all_commit_universe_campaign",
            "repository_provenance": [
                {
                    "repository_identity": identity,
                    "repository_path": str(repo),
                }
            ],
        },
    )

    output = tmp_path / "expanded"
    assert (
        main(
            [
                "--signal-dir",
                str(signal_dir),
                "--universe-dir",
                str(universe_dir),
                "--no-fetch",
                "--output-dir",
                str(output),
            ]
        )
        == 0
    )
    expanded = [
        json.loads(line)
        for line in (output / "candidates.jsonl").read_text().splitlines()
    ]
    rows = {row["sha"]: row for row in expanded}
    assert set(rows) == {landed, member_ai, member_unattributed}
    assert rows[landed]["observed_ai_unit"] is False
    assert rows[member_ai]["observed_ai_unit"] is True
    # Being both a direct candidate and a recovered PR member is not AI
    # attribution. The old relation-membership shortcut promoted this row.
    assert rows[member_unattributed]["observed_ai_unit"] is False
    assert rows[member_unattributed]["retained"] is True
    summary = json.loads((output / "summary.json").read_text())
    assert summary["parent_artifact_kind"] == "recall_first_origin_signal_pilot"
    assert summary["recovered_atomic_member_count"] == 2
    assert summary["member_level_ai_signal_count"] == 1
    roots = [
        json.loads(line)
        for line in (output / "relation_roots.jsonl").read_text().splitlines()
    ]
    assert roots[0]["member_ai_signal_count"] == 1
    assert summary["all_parent_candidates_retained"] is True
