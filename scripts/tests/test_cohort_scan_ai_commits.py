"""Coverage-ledger tests for the forward AI-attributed commit scan."""

from __future__ import annotations

from pathlib import Path

import cohort_scan_ai_commits as scan
import pytest


def _result(identity: str, *, complete: bool, error: str = "") -> dict[str, object]:
    return {
        "repository_identity": identity,
        "complete": complete,
        "error": error,
        "elapsed_seconds": 0.1,
    }


def test_explicit_existing_output_directory_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir = tmp_path / "frozen-scan"
    output_dir.mkdir()
    sentinel = output_dir / "summary.json"
    sentinel.write_text("frozen\n", encoding="utf-8")
    monkeypatch.setattr(scan, "discover_local_clone_groups", lambda _root: ({}, []))

    with pytest.raises(SystemExit, match="output directory already exists"):
        scan.main(["--output-dir", str(output_dir)])

    assert sentinel.read_text(encoding="utf-8") == "frozen\n"


def test_summary_names_complete_repositories_even_when_they_have_zero_ai_commits() -> None:
    complete_zero = "github.com/example/zero"
    complete_one = "github.com/example/one"
    incomplete = "github.com/example/incomplete"
    summary = scan._build_summary(
        [
            _result(complete_zero, complete=True),
            _result(complete_one, complete=True),
            _result(incomplete, complete=False, error="scan_failed"),
        ],
        [
            {
                "repository_identity": complete_one,
                "tools": ["agent"],
                "agent_kinds": ["coding_agent"],
                "source_modules": ["trailer"],
                "signal_types": ["trailer"],
                "year": "2026",
                "merge_topology": "direct",
            }
        ],
        [],
        1.0,
        "2022-01-01",
    )

    assert summary["scanned_repository_identities"] == [
        incomplete,
        complete_one,
        complete_zero,
    ]
    assert summary["complete_repository_identities"] == [
        complete_one,
        complete_zero,
    ]
    assert summary["repositories_complete"] == 2
    assert summary["repositories_with_ai_commits"] == 1
    assert len(summary["repository_coverage_sha256"]) == 64


def test_duplicate_clone_scans_are_losslessly_unioned_by_sha() -> None:
    identity = "github.com/example/repo"
    shared = {
        "sha": "a" * 40,
        "authored_date": "2026-01-01T00:00:00Z",
        "message": "shared",
        "changed_files": ["shared.py"],
        "source_matches": [
            {
                "tool": "claude_code",
                "source_module": "coauthor_trailer",
                "signal_type": "co_author_trailer",
            }
        ],
    }
    left_only = {**shared, "sha": "b" * 40, "message": "left"}
    right_only = {**shared, "sha": "c" * 40, "message": "right"}
    merged = scan._merge_clone_scan_results(
        identity,
        [
            {
                "repo_path": "/cache/project/repo",
                "complete": True,
                "error": "",
                "refs_digest": "left-digest",
                "commits": [shared, left_only],
                "parents": {},
                "elapsed_seconds": 0.1,
            },
            {
                "repo_path": "/cache/home/repo",
                "complete": True,
                "error": "",
                "refs_digest": "right-digest",
                "commits": [shared, right_only],
                "parents": {},
                "elapsed_seconds": 0.2,
            },
        ],
    )

    assert merged["complete"] is True
    assert [commit["sha"] for commit in merged["commits"]] == [
        "a" * 40,
        "b" * 40,
        "c" * 40,
    ]
    assert merged["commits"][0]["_observed_in_clone_paths"] == [
        "/cache/home/repo",
        "/cache/project/repo",
    ]
    assert len(merged["clone_coverage"]) == 2


def test_failed_duplicate_clone_keeps_union_but_marks_repository_incomplete() -> None:
    merged = scan._merge_clone_scan_results(
        "github.com/example/repo",
        [
            {
                "repo_path": "/cache/good/repo",
                "complete": True,
                "error": "",
                "refs_digest": "good",
                "commits": [],
                "parents": {},
                "elapsed_seconds": 0.1,
            },
            {
                "repo_path": "/cache/bad/repo",
                "complete": False,
                "error": "message_prefilter_git_log_nonzero:128",
                "refs_digest": "bad",
                "commits": [],
                "parents": {},
                "elapsed_seconds": 0.1,
            },
        ],
    )

    assert merged["complete"] is False
    assert "/cache/bad/repo:message_prefilter_git_log_nonzero:128" in merged["error"]
