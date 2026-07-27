"""Tests for cohort exposure routing and one-commit-one-unit deduplication."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cohort_classify_exposure import (
    ROUTE_ASSISTANT_DIRECT,
    ROUTE_ASSISTANT_SQUASH,
    ROUTE_AUTONOMOUS,
    ROUTE_SECURITY_AUTOFIX,
    _canonical_repositories,
    _route,
)


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        # A bot that opened and wrote the whole PR: dose is 1.0, nothing to split.
        ({"agent_kinds": ["autonomous_agent"], "merge_topology": "squash", "pr_number": 7},
         ROUTE_AUTONOMOUS),
        # Autonomous wins over a co-credited assistant — the bot still wrote it all.
        ({"agent_kinds": ["assistant", "autonomous_agent"], "merge_topology": "squash",
          "pr_number": 7}, ROUTE_AUTONOMOUS),
        ({"agent_kinds": ["security_autofix"], "merge_topology": "direct", "pr_number": None},
         ROUTE_SECURITY_AUTOFIX),
        ({"agent_kinds": ["assistant"], "merge_topology": "squash", "pr_number": 7},
         ROUTE_ASSISTANT_SQUASH),
        ({"agent_kinds": ["assistant"], "merge_topology": "direct", "pr_number": None},
         ROUTE_ASSISTANT_DIRECT),
        # A squash whose subject carried no PR number cannot be decomposed via
        # refs/pull, so it is read as the single commit it is.
        ({"agent_kinds": ["assistant"], "merge_topology": "squash", "pr_number": None},
         ROUTE_ASSISTANT_DIRECT),
    ],
)
def test_route_assignment(row: dict, expected: str) -> None:
    assert _route(row) == expected


def _write_corpus(tmp_path: Path, rows: list[dict]) -> Path:
    scan = tmp_path / "scan"
    scan.mkdir()
    with (scan / "commits.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    return scan


def test_duplicate_sha_collapses_to_the_busier_repository(tmp_path: Path) -> None:
    """A fork republishes upstream commits verbatim; they are one event, not two."""

    rows = [{"sha": f"sha{i}", "repository_identity": "github.com/up/stream"} for i in range(5)]
    rows += [{"sha": "sha0", "repository_identity": "github.com/user/fork"}]
    scan = _write_corpus(tmp_path, rows)

    canonical, duplicated = _canonical_repositories(scan)

    assert duplicated == 1
    assert canonical["sha0"] == "github.com/up/stream"


def test_deduplication_is_deterministic_across_runs(tmp_path: Path) -> None:
    """Two mirrors of equal size must not swap homes between runs."""

    rows = [
        {"sha": "shared", "repository_identity": "github.com/b/mirror"},
        {"sha": "shared", "repository_identity": "github.com/a/mirror"},
    ]
    scan = _write_corpus(tmp_path, rows)

    first, _ = _canonical_repositories(scan)
    second, _ = _canonical_repositories(scan)

    assert first == second
    assert first["shared"] in {"github.com/a/mirror", "github.com/b/mirror"}


def test_unique_commits_keep_their_own_repository(tmp_path: Path) -> None:
    rows = [
        {"sha": "only-here", "repository_identity": "github.com/small/repo"},
        {"sha": "elsewhere", "repository_identity": "github.com/big/repo"},
        {"sha": "elsewhere2", "repository_identity": "github.com/big/repo"},
    ]
    scan = _write_corpus(tmp_path, rows)

    canonical, duplicated = _canonical_repositories(scan)

    assert duplicated == 0
    assert canonical["only-here"] == "github.com/small/repo"
