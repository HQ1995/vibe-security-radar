from __future__ import annotations

import os
import subprocess
from pathlib import Path

import scan_unknown_ai_writer_20260826 as scan


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "README").write_text("ok\n", encoding="utf-8")
    _git(repo, "add", "README")
    _git(repo, "commit", "-m", "init")
    return repo


def test_list_agent_configs_empty(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    assert scan.list_agent_configs(repo) == []


def test_list_agent_configs_git_failure_is_unknown(tmp_path: Path) -> None:
    assert scan.list_agent_configs(tmp_path / "missing") is None


def test_list_agent_configs_agents_claude_codex(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "AGENTS.md").write_text("# agents\n", encoding="utf-8")
    (repo / ".claude").mkdir()
    (repo / ".claude" / "settings.json").write_text("{}\n", encoding="utf-8")
    (repo / ".codex").mkdir()
    (repo / ".codex" / "config.toml").write_text("\n", encoding="utf-8")
    _git(repo, "add", "AGENTS.md", ".claude", ".codex")
    _git(repo, "commit", "-m", "agent files")
    assert scan.list_agent_configs(repo) == [".claude", ".codex", "AGENTS.md"]


def test_row_is_done_retries_old_no_ai() -> None:
    assert scan.row_is_done(
        {
            "repo": "github.com/a/b",
            "clone_ok": True,
            "scan_complete": True,
            "has_ai": False,
        }
    ) is False
    assert scan.row_is_done(
        {
            "repo": "github.com/a/b",
            "clone_ok": True,
            "scan_complete": True,
            "has_ai": False,
            "agent_configs": [],
        }
    ) is False
    assert scan.row_is_done(
        {
            "repo": "github.com/a/b",
            "clone_ok": True,
            "scan_complete": True,
            "has_ai": False,
            "agent_configs": [],
            "committer_ai_count": 0,
        }
    ) is False
    assert scan.row_is_done(
        {
            "repo": "github.com/a/b",
            "clone_ok": True,
            "scan_complete": True,
            "has_ai": False,
            "agent_configs": [],
            "committer_ai_count": 0,
            "all_refs": True,
        }
    ) is True
    assert scan.row_is_done({"repo": "github.com/a/b", "has_ai": True}) is True
    assert scan.row_is_done({"repo": "github.com/a/b", "clone_ok": False}) is True


def test_origin_fetch_covers_all_heads(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    _git(repo, "remote", "add", "origin", "https://example.com/a.git")
    _git(repo, "config", "remote.origin.fetch", "+refs/heads/main:refs/remotes/origin/main")
    assert scan.origin_fetch_covers_all_heads(repo) is False
    _git(repo, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
    assert scan.origin_fetch_covers_all_heads(repo) is True


def test_ai_committer_counts_as_trace(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "x").write_text("x\n", encoding="utf-8")
    _git(repo, "add", "x")
    env = {
        "GIT_AUTHOR_NAME": "Human",
        "GIT_AUTHOR_EMAIL": "human@example.com",
        "GIT_COMMITTER_NAME": "Cursor",
        "GIT_COMMITTER_EMAIL": "cursoragent@cursor.com",
    }
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "change"],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **env},
    )
    assert scan.count_ai_committer_commits(repo) == 1
