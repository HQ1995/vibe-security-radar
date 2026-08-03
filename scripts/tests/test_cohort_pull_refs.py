"""Tests for token-free PR-head materialization and membership cuts."""

from __future__ import annotations

from types import SimpleNamespace

from cohort import pull_refs


LANDED = "3" * 40
MEMBER = "1" * 40


def test_pull_members_cuts_at_landed_parent(monkeypatch, tmp_path) -> None:
    calls: list[list[str]] = []

    def fake_run_git(command: list[str], *, timeout: int) -> SimpleNamespace:
        assert timeout == 30
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=f"{MEMBER}\n")

    monkeypatch.setattr(pull_refs, "_run_git", fake_run_git)

    members = pull_refs.pull_members(tmp_path, LANDED, 7, timeout=30)

    assert members == [MEMBER]
    assert f"{pull_refs.COHORT_PULL_NAMESPACE}/7" in calls[0]
    assert f"{LANDED}^" in calls[0]
    assert "--max-count=501" in calls[0]


def test_fetch_falls_back_to_individual_refs(monkeypatch, tmp_path) -> None:
    calls: list[list[str]] = []

    def fake_run_git(command: list[str], *, timeout: int) -> SimpleNamespace:
        assert timeout == 30
        calls.append(command)
        if len([part for part in command if part.startswith("+refs/pull/")]) > 1:
            return SimpleNamespace(returncode=1, stdout="")
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(pull_refs, "_run_git", fake_run_git)

    fetched, error = pull_refs.fetch_pull_refs(
        tmp_path, [7, 8], batch=2, timeout=30
    )

    assert fetched == 2
    assert error == ""
    assert len(calls) == 3


def test_fetch_reports_individual_nonzero_failures(monkeypatch, tmp_path) -> None:
    def fake_run_git(command: list[str], *, timeout: int) -> SimpleNamespace:
        return SimpleNamespace(returncode=1, stdout="")

    monkeypatch.setattr(pull_refs, "_run_git", fake_run_git)

    fetched, error = pull_refs.fetch_pull_refs(tmp_path, [7, 8], batch=2, timeout=30)

    assert fetched == 0
    assert error == "fetch_nonzero:2"
