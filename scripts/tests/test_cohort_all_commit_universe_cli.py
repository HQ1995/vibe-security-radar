"""Boundary tests for the all-commit universe history reader."""

from __future__ import annotations

import cohort_all_commit_universe as cli


FIRST = "1" * 40
SECOND = "2" * 40


def test_shallow_marker_can_be_overridden_only_by_complete_local_object_view(
    monkeypatch, tmp_path
) -> None:
    calls: list[tuple[list[str], list[str]]] = []

    def fake_git_output(
        _repo_path,
        arguments: list[str],
        _timeout: int,
        *,
        global_arguments: list[str] | None = None,
    ) -> tuple[str, str]:
        calls.append((arguments, global_arguments or []))
        if arguments[:2] == ["rev-parse", "--is-shallow-repository"]:
            return "true\n", ""
        if arguments[:2] == ["rev-parse", "--verify"]:
            return SECOND + "\n", ""
        if arguments[0] == "for-each-ref":
            return "refs/heads/main\x00" + SECOND + "\n", ""
        assert global_arguments == ["--shallow-file", ""]
        return f"2 {SECOND} {FIRST}\n1 {FIRST}\n", ""

    monkeypatch.setattr(cli, "_git_output", fake_git_output)

    records, _refs, reasons, provenance = cli._enumerate_history(
        "github.com/acme/project", tmp_path, timeout=30
    )

    assert len(records) == 2
    assert reasons == []
    assert provenance["shallow_marker_present"] is True
    assert provenance["history_view"] == (
        "complete_local_object_graph_ignoring_shallow_marker"
    )
    assert any(global_args == ["--shallow-file", ""] for _, global_args in calls)


def test_failed_complete_local_view_stays_blocked_and_keeps_shallow_rows(
    monkeypatch, tmp_path
) -> None:
    def fake_git_output(
        _repo_path,
        arguments: list[str],
        _timeout: int,
        *,
        global_arguments: list[str] | None = None,
    ) -> tuple[str, str]:
        if arguments[:2] == ["rev-parse", "--is-shallow-repository"]:
            return "true\n", ""
        if arguments[:2] == ["rev-parse", "--verify"]:
            return SECOND + "\n", ""
        if arguments[0] == "for-each-ref":
            return "refs/heads/main\x00" + SECOND + "\n", ""
        if global_arguments:
            return "", "git_rev-list_nonzero:128"
        return f"2 {SECOND}\n", ""

    monkeypatch.setattr(cli, "_git_output", fake_git_output)

    records, _refs, reasons, provenance = cli._enumerate_history(
        "github.com/acme/project", tmp_path, timeout=30
    )

    assert [row["sha"] for row in records] == [SECOND]
    assert reasons == [
        "complete_local_object_graph_unavailable",
        "shallow_repository",
    ]
    assert provenance["history_view"] == "declared_shallow_graph"


def test_unborn_head_does_not_block_complete_ref_enumeration(
    monkeypatch, tmp_path
) -> None:
    calls: list[list[str]] = []

    def fake_git_output(
        _repo_path,
        arguments: list[str],
        _timeout: int,
        *,
        global_arguments: list[str] | None = None,
    ) -> tuple[str, str]:
        calls.append(arguments)
        if arguments[:2] == ["rev-parse", "--is-shallow-repository"]:
            return "false\n", ""
        if arguments[:2] == ["rev-parse", "--verify"]:
            return "", "git_rev-parse_nonzero:128"
        if arguments[0] == "for-each-ref":
            return "refs/remotes/origin/main\x00" + SECOND + "\n", ""
        assert arguments == ["rev-list", "--all", "--parents", "--timestamp"]
        assert global_arguments is None
        return f"2 {SECOND} {FIRST}\n1 {FIRST}\n", ""

    monkeypatch.setattr(cli, "_git_output", fake_git_output)

    records, _refs, reasons, _provenance = cli._enumerate_history(
        "github.com/acme/project", tmp_path, timeout=30
    )

    assert len(records) == 2
    assert reasons == []
    assert all("HEAD" not in arguments for arguments in calls)


def test_clone_choice_prefers_complete_graph_then_larger_complete_graph() -> None:
    complete_small = (
        [{"sha": FIRST, "parents": [], "committer_timestamp": 1}],
        "a" * 64,
        [],
        {"repository_path": "/cache/small"},
    )
    blocked_large = (
        [
            {"sha": FIRST, "parents": [], "committer_timestamp": 1},
            {"sha": SECOND, "parents": [], "committer_timestamp": 2},
        ],
        "b" * 64,
        ["shallow_repository"],
        {"repository_path": "/cache/blocked"},
    )
    complete_large = (
        [
            {"sha": FIRST, "parents": [], "committer_timestamp": 1},
            {"sha": SECOND, "parents": [FIRST], "committer_timestamp": 2},
        ],
        "c" * 64,
        [],
        {"repository_path": "/cache/large"},
    )

    chosen, diagnostics = cli._choose_enumeration(
        [complete_small, blocked_large, complete_large], {FIRST}
    )

    assert chosen[3]["repository_path"] == "/cache/large"
    assert sum(row["selected"] is True for row in diagnostics) == 1
