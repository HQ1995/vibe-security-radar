"""Git-level regression tests for the finite-budget origin-signal pilot."""

from __future__ import annotations

import subprocess
from pathlib import Path

import cohort_origin_signal_pilot as pilot
import pytest


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Origin Pilot")
    _git(repo, "config", "user.email", "origin-pilot@example.invalid")
    return repo


def _commit_all(repo: Path, subject: str) -> str:
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", subject)
    return _git(repo, "rev-parse", "HEAD")


def _universe(*shas: str, observed: set[str]) -> dict[str, dict[str, object]]:
    return {
        sha: {
            "sha": sha,
            "observed_ai_unit": sha in observed,
            "ai_routes": ["test"] if sha in observed else [],
            "ai_tools": ["test"] if sha in observed else [],
        }
        for sha in shas
    }


def test_root_eligibility_allows_global_gate_or_target_public_exact() -> None:
    selected = {
        "decision": {"decision": "select", "confidence": "high"},
        "selected_candidates": [{"public_exact": True}],
        "public_control_closure_hit": True,
    }

    assert pilot._root_eligibility({"gate_status": "CONTINUE"}, {}) == (
        "global_root_adjudication_gate"
    )
    assert pilot._root_eligibility(
        {"gate_status": "REVISE_OR_STOP"}, selected
    ) == "target_model_selected_root_hypothesis"

    multiple = {
        "decision": {"decision": "select", "confidence": "high"},
        "selected_candidates": [
            {"sha": "1" * 40, "public_exact": False},
            {"sha": "2" * 40, "public_exact": True},
        ],
        "public_control_closure_hit": True,
    }
    assert pilot._root_eligibility(
        {"gate_status": "REVISE_OR_STOP"},
        multiple,
        multiple["selected_candidates"][1],
    ) == "target_model_selected_root_hypothesis"


def test_root_eligibility_keeps_low_confidence_target_blocked() -> None:
    with pytest.raises(SystemExit, match="target root is not eligible"):
        pilot._root_eligibility(
            {"gate_status": "REVISE_OR_STOP"},
            {
                "decision": {"decision": "select", "confidence": "low"},
                "selected_candidates": [{"public_exact": False}],
                "public_control_closure_hit": True,
            },
        )


def test_explicit_public_exact_root_is_independent_of_model_selection() -> None:
    exact = {"sha": "2" * 40, "public_exact": True}
    model_selected_other = {
        "decision": {"decision": "select", "confidence": "high"},
        "selected_candidates": [{"sha": "1" * 40, "public_exact": False}],
        "public_control_closure_hit": True,
    }

    assert pilot._root_eligibility(
        {"gate_status": "REVISE_OR_STOP"},
        model_selected_other,
        exact,
        explicit_public_control_root=True,
    ) == "target_frozen_public_exact_reference"
    with pytest.raises(SystemExit, match="target root is not eligible"):
        pilot._root_eligibility(
            {"gate_status": "REVISE_OR_STOP"},
            model_selected_other,
            exact,
        )


def test_public_exact_priority_match_ignores_model_ranking_class() -> None:
    fix = "2" * 40
    common = {
        "repository_identity": "github.com/example/project",
        "root_sha": fix,
        "priority_class": "R0_MODEL_OR_EXPLICIT_CONTROL",
        "priority_reasons": ["explicit_public_control_root"],
        "retained": True,
        "root_coverage_status": "RESOLVED",
    }
    rows = [
        {**common, "evidence_kinds": ["enriched_selected"]},
        {**common, "evidence_kinds": ["public_exact"]},
        {
            **common,
            "priority_class": "R2_OTHER_SOURCE_CARRIER",
            "priority_reasons": [],
            "evidence_kinds": ["public_exact"],
        },
    ]

    assert pilot._explicit_public_exact_priority_matches(
        rows,
        repository="github.com/example/project",
        fix_sha=fix,
    ) == [rows[1], rows[2]]


def test_add_only_fix_recovers_origin_without_deleted_line_szz(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    source = repo / "service.py"
    source.write_text(
        "def mutate_project(user, project):\n"
        "    return project.save()\n",
        encoding="utf-8",
    )
    origin = _commit_all(repo, "introduce project mutation")

    (repo / "notes.txt").write_text("unrelated\n", encoding="utf-8")
    noise = _commit_all(repo, "unrelated notes")

    source.write_text(
        "def mutate_project(user, project):\n"
        "    if not user.can_write(project):\n"
        "        raise PermissionError('write denied')\n"
        "    return project.save()\n",
        encoding="utf-8",
    )
    fix = _commit_all(repo, "add authorization check")

    collected = pilot.collect_origin_signals(
        repo,
        [],
        fix,
        _universe(origin, noise, fix, observed={origin}),
        timeout=30,
    )

    assert collected["copy_aware"] == set()
    assert collected["file_local"] == set()
    add_union = (
        collected["add_context"]
        | collected["function_history"]
        | collected["pickaxe_history"]
    )
    assert origin in add_union
    assert collected["add_only_hunk_count"] == 1
    assert collected["guard_like_hunk_count"] == 1
    assert collected["coverage_gaps"] == []


def test_global_guard_promotes_cross_file_route_origin(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    main = repo / "main.py"
    main.write_text("app = WebApp()\n", encoding="utf-8")
    base = _commit_all(repo, "initialize web app")

    routes = repo / "api" / "routes.py"
    routes.parent.mkdir()
    routes.write_text(
        "@router.post('/mutate')\n"
        "def mutate():\n"
        "    return change_state()\n",
        encoding="utf-8",
    )
    origin = _commit_all(repo, "add mutation route")

    main.write_text(
        "app = WebApp()\n"
        "\n"
        "@app.middleware('http')\n"
        "def auth_middleware(request, call_next):\n"
        "    if not request.headers.get('Authorization'):\n"
        "        return unauthorized()\n"
        "    return call_next(request)\n",
        encoding="utf-8",
    )
    fix = _commit_all(repo, "secure every route with auth middleware")

    collected = pilot.collect_origin_signals(
        repo,
        [],
        fix,
        _universe(base, origin, fix, observed={origin}),
        timeout=30,
    )

    assert collected["fix_has_global_guard"] is True
    assert origin not in collected["file_history"]
    assert origin in collected["cross_file_surface"]
    assert origin in collected["cross_file_bridge"]
    assert collected["coverage_gaps"] == []


def test_merge_uses_first_parent_delta_without_importing_other_side(
    tmp_path: Path,
) -> None:
    repo = _init_repo(tmp_path)
    vulnerable = repo / "vulnerable.py"
    vulnerable.write_text(
        "def write(path):\n"
        "    return open(path, 'wb')\n",
        encoding="utf-8",
    )
    base = _commit_all(repo, "add unsafe writer")
    main_branch = _git(repo, "branch", "--show-current")

    _git(repo, "switch", "-q", "-c", "security-fix")
    vulnerable.write_text(
        "def write(path):\n"
        "    if '..' in path:\n"
        "        raise ValueError('unsafe path')\n"
        "    return open(path, 'wb')\n",
        encoding="utf-8",
    )
    fix_branch = _commit_all(repo, "add path guard")

    _git(repo, "switch", "-q", main_branch)
    noise_path = repo / "noise.py"
    noise_path.write_text("VALUE = 1\n", encoding="utf-8")
    noise = _commit_all(repo, "unrelated mainline work")
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge security fix", "security-fix")
    merge = _git(repo, "rev-parse", "HEAD")

    collected = pilot.collect_origin_signals(
        repo,
        [],
        merge,
        _universe(base, fix_branch, noise, merge, observed={noise}),
        timeout=30,
    )

    assert collected["parents"] == [noise, fix_branch]
    assert collected["analysis_parent"] == noise
    assert collected["changed_paths"] == ["vulnerable.py"]
    assert collected["alternate_parent_delta_paths"] == {
        fix_branch: ["noise.py"]
    }
    assert fix_branch in collected["ancestors"]
    assert noise not in collected["file_history"]
