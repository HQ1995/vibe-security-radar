"""Boundary tests for declared cross-repository closure orchestration."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import cohort_ai_routing_pilot as routing_pilot
import cohort_complex_recall as complex_recall
import cohort_control_recall as control_recall
import cohort_cross_repository_closure as closure


TARGET = "github.com/example/target"
UPSTREAM = "github.com/example/upstream"
IMPORT = "1" * 40
FIX = "2" * 40
ORIGIN = "3" * 40
FIX_TWO = "4" * 40


@pytest.mark.parametrize(
    "loader",
    [
        closure._load_jsonl,
        complex_recall._load_jsonl,
        control_recall._load_jsonl,
        routing_pilot._load_jsonl,
    ],
)
def test_jsonl_loader_does_not_split_unicode_paragraph_separators(
    loader, tmp_path
) -> None:
    path = tmp_path / "rows.jsonl"
    row = {"message": "before\u2029after"}
    path.write_text(
        json.dumps(row, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    assert loader(path) == [row]


def test_carrier_discovery_scans_human_commits_reachable_from_fix(monkeypatch, tmp_path) -> None:
    calls: list[list[str]] = []

    def fake_run_git(command: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(command)
        if "log" in command:
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    f"{FIX}\x00{IMPORT}\x00security fix\x00"
                    f"{IMPORT}\x00\x00upstream plugin by @example"
                    "\x00"
                ),
            )
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(closure, "run_git", fake_run_git)
    roots = [
        {
            "repository_identity": TARGET,
            "fix_sha": FIX,
            "status": "RESOLVED",
            "reason": "",
            "advisories": [{"id": "CVE-TEST", "published": ""}],
        }
    ]

    carriers, target_roots, ambiguities = closure.discover_import_carriers(
        roots, {TARGET: tmp_path}, {}, timeout=30
    )

    assert carriers == [
        {
            "target_repository_identity": TARGET,
            "source_repository_identity": UPSTREAM,
            "import_sha": IMPORT,
            "fix_sha": FIX,
            "fix_root_status": "RESOLVED",
            "fix_root_reason": "",
            "advisories": [{"id": "CVE-TEST", "published": ""}],
        }
    ]
    assert target_roots[0]["status"] == "RESOLVED"
    assert target_roots[0]["declared_import_carrier_count"] == 1
    assert target_roots[0]["ambiguous_source_mention_count"] == 0
    assert ambiguities == []
    assert sum("log" in command for command in calls) == 1
    assert not any("merge-base" in command for command in calls)


def test_bare_source_slug_is_blocked_in_first_class_ambiguity_ledger(
    monkeypatch, tmp_path
) -> None:
    def fake_run_git(command: list[str], **_kwargs: object) -> SimpleNamespace:
        if "log" in command:
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    f"{FIX}\x00{IMPORT}\x00security fix\x00"
                    f"{IMPORT}\x00\x00Import implementation from example/upstream"
                    "\x00"
                ),
            )
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(closure, "run_git", fake_run_git)
    roots = [
        {
            "repository_identity": TARGET,
            "fix_sha": FIX,
            "status": "RESOLVED",
            "reason": "",
            "advisories": [{"id": "CVE-TEST", "published": ""}],
        }
    ]

    carriers, target_roots, ambiguities = closure.discover_import_carriers(
        roots, {TARGET: tmp_path}, {}, timeout=30
    )

    assert carriers == []
    assert target_roots[0]["ambiguous_source_mention_count"] == 1
    assert len(ambiguities) == 1
    assert ambiguities[0]["candidate_source_repository_identity"] == UPSTREAM
    assert ambiguities[0]["status"] == "BLOCKED"
    assert ambiguities[0]["reason"] == (
        "bare_owner_repo_may_be_source_or_module_path"
    )


def test_one_parent_graph_walk_propagates_multiple_fix_roots() -> None:
    masks, errors = closure._reachability_masks(
        [
            {"sha": FIX, "parents": [IMPORT], "message": "fix one"},
            {"sha": FIX_TWO, "parents": [IMPORT], "message": "fix two"},
            {"sha": IMPORT, "parents": [], "message": "import"},
        ],
        [FIX, FIX_TWO],
    )

    assert errors == {}
    assert masks[IMPORT].bit_count() == 2


def test_source_coverage_preserves_a_complete_zero_match_repository() -> None:
    source_commits, coverage = closure.source_scan_inputs(
        [],
        {
            "scanned_repository_identities": [UPSTREAM],
            "complete_repository_identities": [UPSTREAM],
            "incomplete_repositories": [],
        },
        {},
    )

    assert source_commits == {}
    assert coverage == {UPSTREAM: {"complete": True, "reason": ""}}


def test_campaign_blocks_missing_source_scan_instead_of_calling_it_negative() -> None:
    carriers = [
        {
            "target_repository_identity": TARGET,
            "source_repository_identity": UPSTREAM,
            "import_sha": IMPORT,
            "fix_sha": FIX,
            "fix_root_status": "RESOLVED",
            "fix_root_reason": "",
        }
    ]
    target_roots = [
        {
            "repository_identity": TARGET,
            "fix_sha": FIX,
            "status": "RESOLVED",
            "reason": "",
        }
    ]

    artifacts = closure.build_cross_repository_campaign(
        carriers, target_roots, [], {}, {}
    )

    assert artifacts["summary"]["coverage_complete"] is False
    assert artifacts["summary"]["import_root_count"] == 1
    assert artifacts["summary"]["blocked_import_root_count"] == 1
    assert artifacts["relations"] == []
    assert artifacts["import_roots"][0]["status"] == "BLOCKED"
    assert artifacts["import_roots"][0]["reason"] == (
        "source_repository_scan_missing"
    )
