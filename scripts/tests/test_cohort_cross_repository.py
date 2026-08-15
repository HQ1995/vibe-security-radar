"""Tests for conservative closure across explicitly declared imports."""

from __future__ import annotations

from cohort.cross_repository import (
    AMBIGUOUS_SOURCE,
    CROSS_REPOSITORY_CANDIDATE_RELATION,
    DECLARED_IMPORT_RELATION,
    build_declared_import_inventory,
    classify_import_source_mentions,
    declared_import_sources,
    expand_declared_import_candidates,
)


TARGET = "github.com/example/target"
UPSTREAM = "github.com/m1heng/clawdbot-feishu"
IMPORT = "1" * 40
FIX = "2" * 40
ORIGIN_A = "3" * 40
ORIGIN_B = "4" * 40


def test_declared_import_source_parser_requires_unambiguous_repository_evidence() -> None:
    assert declared_import_sources(
        "Sync from https://github.com/m1heng/clawdbot-feishu.git"
    ) == [UPSTREAM]
    assert declared_import_sources(
        "Vendor implementation from https://github.com/m1heng/clawdbot-feishu.git"
    ) == [UPSTREAM]
    assert declared_import_sources(
        "Replace with the community-maintained\nclawdbot-feishu plugin by @m1heng."
    ) == [UPSTREAM]
    assert declared_import_sources("sync from m1heng/clawdbot-feishu") == []
    assert declared_import_sources("Import implementation from m1heng/clawdbot-feishu") == []
    assert declared_import_sources("Thanks @m1heng for reviewing the plugin") == []
    assert declared_import_sources("Improve scene by @buddyhadry") == []
    assert declared_import_sources(
        "Merge pull request #794 from roshanasingh4/fix/777-windows-openurl-quotes"
    ) == []
    assert declared_import_sources(
        "Review: https://github.com/example/project/pull/123"
    ) == []


def test_bare_owner_repo_transfer_prose_is_preserved_as_ambiguous() -> None:
    mentions = classify_import_source_mentions(
        "Import implementation from m1heng/clawdbot-feishu"
    )

    assert mentions == [
        {
            "source_repository_identity": UPSTREAM,
            "status": AMBIGUOUS_SOURCE,
            "evidence_kind": "bare_transfer_slug",
            "evidence_text": "Import implementation from m1heng/clawdbot-feishu",
        }
    ]


def _carrier() -> dict[str, object]:
    return {
        "target_repository_identity": TARGET,
        "source_repository_identity": UPSTREAM,
        "import_sha": IMPORT,
        "fix_sha": FIX,
        "fix_root_status": "RESOLVED",
        "fix_root_reason": "",
    }


def test_import_inventory_retains_every_source_ai_commit_without_date_filter() -> None:
    inventory = build_declared_import_inventory(
        [_carrier()],
        {
            UPSTREAM: [
                {"sha": ORIGIN_A, "authored_date": "2025-01-01T00:00:00Z"},
                # Timestamp appears later than the import. It remains a candidate:
                # cross-repository clocks are not ancestry evidence.
                {"sha": ORIGIN_B, "authored_date": "2027-01-01T00:00:00Z"},
            ]
        },
        {UPSTREAM: {"complete": True, "reason": ""}},
    )

    assert inventory["coverage_complete"] is True
    assert len(inventory["relations"]) == 2
    assert {row["origin_sha"] for row in inventory["relations"]} == {
        ORIGIN_A,
        ORIGIN_B,
    }
    assert {row["relation"] for row in inventory["relations"]} == {
        DECLARED_IMPORT_RELATION
    }
    assert inventory["conservation"]["import_roots_conserved"] is True


def test_missing_source_scan_is_blocked_not_negative() -> None:
    inventory = build_declared_import_inventory([_carrier()], {}, {})

    assert inventory["coverage_complete"] is False
    assert inventory["relations"] == []
    assert inventory["import_roots"][0]["status"] == "BLOCKED"
    assert inventory["import_roots"][0]["reason"] == "source_repository_scan_missing"


def test_cross_candidate_composition_preserves_the_import_and_fix_chain() -> None:
    inventory = build_declared_import_inventory(
        [_carrier()],
        {UPSTREAM: [{"sha": ORIGIN_A, "authored_date": "2025-01-01T00:00:00Z"}]},
        {UPSTREAM: {"complete": True, "reason": ""}},
    )

    candidates = expand_declared_import_candidates(
        [_carrier()], inventory["relations"]
    )

    assert len(candidates) == 1
    assert candidates[0]["origin_repository_identity"] == UPSTREAM
    assert candidates[0]["repository_identity"] == TARGET
    assert candidates[0]["candidate_sha"] == ORIGIN_A
    assert candidates[0]["import_sha"] == IMPORT
    assert candidates[0]["fix_sha"] == FIX
    assert candidates[0]["relation"] == CROSS_REPOSITORY_CANDIDATE_RELATION
