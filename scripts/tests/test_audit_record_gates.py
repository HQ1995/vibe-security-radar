"""Fact gates for causal-research records. Judgment stays out of this file."""

from __future__ import annotations

import json
import sys

from audit_record_gates import check_record


BIC = "2aeba972d43391175a94c7793b63c6a5709abc48"
FIX = "2e456897af3158c175bb490ce7fc51d6241c8922"


def _closed(**overrides):
    row = {
        "class_id": "alias-test",
        "verdict": "NOT_AI",
        "advisory_ids": ["GHSA-JV46-XFWM-36J7"],
        "introducer_sha": BIC,
        "fix_sha": FIX,
        "direct_fix_sha": FIX,
        "ai_marker": "Made-with: Cursor",
        "remaining_gap": None,
        "evidence": "",
        "reasoning": "",
    }
    row.update(overrides)
    return row


def test_complete_closed_record_passes() -> None:
    assert check_record(_closed()) == []


def test_evidence_gap_needs_remaining_gap_only() -> None:
    assert check_record(
        {
            "class_id": "alias-gap",
            "verdict": "EVIDENCE_GAP",
            "advisory_ids": [],
            "introducer_sha": None,
            "fix_sha": None,
            "remaining_gap": "cannot pin advisory identity",
        }
    ) == []
    problems = check_record(
        {"class_id": "alias-gap", "verdict": "EVIDENCE_GAP", "remaining_gap": ""}
    )
    assert any("remaining_gap" in p for p in problems)


def test_closed_without_identity_fails() -> None:
    problems = check_record(_closed(advisory_ids=[]))
    assert any("GHSA/CVE" in p for p in problems)


def test_alias_id_is_not_identity() -> None:
    problems = check_record(_closed(advisory_ids=["ALIAS-DEADBEEF"]))
    assert any("GHSA/CVE" in p for p in problems)


def test_closed_without_bic_fails() -> None:
    problems = check_record(_closed(introducer_sha=None))
    assert any("introducer_sha" in p for p in problems)


def test_closed_without_fix_fails_unless_unpatched() -> None:
    problems = check_record(_closed(fix_sha=None, direct_fix_sha=None))
    assert any("unpatched" in p for p in problems)
    prose_only = _closed(
        fix_sha=None,
        direct_fix_sha=None,
        remaining_gap="unpatched; no upstream fix at research time",
    )
    assert any("unpatched" in p for p in check_record(prose_only))
    ok = _closed(
        fix_sha=None,
        direct_fix_sha=None,
        unpatched={
            "confirmed": True,
            "reason": "no upstream fix at research time",
            "potential_fix": {
                "approach": "fail closed when the configured token is empty",
                "rationale": "empty token previously allowed unauthenticated hook access",
            },
        },
    )
    assert check_record(ok) == []


def test_relyra_round7_row_would_not_land() -> None:
    """Pre-backfill shape: closed NOT_AI with no fix must fail the fact gate."""
    problems = check_record(
        {
            "class_id": "alias-57104d605e4cddde423d1ce4",
            "verdict": "NOT_AI",
            "advisory_ids": ["CVE-2026-49454", "GHSA-jv46-xfwm-36j7"],
            "introducer_sha": BIC,
            "fix_sha": None,
            "direct_fix_sha": None,
            "remaining_gap": None,
            "evidence": "cand 2aeba97 creates signature.ex",
            "reasoning": "Made-with: Cursor",
        }
    )
    assert problems


def test_relyra_backfilled_row_lands() -> None:
    """Independent fix backfill; verdict stays NOT_AI and the row may land."""
    assert (
        check_record(
            _closed(
                class_id="alias-57104d605e4cddde423d1ce4",
                advisory_ids=["CVE-2026-49454", "GHSA-jv46-xfwm-36j7"],
            )
        )
        == []
    )


def test_openclaw_cursor_row_would_not_land() -> None:
    """Closed NOT_AI with empty advisory_ids and no fix."""
    problems = check_record(
        {
            "class_id": "alias-6fa8cee871e7f5f2b5a07c0b",
            "verdict": "NOT_AI",
            "advisory_ids": [],
            "introducer_sha": "20523b918adff4feae378ac9965e204c56b6e3d8",
            "fix_sha": None,
            "direct_fix_sha": None,
            "remaining_gap": None,
        }
    )
    assert any("GHSA/CVE" in p for p in problems)
    assert any("unpatched" in p for p in problems)


def test_merge_refuses_incomplete_research_record(tmp_path) -> None:
    from merge_funnel_lane import main as merge_main

    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(
        json.dumps({"class_id": "alias-test", "status": "PARTIALLY_ANALYZED"}) + "\n"
    )
    lane = tmp_path / "lane.jsonl"
    lane.write_text(
        json.dumps(
            {
                "class_id": "alias-test",
                "verdict": "NOT_AI",
                "advisory_ids": [],
                "introducer_sha": BIC,
            }
        )
        + "\n"
    )
    old = sys.argv
    try:
        sys.argv = ["merge_funnel_lane.py", str(ledger), str(lane)]
        assert merge_main() == 1
    finally:
        sys.argv = old
    assert "PARTIALLY_ANALYZED" in ledger.read_text()

