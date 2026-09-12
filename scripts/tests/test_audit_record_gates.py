"""Strict record gates refuse a closed verdict that is missing the contract fields."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_record_gates import check_record, check_record_strict

GOOD = {
    "class_id": "alias-x",
    "verdict": "AI_ROOT_CAUSE",
    "advisory_ids": ["GHSA-1234-5678-90ab"],
    "advisory_disposition": "ACTIVE",
    "introducer_sha": "a" * 40,
    "landing_commit": "b" * 40,
    "bic_granularity": "ATOMIC",
    "fix_sha": "c" * 40,
    "fix_ai_marker": {"state": "ABSENT", "evidence": "no trailers on the fix"},
    "ai_on_bic": True,
    "flip_condition": "a PR page showing the tool was not used for that commit",
}


def test_contract_record_passes_both_gate_sets():
    assert check_record(GOOD) == []
    assert check_record_strict(GOOD) == []


def test_squash_needs_decomposed_members():
    record = {**GOOD, "bic_granularity": "SQUASH_DECOMPOSED"}
    assert "decomposed_shas" in check_record_strict(record)[0]
    assert check_record_strict({**record, "decomposed_shas": ["d" * 40]}) == []


def test_landing_commit_cannot_be_its_own_bic():
    record = {**GOOD, "landing_commit": GOOD["introducer_sha"]}
    assert "own landing commit" in check_record_strict(record)[0]


def test_closed_verdict_needs_flip_condition():
    record = {k: v for k, v in GOOD.items() if k != "flip_condition"}
    assert "flip_condition" in check_record_strict(record)[0]


def test_ai_verdict_needs_a_bic_marker():
    record = {**GOOD, "ai_on_bic": None}
    assert "ai_on_bic true" in check_record_strict(record)[0]
