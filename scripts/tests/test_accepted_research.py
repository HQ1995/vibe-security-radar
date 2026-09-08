"""Accepted causal records stay coherent through finalization and evidence export."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import audit_envelope
import build_missing_code_evidence
import ledger_store


def _row() -> dict:
    return {
        "class_id": "accepted-case",
        "status": "AI_ROOT_CAUSE",
        "repo": "example/project",
        "advisory_ids": ["CVE-2099-1000"],
        "causal_research": {
            "verdict": "AI_ROOT_CAUSE",
            "introducer_sha": "a" * 40,
            "fix_sha": "b" * 40,
            "ai_marker": "Co-Authored-By: Claude",
            "reasoning": "The reviewed change introduced this defect.",
        },
        "round6_research": {
            "verdict": "AI_ROOT_CAUSE",
            "introducer_sha": "old-short-sha",
            "ai_marker": "Old attribution",
            "reasoning": "A superseded explanation.",
        },
    }


def test_envelope_uses_one_accepted_record_without_historical_field_mixing():
    row = _row()
    assert audit_envelope.payloads(row) == [row["causal_research"]]
    assert audit_envelope.violations(row) == []

    del row["causal_research"]["ai_marker"]
    del row["causal_research"]["reasoning"]
    errors = audit_envelope.violations(row)
    assert "ai_marker missing" in errors
    assert "reasoning/bug_semantics/evidence missing" in errors


@pytest.mark.parametrize("accepted", [None, {}, "invalid", {"verdict": "NOT_AI"}])
def test_invalid_accepted_record_cannot_fall_back_to_old_research(accepted):
    row = _row()
    row["causal_research"] = accepted
    assert any("causal_research" in error for error in audit_envelope.violations(row))


def test_new_finalization_requires_explicit_projection_and_supporting_assessments(tmp_path):
    row = _row()
    patch = {"expected_revision": 2, "assessment_ids": ["review-a", "review-b"], "row": row}
    path = tmp_path / "patch.jsonl"

    def check(required=True):
        path.write_text(json.dumps(patch) + "\n")
        return ledger_store.read_patches(path, require_assessments=required)

    assert check()[0] == patch
    row["causal_research"]["verdict"] = "NOT_AI"
    with pytest.raises(SystemExit, match="verdict must match"):
        check()
    del row["causal_research"]
    with pytest.raises(SystemExit, match="requires causal_research"):
        check()
    assert check(required=False)[0] == patch  # Legacy apply remains separate.

    patch["row"] = _row()
    patch["assessment_ids"] = []
    with pytest.raises(SystemExit, match="requires assessment_ids"):
        check()


def test_evidence_builder_keeps_causal_candidates_separate_from_original_bic():
    row = _row()
    row.update({"candidate_set": ["c" * 40], "minimum_fix_set": [], "mechanism": "Accepted summary"})
    overrides = {"cases": {row["class_id"]: {
        "repository": "stale/project", "mechanism": "Superseded summary",
        "candidate_set": ["d" * 40], "minimum_fix_set": ["e" * 40],
    }}}
    case = build_missing_code_evidence.ledger_case(row, overrides)
    assert case["candidate_set"] == ["c" * 40]
    assert case["minimum_fix_set"] == []
    assert case["repository"] == "example/project"
    assert case["mechanism"] == "Accepted summary"
