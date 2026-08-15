"""Contracts for strict OpenC3 promoted-lead follow-up."""

from __future__ import annotations

import json

import pytest

import cohort_openc3_promoted_followup as followup


def _valid() -> dict[str, object]:
    return {
        "candidate_assessments": [
            {
                "sha": sha,
                "verdict": "not_causal_from_exact_delta",
                "changed_vulnerability_mechanism": "no",
                "necessary_or_path_extending": "no",
                "exact_causal_edge": "No causal edge is evidenced.",
                "counterfactual": "The vulnerable path is unchanged without this delta.",
                "evidence": ["No runtime edge"],
                "missing_evidence": [],
            }
            for sha in sorted(followup.EXPECTED_LEADS)
        ],
        "claim_grade_shas": [],
        "missing_evidence": [],
        "summary": "No lead crosses the claim-grade boundary.",
    }


def test_parser_accepts_strict_exact_coverage() -> None:
    value = _valid()

    assert (
        followup._parse_review(json.dumps(value), sorted(followup.EXPECTED_LEADS))
        == value
    )


def test_parser_rejects_inconsistent_claim_grade_declaration() -> None:
    value = _valid()
    value["candidate_assessments"][0]["verdict"] = (
        "claim_grade_compositional_contributor"
    )

    with pytest.raises(ValueError, match="declaration is inconsistent"):
        followup._parse_review(json.dumps(value), sorted(followup.EXPECTED_LEADS))


def test_parser_rejects_missing_candidate() -> None:
    value = _valid()
    value["candidate_assessments"] = value["candidate_assessments"][:-1]

    with pytest.raises(ValueError, match="coverage is not exact"):
        followup._parse_review(json.dumps(value), sorted(followup.EXPECTED_LEADS))


def test_followup_inventory_is_exactly_five_model_leads() -> None:
    assert len(followup.EXPECTED_LEADS) == 5
    assert followup.AUTH_UI_AI_SHA in followup.EXPECTED_LEADS
