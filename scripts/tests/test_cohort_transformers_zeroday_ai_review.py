"""Contracts for the Transformers add-only independent-review packet."""

from __future__ import annotations

import json

import pytest

import cohort_transformers_zeroday_ai_review as review


SHAS = ["a" * 40, "b" * 40]
CVES = ["CVE-2025-14920", "CVE-2025-14921"]


def _valid() -> dict[str, object]:
    return {
        "candidate_assessments": [
            {
                "sha": sha,
                "verdict": "retain_insufficient",
                "related_cves": [],
                "causal_role": "No supported role yet.",
                "reasoning": "The exact public mechanism is missing.",
                "missing_evidence": ["Exact vulnerable line."],
            }
            for sha in SHAS
        ],
        "family_assessments": [
            {
                "cve": cve,
                "ai_involvement": "insufficient",
                "candidate_shas": [],
                "reasoning": "The mapping is incomplete.",
                "missing_evidence": ["Vendor line mapping."],
            }
            for cve in CVES
        ],
        "cross_file_hypotheses": [],
        "missing_evidence": [],
        "summary": "All negative outcomes retain their candidates.",
    }


def test_review_parser_requires_exact_candidate_and_family_coverage() -> None:
    payload = _valid()

    assert review._parse_review(json.dumps(payload), SHAS, CVES) == payload


def test_review_parser_rejects_an_omitted_candidate() -> None:
    payload = _valid()
    assessments = payload["candidate_assessments"]
    assert isinstance(assessments, list)
    assessments.pop()

    with pytest.raises(ValueError, match="coverage is not exact"):
        review._parse_review(json.dumps(payload), SHAS, CVES)


def test_review_parser_rejects_unknown_cross_file_identity() -> None:
    payload = _valid()
    payload["cross_file_hypotheses"] = [
        {
            "candidate_shas": ["c" * 40],
            "cves": [CVES[0]],
            "status": "possible",
            "hypothesis": "Unknown candidate.",
            "evidence_needed": [],
        }
    ]

    with pytest.raises(ValueError, match="unknown identity"):
        review._parse_review(json.dumps(payload), SHAS, CVES)


def test_retain_possible_is_add_only_promotion() -> None:
    assert "retain_possible" in review.PROMOTED_VERDICTS
    assert "retain_unrelated" not in review.PROMOTED_VERDICTS


def test_review_transport_remains_loopback_only() -> None:
    assert review._loopback("http://127.0.0.1:8317/v1") is True
    assert review._loopback("https://example.com/v1") is False
