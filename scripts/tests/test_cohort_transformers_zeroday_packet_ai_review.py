"""Contracts for packetized Transformers add-only review."""

from __future__ import annotations

import json

import pytest

import cohort_transformers_zeroday_packet_ai_review as review


SHAS = ["a" * 40, "b" * 40]
GLOBAL_SHAS = {*SHAS, "c" * 40}
CVES = ["CVE-2025-14920", "CVE-2025-14930"]


def _valid() -> dict[str, object]:
    return {
        "candidate_assessments": [
            {
                "sha": sha,
                "verdict": "retain_insufficient",
                "related_cves": [],
                "causal_role": "No exact role is established.",
                "reasoning": "The public mechanism mapping is incomplete.",
                "missing_evidence": ["Exact causal line."],
            }
            for sha in SHAS
        ],
        "cross_file_hypotheses": [],
        "missing_evidence": [],
        "summary": "Every candidate remains retained.",
    }


def test_parser_requires_exact_packet_coverage() -> None:
    payload = _valid()

    assert (
        review._parse_review(
            json.dumps(payload),
            SHAS,
            CVES,
            GLOBAL_SHAS,
            structural_lane=False,
        )
        == payload
    )


def test_parser_rejects_omitted_candidate() -> None:
    payload = _valid()
    payload["candidate_assessments"] = payload["candidate_assessments"][:-1]

    with pytest.raises(ValueError, match="coverage is not exact"):
        review._parse_review(
            json.dumps(payload),
            SHAS,
            CVES,
            GLOBAL_SHAS,
            structural_lane=False,
        )


def test_structural_lane_cannot_promote_direct_ai_root() -> None:
    payload = _valid()
    payload["candidate_assessments"][0]["verdict"] = "promote_direct_introducer"

    with pytest.raises(ValueError, match="cannot be a direct AI root"):
        review._parse_review(
            json.dumps(payload),
            SHAS,
            CVES,
            GLOBAL_SHAS,
            structural_lane=True,
        )


def test_cross_file_hypothesis_must_include_packet_candidate() -> None:
    payload = _valid()
    payload["cross_file_hypotheses"] = [
        {
            "candidate_shas": ["c" * 40],
            "cves": [CVES[0]],
            "status": "possible",
            "hypothesis": "A global-only hypothesis has no reviewed packet anchor.",
            "evidence_needed": [],
        }
    ]

    with pytest.raises(ValueError, match="candidate scope is invalid"):
        review._parse_review(
            json.dumps(payload),
            SHAS,
            CVES,
            GLOBAL_SHAS,
            structural_lane=False,
        )


def test_packet_bounds_are_exact_and_fail_closed() -> None:
    assert review._packet_bounds(6, 4, 0) == (0, 4, 2)
    assert review._packet_bounds(6, 4, 1) == (4, 6, 2)
    with pytest.raises(ValueError, match="outside"):
        review._packet_bounds(6, 4, 2)


def test_retain_possible_enters_followup_but_not_delete_lane() -> None:
    assert "retain_possible" in review.PROMOTED_VERDICTS
    assert "retain_unrelated" not in review.PROMOTED_VERDICTS
