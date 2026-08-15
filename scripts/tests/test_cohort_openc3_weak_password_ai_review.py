"""Contracts for carrier-aware OpenC3 review packets."""

from __future__ import annotations

import json

import pytest

import cohort_openc3_weak_password_ai_review as review


SHAS = ["a" * 40, "b" * 40, "c" * 40]


def _valid() -> dict[str, object]:
    return {
        "candidate_assessments": [
            {
                "sha": sha,
                "verdict": "retain_insufficient",
                "causal_role": "No direct role established; candidate remains retained.",
                "mechanism_relation": "No exact password-path relation established.",
                "evidence": [],
                "missing_evidence": ["Runtime dependency trace"],
            }
            for sha in SHAS
        ],
        "family_assessment": {
            "cve": review.ADVISORY_ID,
            "ai_involvement": "insufficient",
            "candidate_shas": [],
            "reasoning": "Original introduction is excluded but composition is unresolved.",
            "missing_evidence": ["Complete runtime dependency graph"],
        },
        "cross_file_hypotheses": [],
        "missing_evidence": ["Complete runtime dependency graph"],
        "summary": "All candidates remain retained.",
    }


def test_review_parser_accepts_exact_coverage_and_fence() -> None:
    valid = _valid()

    parsed = review._parse_review("```json\n" + json.dumps(valid) + "\n```", SHAS)

    assert parsed == valid


def test_review_parser_rejects_missing_candidate() -> None:
    invalid = _valid()
    invalid["candidate_assessments"] = invalid["candidate_assessments"][:-1]

    with pytest.raises(ValueError, match="coverage is not exact"):
        review._parse_review(json.dumps(invalid), SHAS)


def test_review_parser_rejects_unknown_fields() -> None:
    invalid = {**_valid(), "confidence": 0.9}

    with pytest.raises(ValueError, match="keys are invalid"):
        review._parse_review(json.dumps(invalid), SHAS)


def test_packetizer_conserves_order_and_allows_single_oversize() -> None:
    rows = [
        {"sha": SHAS[0], "exact_diff_bytes": 40},
        {"sha": SHAS[1], "exact_diff_bytes": 80},
        {"sha": SHAS[2], "exact_diff_bytes": 200},
    ]

    packets = review._packetize(rows, max_diff_bytes=100, max_candidates=2)

    assert [[row["sha"] for row in packet] for packet in packets] == [
        [SHAS[0]],
        [SHAS[1]],
        [SHAS[2]],
    ]


def test_packetizer_rejects_nonpositive_bounds() -> None:
    with pytest.raises(ValueError, match="bounds must be positive"):
        review._packetize([], max_diff_bytes=0, max_candidates=1)


def test_nonempty_graph_buckets_cover_all_frozen_candidates() -> None:
    assert (
        sum(review.EXPECTED_GRAPH_BUCKET_COUNTS[bucket] for bucket in review.BUCKETS)
        == 55
    )
