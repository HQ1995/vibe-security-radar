"""Contracts for exact OpenC3 packet-review aggregation."""

from __future__ import annotations

from pathlib import Path

import pytest

import cohort_openc3_review_aggregate as aggregate


def _certificate() -> dict[str, object]:
    return {
        "observed_ai_candidates": [
            {"sha": f"{index:040x}"}
            for index in range(aggregate.EXPECTED_OBSERVED_AI_UNITS)
        ]
    }


def _result(shas: list[str]) -> dict[str, object]:
    return {
        "artifact_kind": "openc3_weak_password_packet_ai_review",
        "result_status": "completed",
        "certificate_sha256": "digest",
        "model": "model",
        "reasoning_effort": "high",
        "packet": {
            "bucket": "bucket",
            "packet_index": 0,
            "packet_count": 1,
            "candidate_shas": shas,
        },
        "review": {
            "candidate_assessments": [
                {"sha": sha, "verdict": "retain_unrelated"} for sha in shas
            ]
        },
        "usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
    }


def test_aggregate_requires_exact_global_coverage() -> None:
    certificate = _certificate()
    shas = [str(row["sha"]) for row in certificate["observed_ai_candidates"]]

    result = aggregate._aggregate(
        certificate, [(Path("result.json"), _result(shas))], certificate_sha256="digest"
    )

    assert result["candidate_assessment_count"] == 55
    assert result["conservation"]["passed"] is True
    assert result["claim_grade_positive_count"] == 0


def test_aggregate_rejects_missing_candidate() -> None:
    certificate = _certificate()
    shas = [str(row["sha"]) for row in certificate["observed_ai_candidates"]][:-1]

    with pytest.raises(ValueError, match="global review coverage failed"):
        aggregate._aggregate(
            certificate,
            [(Path("result.json"), _result(shas))],
            certificate_sha256="digest",
        )


def test_aggregate_rejects_digest_mismatch() -> None:
    certificate = _certificate()
    shas = [str(row["sha"]) for row in certificate["observed_ai_candidates"]]
    result = _result(shas)
    result["certificate_sha256"] = "wrong"

    with pytest.raises(ValueError, match="digest mismatch"):
        aggregate._aggregate(
            certificate, [(Path("result.json"), result)], certificate_sha256="digest"
        )
