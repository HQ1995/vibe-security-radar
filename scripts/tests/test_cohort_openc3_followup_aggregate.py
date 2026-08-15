"""Contracts for final OpenC3 strict-follow-up aggregation."""

from __future__ import annotations

from pathlib import Path

import pytest

import cohort_openc3_followup_aggregate as aggregate


def _certificate() -> dict[str, object]:
    return {
        "conservation": {
            "retained_candidate_count": aggregate.EXPECTED_OBSERVED_AI_UNITS,
            "hard_filter_count": 0,
            "passed": True,
        }
    }


def _recall() -> dict[str, object]:
    return {
        "artifact_kind": "openc3_weak_password_ai_review_aggregate",
        "certificate_sha256": "certificate",
        "model_promoted_candidate_shas": sorted(aggregate.EXPECTED_LEADS),
    }


def _followup(*, status: str = "completed", promoted: str | None = None) -> dict[str, object]:
    assessments = [
        {
            "sha": sha,
            "verdict": (
                "claim_grade_path_extension" if sha == promoted else "not_causal_from_exact_delta"
            ),
        }
        for sha in sorted(aggregate.EXPECTED_LEADS)
    ]
    return {
        "artifact_kind": "openc3_weak_password_promoted_followup",
        "certificate_sha256": "certificate",
        "aggregate_sha256": "recall",
        "candidate_shas": sorted(aggregate.EXPECTED_LEADS),
        "model": "model",
        "observed_model": "model",
        "reasoning_effort": "high",
        "prompt_sha256": "prompt",
        "finish_reason": "stop" if status == "completed" else "length",
        "result_status": status,
        "usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
        "review": {"candidate_assessments": assessments} if status == "completed" else {},
        "claim_grade_shas": [promoted] if promoted else [],
        "parse_error": "truncated" if status != "completed" else "",
    }


def test_aggregate_keeps_incomplete_run_out_of_negative_evidence() -> None:
    complete = _followup()
    incomplete = _followup(status="parse_error")
    incomplete["observed_model"] = "other-model"

    result = aggregate._aggregate(
        _certificate(),
        _recall(),
        [(Path("complete.json"), complete), (Path("incomplete.json"), incomplete)],
        certificate_sha256="certificate",
        aggregate_sha256="recall",
    )

    assert result["candidate_retained_count"] == 55
    assert result["strict_complete_run_count"] == 1
    assert result["strict_incomplete_run_count"] == 1
    assert result["strict_incomplete_runs"][0]["disposition"] == (
        "INCOMPLETE_NOT_INTERPRETED_AS_NEGATIVE"
    )
    assert result["claim_grade_positive_count"] == 0
    assert result["conservation"]["passed"] is True


def test_aggregate_preserves_positive_from_complete_run() -> None:
    promoted = sorted(aggregate.EXPECTED_LEADS)[0]

    result = aggregate._aggregate(
        _certificate(),
        _recall(),
        [(Path("complete.json"), _followup(promoted=promoted))],
        certificate_sha256="certificate",
        aggregate_sha256="recall",
    )

    assert result["claim_grade_positive_shas"] == [promoted]


def test_aggregate_rejects_only_incomplete_runs() -> None:
    with pytest.raises(ValueError, match="no complete strict follow-up"):
        aggregate._aggregate(
            _certificate(),
            _recall(),
            [(Path("incomplete.json"), _followup(status="parse_error"))],
            certificate_sha256="certificate",
            aggregate_sha256="recall",
        )


def test_aggregate_rejects_digest_drift() -> None:
    followup = _followup()
    followup["aggregate_sha256"] = "wrong"

    with pytest.raises(ValueError, match="aggregate digest mismatch"):
        aggregate._aggregate(
            _certificate(),
            _recall(),
            [(Path("followup.json"), followup)],
            certificate_sha256="certificate",
            aggregate_sha256="recall",
        )
