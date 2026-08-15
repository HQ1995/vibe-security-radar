"""Contracts for recall-conserving Transformers packet aggregation."""

from __future__ import annotations

from pathlib import Path

import pytest

import cohort_transformers_zeroday_packet_review_aggregate as aggregate


def _closure() -> dict[str, object]:
    source = [
        {
            "sha": f"{index:040x}",
            "source_v3_ai_evidence": True,
            "advisory_model_path_hits": [],
        }
        for index in range(aggregate.EXPECTED_SOURCE_COUNT)
    ]
    structural = [
        {
            "sha": f"{1000 + index:040x}",
            "source_v3_ai_evidence": False,
            "advisory_model_path_hits": ["CVE-test"],
        }
        for index in range(aggregate.EXPECTED_STRUCTURAL_COUNT)
    ]
    filler = [
        {
            "sha": f"{2000 + index:040x}",
            "source_v3_ai_evidence": False,
            "advisory_model_path_hits": [],
        }
        for index in range(aggregate.EXPECTED_MEMBER_COUNT - len(structural))
    ]
    return {
        "artifact_kind": "transformers_zeroday_squash_member_closure",
        "member_candidates": [*structural, *filler],
        "noncarrier_observed_ai_candidates": source,
        "conservation": {
            "hard_filter_count": 0,
            "squash_members_retained": aggregate.EXPECTED_MEMBER_COUNT,
        },
    }


def _result(
    lane: str,
    shas: list[str],
    *,
    status: str = "completed",
    packet_index: int = 0,
    packet_count: int = 1,
) -> dict[str, object]:
    lane_count = (
        aggregate.EXPECTED_SOURCE_COUNT
        if lane == "source_attributed"
        else aggregate.EXPECTED_STRUCTURAL_COUNT
    )
    assessments = (
        [{"sha": sha, "verdict": "retain_unrelated"} for sha in shas]
        if status == "completed"
        else []
    )
    return {
        "artifact_kind": "transformers_zeroday_packet_ai_review",
        "result_status": status,
        "closure_sha256": "digest",
        "model": "model",
        "reasoning_effort": "low",
        "packet": {
            "lane": lane,
            "packet_index": packet_index,
            "packet_count": packet_count,
            "lane_candidate_count": lane_count,
            "candidate_shas": shas,
        },
        "review": {"candidate_assessments": assessments},
        "usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
    }


def _complete_results(
    closure: dict[str, object],
) -> list[tuple[Path, dict[str, object]]]:
    source, structural = aggregate._candidate_rows(closure)
    return [
        (
            Path("source/result.json"),
            _result("source_attributed", [str(row["sha"]) for row in source]),
        ),
        (
            Path("structural/result.json"),
            _result(
                "structural_path_partner_no_ai_signal",
                [str(row["sha"]) for row in structural],
            ),
        ),
    ]


def test_aggregate_accepts_completed_retry_and_audits_incomplete_attempt() -> None:
    closure = _closure()
    results = _complete_results(closure)
    source_shas = list(results[0][1]["packet"]["candidate_shas"])
    results.append(
        (
            Path("source-medium/result.json"),
            _result("source_attributed", source_shas, status="parse_error"),
        )
    )

    value = aggregate._aggregate(closure, results, closure_sha256="digest")

    assert value["candidate_assessment_count"] == 32
    assert value["completed_packet_count"] == 2
    assert value["incomplete_attempt_count"] == 1
    assert value["incomplete_attempts"][0]["negative_authority"] is False
    assert value["usage"]["accepted_completed_attempts"]["total_tokens"] == 24
    assert value["usage"]["all_attempts_including_incomplete"]["total_tokens"] == 36
    assert value["conservation"]["passed"] is True


def test_aggregate_rejects_incomplete_only_packet() -> None:
    closure = _closure()
    results = _complete_results(closure)
    results[0] = (
        results[0][0],
        {**results[0][1], "result_status": "parse_error", "review": {}},
    )

    with pytest.raises(ValueError, match="global review coverage failed"):
        aggregate._aggregate(closure, results, closure_sha256="digest")


def test_aggregate_rejects_duplicate_completed_retry() -> None:
    closure = _closure()
    results = _complete_results(closure)
    results.append((Path("duplicate/result.json"), dict(results[0][1])))

    with pytest.raises(ValueError, match="duplicate completed review packet"):
        aggregate._aggregate(closure, results, closure_sha256="digest")


def test_aggregate_rejects_digest_mismatch() -> None:
    closure = _closure()
    results = _complete_results(closure)
    results[0][1]["closure_sha256"] = "wrong"

    with pytest.raises(ValueError, match="digest mismatch"):
        aggregate._aggregate(closure, results, closure_sha256="digest")


def test_aggregate_rejects_nonconserving_closure() -> None:
    closure = _closure()
    closure["conservation"]["hard_filter_count"] = 1

    with pytest.raises(ValueError, match="179-member inventory"):
        aggregate._aggregate(
            closure, _complete_results(closure), closure_sha256="digest"
        )
