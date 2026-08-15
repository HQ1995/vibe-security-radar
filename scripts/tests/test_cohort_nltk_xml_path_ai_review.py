"""Contracts for the NLTK affected-ancestor AI review."""

from __future__ import annotations

import json

import pytest

import cohort_nltk_xml_path_ai_review as review


def _assessment(sha: str, verdict: str = "retain_unrelated") -> dict[str, object]:
    return {
        "sha": sha,
        "verdict": verdict,
        "causal_role": "No causal delta.",
        "reasoning": "The changed lines are unrelated.",
        "missing_evidence": [],
    }


def test_packetize_is_exact_and_stable() -> None:
    rows = [{"sha": str(index)} for index in range(13)]

    packets = review._packetize(rows, 6)

    assert [len(packet) for packet in packets] == [6, 6, 1]
    assert [row for packet in packets for row in packet] == rows


def test_candidate_filter_preserves_parent_order() -> None:
    rows = [{"sha": "a" * 40}, {"sha": "b" * 40}, {"sha": "c" * 40}]

    selected = review._filter_candidates(rows, ["c" * 40, "a" * 40])

    assert [row["sha"] for row in selected] == ["a" * 40, "c" * 40]


def test_parse_review_requires_exact_candidate_coverage() -> None:
    shas = ["a" * 40, "b" * 40]
    payload = {
        "candidate_assessments": [_assessment(shas[0]), _assessment(shas[1])],
        "cross_file_hypotheses": [],
        "summary": "No causal candidate in this packet.",
    }

    parsed = review._parse_review(json.dumps(payload), shas, set(shas))

    assert len(parsed["candidate_assessments"]) == 2


def test_parse_review_rejects_missing_candidate() -> None:
    shas = ["a" * 40, "b" * 40]
    payload = {
        "candidate_assessments": [_assessment(shas[0])],
        "cross_file_hypotheses": [],
        "summary": "Incomplete.",
    }

    with pytest.raises(ValueError, match="coverage is not exact"):
        review._parse_review(json.dumps(payload), shas, set(shas))


def test_parse_review_keeps_possible_as_a_promotion() -> None:
    assert "retain_possible" in review.PROMOTED_VERDICTS
    assert "retain_insufficient" not in review.PROMOTED_VERDICTS
    assert "retain_unrelated" not in review.PROMOTED_VERDICTS


def test_cross_file_hypothesis_must_include_packet_candidate() -> None:
    packet_sha = "a" * 40
    other_sha = "b" * 40
    payload = {
        "candidate_assessments": [_assessment(packet_sha)],
        "cross_file_hypotheses": [
            {
                "candidate_shas": [other_sha],
                "status": "possible",
                "hypothesis": "A cross-file activation.",
                "evidence_needed": [],
            }
        ],
        "summary": "One hypothesis.",
    }

    with pytest.raises(ValueError, match="scope is invalid"):
        review._parse_review(json.dumps(payload), [packet_sha], {packet_sha, other_sha})


def test_priority_order_puts_semantic_and_path_candidates_first() -> None:
    assert review.PRIORITY_ORDER["P0_AI_CAUSAL_SEMANTIC_CODE"] == 0
    assert review.PRIORITY_ORDER["P3_AI_ANCESTRY_FALLBACK"] == 3
