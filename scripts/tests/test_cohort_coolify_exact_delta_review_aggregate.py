"""Tests for lossless aggregation of partial exact-delta reviews."""

from __future__ import annotations

import json

from cohort_coolify_exact_delta_review_aggregate import _parse_partial_review


def _review(key: str, verdict: str) -> dict[str, object]:
    return {
        "key": key,
        "verdict": verdict,
        "confidence": 0.8,
        "defect_type": "FUNCTIONAL_REGRESSION",
        "causal_chain": "candidate state is repaired by fix state",
        "decisive_evidence": [],
        "missing_evidence": [],
        "possible_overlap": [],
    }


def test_partial_parser_recovers_valid_rows_and_reports_seen_keys() -> None:
    payload = {"reviews": [_review("a", "PROMOTE")], "batch_notes": []}

    parsed, seen = _parse_partial_review(
        f"```json\n{json.dumps(payload)}\n```", {"a", "b"}
    )

    assert seen == {"a"}
    assert parsed["reviews"][0]["verdict"] == "PROMOTE"


def test_partial_parser_rejects_unknown_key() -> None:
    payload = {"reviews": [_review("outside", "REJECT")], "batch_notes": []}

    try:
        _parse_partial_review(json.dumps(payload), {"a"})
    except ValueError as exc:
        assert "unexpected" in str(exc)
    else:
        raise AssertionError("unknown review key should fail")
