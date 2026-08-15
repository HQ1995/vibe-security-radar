"""Tests for the independent preimage-batch model review contract."""

from __future__ import annotations

import json

import pytest

from cohort_coolify_preimage_batch_ai_review import _parse_review


def _row(key: str, verdict: str = "PROMOTE") -> dict[str, object]:
    return {
        "key": key,
        "verdict": verdict,
        "confidence": 0.8,
        "causal_delta": "exact state is repaired",
        "missing_evidence": [],
        "possible_overlap": [],
    }


def test_parse_review_requires_every_case_once() -> None:
    payload = {"reviews": [_row("a"), _row("b", "DEFER")], "batch_notes": []}

    parsed = _parse_review(json.dumps(payload), {"a", "b"})

    assert parsed == payload


def test_parse_review_rejects_omitted_case() -> None:
    payload = {"reviews": [_row("a")], "batch_notes": []}

    with pytest.raises(ValueError, match="omitted"):
        _parse_review(json.dumps(payload), {"a", "b"})
