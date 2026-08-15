"""Contracts for ChurchCRM compositional independent-review packets."""

from __future__ import annotations

import json

import pytest

import cohort_churchcrm_compositional_ai_review as review


VALID = {
    "verdict": "confirmed_compositional_contributor",
    "independent_ai_root": "no",
    "latent_ai_primitive": "yes",
    "human_activation_required": "yes",
    "counterfactual": "Without the helper there is no permissive target; without activation it is not selected.",
    "causal_chain": ["AI adds helper", "human selects helper"],
    "missing_evidence": [],
}


def test_review_parser_accepts_exact_schema_and_markdown_fence() -> None:
    text = "```json\n" + json.dumps(VALID) + "\n```"

    assert review._parse_review(text) == VALID


def test_review_parser_rejects_unknown_fields() -> None:
    value = {**VALID, "confidence": 0.9}

    with pytest.raises(ValueError, match="keys are invalid"):
        review._parse_review(json.dumps(value))


def test_review_parser_rejects_overlong_chain() -> None:
    value = {**VALID, "causal_chain": [str(index) for index in range(6)]}

    with pytest.raises(ValueError, match="exceeds five"):
        review._parse_review(json.dumps(value))


def test_review_transport_is_loopback_only() -> None:
    assert review._loopback("http://127.0.0.1:8317/v1") is True
    assert review._loopback("http://localhost:8317/v1") is True
    assert review._loopback("https://example.com/v1") is False
