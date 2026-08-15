"""Tests for local semantic review of exact-delta packets."""

from __future__ import annotations

import json

import pytest

from cohort_coolify_exact_delta_ai_review import _build_prompt, _parse_review


def _packet() -> dict[str, object]:
    return {
        "case_results": [
            {
                "key": "candidate__fix",
                "candidate_sha": "a" * 40,
                "fix_sha": "b" * 40,
                "candidate_metadata": {"subject": "add unsafe path"},
                "fix_metadata": {"subject": "fix unsafe path"},
                "candidate_diff_stat": "app/a.php | 2 +-",
                "fix_diff_stat": "app/a.php | 2 +-",
                "bridge_class": "B0_CANDIDATE_ADDITION_EXACTLY_REMOVED",
                "exact_reversal_counts": {
                    "candidate_added_fix_removed": 1,
                    "candidate_removed_fix_added": 0,
                },
                "focal_exact_delta_sample": [],
                "omitted_focal_path_count": 0,
                "path_packets": [
                    {
                        "path": "app/a.php",
                        "candidate_patch": {"excerpt": "+unsafe();"},
                        "fix_patch": {"excerpt": "-unsafe();\n+safe();"},
                    }
                ],
                "checks": {"candidate_is_observed_ai": True},
                "passed": True,
            }
        ]
    }


def test_prompt_contains_both_candidate_and_fix_hunks() -> None:
    prompt = _build_prompt(_packet())

    assert "+unsafe();" in prompt
    assert "-unsafe();" in prompt
    assert "PROMOTE|DEFER|REJECT" in prompt


def test_prompt_uses_first_message_line_when_metadata_has_no_subject() -> None:
    packet = _packet()
    case = packet["case_results"][0]
    case["candidate_metadata"] = {"message": "candidate first line\nbody"}
    case["fix_metadata"] = {"message": "fix first line\nbody"}

    prompt = _build_prompt(packet)

    assert '"candidate_subject": "candidate first line"' in prompt
    assert '"fix_subject": "fix first line"' in prompt


def test_parse_review_accepts_fenced_complete_json() -> None:
    payload = {
        "reviews": [
            {
                "key": "candidate__fix",
                "verdict": "PROMOTE",
                "confidence": 0.9,
                "defect_type": "FUNCTIONAL_REGRESSION",
                "causal_chain": "candidate added unsafe state and fix removed it",
                "decisive_evidence": ["matching hunk"],
                "missing_evidence": [],
                "possible_overlap": [],
            }
        ],
        "batch_notes": [],
    }

    parsed = _parse_review(
        f"```json\n{json.dumps(payload)}\n```", {"candidate__fix"}
    )

    assert parsed["reviews"][0]["verdict"] == "PROMOTE"


def test_parse_review_rejects_omitted_case() -> None:
    with pytest.raises(ValueError, match="omitted"):
        _parse_review('{"reviews": [], "batch_notes": []}', {"candidate__fix"})
