"""Tests for deterministic repair of Transformers model reviews."""

from __future__ import annotations

import cohort_transformers_review_repair as repair


def _payload() -> dict[str, object]:
    return {
        "candidate_assessments": [
            {
                "sha": "a" * 40,
                "verdict": "retain_unrelated",
                "related_cves": [],
                "causal_role": "",
                "reasoning": "No relevant path change.",
                "missing_evidence": [],
            }
        ],
        "family_assessments": [
            {
                "cve": "CVE-2025-14920",
                "ai_involvement": "not_supported",
                "candidate_shas": [],
                "reasoning": "No source-attributed overlap.",
                "missing_evidence": [],
            }
        ],
        "cross_file_hypotheses": [],
        "missing_evidence": [],
        "summary": "Retain both candidates.",
    }


def test_repair_fills_empty_role_and_exact_patch_equivalent() -> None:
    first = "a" * 40
    second = "b" * 40

    result, actions = repair._repair_payload(
        _payload(),
        candidate_shas=[first, second],
        cves=["CVE-2025-14920"],
        patch_ids={first: "same-patch", second: "same-patch"},
    )

    assessments = result["candidate_assessments"]
    assert isinstance(assessments, list)
    assert [row["sha"] for row in assessments] == [first, second]
    assert all(row["causal_role"] for row in assessments)
    assert len(actions) == 2


def test_repair_refuses_to_propagate_without_exact_patch_equivalence() -> None:
    first = "a" * 40
    second = "b" * 40

    try:
        repair._repair_payload(
            _payload(),
            candidate_shas=[first, second],
            cves=["CVE-2025-14920"],
            patch_ids={first: "first", second: "second"},
        )
    except ValueError as exc:
        assert "one assessed patch equivalent" in str(exc)
    else:
        raise AssertionError("repair unexpectedly propagated across different patches")
