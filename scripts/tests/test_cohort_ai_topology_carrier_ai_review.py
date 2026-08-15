"""Tests for topology-carrier semantic reviewer prompts."""

from __future__ import annotations

from cohort_ai_topology_carrier_ai_review import _build_prompt


def test_prompt_contains_candidate_carrier_and_fix_hunks() -> None:
    packet = {
        "case_results": [
            {
                "key": "candidate__fix",
                "candidate_sha": "a" * 40,
                "carrier_sha": "b" * 40,
                "fix_sha": "c" * 40,
                "candidate_metadata": {"subject": "candidate"},
                "carrier_metadata": {"subject": "carrier"},
                "fix_metadata": {"subject": "fix"},
                "carrier_chains": [{"patch_id": "d" * 40}],
                "path_packets": [
                    {
                        "candidate_patch": {"excerpt": "+unsafe();"},
                        "carrier_patch": {"excerpt": "+unsafe();"},
                        "fix_patch": {"excerpt": "-unsafe();\n+safe();"},
                    }
                ],
                "checks": {"carrier_strictly_precedes_fix": True},
                "passed": True,
            }
        ]
    }

    prompt = _build_prompt(packet)

    assert prompt.count("+unsafe();") == 1
    assert "-unsafe();" in prompt
    assert "carrier_patch_omitted_as_stable_patch_id_equivalent" in prompt
    assert "PROMOTE|DEFER|REJECT" in prompt
