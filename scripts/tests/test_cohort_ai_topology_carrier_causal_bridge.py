"""Tests for compositional topology carrier-to-fix evidence."""

from __future__ import annotations

from cohort_ai_topology_carrier_causal_bridge import build_carrier_bridge


def _sha(character: str) -> str:
    return character * 40


def test_patch_equivalent_carrier_ancestor_bridges_incomparable_ai_to_fix() -> None:
    base = _sha("0")
    candidate = _sha("a")
    carrier = _sha("1")
    fix = _sha("2")
    commits = [
        {"sha": base, "parents": [], "graph_order": 1},
        {"sha": candidate, "parents": [base], "graph_order": 2},
        {"sha": carrier, "parents": [base], "graph_order": 3},
        {"sha": fix, "parents": [carrier], "graph_order": 4},
    ]
    relations = [
        {
            "candidate_sha": candidate,
            "carrier_sha": carrier,
            "relation": "stable_patch_id_equivalent",
            "shared_patch_ids": [_sha("9")],
            "candidate_parent_evidence": {_sha("9"): [base]},
            "carrier_parent_evidence": {_sha("9"): [base]},
        }
    ]
    delta_rows = [
        {
            "candidate_sha": candidate,
            "fix_sha": fix,
            "delta_class": "D0_CANDIDATE_ADDITION_EXACTLY_REMOVED",
            "exact_same_path_reversal_match_count": 1,
            "generated_only_reversal": False,
            "delta_review_priority_score": 100,
            "reversal_match_sample": [
                {
                    "match_kind": "exact_same_path",
                    "meaningful": True,
                    "generated_or_machine_artifact": False,
                    "candidate_parent_sha": base,
                    "fix_parent_sha": carrier,
                    "candidate_path": "src/app.py",
                    "fix_path": "src/app.py",
                }
            ],
            "retained": True,
        }
    ]

    artifacts = build_carrier_bridge(
        patch_summary={
            "source_pair_membership_unchanged": True,
            "hard_filter_count": 0,
            "exact_patch_equivalent_relation_count": 1,
        },
        relation_rows=relations,
        delta_summary={
            "repository_identity": "github.com/acme/repo",
            "all_residual_pairs_conserved": True,
            "hard_filter_count": 0,
            "exact_or_normalized_reversal_pair_count": 1,
        },
        exact_delta_rows=delta_rows,
        commit_rows=commits,
        split_id="test-v1",
    )
    row = artifacts["bridge_rows"][0]

    assert row["carrier_bridge_class"] == (
        "C0_EXACT_CARRIER_ANCESTOR_WITH_SAME_PATH_REVERSAL"
    )
    assert row["strict_ancestor_carriers"][0]["carrier_sha"] == carrier
    assert artifacts["summary"]["compositional_carrier_ancestor_pair_count"] == 1
    assert artifacts["summary"]["all_exact_reversal_pairs_conserved"] is True


def test_merge_parent_mismatch_stays_retained_but_is_not_strong() -> None:
    base = _sha("0")
    other_parent = _sha("3")
    candidate = _sha("a")
    carrier = _sha("1")
    fix = _sha("2")
    commits = [
        {"sha": base, "parents": [], "graph_order": 1},
        {"sha": other_parent, "parents": [base], "graph_order": 2},
        {"sha": candidate, "parents": [base, other_parent], "graph_order": 3},
        {"sha": carrier, "parents": [base], "graph_order": 4},
        {"sha": fix, "parents": [carrier], "graph_order": 5},
    ]
    relations = [
        {
            "candidate_sha": candidate,
            "carrier_sha": carrier,
            "relation": "stable_patch_id_equivalent",
            "shared_patch_ids": [_sha("9")],
            "candidate_parent_evidence": {_sha("9"): [base]},
            "carrier_parent_evidence": {_sha("9"): [base]},
        }
    ]
    delta_rows = [
        {
            "candidate_sha": candidate,
            "fix_sha": fix,
            "delta_class": "D0_CANDIDATE_ADDITION_EXACTLY_REMOVED",
            "exact_same_path_reversal_match_count": 1,
            "generated_only_reversal": False,
            "delta_review_priority_score": 100,
            "reversal_match_sample": [
                {
                    "match_kind": "exact_same_path",
                    "meaningful": True,
                    "generated_or_machine_artifact": False,
                    "candidate_parent_sha": other_parent,
                    "fix_parent_sha": carrier,
                    "candidate_path": "src/app.py",
                    "fix_path": "src/app.py",
                }
            ],
            "retained": True,
        }
    ]

    artifacts = build_carrier_bridge(
        patch_summary={
            "source_pair_membership_unchanged": True,
            "hard_filter_count": 0,
            "exact_patch_equivalent_relation_count": 1,
        },
        relation_rows=relations,
        delta_summary={
            "repository_identity": "github.com/acme/repo",
            "all_residual_pairs_conserved": True,
            "hard_filter_count": 0,
            "exact_or_normalized_reversal_pair_count": 1,
        },
        exact_delta_rows=delta_rows,
        commit_rows=commits,
        split_id="test-v1",
    )
    row = artifacts["bridge_rows"][0]

    assert row["carrier_bridge_class"] == (
        "C1_EXACT_CARRIER_ANCESTOR_WITH_WEAKER_REVERSAL"
    )
    assert row["carrier_linked_same_path_reversal_sample_count"] == 0
    assert row["retained"] is True
