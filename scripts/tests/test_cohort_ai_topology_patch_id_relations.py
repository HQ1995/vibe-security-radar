"""Tests for exact patch-equivalent topology carrier relations."""

from __future__ import annotations

from cohort_ai_topology_patch_id_relations import (
    PatchIdEvidence,
    build_patch_relations,
)


def _sha(character: str) -> str:
    return character * 40


def test_patch_id_equality_adds_relation_without_changing_pair_membership() -> None:
    candidate = _sha("a")
    carrier = _sha("1")
    unrelated = _sha("2")
    parent = _sha("f")
    shared_patch = _sha("9")
    pairs = [
        {
            "candidate_sha": candidate,
            "fix_sha": carrier,
            "candidate_subject": "change panel",
            "fix_subject": "change panel (#1)",
            "fix_original_route": "nonancestral_topology_fallback",
            "topology_relation": "git_graph_incomparable",
            "retained": True,
        },
        {
            "candidate_sha": candidate,
            "fix_sha": unrelated,
            "candidate_subject": "change panel",
            "fix_subject": "other",
            "fix_original_route": "direct_ai_ancestry",
            "topology_relation": "git_graph_incomparable",
            "retained": True,
        },
    ]
    artifacts = build_patch_relations(
        overlap_summary={
            "repository_identity": "github.com/acme/repo",
            "all_residual_pairs_conserved": True,
            "retained_residual_pair_count": 2,
        },
        pair_rows=pairs,
        evidence_by_sha={
            candidate: PatchIdEvidence(candidate, ((parent, shared_patch),)),
            carrier: PatchIdEvidence(carrier, ((parent, shared_patch),)),
            unrelated: PatchIdEvidence(unrelated, ((parent, _sha("8")),)),
        },
        split_id="test-v1",
    )

    assert len(artifacts["relations"]) == 1
    assert artifacts["relations"][0]["carrier_sha"] == carrier
    assert artifacts["relations"][0]["relation_is_not_fix_label"] is True
    assert artifacts["summary"]["source_residual_pair_count"] == 2
    assert artifacts["summary"]["source_pair_membership_unchanged"] is True
