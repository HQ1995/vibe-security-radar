"""Tests for the lossless merge-member topology overlay."""

from __future__ import annotations

from cohort_coolify_merge_member_topology_overlay import build_overlay


def _topology(
    sha: str,
    *,
    strict: int = 0,
    before: int = 0,
    identity: int = 0,
    incomparable: int = 0,
) -> dict[str, object]:
    return {
        "sha": sha,
        "strict_ai_ancestor_bitset_hex": format(strict, "01x"),
        "fix_precedes_ai_bitset_hex": format(before, "01x"),
        "identity_bitset_hex": format(identity, "01x"),
        "incomparable_residual_bitset_hex": format(incomparable, "01x"),
    }


def _exact(candidate: str, member: str, carrier: str) -> dict[str, object]:
    return {
        "candidate_sha": candidate,
        "member_fix_sha": member,
        "member_kind": "atomic_or_root",
        "merge_carrier_shas": [carrier],
        "exact_reversal_line_count": 1,
        "exact_reversal_sample": [
            {
                "path": "app/Auth.php",
                "content_excerpt": "if (!$allowed) { deny(); }",
                "control_like": True,
                "generated_or_machine_artifact": False,
            }
        ],
        "retained": True,
    }


def test_direct_and_carrier_landed_pairs_are_both_retained() -> None:
    candidate = "a" * 40
    member_direct = "b" * 40
    member_branch = "c" * 40
    carrier_direct = "d" * 40
    carrier_branch = "e" * 40
    first_direct = "f" * 40
    first_branch = "1" * 40
    rows = [
        _topology(member_direct, strict=1),
        _topology(member_branch, incomparable=1),
        _topology(carrier_direct, strict=1),
        _topology(carrier_branch, strict=1),
        _topology(first_direct, strict=1),
        _topology(first_branch, strict=1),
    ]
    commits = [
        {"sha": candidate, "subject": "add authorization check", "authored_at": "1"},
        {
            "sha": member_direct,
            "subject": "fix authorization rule",
            "authored_at": "2",
        },
        {"sha": member_branch, "subject": "branch implementation", "authored_at": "2"},
    ]
    payload = build_overlay(
        exact_rows=[
            _exact(candidate, member_direct, carrier_direct),
            _exact(candidate, member_branch, carrier_branch),
        ],
        inventory_rows=[
            {"merge_sha": carrier_direct, "first_parent_sha": first_direct},
            {"merge_sha": carrier_branch, "first_parent_sha": first_branch},
        ],
        ai_shas=[candidate],
        topology_rows=rows,
        commit_rows=commits,
        split_id="test-v1",
        repository_identity="github.com/coollabsio/coolify",
        compressed_pair_count=20,
    )

    summary = payload["summary"]
    assert summary["retained_exact_pair_count"] == 2
    assert summary["candidate_frontier_count"] == 1
    assert summary["hard_filter_count"] == 0
    assert summary["member_topology_class_counts"] == {
        "T0_DIRECT_MEMBER_AFTER_CANDIDATE": 1,
        "T1_MEMBER_LANDED_ON_CANDIDATE_FIRST_PARENT": 1,
    }
    assert payload["frontier"][0]["member_fix_sha"] == member_direct
    assert "GUARD_OR_VALIDATION_CHANGE" in payload["frontier"][0]["semantic_lanes"]
    assert payload["frontier"][0]["subject_token_overlap_tokens"] == ["authorization"]
    assert payload["frontier"][0]["candidate_exact_member_count"] == 2


def test_preexisting_member_is_retained_as_landing_evidence() -> None:
    candidate = "a" * 40
    member = "b" * 40
    carrier = "c" * 40
    first_parent = "d" * 40
    payload = build_overlay(
        exact_rows=[_exact(candidate, member, carrier)],
        inventory_rows=[{"merge_sha": carrier, "first_parent_sha": first_parent}],
        ai_shas=[candidate],
        topology_rows=[
            _topology(member, before=1),
            _topology(carrier, strict=1),
            _topology(first_parent, strict=1),
        ],
        commit_rows=[
            {"sha": candidate, "subject": "bad change", "authored_at": "2"},
            {"sha": member, "subject": "older correct code", "authored_at": "1"},
        ],
        split_id="test-v1",
        repository_identity="github.com/coollabsio/coolify",
        compressed_pair_count=1,
    )

    row = payload["exact_rows"][0]
    assert row["candidate_to_member_relation"] == "COMMIT_STRICT_ANCESTOR"
    assert row["member_topology_class"] == (
        "T1_MEMBER_LANDED_ON_CANDIDATE_FIRST_PARENT"
    )
    assert row["retained"] is True
