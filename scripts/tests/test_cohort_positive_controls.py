"""Tests for separated relation and advisory-source control recall."""

from __future__ import annotations

from cohort.positive_controls import evaluate_positive_controls


REPOSITORY = "github.com/new/project"
ORIGIN = "1" * 40
LANDED = "3" * 40
FIX = "4" * 40
RELATION = "pull_request_member_landed_as_squash_then_reachable_ancestor"


def _control() -> dict[str, object]:
    return {
        "advisory": "CVE-2026-1000",
        "repository_identity": "github.com/old/project",
        "atomic_origin_sha": ORIGIN,
        "expected_landed_sha": LANDED,
        "fix_sha": FIX,
        "expected_relation": RELATION,
    }


def test_relation_pass_does_not_imply_public_source_pass() -> None:
    result = evaluate_positive_controls(
        [_control()],
        [
            {
                "edge_id": "edge-1",
                "repository_identity": REPOSITORY,
                "candidate_sha": ORIGIN,
                "landed_sha": LANDED,
                "fix_sha": FIX,
                "relation": RELATION,
            }
        ],
        [],
        {"github.com/old/project": REPOSITORY},
    )

    assert result["relation_gate_passed"] is True
    assert result["relation_engine_recall"] == 1.0
    assert result["public_exact_fix_recall"] == 0.0


def test_public_source_requires_same_advisory_and_exact_fix() -> None:
    result = evaluate_positive_controls(
        [_control()],
        [],
        [
            {
                "repository_identity": REPOSITORY,
                "advisory": "CVE-2026-OTHER",
                "fix_sha": FIX,
            },
            {
                "repository_identity": REPOSITORY,
                "advisory": "CVE-2026-1000",
                "fix_sha": "5" * 40,
            },
        ],
        {"github.com/old/project": REPOSITORY},
    )

    assert result["relation_gate_passed"] is False
    assert result["public_exact_fix_recall"] == 0.0
