import pytest

from build_atomic_ai_causal_ledger import (
    _accepted_edges,
    _explicit_ai_signals,
    review_edge_support,
    review_edge_verdict_support,
)


def test_review_support_is_edge_specific_and_source_distinct() -> None:
    positive = {
        "status": "COMPLETE",
        "class_id": "alias-1",
        "reviews": [
            {
                "candidate_sha": "a" * 40,
                "fix_sha": "f" * 40,
                "verdict": "AI_CAUSAL",
            }
        ],
    }
    wrong_edge = {
        **positive,
        "reviews": [
            {
                "candidate_sha": "b" * 40,
                "fix_sha": "f" * 40,
                "verdict": "AI_CAUSAL",
            }
        ],
    }

    support = review_edge_support(
        {"run-a": [positive, positive], "run-b": [positive], "run-c": [wrong_edge]}
    )

    assert support[("alias-1", "a" * 40, "f" * 40)] == {"run-a", "run-b"}
    assert support[("alias-1", "b" * 40, "f" * 40)] == {"run-c"}


def test_review_verdict_support_preserves_counterevidence() -> None:
    def row(verdict: str) -> dict[str, object]:
        return {
            "status": "COMPLETE",
            "class_id": "alias-1",
            "reviews": [
                {
                    "candidate_sha": "a" * 40,
                    "fix_sha": "f" * 40,
                    "verdict": verdict,
                }
            ],
        }

    support = review_edge_verdict_support(
        {
            "positive": [row("AI_CAUSAL")],
            "negative": [row("NOT_AI_CAUSAL")],
            "unclear": [row("INCONCLUSIVE")],
        }
    )

    assert support[("alias-1", "a" * 40, "f" * 40)] == {
        "AI_CAUSAL": {"positive"},
        "NOT_AI_CAUSAL": {"negative"},
        "INCONCLUSIVE": {"unclear"},
    }


def test_explicit_ai_signals_extracts_commit_attribution() -> None:
    assert _explicit_ai_signals(
        {
            "proof": {"binding": "Generated with Claude Code"},
            "irrelevant": "ordinary human commit",
        }
    ) == ["Generated with Claude Code"]


def test_accepted_edges_require_atomic_sha_fix_and_ai_binding() -> None:
    assert _accepted_edges(
        [
            {
                "candidate_sha": "a" * 40,
                "fix_sha": "f" * 40,
                "origin_kind": "squash_member",
                "carrier_sha": "c" * 40,
                "ai_signal": "Co-Authored-By: Claude <noreply@anthropic.com>",
            }
        ],
        "alias-1",
    ) == [
        {
            "candidate_sha": "a" * 40,
            "fix_sha": "f" * 40,
            "origin_kind": "squash_member",
            "carrier_sha": "c" * 40,
            "ai_signal": "Co-Authored-By: Claude <noreply@anthropic.com>",
        }
    ]

    with pytest.raises(SystemExit, match="strict PASS lacks accepted edges"):
        _accepted_edges([], "alias-1")
    with pytest.raises(SystemExit, match="malformed accepted edge"):
        _accepted_edges(
            [
                {
                    "candidate_sha": "a" * 40,
                    "fix_sha": "f" * 40,
                    "origin_kind": "direct_commit",
                    "ai_signal": "human-authored commit",
                }
            ],
            "alias-1",
        )
