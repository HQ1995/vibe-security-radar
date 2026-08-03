"""Tests for atomic and complex origin-control normalization."""

from __future__ import annotations

import pytest

from cohort.origin_controls import (
    OriginControlContractError,
    flatten_origin_controls,
)


def test_atomic_control_is_preserved() -> None:
    row = {
        "advisory": "CVE-test",
        "repository_identity": "github.com/example/repo",
        "fix_sha": "f" * 40,
        "atomic_origin_sha": "a" * 40,
        "expected_relation": "reachable_ancestor",
    }

    assert flatten_origin_controls({"controls": [row]}) == [row]


def test_complex_control_flattens_every_target_edge() -> None:
    payload = {
        "controls": [
            {
                "advisory": "CVE-test",
                "dimensions": ["MULTI_ORIGIN"],
                "source": "evidence.json",
                "source_sha256": "1" * 64,
                "topology_sources": [],
                "target_repository_identity": "github.com/example/repo",
                "target_edges": [
                    {
                        "candidate_sha": "a" * 40,
                        "fix_sha": "f" * 40,
                        "expected_relation": "reachable_ancestor",
                    },
                    {
                        "candidate_sha": "b" * 40,
                        "fix_sha": "f" * 40,
                        "expected_relation": "reachable_ancestor",
                    },
                ],
                "upstream_imports": [],
                "public_fixes": ["f" * 40],
            }
        ]
    }

    rows = flatten_origin_controls(payload)

    assert [row["atomic_origin_sha"] for row in rows] == ["a" * 40, "b" * 40]
    assert {row["repository_identity"] for row in rows} == {
        "github.com/example/repo"
    }


def test_mixed_control_shapes_fail_closed() -> None:
    with pytest.raises(OriginControlContractError, match="mixes"):
        flatten_origin_controls(
            {
                "controls": [
                    {
                        "advisory": "CVE-one",
                        "repository_identity": "github.com/example/repo",
                        "fix_sha": "f" * 40,
                        "atomic_origin_sha": "a" * 40,
                    },
                    {"target_edges": []},
                ]
            }
        )
