"""Tests for the Coolify upgrade shutdown-order regression witness."""

from __future__ import annotations

import pytest

import cohort_coolify_upgrade_shutdown_order_witness as witness


SAFE_SOURCE = """
echo before
for container in coolify coolify-db coolify-redis coolify-realtime; do
    docker stop "$container"
done
"""

INVERTED_SOURCE = r"""
nohup bash -c "
    for container in coolify-db coolify-redis coolify-realtime coolify; do
        docker stop \"\$container\"
    done
"
"""


def test_extract_stop_order_accepts_plain_and_detached_shell_loops() -> None:
    assert witness._extract_stop_order(SAFE_SOURCE) == witness.EXPECTED_CONTAINERS
    assert witness._extract_stop_order(INVERTED_SOURCE) == (
        *witness.DEPENDENCIES,
        witness.CONTROL_PLANE,
    )


@pytest.mark.parametrize(
    "source",
    [
        "echo no-loop\n",
        SAFE_SOURCE + SAFE_SOURCE,
        "for container in coolify coolify coolify-db coolify-redis; do\n",
        "for container in coolify coolify-db coolify-redis unknown; do\n",
    ],
)
def test_extract_stop_order_fails_closed_on_ambiguous_or_invalid_source(
    source: str,
) -> None:
    with pytest.raises(ValueError):
        witness._extract_stop_order(source)


def test_shutdown_simulator_distinguishes_safe_and_inverted_orders() -> None:
    safe = witness._evaluate_shutdown_order(witness.EXPECTED_CONTAINERS)
    inverted = witness._evaluate_shutdown_order(
        (*witness.DEPENDENCIES, witness.CONTROL_PLANE)
    )

    assert safe["dependency_safe"] is True
    assert safe["violation_count"] == 0
    assert safe["stopped_before_control_plane"] == []

    assert inverted["dependency_safe"] is False
    assert inverted["violation_count"] == 3
    assert inverted["violation_steps"] == [1, 2, 3]
    assert inverted["stopped_before_control_plane"] == list(witness.DEPENDENCIES)
    assert inverted["states"][0]["unavailable_control_plane_dependencies"] == [
        "coolify-db"
    ]
    assert inverted["states"][2]["unavailable_control_plane_dependencies"] == [
        "coolify-db",
        "coolify-realtime",
        "coolify-redis",
    ]


@pytest.mark.parametrize(
    "order",
    [
        ("coolify", "coolify-db", "coolify-redis", "coolify-redis"),
        ("coolify", "coolify-db", "coolify-redis", "unknown"),
    ],
)
def test_shutdown_simulator_rejects_invalid_container_sets(
    order: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError):
        witness._evaluate_shutdown_order(order)


def test_timing_contract_handles_offsets_and_rejects_reverse_time() -> None:
    assert (
        witness._seconds_between(
            "2025-12-12T15:36:01+01:00", "2025-12-12T15:39:08+01:00"
        )
        == 187
    )
    with pytest.raises(ValueError):
        witness._seconds_between(
            "2025-12-12T15:39:08+01:00", "2025-12-12T15:36:01+01:00"
        )


def test_containing_tag_parser_preserves_chronological_first_row() -> None:
    rows = witness._parse_containing_tags(
        "2025-12-17T10:23:45+01:00\tv4.0.0-beta.455\n"
        "2025-12-18T09:58:24+01:00\tv4.0.0-beta.456\n"
    )

    assert rows[0] == {
        "created_at": "2025-12-17T10:23:45+01:00",
        "tag": "v4.0.0-beta.455",
    }
    with pytest.raises(ValueError):
        witness._parse_containing_tags("")
