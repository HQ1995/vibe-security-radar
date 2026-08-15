"""Tests for the Coolify global-search new-image origin witness."""

from __future__ import annotations

import pytest

import cohort_coolify_global_search_new_image_origin_witness as witness


def test_legacy_matcher_reproduces_new_image_alias_failure() -> None:
    assert witness._legacy_client_match("new image", witness.DOCKER_IMAGE_ITEM) is False
    assert (
        witness._legacy_client_match("new docker image", witness.DOCKER_IMAGE_ITEM)
        is True
    )


def test_fixed_matcher_resolves_both_docker_image_aliases() -> None:
    assert witness._fixed_client_match("new image", witness.DOCKER_IMAGE_ITEM) is True
    assert (
        witness._fixed_client_match("new docker image", witness.DOCKER_IMAGE_ITEM)
        is True
    )


def test_fixed_matcher_does_not_match_unrelated_command() -> None:
    assert witness._fixed_client_match("new redis", witness.DOCKER_IMAGE_ITEM) is False


def test_region_requires_unique_start_and_ordered_end() -> None:
    assert witness._region("before START body END after", "START", "END") == (
        "START body "
    )
    with pytest.raises(ValueError, match="2 positions"):
        witness._region("START one END START two END", "START", "END")
    with pytest.raises(ValueError, match="end marker"):
        witness._region("START only", "START", "END")


def test_bridge_edge_requires_one_exact_pair() -> None:
    rows = [{"candidate_sha": "a" * 40, "fix_sha": "b" * 40}]

    assert witness._bridge_edge(rows, "a" * 40, "b" * 40) == rows[0]
    with pytest.raises(ValueError, match="resolved to 0"):
        witness._bridge_edge(rows, "c" * 40, "d" * 40)
