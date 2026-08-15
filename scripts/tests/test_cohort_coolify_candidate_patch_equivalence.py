"""Tests for Coolify candidate patch-equivalence grouping."""

from __future__ import annotations

import cohort_coolify_candidate_patch_equivalence as equivalence


def test_patch_groups_collapse_only_nonempty_equal_deltas() -> None:
    patch = "1" * 40
    groups, identities = equivalence._patch_groups(
        {
            "a" * 40: patch,
            "b" * 40: patch,
            "c" * 40: None,
            "d" * 40: None,
        }
    )

    duplicate = [group for group in groups if group["patch_equivalent"]]
    assert len(duplicate) == 1
    assert duplicate[0]["candidate_shas"] == ["a" * 40, "b" * 40]
    assert identities["a" * 40] == identities["b" * 40] == patch
    assert identities["c" * 40] != identities["d" * 40]
    assert len(groups) == 3
