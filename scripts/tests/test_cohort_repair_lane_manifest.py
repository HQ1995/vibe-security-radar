"""Tests for lossless staged repair-lane manifests."""

from __future__ import annotations

import pytest

from cohort.root_adjudication import canonical_sha256
from cohort_repair_lane_manifest import RepairLaneError, prepare_repair_lane


def _inputs() -> tuple[dict[str, object], dict[str, object]]:
    fixes = [
        {
            "advisory": "GHSA-test",
            "repository_identity": "github.com/acme/repo",
            "fix_sha": digit * 40,
        }
        for digit in ("1", "2", "3")
    ]
    manifest = {
        "schema_version": 1,
        "artifact_kind": "sealed_fix_manifest",
        "split_id": "parent-v1",
        "frozen_at": "2026-08-01T00:00:00Z",
        "fixes": fixes,
    }
    schedule = [
        {
            **row,
            "already_in_seed_manifest": index == 0,
            "review_tier": index,
            "review_lane": lane,
            "signals": [],
            "priority_rank": index + 1,
        }
        for index, (row, lane) in enumerate(
            zip(
                fixes,
                (
                    "sealed_seed_fix",
                    "explicit_security_regression",
                    "command_input_validation",
                ),
                strict=True,
            )
        )
    ]
    provenance = {
        "artifact_kind": "semantic_repair_chain_expansion",
        "expanded_manifest_sha256": canonical_sha256(manifest),
        "repair_schedule": schedule,
    }
    return manifest, provenance


def test_lane_selection_accounts_for_selected_and_deferred_roots() -> None:
    manifest, provenance = _inputs()

    selected, result = prepare_repair_lane(
        manifest,
        provenance,
        review_lanes={"explicit_security_regression"},
        split_id="p1-v1",
        frozen_at="2026-08-01T00:00:00Z",
    )

    assert [row["fix_sha"] for row in selected["fixes"]] == ["2" * 40]
    assert result["selected_root_count"] == 1
    assert result["deferred_root_count"] == 2
    assert result["all_parent_roots_accounted_for"] is True
    assert result["parent_root_count"] == sum(result["parent_lane_counts"].values())


def test_lane_selection_fails_closed_on_schedule_omission() -> None:
    manifest, provenance = _inputs()
    provenance["repair_schedule"] = provenance["repair_schedule"][:-1]

    with pytest.raises(RepairLaneError, match="does not conserve"):
        prepare_repair_lane(
            manifest,
            provenance,
            review_lanes={"explicit_security_regression"},
            split_id="p1-v1",
            frozen_at="2026-08-01T00:00:00Z",
        )


def test_lane_selection_can_bound_work_without_losing_parent_accounting() -> None:
    manifest, provenance = _inputs()

    selected, result = prepare_repair_lane(
        manifest,
        provenance,
        review_lanes={
            "explicit_security_regression",
            "command_input_validation",
        },
        max_roots=1,
        split_id="bounded-v1",
        frozen_at="2026-08-01T00:00:00Z",
    )

    assert [row["fix_sha"] for row in selected["fixes"]] == ["2" * 40]
    assert result["selected_root_count"] == 1
    assert result["deferred_root_count"] == 2
    assert result["max_selected_roots"] == 1
    assert result["all_parent_roots_accounted_for"] is True
