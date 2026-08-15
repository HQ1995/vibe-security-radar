"""Tests for the Coolify Sentinel activation carrier witness."""

from __future__ import annotations

import cohort_coolify_sentinel_activation_carrier_witness as witness


PATCH_ID = "1" * 40
OLD_BLOB = "2" * 40
NEW_BLOB = "3" * 40


def _delta(
    *,
    empty: bool = False,
    patch_id: str | None = PATCH_ID,
    before_blob: str = OLD_BLOB,
    after_blob: str = NEW_BLOB,
) -> dict[str, object]:
    return {
        "empty": empty,
        "stable_patch_id": patch_id,
        "before_blob_oid": before_blob,
        "after_blob_oid": after_blob,
    }


def test_path_identity_requires_patch_id_preimage_and_result_equivalence() -> None:
    canonical = _delta()
    alias = _delta()
    carrier = _delta()

    assert all(witness._path_identity_checks(canonical, alias, carrier).values())

    alias["stable_patch_id"] = "4" * 40
    checks = witness._path_identity_checks(canonical, alias, carrier)
    assert checks["canonical_alias_and_carrier_share_stable_path_patch_id"] is False


def test_carrier_merge_requires_first_parent_transition_and_second_parent_noop() -> (
    None
):
    canonical = _delta()
    carrier = {
        "parents": [
            witness.MAINLINE_PRE_CARRIER_SHA,
            witness.CARRIER_SECOND_PARENT_SHA,
        ],
        "first_parent_delta": _delta(),
        "second_parent_delta": _delta(
            empty=True,
            patch_id=None,
            before_blob=NEW_BLOB,
            after_blob=NEW_BLOB,
        ),
        "parent_blob_oids": [OLD_BLOB, NEW_BLOB],
        "result_blob_oid": NEW_BLOB,
    }

    assert all(witness._carrier_merge_checks(canonical, carrier).values())

    carrier["parents"] = [
        witness.CARRIER_SECOND_PARENT_SHA,
        witness.MAINLINE_PRE_CARRIER_SHA,
    ]
    checks = witness._carrier_merge_checks(canonical, carrier)
    assert checks["carrier_has_frozen_parent_order"] is False


def test_alias_merges_must_be_path_noops_to_both_parents() -> None:
    empty = _delta(
        empty=True,
        patch_id=None,
        before_blob=NEW_BLOB,
        after_blob=NEW_BLOB,
    )
    alias_sync = {
        "parents": [witness.PATCH_ALIAS_SHA, witness.MAINLINE_CARRIER_SHA],
        "first_parent_delta": dict(empty),
        "second_parent_delta": dict(empty),
    }
    alias_mainline = {
        "parents": [
            witness.MAINLINE_CARRIER_SHA,
            witness.ALIAS_BRANCH_SYNC_SHA,
        ],
        "first_parent_delta": dict(empty),
        "second_parent_delta": dict(empty),
        "parent_blob_oids": [NEW_BLOB, NEW_BLOB],
        "result_blob_oid": NEW_BLOB,
    }

    assert all(witness._alias_merge_checks(alias_sync, alias_mainline).values())

    alias_mainline["first_parent_delta"] = _delta()
    checks = witness._alias_merge_checks(alias_sync, alias_mainline)
    assert checks["alias_mainline_merge_has_zero_path_delta_to_both_parents"] is False

    alias_mainline["first_parent_delta"] = dict(empty)
    alias_mainline["parent_blob_oids"] = [NEW_BLOB]
    checks = witness._alias_merge_checks(alias_sync, alias_mainline)
    assert checks["alias_mainline_merge_preserves_same_path_blob"] is False


def test_repair_blame_contract_selects_canonical_carrier_not_alias() -> None:
    origins = {
        "canonical_activation": {"origin_sha": witness.CANONICAL_CANDIDATE_SHA},
        "alias_activation": {"origin_sha": witness.PATCH_ALIAS_SHA},
        "carrier_activation": {"origin_sha": witness.CANONICAL_CANDIDATE_SHA},
        "post_alias_merge_activation": {"origin_sha": witness.CANONICAL_CANDIDATE_SHA},
        "pre_repair_activation": {"origin_sha": witness.CANONICAL_CANDIDATE_SHA},
        "post_repair_activation": {"origin_sha": witness.CANONICAL_CANDIDATE_SHA},
        "repair_setting_validator": {"origin_sha": witness.SECURITY_REPAIR_SHA},
        "repair_start_validation": {"origin_sha": witness.SECURITY_REPAIR_SHA},
        "repair_reported_poc_test": {"origin_sha": witness.SECURITY_REPAIR_SHA},
    }

    assert all(witness._repair_blame_checks(origins).values())

    origins["pre_repair_activation"] = {"origin_sha": witness.PATCH_ALIAS_SHA}
    checks = witness._repair_blame_checks(origins)
    assert (
        checks["canonical_candidate_owns_activation_line_in_repair_preimage"] is False
    )
