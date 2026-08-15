#!/usr/bin/env python3
"""Freeze the canonical Coolify Sentinel activation carrier witness."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from collections.abc import Mapping
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
)
from cohort_coolify_sentinel_command_injection_witness import _blame_line
from cohort_coolify_sentinel_restart_activation_witness import (
    _evaluate_activation_test,
    _evaluate_repair,
    _evaluate_restart_dispatch,
    _evaluate_setting_trigger,
    _evaluate_start_sink,
    _evaluate_ui_write,
    _line_number,
)


CANONICAL_PARENT_SHA = "53cd2a6e8622bf6715f5037666f174691e417ef3"
CANONICAL_CANDIDATE_SHA = "728f261316f2af904f755756d687a722d2967223"
MAINLINE_PRE_CARRIER_SHA = "51d232f7a16acb69d2321525b6dfe6a48da601c7"
CARRIER_SECOND_PARENT_SHA = "1e360aa1567100167d9f7ae3aa38d57b539095c5"
MAINLINE_CARRIER_SHA = "4783dcb80a781fbf0ab922a92fadb0dd9377371a"

PATCH_ALIAS_PARENT_SHA = "23c1184e86c44f10b32f86666a373414615771b9"
PATCH_ALIAS_SHA = "e04b9cd07c11b79d4fcd62d8dca441d8571e4086"
ALIAS_BRANCH_SYNC_SHA = "fd63c4f6f9a8234331daf87815a9d3a91992526e"
ALIAS_MAINLINE_MERGE_SHA = "6fbac979c66a058f602c729082f1ad8f0bcc3424"

REPAIR_PARENT_SHA = "6fbb5e626a82c576ae7a1a08b4e1d16aee2e82ed"
SECURITY_REPAIR_SHA = "096d4369e59b3db7ace2db3ca42588c41b9b6019"

SETTING_PATH = "app/Models/ServerSetting.php"
SERVER_PATH = "app/Models/Server.php"
UI_PATH = "app/Livewire/Server/Show.php"
START_PATH = "app/Actions/Server/StartSentinel.php"
ACTIVATION_TEST_PATH = "tests/Feature/ServerSettingSentinelRestartTest.php"
REPAIR_TEST_PATH = "tests/Feature/SentinelTokenValidationTest.php"
ACTIVATION_MARKER = "$settings->wasChanged('sentinel_token')"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_record(repository: Path, revision: str, source_path: str) -> dict[str, str]:
    blob = _git_blob(repository, revision, source_path)
    return {
        "revision": revision,
        "path": source_path,
        "git_blob_oid": _path_blob_oid(repository, revision, source_path),
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _path_blob_oid(repository: Path, revision: str, source_path: str) -> str:
    value = _git(
        repository,
        ["rev-parse", f"{revision}:{source_path}"],
        text=True,
    )
    assert isinstance(value, str)
    oid = value.strip()
    if len(oid) != 40:
        raise SystemExit(
            f"unexpected blob object id for {revision}:{source_path}: {oid!r}"
        )
    return oid


def _path_diff(repository: Path, before: str, after: str, source_path: str) -> bytes:
    value = _git(
        repository,
        [
            "diff",
            "--full-index",
            "--no-color",
            "--no-ext-diff",
            "--no-renames",
            before,
            after,
            "--",
            source_path,
        ],
    )
    assert isinstance(value, bytes)
    return value


def _stable_patch_id(repository: Path, diff: bytes) -> str | None:
    if not diff.strip():
        return None
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), "patch-id", "--stable"],
            input=diff,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"git patch-id --stable failed: {exc}") from exc
    if completed.returncode != 0:
        reason = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"git patch-id --stable failed: {reason}")
    fields = completed.stdout.decode("ascii", errors="strict").split()
    if len(fields) < 2 or len(fields[0]) != 40:
        raise SystemExit("git patch-id --stable returned malformed output")
    return fields[0]


def _path_delta_record(
    repository: Path, before: str, after: str, source_path: str
) -> dict[str, object]:
    diff = _path_diff(repository, before, after, source_path)
    return {
        "before_revision": before,
        "after_revision": after,
        "path": source_path,
        "before_blob_oid": _path_blob_oid(repository, before, source_path),
        "after_blob_oid": _path_blob_oid(repository, after, source_path),
        "diff_byte_count": len(diff),
        "diff_sha256": hashlib.sha256(diff).hexdigest(),
        "empty": not bool(diff),
        "stable_patch_id": _stable_patch_id(repository, diff),
    }


def _merge_path_record(
    repository: Path, revision: str, source_path: str
) -> dict[str, object]:
    metadata = _commit_metadata(repository, revision)
    parents = metadata["parents"]
    if not isinstance(parents, list) or len(parents) != 2:
        raise SystemExit(f"expected a two-parent merge commit: {revision}")
    first_parent, second_parent = (str(parent) for parent in parents)
    return {
        "revision": revision,
        "parents": [first_parent, second_parent],
        "path": source_path,
        "first_parent_delta": _path_delta_record(
            repository, first_parent, revision, source_path
        ),
        "second_parent_delta": _path_delta_record(
            repository, second_parent, revision, source_path
        ),
        "parent_blob_oids": [
            _path_blob_oid(repository, first_parent, source_path),
            _path_blob_oid(repository, second_parent, source_path),
        ],
        "result_blob_oid": _path_blob_oid(repository, revision, source_path),
    }


def _path_identity_checks(
    canonical_delta: Mapping[str, object],
    alias_delta: Mapping[str, object],
    carrier_delta: Mapping[str, object],
) -> dict[str, bool]:
    patch_ids = {
        canonical_delta.get("stable_patch_id"),
        alias_delta.get("stable_patch_id"),
        carrier_delta.get("stable_patch_id"),
    }
    return {
        "all_three_path_deltas_are_nonempty": all(
            row.get("empty") is False
            for row in (canonical_delta, alias_delta, carrier_delta)
        ),
        "canonical_alias_and_carrier_share_stable_path_patch_id": (
            len(patch_ids) == 1 and None not in patch_ids
        ),
        "canonical_and_alias_have_identical_preimage_blob": (
            canonical_delta.get("before_blob_oid") == alias_delta.get("before_blob_oid")
        ),
        "canonical_alias_and_carrier_have_identical_result_blob": (
            len(
                {
                    canonical_delta.get("after_blob_oid"),
                    alias_delta.get("after_blob_oid"),
                    carrier_delta.get("after_blob_oid"),
                }
            )
            == 1
        ),
    }


def _carrier_merge_checks(
    canonical_delta: Mapping[str, object],
    carrier: Mapping[str, object],
) -> dict[str, bool]:
    first_delta = carrier.get("first_parent_delta")
    second_delta = carrier.get("second_parent_delta")
    if not isinstance(first_delta, Mapping) or not isinstance(second_delta, Mapping):
        return {"carrier_merge_record_is_well_formed": False}
    parents = carrier.get("parents")
    parent_blobs = carrier.get("parent_blob_oids")
    return {
        "carrier_has_frozen_parent_order": parents
        == [MAINLINE_PRE_CARRIER_SHA, CARRIER_SECOND_PARENT_SHA],
        "carrier_first_parent_delta_is_canonical_patch": (
            first_delta.get("empty") is False
            and first_delta.get("stable_patch_id")
            == canonical_delta.get("stable_patch_id")
        ),
        "carrier_second_parent_delta_is_empty": second_delta.get("empty") is True,
        "carrier_first_parent_has_preimage_blob": (
            isinstance(parent_blobs, list)
            and len(parent_blobs) == 2
            and parent_blobs[0] == canonical_delta.get("before_blob_oid")
        ),
        "carrier_second_parent_and_result_have_canonical_result_blob": (
            isinstance(parent_blobs, list)
            and len(parent_blobs) == 2
            and parent_blobs[1] == canonical_delta.get("after_blob_oid")
            and carrier.get("result_blob_oid") == canonical_delta.get("after_blob_oid")
        ),
    }


def _alias_merge_checks(
    alias_sync: Mapping[str, object], alias_mainline: Mapping[str, object]
) -> dict[str, bool]:
    sync_first = alias_sync.get("first_parent_delta")
    sync_second = alias_sync.get("second_parent_delta")
    main_first = alias_mainline.get("first_parent_delta")
    main_second = alias_mainline.get("second_parent_delta")
    if not all(
        isinstance(value, Mapping)
        for value in (sync_first, sync_second, main_first, main_second)
    ):
        return {"alias_merge_records_are_well_formed": False}
    assert isinstance(sync_first, Mapping)
    assert isinstance(sync_second, Mapping)
    assert isinstance(main_first, Mapping)
    assert isinstance(main_second, Mapping)
    mainline_parent_blobs = alias_mainline.get("parent_blob_oids")
    return {
        "alias_sync_has_frozen_parent_order": alias_sync.get("parents")
        == [PATCH_ALIAS_SHA, MAINLINE_CARRIER_SHA],
        "alias_sync_has_zero_path_delta_to_both_parents": (
            sync_first.get("empty") is True and sync_second.get("empty") is True
        ),
        "alias_mainline_merge_has_frozen_parent_order": alias_mainline.get("parents")
        == [MAINLINE_CARRIER_SHA, ALIAS_BRANCH_SYNC_SHA],
        "alias_mainline_merge_has_zero_path_delta_to_both_parents": (
            main_first.get("empty") is True and main_second.get("empty") is True
        ),
        "alias_mainline_merge_preserves_same_path_blob": (
            isinstance(mainline_parent_blobs, list)
            and len(mainline_parent_blobs) == 2
            and len(
                {
                    *mainline_parent_blobs,
                    alias_mainline.get("result_blob_oid"),
                }
            )
            == 1
        ),
    }


def _repair_blame_checks(
    line_origins: Mapping[str, Mapping[str, object]],
) -> dict[str, bool]:
    return {
        "canonical_candidate_owns_activation_line_at_own_commit": (
            line_origins["canonical_activation"]["origin_sha"]
            == CANONICAL_CANDIDATE_SHA
        ),
        "alias_owns_parallel_activation_line_at_own_commit": (
            line_origins["alias_activation"]["origin_sha"] == PATCH_ALIAS_SHA
        ),
        "canonical_candidate_owns_line_after_first_mainline_carrier": (
            line_origins["carrier_activation"]["origin_sha"] == CANONICAL_CANDIDATE_SHA
        ),
        "canonical_candidate_still_owns_line_after_alias_merge": (
            line_origins["post_alias_merge_activation"]["origin_sha"]
            == CANONICAL_CANDIDATE_SHA
        ),
        "canonical_candidate_owns_activation_line_in_repair_preimage": (
            line_origins["pre_repair_activation"]["origin_sha"]
            == CANONICAL_CANDIDATE_SHA
        ),
        "canonical_candidate_owns_unchanged_activation_line_after_repair": (
            line_origins["post_repair_activation"]["origin_sha"]
            == CANONICAL_CANDIDATE_SHA
        ),
        "repair_owns_added_setting_validator": (
            line_origins["repair_setting_validator"]["origin_sha"]
            == SECURITY_REPAIR_SHA
        ),
        "repair_owns_added_start_validation": (
            line_origins["repair_start_validation"]["origin_sha"] == SECURITY_REPAIR_SHA
        ),
        "repair_owns_reported_poc_test": (
            line_origins["repair_reported_poc_test"]["origin_sha"]
            == SECURITY_REPAIR_SHA
        ),
    }


def _line_origin(
    repository: Path,
    revision: str,
    source_path: str,
    source: str,
    marker: str,
    label: str,
) -> dict[str, object]:
    return _blame_line(
        repository,
        revision,
        source_path,
        _line_number(source, marker),
        label,
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    revisions = {
        "canonical_candidate": CANONICAL_CANDIDATE_SHA,
        "first_mainline_carrier": MAINLINE_CARRIER_SHA,
        "patch_equivalent_alias": PATCH_ALIAS_SHA,
        "alias_branch_sync_merge": ALIAS_BRANCH_SYNC_SHA,
        "alias_mainline_merge": ALIAS_MAINLINE_MERGE_SHA,
        "security_repair": SECURITY_REPAIR_SHA,
    }
    metadata = {
        name: _commit_metadata(repository, revision)
        for name, revision in revisions.items()
    }

    canonical_delta = _path_delta_record(
        repository, CANONICAL_PARENT_SHA, CANONICAL_CANDIDATE_SHA, SETTING_PATH
    )
    alias_delta = _path_delta_record(
        repository, PATCH_ALIAS_PARENT_SHA, PATCH_ALIAS_SHA, SETTING_PATH
    )
    carrier = _merge_path_record(repository, MAINLINE_CARRIER_SHA, SETTING_PATH)
    alias_sync = _merge_path_record(repository, ALIAS_BRANCH_SYNC_SHA, SETTING_PATH)
    alias_mainline = _merge_path_record(
        repository, ALIAS_MAINLINE_MERGE_SHA, SETTING_PATH
    )
    carrier_delta = carrier["first_parent_delta"]
    assert isinstance(carrier_delta, Mapping)

    topology = {
        "canonical_is_in_carrier_history": _is_ancestor(
            repository, CANONICAL_CANDIDATE_SHA, MAINLINE_CARRIER_SHA
        ),
        "canonical_is_absent_from_carrier_first_parent": not _is_ancestor(
            repository, CANONICAL_CANDIDATE_SHA, MAINLINE_PRE_CARRIER_SHA
        ),
        "canonical_is_present_in_carrier_second_parent": _is_ancestor(
            repository, CANONICAL_CANDIDATE_SHA, CARRIER_SECOND_PARENT_SHA
        ),
        "alias_is_absent_from_first_mainline_carrier": not _is_ancestor(
            repository, PATCH_ALIAS_SHA, MAINLINE_CARRIER_SHA
        ),
        "canonical_and_alias_are_incomparable": not _is_ancestor(
            repository, CANONICAL_CANDIDATE_SHA, PATCH_ALIAS_SHA
        )
        and not _is_ancestor(repository, PATCH_ALIAS_SHA, CANONICAL_CANDIDATE_SHA),
        "alias_and_carrier_are_both_in_alias_sync": _is_ancestor(
            repository, PATCH_ALIAS_SHA, ALIAS_BRANCH_SYNC_SHA
        )
        and _is_ancestor(repository, MAINLINE_CARRIER_SHA, ALIAS_BRANCH_SYNC_SHA),
        "alias_sync_and_carrier_are_both_in_mainline_merge": _is_ancestor(
            repository, ALIAS_BRANCH_SYNC_SHA, ALIAS_MAINLINE_MERGE_SHA
        )
        and _is_ancestor(repository, MAINLINE_CARRIER_SHA, ALIAS_MAINLINE_MERGE_SHA),
        "canonical_carrier_and_alias_merge_precede_repair": all(
            _is_ancestor(repository, revision, SECURITY_REPAIR_SHA)
            for revision in (
                CANONICAL_CANDIDATE_SHA,
                MAINLINE_CARRIER_SHA,
                ALIAS_MAINLINE_MERGE_SHA,
            )
        ),
    }

    sources = {
        "canonical_parent_setting": _text_blob(
            repository, CANONICAL_PARENT_SHA, SETTING_PATH
        ),
        "canonical_setting": _text_blob(
            repository, CANONICAL_CANDIDATE_SHA, SETTING_PATH
        ),
        "canonical_activation_test": _text_blob(
            repository, CANONICAL_CANDIDATE_SHA, ACTIVATION_TEST_PATH
        ),
        "canonical_ui": _text_blob(repository, CANONICAL_CANDIDATE_SHA, UI_PATH),
        "canonical_server": _text_blob(
            repository, CANONICAL_CANDIDATE_SHA, SERVER_PATH
        ),
        "canonical_start": _text_blob(repository, CANONICAL_CANDIDATE_SHA, START_PATH),
        "alias_setting": _text_blob(repository, PATCH_ALIAS_SHA, SETTING_PATH),
        "carrier_setting": _text_blob(repository, MAINLINE_CARRIER_SHA, SETTING_PATH),
        "post_alias_merge_setting": _text_blob(
            repository, ALIAS_MAINLINE_MERGE_SHA, SETTING_PATH
        ),
        "pre_repair_setting": _text_blob(repository, REPAIR_PARENT_SHA, SETTING_PATH),
        "repair_setting": _text_blob(repository, SECURITY_REPAIR_SHA, SETTING_PATH),
        "repair_start": _text_blob(repository, SECURITY_REPAIR_SHA, START_PATH),
        "repair_test": _text_blob(repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH),
    }
    evaluations = {
        "canonical_parent_trigger": _evaluate_setting_trigger(
            sources["canonical_parent_setting"]
        ),
        "canonical_trigger": _evaluate_setting_trigger(sources["canonical_setting"]),
        "alias_trigger": _evaluate_setting_trigger(sources["alias_setting"]),
        "canonical_activation_test": _evaluate_activation_test(
            sources["canonical_activation_test"]
        ),
        "preexisting_ui_write": _evaluate_ui_write(sources["canonical_ui"]),
        "preexisting_restart_dispatch": _evaluate_restart_dispatch(
            sources["canonical_server"]
        ),
        "preexisting_start_sink": _evaluate_start_sink(sources["canonical_start"]),
        "security_repair": _evaluate_repair(
            sources["repair_setting"],
            sources["repair_start"],
            sources["repair_test"],
        ),
    }

    line_origins = {
        "canonical_activation": _line_origin(
            repository,
            CANONICAL_CANDIDATE_SHA,
            SETTING_PATH,
            sources["canonical_setting"],
            ACTIVATION_MARKER,
            "canonical Conductor activation line",
        ),
        "alias_activation": _line_origin(
            repository,
            PATCH_ALIAS_SHA,
            SETTING_PATH,
            sources["alias_setting"],
            ACTIVATION_MARKER,
            "parallel Claude patch-equivalent activation line",
        ),
        "carrier_activation": _line_origin(
            repository,
            MAINLINE_CARRIER_SHA,
            SETTING_PATH,
            sources["carrier_setting"],
            ACTIVATION_MARKER,
            "activation line after first mainline carrier",
        ),
        "post_alias_merge_activation": _line_origin(
            repository,
            ALIAS_MAINLINE_MERGE_SHA,
            SETTING_PATH,
            sources["post_alias_merge_setting"],
            ACTIVATION_MARKER,
            "activation line after patch-equivalent alias merge",
        ),
        "pre_repair_activation": _line_origin(
            repository,
            REPAIR_PARENT_SHA,
            SETTING_PATH,
            sources["pre_repair_setting"],
            ACTIVATION_MARKER,
            "activation line in security-repair preimage",
        ),
        "post_repair_activation": _line_origin(
            repository,
            SECURITY_REPAIR_SHA,
            SETTING_PATH,
            sources["repair_setting"],
            ACTIVATION_MARKER,
            "unchanged activation line after security repair",
        ),
        "repair_setting_validator": _line_origin(
            repository,
            SECURITY_REPAIR_SHA,
            SETTING_PATH,
            sources["repair_setting"],
            "function isValidSentinelToken",
            "repair-added token validator",
        ),
        "repair_start_validation": _line_origin(
            repository,
            SECURITY_REPAIR_SHA,
            START_PATH,
            sources["repair_start"],
            "ServerSetting::isValidSentinelToken($token)",
            "repair-added validation before shell sink",
        ),
        "repair_reported_poc_test": _line_origin(
            repository,
            SECURITY_REPAIR_SHA,
            REPAIR_TEST_PATH,
            sources["repair_test"],
            "rejects the reported PoC payload",
            "repair regression test for reported command-injection PoC",
        ),
    }

    path_identity_checks = _path_identity_checks(
        canonical_delta, alias_delta, carrier_delta
    )
    carrier_merge_checks = _carrier_merge_checks(canonical_delta, carrier)
    alias_merge_checks = _alias_merge_checks(alias_sync, alias_mainline)
    repair_blame_checks = _repair_blame_checks(line_origins)

    canonical_parent_trigger = evaluations["canonical_parent_trigger"]
    canonical_trigger = evaluations["canonical_trigger"]
    alias_trigger = evaluations["alias_trigger"]
    preexisting_sink = evaluations["preexisting_start_sink"]
    semantic_checks = {
        "canonical_and_alias_are_explicit_ai_commits": (
            metadata["canonical_candidate"]["explicit_claude_signal"] is True
            and metadata["patch_equivalent_alias"]["explicit_claude_signal"] is True
        ),
        "all_frozen_commit_parent_lists_match": (
            metadata["canonical_candidate"]["parents"] == [CANONICAL_PARENT_SHA]
            and metadata["first_mainline_carrier"]["parents"]
            == [MAINLINE_PRE_CARRIER_SHA, CARRIER_SECOND_PARENT_SHA]
            and metadata["patch_equivalent_alias"]["parents"]
            == [PATCH_ALIAS_PARENT_SHA]
            and metadata["alias_branch_sync_merge"]["parents"]
            == [PATCH_ALIAS_SHA, MAINLINE_CARRIER_SHA]
            and metadata["alias_mainline_merge"]["parents"]
            == [MAINLINE_CARRIER_SHA, ALIAS_BRANCH_SYNC_SHA]
            and metadata["security_repair"]["parents"] == [REPAIR_PARENT_SHA]
        ),
        "canonical_changes_ineffective_trigger_to_effective_trigger": (
            isinstance(canonical_parent_trigger, Mapping)
            and isinstance(canonical_trigger, Mapping)
            and canonical_parent_trigger["uses_post_update_is_dirty_for_token"] is True
            and canonical_parent_trigger["uses_post_update_was_changed_for_token"]
            is False
            and canonical_trigger["uses_post_update_is_dirty_for_token"] is False
            and canonical_trigger["uses_post_update_was_changed_for_token"] is True
            and canonical_trigger["changed_token_dispatches_restart"] is True
        ),
        "alias_has_same_effective_trigger_contract": (
            isinstance(alias_trigger, Mapping) and alias_trigger == canonical_trigger
        ),
        "canonical_commit_contains_activation_regression_test": all(
            bool(value) for value in evaluations["canonical_activation_test"].values()
        ),
        "preexisting_ui_dispatch_and_shell_sink_complete_causal_path": (
            all(bool(value) for value in evaluations["preexisting_ui_write"].values())
            and all(
                bool(value)
                for value in evaluations["preexisting_restart_dispatch"].values()
            )
            and isinstance(preexisting_sink, Mapping)
            and preexisting_sink["reads_persisted_token"] is True
            and preexisting_sink["places_token_in_environment"] is True
            and preexisting_sink[
                "builds_double_quoted_environment_without_shell_escaping"
            ]
            is True
            and preexisting_sink["executes_composed_docker_command"] is True
            and preexisting_sink["validates_token_before_sink"] is False
            and preexisting_sink["shell_quotes_environment"] is False
        ),
        "security_repair_closes_and_tests_the_sink": all(
            bool(value) for value in evaluations["security_repair"].values()
        ),
    }

    check_groups = {
        "topology": topology,
        "path_identity": path_identity_checks,
        "first_mainline_carrier": carrier_merge_checks,
        "patch_equivalent_alias_merges": alias_merge_checks,
        "repair_blame": repair_blame_checks,
        "semantics": semantic_checks,
    }
    witness_passed = all(
        value is True for group in check_groups.values() for value in group.values()
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_sentinel_activation_carrier_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "canonical_candidate_sha": CANONICAL_CANDIDATE_SHA,
        "first_mainline_carrier_sha": MAINLINE_CARRIER_SHA,
        "patch_equivalent_alias_sha": PATCH_ALIAS_SHA,
        "alias_branch_sync_merge_sha": ALIAS_BRANCH_SYNC_SHA,
        "alias_mainline_merge_sha": ALIAS_MAINLINE_MERGE_SHA,
        "fix_sha": SECURITY_REPAIR_SHA,
        "metadata": metadata,
        "topology": topology,
        "path_identity": {
            "path": SETTING_PATH,
            "canonical_candidate_delta": canonical_delta,
            "patch_equivalent_alias_delta": alias_delta,
            "stable_code_change_identity": canonical_delta["stable_patch_id"],
            "checks": path_identity_checks,
        },
        "merge_path_evidence": {
            "first_mainline_carrier": carrier,
            "alias_branch_sync_merge": alias_sync,
            "alias_mainline_merge": alias_mainline,
            "checks": {
                **carrier_merge_checks,
                **alias_merge_checks,
            },
        },
        "evaluations": evaluations,
        "line_origins": line_origins,
        "repair_blame_checks": repair_blame_checks,
        "source_blobs": [
            _blob_record(repository, CANONICAL_PARENT_SHA, SETTING_PATH),
            _blob_record(repository, CANONICAL_CANDIDATE_SHA, SETTING_PATH),
            _blob_record(repository, PATCH_ALIAS_PARENT_SHA, SETTING_PATH),
            _blob_record(repository, PATCH_ALIAS_SHA, SETTING_PATH),
            _blob_record(repository, MAINLINE_PRE_CARRIER_SHA, SETTING_PATH),
            _blob_record(repository, CARRIER_SECOND_PARENT_SHA, SETTING_PATH),
            _blob_record(repository, MAINLINE_CARRIER_SHA, SETTING_PATH),
            _blob_record(repository, ALIAS_MAINLINE_MERGE_SHA, SETTING_PATH),
            _blob_record(repository, REPAIR_PARENT_SHA, SETTING_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, SETTING_PATH),
            _blob_record(repository, CANONICAL_CANDIDATE_SHA, UI_PATH),
            _blob_record(repository, CANONICAL_CANDIDATE_SHA, SERVER_PATH),
            _blob_record(repository, CANONICAL_CANDIDATE_SHA, START_PATH),
            _blob_record(repository, CANONICAL_CANDIDATE_SHA, ACTIVATION_TEST_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, START_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH),
        ],
        "confirmed_edge": {
            "adjudication": "CONFIRMED_AI_SHELL_TRIGGER_ACTIVATION_CONTRIBUTOR",
            "candidate_sha": CANONICAL_CANDIDATE_SHA,
            "fix_sha": SECURITY_REPAIR_SHA,
            "mechanism_group": "sentinel_setting_updated_restart_command_injection",
        },
        "alias_disposition": {
            "candidate_sha": PATCH_ALIAS_SHA,
            "status": "PATCH_EQUIVALENT_ALIAS_NO_INDEPENDENT_MAINLINE_PATH_CONTRIBUTION",
            "candidate_level_true_positive_increment": 0,
            "reason": (
                "The alias owns the same path patch on its parallel branch, but the "
                "canonical blob had already entered mainline through 4783dcb. Both "
                "the alias-branch sync merge and the later mainline merge have zero "
                "net ServerSetting.php delta to either parent."
            ),
        },
        "counting": {
            "candidate_level_true_positive_count": 1,
            "unique_path_code_change_identity_count": 1,
            "patch_equivalent_alias_increment": 0,
            "earliest_command_injection_origin_is_ai_not_asserted": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "check_groups": check_groups,
        "claim_boundary": (
            "The Conductor commit 728f261 is the canonical mainline carrier for "
            "the Sentinel wasChanged activation path: it is absent from 4783dcb's "
            "first parent, present in its second-parent history, supplies exactly "
            "the first-parent path delta at that merge, and remains the blamed "
            "origin through the repair preimage. The earlier-authored Claude commit "
            "e04b9cd is a parallel path-patch-equivalent alias. It reaches mainline "
            "through fd63c4f and 6fbac979 only after the canonical blob is present, "
            "with zero ServerSetting.php delta at both merges, so it is not counted "
            "as a second causal path contribution. The repair 096d436 validates and "
            "shell-quotes the token and tests the reported PoC. This confirms one "
            "AI-created automatic trigger/path extension, not AI origination of the "
            "pre-existing shell sink or local exploit execution."
        ),
        "witness_passed": witness_passed,
    }
    _atomic_json(args.output, payload)
    print("Coolify Sentinel activation carrier witness frozen")
    print(f"  canonical candidate : {CANONICAL_CANDIDATE_SHA}")
    print(f"  first carrier       : {MAINLINE_CARRIER_SHA}")
    print(f"  patch alias         : {PATCH_ALIAS_SHA}")
    print(f"  repair              : {SECURITY_REPAIR_SHA}")
    print(f"  witness passed      : {witness_passed}")
    print(f"  output              : {args.output}")
    return 0 if witness_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
