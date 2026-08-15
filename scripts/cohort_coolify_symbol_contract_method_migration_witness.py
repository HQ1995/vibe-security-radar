#!/usr/bin/env python3
"""Freeze the Coolify EditDomain partial method-migration causal witness."""

from __future__ import annotations

import argparse
import hashlib
import re
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


REPOSITORY_IDENTITY = "github.com/coollabsio/coolify"
INITIAL_CALL_AUTHOR_SHA = "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd"
CANDIDATE_PARENT_SHA = "543d6fb334e8ef3a7e5ddaae62e156528b6790ef"
CANDIDATE_SHA = "e2c254a5a8518c8dd9d31df60c9009fad119226d"
FIX_PARENT_SHA = "364fe04e8c1691415e2dca4221818e0f9cb2a638"
FIX_SHA = "4fc0c946daf3a858bfe0e14999b0432b1f38b4a3"
FIX_CARRIER_SHA = "b9c23ddc6f4927984861772f8fe784b33d712cd6"

SOURCE_PATH = "app/Livewire/Project/Service/EditDomain.php"
TRAIT_PATH = "app/Livewire/Concerns/SynchronizesModelData.php"
CONDUCTOR_MARKER = "Changes auto-committed by Conductor"
FIX_CARRIER_MESSAGE = (
    "Merge pull request #6945 from "
    "coollabsio/andrasbacsai/fix-service-edit-domain\n\n"
    "Fix: Use syncFromModel in EditDomain"
)
STALE_CALL = "$this->syncData(false);"
MIGRATED_CALL = "$this->syncFromModel();"
TO_MODEL_CALL = "$this->syncToModel();"
SYNC_METHODS = ("syncData", "syncFromModel", "syncToModel", "getModelBindings")

_METHOD_DEFINITION_RE = re.compile(
    r"^\s*(?:public|protected|private)\s+function\s+([A-Za-z_]\w*)\s*\(",
    re.MULTILINE,
)
_THIS_METHOD_CALL_RE = re.compile(r"\$this->([A-Za-z_]\w*)\s*\(")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


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
            "--unified=0",
            before,
            after,
            "--",
            source_path,
        ],
    )
    assert isinstance(value, bytes)
    return value


def _changed_lines(diff: bytes) -> tuple[list[str], list[str]]:
    added: list[str] = []
    removed: list[str] = []
    for line in diff.decode("utf-8", errors="strict").splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added.append(line[1:].strip())
        elif line.startswith("-"):
            removed.append(line[1:].strip())
    return added, removed


def _delta_record(
    repository: Path, before: str, after: str, source_path: str
) -> dict[str, object]:
    diff = _path_diff(repository, before, after, source_path)
    added, removed = _changed_lines(diff)
    return {
        "before_revision": before,
        "after_revision": after,
        "path": source_path,
        "before_blob_oid": _path_blob_oid(repository, before, source_path),
        "after_blob_oid": _path_blob_oid(repository, after, source_path),
        "diff_byte_count": len(diff),
        "diff_sha256": hashlib.sha256(diff).hexdigest(),
        "empty": not bool(diff),
        "added_lines": added,
        "removed_lines": removed,
    }


def _changed_paths(repository: Path, revision: str) -> list[str]:
    value = _git(
        repository,
        ["diff-tree", "--no-commit-id", "--name-only", "-r", revision],
        text=True,
    )
    assert isinstance(value, str)
    return [line for line in value.splitlines() if line]


def _symbol_snapshot(source: str) -> dict[str, object]:
    definitions = Counter(_METHOD_DEFINITION_RE.findall(source))
    calls = Counter(_THIS_METHOD_CALL_RE.findall(source))
    lines = source.splitlines()
    return {
        "definition_counts": {name: definitions[name] for name in SYNC_METHODS},
        "call_counts": {name: calls[name] for name in SYNC_METHODS},
        "sync_data_call_lines": [
            number
            for number, line in enumerate(lines, start=1)
            if line.strip() == STALE_CALL
        ],
        "sync_from_model_call_lines": [
            number
            for number, line in enumerate(lines, start=1)
            if line.strip() == MIGRATED_CALL
        ],
        "sync_to_model_call_lines": [
            number
            for number, line in enumerate(lines, start=1)
            if line.strip() == TO_MODEL_CALL
        ],
        "uses_synchronizes_model_data_trait": "use SynchronizesModelData;" in source,
        "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def _evaluate_contract_versions(
    initial_call_author: str,
    candidate_parent: str,
    candidate: str,
    fix_parent: str,
    fix: str,
    trait: str,
) -> dict[str, object]:
    snapshots = {
        "initial_call_author": _symbol_snapshot(initial_call_author),
        "candidate_parent": _symbol_snapshot(candidate_parent),
        "candidate": _symbol_snapshot(candidate),
        "fix_parent": _symbol_snapshot(fix_parent),
        "fix": _symbol_snapshot(fix),
        "candidate_trait": _symbol_snapshot(trait),
    }
    initial = snapshots["initial_call_author"]
    baseline = snapshots["candidate_parent"]
    broken = snapshots["candidate"]
    surviving = snapshots["fix_parent"]
    repaired = snapshots["fix"]
    trait_contract = snapshots["candidate_trait"]

    initial_definitions = initial["definition_counts"]
    initial_calls = initial["call_counts"]
    baseline_definitions = baseline["definition_counts"]
    baseline_calls = baseline["call_counts"]
    broken_definitions = broken["definition_counts"]
    broken_calls = broken["call_counts"]
    repaired_calls = repaired["call_counts"]
    trait_definitions = trait_contract["definition_counts"]
    assert isinstance(initial_definitions, Mapping)
    assert isinstance(initial_calls, Mapping)
    assert isinstance(baseline_definitions, Mapping)
    assert isinstance(baseline_calls, Mapping)
    assert isinstance(broken_definitions, Mapping)
    assert isinstance(broken_calls, Mapping)
    assert isinstance(repaired_calls, Mapping)
    assert isinstance(trait_definitions, Mapping)

    checks = {
        "initial_call_author_introduces_self_consistent_local_contract": (
            initial_definitions.get("syncData") == 1
            and initial_calls.get("syncData") == 4
            and initial.get("uses_synchronizes_model_data_trait") is False
        ),
        "candidate_parent_retains_self_consistent_local_contract": (
            baseline_definitions.get("syncData") == 1
            and baseline_calls.get("syncData") == 4
            and baseline.get("uses_synchronizes_model_data_trait") is False
        ),
        "candidate_replaces_local_callee_with_trait_contract": (
            broken_definitions.get("syncData") == 0
            and broken_definitions.get("getModelBindings") == 1
            and broken.get("uses_synchronizes_model_data_trait") is True
            and trait_definitions.get("syncData") == 0
            and trait_definitions.get("syncFromModel") == 1
            and trait_definitions.get("syncToModel") == 1
        ),
        "candidate_migrates_two_calls_but_leaves_two_old_calls": (
            broken_calls.get("syncData") == 2
            and broken_calls.get("syncFromModel") == 1
            and broken_calls.get("syncToModel") == 1
            and len(broken["sync_data_call_lines"]) == 2
        ),
        "broken_contract_survives_byte_exact_to_fix_parent": (
            candidate == fix_parent and broken == surviving
        ),
        "fix_removes_all_dangling_old_calls": (
            repaired_calls.get("syncData") == 0
            and len(repaired["sync_data_call_lines"]) == 0
        ),
        "fix_migrates_only_remaining_from_model_calls": (
            repaired_calls.get("syncFromModel") == 3
            and repaired_calls.get("syncToModel") == 1
            and repaired.get("uses_synchronizes_model_data_trait") is True
        ),
    }
    return {"snapshots": snapshots, "checks": checks}


def _evaluate_exact_fix_delta(
    fix_delta: Mapping[str, object],
    changed_paths: list[str],
    carrier_first_parent_delta: Mapping[str, object],
    carrier_second_parent_delta: Mapping[str, object],
) -> dict[str, bool]:
    return {
        "fix_changes_only_edit_domain": changed_paths == [SOURCE_PATH],
        "fix_removes_exactly_two_stale_calls": Counter(fix_delta["removed_lines"])
        == Counter({STALE_CALL: 2}),
        "fix_adds_exactly_two_trait_calls": Counter(fix_delta["added_lines"])
        == Counter({MIGRATED_CALL: 2}),
        "carrier_first_parent_replays_exact_fix_delta": (
            carrier_first_parent_delta.get("diff_sha256")
            == fix_delta.get("diff_sha256")
            and carrier_first_parent_delta.get("before_blob_oid")
            == fix_delta.get("before_blob_oid")
            and carrier_first_parent_delta.get("after_blob_oid")
            == fix_delta.get("after_blob_oid")
        ),
        "carrier_is_path_noop_relative_to_fix_second_parent": (
            carrier_second_parent_delta.get("empty") is True
            and carrier_second_parent_delta.get("before_blob_oid")
            == carrier_second_parent_delta.get("after_blob_oid")
            == fix_delta.get("after_blob_oid")
        ),
    }


def _commit_distance(repository: Path, before: str, after: str) -> int:
    value = _git(
        repository,
        ["rev-list", "--count", f"{before}..{after}"],
        text=True,
    )
    assert isinstance(value, str)
    return int(value.strip())


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    sources = {
        "initial_call_author": _text_blob(
            repository, INITIAL_CALL_AUTHOR_SHA, SOURCE_PATH
        ),
        "candidate_parent": _text_blob(repository, CANDIDATE_PARENT_SHA, SOURCE_PATH),
        "candidate": _text_blob(repository, CANDIDATE_SHA, SOURCE_PATH),
        "fix_parent": _text_blob(repository, FIX_PARENT_SHA, SOURCE_PATH),
        "fix": _text_blob(repository, FIX_SHA, SOURCE_PATH),
        "candidate_trait": _text_blob(repository, CANDIDATE_SHA, TRAIT_PATH),
    }
    contract = _evaluate_contract_versions(
        sources["initial_call_author"],
        sources["candidate_parent"],
        sources["candidate"],
        sources["fix_parent"],
        sources["fix"],
        sources["candidate_trait"],
    )

    candidate_delta = _delta_record(
        repository, CANDIDATE_PARENT_SHA, CANDIDATE_SHA, SOURCE_PATH
    )
    fix_delta = _delta_record(repository, FIX_PARENT_SHA, FIX_SHA, SOURCE_PATH)
    carrier_first_parent_delta = _delta_record(
        repository, FIX_PARENT_SHA, FIX_CARRIER_SHA, SOURCE_PATH
    )
    carrier_second_parent_delta = _delta_record(
        repository, FIX_SHA, FIX_CARRIER_SHA, SOURCE_PATH
    )
    exact_fix_checks = _evaluate_exact_fix_delta(
        fix_delta,
        _changed_paths(repository, FIX_SHA),
        carrier_first_parent_delta,
        carrier_second_parent_delta,
    )

    metadata = {
        "initial_call_author": _commit_metadata(repository, INITIAL_CALL_AUTHOR_SHA),
        "candidate": _commit_metadata(repository, CANDIDATE_SHA),
        "fix": _commit_metadata(repository, FIX_SHA),
        "fix_carrier": _commit_metadata(repository, FIX_CARRIER_SHA),
    }
    ancestry = {
        "initial_call_author_strictly_precedes_candidate": _is_ancestor(
            repository, INITIAL_CALL_AUTHOR_SHA, CANDIDATE_SHA
        ),
        "candidate_strictly_precedes_fix_parent": _is_ancestor(
            repository, CANDIDATE_SHA, FIX_PARENT_SHA
        ),
        "candidate_strictly_precedes_fix": _is_ancestor(
            repository, CANDIDATE_SHA, FIX_SHA
        ),
        "fix_does_not_precede_candidate": not _is_ancestor(
            repository, FIX_SHA, CANDIDATE_SHA
        ),
        "fix_is_second_parent_of_carrier": metadata["fix_carrier"]["parents"]
        == [FIX_PARENT_SHA, FIX_SHA],
        "candidate_and_fix_precede_carrier": (
            _is_ancestor(repository, CANDIDATE_SHA, FIX_CARRIER_SHA)
            and _is_ancestor(repository, FIX_SHA, FIX_CARRIER_SHA)
        ),
    }
    commit_distance_including_fix = _commit_distance(repository, CANDIDATE_SHA, FIX_SHA)
    metadata_checks = {
        "candidate_parent_is_exact": metadata["candidate"]["parents"]
        == [CANDIDATE_PARENT_SHA],
        "fix_parent_is_exact": metadata["fix"]["parents"] == [FIX_PARENT_SHA],
        "candidate_has_exact_conductor_marker": (
            metadata["candidate"]["message"] == CONDUCTOR_MARKER
            and metadata["candidate"]["explicit_claude_signal"] is True
        ),
        "fix_has_exact_conductor_marker": (
            metadata["fix"]["message"] == CONDUCTOR_MARKER
            and metadata["fix"]["explicit_claude_signal"] is True
        ),
        "carrier_freezes_explicit_fix_intent": (
            metadata["fix_carrier"]["message"] == FIX_CARRIER_MESSAGE
        ),
        "candidate_to_fix_distance_is_frozen": commit_distance_including_fix == 92,
    }

    fix_parent_stale_lines = contract["snapshots"]["fix_parent"]["sync_data_call_lines"]
    assert isinstance(fix_parent_stale_lines, list)
    stale_call_origins = [
        _blame_line(
            repository,
            FIX_PARENT_SHA,
            SOURCE_PATH,
            int(line),
            "preexisting syncData(false) call left dangling by candidate",
        )
        for line in fix_parent_stale_lines
    ]
    origin_exclusion_checks = {
        "both_stale_call_lines_are_owned_by_initial_call_author": (
            len(stale_call_origins) == 2
            and all(
                row["origin_sha"] == INITIAL_CALL_AUTHOR_SHA
                for row in stale_call_origins
            )
        ),
        "initial_line_author_snapshot_is_not_broken": contract["checks"][
            "initial_call_author_introduces_self_consistent_local_contract"
        ],
        "candidate_parent_is_still_not_broken": contract["checks"][
            "candidate_parent_retains_self_consistent_local_contract"
        ],
        "candidate_transition_is_the_frozen_contract_break": (
            contract["checks"]["candidate_replaces_local_callee_with_trait_contract"]
            and contract["checks"][
                "candidate_migrates_two_calls_but_leaves_two_old_calls"
            ]
        ),
    }

    path_blob_oids = {
        "candidate_parent": candidate_delta["before_blob_oid"],
        "candidate": candidate_delta["after_blob_oid"],
        "fix_parent": fix_delta["before_blob_oid"],
        "fix": fix_delta["after_blob_oid"],
        "carrier": carrier_first_parent_delta["after_blob_oid"],
        "candidate_trait": _path_blob_oid(repository, CANDIDATE_SHA, TRAIT_PATH),
    }
    path_topology_checks = {
        "candidate_contract_break_survives_byte_exact_to_fix_parent": (
            path_blob_oids["candidate"] == path_blob_oids["fix_parent"]
        ),
        "fix_and_carrier_have_identical_repaired_blob": (
            path_blob_oids["fix"] == path_blob_oids["carrier"]
        ),
        "candidate_parent_and_broken_blob_differ": (
            path_blob_oids["candidate_parent"] != path_blob_oids["candidate"]
        ),
        "broken_and_repaired_blob_differ": (
            path_blob_oids["fix_parent"] != path_blob_oids["fix"]
        ),
    }

    check_groups: dict[str, Mapping[str, object]] = {
        "contract": contract["checks"],
        "exact_fix_delta": exact_fix_checks,
        "metadata": metadata_checks,
        "ancestry": ancestry,
        "origin_exclusion": origin_exclusion_checks,
        "path_topology": path_topology_checks,
    }
    witness_passed = all(
        value is True for checks in check_groups.values() for value in checks.values()
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_symbol_contract_method_migration_causal_witness",
        "repository_identity": REPOSITORY_IDENTITY,
        "candidate_sha": CANDIDATE_SHA,
        "fix_sha": FIX_SHA,
        "fix_carrier_sha": FIX_CARRIER_SHA,
        "initial_call_author_sha": INITIAL_CALL_AUTHOR_SHA,
        "source_path": SOURCE_PATH,
        "trait_path": TRAIT_PATH,
        "metadata": metadata,
        "symbol_contract": contract,
        "candidate_delta": candidate_delta,
        "fix_delta": fix_delta,
        "carrier_topology": {
            "first_parent_delta": carrier_first_parent_delta,
            "second_parent_delta": carrier_second_parent_delta,
            "path_blob_oids": path_blob_oids,
        },
        "stale_call_line_origins": stale_call_origins,
        "checks": check_groups,
        "candidate_to_fix_commit_count_including_fix": commit_distance_including_fix,
        "intervening_commit_count": commit_distance_including_fix - 1,
        "confirmed_edges": [
            {
                "candidate_sha": CANDIDATE_SHA,
                "fix_sha": FIX_SHA,
                "causal_role": "DIRECT_AI_SYMBOL_CONTRACT_BREAK",
            }
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_SYMBOL_CONTRACT_BREAK",
        "mechanism_group": "edit_domain_partial_sync_method_migration",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Conductor candidate removes EditDomain's local syncData callee "
            "while migrating only two of four call sites to the replacement trait "
            "methods, leaving two executable syncData(false) calls with no local or "
            "trait definition. The broken source survives byte-for-byte to the fix "
            "parent. The later Conductor fix changes only those two calls to "
            "syncFromModel(), and its immediate PR merge carrier explicitly names "
            "that repair. Although blame assigns the old call lines to f77ad4c, "
            "that earlier snapshot and the candidate parent both define syncData "
            "and are self-consistent; line authorship is therefore not causal "
            "authorship for this method-contract break. This witness does not "
            "attribute the later wholesale SynchronizesModelData refactor, boolean "
            "casts, authorization hardening, or any security advisory impact."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        failed = [
            f"{group}.{name}"
            for group, checks in check_groups.items()
            for name, value in checks.items()
            if value is not True
        ]
        raise SystemExit(
            "Coolify symbol-contract method-migration witness failed: "
            + ", ".join(failed)
        )
    print("Coolify symbol-contract method-migration witness frozen")
    print(f"  candidate: {CANDIDATE_SHA}")
    print(f"  fix      : {FIX_SHA}")
    print(f"  carrier  : {FIX_CARRIER_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
