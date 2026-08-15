#!/usr/bin/env python3
"""Freeze the Coolify modal wire:ignore selective-revert causal witness."""

from __future__ import annotations

import argparse
import hashlib
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
PREEXISTING_WIRE_IGNORE_AUTHOR_SHA = "020cb5b3aa5950aee69ff989684bb3ffc854715c"
CANDIDATE_PARENT_SHA = "1ab4b9aa31c6ed85815527d06f100afd2c87cb9b"
CANDIDATE_SHA = "28fc3feab00d99bade5d4beeef959b8df011667e"
FIX_PARENT_SHA = CANDIDATE_SHA
FIX_SHA = "974a8bdf647c0aea240469b979856a868c0499e6"

MODAL_PATH = "resources/views/components/modal-input.blade.php"
STACK_PATH = "resources/views/livewire/project/service/stack-form.blade.php"

ISOLATED_MODAL_ROOT = 'class="relative w-auto h-auto" wire:ignore>'
UNISOLATED_MODAL_ROOT = 'class="relative w-auto h-auto">'
UNKEYED_EDIT_COMPOSE = (
    '<livewire:project.service.edit-compose serviceId="{{ $service->id }}" />'
)
KEYED_EDIT_COMPOSE = (
    "<livewire:project.service.edit-compose :key=\"'edit-compose-'.$service->id\" "
    'serviceId="{{ $service->id }}" />'
)

MODAL_STRUCTURE_MARKERS = (
    'x-data="{ modalOpen: false }"',
    "$wire.dispatch('modalClosed')",
    '<template x-teleport="body">',
    '<div x-show="modalOpen"',
    'x-trap.inert.noscroll="modalOpen"',
    "{{ $slot }}",
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8", errors="strict")


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


def _commit_distance(repository: Path, before: str, after: str) -> int:
    value = _git(
        repository,
        ["rev-list", "--count", f"{before}..{after}"],
        text=True,
    )
    assert isinstance(value, str)
    return int(value.strip())


def _unique_line_number(source: str, marker: str) -> int:
    matches = [
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if line.strip() == marker
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one exact marker {marker!r}, found {matches}")
    return matches[0]


def _modal_snapshot(source: str) -> dict[str, object]:
    stripped_lines = [line.strip() for line in source.splitlines()]
    return {
        "isolated_root_line_count": stripped_lines.count(ISOLATED_MODAL_ROOT),
        "unisolated_root_line_count": stripped_lines.count(UNISOLATED_MODAL_ROOT),
        "structure_markers": {
            marker: marker in source for marker in MODAL_STRUCTURE_MARKERS
        },
        "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def _stack_snapshot(source: str) -> dict[str, object]:
    stripped_lines = [line.strip() for line in source.splitlines()]
    return {
        "unkeyed_edit_compose_count": stripped_lines.count(UNKEYED_EDIT_COMPOSE),
        "keyed_edit_compose_count": stripped_lines.count(KEYED_EDIT_COMPOSE),
        "modal_wraps_edit_compose": (
            '<x-modal-input buttonTitle="Edit Compose File"' in source
            and "</x-modal-input>" in source
        ),
        "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def _all_modal_structure_markers_present(snapshot: Mapping[str, object]) -> bool:
    markers = snapshot.get("structure_markers")
    return isinstance(markers, Mapping) and all(
        value is True for value in markers.values()
    )


def _evaluate_contract_versions(
    candidate_parent_modal: str,
    candidate_parent_stack: str,
    candidate_modal: str,
    candidate_stack: str,
    fix_parent_modal: str,
    fix_parent_stack: str,
    fix_modal: str,
    fix_stack: str,
) -> dict[str, object]:
    snapshots = {
        "candidate_parent": {
            "modal": _modal_snapshot(candidate_parent_modal),
            "stack": _stack_snapshot(candidate_parent_stack),
        },
        "candidate": {
            "modal": _modal_snapshot(candidate_modal),
            "stack": _stack_snapshot(candidate_stack),
        },
        "fix_parent": {
            "modal": _modal_snapshot(fix_parent_modal),
            "stack": _stack_snapshot(fix_parent_stack),
        },
        "fix": {
            "modal": _modal_snapshot(fix_modal),
            "stack": _stack_snapshot(fix_stack),
        },
    }
    parent = snapshots["candidate_parent"]
    candidate = snapshots["candidate"]
    fix_parent = snapshots["fix_parent"]
    fix = snapshots["fix"]
    parent_modal = parent["modal"]
    parent_stack = parent["stack"]
    candidate_modal_snapshot = candidate["modal"]
    candidate_stack_snapshot = candidate["stack"]
    fix_modal_snapshot = fix["modal"]
    fix_stack_snapshot = fix["stack"]
    assert isinstance(parent_modal, Mapping)
    assert isinstance(parent_stack, Mapping)
    assert isinstance(candidate_modal_snapshot, Mapping)
    assert isinstance(candidate_stack_snapshot, Mapping)
    assert isinstance(fix_modal_snapshot, Mapping)
    assert isinstance(fix_stack_snapshot, Mapping)

    checks = {
        "candidate_parent_has_isolated_modal_root": (
            parent_modal.get("isolated_root_line_count") == 1
            and parent_modal.get("unisolated_root_line_count") == 0
        ),
        "candidate_parent_has_unkeyed_edit_compose_child": (
            parent_stack.get("unkeyed_edit_compose_count") == 1
            and parent_stack.get("keyed_edit_compose_count") == 0
        ),
        "candidate_removes_only_modal_root_isolation_state": (
            candidate_modal_snapshot.get("isolated_root_line_count") == 0
            and candidate_modal_snapshot.get("unisolated_root_line_count") == 1
        ),
        "candidate_adds_keyed_edit_compose_child": (
            candidate_stack_snapshot.get("unkeyed_edit_compose_count") == 0
            and candidate_stack_snapshot.get("keyed_edit_compose_count") == 1
        ),
        "alpine_teleport_modal_structure_present_in_all_states": all(
            _all_modal_structure_markers_present(state["modal"])
            for state in snapshots.values()
        ),
        "candidate_state_survives_byte_exact_to_fix_parent": (
            candidate_modal == fix_parent_modal
            and candidate_stack == fix_parent_stack
            and candidate == fix_parent
        ),
        "fix_restores_exact_candidate_parent_modal": fix_modal
        == candidate_parent_modal,
        "fix_preserves_candidate_keyed_child_byte_exact": (
            fix_stack == candidate_stack
            and fix_stack_snapshot.get("unkeyed_edit_compose_count") == 0
            and fix_stack_snapshot.get("keyed_edit_compose_count") == 1
        ),
        "fix_composes_restored_isolation_with_preserved_key": (
            fix_modal_snapshot.get("isolated_root_line_count") == 1
            and fix_modal_snapshot.get("unisolated_root_line_count") == 0
            and fix_stack_snapshot.get("keyed_edit_compose_count") == 1
        ),
    }
    return {"snapshots": snapshots, "checks": checks}


def _evaluate_exact_deltas(
    candidate_modal_delta: Mapping[str, object],
    candidate_stack_delta: Mapping[str, object],
    fix_modal_delta: Mapping[str, object],
    fix_stack_delta: Mapping[str, object],
    candidate_changed_paths: list[str],
    fix_changed_paths: list[str],
) -> dict[str, bool]:
    return {
        "candidate_changes_exactly_modal_and_stack_paths": sorted(
            candidate_changed_paths
        )
        == sorted([MODAL_PATH, STACK_PATH]),
        "candidate_modal_delta_is_exact_isolation_removal": (
            Counter(candidate_modal_delta.get("removed_lines", []))
            == Counter({ISOLATED_MODAL_ROOT: 1})
            and Counter(candidate_modal_delta.get("added_lines", []))
            == Counter({UNISOLATED_MODAL_ROOT: 1})
        ),
        "candidate_stack_delta_is_exact_key_addition": (
            Counter(candidate_stack_delta.get("removed_lines", []))
            == Counter({UNKEYED_EDIT_COMPOSE: 1})
            and Counter(candidate_stack_delta.get("added_lines", []))
            == Counter({KEYED_EDIT_COMPOSE: 1})
        ),
        "fix_changes_only_modal_path": fix_changed_paths == [MODAL_PATH],
        "fix_modal_delta_exactly_reverses_isolation_removal": (
            Counter(fix_modal_delta.get("removed_lines", []))
            == Counter({UNISOLATED_MODAL_ROOT: 1})
            and Counter(fix_modal_delta.get("added_lines", []))
            == Counter({ISOLATED_MODAL_ROOT: 1})
            and fix_modal_delta.get("before_blob_oid")
            == candidate_modal_delta.get("after_blob_oid")
            and fix_modal_delta.get("after_blob_oid")
            == candidate_modal_delta.get("before_blob_oid")
        ),
        "fix_leaves_candidate_key_addition_byte_exact": (
            fix_stack_delta.get("empty") is True
            and fix_stack_delta.get("before_blob_oid")
            == fix_stack_delta.get("after_blob_oid")
            == candidate_stack_delta.get("after_blob_oid")
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    sources = {
        label: {
            "modal": _text_blob(repository, revision, MODAL_PATH),
            "stack": _text_blob(repository, revision, STACK_PATH),
        }
        for label, revision in (
            ("candidate_parent", CANDIDATE_PARENT_SHA),
            ("candidate", CANDIDATE_SHA),
            ("fix_parent", FIX_PARENT_SHA),
            ("fix", FIX_SHA),
        )
    }
    contract = _evaluate_contract_versions(
        sources["candidate_parent"]["modal"],
        sources["candidate_parent"]["stack"],
        sources["candidate"]["modal"],
        sources["candidate"]["stack"],
        sources["fix_parent"]["modal"],
        sources["fix_parent"]["stack"],
        sources["fix"]["modal"],
        sources["fix"]["stack"],
    )

    deltas = {
        "candidate_modal": _delta_record(
            repository, CANDIDATE_PARENT_SHA, CANDIDATE_SHA, MODAL_PATH
        ),
        "candidate_stack": _delta_record(
            repository, CANDIDATE_PARENT_SHA, CANDIDATE_SHA, STACK_PATH
        ),
        "fix_modal": _delta_record(repository, FIX_PARENT_SHA, FIX_SHA, MODAL_PATH),
        "fix_stack": _delta_record(repository, FIX_PARENT_SHA, FIX_SHA, STACK_PATH),
    }
    candidate_changed_paths = _changed_paths(repository, CANDIDATE_SHA)
    fix_changed_paths = _changed_paths(repository, FIX_SHA)
    exact_delta_checks = _evaluate_exact_deltas(
        deltas["candidate_modal"],
        deltas["candidate_stack"],
        deltas["fix_modal"],
        deltas["fix_stack"],
        candidate_changed_paths,
        fix_changed_paths,
    )

    metadata = {
        "preexisting_wire_ignore_author": _commit_metadata(
            repository, PREEXISTING_WIRE_IGNORE_AUTHOR_SHA
        ),
        "candidate": _commit_metadata(repository, CANDIDATE_SHA),
        "fix": _commit_metadata(repository, FIX_SHA),
    }
    candidate_message = metadata["candidate"]["message"]
    fix_message = metadata["fix"]["message"]
    assert isinstance(candidate_message, str)
    assert isinstance(fix_message, str)
    commit_count_including_fix = _commit_distance(repository, CANDIDATE_SHA, FIX_SHA)
    metadata_checks = {
        "candidate_parent_is_exact": metadata["candidate"]["parents"]
        == [CANDIDATE_PARENT_SHA],
        "fix_parent_is_candidate_exactly": metadata["fix"]["parents"]
        == [CANDIDATE_SHA],
        "candidate_has_explicit_claude_provenance": metadata["candidate"][
            "explicit_claude_signal"
        ]
        is True,
        "candidate_message_declares_both_modal_and_key_changes": (
            candidate_message.startswith(
                "fix: remove wire:ignore from modal and add wire:key"
            )
            and "Remove wire:ignore from modal-input.blade.php wrapper"
            in candidate_message
            and "Add unique wire:key to EditCompose component" in candidate_message
        ),
        "fix_message_declares_wire_ignore_restoration": fix_message
        == "fix: add wire:ignore directive to modal component for improved functionality",
        "candidate_to_fix_distance_is_one_commit": commit_count_including_fix == 1,
        "intervening_commit_count_is_zero": commit_count_including_fix - 1 == 0,
    }
    ancestry_checks = {
        "candidate_parent_strictly_precedes_candidate": (
            CANDIDATE_PARENT_SHA != CANDIDATE_SHA
            and _is_ancestor(repository, CANDIDATE_PARENT_SHA, CANDIDATE_SHA)
        ),
        "candidate_strictly_precedes_fix": (
            CANDIDATE_SHA != FIX_SHA
            and _is_ancestor(repository, CANDIDATE_SHA, FIX_SHA)
        ),
        "fix_does_not_precede_candidate": not _is_ancestor(
            repository, FIX_SHA, CANDIDATE_SHA
        ),
    }

    parent_modal_source = sources["candidate_parent"]["modal"]
    isolated_root_line = _unique_line_number(parent_modal_source, ISOLATED_MODAL_ROOT)
    preexisting_origin = _blame_line(
        repository,
        CANDIDATE_PARENT_SHA,
        MODAL_PATH,
        isolated_root_line,
        "preexisting modal wire:ignore root removed by candidate",
    )
    origin_exclusion_checks = {
        "wire_ignore_predates_candidate": preexisting_origin["origin_sha"]
        == PREEXISTING_WIRE_IGNORE_AUTHOR_SHA,
        "candidate_is_not_preexisting_wire_ignore_author": preexisting_origin[
            "origin_sha"
        ]
        != CANDIDATE_SHA,
        "direct_fix_parent_excludes_intervening_origin": (
            metadata["fix"]["parents"] == [CANDIDATE_SHA]
            and commit_count_including_fix == 1
        ),
    }

    check_groups: dict[str, Mapping[str, object]] = {
        "contract": contract["checks"],
        "exact_deltas": exact_delta_checks,
        "metadata": metadata_checks,
        "ancestry": ancestry_checks,
        "origin_exclusion": origin_exclusion_checks,
    }
    witness_passed = all(
        value is True for checks in check_groups.values() for value in checks.values()
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_modal_wire_ignore_selective_revert_causal_witness",
        "repository_identity": REPOSITORY_IDENTITY,
        "candidate_parent_sha": CANDIDATE_PARENT_SHA,
        "candidate_sha": CANDIDATE_SHA,
        "fix_parent_sha": FIX_PARENT_SHA,
        "fix_sha": FIX_SHA,
        "source_paths": [MODAL_PATH, STACK_PATH],
        "metadata": metadata,
        "contract": contract,
        "deltas": deltas,
        "changed_paths": {
            "candidate": candidate_changed_paths,
            "fix": fix_changed_paths,
        },
        "preexisting_wire_ignore_origin": preexisting_origin,
        "candidate_to_fix_commit_count_including_fix": commit_count_including_fix,
        "intervening_commit_count": commit_count_including_fix - 1,
        "checks": check_groups,
        "confirmed_edges": [
            {
                "candidate_sha": CANDIDATE_SHA,
                "fix_sha": FIX_SHA,
                "causal_role": "DIRECT_AI_MODAL_ISOLATION_REGRESSION",
            }
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_MODAL_ISOLATION_REGRESSION",
        "mechanism_group": "modal_wire_ignore_isolation_removal",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The explicit-Claude candidate removes the preexisting wire:ignore "
            "attribute from the root of an Alpine-controlled, body-teleported modal "
            "while independently adding a wire:key to its EditCompose child. Its "
            "immediate child fix restores exactly the prior modal blob and changes "
            "no other path, while preserving the candidate's keyed child blob. The "
            "candidate state is therefore the exact fix-parent state, with zero "
            "intervening commits or alternative intervening origin. This establishes "
            "a direct code-level selective correction of the candidate's modal "
            "isolation removal. It does not prove the candidate message's specific "
            "browser error, whether the preserved wire:key was necessary, runtime "
            "impact under every Livewire/Alpine interaction, security impact, or an "
            "advisory-level increment."
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
            "Coolify modal wire:ignore causal witness failed: " + ", ".join(failed)
        )
    print("Coolify modal wire:ignore causal witness frozen")
    print(f"  candidate: {CANDIDATE_SHA}")
    print(f"  fix      : {FIX_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
