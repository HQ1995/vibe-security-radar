#!/usr/bin/env python3
"""Freeze the Coolify activity-monitor target/key causal witness."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
)


REPOSITORY_IDENTITY = "github.com/coollabsio/coolify"
CANDIDATE_PARENT_SHA = "6cb3e4d51570ed63198263c7fe86a0c0b1d11377"
CANDIDATE_SHA = "a5dafe785b1487197bbbbede2c3dee7bf5886393"
PATCH_EQUIVALENT_ALIAS_PARENT_SHA = "cd236689462714bd99ccd2b6a836019c44e5f733"
PATCH_EQUIVALENT_ALIAS_SHA = "d07cc48369ac4beb0405823bf34aad02200e4a6f"
FIX_SHA = "226de3514606192c1d6cc66326033dc20ae8f2c4"
LATER_ROOT_CAUSE_SHA = "f2a017a0636ade05626b20f5357fe520a3b1bc0c"

IMPORT_PATH = "app/Livewire/Project/Database/Import.php"
VIEW_PATH = "resources/views/livewire/project/database/import.blade.php"
MONITOR_PATH = "app/Livewire/ActivityMonitor.php"
COMPOSER_LOCK_PATH = "composer.lock"

MONITOR_COMPONENT_NAME = "activity-monitor"
S3_KEY = "s3-download-monitor"
DATABASE_KEY = "database-restore-monitor"
CLAIM_BOUNDARY = (
    "The witness counts only the AI candidate's event-routing regression: it "
    "used two Livewire instance keys as component-name targets, so neither "
    "target named the rendered activity-monitor component. The immediate fix "
    "exactly restores the two affected blobs, and a later root-cause commit "
    "freezes the correct contract as broadcast dispatch plus instance keys and "
    "one rendered monitor at a time. It does not claim that the immediate "
    "revert alone solved the pre-existing duplicate-output problem."
)


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
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _diff_record(
    repository: Path,
    parent: str,
    revision: str,
    paths: list[str],
) -> dict[str, object]:
    raw = _git(
        repository,
        [
            "diff",
            "--no-ext-diff",
            "--full-index",
            "--no-color",
            parent,
            revision,
            "--",
            *paths,
        ],
    )
    assert isinstance(raw, bytes)
    return {
        "parent": parent,
        "revision": revision,
        "paths": paths,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "byte_count": len(raw),
    }


def _activity_dispatches(source: str) -> list[dict[str, str | None]]:
    rows: list[dict[str, str | None]] = []
    for line in source.splitlines():
        if "$this->dispatch('activityMonitor'" not in line:
            continue
        target_match = re.search(r"->to\('([^']+)'\)", line)
        rows.append(
            {
                "line": line.strip(),
                "target": target_match.group(1) if target_match else None,
            }
        )
    return rows


def _monitor_instances(view: str) -> list[dict[str, str | None]]:
    rows: list[dict[str, str | None]] = []
    for match in re.finditer(
        r"<livewire:([a-z0-9_.:-]+)\b(?P<attrs>.*?)/>",
        view,
        flags=re.DOTALL,
    ):
        if match.group(1) != MONITOR_COMPONENT_NAME:
            continue
        attrs = match.group("attrs")
        key_match = re.search(r'\b(?:wire:)?key="([^"]+)"', attrs)
        rows.append(
            {
                "component_name": match.group(1),
                "instance_key": key_match.group(1) if key_match else None,
            }
        )
    return rows


def _static_delivery_matrix(source: str, view: str) -> list[dict[str, object]]:
    component_names = {row["component_name"] for row in _monitor_instances(view)}
    rows: list[dict[str, object]] = []
    for dispatch in _activity_dispatches(source):
        target = dispatch["target"]
        rows.append(
            {
                "target": target,
                "matching_rendered_component_name_count": (
                    len(component_names)
                    if target is None
                    else int(target in component_names)
                ),
            }
        )
    return rows


def _evaluate_parent(source: str, view: str) -> dict[str, bool]:
    dispatches = _activity_dispatches(source)
    instances = _monitor_instances(view)
    return {
        "three_activity_dispatches_preexist": len(dispatches) == 3,
        "all_parent_dispatches_are_broadcast": all(
            row["target"] is None for row in dispatches
        ),
        "two_activity_monitor_instances_preexist": len(instances) == 2,
        "parent_instances_have_no_keys": all(
            row["instance_key"] is None for row in instances
        ),
    }


def _evaluate_candidate(source: str, view: str, monitor: str) -> dict[str, bool]:
    dispatches = _activity_dispatches(source)
    instances = _monitor_instances(view)
    targets = [row["target"] for row in dispatches]
    instance_keys = {row["instance_key"] for row in instances}
    delivery = _static_delivery_matrix(source, view)
    return {
        "candidate_targets_all_three_dispatches": len(dispatches) == 3
        and all(target is not None for target in targets),
        "candidate_targets_are_exactly_instance_keys": set(targets)
        == {S3_KEY, DATABASE_KEY}
        == instance_keys,
        "rendered_component_name_remains_activity_monitor": len(instances) == 2
        and all(row["component_name"] == MONITOR_COMPONENT_NAME for row in instances),
        "instance_keys_do_not_name_rendered_component": all(
            target != MONITOR_COMPONENT_NAME for target in targets
        ),
        "static_target_resolution_finds_no_component_name": len(delivery) == 3
        and all(row["matching_rendered_component_name_count"] == 0 for row in delivery),
        "activity_monitor_still_listens_for_broadcast_event": (
            "protected $listeners = ['activityMonitor' => 'newMonitorActivity'];"
            in monitor
        ),
    }


def _evaluate_fix(
    parent_source: str,
    parent_view: str,
    fix_source: str,
    fix_view: str,
) -> dict[str, bool]:
    dispatches = _activity_dispatches(fix_source)
    return {
        "fix_exactly_restores_parent_import_blob": fix_source == parent_source,
        "fix_exactly_restores_parent_view_blob": fix_view == parent_view,
        "fix_removes_all_instance_key_targets": len(dispatches) == 3
        and all(row["target"] is None for row in dispatches),
    }


def _evaluate_later_root_cause(
    message: str,
    source: str,
    view: str,
) -> dict[str, bool]:
    dispatches = _activity_dispatches(source)
    return {
        "later_message_names_dispatch_listener_contract": all(
            fragment in message
            for fragment in (
                "Original approach was correct: use dispatch + event listeners",
                "Use @if conditionals to render only one monitor at a time",
                "unique wire:key per monitor",
            )
        ),
        "later_source_uses_only_broadcast_dispatch": len(dispatches) >= 2
        and all(row["target"] is None for row in dispatches),
        "later_view_uses_unique_instance_keys": all(
            marker in view
            for marker in (
                'wire:key="s3-download-{{ $resource->uuid }}"',
                'wire:key="database-restore-{{ $resource->uuid }}"',
            )
        ),
        "later_view_renders_monitors_conditionally": (
            "@if ($s3DownloadInProgress)" in view and "@if ($importRunning)" in view
        ),
    }


def _livewire_dependency(composer_lock: str) -> dict[str, object]:
    payload = json.loads(composer_lock)
    packages = [
        row
        for row in payload.get("packages", [])
        if row.get("name") == "livewire/livewire"
    ]
    if len(packages) != 1:
        raise SystemExit(
            f"expected one livewire/livewire package, found {len(packages)}"
        )
    package = packages[0]
    return {
        "name": package.get("name"),
        "version": package.get("version"),
        "source_reference": package.get("source", {}).get("reference"),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    parent_source = _text_blob(repository, CANDIDATE_PARENT_SHA, IMPORT_PATH)
    parent_view = _text_blob(repository, CANDIDATE_PARENT_SHA, VIEW_PATH)
    candidate_source = _text_blob(repository, CANDIDATE_SHA, IMPORT_PATH)
    candidate_view = _text_blob(repository, CANDIDATE_SHA, VIEW_PATH)
    candidate_monitor = _text_blob(repository, CANDIDATE_SHA, MONITOR_PATH)
    fix_source = _text_blob(repository, FIX_SHA, IMPORT_PATH)
    fix_view = _text_blob(repository, FIX_SHA, VIEW_PATH)
    later_source = _text_blob(repository, LATER_ROOT_CAUSE_SHA, IMPORT_PATH)
    later_view = _text_blob(repository, LATER_ROOT_CAUSE_SHA, VIEW_PATH)

    metadata = {
        "candidate_parent": _commit_metadata(repository, CANDIDATE_PARENT_SHA),
        "candidate": _commit_metadata(repository, CANDIDATE_SHA),
        "patch_equivalent_alias_parent": _commit_metadata(
            repository, PATCH_EQUIVALENT_ALIAS_PARENT_SHA
        ),
        "patch_equivalent_alias": _commit_metadata(
            repository, PATCH_EQUIVALENT_ALIAS_SHA
        ),
        "fix": _commit_metadata(repository, FIX_SHA),
        "later_root_cause": _commit_metadata(repository, LATER_ROOT_CAUSE_SHA),
    }
    ancestry = {
        "candidate_parent_is_immediate_parent": metadata["candidate"]["parents"]
        == [CANDIDATE_PARENT_SHA],
        "candidate_is_immediate_fix_parent": metadata["fix"]["parents"]
        == [CANDIDATE_SHA],
        "candidate_strictly_precedes_fix": _is_ancestor(
            repository, CANDIDATE_SHA, FIX_SHA
        ),
        "candidate_strictly_precedes_later_root_cause": _is_ancestor(
            repository, CANDIDATE_SHA, LATER_ROOT_CAUSE_SHA
        ),
        "parallel_alias_does_not_precede_fix": not _is_ancestor(
            repository, PATCH_EQUIVALENT_ALIAS_SHA, FIX_SHA
        ),
    }
    evaluations = {
        "candidate_parent": _evaluate_parent(parent_source, parent_view),
        "candidate": _evaluate_candidate(
            candidate_source, candidate_view, candidate_monitor
        ),
        "fix": _evaluate_fix(parent_source, parent_view, fix_source, fix_view),
        "later_root_cause": _evaluate_later_root_cause(
            str(metadata["later_root_cause"]["message"]),
            later_source,
            later_view,
        ),
    }
    alias_equivalence = {
        "alias_parent_import_equals_candidate_parent": _text_blob(
            repository, PATCH_EQUIVALENT_ALIAS_PARENT_SHA, IMPORT_PATH
        )
        == parent_source,
        "alias_parent_view_equals_candidate_parent": _text_blob(
            repository, PATCH_EQUIVALENT_ALIAS_PARENT_SHA, VIEW_PATH
        )
        == parent_view,
        "alias_import_equals_candidate": _text_blob(
            repository, PATCH_EQUIVALENT_ALIAS_SHA, IMPORT_PATH
        )
        == candidate_source,
        "alias_view_equals_candidate": _text_blob(
            repository, PATCH_EQUIVALENT_ALIAS_SHA, VIEW_PATH
        )
        == candidate_view,
    }
    candidate_metadata = metadata["candidate"]
    witness_passed = (
        candidate_metadata["explicit_claude_signal"] is True
        and all(ancestry.values())
        and all(all(section.values()) for section in evaluations.values())
        and all(alias_equivalence.values())
    )

    revisions = [
        CANDIDATE_PARENT_SHA,
        CANDIDATE_SHA,
        FIX_SHA,
        LATER_ROOT_CAUSE_SHA,
    ]
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_activity_monitor_target_key_causal_witness",
        "repository_identity": REPOSITORY_IDENTITY,
        "candidate_sha": CANDIDATE_SHA,
        "fix_sha": FIX_SHA,
        "metadata": metadata,
        "ancestry": ancestry,
        "evaluations": evaluations,
        "alias_equivalence": alias_equivalence,
        "static_delivery_matrix": {
            "candidate": _static_delivery_matrix(candidate_source, candidate_view),
            "fix": _static_delivery_matrix(fix_source, fix_view),
        },
        "livewire_dependency": _livewire_dependency(
            _text_blob(repository, CANDIDATE_SHA, COMPOSER_LOCK_PATH)
        ),
        "source_blobs": [
            _blob_record(repository, revision, path)
            for revision in revisions
            for path in (IMPORT_PATH, VIEW_PATH)
        ]
        + [_blob_record(repository, CANDIDATE_SHA, MONITOR_PATH)],
        "diffs": [
            _diff_record(
                repository,
                CANDIDATE_PARENT_SHA,
                CANDIDATE_SHA,
                [IMPORT_PATH, VIEW_PATH],
            ),
            _diff_record(
                repository,
                CANDIDATE_SHA,
                FIX_SHA,
                [IMPORT_PATH, VIEW_PATH],
            ),
        ],
        "confirmed_edges": [
            {
                "candidate_sha": CANDIDATE_SHA,
                "fix_sha": FIX_SHA,
                "causal_role": "DIRECT_AI_EVENT_TARGET_REGRESSION",
            }
        ],
        "non_counted_related_commits": [
            {
                "sha": PATCH_EQUIVALENT_ALIAS_SHA,
                "reason": (
                    "parallel patch-equivalent alias; it is not on the fix's "
                    "ancestry path and contributes no independent count"
                ),
            },
            {
                "sha": LATER_ROOT_CAUSE_SHA,
                "reason": (
                    "later corroborating root-cause repair in the same workflow, "
                    "not a second origin for this edge"
                ),
            },
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_EVENT_TARGET_ALIAS_REGRESSION",
        "mechanism_group": (
            "activity_monitor_dispatch_targets_instance_key_as_component_name"
        ),
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "patch_equivalent_alias_increment": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify activity-monitor target/key witness failed")
    print("Coolify activity-monitor target/key causal witness frozen")
    print(f"  candidate: {CANDIDATE_SHA}")
    print(f"  repair   : {FIX_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
