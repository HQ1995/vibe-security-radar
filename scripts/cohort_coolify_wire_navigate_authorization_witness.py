#!/usr/bin/env python3
"""Freeze the Coolify AI wire-navigate authorization path witness."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


AI_PATH_EXTENSION_SHA = "e709e2c131aeebb9a1121437ce5e1ec4c2fc2f0b"
SECURITY_REPAIR_SHA = "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e"
COMPONENT_PATH = "app/Livewire/Settings/Advanced.php"
MODEL_PATH = "app/Models/InstanceSettings.php"
VIEW_PATH = "resources/views/livewire/settings/advanced.blade.php"
MIGRATION_PATH = (
    "database/migrations/"
    "2025_12_17_000001_add_is_wire_navigate_enabled_to_instance_settings_table.php"
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_record(
    repository: Path, revision: str, source_path: str
) -> dict[str, str]:
    blob = _git_blob(repository, revision, source_path)
    return {
        "revision": revision,
        "path": source_path,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _nth_line(source: str, marker: str, occurrence: int = 1) -> int:
    matches = [
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if occurrence < 1 or len(matches) < occurrence:
        raise SystemExit(
            f"expected marker {marker!r} occurrence {occurrence}, found {matches}"
        )
    return matches[occurrence - 1]


def _evaluate_versions(
    baseline_component: str,
    baseline_model: str,
    baseline_view: str,
    candidate_component: str,
    candidate_model: str,
    candidate_view: str,
    candidate_migration: str,
    repair_component: str,
) -> dict[str, bool]:
    candidate_instant_save = _php_method_region(candidate_component, "instantSave")
    repair_instant_save = _php_method_region(repair_component, "instantSave")
    field = "is_wire_navigate_enabled"
    return {
        "baseline_has_no_wire_navigate_state_path": all(
            field not in source
            for source in (baseline_component, baseline_model, baseline_view)
        ),
        "candidate_adds_public_boolean_state": (
            "public bool $is_wire_navigate_enabled;" in candidate_component
            and "'is_wire_navigate_enabled' => 'boolean'" in candidate_component
        ),
        "candidate_loads_instance_setting": (
            "$this->is_wire_navigate_enabled = "
            "$this->settings->is_wire_navigate_enabled ?? true;"
            in candidate_component
        ),
        "candidate_adds_instant_save_ui_action": (
            '<x-forms.checkbox instantSave id="is_wire_navigate_enabled"'
            in candidate_view
        ),
        "candidate_persists_new_state_in_public_action": all(
            marker in candidate_instant_save
            for marker in (
                "public function instantSave()",
                "$this->settings->is_wire_navigate_enabled = "
                "$this->is_wire_navigate_enabled;",
                "$this->settings->save();",
            )
        ),
        "candidate_public_action_has_no_method_authorization": (
            "$this->authorize(" not in candidate_instant_save
        ),
        "candidate_relies_on_mount_time_admin_redirect": all(
            marker in _php_method_region(candidate_component, "mount")
            for marker in (
                "if (! isInstanceAdmin())",
                "return redirect()->route('dashboard');",
            )
        ),
        "candidate_adds_model_cast": (
            "'is_wire_navigate_enabled' => 'boolean'" in candidate_model
        ),
        "candidate_adds_persistent_default": (
            "$table->boolean('is_wire_navigate_enabled')->default(true);"
            in candidate_migration
        ),
        "repair_adds_method_level_authorization": (
            "$this->authorize('update', $this->settings);" in repair_instant_save
        ),
        "repair_preserves_and_guards_same_sink": all(
            marker in repair_instant_save
            for marker in (
                "$this->settings->is_wire_navigate_enabled = "
                "$this->is_wire_navigate_enabled;",
                "$this->settings->save();",
            )
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_revision = f"{AI_PATH_EXTENSION_SHA}^"
    baseline_component = _text_blob(repository, baseline_revision, COMPONENT_PATH)
    baseline_model = _text_blob(repository, baseline_revision, MODEL_PATH)
    baseline_view = _text_blob(repository, baseline_revision, VIEW_PATH)
    candidate_component = _text_blob(repository, AI_PATH_EXTENSION_SHA, COMPONENT_PATH)
    candidate_model = _text_blob(repository, AI_PATH_EXTENSION_SHA, MODEL_PATH)
    candidate_view = _text_blob(repository, AI_PATH_EXTENSION_SHA, VIEW_PATH)
    candidate_migration = _text_blob(
        repository, AI_PATH_EXTENSION_SHA, MIGRATION_PATH
    )
    repair_component = _text_blob(repository, SECURITY_REPAIR_SHA, COMPONENT_PATH)

    evaluation = _evaluate_versions(
        baseline_component,
        baseline_model,
        baseline_view,
        candidate_component,
        candidate_model,
        candidate_view,
        candidate_migration,
        repair_component,
    )
    candidate_metadata = _commit_metadata(repository, AI_PATH_EXTENSION_SHA)
    repair_metadata = _commit_metadata(repository, SECURITY_REPAIR_SHA)
    ancestry = {
        "candidate_parent_to_candidate": _is_ancestor(
            repository, baseline_revision, AI_PATH_EXTENSION_SHA
        ),
        "candidate_to_repair": _is_ancestor(
            repository, AI_PATH_EXTENSION_SHA, SECURITY_REPAIR_SHA
        ),
    }

    line_specs = {
        "candidate_public_state": (
            AI_PATH_EXTENSION_SHA,
            COMPONENT_PATH,
            candidate_component,
            "public bool $is_wire_navigate_enabled;",
            "AI public wire-navigate state",
        ),
        "candidate_state_sink": (
            AI_PATH_EXTENSION_SHA,
            COMPONENT_PATH,
            candidate_component,
            "$this->settings->is_wire_navigate_enabled = ",
            "AI instance-setting persistence sink",
        ),
        "candidate_ui_action": (
            AI_PATH_EXTENSION_SHA,
            VIEW_PATH,
            candidate_view,
            '<x-forms.checkbox instantSave id="is_wire_navigate_enabled"',
            "AI instant-save UI action",
        ),
        "repair_method_authorization": (
            SECURITY_REPAIR_SHA,
            COMPONENT_PATH,
            repair_component,
            "$this->authorize('update', $this->settings);",
            "follow-up method-level authorization",
        ),
    }
    line_origins = {
        key: _blame_line(
            repository,
            revision,
            source_path,
            _nth_line(source, marker),
            label,
        )
        for key, (
            revision,
            source_path,
            source,
            marker,
            label,
        ) in line_specs.items()
    }
    expected_origins = {
        "candidate_public_state": AI_PATH_EXTENSION_SHA,
        "candidate_state_sink": AI_PATH_EXTENSION_SHA,
        "candidate_ui_action": AI_PATH_EXTENSION_SHA,
        "repair_method_authorization": SECURITY_REPAIR_SHA,
    }

    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"]
        == [_commit_metadata(repository, baseline_revision)["sha"]]
        and "wire:navigate" in str(candidate_metadata["message"])
        and "enforce team member authorization" in str(repair_metadata["message"])
        and all(ancestry.values())
        and all(evaluation.values())
        and all(
            line_origins[key]["origin_sha"] == expected
            for key, expected in expected_origins.items()
        )
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_wire_navigate_authorization_path_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_PATH_EXTENSION_SHA,
        "fix_sha": SECURITY_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, baseline_revision, COMPONENT_PATH),
            _blob_record(repository, baseline_revision, MODEL_PATH),
            _blob_record(repository, baseline_revision, VIEW_PATH),
            _blob_record(repository, AI_PATH_EXTENSION_SHA, COMPONENT_PATH),
            _blob_record(repository, AI_PATH_EXTENSION_SHA, MODEL_PATH),
            _blob_record(repository, AI_PATH_EXTENSION_SHA, VIEW_PATH),
            _blob_record(repository, AI_PATH_EXTENSION_SHA, MIGRATION_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, COMPONENT_PATH),
        ],
        "confirmed_edge": {
            "adjudication": "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_EXTENSION",
            "candidate_sha": AI_PATH_EXTENSION_SHA,
            "fix_sha": SECURITY_REPAIR_SHA,
            "mechanism_group": "instance_wire_navigate_setting_authorization",
        },
        "claim_boundary": (
            "The AI commit directly added a persistent instance-wide setting, a public "
            "Livewire state property, an instant-save UI trigger, and a write in the "
            "unguarded public instantSave action. The later security commit retained "
            "that sink and added method-level update authorization. This is a vulnerable "
            "path-extension claim, not a claim that the AI commit originated the older "
            "authorization gap or that a runtime exploit was reproduced."
        ),
        "witness_passed": witness_passed,
    }
    _atomic_json(args.output, payload)
    print("Coolify wire-navigate authorization witness frozen")
    print(f"  witness passed : {witness_passed}")
    print(f"  output         : {args.output}")
    return 0 if witness_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
