#!/usr/bin/env python3
"""Freeze three deterministic Coolify deployment-rollback causal witnesses."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _is_ancestor,
)


CANDIDATE_SHA = "885fb20445c48eb3ba0f6ff3905d5a0e1d5cc681"
IMAGE_IDENTITY_FIX_SHA = "bb6dfe9f8c3a8d32b447f93845d647f52d8297c1"
SYMLINK_FIX_SHA = "b227619cbf010954a99375405fbcc7a06132746e"
HISTORICAL_ENV_FIX_SHA = "45f931ecc8bc0979bc67925744f8b35076c5fc72"

SNAPSHOT_PATH = "app/Actions/Application/SaveDeploymentSnapshot.php"
JOB_PATH = "app/Jobs/ApplicationDeploymentJob.php"
ROLLBACK_PATH = "app/Livewire/Project/Application/Rollback.php"

IMAGE_MECHANISM = "rollback_image_tag_omits_build_config_hash"
SYMLINK_MECHANISM = "rollback_snapshot_legacy_env_symlink_overwrite"
HISTORICAL_ENV_MECHANISM = "rollback_rebuild_missing_historical_environment_snapshot"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--exact-overlap-dir", type=Path, required=True)
    parser.add_argument("--delta-bridge-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_jsonl(source_path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with source_path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(
                        f"{source_path}:{line_number} is not a JSON object"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load {source_path}: {exc}") from exc
    return rows


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_file(source_path: Path) -> str:
    return _sha256_bytes(source_path.read_bytes())


def _git_text(repository: Path, arguments: Sequence[str]) -> str:
    value = _git(repository, list(arguments), text=True)
    assert isinstance(value, str)
    return value


def _git_bytes(repository: Path, arguments: Sequence[str]) -> bytes:
    value = _git(repository, list(arguments))
    assert isinstance(value, bytes)
    return value


def _first_parent(repository: Path, revision: str) -> str:
    return _git_text(repository, ("rev-parse", f"{revision}^1")).strip()


def _path_exists(repository: Path, revision: str, source_path: str) -> bool:
    return bool(
        _git_text(
            repository,
            ("ls-tree", "--name-only", revision, "--", source_path),
        ).strip()
    )


def _blob(repository: Path, revision: str, source_path: str) -> str:
    if not _path_exists(repository, revision, source_path):
        raise ValueError(f"missing Git path: {revision}:{source_path}")
    return _git_text(repository, ("show", f"{revision}:{source_path}"))


def _blob_record(
    repository: Path, revision: str, source_path: str
) -> dict[str, object]:
    content = _git_bytes(repository, ("show", f"{revision}:{source_path}"))
    object_id = _git_text(
        repository, ("rev-parse", f"{revision}:{source_path}")
    ).strip()
    return {
        "revision": revision,
        "path": source_path,
        "git_blob_oid": object_id,
        "byte_count": len(content),
        "sha256": _sha256_bytes(content),
    }


def _diff(
    repository: Path,
    before: str,
    after: str,
    source_paths: Sequence[str],
) -> bytes:
    return _git_bytes(
        repository,
        (
            "diff",
            "--full-index",
            "--no-color",
            "--no-ext-diff",
            "--no-renames",
            before,
            after,
            "--",
            *source_paths,
        ),
    )


def _diff_record(
    repository: Path,
    before: str,
    after: str,
    source_paths: Sequence[str],
) -> dict[str, object]:
    value = _diff(repository, before, after, source_paths)
    return {
        "before_revision": before,
        "after_revision": after,
        "paths": list(source_paths),
        "byte_count": len(value),
        "sha256": _sha256_bytes(value),
    }


def _contains_all(value: str, fragments: Sequence[str]) -> bool:
    return all(fragment in value for fragment in fragments)


def _contains_none(value: str, fragments: Sequence[str]) -> bool:
    return all(fragment not in value for fragment in fragments)


def _single_sha_row(
    rows: Sequence[Mapping[str, object]], sha: str
) -> Mapping[str, object]:
    matches = [row for row in rows if row.get("sha") == sha]
    if len(matches) != 1:
        raise ValueError(f"{sha} resolved to {len(matches)} AI rows")
    return matches[0]


def _single_edge_row(
    rows: Sequence[Mapping[str, object]], candidate_sha: str, fix_sha: str
) -> Mapping[str, object]:
    matches = [
        row
        for row in rows
        if row.get("candidate_sha") == candidate_sha and row.get("fix_sha") == fix_sha
    ]
    if len(matches) != 1:
        raise ValueError(
            f"{candidate_sha}:{fix_sha} resolved to {len(matches)} edge rows"
        )
    return matches[0]


def _image_identity_semantics() -> dict[str, object]:
    commit = "a" * 40
    first_config_hash = "1" * 32
    second_config_hash = "2" * 32
    candidate_first = commit[:128]
    candidate_second = commit[:128]
    fixed_first = f"{commit[:119]}-{first_config_hash[:8]}"
    fixed_second = f"{commit[:119]}-{second_config_hash[:8]}"
    checks = {
        "same_commit_different_configs_collide_before_fix": (
            candidate_first == candidate_second
        ),
        "same_commit_different_configs_are_distinct_after_fix": (
            fixed_first != fixed_second
        ),
        "fixed_tags_bind_expected_config_hash_prefix": (
            fixed_first.endswith(first_config_hash[:8])
            and fixed_second.endswith(second_config_hash[:8])
        ),
    }
    return {
        "inputs": {
            "commit_sha256": _sha256_text(commit),
            "first_config_sha256": _sha256_text(first_config_hash),
            "second_config_sha256": _sha256_text(second_config_hash),
        },
        "candidate_tags": [candidate_first, candidate_second],
        "fixed_tags": [fixed_first, fixed_second],
        "checks": checks,
        "passed": all(checks.values()),
    }


def _simulate_legacy_env_symlink(base_directory: Path) -> dict[str, object]:
    application_dir = base_directory / "application"
    deployment_dir = application_dir / "deployments" / "deployment-one"
    deployment_dir.mkdir(parents=True)
    snapshot_env = deployment_dir / ".env"
    snapshot_env.write_text("SNAPSHOT=old\n", encoding="utf-8")

    current_link = application_dir / "current"
    current_link.symlink_to(deployment_dir, target_is_directory=True)
    legacy_env = application_dir / ".env"
    legacy_env.symlink_to(current_link / ".env")

    legacy_env.write_text("SNAPSHOT=next\n", encoding="utf-8")
    candidate_snapshot_value = snapshot_env.read_text(encoding="utf-8")
    candidate_legacy_is_symlink = legacy_env.is_symlink()

    legacy_env.unlink()
    snapshot_env.write_text("SNAPSHOT=old\n", encoding="utf-8")
    legacy_env.symlink_to(current_link / ".env")
    legacy_env.unlink()
    legacy_env.write_text("SNAPSHOT=next\n", encoding="utf-8")
    fixed_snapshot_value = snapshot_env.read_text(encoding="utf-8")
    fixed_legacy_value = legacy_env.read_text(encoding="utf-8")

    checks = {
        "candidate_writer_follows_legacy_symlink_into_old_snapshot": (
            candidate_snapshot_value == "SNAPSHOT=next\n"
            and candidate_legacy_is_symlink
        ),
        "unlink_before_write_preserves_old_snapshot": (
            fixed_snapshot_value == "SNAPSHOT=old\n"
        ),
        "unlink_before_write_creates_new_regular_legacy_env": (
            fixed_legacy_value == "SNAPSHOT=next\n" and not legacy_env.is_symlink()
        ),
    }
    return {
        "candidate_snapshot_after_write_sha256": _sha256_text(candidate_snapshot_value),
        "fixed_snapshot_after_write_sha256": _sha256_text(fixed_snapshot_value),
        "fixed_legacy_env_sha256": _sha256_text(fixed_legacy_value),
        "checks": checks,
        "passed": all(checks.values()),
    }


def _legacy_env_symlink_semantics() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="coolify-rollback-witness-") as raw:
        return _simulate_legacy_env_symlink(Path(raw))


def _historical_environment_semantics() -> dict[str, object]:
    historical_environment = {
        "APP_MODE": "historical",
        "BUILD_TOKEN": "old-build-token",
    }
    current_environment = {
        "APP_MODE": "current",
        "BUILD_TOKEN": "new-build-token",
    }
    candidate_queue = {
        "commit": "a" * 40,
        "rollback": True,
        "force_rebuild": True,
    }
    candidate_metadata = {"commit": "a" * 40}
    candidate_selected = current_environment

    fixed_queue = {
        **candidate_queue,
        "rollback_deployment_uuid": "deployment-one",
    }
    fixed_metadata = {
        **candidate_metadata,
        "build_environment_variables": historical_environment,
        "runtime_environment_variables": historical_environment,
    }
    fixed_selected = fixed_metadata["build_environment_variables"]
    checks = {
        "historical_and_current_environments_are_distinct": (
            historical_environment != current_environment
        ),
        "candidate_rebuild_has_no_snapshot_identity": (
            "rollback_deployment_uuid" not in candidate_queue
        ),
        "candidate_metadata_has_no_historical_environment": (
            "build_environment_variables" not in candidate_metadata
            and "runtime_environment_variables" not in candidate_metadata
        ),
        "candidate_rebuild_falls_through_to_current_environment": (
            candidate_selected == current_environment
            and candidate_selected != historical_environment
        ),
        "fixed_rebuild_binds_snapshot_identity": (
            fixed_queue["rollback_deployment_uuid"] == "deployment-one"
        ),
        "fixed_rebuild_selects_historical_environment": (
            fixed_selected == historical_environment
            and fixed_selected != current_environment
        ),
    }
    return {
        "historical_environment_sha256": _sha256_text(
            json.dumps(historical_environment, sort_keys=True)
        ),
        "current_environment_sha256": _sha256_text(
            json.dumps(current_environment, sort_keys=True)
        ),
        "candidate_queue_fields": sorted(candidate_queue),
        "fixed_queue_fields": sorted(fixed_queue),
        "checks": checks,
        "passed": all(checks.values()),
    }


def _candidate_ai_checks(ai_row: Mapping[str, object]) -> dict[str, bool]:
    source_modules = ai_row.get("source_modules")
    message = str(ai_row.get("message") or "")
    return {
        "candidate_is_in_frozen_ai_scan": ai_row.get("sha") == CANDIDATE_SHA,
        "candidate_has_coauthor_trailer_source": (
            isinstance(source_modules, list) and "coauthor_trailer" in source_modules
        ),
        "candidate_message_has_claude_code_marker": (
            "Generated with [Claude Code]" in message
        ),
        "candidate_message_has_anthropic_coauthor": (
            "Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>" in message
        ),
    }


def _image_identity_case(
    repository: Path,
    *,
    ai_checks: Mapping[str, bool],
    overlap_row: Mapping[str, object],
) -> dict[str, object]:
    candidate_parent = _first_parent(repository, CANDIDATE_SHA)
    fix_parent = _first_parent(repository, IMAGE_IDENTITY_FIX_SHA)
    candidate_snapshot = _blob(repository, CANDIDATE_SHA, SNAPSHOT_PATH)
    candidate_job = _blob(repository, CANDIDATE_SHA, JOB_PATH)
    candidate_rollback = _blob(repository, CANDIDATE_SHA, ROLLBACK_PATH)
    pre_fix_snapshot = _blob(repository, fix_parent, SNAPSHOT_PATH)
    pre_fix_job = _blob(repository, fix_parent, JOB_PATH)
    fixed_snapshot = _blob(repository, IMAGE_IDENTITY_FIX_SHA, SNAPSHOT_PATH)
    fixed_job = _blob(repository, IMAGE_IDENTITY_FIX_SHA, JOB_PATH)
    fixed_rollback = _blob(repository, IMAGE_IDENTITY_FIX_SHA, ROLLBACK_PATH)
    candidate_patch = _diff(
        repository,
        candidate_parent,
        CANDIDATE_SHA,
        (SNAPSHOT_PATH, JOB_PATH, ROLLBACK_PATH),
    ).decode("utf-8", errors="strict")
    fix_patch = _diff(
        repository,
        fix_parent,
        IMAGE_IDENTITY_FIX_SHA,
        (SNAPSHOT_PATH, JOB_PATH, ROLLBACK_PATH),
    ).decode("utf-8", errors="strict")
    semantics = _image_identity_semantics()
    checks = {
        **ai_checks,
        "edge_is_in_frozen_exact_overlap": overlap_row.get("retained") is True,
        "edge_is_exact_production_overlap": (
            overlap_row.get("pair_class") == "exact_production_overlap"
        ),
        "candidate_is_direct_parent_of_fix": (
            fix_parent == CANDIDATE_SHA
            and overlap_row.get("candidate_is_direct_parent_of_fix") is True
        ),
        "candidate_is_ancestor_of_fix": _is_ancestor(
            repository, CANDIDATE_SHA, IMAGE_IDENTITY_FIX_SHA
        ),
        "candidate_parent_lacks_snapshot_action": not _path_exists(
            repository, candidate_parent, SNAPSHOT_PATH
        ),
        "candidate_adds_commit_only_snapshot_identity": _contains_all(
            candidate_patch,
            (
                "class SaveDeploymentSnapshot",
                "$imageName = $application->docker_registry_image_name",
                '"{$application->uuid}:{$deployment->commit}"',
                "docker images -q {$imageName}",
            ),
        ),
        "candidate_state_uses_commit_only_tag_and_metadata": (
            _contains_all(
                candidate_snapshot,
                (
                    "$imageName = $application->docker_registry_image_name",
                    "'image_name' => $imageName",
                ),
            )
            and "$this->dockerImageTag = str($this->commit)->substr(0, 128);"
            in candidate_job
            and "docker images -q {$imageName}" in candidate_rollback
        ),
        "fault_persists_to_fix_parent": (
            "$imageName = $application->docker_registry_image_name" in pre_fix_snapshot
            and "$this->dockerImageTag = str($this->commit)->substr(0, 128);"
            in pre_fix_job
        ),
        "fix_adds_config_bound_image_identity": _contains_all(
            fix_patch,
            (
                "$configHash = substr($this->application->config_hash ?? '', 0, 8);",
                "?string $productionImageName = null",
                "$metadata['image_name']",
            ),
        ),
        "fixed_state_binds_tag_metadata_and_lookup": (
            "$this->dockerImageTag = str($this->commit)->substr(0, 119).'-'.$configHash;"
            in fixed_job
            and "$imageName = $productionImageName ??" in fixed_snapshot
            and "$imageName = $metadata['image_name'] ??" in fixed_rollback
        ),
        "composition_semantics_pass": semantics["passed"] is True,
    }
    return {
        "key": "rollback_image_identity",
        "candidate_sha": CANDIDATE_SHA,
        "fix_sha": IMAGE_IDENTITY_FIX_SHA,
        "candidate_parent_sha": candidate_parent,
        "fix_parent_sha": fix_parent,
        "adjudication": "CONFIRMED_DIRECT_AI_ROLLBACK_IMAGE_IDENTITY_REGRESSION",
        "causal_role": "DIRECT_ORIGIN",
        "mechanism_group": IMAGE_MECHANISM,
        "failure_surface": "built_image_identity",
        "claim": (
            "the AI-created versioned rollback keyed images and metadata only by "
            "commit, so builds of one commit with different build configuration "
            "collided; the direct child binds the tag, metadata, and rollback lookup "
            "to a configuration hash"
        ),
        "checks": checks,
        "semantic_witness": semantics,
        "state_records": {
            "candidate_snapshot": _blob_record(
                repository, CANDIDATE_SHA, SNAPSHOT_PATH
            ),
            "fix_parent_job": _blob_record(repository, fix_parent, JOB_PATH),
            "fixed_job": _blob_record(repository, IMAGE_IDENTITY_FIX_SHA, JOB_PATH),
            "candidate_delta": _diff_record(
                repository,
                candidate_parent,
                CANDIDATE_SHA,
                (SNAPSHOT_PATH, JOB_PATH, ROLLBACK_PATH),
            ),
            "fix_delta": _diff_record(
                repository,
                fix_parent,
                IMAGE_IDENTITY_FIX_SHA,
                (SNAPSHOT_PATH, JOB_PATH, ROLLBACK_PATH),
            ),
        },
        "passed": all(checks.values()),
    }


def _symlink_overwrite_case(
    repository: Path,
    *,
    ai_checks: Mapping[str, bool],
    delta_row: Mapping[str, object],
) -> dict[str, object]:
    candidate_parent = _first_parent(repository, CANDIDATE_SHA)
    fix_parent = _first_parent(repository, SYMLINK_FIX_SHA)
    parent_job = _blob(repository, candidate_parent, JOB_PATH)
    candidate_snapshot = _blob(repository, CANDIDATE_SHA, SNAPSHOT_PATH)
    candidate_job = _blob(repository, CANDIDATE_SHA, JOB_PATH)
    pre_fix_snapshot = _blob(repository, fix_parent, SNAPSHOT_PATH)
    pre_fix_job = _blob(repository, fix_parent, JOB_PATH)
    fixed_job = _blob(repository, SYMLINK_FIX_SHA, JOB_PATH)
    candidate_patch = _diff(
        repository,
        candidate_parent,
        CANDIDATE_SHA,
        (SNAPSHOT_PATH, JOB_PATH),
    ).decode("utf-8", errors="strict")
    fix_patch = _diff(repository, fix_parent, SYMLINK_FIX_SHA, (JOB_PATH,)).decode(
        "utf-8", errors="strict"
    )
    semantics = _legacy_env_symlink_semantics()
    unlink_guard = "rm -f $this->configuration_dir/.env 2>/dev/null || true"
    writer = (
        "echo '$envs_base64' | base64 -d | tee "
        "$this->configuration_dir/.env > /dev/null"
    )
    legacy_link = "ln -sf {$currentSymlink}/.env {$appBaseDir}/.env 2>/dev/null || true"
    checks = {
        **ai_checks,
        "edge_is_in_frozen_delta_bridge": delta_row.get("retained") is True,
        "edge_is_p0_exact_reversal": (
            delta_row.get("source_priority_class") == "P0_DIRECT_RUNTIME_PREIMAGE_OWNER"
            and str(delta_row.get("delta_bridge_class") or "").startswith("B0_")
        ),
        "candidate_is_ancestor_of_fix": _is_ancestor(
            repository, CANDIDATE_SHA, SYMLINK_FIX_SHA
        ),
        "writer_and_configuration_path_preexist_candidate": _contains_all(
            parent_job,
            (
                '$this->configuration_dir = application_configuration_dir()."/{$this->application->uuid}";',
                writer,
            ),
        ),
        "candidate_adds_legacy_env_symlink": (
            legacy_link in candidate_patch and legacy_link in candidate_snapshot
        ),
        "candidate_composes_symlink_with_existing_writer_path": (
            '$appBaseDir = application_configuration_dir()."/{$application->uuid}";'
            in candidate_snapshot
            and legacy_link in candidate_snapshot
            and '$this->configuration_dir = application_configuration_dir()."/{$this->application->uuid}";'
            in candidate_job
            and writer in candidate_job
        ),
        "fault_composition_persists_to_fix_parent": (
            legacy_link in pre_fix_snapshot
            and writer in pre_fix_job
            and unlink_guard not in pre_fix_job
        ),
        "fix_adds_unlink_before_empty_and_nonempty_env_writes": (
            fix_patch.count(unlink_guard) >= 4
            and fixed_job.count(unlink_guard) >= 4
            and writer in fixed_job
        ),
        "composition_semantics_pass": semantics["passed"] is True,
    }
    return {
        "key": "rollback_legacy_env_symlink_overwrite",
        "candidate_sha": CANDIDATE_SHA,
        "fix_sha": SYMLINK_FIX_SHA,
        "candidate_parent_sha": candidate_parent,
        "fix_parent_sha": fix_parent,
        "adjudication": "CONFIRMED_DIRECT_AI_ROLLBACK_SNAPSHOT_SYMLINK_OVERWRITE",
        "causal_role": "COMPOSITIONAL_PATH_EXTENSION",
        "mechanism_group": SYMLINK_MECHANISM,
        "failure_surface": "snapshot_file_integrity",
        "claim": (
            "the AI rollback feature linked the legacy application .env path into "
            "the current versioned snapshot while the existing deployment writer "
            "continued to write through that legacy path; the repair unlinks the "
            "symlink before every empty or populated .env write"
        ),
        "checks": checks,
        "semantic_witness": semantics,
        "state_records": {
            "candidate_snapshot": _blob_record(
                repository, CANDIDATE_SHA, SNAPSHOT_PATH
            ),
            "fix_parent_snapshot": _blob_record(repository, fix_parent, SNAPSHOT_PATH),
            "fix_parent_job": _blob_record(repository, fix_parent, JOB_PATH),
            "fixed_job": _blob_record(repository, SYMLINK_FIX_SHA, JOB_PATH),
            "candidate_delta": _diff_record(
                repository,
                candidate_parent,
                CANDIDATE_SHA,
                (SNAPSHOT_PATH, JOB_PATH),
            ),
            "fix_delta": _diff_record(
                repository, fix_parent, SYMLINK_FIX_SHA, (JOB_PATH,)
            ),
        },
        "passed": all(checks.values()),
    }


def _historical_environment_case(
    repository: Path,
    *,
    ai_checks: Mapping[str, bool],
    delta_row: Mapping[str, object],
) -> dict[str, object]:
    candidate_parent = _first_parent(repository, CANDIDATE_SHA)
    fix_parent = _first_parent(repository, HISTORICAL_ENV_FIX_SHA)
    candidate_snapshot = _blob(repository, CANDIDATE_SHA, SNAPSHOT_PATH)
    candidate_rollback = _blob(repository, CANDIDATE_SHA, ROLLBACK_PATH)
    pre_fix_snapshot = _blob(repository, fix_parent, SNAPSHOT_PATH)
    pre_fix_job = _blob(repository, fix_parent, JOB_PATH)
    pre_fix_rollback = _blob(repository, fix_parent, ROLLBACK_PATH)
    fixed_snapshot = _blob(repository, HISTORICAL_ENV_FIX_SHA, SNAPSHOT_PATH)
    fixed_job = _blob(repository, HISTORICAL_ENV_FIX_SHA, JOB_PATH)
    fixed_rollback = _blob(repository, HISTORICAL_ENV_FIX_SHA, ROLLBACK_PATH)
    candidate_patch = _diff(
        repository,
        candidate_parent,
        CANDIDATE_SHA,
        (SNAPSHOT_PATH, JOB_PATH, ROLLBACK_PATH),
    ).decode("utf-8", errors="strict")
    fix_patch = _diff(
        repository,
        fix_parent,
        HISTORICAL_ENV_FIX_SHA,
        (SNAPSHOT_PATH, JOB_PATH, ROLLBACK_PATH),
    ).decode("utf-8", errors="strict")
    semantics = _historical_environment_semantics()
    historical_fragments = (
        "'build_environment_variables' => $this->serializeEnvironmentVariables($application, true)",
        "'runtime_environment_variables' => $this->serializeEnvironmentVariables($application, false)",
        "'value' => encrypt($var->real_value)",
    )
    repair_job_fragments = (
        "private ?string $rollback_deployment_uuid = null;",
        "$this->rollback_snapshot = $this->loadRollbackSnapshot();",
        "$this->applyRollbackConfiguration();",
        "$var['value'] = decrypt($var['value']);",
        "$rollbackBuildVars = $this->getRollbackBuildEnvironmentVariables();",
        "$rollbackRuntimeVars = $this->getRollbackRuntimeEnvironmentVariables();",
    )
    checks = {
        **ai_checks,
        "edge_is_in_frozen_delta_bridge": delta_row.get("retained") is True,
        "edge_is_p0_exact_reversal": (
            delta_row.get("source_priority_class") == "P0_DIRECT_RUNTIME_PREIMAGE_OWNER"
            and str(delta_row.get("delta_bridge_class") or "").startswith("B0_")
        ),
        "candidate_is_ancestor_of_fix": _is_ancestor(
            repository, CANDIDATE_SHA, HISTORICAL_ENV_FIX_SHA
        ),
        "candidate_adds_rebuild_rollback_without_snapshot_identity": (
            _contains_all(
                candidate_patch,
                (
                    "private function triggerRebuildRollback",
                    "rollback: true",
                    "force_rebuild: true",
                ),
            )
            and "rollback_deployment_uuid" not in candidate_rollback
        ),
        "candidate_metadata_omits_historical_environment": _contains_none(
            candidate_snapshot,
            (
                "build_environment_variables",
                "runtime_environment_variables",
                "serializeEnvironmentVariables",
            ),
        ),
        "fault_persists_to_fix_parent": (
            _contains_none(pre_fix_snapshot, historical_fragments)
            and "rollback_deployment_uuid" not in pre_fix_job
            and "rollback_deployment_uuid" not in pre_fix_rollback
        ),
        "fix_adds_encrypted_historical_environment_snapshot": (
            _contains_all(fix_patch, historical_fragments)
            and _contains_all(fixed_snapshot, historical_fragments)
        ),
        "fix_binds_and_applies_snapshot_during_rebuild": (
            _contains_all(fixed_job, repair_job_fragments)
            and "rollback_deployment_uuid: $deploymentUuid" in fixed_rollback
        ),
        "composition_semantics_pass": semantics["passed"] is True,
    }
    return {
        "key": "rollback_rebuild_historical_environment",
        "candidate_sha": CANDIDATE_SHA,
        "fix_sha": HISTORICAL_ENV_FIX_SHA,
        "candidate_parent_sha": candidate_parent,
        "fix_parent_sha": fix_parent,
        "adjudication": "CONFIRMED_DIRECT_AI_ROLLBACK_REBUILD_STATE_LOSS",
        "causal_role": "DIRECT_ORIGIN",
        "mechanism_group": HISTORICAL_ENV_MECHANISM,
        "failure_surface": "rollback_rebuild_input_state",
        "claim": (
            "the AI-created rebuild rollback queued only a commit and stored no "
            "recoverable historical build/runtime environment, so rebuilding used "
            "current configuration; the repair binds a deployment UUID, stores "
            "encrypted historical variables, and loads them into the rebuild"
        ),
        "checks": checks,
        "semantic_witness": semantics,
        "state_records": {
            "candidate_snapshot": _blob_record(
                repository, CANDIDATE_SHA, SNAPSHOT_PATH
            ),
            "fix_parent_snapshot": _blob_record(repository, fix_parent, SNAPSHOT_PATH),
            "fix_parent_job": _blob_record(repository, fix_parent, JOB_PATH),
            "fixed_snapshot": _blob_record(
                repository, HISTORICAL_ENV_FIX_SHA, SNAPSHOT_PATH
            ),
            "fixed_job": _blob_record(repository, HISTORICAL_ENV_FIX_SHA, JOB_PATH),
            "candidate_delta": _diff_record(
                repository,
                candidate_parent,
                CANDIDATE_SHA,
                (SNAPSHOT_PATH, JOB_PATH, ROLLBACK_PATH),
            ),
            "fix_delta": _diff_record(
                repository,
                fix_parent,
                HISTORICAL_ENV_FIX_SHA,
                (SNAPSHOT_PATH, JOB_PATH, ROLLBACK_PATH),
            ),
        },
        "passed": all(checks.values()),
    }


def _independence_checks(
    case_results: Sequence[Mapping[str, object]],
) -> dict[str, bool]:
    mechanisms = [str(row.get("mechanism_group") or "") for row in case_results]
    fix_shas = [str(row.get("fix_sha") or "") for row in case_results]
    failure_surfaces = [str(row.get("failure_surface") or "") for row in case_results]
    candidate_shas = {str(row.get("candidate_sha") or "") for row in case_results}
    return {
        "exactly_three_cases": len(case_results) == 3,
        "one_shared_candidate": candidate_shas == {CANDIDATE_SHA},
        "three_distinct_fix_commits": len(set(fix_shas)) == len(fix_shas) == 3,
        "three_distinct_mechanism_groups": (
            len(set(mechanisms)) == len(mechanisms) == 3
        ),
        "three_distinct_failure_surfaces": (
            len(set(failure_surfaces)) == len(failure_surfaces) == 3
        ),
        "symlink_claim_is_not_broadened_to_other_b227_repairs": (
            any(
                row.get("fix_sha") == SYMLINK_FIX_SHA
                and row.get("mechanism_group") == SYMLINK_MECHANISM
                and row.get("failure_surface") == "snapshot_file_integrity"
                for row in case_results
            )
        ),
    }


def build_witness(
    repository: Path,
    *,
    ai_rows: Sequence[Mapping[str, object]],
    overlap_rows: Sequence[Mapping[str, object]],
    delta_rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    ai_row = _single_sha_row(ai_rows, CANDIDATE_SHA)
    ai_checks = _candidate_ai_checks(ai_row)
    image_overlap = _single_edge_row(
        overlap_rows, CANDIDATE_SHA, IMAGE_IDENTITY_FIX_SHA
    )
    symlink_delta = _single_edge_row(delta_rows, CANDIDATE_SHA, SYMLINK_FIX_SHA)
    historical_delta = _single_edge_row(
        delta_rows, CANDIDATE_SHA, HISTORICAL_ENV_FIX_SHA
    )
    case_results = [
        _image_identity_case(
            repository, ai_checks=ai_checks, overlap_row=image_overlap
        ),
        _symlink_overwrite_case(
            repository, ai_checks=ai_checks, delta_row=symlink_delta
        ),
        _historical_environment_case(
            repository, ai_checks=ai_checks, delta_row=historical_delta
        ),
    ]
    independence = _independence_checks(case_results)
    witness_passed = all(row.get("passed") is True for row in case_results) and all(
        independence.values()
    )
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_deployment_rollback_causal_batch_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate": _commit_metadata(repository, CANDIDATE_SHA),
        "repair_chain": [
            _commit_metadata(repository, revision)
            for revision in (
                IMAGE_IDENTITY_FIX_SHA,
                SYMLINK_FIX_SHA,
                HISTORICAL_ENV_FIX_SHA,
            )
        ],
        "confirmed_edges": [
            {
                "candidate_sha": row["candidate_sha"],
                "fix_sha": row["fix_sha"],
                "adjudication": row["adjudication"],
                "causal_role": row["causal_role"],
                "mechanism_group": row["mechanism_group"],
            }
            for row in case_results
        ],
        "case_results": case_results,
        "independence_checks": independence,
        "summary": {
            "confirmed_edge_count": len(case_results),
            "unique_candidate_count": len(
                {str(row["candidate_sha"]) for row in case_results}
            ),
            "mechanism_group_count": len(
                {str(row["mechanism_group"]) for row in case_results}
            ),
            "failed_case_count": sum(
                row.get("passed") is not True for row in case_results
            ),
        },
        "witness_passed": witness_passed,
        "claim_boundary": (
            "Each edge proves an observed-AI candidate, retained candidate-source "
            "provenance, Git ancestry, candidate introduction or compositional "
            "activation, persistence through the fix parent, and a deterministic "
            "repair closure. The three mechanisms concern image identity, snapshot "
            "file integrity, and rebuild input state respectively. The b227 edge "
            "claims only legacy .env symlink overwrite. These are causal repair "
            "edges, not evidence that any defect shipped or caused a field incident."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    ai_path = args.ai_scan_dir.resolve() / "commits.jsonl"
    overlap_path = args.exact_overlap_dir.resolve() / "exact_overlap_pairs.jsonl"
    delta_path = args.delta_bridge_dir.resolve() / "delta_bridge_pairs.jsonl"
    try:
        ai_rows = _load_jsonl(ai_path)
        overlap_rows = _load_jsonl(overlap_path)
        delta_rows = _load_jsonl(delta_path)
        payload = build_witness(
            repository,
            ai_rows=ai_rows,
            overlap_rows=overlap_rows,
            delta_rows=delta_rows,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    payload["source_artifacts"] = {
        "ai_commits": {
            "path": str(ai_path),
            "sha256": _sha256_file(ai_path),
        },
        "exact_overlap_pairs": {
            "path": str(overlap_path),
            "sha256": _sha256_file(overlap_path),
        },
        "delta_bridge_pairs": {
            "path": str(delta_path),
            "sha256": _sha256_file(delta_path),
        },
    }
    if payload["witness_passed"] is not True:
        failed = [
            str(row["key"])
            for row in payload["case_results"]
            if row.get("passed") is not True
        ]
        raise SystemExit(f"deployment rollback witness failed: {failed}")
    _atomic_json(args.output.resolve(), payload)
    output_sha = _sha256_file(args.output.resolve())
    print("Coolify deployment rollback causal batch witness frozen")
    print(f"  confirmed edges  : {payload['summary']['confirmed_edge_count']}")
    print(f"  unique candidates: {payload['summary']['unique_candidate_count']}")
    print(f"  mechanisms       : {payload['summary']['mechanism_group_count']}")
    print(f"  output SHA256     : {output_sha}")
    print(f"  output            : {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
