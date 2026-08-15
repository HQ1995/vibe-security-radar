#!/usr/bin/env python3
"""Freeze the Coolify read-only volume path-normalization repair witness."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _is_ancestor,
    _php_method_region,
)


CANDIDATE_SHA = "f152ec00ada70757da38e0b789f049b14d813e33"
CANDIDATE_SUBJECT = (
    "fix: Detect read-only Docker volumes with long-form syntax and enable refresh"
)
INTERMEDIATE_SHA = "475cfd78cd19d1beecb33bcd80e16c76f544087e"
INTERMEDIATE_SUBJECT = (
    "fix: Prevent N+1 query in LocalPersistentVolume.isDockerComposeResource()"
)
FIX_SHA = "9bc33d65abd022884ddc6d0e3c463ad4032bb144"
FIX_SUBJECT = "fix: Improve read-only volume detection and UI messaging"

LOCAL_FILE_PATH = "app/Models/LocalFileVolume.php"
PERSISTENT_FILE_PATH = "app/Models/LocalPersistentVolume.php"
TEST_PATH = "tests/Unit/LocalFileVolumeReadOnlyTest.php"
FILE_STORAGE_COMPONENT_PATH = "app/Livewire/Project/Service/FileStorage.php"
SHARED_STORAGE_COMPONENT_PATH = "app/Livewire/Project/Shared/Storages/Show.php"

MECHANISM = "local_file_volume_leading_slash_normalization_omission"
FAILURE_SURFACE = "readonly_volume_ui_detection"
PR_URL = "https://github.com/coollabsio/coolify/pull/7588"
REVIEW_COMMENT_ID = 2610583032


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--secondary-repository", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--census-dir", type=Path, required=True)
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
    return {
        "revision": revision,
        "path": source_path,
        "git_blob_oid": _git_text(
            repository, ("rev-parse", f"{revision}:{source_path}")
        ).strip(),
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
    content = _diff(repository, before, after, source_paths)
    return {
        "before_revision": before,
        "after_revision": after,
        "paths": list(source_paths),
        "byte_count": len(content),
        "sha256": _sha256_bytes(content),
    }


def _single_sha_row(
    rows: Sequence[Mapping[str, object]], sha: str
) -> Mapping[str, object]:
    matches = [row for row in rows if row.get("sha") == sha]
    if len(matches) != 1:
        raise ValueError(f"{sha} resolved to {len(matches)} rows")
    return matches[0]


def _line_origin(
    repository: Path,
    revision: str,
    source_path: str,
    marker: str,
    *,
    occurrence: int = 1,
) -> dict[str, object]:
    source = _blob(repository, revision, source_path)
    matching_lines = [
        index + 1 for index, line in enumerate(source.splitlines()) if marker in line
    ]
    if occurrence < 1 or len(matching_lines) < occurrence:
        raise ValueError(
            f"expected occurrence {occurrence} of {marker!r} at "
            f"{revision}:{source_path}; found {matching_lines}"
        )
    line_number = matching_lines[occurrence - 1]
    blame = _git_text(
        repository,
        (
            "blame",
            "--line-porcelain",
            "-L",
            f"{line_number},{line_number}",
            revision,
            "--",
            source_path,
        ),
    )
    return {
        "revision": revision,
        "path": source_path,
        "line": line_number,
        "marker": marker,
        "origin_sha": blame.split(None, 1)[0].lstrip("^"),
    }


def _ai_provenance_checks(
    sha: str,
    ai_row: Mapping[str, object],
    census_row: Mapping[str, object],
) -> dict[str, bool]:
    source_modules = ai_row.get("source_modules")
    tools = ai_row.get("tools")
    message = str(ai_row.get("message") or "")
    return {
        "present_in_frozen_ai_scan": ai_row.get("sha") == sha,
        "observed_ai_commit_in_census": (
            census_row.get("sha") == sha
            and census_row.get("observed_ai_commit") is True
        ),
        "coauthor_trailer_source_present": (
            isinstance(source_modules, list) and "coauthor_trailer" in source_modules
        ),
        "claude_code_tool_present": (
            isinstance(tools, list) and "claude_code" in tools
        ),
        "message_has_explicit_claude_provenance": (
            "Generated with" in message
            and "Claude Code" in message
            and "Co-Authored-By: Claude" in message
        ),
    }


def _method_contract(method_source: str) -> dict[str, object]:
    literal_marker = "if ($containerPath === $this->mount_path)"
    mount_normalization = "$mountPath = str($this->mount_path)->ltrim('/')->toString();"
    target_normalization = (
        "$containerPathClean = str($containerPath)->ltrim('/')->toString();"
    )
    normalized_compare = (
        "if ($mountPath === $containerPathClean || "
        "$this->mount_path === $containerPath)"
    )
    return {
        "handles_long_form_array": "elseif (is_array($volume))" in method_source,
        "reads_long_form_target": "data_get($volume, 'target')" in method_source,
        "reads_long_form_read_only": (
            "data_get($volume, 'read_only', false)" in method_source
        ),
        "literal_compare_count": method_source.count(literal_marker),
        "mount_normalization_count": method_source.count(mount_normalization),
        "target_normalization_count": method_source.count(target_normalization),
        "normalized_compare_count": method_source.count(normalized_compare),
    }


def _test_contract(test_source: str) -> dict[str, object]:
    mount_arguments = re.findall(
        r"isVolumeReadOnly\(\$compose,\s*'[^']+',\s*'([^']+)'\)",
        test_source,
    )
    return {
        "mirrors_production_logic": (
            "This mirrors the logic in LocalFileVolume::isReadOnlyVolume()"
            in test_source
        ),
        "helper_uses_literal_compare": (
            "if ($containerPath === $mountPath)" in test_source
        ),
        "helper_has_no_path_normalization": "ltrim('/')" not in test_source,
        "mount_argument_count": len(mount_arguments),
        "all_mount_arguments_have_leading_slash": (
            bool(mount_arguments)
            and all(argument.startswith("/") for argument in mount_arguments)
        ),
        "has_leading_slash_mismatch_case": any(
            not argument.startswith("/") for argument in mount_arguments
        ),
    }


def _candidate_path_match(mount_path: str, container_path: str) -> bool:
    return container_path == mount_path


def _fixed_path_match(mount_path: str, container_path: str) -> bool:
    return mount_path.lstrip("/") == container_path.lstrip("/")


def _path_normalization_semantics() -> dict[str, object]:
    cases = [
        {
            "key": "exact_absolute_paths",
            "mount_path": "/etc/config.toml",
            "container_path": "/etc/config.toml",
            "candidate_matches": _candidate_path_match(
                "/etc/config.toml", "/etc/config.toml"
            ),
            "fixed_matches": _fixed_path_match("/etc/config.toml", "/etc/config.toml"),
        },
        {
            "key": "stored_mount_missing_leading_slash",
            "mount_path": "etc/config.toml",
            "container_path": "/etc/config.toml",
            "candidate_matches": _candidate_path_match(
                "etc/config.toml", "/etc/config.toml"
            ),
            "fixed_matches": _fixed_path_match("etc/config.toml", "/etc/config.toml"),
        },
        {
            "key": "compose_target_missing_leading_slash",
            "mount_path": "/etc/config.toml",
            "container_path": "etc/config.toml",
            "candidate_matches": _candidate_path_match(
                "/etc/config.toml", "etc/config.toml"
            ),
            "fixed_matches": _fixed_path_match("/etc/config.toml", "etc/config.toml"),
        },
        {
            "key": "different_paths_remain_distinct",
            "mount_path": "/etc/config.toml",
            "container_path": "/etc/other.toml",
            "candidate_matches": _candidate_path_match(
                "/etc/config.toml", "/etc/other.toml"
            ),
            "fixed_matches": _fixed_path_match("/etc/config.toml", "/etc/other.toml"),
        },
    ]
    by_key = {str(row["key"]): row for row in cases}
    checks = {
        "exact_match_is_preserved": (
            by_key["exact_absolute_paths"]["candidate_matches"] is True
            and by_key["exact_absolute_paths"]["fixed_matches"] is True
        ),
        "candidate_misses_stored_mount_slash_drift": (
            by_key["stored_mount_missing_leading_slash"]["candidate_matches"] is False
        ),
        "fix_accepts_stored_mount_slash_drift": (
            by_key["stored_mount_missing_leading_slash"]["fixed_matches"] is True
        ),
        "candidate_misses_compose_target_slash_drift": (
            by_key["compose_target_missing_leading_slash"]["candidate_matches"] is False
        ),
        "fix_accepts_compose_target_slash_drift": (
            by_key["compose_target_missing_leading_slash"]["fixed_matches"] is True
        ),
        "different_paths_remain_distinct": (
            by_key["different_paths_remain_distinct"]["candidate_matches"] is False
            and by_key["different_paths_remain_distinct"]["fixed_matches"] is False
        ),
    }
    return {"cases": cases, "checks": checks, "passed": all(checks.values())}


def _cross_clone_verification(
    primary_repository: Path,
    secondary_repository: Path,
) -> dict[str, object]:
    revisions = (CANDIDATE_SHA, INTERMEDIATE_SHA, FIX_SHA)
    blob_targets = (
        (CANDIDATE_SHA, LOCAL_FILE_PATH),
        (INTERMEDIATE_SHA, LOCAL_FILE_PATH),
        (FIX_SHA, LOCAL_FILE_PATH),
        (CANDIDATE_SHA, PERSISTENT_FILE_PATH),
        (CANDIDATE_SHA, TEST_PATH),
        (FIX_SHA, TEST_PATH),
    )
    primary_trees = {
        revision: _git_text(
            primary_repository, ("rev-parse", f"{revision}^{{tree}}")
        ).strip()
        for revision in revisions
    }
    secondary_trees = {
        revision: _git_text(
            secondary_repository, ("rev-parse", f"{revision}^{{tree}}")
        ).strip()
        for revision in revisions
    }
    primary_blobs = {
        f"{revision}:{source_path}": _git_text(
            primary_repository, ("rev-parse", f"{revision}:{source_path}")
        ).strip()
        for revision, source_path in blob_targets
    }
    secondary_blobs = {
        f"{revision}:{source_path}": _git_text(
            secondary_repository, ("rev-parse", f"{revision}:{source_path}")
        ).strip()
        for revision, source_path in blob_targets
    }
    primary_candidate_delta = _diff_record(
        primary_repository,
        _first_parent(primary_repository, CANDIDATE_SHA),
        CANDIDATE_SHA,
        (LOCAL_FILE_PATH, PERSISTENT_FILE_PATH, TEST_PATH),
    )
    secondary_candidate_delta = _diff_record(
        secondary_repository,
        _first_parent(secondary_repository, CANDIDATE_SHA),
        CANDIDATE_SHA,
        (LOCAL_FILE_PATH, PERSISTENT_FILE_PATH, TEST_PATH),
    )
    primary_fix_delta = _diff_record(
        primary_repository,
        _first_parent(primary_repository, FIX_SHA),
        FIX_SHA,
        (
            LOCAL_FILE_PATH,
            FILE_STORAGE_COMPONENT_PATH,
            SHARED_STORAGE_COMPONENT_PATH,
        ),
    )
    secondary_fix_delta = _diff_record(
        secondary_repository,
        _first_parent(secondary_repository, FIX_SHA),
        FIX_SHA,
        (
            LOCAL_FILE_PATH,
            FILE_STORAGE_COMPONENT_PATH,
            SHARED_STORAGE_COMPONENT_PATH,
        ),
    )
    primary_parents = {
        revision: _first_parent(primary_repository, revision) for revision in revisions
    }
    secondary_parents = {
        revision: _first_parent(secondary_repository, revision)
        for revision in revisions
    }
    checks = {
        "commit_tree_oids_match": primary_trees == secondary_trees,
        "first_parent_topology_matches": primary_parents == secondary_parents,
        "critical_blob_oids_match": primary_blobs == secondary_blobs,
        "candidate_delta_matches": (
            primary_candidate_delta["sha256"] == secondary_candidate_delta["sha256"]
        ),
        "fix_delta_matches": (
            primary_fix_delta["sha256"] == secondary_fix_delta["sha256"]
        ),
    }
    return {
        "primary_repository": str(primary_repository),
        "secondary_repository": str(secondary_repository),
        "checks": checks,
        "tree_oids": primary_trees,
        "first_parents": primary_parents,
        "critical_blob_oids": primary_blobs,
        "candidate_delta_sha256": primary_candidate_delta["sha256"],
        "fix_delta_sha256": primary_fix_delta["sha256"],
        "passed": all(checks.values()),
    }


def build_witness(
    repository: Path,
    *,
    ai_rows: Sequence[Mapping[str, object]],
    census_rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    candidate_parent = _first_parent(repository, CANDIDATE_SHA)
    intermediate_parent = _first_parent(repository, INTERMEDIATE_SHA)
    fix_parent = _first_parent(repository, FIX_SHA)

    candidate_census = _single_sha_row(census_rows, CANDIDATE_SHA)
    intermediate_census = _single_sha_row(census_rows, INTERMEDIATE_SHA)
    fix_census = _single_sha_row(census_rows, FIX_SHA)
    candidate_metadata = _commit_metadata(repository, CANDIDATE_SHA)
    intermediate_metadata = _commit_metadata(repository, INTERMEDIATE_SHA)
    fix_metadata = _commit_metadata(repository, FIX_SHA)

    candidate_parent_local = _blob(repository, candidate_parent, LOCAL_FILE_PATH)
    candidate_local = _blob(repository, CANDIDATE_SHA, LOCAL_FILE_PATH)
    intermediate_local = _blob(repository, INTERMEDIATE_SHA, LOCAL_FILE_PATH)
    fixed_local = _blob(repository, FIX_SHA, LOCAL_FILE_PATH)
    candidate_persistent = _blob(repository, CANDIDATE_SHA, PERSISTENT_FILE_PATH)
    candidate_test = _blob(repository, CANDIDATE_SHA, TEST_PATH)
    intermediate_test = _blob(repository, INTERMEDIATE_SHA, TEST_PATH)
    fixed_test = _blob(repository, FIX_SHA, TEST_PATH)
    fix_parent_file_storage = _blob(repository, fix_parent, FILE_STORAGE_COMPONENT_PATH)
    fixed_file_storage = _blob(repository, FIX_SHA, FILE_STORAGE_COMPONENT_PATH)
    fix_parent_shared_storage = _blob(
        repository, fix_parent, SHARED_STORAGE_COMPONENT_PATH
    )
    fixed_shared_storage = _blob(repository, FIX_SHA, SHARED_STORAGE_COMPONENT_PATH)

    candidate_parent_contract = _method_contract(
        _php_method_region(candidate_parent_local, "isReadOnlyVolume")
    )
    candidate_contract = _method_contract(
        _php_method_region(candidate_local, "isReadOnlyVolume")
    )
    candidate_persistent_contract = _method_contract(
        _php_method_region(candidate_persistent, "isReadOnlyVolume")
    )
    fixed_contract = _method_contract(
        _php_method_region(fixed_local, "isReadOnlyVolume")
    )
    candidate_test_contract = _test_contract(candidate_test)
    fixed_test_contract = _test_contract(fixed_test)
    semantic_witness = _path_normalization_semantics()

    candidate_patch = _diff(
        repository,
        candidate_parent,
        CANDIDATE_SHA,
        (LOCAL_FILE_PATH, PERSISTENT_FILE_PATH, TEST_PATH),
    ).decode("utf-8", errors="strict")
    fix_patch = _diff(
        repository,
        fix_parent,
        FIX_SHA,
        (
            LOCAL_FILE_PATH,
            FILE_STORAGE_COMPONENT_PATH,
            SHARED_STORAGE_COMPONENT_PATH,
        ),
    ).decode("utf-8", errors="strict")

    literal_marker = "if ($containerPath === $this->mount_path)"
    mount_normalization = "$mountPath = str($this->mount_path)->ltrim('/')->toString();"
    target_normalization = (
        "$containerPathClean = str($containerPath)->ltrim('/')->toString();"
    )
    line_origins = {
        "candidate_local_short_form_literal_compare": _line_origin(
            repository,
            CANDIDATE_SHA,
            LOCAL_FILE_PATH,
            literal_marker,
            occurrence=1,
        ),
        "candidate_local_long_form_literal_compare": _line_origin(
            repository,
            CANDIDATE_SHA,
            LOCAL_FILE_PATH,
            literal_marker,
            occurrence=2,
        ),
        "candidate_persistent_long_form_normalization": _line_origin(
            repository,
            CANDIDATE_SHA,
            PERSISTENT_FILE_PATH,
            mount_normalization,
            occurrence=2,
        ),
        "fixed_local_short_form_normalization": _line_origin(
            repository,
            FIX_SHA,
            LOCAL_FILE_PATH,
            mount_normalization,
            occurrence=1,
        ),
        "fixed_local_long_form_normalization": _line_origin(
            repository,
            FIX_SHA,
            LOCAL_FILE_PATH,
            mount_normalization,
            occurrence=2,
        ),
    }

    candidate_ai_checks = _ai_provenance_checks(
        CANDIDATE_SHA,
        _single_sha_row(ai_rows, CANDIDATE_SHA),
        candidate_census,
    )
    intermediate_ai_checks = _ai_provenance_checks(
        INTERMEDIATE_SHA,
        _single_sha_row(ai_rows, INTERMEDIATE_SHA),
        intermediate_census,
    )
    fix_ai_checks = _ai_provenance_checks(
        FIX_SHA,
        _single_sha_row(ai_rows, FIX_SHA),
        fix_census,
    )

    checks = {
        "candidate_parent_matches_git_and_census": (
            candidate_census.get("parents") == [candidate_parent]
            and candidate_metadata.get("parents") == [candidate_parent]
        ),
        "intermediate_is_direct_ai_child_of_candidate": (
            intermediate_parent == CANDIDATE_SHA
            and intermediate_census.get("parents") == [CANDIDATE_SHA]
            and intermediate_metadata.get("parents") == [CANDIDATE_SHA]
            and all(intermediate_ai_checks.values())
        ),
        "fix_is_direct_ai_child_of_intermediate": (
            fix_parent == INTERMEDIATE_SHA
            and fix_census.get("parents") == [INTERMEDIATE_SHA]
            and fix_metadata.get("parents") == [INTERMEDIATE_SHA]
            and all(fix_ai_checks.values())
        ),
        "candidate_is_ancestor_of_fix": _is_ancestor(
            repository, CANDIDATE_SHA, FIX_SHA
        ),
        "candidate_subjects_match_frozen_census": (
            candidate_census.get("subject") == CANDIDATE_SUBJECT
            and intermediate_census.get("subject") == INTERMEDIATE_SUBJECT
            and fix_census.get("subject") == FIX_SUBJECT
        ),
        "candidate_has_explicit_ai_provenance": all(candidate_ai_checks.values()),
        "candidate_parent_lacks_long_form_local_file_detection": (
            candidate_parent_contract["handles_long_form_array"] is False
        ),
        "candidate_adds_long_form_with_two_literal_path_comparisons": (
            "elseif (is_array($volume))" in candidate_patch
            and candidate_contract["handles_long_form_array"] is True
            and candidate_contract["reads_long_form_target"] is True
            and candidate_contract["reads_long_form_read_only"] is True
            and candidate_contract["literal_compare_count"] == 2
            and candidate_contract["mount_normalization_count"] == 0
            and candidate_contract["target_normalization_count"] == 0
        ),
        "candidate_persistent_long_form_branch_already_normalizes_paths": (
            candidate_persistent_contract["handles_long_form_array"] is True
            and candidate_persistent_contract["mount_normalization_count"] >= 2
            and candidate_persistent_contract["target_normalization_count"] >= 2
            and candidate_persistent_contract["normalized_compare_count"] >= 2
            and line_origins["candidate_persistent_long_form_normalization"][
                "origin_sha"
            ]
            == CANDIDATE_SHA
        ),
        "candidate_test_mirrors_literal_logic_and_misses_slash_drift": (
            not _path_exists(repository, candidate_parent, TEST_PATH)
            and candidate_test_contract["mirrors_production_logic"] is True
            and candidate_test_contract["helper_uses_literal_compare"] is True
            and candidate_test_contract["helper_has_no_path_normalization"] is True
            and candidate_test_contract["all_mount_arguments_have_leading_slash"]
            is True
            and candidate_test_contract["has_leading_slash_mismatch_case"] is False
        ),
        "local_file_fault_survives_intermediate_byte_exact": (
            candidate_local == intermediate_local
        ),
        "candidate_test_survives_intermediate_byte_exact": (
            candidate_test == intermediate_test
        ),
        "fix_normalizes_both_local_file_branches": (
            mount_normalization in fix_patch
            and target_normalization in fix_patch
            and fixed_contract["handles_long_form_array"] is True
            and fixed_contract["literal_compare_count"] == 0
            and fixed_contract["mount_normalization_count"] == 2
            and fixed_contract["target_normalization_count"] == 2
            and fixed_contract["normalized_compare_count"] == 2
        ),
        "fix_message_names_leading_slash_repair": (
            "Update path matching to handle leading slashes in volume comparisons"
            in str(fix_metadata.get("message") or "")
        ),
        "fix_switches_related_ui_consumers_to_policy_helper": (
            "$this->fileStorage->isReadOnlyVolume()" in fix_parent_file_storage
            and "$this->fileStorage->shouldBeReadOnlyInUI()" in fixed_file_storage
            and "$this->storage->isReadOnlyVolume()" in fix_parent_shared_storage
            and "$this->storage->shouldBeReadOnlyInUI()" in fixed_shared_storage
            and "public function shouldBeReadOnlyInUI(): bool" in fixed_local
        ),
        "candidate_and_fix_line_origins_are_exact": (
            line_origins["candidate_local_short_form_literal_compare"]["origin_sha"]
            == CANDIDATE_SHA
            and line_origins["candidate_local_long_form_literal_compare"]["origin_sha"]
            == CANDIDATE_SHA
            and line_origins["fixed_local_short_form_normalization"]["origin_sha"]
            == FIX_SHA
            and line_origins["fixed_local_long_form_normalization"]["origin_sha"]
            == FIX_SHA
        ),
        "semantic_path_normalization_witness_passes": (
            semantic_witness["passed"] is True
        ),
        "repair_test_gap_is_preserved_and_explicit": (
            candidate_test == fixed_test
            and fixed_test_contract["has_leading_slash_mismatch_case"] is False
            and fixed_test_contract["helper_has_no_path_normalization"] is True
        ),
    }
    passed = all(checks.values())

    return {
        "schema_version": 1,
        "artifact_kind": "coolify_readonly_volume_path_normalization_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": CANDIDATE_SHA,
        "intermediate_sha": INTERMEDIATE_SHA,
        "fix_sha": FIX_SHA,
        "candidate_parent_sha": candidate_parent,
        "fix_parent_sha": fix_parent,
        "adjudication": "CONFIRMED_AI_TO_AI_INCOMPLETE_REPAIR",
        "causal_role": "INCOMPLETE_AI_REPAIR",
        "mechanism_group": MECHANISM,
        "failure_surface": FAILURE_SURFACE,
        "claim": (
            "the AI candidate added LocalFileVolume long-form read-only detection "
            "with literal container-target/mount-path comparisons while its sibling "
            "persistent-volume branch normalized leading slashes; the local-file "
            "omission survived an intermediate AI commit byte-for-byte, and the "
            "next AI commit normalized both local-file branches and routed related "
            "UI consumers through read-only policy helpers"
        ),
        "checks": checks,
        "candidate_ai_provenance_checks": candidate_ai_checks,
        "intermediate_ai_provenance_checks": intermediate_ai_checks,
        "fix_ai_provenance_checks": fix_ai_checks,
        "method_contracts": {
            "candidate_parent_local_file": candidate_parent_contract,
            "candidate_local_file": candidate_contract,
            "candidate_persistent_volume": candidate_persistent_contract,
            "fixed_local_file": fixed_contract,
        },
        "test_contracts": {
            "candidate": candidate_test_contract,
            "fixed": fixed_test_contract,
        },
        "semantic_witness": semantic_witness,
        "line_origins": line_origins,
        "upstream_review_context": {
            "status": "context_only_not_a_deterministic_pass_gate",
            "pull_request_url": PR_URL,
            "review_comment_id": REVIEW_COMMENT_ID,
            "review_comment_url": f"{PR_URL}#discussion_r{REVIEW_COMMENT_ID}",
            "original_commit_sha": CANDIDATE_SHA,
            "resolved_commit_sha": FIX_SHA,
            "narrow_observation": (
                "the review comment identified literal leading-slash drift in "
                "LocalFileVolume and the resolved commit is the fix SHA"
            ),
        },
        "state_records": {
            "candidate_parent_local_file": _blob_record(
                repository, candidate_parent, LOCAL_FILE_PATH
            ),
            "candidate_local_file": _blob_record(
                repository, CANDIDATE_SHA, LOCAL_FILE_PATH
            ),
            "intermediate_local_file": _blob_record(
                repository, INTERMEDIATE_SHA, LOCAL_FILE_PATH
            ),
            "fixed_local_file": _blob_record(repository, FIX_SHA, LOCAL_FILE_PATH),
            "candidate_persistent_volume": _blob_record(
                repository, CANDIDATE_SHA, PERSISTENT_FILE_PATH
            ),
            "candidate_test": _blob_record(repository, CANDIDATE_SHA, TEST_PATH),
            "intermediate_test": _blob_record(repository, INTERMEDIATE_SHA, TEST_PATH),
            "fixed_test": _blob_record(repository, FIX_SHA, TEST_PATH),
            "candidate_delta": _diff_record(
                repository,
                candidate_parent,
                CANDIDATE_SHA,
                (LOCAL_FILE_PATH, PERSISTENT_FILE_PATH, TEST_PATH),
            ),
            "fix_delta": _diff_record(
                repository,
                fix_parent,
                FIX_SHA,
                (
                    LOCAL_FILE_PATH,
                    FILE_STORAGE_COMPONENT_PATH,
                    SHARED_STORAGE_COMPONENT_PATH,
                ),
            ),
        },
        "claim_boundary": (
            "This proves a LocalFileVolume leading-slash normalization omission in "
            "an AI-authored attempted repair and its AI-authored intra-PR closure. "
            "It does not claim that the candidate first introduced the underlying "
            "long-form read-only bug, that a human authored the repair, that the "
            "related UI refactor is a second independent defect, or that a field "
            "incident/security vulnerability was demonstrated. The existing test "
            "suite duplicates the candidate predicate and is unchanged at the fix; "
            "therefore it does not provide regression coverage for normalization."
        ),
        "witness_passed": passed,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    secondary_repository = args.secondary_repository.resolve()
    if (
        not secondary_repository.is_dir()
        or not (secondary_repository / ".git").exists()
    ):
        raise SystemExit(
            f"secondary repository is not a Git checkout: {secondary_repository}"
        )

    ai_path = args.ai_scan_dir.resolve() / "commits.jsonl"
    census_path = args.census_dir.resolve() / "review_schedule.jsonl"
    try:
        payload = build_witness(
            repository,
            ai_rows=_load_jsonl(ai_path),
            census_rows=_load_jsonl(census_path),
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    payload["source_artifacts"] = {
        "ai_commits": {"path": str(ai_path), "sha256": _sha256_file(ai_path)},
        "repair_census": {
            "path": str(census_path),
            "sha256": _sha256_file(census_path),
        },
    }
    payload["cross_clone_verification"] = _cross_clone_verification(
        repository,
        secondary_repository,
    )
    payload["checks"]["cross_clone_evidence_matches"] = payload[
        "cross_clone_verification"
    ]["passed"]
    payload["witness_passed"] = all(payload["checks"].values())
    if payload["witness_passed"] is not True:
        failed = [key for key, value in payload["checks"].items() if value is not True]
        raise SystemExit(f"read-only volume witness failed: {failed}")

    output_path = args.output.resolve()
    _atomic_json(output_path, payload)
    print("Coolify read-only volume path-normalization witness frozen")
    print(f"  candidate : {CANDIDATE_SHA}")
    print(f"  carrier   : {INTERMEDIATE_SHA}")
    print(f"  fix       : {FIX_SHA}")
    print(f"  checks    : {len(payload['checks'])}")
    print(f"  SHA256    : {_sha256_file(output_path)}")
    print(f"  output    : {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
