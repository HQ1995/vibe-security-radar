#!/usr/bin/env python3
"""Freeze the Coolify updateCompose map-style underacceptance witness."""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


BASELINE_SHA = "8af6339695146487b57ab4ecb02fcda0d554b5ff"
CANDIDATE_SHA = "56f32d0f87609d48c4f9f8d766c96c183bcd60f9"
FIX_SHA = "a5ce1db8715d62b437cb3104af5ca6427f28a47b"

HELPER_PATH = "bootstrap/helpers/services.php"
TEST_PATH = "tests/Unit/UpdateComposeAbbreviatedVariablesTest.php"
MAP_TEMPLATE_MARKERS = {
    "templates/compose/trigger.yaml": 'SERVICE_URL_TRIGGER_3000: ""',
    "templates/compose/langfuse.yaml": (
        "SERVICE_URL_LANGFUSE_3000: ${SERVICE_URL_LANGFUSE_3000}"
    ),
    "templates/compose/paymenter.yaml": (
        "SERVICE_URL_PAYMENTER: ${SERVICE_URL_PAYMENTER_80}"
    ),
}

CANDIDATE_LOOP = "foreach ($environment as $envVar) {"
FIX_LOOP = "foreach ($environment as $key => $value) {"
FIX_MAP_BRANCH = "} elseif (is_string($key)) {"
FIX_TEST_NAMES = (
    "detects SERVICE_URL variables in map-style environment format",
    "handles multiple map-style SERVICE_URL and SERVICE_FQDN variables",
    "does not detect SERVICE_URL references in map-style values",
    "handles map-style with abbreviated service names",
    "verifies updateCompose helper has dual-format handling",
)
MECHANISM_GROUP = "update_compose_map_style_environment_underacceptance"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_record(
    repository: Path, revision: str, source_path: str
) -> dict[str, object]:
    value = _git_blob(repository, revision, source_path)
    object_id = _git(
        repository,
        ["rev-parse", f"{revision}:{source_path}"],
        text=True,
    )
    assert isinstance(object_id, str)
    return {
        "revision": revision,
        "path": source_path,
        "git_blob_oid": object_id.strip(),
        "byte_count": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
    }


def _diff_record(
    repository: Path,
    before: str,
    after: str,
    source_paths: Sequence[str],
) -> dict[str, object]:
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
            *source_paths,
        ],
    )
    assert isinstance(value, bytes)
    return {
        "before_revision": before,
        "after_revision": after,
        "paths": list(source_paths),
        "byte_count": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
    }


def _changed_paths(repository: Path, revision: str) -> list[str]:
    value = _git(
        repository,
        ["diff-tree", "--no-commit-id", "--name-only", "-r", revision],
        text=True,
    )
    assert isinstance(value, str)
    return [line for line in value.splitlines() if line]


def _numstat(
    repository: Path, before: str, after: str, source_path: str
) -> dict[str, object]:
    value = _git(
        repository,
        ["diff", "--numstat", before, after, "--", source_path],
        text=True,
    )
    assert isinstance(value, str)
    fields = value.strip().split("\t")
    if len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit():
        raise SystemExit(f"unexpected numstat for {source_path}: {value!r}")
    return {
        "path": fields[2],
        "added_lines": int(fields[0]),
        "deleted_lines": int(fields[1]),
    }


def _line_number(source: str, marker: str) -> int:
    matches = [
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one marker {marker!r}, found {matches}")
    return matches[0]


def _direct_variable_name(value: str) -> str | None:
    name = value.split("=", 1)[0].strip()
    if name.startswith(("SERVICE_URL_", "SERVICE_FQDN_")):
        return name
    return None


def _candidate_extract_template_names(
    environment: Sequence[object] | Mapping[object, object],
) -> list[str]:
    """Mirror the candidate's value-only PHP foreach extraction."""

    values = environment.values() if isinstance(environment, Mapping) else environment
    names: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        name = _direct_variable_name(value)
        if name is not None:
            names.append(name)
    return list(dict.fromkeys(names))


def _fixed_extract_template_names(
    environment: Sequence[object] | Mapping[object, object],
) -> list[str]:
    """Mirror the repair's numeric-key/list and string-key/map branches."""

    items = (
        environment.items()
        if isinstance(environment, Mapping)
        else enumerate(environment)
    )
    names: list[str] = []
    for key, value in items:
        name: str | None = None
        if isinstance(key, int) and isinstance(value, str):
            name = _direct_variable_name(value)
        elif isinstance(key, str):
            name = _direct_variable_name(key)
        if name is not None:
            names.append(name)
    return list(dict.fromkeys(names))


def _semantic_witness() -> dict[str, object]:
    list_style: list[object] = [
        "SERVICE_URL_TRIGGER_3000",
        "LOGIN_ORIGIN=${SERVICE_URL_TRIGGER_3000}",
        "OTHER_VAR=value",
    ]
    map_style: dict[object, object] = {
        "SERVICE_URL_TRIGGER_3000": "",
        "SERVICE_FQDN_DB": "localhost",
        "NEXT_PUBLIC_URL": "${SERVICE_URL_TRIGGER_3000}",
    }
    candidate_list = _candidate_extract_template_names(list_style)
    candidate_map = _candidate_extract_template_names(map_style)
    fixed_list = _fixed_extract_template_names(list_style)
    fixed_map = _fixed_extract_template_names(map_style)
    expected_list = ["SERVICE_URL_TRIGGER_3000"]
    expected_map = ["SERVICE_URL_TRIGGER_3000", "SERVICE_FQDN_DB"]
    checks = {
        "candidate_accepts_list_style_direct_declaration": (
            candidate_list == expected_list
        ),
        "candidate_underaccepts_map_style_direct_declarations": (candidate_map == []),
        "repair_preserves_list_style_acceptance": fixed_list == expected_list,
        "repair_accepts_map_style_keys": fixed_map == expected_map,
        "repair_does_not_promote_map_style_reference_values": (
            "NEXT_PUBLIC_URL" not in fixed_map
            and "SERVICE_URL_TRIGGER_3000" in fixed_map
            and fixed_map.count("SERVICE_URL_TRIGGER_3000") == 1
        ),
    }
    return {
        "list_style_environment": list_style,
        "map_style_environment": map_style,
        "candidate_list_extraction": candidate_list,
        "candidate_map_extraction": candidate_map,
        "fixed_list_extraction": fixed_list,
        "fixed_map_extraction": fixed_map,
        "checks": checks,
        "passed": all(checks.values()),
    }


def _evaluate_sources(
    baseline_helper: str,
    candidate_helper: str,
    fix_helper: str,
    candidate_tests: str,
    fix_tests: str,
    template_versions: Mapping[str, tuple[str, str, str]],
) -> dict[str, bool]:
    baseline_generation_markers = (
        "$serviceName = str($resource->name)->upper()",
        '"SERVICE_URL_{$serviceName}%"',
        '"SERVICE_FQDN_{$serviceName}%"',
    )
    candidate_scan_markers = (
        "$environment = data_get($serviceConfig, 'environment', []);",
        "$templateVariableNames = [];",
        CANDIDATE_LOOP,
        "if (is_string($envVar))",
        "$templateVariableNames[] = $envVarName->value();",
    )
    fix_scan_markers = (
        FIX_LOOP,
        "if (is_int($key) && is_string($value))",
        FIX_MAP_BRANCH,
        "$envVarName = str($key);",
    )
    return {
        "baseline_generates_names_without_environment_representation_scan": (
            all(marker in baseline_helper for marker in baseline_generation_markers)
            and "$templateVariableNames = [];" not in baseline_helper
        ),
        "candidate_authors_template_environment_scan": all(
            marker in candidate_helper for marker in candidate_scan_markers
        ),
        "candidate_scan_is_value_only_and_has_no_map_key_branch": (
            FIX_LOOP not in candidate_helper
            and FIX_MAP_BRANCH not in candidate_helper
            and "is_int($key)" not in candidate_helper
        ),
        "repair_replaces_value_only_loop_with_dual_format_loop": (
            CANDIDATE_LOOP not in fix_helper
            and all(marker in fix_helper for marker in fix_scan_markers)
        ),
        "three_map_style_inputs_preexist_candidate_and_remain_unchanged": all(
            marker in baseline
            and marker in candidate
            and marker in repair
            and baseline == candidate == repair
            for path, (baseline, candidate, repair) in template_versions.items()
            for marker in (MAP_TEMPLATE_MARKERS[path],)
        ),
        "candidate_tests_do_not_cover_the_five_map_style_cases": all(
            name not in candidate_tests for name in FIX_TEST_NAMES
        ),
        "repair_tests_add_all_five_map_style_cases": all(
            name in fix_tests for name in FIX_TEST_NAMES
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_helper = _text_blob(repository, BASELINE_SHA, HELPER_PATH)
    candidate_helper = _text_blob(repository, CANDIDATE_SHA, HELPER_PATH)
    fix_parent_helper = _text_blob(repository, f"{FIX_SHA}^", HELPER_PATH)
    fix_helper = _text_blob(repository, FIX_SHA, HELPER_PATH)
    candidate_tests = _text_blob(repository, CANDIDATE_SHA, TEST_PATH)
    fix_tests = _text_blob(repository, FIX_SHA, TEST_PATH)
    template_versions = {
        path: (
            _text_blob(repository, BASELINE_SHA, path),
            _text_blob(repository, CANDIDATE_SHA, path),
            _text_blob(repository, FIX_SHA, path),
        )
        for path in MAP_TEMPLATE_MARKERS
    }

    candidate_metadata = _commit_metadata(repository, CANDIDATE_SHA)
    fix_metadata = _commit_metadata(repository, FIX_SHA)
    evaluation = _evaluate_sources(
        baseline_helper,
        candidate_helper,
        fix_helper,
        candidate_tests,
        fix_tests,
        template_versions,
    )
    semantics = _semantic_witness()
    fix_changed_paths = _changed_paths(repository, FIX_SHA)
    fix_test_numstat = _numstat(repository, CANDIDATE_SHA, FIX_SHA, TEST_PATH)

    line_origins = {
        "candidate_value_only_environment_loop": _blame_line(
            repository,
            CANDIDATE_SHA,
            HELPER_PATH,
            _line_number(candidate_helper, CANDIDATE_LOOP),
            "candidate value-only environment loop",
        ),
        "fix_parent_value_only_environment_loop": _blame_line(
            repository,
            f"{FIX_SHA}^",
            HELPER_PATH,
            _line_number(fix_parent_helper, CANDIDATE_LOOP),
            "value-only loop surviving at fix parent",
        ),
        "repair_dual_format_environment_loop": _blame_line(
            repository,
            FIX_SHA,
            HELPER_PATH,
            _line_number(fix_helper, FIX_LOOP),
            "repair key-value environment loop",
        ),
        "repair_map_style_key_branch": _blame_line(
            repository,
            FIX_SHA,
            HELPER_PATH,
            _line_number(fix_helper, FIX_MAP_BRANCH),
            "repair map-style key branch",
        ),
    }
    template_line_origins = {
        path: _blame_line(
            repository,
            CANDIDATE_SHA,
            path,
            _line_number(template_versions[path][1], marker),
            f"pre-existing map-style declaration in {path}",
        )
        for path, marker in MAP_TEMPLATE_MARKERS.items()
    }
    template_origins_preexist_candidate = all(
        record["origin_sha"] not in {CANDIDATE_SHA, FIX_SHA}
        and _is_ancestor(repository, str(record["origin_sha"]), BASELINE_SHA)
        for record in template_line_origins.values()
    )

    ancestry = {
        "baseline_is_candidate_only_parent": candidate_metadata["parents"]
        == [BASELINE_SHA],
        "candidate_is_fix_only_parent": fix_metadata["parents"] == [CANDIDATE_SHA],
        "baseline_to_candidate": _is_ancestor(repository, BASELINE_SHA, CANDIDATE_SHA),
        "candidate_to_fix": _is_ancestor(repository, CANDIDATE_SHA, FIX_SHA),
    }
    survival = {
        "fix_parent_sha": str(fix_metadata["parents"][0]),
        "fix_parent_is_candidate": fix_metadata["parents"] == [CANDIDATE_SHA],
        "fix_parent_helper_equals_candidate_helper": (
            fix_parent_helper == candidate_helper
        ),
        "bad_loop_origin_at_candidate": (
            line_origins["candidate_value_only_environment_loop"]["origin_sha"]
            == CANDIDATE_SHA
        ),
        "bad_loop_origin_unchanged_at_fix_parent": (
            line_origins["fix_parent_value_only_environment_loop"]["origin_sha"]
            == CANDIDATE_SHA
        ),
    }
    test_attribution = {
        "fix_changed_paths": fix_changed_paths,
        "fix_changes_only_helper_and_target_test": set(fix_changed_paths)
        == {HELPER_PATH, TEST_PATH},
        "fix_test_numstat": fix_test_numstat,
        "fix_adds_test_lines_without_deleting_existing_tests": (
            fix_test_numstat["added_lines"] > 0
            and fix_test_numstat["deleted_lines"] == 0
        ),
        "fix_message_names_map_style_update_compose": (
            "handle map-style environment variables in updateCompose"
            in str(fix_metadata["message"])
        ),
        "five_targeted_test_names": list(FIX_TEST_NAMES),
    }

    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and "Parse template variables directly" in str(candidate_metadata["message"])
        and all(ancestry.values())
        and all(evaluation.values())
        and semantics["passed"] is True
        and all(value for key, value in survival.items() if key != "fix_parent_sha")
        and test_attribution["fix_changes_only_helper_and_target_test"] is True
        and test_attribution["fix_adds_test_lines_without_deleting_existing_tests"]
        is True
        and test_attribution["fix_message_names_map_style_update_compose"] is True
        and line_origins["repair_dual_format_environment_loop"]["origin_sha"] == FIX_SHA
        and line_origins["repair_map_style_key_branch"]["origin_sha"] == FIX_SHA
        and template_origins_preexist_candidate
    )

    source_blobs = [
        _blob_record(repository, revision, HELPER_PATH)
        for revision in (BASELINE_SHA, CANDIDATE_SHA, FIX_SHA)
    ]
    source_blobs.extend(
        _blob_record(repository, revision, TEST_PATH)
        for revision in (CANDIDATE_SHA, FIX_SHA)
    )
    source_blobs.extend(
        _blob_record(repository, revision, path)
        for path in MAP_TEMPLATE_MARKERS
        for revision in (BASELINE_SHA, CANDIDATE_SHA, FIX_SHA)
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_update_compose_map_style_origin_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": CANDIDATE_SHA,
        "fix_sha": FIX_SHA,
        "candidate_metadata": candidate_metadata,
        "fix_metadata": fix_metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "semantic_witness": semantics,
        "fix_parent_survival": survival,
        "test_attribution": test_attribution,
        "line_origins": line_origins,
        "template_line_origins": template_line_origins,
        "template_origins_preexist_candidate": template_origins_preexist_candidate,
        "source_blobs": source_blobs,
        "diffs": {
            "candidate_helper": _diff_record(
                repository, BASELINE_SHA, CANDIDATE_SHA, (HELPER_PATH,)
            ),
            "repair_helper_and_tests": _diff_record(
                repository, CANDIDATE_SHA, FIX_SHA, (HELPER_PATH, TEST_PATH)
            ),
        },
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_DIRECT_AI_UPDATE_COMPOSE_MAP_STYLE_UNDERACCEPTANCE"
        ),
        "mechanism_group": MECHANISM_GROUP,
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude candidate replaces environment-representation-independent "
            "resource-name generation with a new template-variable extraction stage, "
            "but reads only foreach values. Existing map-style SERVICE_URL keys in "
            "trigger, langfuse, and paymenter are therefore invisible, while list-style "
            "declarations remain accepted. The candidate is the repair's only parent, "
            "so the value-only loop survives unchanged to the fix parent. The repair "
            "changes that exact loop to distinguish numeric list keys from string map "
            "keys and adds five directly targeted tests. This proves direct origin of "
            "the updateCompose map-style underacceptance. It does not assert a full "
            "Laravel deployment reproduction for every template, security impact, or "
            "a unique advisory increment."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify updateCompose map-style witness failed")

    print("Coolify updateCompose map-style origin witness frozen")
    print(f"  candidate: {CANDIDATE_SHA}")
    print(f"  fix      : {FIX_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
