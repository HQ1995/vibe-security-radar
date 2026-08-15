#!/usr/bin/env python3
"""Freeze the Coolify buildtime.env duplicate-origin reattribution witness."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)


REPOSITORY_IDENTITY = "github.com/coollabsio/coolify"
PROMOTED_CANDIDATE_PARENT_SHA = "23c1184e86c44f10b32f86666a373414615771b9"
PROMOTED_CANDIDATE_SHA = "41afa9568d5ed2dcf56b42791ee941dbf1931fbf"
ACTUAL_ORIGIN_PARENT_SHA = "2921fe907de4beb9ac80c6bf76f8b08be78c65b1"
ACTUAL_ORIGIN_SHA = "ef332b9af488a6249aa0ee5021d1653d9ac8f9a4"
FIX_SHA = "be2b01786ac08b69f40646d4dac4f168b04e5197"

SOURCE_PATH = "app/Jobs/ApplicationDeploymentJob.php"
AI_SCAN_FILENAME = "commits.jsonl"

SEQUENTIAL_INIT = "$envs = collect([]);"
NIXPACKS_FILTER = "->where('key', 'not like', 'NIXPACKS_%')"
PLAN_LOOKUP = "$planVariables = data_get($this->nixpacks_plan_json, 'variables', []);"
PLAN_LOOP = "foreach ($planVariables as $key => $value) {"
PLAN_PUSH = "$envs->push($key.'='.$escapedValue);"
USER_PUSH = "$envs->push($env->key.'='.$escapedValue);"

DICT_INIT = "$envs_dict = [];"
PLAN_DICT_ASSIGNMENT = "$envs_dict[$key] = $escapedValue;"
USER_DICT_ASSIGNMENT = "$envs_dict[$env->key] = $escapedValue;"
DICT_COLLECTION_LOOP = "foreach ($envs_dict as $key => $value) {"

EXPECTED_OVERLAP_LINES = frozenset(
    {
        "$envs->push($key.'='.escapeBashEnvValue($item));",
        "$envs->push('SERVICE_NAME_'.str($serviceName)->upper().'='.escapeBashEnvValue($serviceName));",
        "$envs->push('SERVICE_URL_'.str($forServiceName)->upper().'='.escapeBashEnvValue($coolifyUrl->__toString()));",
        "$envs->push('SERVICE_FQDN_'.str($forServiceName)->upper().'='.escapeBashEnvValue($coolifyFqdn));",
        "$envs->push('SERVICE_NAME_'.str($rawServiceName)->upper().'='.escapeBashEnvValue(addPreviewDeploymentSuffix($rawServiceName, $this->pull_request_id)));",
        USER_PUSH,
    }
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _source(repository: Path, revision: str) -> str:
    return _git_blob(repository, revision, SOURCE_PATH).decode("utf-8", errors="strict")


def _diff(repository: Path, before: str, after: str) -> str:
    value = _git(
        repository,
        [
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--no-renames",
            "--unified=0",
            before,
            after,
            "--",
            SOURCE_PATH,
        ],
        text=True,
    )
    assert isinstance(value, str)
    return value


def _changed_lines(diff: str) -> tuple[list[str], list[str]]:
    added: list[str] = []
    removed: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added.append(line[1:].strip())
        elif line.startswith("-"):
            removed.append(line[1:].strip())
    return added, removed


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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise SystemExit(f"{path}:{line_number}: expected object")
            rows.append(row)
    return rows


def _snapshot(source: str) -> dict[str, object]:
    if "private function generate_buildtime_environment_variables()" in source:
        source = _php_method_region(source, "generate_buildtime_environment_variables")
    plan_position = source.find(PLAN_DICT_ASSIGNMENT)
    user_position = source.find(USER_DICT_ASSIGNMENT)
    snapshot = {
        "sequential_collection_count": source.count(SEQUENTIAL_INIT),
        "nixpacks_user_filter_count": source.count(NIXPACKS_FILTER),
        "plan_lookup_count": source.count(PLAN_LOOKUP),
        "plan_loop_count": source.count(PLAN_LOOP),
        "plan_sequential_push_count": source.count(PLAN_PUSH),
        "user_sequential_push_count": source.count(USER_PUSH),
        "dictionary_init_count": source.count(DICT_INIT),
        "plan_dictionary_assignment_count": source.count(PLAN_DICT_ASSIGNMENT),
        "user_dictionary_assignment_count": source.count(USER_DICT_ASSIGNMENT),
        "dictionary_collection_loop_count": source.count(DICT_COLLECTION_LOOP),
        "plan_precedes_user_dictionary_assignment": (
            plan_position >= 0 and user_position > plan_position
        ),
        "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }
    snapshot["duplicate_plan_user_mechanism_active"] = bool(
        snapshot["sequential_collection_count"] == 1
        and snapshot["plan_lookup_count"] == 1
        and snapshot["plan_loop_count"] == 1
        and snapshot["plan_sequential_push_count"] == 1
        and snapshot["user_sequential_push_count"] >= 2
        and snapshot["nixpacks_user_filter_count"] == 0
    )
    snapshot["unique_key_override_contract_active"] = bool(
        snapshot["dictionary_init_count"] == 1
        and snapshot["plan_dictionary_assignment_count"] == 1
        and snapshot["user_dictionary_assignment_count"] >= 2
        and snapshot["dictionary_collection_loop_count"] == 1
        and snapshot["plan_precedes_user_dictionary_assignment"] is True
        and snapshot["plan_sequential_push_count"] == 0
        and snapshot["user_sequential_push_count"] == 0
    )
    return snapshot


def _evaluate_states(
    candidate_parent: str,
    candidate: str,
    origin_parent: str,
    origin: str,
    fix_parent: str,
    fixed: str,
) -> dict[str, object]:
    snapshots = {
        "promoted_candidate_parent": _snapshot(candidate_parent),
        "promoted_candidate": _snapshot(candidate),
        "actual_origin_parent": _snapshot(origin_parent),
        "actual_origin": _snapshot(origin),
        "fix_parent": _snapshot(fix_parent),
        "fix": _snapshot(fixed),
    }
    candidate_parent_state = snapshots["promoted_candidate_parent"]
    candidate_state = snapshots["promoted_candidate"]
    origin_parent_state = snapshots["actual_origin_parent"]
    origin_state = snapshots["actual_origin"]
    fix_parent_state = snapshots["fix_parent"]
    fixed_state = snapshots["fix"]
    checks = {
        "candidate_parent_has_sequential_sink_but_excludes_nixpacks_users": (
            candidate_parent_state["sequential_collection_count"] == 1
            and candidate_parent_state["nixpacks_user_filter_count"] == 2
            and candidate_parent_state["plan_lookup_count"] == 0
        ),
        "promoted_candidate_still_excludes_nixpacks_users_and_has_no_plan_source": (
            candidate_state["sequential_collection_count"] == 1
            and candidate_state["nixpacks_user_filter_count"] == 2
            and candidate_state["plan_lookup_count"] == 0
        ),
        "duplicate_mechanism_absent_before_and_after_promoted_candidate": (
            candidate_parent_state["duplicate_plan_user_mechanism_active"] is False
            and candidate_state["duplicate_plan_user_mechanism_active"] is False
        ),
        "origin_parent_still_excludes_duplicate_mechanism": (
            origin_parent_state["nixpacks_user_filter_count"] == 2
            and origin_parent_state["plan_lookup_count"] == 0
            and origin_parent_state["duplicate_plan_user_mechanism_active"] is False
        ),
        "intervening_origin_activates_plan_user_duplicate_mechanism": (
            origin_state["nixpacks_user_filter_count"] == 0
            and origin_state["plan_lookup_count"] == 1
            and origin_state["plan_sequential_push_count"] == 1
            and origin_state["user_sequential_push_count"] >= 2
            and origin_state["duplicate_plan_user_mechanism_active"] is True
        ),
        "origin_state_survives_byte_exact_to_fix_parent": (
            origin == fix_parent and origin_state == fix_parent_state
        ),
        "fix_replaces_duplicate_sequence_with_unique_key_override_contract": (
            fixed_state["duplicate_plan_user_mechanism_active"] is False
            and fixed_state["unique_key_override_contract_active"] is True
        ),
    }
    return {"snapshots": snapshots, "checks": checks}


def _evaluate_transitions(
    candidate_diff: str,
    origin_diff: str,
    fix_diff: str,
) -> dict[str, object]:
    candidate_added, candidate_removed = _changed_lines(candidate_diff)
    origin_added, origin_removed = _changed_lines(origin_diff)
    fix_added, fix_removed = _changed_lines(fix_diff)
    overlap_lines = sorted(
        set(candidate_added) & set(fix_removed) & EXPECTED_OVERLAP_LINES
    )
    checks = {
        "promoted_candidate_has_expected_exact_fix_overlap": set(overlap_lines)
        == EXPECTED_OVERLAP_LINES,
        "promoted_candidate_delta_does_not_add_plan_source": not any(
            marker in line
            for line in candidate_added
            for marker in ("nixpacks_plan_json", "$planVariables", PLAN_LOOP)
        ),
        "promoted_candidate_delta_does_not_remove_nixpacks_filter": NIXPACKS_FILTER
        not in candidate_removed,
        "actual_origin_delta_adds_plan_sequence": all(
            marker in origin_added for marker in (PLAN_LOOKUP, PLAN_LOOP, PLAN_PUSH)
        ),
        "actual_origin_delta_removes_both_nixpacks_filters": origin_removed.count(
            NIXPACKS_FILTER
        )
        == 2,
        "fix_delta_removes_plan_and_user_pushes": (
            PLAN_PUSH in fix_removed and USER_PUSH in fix_removed
        ),
        "fix_delta_adds_plan_and_user_dictionary_assignments": (
            PLAN_DICT_ASSIGNMENT in fix_added and USER_DICT_ASSIGNMENT in fix_added
        ),
    }
    return {
        "checks": checks,
        "exact_promoted_candidate_fix_overlap_lines": overlap_lines,
        "line_counts": {
            "promoted_candidate_added": len(candidate_added),
            "promoted_candidate_removed": len(candidate_removed),
            "actual_origin_added": len(origin_added),
            "actual_origin_removed": len(origin_removed),
            "fix_added": len(fix_added),
            "fix_removed": len(fix_removed),
        },
    }


def _evaluate_ai_membership(observed_ai: set[str]) -> dict[str, bool]:
    return {
        "promoted_candidate_is_observed_ai": PROMOTED_CANDIDATE_SHA in observed_ai,
        "actual_origin_is_not_observed_ai": ACTUAL_ORIGIN_SHA not in observed_ai,
        "fix_is_observed_ai": FIX_SHA in observed_ai,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    ai_scan_path = args.ai_scan_dir.resolve() / AI_SCAN_FILENAME
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    if not ai_scan_path.is_file():
        raise SystemExit(f"AI scan commits file does not exist: {ai_scan_path}")

    sources = {
        "promoted_candidate_parent": _source(repository, PROMOTED_CANDIDATE_PARENT_SHA),
        "promoted_candidate": _source(repository, PROMOTED_CANDIDATE_SHA),
        "actual_origin_parent": _source(repository, ACTUAL_ORIGIN_PARENT_SHA),
        "actual_origin": _source(repository, ACTUAL_ORIGIN_SHA),
        "fix_parent": _source(repository, ACTUAL_ORIGIN_SHA),
        "fix": _source(repository, FIX_SHA),
    }
    states = _evaluate_states(
        sources["promoted_candidate_parent"],
        sources["promoted_candidate"],
        sources["actual_origin_parent"],
        sources["actual_origin"],
        sources["fix_parent"],
        sources["fix"],
    )
    transitions = _evaluate_transitions(
        _diff(repository, PROMOTED_CANDIDATE_PARENT_SHA, PROMOTED_CANDIDATE_SHA),
        _diff(repository, ACTUAL_ORIGIN_PARENT_SHA, ACTUAL_ORIGIN_SHA),
        _diff(repository, ACTUAL_ORIGIN_SHA, FIX_SHA),
    )

    metadata = {
        "promoted_candidate": _commit_metadata(repository, PROMOTED_CANDIDATE_SHA),
        "actual_origin": _commit_metadata(repository, ACTUAL_ORIGIN_SHA),
        "fix": _commit_metadata(repository, FIX_SHA),
    }
    candidate_message = str(metadata["promoted_candidate"]["message"])
    origin_message = str(metadata["actual_origin"]["message"])
    fix_message = str(metadata["fix"]["message"])
    metadata_checks = {
        "promoted_candidate_parent_is_exact": metadata["promoted_candidate"]["parents"]
        == [PROMOTED_CANDIDATE_PARENT_SHA],
        "actual_origin_parent_is_exact": metadata["actual_origin"]["parents"]
        == [ACTUAL_ORIGIN_PARENT_SHA],
        "fix_parent_is_actual_origin_exactly": metadata["fix"]["parents"]
        == [ACTUAL_ORIGIN_SHA],
        "promoted_candidate_message_is_null_escaping_scoped": (
            candidate_message.startswith(
                "fix: handle null environment variable values in bash escaping"
            )
            and "duplicate" not in candidate_message.casefold()
            and "nixpacks plan" not in candidate_message.casefold()
        ),
        "actual_origin_message_names_nixpacks_plan_addition": origin_message
        == "fix: add support for nixpacks plan variables in buildtime environment",
        "fix_message_names_duplicate_root_cause_and_plan_user_collision": all(
            marker in fix_message
            for marker in (
                "prevent duplicate environment variables in buildtime.env",
                "After adding nixpacks plan variables",
                "Once from nixpacks plan",
                "Once from user-defined variables",
                "push() method adds items sequentially",
            )
        ),
    }

    candidate_to_fix_distance = _commit_distance(
        repository, PROMOTED_CANDIDATE_SHA, FIX_SHA
    )
    origin_to_fix_distance = _commit_distance(repository, ACTUAL_ORIGIN_SHA, FIX_SHA)
    topology_checks = {
        "promoted_candidate_strictly_precedes_actual_origin": (
            PROMOTED_CANDIDATE_SHA != ACTUAL_ORIGIN_SHA
            and _is_ancestor(repository, PROMOTED_CANDIDATE_SHA, ACTUAL_ORIGIN_SHA)
        ),
        "promoted_candidate_is_not_direct_fix_parent": metadata["fix"]["parents"]
        != [PROMOTED_CANDIDATE_SHA],
        "many_commits_intervene_after_promoted_candidate": candidate_to_fix_distance
        > 1,
        "actual_origin_is_immediate_fix_parent": origin_to_fix_distance == 1,
        "fix_does_not_precede_actual_origin": not _is_ancestor(
            repository, FIX_SHA, ACTUAL_ORIGIN_SHA
        ),
    }
    path_checks = {
        "promoted_candidate_changes_expected_three_paths": _changed_paths(
            repository, PROMOTED_CANDIDATE_SHA
        )
        == [
            SOURCE_PATH,
            "bootstrap/helpers/docker.php",
            "tests/Unit/BashEnvEscapingTest.php",
        ],
        "actual_origin_changes_only_deployment_job": _changed_paths(
            repository, ACTUAL_ORIGIN_SHA
        )
        == [SOURCE_PATH],
        "fix_changes_only_deployment_job": _changed_paths(repository, FIX_SHA)
        == [SOURCE_PATH],
    }

    ai_rows = _load_jsonl(ai_scan_path)
    observed_ai = {str(row.get("sha") or "") for row in ai_rows}
    ai_membership_checks = _evaluate_ai_membership(observed_ai)
    check_groups: dict[str, Mapping[str, object]] = {
        "states": states["checks"],
        "transitions": transitions["checks"],
        "metadata": metadata_checks,
        "topology": topology_checks,
        "paths": path_checks,
        "ai_membership": ai_membership_checks,
    }
    witness_passed = all(
        value is True for checks in check_groups.values() for value in checks.values()
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_buildtime_env_duplicate_reattribution_witness",
        "repository_identity": REPOSITORY_IDENTITY,
        "source_path": SOURCE_PATH,
        "metadata": metadata,
        "states": states,
        "transitions": transitions,
        "topology": {
            "promoted_candidate_to_fix_commit_count_including_fix": candidate_to_fix_distance,
            "actual_origin_to_fix_commit_count_including_fix": origin_to_fix_distance,
            "actual_origin_to_fix_intervening_commit_count": origin_to_fix_distance - 1,
        },
        "checks": check_groups,
        "promoted_edge": {
            "candidate_sha": PROMOTED_CANDIDATE_SHA,
            "fix_sha": FIX_SHA,
            "adjudication": "REJECTED_NONCAUSAL_EXACT_OVERLAP_INTERVENING_ORIGIN",
            "candidate_retained_for_recall": True,
            "counted_ai_true_positive": False,
            "reason": (
                "The exact-overlap lines are preexisting sequential sinks whose "
                "values the promoted candidate escaped. That candidate neither "
                "adds the nixpacks plan producer nor removes the NIXPACKS user "
                "filters, so the repaired duplicate-key mechanism is absent in "
                "both its parent and its result."
            ),
        },
        "replacement_edge": {
            "candidate_sha": ACTUAL_ORIGIN_SHA,
            "fix_sha": FIX_SHA,
            "adjudication": "CONFIRMED_NON_OBSERVED_AI_CODE_CAUSAL_REPLACEMENT",
            "causal_role": "INTERVENING_DIRECT_FIX_PARENT_ORIGIN",
            "observed_ai": False,
            "counted_ai_true_positive": False,
            "mechanism_group": "nixpacks_plan_user_buildtime_env_duplicate_key",
            "claim": (
                "The non-observed-AI direct fix parent adds a sequential nixpacks "
                "plan producer and removes both NIXPACKS user exclusions. The fix "
                "replaces the two append lanes with one key-indexed dictionary, "
                "using plan-first and user-last assignment order."
            ),
        },
        "counting": {
            "audited_promoted_edge_count": 1,
            "rejected_promoted_edge_count": 1,
            "code_causal_replacement_edge_count": 1,
            "observed_ai_replacement_edge_count": 0,
            "ai_true_positive_edge_count": 0,
            "unique_ai_candidate_true_positive_count": 0,
            "model_call_count": 0,
            "ledger_mutation_count": 0,
        },
        "source_artifacts": {
            "ai_scan_commits": {
                "path": str(ai_scan_path),
                "sha256": _sha256(ai_scan_path),
                "observed_commit_count": len(observed_ai),
            }
        },
        "witness_passed": witness_passed,
        "claim_boundary": (
            "This witness rejects causal ownership by the observed-AI escaping "
            "candidate while retaining it as a recall candidate. It reattributes "
            "the code-level duplicate-key mechanism to the fix's immediate parent, "
            "which is absent from the frozen observed-AI scan, so the replacement "
            "does not increment AI true positives. Absence from that scan is not "
            "proof of human authorship. The witness does not establish deployment "
            "frequency, issue severity, or security impact."
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
            "Coolify buildtime.env duplicate reattribution witness failed: "
            + ", ".join(failed)
        )
    print("Coolify buildtime.env duplicate reattribution witness frozen")
    print(f"  rejected   : {PROMOTED_CANDIDATE_SHA} -> {FIX_SHA}")
    print(f"  replacement: {ACTUAL_ORIGIN_SHA} -> {FIX_SHA} (non-observed-AI)")
    print(f"  output     : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
