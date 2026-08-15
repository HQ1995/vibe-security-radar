#!/usr/bin/env python3
"""Freeze two evidence-backed non-causal Coolify AI candidate adjudications."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)


SECURITY_REPAIR_SHA = "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486"

VALIDATION_CANDIDATE_SHA = "cb1f571eb4b36da153d559246534f75683117299"
VALIDATION_BASELINE_SHA = "988c08f2d1b22ea8bfe4ceece23041d27cce3e8c"
VALIDATION_SOURCE_PATH = "app/Livewire/Project/New/DockerCompose.php"

UI_ALIAS_CANDIDATE_SHA = "66cff9d9b84def9cf3a600ef637a51a8c35d9a2a"
UI_ALIAS_BASELINE_SHA = "6d3c996ef374a8827eaf0e14318570344522420c"
UI_ALIAS_SOURCE_PATH = "app/Livewire/GlobalSearch.php"
UI_ALIAS_VIEW_PATH = "resources/views/livewire/global-search.blade.php"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _added_lines(diff: str) -> list[str]:
    return [
        line[1:]
        for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]


def _line_number(source: str, marker: str) -> int:
    matches = [
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one marker {marker!r}, found {matches}")
    return matches[0]


def _blame_origin(
    repository: Path, revision: str, source_path: str, marker: str
) -> dict[str, object]:
    source = _git_blob(repository, revision, source_path).decode("utf-8")
    line = _line_number(source, marker)
    value = _git(
        repository,
        [
            "blame",
            "--line-porcelain",
            "-L",
            f"{line},{line}",
            revision,
            "--",
            source_path,
        ],
        text=True,
    )
    assert isinstance(value, str)
    return {
        "path": source_path,
        "line": line,
        "marker": marker,
        "origin_sha": value.split(None, 1)[0].lstrip("^"),
    }


def _evaluate_unchanged_context(
    baseline_source: str,
    candidate_source: str,
    repair_source: str,
    candidate_diff: str,
) -> dict[str, object]:
    unscoped_lookup = (
        "$project = Project::where('uuid', "
        "$this->parameters['project_uuid'])->first();"
    )
    scoped_lookup = (
        "$project = Project::ownedByCurrentTeam()->where('uuid', "
        "$this->parameters['project_uuid'])->first();"
    )
    additions = _added_lines(candidate_diff)
    return {
        "baseline_unscoped_lookup_present": unscoped_lookup in baseline_source,
        "candidate_unscoped_lookup_present": unscoped_lookup in candidate_source,
        "repair_scoped_lookup_present": scoped_lookup in repair_source,
        "candidate_adds_pre_save_command_injection_validation": any(
            "validateDockerComposeForInjection($this->dockerComposeRaw)" in line
            for line in additions
        ),
        "candidate_adds_or_changes_project_lookup": any(
            "Project::" in line and "$project" in line for line in additions
        ),
    }


def _method_sha256(source: str, method_name: str) -> str:
    return hashlib.sha256(_php_method_region(source, method_name).encode()).hexdigest()


def _evaluate_ui_alias(
    baseline_source: str,
    candidate_source: str,
    repair_source: str,
    baseline_view: str,
    candidate_view: str,
    candidate_source_diff: str,
) -> dict[str, object]:
    baseline_destinations = _php_method_region(baseline_source, "loadDestinations")
    candidate_destinations = _php_method_region(candidate_source, "loadDestinations")
    baseline_environments = _php_method_region(baseline_source, "loadEnvironments")
    candidate_environments = _php_method_region(candidate_source, "loadEnvironments")
    additions = _added_lines(candidate_source_diff)
    return {
        "preexisting_equivalent_docker_image_command": (
            "'new docker image'" in baseline_view
        ),
        "preexisting_name_based_command_resolution": (
            "const itemSearchText = `new ${item.name}`.toLowerCase();" in baseline_view
            and "itemSearchText === trimmed" in baseline_view
        ),
        "candidate_adds_new_image_quickcommand_resolution": (
            "item.quickcommand && item.quickcommand.toLowerCase().includes(trimmed)"
            in candidate_view
        ),
        "preexisting_resource_creation_entrypoint": (
            "function navigateToResourceCreation" in baseline_source
        ),
        "destinations_method_unchanged": (
            baseline_destinations == candidate_destinations
        ),
        "environments_method_unchanged": (
            baseline_environments == candidate_environments
        ),
        "destinations_method_sha256": _method_sha256(
            candidate_source, "loadDestinations"
        ),
        "environments_method_sha256": _method_sha256(
            candidate_source, "loadEnvironments"
        ),
        "candidate_adds_server_or_project_lookup": any(
            "Server::" in line or "Project::" in line for line in additions
        ),
        "repair_scopes_server_lookup": (
            "Server::ownedByCurrentTeam()->find($this->selectedServerId)"
            in repair_source
        ),
        "repair_scopes_project_lookup": (
            "Project::ownedByCurrentTeam()->where('uuid', "
            "$this->selectedProjectUuid)->first()" in repair_source
        ),
    }


def _diff(repository: Path, baseline: str, candidate: str, *paths: str) -> str:
    value = _git(
        repository,
        ["diff", baseline, candidate, "--", *paths],
        text=True,
    )
    assert isinstance(value, str)
    return value


def _unchanged_context_case(repository: Path) -> dict[str, object]:
    baseline = _git_blob(
        repository, VALIDATION_BASELINE_SHA, VALIDATION_SOURCE_PATH
    ).decode("utf-8")
    candidate = _git_blob(
        repository, VALIDATION_CANDIDATE_SHA, VALIDATION_SOURCE_PATH
    ).decode("utf-8")
    repair = _git_blob(
        repository, SECURITY_REPAIR_SHA, VALIDATION_SOURCE_PATH
    ).decode("utf-8")
    evaluation = _evaluate_unchanged_context(
        baseline,
        candidate,
        repair,
        _diff(
            repository,
            VALIDATION_BASELINE_SHA,
            VALIDATION_CANDIDATE_SHA,
            VALIDATION_SOURCE_PATH,
        ),
    )
    lookup_marker = (
        "$project = Project::where('uuid', "
        "$this->parameters['project_uuid'])->first();"
    )
    lookup_origin = _blame_origin(
        repository,
        VALIDATION_CANDIDATE_SHA,
        VALIDATION_SOURCE_PATH,
        lookup_marker,
    )
    candidate_metadata = _commit_metadata(repository, VALIDATION_CANDIDATE_SHA)
    passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"] == [VALIDATION_BASELINE_SHA]
        and _is_ancestor(
            repository, VALIDATION_CANDIDATE_SHA, SECURITY_REPAIR_SHA
        )
        and evaluation["baseline_unscoped_lookup_present"] is True
        and evaluation["candidate_unscoped_lookup_present"] is True
        and evaluation["repair_scoped_lookup_present"] is True
        and evaluation["candidate_adds_pre_save_command_injection_validation"]
        is True
        and evaluation["candidate_adds_or_changes_project_lookup"] is False
        and lookup_origin["origin_sha"] != VALIDATION_CANDIDATE_SHA
    )
    return {
        "candidate_sha": VALIDATION_CANDIDATE_SHA,
        "fix_shas": [
            SECURITY_REPAIR_SHA,
            "3ba4553df5657582ad720a6572d83383fe89c078",
        ],
        "adjudication": "REJECTED_UNCHANGED_CONTEXT_NOT_CAUSAL_DELTA",
        "candidate_retained": True,
        "candidate_metadata": candidate_metadata,
        "lookup_line_origin": lookup_origin,
        "evaluation": evaluation,
        "witness_passed": passed,
        "reason": (
            "The AI delta adds command-injection validation but leaves the unscoped "
            "project lookup byte-for-byte present from its parent. Later team-scope "
            "repairs modify that pre-existing lookup, so diff context is not causal."
        ),
    }


def _ui_alias_case(repository: Path) -> dict[str, object]:
    baseline_source = _git_blob(
        repository, UI_ALIAS_BASELINE_SHA, UI_ALIAS_SOURCE_PATH
    ).decode("utf-8")
    candidate_source = _git_blob(
        repository, UI_ALIAS_CANDIDATE_SHA, UI_ALIAS_SOURCE_PATH
    ).decode("utf-8")
    repair_source = _git_blob(
        repository, SECURITY_REPAIR_SHA, UI_ALIAS_SOURCE_PATH
    ).decode("utf-8")
    baseline_view = _git_blob(
        repository, UI_ALIAS_BASELINE_SHA, UI_ALIAS_VIEW_PATH
    ).decode("utf-8")
    candidate_view = _git_blob(
        repository, UI_ALIAS_CANDIDATE_SHA, UI_ALIAS_VIEW_PATH
    ).decode("utf-8")
    evaluation = _evaluate_ui_alias(
        baseline_source,
        candidate_source,
        repair_source,
        baseline_view,
        candidate_view,
        _diff(
            repository,
            UI_ALIAS_BASELINE_SHA,
            UI_ALIAS_CANDIDATE_SHA,
            UI_ALIAS_SOURCE_PATH,
        ),
    )
    lookup_origins = {
        "server": _blame_origin(
            repository,
            UI_ALIAS_CANDIDATE_SHA,
            UI_ALIAS_SOURCE_PATH,
            "Server::find($this->selectedServerId)",
        ),
        "project": _blame_origin(
            repository,
            UI_ALIAS_CANDIDATE_SHA,
            UI_ALIAS_SOURCE_PATH,
            "Project::where('uuid', $this->selectedProjectUuid)->first()",
        ),
    }
    candidate_metadata = _commit_metadata(repository, UI_ALIAS_CANDIDATE_SHA)
    passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"] == [UI_ALIAS_BASELINE_SHA]
        and _is_ancestor(repository, UI_ALIAS_CANDIDATE_SHA, SECURITY_REPAIR_SHA)
        and evaluation["preexisting_equivalent_docker_image_command"] is True
        and evaluation["preexisting_name_based_command_resolution"] is True
        and evaluation["candidate_adds_new_image_quickcommand_resolution"] is True
        and evaluation["preexisting_resource_creation_entrypoint"] is True
        and evaluation["destinations_method_unchanged"] is True
        and evaluation["environments_method_unchanged"] is True
        and evaluation["candidate_adds_server_or_project_lookup"] is False
        and evaluation["repair_scopes_server_lookup"] is True
        and evaluation["repair_scopes_project_lookup"] is True
        and all(
            value["origin_sha"] != UI_ALIAS_CANDIDATE_SHA
            for value in lookup_origins.values()
        )
    )
    return {
        "candidate_sha": UI_ALIAS_CANDIDATE_SHA,
        "fix_shas": [SECURITY_REPAIR_SHA],
        "adjudication": "REJECTED_EQUIVALENT_UI_ALIAS_TO_PREEXISTING_SECURITY_PATH",
        "candidate_retained": True,
        "candidate_metadata": candidate_metadata,
        "lookup_line_origins": lookup_origins,
        "evaluation": evaluation,
        "witness_passed": passed,
        "reason": (
            "The AI delta makes the shorter 'new image' alias resolve, but the "
            "equivalent 'new docker image' trigger and resource-creation flow already "
            "worked. Both unscoped lookup methods are unchanged and predate this "
            "commit, so the alias is not an independent security path extension."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    cases = [
        _unchanged_context_case(repository),
        _ui_alias_case(repository),
    ]
    witness_passed = all(case["witness_passed"] is True for case in cases)
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_noncausal_ai_candidate_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "security_repair_sha": SECURITY_REPAIR_SHA,
        "cases": cases,
        "witness_passed": witness_passed,
        "conservation": {
            "candidate_count": len(cases),
            "candidate_retained_count": sum(
                case["candidate_retained"] is True for case in cases
            ),
            "hard_delete_count": 0,
            "passed": all(case["candidate_retained"] is True for case in cases),
        },
        "claim_boundary": (
            "These are exact-edge negative adjudications, not heuristic hard filters. "
            "They prevent two demonstrated model failure modes from inflating TP "
            "counts while keeping both candidates in the conserved inventory."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify non-causal AI candidate witness frozen")
    for case in cases:
        print(
            f"  {str(case['candidate_sha'])[:12]}: "
            f"{case['adjudication']} "
            f"({'PASS' if case['witness_passed'] else 'FAIL'})"
        )
    print(f"  output: {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
