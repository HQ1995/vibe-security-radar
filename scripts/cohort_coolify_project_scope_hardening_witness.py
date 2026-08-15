#!/usr/bin/env python3
"""Freeze two Coolify AI project-scope hardening causal witnesses."""

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


AI_SCOPE_SHA = "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486"
ONBOARDING_REPAIR_SHA = "3ba4553df5657582ad720a6572d83383fe89c078"
DESTINATION_REPAIR_SHA = "a478ac66eb7037837c178d64006f83a13eca12d2"

BOARDING_PATH = "app/Livewire/Boarding/Index.php"
CROSS_TEAM_TEST_PATH = "tests/Feature/CrossTeamIdorServerProjectTest.php"
DESTINATION_TEST_PATH = "tests/Feature/TeamScopedDestinationTest.php"
RESOURCE_PROOF_TEST_PATH = "tests/Feature/TeamScopedResourceProofsTest.php"
RESOURCE_PATHS = (
    "app/Livewire/Project/New/DockerCompose.php",
    "app/Livewire/Project/New/DockerImage.php",
    "app/Livewire/Project/New/GithubPrivateRepository.php",
    "app/Livewire/Project/New/GithubPrivateRepositoryDeployKey.php",
    "app/Livewire/Project/New/PublicGitRepository.php",
    "app/Livewire/Project/New/SimpleDockerfile.php",
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


def _method_line(source: str, method_name: str, marker: str) -> int:
    region = _php_method_region(source, method_name)
    marker_offset = region.find(marker)
    if marker_offset < 0:
        raise SystemExit(f"expected marker {marker!r} in method {method_name}")
    region_offset = source.find(region)
    if region_offset < 0:
        raise SystemExit(f"cannot locate method {method_name} in source")
    return source[: region_offset + marker_offset].count("\n") + 1


def _test_region(source: str, start_marker: str, end_marker: str) -> str:
    start = source.find(start_marker)
    if start < 0:
        raise ValueError(f"missing test marker: {start_marker}")
    end = source.find(end_marker, start + len(start_marker))
    if end < 0:
        raise ValueError(f"missing following test marker: {end_marker}")
    return source[start:end]


def _project_line(method: str) -> str:
    return next(
        (line.strip() for line in method.splitlines() if "Project::" in line),
        "",
    )


def _evaluate_onboarding(
    baseline_component: str,
    candidate_component: str,
    repair_component: str,
    candidate_test: str,
    repair_test: str,
) -> dict[str, bool]:
    baseline_select = _php_method_region(
        baseline_component, "selectExistingProject"
    )
    candidate_select = _php_method_region(
        candidate_component, "selectExistingProject"
    )
    repair_select = _php_method_region(repair_component, "selectExistingProject")
    candidate_show = _php_method_region(candidate_component, "showNewResource")
    candidate_case = _test_region(
        candidate_test,
        "test('boarding selectExistingProject cannot load project from another team'",
        "test('boarding selectExistingProject can load own team project'",
    )
    repair_case = _test_region(
        repair_test,
        "test('boarding selectExistingProject cannot load project from another team'",
        "test('boarding selectExistingProject can load own team project'",
    )
    repair_guard = "if (! $this->createdProject)"
    repair_transition = "$this->currentState = 'create-resource';"
    return {
        "baseline_select_uses_unscoped_project_find": (
            "Project::find($this->selectedProject)" in baseline_select
            and "ownedByCurrentTeam" not in baseline_select
        ),
        "candidate_changes_select_to_nullable_team_scope": (
            "Project::ownedByCurrentTeam()->find($this->selectedProject)"
            in candidate_select
        ),
        "candidate_has_no_null_guard_before_state_transition": (
            repair_guard not in candidate_select
            and repair_transition in candidate_select
        ),
        "candidate_followup_dereferences_nullable_project": all(
            marker in candidate_show
            for marker in (
                "$this->createdProject->uuid",
                "$this->createdProject->environments->first()->uuid",
            )
        ),
        "candidate_test_observes_null_but_omits_error_contract": (
            "expect($component->get('createdProject'))->toBeNull();"
            in candidate_case
            and "assertDispatched('error')" not in candidate_case
        ),
        "repair_adds_early_null_guard": all(
            marker in repair_select
            for marker in (
                repair_guard,
                "return $this->dispatch('error', 'Project not found.');",
                repair_transition,
            )
        )
        and repair_select.index(repair_guard)
        < repair_select.index(repair_transition),
        "repair_test_asserts_error_contract": (
            "assertDispatched('error')" in repair_case
        ),
    }


def _evaluate_destination_scope(
    baseline_sources: dict[str, str],
    candidate_sources: dict[str, str],
    repair_sources: dict[str, str],
    destination_test: str,
    resource_proof_test: str,
) -> dict[str, bool]:
    evaluation: dict[str, bool] = {}
    for source_path in RESOURCE_PATHS:
        slug = Path(source_path).stem
        baseline_submit = _php_method_region(
            baseline_sources[source_path], "submit"
        )
        candidate_submit = _php_method_region(
            candidate_sources[source_path], "submit"
        )
        repair_submit = _php_method_region(repair_sources[source_path], "submit")
        baseline_project = _project_line(baseline_submit)
        candidate_project = _project_line(candidate_submit)
        repair_project = _project_line(repair_submit)
        evaluation[f"{slug}_baseline_project_lookup_is_unscoped"] = (
            "Project::where('uuid'" in baseline_project
            and "ownedByCurrentTeam" not in baseline_project
        )
        evaluation[f"{slug}_candidate_scopes_project_lookup"] = (
            "Project::ownedByCurrentTeam()->where('uuid'" in candidate_project
            and candidate_project.endswith("->first();")
        )
        evaluation[f"{slug}_candidate_retains_unscoped_destination_lookup"] = all(
            marker in candidate_submit
            for marker in (
                "StandaloneDocker::where('uuid', $destination_uuid)->first()",
                "SwarmDocker::where('uuid', $destination_uuid)->first()",
            )
        )
        evaluation[f"{slug}_candidate_uses_destination_in_creation_sink"] = (
            "'destination_id' => $destination->id" in candidate_submit
        )
        evaluation[f"{slug}_repair_fails_closed_on_project_and_environment"] = (
            "Project::ownedByCurrentTeam()->where('uuid'" in repair_project
            and repair_project.endswith("->firstOrFail();")
            and "$project->environments()->where('uuid'" in repair_submit
            and "->firstOrFail();" in repair_submit
        )
        evaluation[f"{slug}_repair_scopes_destination_lookup"] = (
            "find_destination_for_current_team($destination_uuid)" in repair_submit
            and "StandaloneDocker::where('uuid', $destination_uuid)"
            not in repair_submit
            and "SwarmDocker::where('uuid', $destination_uuid)"
            not in repair_submit
        )

    destination_test_markers = (
        "describe('SimpleDockerfile destination team scope'",
        "describe('DockerImage destination team scope'",
        "describe('DockerCompose destination + server_id team scope'",
        "describe('PublicGitRepository destination team scope'",
        "describe('GithubPrivateRepository destination team scope'",
        "describe('GithubPrivateRepositoryDeployKey destination team scope'",
        "find_destination_for_current_team($this->destinationB->uuid)",
        "Destination not found.",
    )
    evaluation["repair_tests_all_six_resource_creation_flows"] = all(
        marker in destination_test for marker in destination_test_markers
    )
    evaluation["repair_canary_proves_unscoped_cross_team_destination"] = all(
        marker in resource_proof_test
        for marker in (
            "test('unscoped StandaloneDocker lookup returns another teams destination'",
            "$dest = StandaloneDocker::where('uuid', "
            "$this->destinationB->uuid)->first();",
            "test('Team A can create Application in Team B environment via unscoped lookups'",
            "'destination_id' => $destination->id",
        )
    )
    return evaluation


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_revision = f"{AI_SCOPE_SHA}^"
    baseline_boarding = _text_blob(repository, baseline_revision, BOARDING_PATH)
    candidate_boarding = _text_blob(repository, AI_SCOPE_SHA, BOARDING_PATH)
    onboarding_repair = _text_blob(
        repository, ONBOARDING_REPAIR_SHA, BOARDING_PATH
    )
    candidate_cross_team_test = _text_blob(
        repository, AI_SCOPE_SHA, CROSS_TEAM_TEST_PATH
    )
    repair_cross_team_test = _text_blob(
        repository, ONBOARDING_REPAIR_SHA, CROSS_TEAM_TEST_PATH
    )
    baseline_resources = {
        path: _text_blob(repository, baseline_revision, path)
        for path in RESOURCE_PATHS
    }
    candidate_resources = {
        path: _text_blob(repository, AI_SCOPE_SHA, path) for path in RESOURCE_PATHS
    }
    repair_resources = {
        path: _text_blob(repository, DESTINATION_REPAIR_SHA, path)
        for path in RESOURCE_PATHS
    }
    destination_test = _text_blob(
        repository, DESTINATION_REPAIR_SHA, DESTINATION_TEST_PATH
    )
    resource_proof_test = _text_blob(
        repository, DESTINATION_REPAIR_SHA, RESOURCE_PROOF_TEST_PATH
    )

    onboarding_evaluation = _evaluate_onboarding(
        baseline_boarding,
        candidate_boarding,
        onboarding_repair,
        candidate_cross_team_test,
        repair_cross_team_test,
    )
    destination_evaluation = _evaluate_destination_scope(
        baseline_resources,
        candidate_resources,
        repair_resources,
        destination_test,
        resource_proof_test,
    )

    candidate_metadata = _commit_metadata(repository, AI_SCOPE_SHA)
    onboarding_repair_metadata = _commit_metadata(
        repository, ONBOARDING_REPAIR_SHA
    )
    destination_repair_metadata = _commit_metadata(
        repository, DESTINATION_REPAIR_SHA
    )
    ancestry = {
        "candidate_parent_to_candidate": _is_ancestor(
            repository, baseline_revision, AI_SCOPE_SHA
        ),
        "candidate_to_onboarding_repair": _is_ancestor(
            repository, AI_SCOPE_SHA, ONBOARDING_REPAIR_SHA
        ),
        "candidate_to_destination_repair": _is_ancestor(
            repository, AI_SCOPE_SHA, DESTINATION_REPAIR_SHA
        ),
    }

    line_specs: dict[str, tuple[str, str, int, str]] = {
        "candidate_boarding_project_scope": (
            AI_SCOPE_SHA,
            BOARDING_PATH,
            _method_line(
                candidate_boarding,
                "selectExistingProject",
                "Project::ownedByCurrentTeam()->find($this->selectedProject)",
            ),
            "AI team-scoped boarding project lookup",
        ),
        "onboarding_repair_null_guard": (
            ONBOARDING_REPAIR_SHA,
            BOARDING_PATH,
            _method_line(
                onboarding_repair,
                "selectExistingProject",
                "if (! $this->createdProject)",
            ),
            "follow-up boarding null guard",
        ),
        "onboarding_repair_test_error": (
            ONBOARDING_REPAIR_SHA,
            CROSS_TEAM_TEST_PATH,
            _nth_line(repair_cross_team_test, "$component->assertDispatched('error');"),
            "follow-up boarding error assertion",
        ),
        "destination_repair_cross_team_test": (
            DESTINATION_REPAIR_SHA,
            DESTINATION_TEST_PATH,
            _nth_line(
                destination_test,
                "test('submit with other team destination throws and creates no application'",
            ),
            "follow-up cross-team destination test",
        ),
        "destination_repair_unscoped_canary": (
            DESTINATION_REPAIR_SHA,
            RESOURCE_PROOF_TEST_PATH,
            _nth_line(
                resource_proof_test,
                "test('unscoped StandaloneDocker lookup returns another teams destination'",
            ),
            "follow-up unscoped destination canary",
        ),
    }
    for source_path in RESOURCE_PATHS:
        slug = Path(source_path).stem
        line_specs[f"candidate_{slug}_project_scope"] = (
            AI_SCOPE_SHA,
            source_path,
            _method_line(
                candidate_resources[source_path],
                "submit",
                "Project::ownedByCurrentTeam()->where('uuid'",
            ),
            f"AI {slug} project scope",
        )
        line_specs[f"candidate_{slug}_unscoped_destination"] = (
            AI_SCOPE_SHA,
            source_path,
            _method_line(
                candidate_resources[source_path],
                "submit",
                "StandaloneDocker::where('uuid', $destination_uuid)",
            ),
            f"preserved {slug} unscoped destination lookup",
        )
        line_specs[f"repair_{slug}_destination_scope"] = (
            DESTINATION_REPAIR_SHA,
            source_path,
            _method_line(
                repair_resources[source_path],
                "submit",
                "find_destination_for_current_team($destination_uuid)",
            ),
            f"follow-up {slug} destination scope",
        )

    line_origins = {
        key: _blame_line(repository, revision, path, line_number, label)
        for key, (revision, path, line_number, label) in line_specs.items()
    }
    expected_origins = {
        "candidate_boarding_project_scope": AI_SCOPE_SHA,
        "onboarding_repair_null_guard": ONBOARDING_REPAIR_SHA,
        "onboarding_repair_test_error": ONBOARDING_REPAIR_SHA,
        "destination_repair_cross_team_test": DESTINATION_REPAIR_SHA,
        "destination_repair_unscoped_canary": DESTINATION_REPAIR_SHA,
    }
    for source_path in RESOURCE_PATHS:
        slug = Path(source_path).stem
        expected_origins[f"candidate_{slug}_project_scope"] = AI_SCOPE_SHA
        expected_origins[f"repair_{slug}_destination_scope"] = (
            DESTINATION_REPAIR_SHA
        )
    preserved_destination_origins = {
        key: value
        for key, value in line_origins.items()
        if key.endswith("_unscoped_destination")
    }

    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"]
        == [_commit_metadata(repository, baseline_revision)["sha"]]
        and "scope server and project queries to current team"
        in str(candidate_metadata["message"])
        and "team-scoped project/env lookups in onboarding"
        in str(onboarding_repair_metadata["message"])
        and "scope destination and resource lookups by current team"
        in str(destination_repair_metadata["message"])
        and all(ancestry.values())
        and all(onboarding_evaluation.values())
        and all(destination_evaluation.values())
        and all(
            line_origins[key]["origin_sha"] == expected
            for key, expected in expected_origins.items()
        )
        and all(
            record["origin_sha"] != AI_SCOPE_SHA
            for record in preserved_destination_origins.values()
        )
    )

    source_blobs = [
        _blob_record(repository, baseline_revision, BOARDING_PATH),
        _blob_record(repository, AI_SCOPE_SHA, BOARDING_PATH),
        _blob_record(repository, ONBOARDING_REPAIR_SHA, BOARDING_PATH),
        _blob_record(repository, AI_SCOPE_SHA, CROSS_TEAM_TEST_PATH),
        _blob_record(repository, ONBOARDING_REPAIR_SHA, CROSS_TEAM_TEST_PATH),
        _blob_record(
            repository, DESTINATION_REPAIR_SHA, DESTINATION_TEST_PATH
        ),
        _blob_record(
            repository, DESTINATION_REPAIR_SHA, RESOURCE_PROOF_TEST_PATH
        ),
    ]
    for source_path in RESOURCE_PATHS:
        source_blobs.extend(
            [
                _blob_record(repository, baseline_revision, source_path),
                _blob_record(repository, AI_SCOPE_SHA, source_path),
                _blob_record(repository, DESTINATION_REPAIR_SHA, source_path),
            ]
        )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_project_scope_hardening_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_SCOPE_SHA,
        "fix_shas": [ONBOARDING_REPAIR_SHA, DESTINATION_REPAIR_SHA],
        "candidate_metadata": candidate_metadata,
        "repair_metadata": {
            "onboarding": onboarding_repair_metadata,
            "destination": destination_repair_metadata,
        },
        "ancestry": ancestry,
        "evaluation": {
            "onboarding_null_transition": onboarding_evaluation,
            "incomplete_destination_scope": destination_evaluation,
        },
        "line_origins": line_origins,
        "source_blobs": source_blobs,
        "confirmed_edges": [
            {
                "adjudication": "CONFIRMED_AI_TEAM_SCOPE_NULL_HANDLING_REGRESSION",
                "candidate_sha": AI_SCOPE_SHA,
                "fix_sha": ONBOARDING_REPAIR_SHA,
                "mechanism_group": (
                    "onboarding_team_scoped_project_null_transition"
                ),
            },
            {
                "adjudication": "CONFIRMED_AI_INCOMPLETE_RESOURCE_SCOPE_HARDENING",
                "candidate_sha": AI_SCOPE_SHA,
                "fix_sha": DESTINATION_REPAIR_SHA,
                "mechanism_group": "resource_creation_destination_team_scope",
            },
        ],
        "claim_boundary": (
            "The AI commit directly changed selectExistingProject from an unscoped "
            "lookup to a nullable team-scoped lookup while still advancing to a state "
            "whose next action dereferences the project; the next-day repair added the "
            "missing early null guard. Separately, the AI security-hardening commit "
            "changed Project lookups in six resource-creation submit methods but "
            "preserved older unscoped Destination lookups feeding the same creation "
            "sinks; the later repair replaced those lookups with a team-scoped helper "
            "and added cross-team tests. The second edge is an incomplete-hardening "
            "claim, not a claim that the AI commit originated the older destination "
            "bug. Neither edge claims a separately reproduced runtime exploit."
        ),
        "witness_passed": witness_passed,
    }
    _atomic_json(args.output, payload)
    print("Coolify project-scope hardening witness frozen")
    print(f"  witness passed : {witness_passed}")
    print(f"  confirmed edges: {len(payload['confirmed_edges'])}")
    print(f"  output         : {args.output}")
    return 0 if witness_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
