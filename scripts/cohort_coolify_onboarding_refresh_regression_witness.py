#!/usr/bin/env python3
"""Freeze the Coolify onboarding URL-state refresh regression witness."""

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


BASELINE_SHA = "821aa6a5317f46c34934e5e89b6cbdf61f6c562d"
AI_ONBOARDING_SHA = "7a008c859ad68332de72683ddb751e40a6487c38"
FOLLOWUP_REPAIR_SHA = "04625591eaafac64db412b21b0f4c4c0f82fc8ad"
SOURCE_PATH = "app/Livewire/Boarding/Index.php"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str) -> str:
    return _git_blob(repository, revision, SOURCE_PATH).decode("utf-8")


def _blob_record(repository: Path, revision: str) -> dict[str, str]:
    blob = _git_blob(repository, revision, SOURCE_PATH)
    return {
        "revision": revision,
        "path": SOURCE_PATH,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _nth_line(source: str, marker: str) -> int:
    matches = [
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one marker {marker!r}, found {matches}")
    return matches[0]


def _evaluate_versions(
    baseline: str,
    candidate: str,
    repair: str,
) -> dict[str, bool]:
    candidate_mount = _php_method_region(candidate, "mount")
    repair_mount = _php_method_region(repair, "mount")
    refresh_guard = (
        "if ($this->currentState === 'create-project' "
        "&& $this->projects->isEmpty())"
    )
    return {
        "baseline_has_no_url_persisted_step": (
            "#[\\Livewire\\Attributes\\Url(as: 'step', history: true)]"
            not in baseline
        ),
        "candidate_makes_step_url_restorable": (
            "#[\\Livewire\\Attributes\\Url(as: 'step', history: true)]"
            in candidate
        ),
        "candidate_initializes_projects_empty": all(
            marker in candidate_mount
            for marker in (
                "if (! isset($this->projects))",
                "$this->projects = collect()",
            )
        ),
        "candidate_only_reload_path_requires_selected_project": all(
            marker in candidate_mount
            for marker in (
                "if ($this->selectedProject)",
                "$this->projects = Project::ownedByCurrentTeam(['name'])->get()",
            )
        ),
        "candidate_misses_create_project_refresh_guard": (
            refresh_guard not in candidate_mount
        ),
        "repair_adds_create_project_refresh_guard": (
            refresh_guard in repair_mount
        ),
        "repair_reloads_team_scoped_projects": (
            repair_mount.count(
                "$this->projects = Project::ownedByCurrentTeam(['name'])->get()"
            )
            > candidate_mount.count(
                "$this->projects = Project::ownedByCurrentTeam(['name'])->get()"
            )
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline = _text_blob(repository, BASELINE_SHA)
    candidate = _text_blob(repository, AI_ONBOARDING_SHA)
    repair = _text_blob(repository, FOLLOWUP_REPAIR_SHA)
    evaluation = _evaluate_versions(baseline, candidate, repair)
    candidate_metadata = _commit_metadata(repository, AI_ONBOARDING_SHA)
    repair_metadata = _commit_metadata(repository, FOLLOWUP_REPAIR_SHA)
    ancestry = {
        "baseline_to_candidate": _is_ancestor(
            repository, BASELINE_SHA, AI_ONBOARDING_SHA
        ),
        "candidate_to_repair": _is_ancestor(
            repository, AI_ONBOARDING_SHA, FOLLOWUP_REPAIR_SHA
        ),
    }
    origin_specs = {
        "candidate_url_step": (
            AI_ONBOARDING_SHA,
            candidate,
            "#[\\Livewire\\Attributes\\Url(as: 'step', history: true)]",
            "AI URL-persisted onboarding step",
        ),
        "candidate_empty_project_collection": (
            AI_ONBOARDING_SHA,
            candidate,
            "$this->projects = collect();",
            "AI empty project collection initialization",
        ),
        "repair_create_project_refresh_guard": (
            FOLLOWUP_REPAIR_SHA,
            repair,
            "if ($this->currentState === 'create-project'",
            "repair project-step refresh guard",
        ),
    }
    line_origins = {
        key: _blame_line(
            repository,
            revision,
            SOURCE_PATH,
            _nth_line(source, marker),
            label,
        )
        for key, (revision, source, marker, label) in origin_specs.items()
    }
    expected_origins = {
        key: revision
        for key, (revision, _source, _marker, _label) in origin_specs.items()
    }
    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"] == [BASELINE_SHA]
        and all(ancestry.values())
        and "state persistence" in str(candidate_metadata["message"])
        and "Fix project loading on page refresh" in str(repair_metadata["message"])
        and all(evaluation.values())
        and all(
            line_origins[key]["origin_sha"] == expected
            for key, expected in expected_origins.items()
        )
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_onboarding_refresh_regression_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_ONBOARDING_SHA,
        "fix_sha": FOLLOWUP_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, revision)
            for revision in (BASELINE_SHA, AI_ONBOARDING_SHA, FOLLOWUP_REPAIR_SHA)
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_AI_INCOMPLETE_ONBOARDING_URL_STATE_RESTORATION"
        ),
        "mechanism_group": "onboarding_project_refresh_state",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude redesign made the onboarding step restorable from URL history "
            "and initialized projects to an empty collection, but did not repopulate "
            "that collection when a refresh restored create-project without a selected "
            "project. The follow-up commit explicitly identifies project loading on "
            "page refresh and adds the missing team-scoped reload guard. This is a "
            "functional regression edge, not a security vulnerability or a new unique "
            "AI candidate. No browser-level runtime reproduction is asserted."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify onboarding refresh regression witness failed")

    print("Coolify onboarding refresh regression witness frozen")
    print(f"  candidate: {AI_ONBOARDING_SHA}")
    print(f"  repair   : {FOLLOWUP_REPAIR_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
