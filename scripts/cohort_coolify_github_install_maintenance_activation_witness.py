#!/usr/bin/env python3
"""Freeze the AI maintenance-state activation edge for GitHub App install."""

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


AI_ACTIVATION_SHA = "158d54712f4ed212750f0b1da6d98d761bd97454"
SECURITY_REPAIR_SHA = "5a7408a919e1128e75f23c2598926814685928f6"

CONTROLLER_PATH = "app/Http/Controllers/Webhook/Github.php"
ROUTES_PATH = "routes/webhooks.php"


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


def _evaluate_parent(controller: str) -> dict[str, bool]:
    install = _php_method_region(controller, "install")
    maintenance = install.find("if (app()->isDownForMaintenance())")
    source_lookup = install.find("$source = $request->get('source')")
    persistence = install.find("$github_app->installation_id = $installation_id")
    return {
        "maintenance_short_circuit_precedes_install_lookup": (
            maintenance >= 0 and source_lookup > maintenance
        ),
        "maintenance_path_stores_request_then_returns": all(
            marker in install
            for marker in (
                "Storage::disk('webhooks-during-maintenance')->put",
                "return;",
            )
        ),
        "vulnerable_install_write_exists_after_short_circuit": (
            source_lookup >= 0 and persistence > source_lookup
        ),
    }


def _evaluate_candidate(controller: str) -> dict[str, bool]:
    install = _php_method_region(controller, "install")
    return {
        "maintenance_short_circuit_removed": all(
            marker not in install
            for marker in (
                "isDownForMaintenance",
                "webhooks-during-maintenance",
            )
        ),
        "request_controls_source_and_installation_id": all(
            marker in install
            for marker in (
                "$installation_id = $request->get('installation_id')",
                "$source = $request->get('source')",
            )
        ),
        "candidate_uses_unscoped_source_uuid_lookup": (
            "GithubApp::where('uuid', $source)->firstOrFail()" in install
            and "ownedByCurrentTeam" not in install
        ),
        "candidate_persists_unverified_installation_id": all(
            marker in install
            for marker in (
                "$github_app->installation_id = $installation_id",
                "$github_app->save()",
            )
        )
        and "githubInstallationBelongsToApp" not in install,
    }


def _evaluate_repair(controller: str, routes: str) -> dict[str, bool]:
    install = _php_method_region(controller, "install")
    return {
        "repair_requires_authenticated_rate_limited_callback": all(
            marker in routes
            for marker in (
                "Route::middleware(['web', 'auth', 'throttle:30,1'])",
                "Route::get('/source/github/install'",
            )
        ),
        "repair_scopes_app_to_current_team": (
            "GithubApp::ownedByCurrentTeam()->where('uuid', $source)->firstOrFail()"
            in install
        ),
        "repair_validates_installation_id_shape": (
            "ctype_digit($installation_id)" in install
        ),
        "repair_verifies_installation_belongs_to_app": (
            "$this->githubInstallationBelongsToApp($github_app, $installation_id)"
            in install
        ),
        "repair_persists_only_after_verification": (
            install.find("githubInstallationBelongsToApp")
            < install.find("$github_app->installation_id = $installation_id")
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    candidate_metadata = _commit_metadata(repository, AI_ACTIVATION_SHA)
    parents = candidate_metadata.get("parents")
    if not isinstance(parents, list) or len(parents) != 1:
        raise SystemExit("AI activation candidate must have exactly one parent")
    parent_sha = str(parents[0])

    parent_controller = _text_blob(repository, parent_sha, CONTROLLER_PATH)
    candidate_controller = _text_blob(
        repository, AI_ACTIVATION_SHA, CONTROLLER_PATH
    )
    repair_controller = _text_blob(
        repository, SECURITY_REPAIR_SHA, CONTROLLER_PATH
    )
    repair_routes = _text_blob(repository, SECURITY_REPAIR_SHA, ROUTES_PATH)

    parent_evaluation = _evaluate_parent(parent_controller)
    candidate_evaluation = _evaluate_candidate(candidate_controller)
    repair_evaluation = _evaluate_repair(repair_controller, repair_routes)
    ancestry = _is_ancestor(repository, AI_ACTIVATION_SHA, SECURITY_REPAIR_SHA)
    patch = _git(
        repository,
        [
            "diff",
            "--no-ext-diff",
            "--no-color",
            parent_sha,
            AI_ACTIVATION_SHA,
            "--",
            CONTROLLER_PATH,
        ],
    )
    assert isinstance(patch, bytes)
    patch_text = patch.decode("utf-8")
    exact_delta = {
        "candidate_removes_install_maintenance_gate": all(
            marker in patch_text
            for marker in (
                "-            if (app()->isDownForMaintenance()) {",
                "-                Storage::disk('webhooks-during-maintenance')->put",
                "-                return;",
            )
        ),
        "candidate_does_not_rewrite_install_sink": (
            "+            $github_app->installation_id = $installation_id"
            not in patch_text
        ),
        "candidate_controller_patch_sha256": hashlib.sha256(patch).hexdigest(),
    }

    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and ancestry
        and all(parent_evaluation.values())
        and all(candidate_evaluation.values())
        and all(repair_evaluation.values())
        and exact_delta["candidate_removes_install_maintenance_gate"] is True
        and exact_delta["candidate_does_not_rewrite_install_sink"] is True
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_github_install_maintenance_activation_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_ACTIVATION_SHA,
        "candidate_parent_sha": parent_sha,
        "fix_sha": SECURITY_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "ancestry": ancestry,
        "parent_evaluation": parent_evaluation,
        "candidate_evaluation": candidate_evaluation,
        "repair_evaluation": repair_evaluation,
        "exact_candidate_delta": exact_delta,
        "source_blobs": [
            _blob_record(repository, parent_sha, CONTROLLER_PATH),
            _blob_record(repository, AI_ACTIVATION_SHA, CONTROLLER_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, CONTROLLER_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, ROUTES_PATH),
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_AI_MAINTENANCE_STATE_REACHABILITY_EXTENSION"
        ),
        "mechanism_group": "github_app_install_callback_state_binding",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 0,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The installation-id write and predictable source lookup predated the "
            "Claude commit and were already reachable while the application was not "
            "in maintenance mode. The Claude commit did not originate that sink; it "
            "removed the earlier maintenance-mode return immediately before it, "
            "making the same unscoped, unverified write reachable in an additional "
            "runtime state. The later security repair authenticated and rate-limited "
            "the callback, scoped the app lookup to the current team, and verified "
            "the installation against GitHub before persistence. This proves a "
            "state-specific reachability contributor, not sole vulnerability origin "
            "and not a distinct advisory."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify GitHub install maintenance witness failed")

    print("Coolify GitHub install maintenance activation witness frozen")
    print(f"  candidate: {AI_ACTIVATION_SHA}")
    print(f"  repair   : {SECURITY_REPAIR_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
