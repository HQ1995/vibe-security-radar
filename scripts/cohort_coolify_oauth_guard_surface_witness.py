#!/usr/bin/env python3
"""Freeze causal and non-causal OAuth password-bypass guard surfaces in Coolify."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from cohort_coolify_oauth_team_delete_path_extension_witness import (
    _blame_line,
    _evaluate_helper,
    _line_in_method,
    _line_number,
)
from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)


BASELINE_SHA = "366ff95893572d4a45221ef2628a5474bbccc041"
AI_OAUTH_SHA = "b0d50669b1b8929b3c82ee4103fb3d1f2a1b0bf1"

DESTINATION_REPAIR_SHA = "86b05b902aedbbb074e73bfe233b3ed006f19b39"
DESTINATION_REPAIR_PARENT_SHA = "12f8f80eb16c82397ba6e2993caf8bdd335bc163"
ADVANCED_REPAIR_SHA = "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e"
ADVANCED_REPAIR_PARENT_SHA = "e82942b3875a25f11c4ee1fd62642dd0f0edac2f"

DESTINATION_PATH = "app/Livewire/Project/Shared/Destination.php"
ADVANCED_PATH = "app/Livewire/Settings/Advanced.php"
HELPER_PATH = "bootstrap/helpers/shared.php"
APPLICATION_POLICY_PATH = "app/Policies/ApplicationPolicy.php"
APPLICATION_POLICY_TEST_PATH = "tests/Unit/Policies/ApplicationPolicyTest.php"
INSTANCE_SETTINGS_POLICY_PATH = "app/Policies/InstanceSettingsPolicy.php"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _evaluate_destination(source: str) -> dict[str, bool]:
    method = _php_method_region(source, "removeServer")
    return {
        "public_livewire_action": "public function removeServer(" in method,
        "uses_direct_password_hash_check": (
            "Hash::check($password, Auth::user()->password)" in method
        ),
        "uses_oauth_aware_password_helper": (
            "verifyPasswordConfirmation($password, $this)" in method
        ),
        "authorizes_application_update": (
            "$this->authorize('update', $this->resource)" in method
        ),
        "server_lookup_is_current_team_scoped": (
            "Server::ownedByCurrentTeam()->findOrFail($server_id)" in method
        ),
        "stops_application_on_selected_server": (
            "StopApplicationOneServer::run($this->resource, $server)" in method
        ),
        "detaches_selected_additional_network": (
            "$this->resource->additional_networks()->detach(" in method
            and "$network_id, ['server_id' => $server_id]" in method
        ),
    }


def _evaluate_advanced(source: str) -> dict[str, bool]:
    mount = _php_method_region(source, "mount")
    toggle = _php_method_region(source, "toggleTwoStepConfirmation")
    return {
        "mount_rejects_non_instance_admin": "if (! isInstanceAdmin())" in mount,
        "mount_redirects_rejected_user": (
            "return redirect()->route('dashboard')" in mount
        ),
        "uses_direct_password_hash_check": (
            "Hash::check($password, Auth::user()->password)" in toggle
        ),
        "uses_oauth_aware_password_helper": (
            "verifyPasswordConfirmation($password, $this)" in toggle
        ),
        "authorizes_instance_settings_update": (
            "$this->authorize('update', $this->settings)" in toggle
        ),
        "disables_global_two_step_confirmation": (
            "$this->settings->disable_two_step_confirmation = "
            "$this->disable_two_step_confirmation = true" in toggle
        ),
        "persists_instance_settings": "$this->settings->save()" in toggle,
    }


def _evaluate_application_policy(source: str) -> dict[str, bool]:
    update = _php_method_region(source, "update")
    return {
        "unconditionally_allows_update": (
            "return Response::allow();" in update
            and "isAdminOfTeam($teamId)" not in update
        ),
        "resolves_application_team": (
            "$teamId = $this->getTeamId($application)" in update
        ),
        "requires_team_admin_or_owner": "isAdminOfTeam($teamId)" in update,
        "denies_non_admin_update": (
            "return Response::deny(" in update
            and "admin or owner permissions" in update
        ),
    }


def _evaluate_application_policy_test(source: str) -> dict[str, bool]:
    return {
        "team_admin_positive_case": (
            "it('allows team admin to update their own team application'" in source
            and "isAdminOfTeam')->with(1)->andReturn(true)" in source
        ),
        "team_member_negative_case": (
            "it('denies team member to update their own team application'" in source
            and "isAdminOfTeam')->with(1)->andReturn(false)" in source
            and "update($user, $application)->allowed())->toBeFalse()" in source
        ),
    }


def _evaluate_instance_settings_policy(source: str) -> dict[str, bool]:
    update = _php_method_region(source, "update")
    return {
        "update_requires_instance_admin": "return isInstanceAdmin();" in update,
    }


def _snapshot(repository: Path, label: str, revision: str) -> dict[str, object]:
    blobs = {
        DESTINATION_PATH: _git_blob(repository, revision, DESTINATION_PATH),
        ADVANCED_PATH: _git_blob(repository, revision, ADVANCED_PATH),
        HELPER_PATH: _git_blob(repository, revision, HELPER_PATH),
    }
    return {
        "label": label,
        "revision": revision,
        "blob_sha256": {
            path: hashlib.sha256(blob).hexdigest() for path, blob in blobs.items()
        },
        "evaluation": {
            "destination": _evaluate_destination(
                blobs[DESTINATION_PATH].decode("utf-8")
            ),
            "advanced": _evaluate_advanced(blobs[ADVANCED_PATH].decode("utf-8")),
            "helper": _evaluate_helper(blobs[HELPER_PATH].decode("utf-8")),
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    runs = [
        _snapshot(repository, "baseline", BASELINE_SHA),
        _snapshot(repository, "direct_ai_oauth_extension", AI_OAUTH_SHA),
        _snapshot(
            repository,
            "destination_repair_parent",
            DESTINATION_REPAIR_PARENT_SHA,
        ),
        _snapshot(repository, "destination_repair", DESTINATION_REPAIR_SHA),
        _snapshot(repository, "advanced_repair_parent", ADVANCED_REPAIR_PARENT_SHA),
        _snapshot(repository, "advanced_repair", ADVANCED_REPAIR_SHA),
    ]
    evaluations = {str(run["label"]): run["evaluation"] for run in runs}

    candidate_destination = _git_blob(
        repository, AI_OAUTH_SHA, DESTINATION_PATH
    ).decode("utf-8")
    candidate_advanced = _git_blob(repository, AI_OAUTH_SHA, ADVANCED_PATH).decode(
        "utf-8"
    )
    candidate_helper = _git_blob(repository, AI_OAUTH_SHA, HELPER_PATH).decode(
        "utf-8"
    )
    repaired_destination = _git_blob(
        repository, DESTINATION_REPAIR_SHA, DESTINATION_PATH
    ).decode("utf-8")
    repaired_advanced = _git_blob(
        repository, ADVANCED_REPAIR_SHA, ADVANCED_PATH
    ).decode("utf-8")
    repaired_application_policy_source = _git_blob(
        repository, DESTINATION_REPAIR_SHA, APPLICATION_POLICY_PATH
    ).decode("utf-8")
    parent_application_policy_source = _git_blob(
        repository, DESTINATION_REPAIR_PARENT_SHA, APPLICATION_POLICY_PATH
    ).decode("utf-8")
    repaired_application_policy_test_source = _git_blob(
        repository, DESTINATION_REPAIR_SHA, APPLICATION_POLICY_TEST_PATH
    ).decode("utf-8")
    instance_settings_policy_source = _git_blob(
        repository, ADVANCED_REPAIR_SHA, INSTANCE_SETTINGS_POLICY_PATH
    ).decode("utf-8")

    policy = {
        "destination_repair_parent": _evaluate_application_policy(
            parent_application_policy_source
        ),
        "destination_repair": _evaluate_application_policy(
            repaired_application_policy_source
        ),
        "destination_repair_test": _evaluate_application_policy_test(
            repaired_application_policy_test_source
        ),
        "advanced_repair": _evaluate_instance_settings_policy(
            instance_settings_policy_source
        ),
    }
    line_origins = {
        "candidate_destination_oauth_helper": _blame_line(
            repository,
            AI_OAUTH_SHA,
            DESTINATION_PATH,
            _line_in_method(
                candidate_destination,
                "removeServer",
                "verifyPasswordConfirmation($password, $this)",
            ),
            "verifyPasswordConfirmation($password, $this)",
        ),
        "candidate_passwordless_oauth_skip": _blame_line(
            repository,
            AI_OAUTH_SHA,
            HELPER_PATH,
            _line_in_method(
                candidate_helper,
                "shouldSkipPasswordConfirmation",
                "if (! Auth::user()?->hasPassword())",
            ),
            "if (! Auth::user()?->hasPassword())",
        ),
        "destination_repair_authorization": _blame_line(
            repository,
            DESTINATION_REPAIR_SHA,
            DESTINATION_PATH,
            _line_in_method(
                repaired_destination,
                "removeServer",
                "$this->authorize('update', $this->resource)",
            ),
            "$this->authorize('update', $this->resource)",
        ),
        "destination_repair_member_negative_test": _blame_line(
            repository,
            DESTINATION_REPAIR_SHA,
            APPLICATION_POLICY_TEST_PATH,
            _line_number(
                repaired_application_policy_test_source,
                "it('denies team member to update their own team application'",
            ),
            "it('denies team member to update their own team application'",
        ),
        "candidate_advanced_instance_admin_gate": _blame_line(
            repository,
            AI_OAUTH_SHA,
            ADVANCED_PATH,
            _line_in_method(
                candidate_advanced,
                "mount",
                "if (! isInstanceAdmin())",
            ),
            "if (! isInstanceAdmin())",
        ),
        "advanced_repair_authorization": _blame_line(
            repository,
            ADVANCED_REPAIR_SHA,
            ADVANCED_PATH,
            _line_in_method(
                repaired_advanced,
                "toggleTwoStepConfirmation",
                "$this->authorize('update', $this->settings)",
            ),
            "$this->authorize('update', $this->settings)",
        ),
    }

    candidate_metadata = _commit_metadata(repository, AI_OAUTH_SHA)
    destination_repair_metadata = _commit_metadata(
        repository, DESTINATION_REPAIR_SHA
    )
    advanced_repair_metadata = _commit_metadata(repository, ADVANCED_REPAIR_SHA)
    baseline = evaluations["baseline"]
    candidate = evaluations["direct_ai_oauth_extension"]
    destination_parent = evaluations["destination_repair_parent"]
    destination_repair = evaluations["destination_repair"]
    advanced_parent = evaluations["advanced_repair_parent"]
    advanced_repair = evaluations["advanced_repair"]

    destination_positive_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"] == [BASELINE_SHA]
        and destination_repair_metadata["parents"]
        == [DESTINATION_REPAIR_PARENT_SHA]
        and _is_ancestor(repository, AI_OAUTH_SHA, DESTINATION_REPAIR_SHA)
        and baseline["destination"]["uses_direct_password_hash_check"] is True
        and baseline["destination"]["uses_oauth_aware_password_helper"] is False
        and baseline["destination"]["authorizes_application_update"] is False
        and baseline["destination"]["stops_application_on_selected_server"] is True
        and baseline["destination"]["detaches_selected_additional_network"] is True
        and candidate["destination"]["uses_oauth_aware_password_helper"] is True
        and candidate["destination"]["authorizes_application_update"] is False
        and candidate["destination"]["stops_application_on_selected_server"] is True
        and candidate["destination"]["detaches_selected_additional_network"] is True
        and all(candidate["helper"].values())
        and destination_parent["destination"][
            "uses_oauth_aware_password_helper"
        ]
        is True
        and destination_parent["destination"]["authorizes_application_update"]
        is False
        and destination_repair["destination"][
            "uses_oauth_aware_password_helper"
        ]
        is True
        and destination_repair["destination"]["authorizes_application_update"]
        is True
        and destination_repair["destination"][
            "stops_application_on_selected_server"
        ]
        is True
        and destination_repair["destination"][
            "detaches_selected_additional_network"
        ]
        is True
        and policy["destination_repair_parent"]["unconditionally_allows_update"]
        is True
        and policy["destination_repair"]["requires_team_admin_or_owner"] is True
        and policy["destination_repair"]["denies_non_admin_update"] is True
        and all(policy["destination_repair_test"].values())
        and line_origins["candidate_destination_oauth_helper"]["origin_sha"]
        == AI_OAUTH_SHA
        and line_origins["candidate_passwordless_oauth_skip"]["origin_sha"]
        == AI_OAUTH_SHA
        and line_origins["destination_repair_authorization"]["origin_sha"]
        == DESTINATION_REPAIR_SHA
        and line_origins["destination_repair_member_negative_test"]["origin_sha"]
        == DESTINATION_REPAIR_SHA
    )

    advanced_noncausal_passed = bool(
        advanced_repair_metadata["parents"] == [ADVANCED_REPAIR_PARENT_SHA]
        and _is_ancestor(repository, AI_OAUTH_SHA, ADVANCED_REPAIR_SHA)
        and baseline["advanced"]["mount_rejects_non_instance_admin"] is True
        and baseline["advanced"]["mount_redirects_rejected_user"] is True
        and baseline["advanced"]["uses_direct_password_hash_check"] is True
        and candidate["advanced"]["mount_rejects_non_instance_admin"] is True
        and candidate["advanced"]["uses_oauth_aware_password_helper"] is True
        and candidate["advanced"]["authorizes_instance_settings_update"] is False
        and candidate["advanced"]["disables_global_two_step_confirmation"] is True
        and candidate["advanced"]["persists_instance_settings"] is True
        and advanced_parent["advanced"]["mount_rejects_non_instance_admin"] is True
        and advanced_parent["advanced"]["authorizes_instance_settings_update"]
        is False
        and advanced_repair["advanced"]["mount_rejects_non_instance_admin"]
        is True
        and advanced_repair["advanced"]["authorizes_instance_settings_update"]
        is True
        and policy["advanced_repair"]["update_requires_instance_admin"] is True
        and line_origins["candidate_advanced_instance_admin_gate"]["origin_sha"]
        != AI_OAUTH_SHA
        and line_origins["advanced_repair_authorization"]["origin_sha"]
        == ADVANCED_REPAIR_SHA
    )

    witness_passed = destination_positive_passed and advanced_noncausal_passed
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_oauth_guard_surface_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_OAUTH_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": {
            "destination": destination_repair_metadata,
            "advanced": advanced_repair_metadata,
        },
        "runs": runs,
        "policy_evaluation": policy,
        "line_origins": line_origins,
        "confirmed_edges": [
            {
                "candidate_sha": AI_OAUTH_SHA,
                "fix_sha": DESTINATION_REPAIR_SHA,
                "adjudication": (
                    "CONFIRMED_DIRECT_AI_OAUTH_DESTRUCTIVE_PATH_EXTENSION"
                ),
                "mechanism_group": (
                    "oauth_destination_remove_server_authorization"
                ),
                "witness_passed": destination_positive_passed,
                "reason": (
                    "The AI delta makes removeServer callable by passwordless OAuth "
                    "team members while preserving its stop-and-detach sinks and the "
                    "missing application-update guard. The repair preserves that "
                    "path but adds a team-admin policy check and a member-negative "
                    "policy regression test."
                ),
            }
        ],
        "rejected_edges": [
            {
                "candidate_sha": AI_OAUTH_SHA,
                "fix_sha": ADVANCED_REPAIR_SHA,
                "adjudication": (
                    "REJECTED_PREEXISTING_EQUIVALENT_INSTANCE_ADMIN_GATE"
                ),
                "candidate_retained": True,
                "witness_passed": advanced_noncausal_passed,
                "reason": (
                    "The AI delta makes the action usable by passwordless OAuth "
                    "instance admins, but Advanced.mount already rejects every "
                    "non-instance-admin. The later method authorization enforces "
                    "the same principal set, so this edge adds defense in depth, "
                    "not a newly unauthorized path."
                ),
            }
        ],
        "witness_passed": witness_passed,
        "conservation": {
            "adjudicated_edge_count": 2,
            "confirmed_edge_count": 1,
            "rejected_edge_count": 1,
            "candidate_retained_count": 2,
            "hard_delete_count": 0,
            "passed": witness_passed,
        },
        "claim_boundary": (
            "This source-and-blame witness splits one broad Claude commit by exact "
            "method and later repair edge. It confirms only the Destination "
            "member-role path extension. It rejects the Advanced edge because its "
            "pre-existing mount guard already enforced the same InstanceSettings "
            "policy principal set. It is not a locally executed exploit or a new "
            "advisory claim."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify OAuth guard-surface witness frozen")
    print(
        "  Destination edge: "
        f"{'PASS' if destination_positive_passed else 'FAIL'} (confirmed)"
    )
    print(
        "  Advanced edge   : "
        f"{'PASS' if advanced_noncausal_passed else 'FAIL'} (rejected)"
    )
    print(f"  output          : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
