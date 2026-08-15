#!/usr/bin/env python3
"""Freeze three Coolify true positives recovered by fix-preimage lineage."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)


WEBHOOK_UI_SHA = "769d2eca35e4aa01bb5cfcf14c583007efdfd6e8"
VALIDATE_RENAME_SHA = "ef0a1241b0e8ac64252a108e468d492b84573b56"
API_ORIGIN_SHA = "62c394d3a1dba6aa6d4ab1456b7a7911f6b72639"

WEBHOOK_REPAIR_SHA = "5973bb4d4f3c236d76ac25cb77c22e5317d5379f"
TEAM_ACCESS_REPAIR_SHA = "062ad5774041fb3be71abedcff33c4315613152c"
ROLE_AUTH_REPAIR_SHA = "86b05b902aedbbb074e73bfe233b3ed006f19b39"

WEBHOOK_VIEW = "resources/views/livewire/notifications/webhook.blade.php"
WEBHOOK_COMPONENT = "app/Livewire/Notifications/Webhook.php"
NOTIFICATION_POLICY = "app/Policies/NotificationPolicy.php"
BASE_CONTROLLER = "app/Http/Controllers/Controller.php"
CLOUD_CONTROLLER = "app/Http/Controllers/Api/CloudProviderTokensController.php"
HETZNER_CONTROLLER = "app/Http/Controllers/Api/HetznerController.php"
CLOUD_POLICY = "app/Policies/CloudProviderTokenPolicy.php"
SERVER_POLICY = "app/Policies/ServerPolicy.php"
API_ROUTES = "routes/api.php"


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


def _path_exists(repository: Path, revision: str, source_path: str) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(repository), "cat-file", "-e", f"{revision}:{source_path}"],
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode not in {0, 1, 128}:
        raise SystemExit(f"cannot probe Git path {revision}:{source_path}")
    return completed.returncode == 0


def _method_has_authorize(source: str, method: str, ability: str) -> bool:
    return f"$this->authorize('{ability}'" in _php_method_region(source, method)


def _evaluate_webhook(
    *,
    baseline_view: str,
    candidate_view: str,
    candidate_component: str,
    repair_view: str,
    repair_component: str,
    policy: str,
) -> dict[str, bool]:
    password_input = re.compile(
        r"<x-forms\.input(?=[^>]*\btype=\"password\")"
        r"(?=[^>]*\bid=\"webhookUrl\")[^>]*>",
        re.DOTALL,
    )
    return {
        "baseline_already_rendered_bound_secret": bool(
            'id="webhookUrl"' in baseline_view and 'type="url"' in baseline_view
        ),
        "candidate_preserves_bound_secret_input": bool(
            password_input.search(candidate_view)
            and 'canGate="update"' in candidate_view
            and ':canResource="$settings"' in candidate_view
        ),
        "candidate_component_loads_secret_for_every_viewer": bool(
            "$this->webhookUrl = $this->settings->webhook_url;"
            in candidate_component
            and "auth()->user()->can('update', $this->settings)" not in candidate_component
        ),
        "repair_gates_livewire_secret_state": bool(
            "auth()->user()->can('update', $this->settings)"
            in repair_component
            and "? $this->settings->webhook_url" in repair_component
            and ": null;" in repair_component
        ),
        "repair_gates_rendered_secret_control": bool(
            "@can('update', $settings)" in repair_view
            and "Hidden (only admins can view)" in repair_view
        ),
        "policy_view_allows_team_member": (
            "teams->contains('id', $notificationSettings->team->id)" in policy
        ),
        "policy_update_requires_team_admin": (
            "isAdminOfTeam($teamId)" in policy
        ),
    }


def _normalized_validate_method(source: str, method: str) -> str:
    region = _php_method_region(source, method)
    return re.sub(
        rf"function\s+{re.escape(method)}\s*\(",
        "function VALIDATE_TOKEN(",
        region,
        count=1,
    )


def _evaluate_validate_activation(
    *,
    base_controller: str,
    parent_controller: str,
    parent_routes: str,
    candidate_controller: str,
    candidate_routes: str,
    repair_parent_controller: str,
    repair_controller: str,
    cloud_policy: str,
) -> dict[str, bool]:
    candidate_method = _php_method_region(candidate_controller, "validateToken")
    repair_parent_method = _php_method_region(repair_parent_controller, "validateToken")
    repair_method = _php_method_region(repair_controller, "validateToken")
    return {
        "base_controller_inherits_validate_trait": (
            "use AuthorizesRequests, ValidatesRequests;" in base_controller
        ),
        "parent_declares_conflicting_validate_name": (
            "public function validate(Request $request)" in parent_controller
        ),
        "parent_route_targets_conflicting_name": bool(
            re.search(
                r"cloud-tokens/\{uuid\}/validate'.*::class, 'validate'",
                parent_routes,
            )
        ),
        "candidate_renames_method_without_body_change": (
            _normalized_validate_method(parent_controller, "validate")
            == _normalized_validate_method(candidate_controller, "validateToken")
        ),
        "candidate_rewires_route": bool(
            re.search(
                r"cloud-tokens/\{uuid\}/validate'.*::class, 'validateToken'",
                candidate_routes,
            )
        ),
        "candidate_uses_stored_provider_credential": bool(
            "$cloudToken->token" in candidate_method
            and "Http::withHeaders" in candidate_method
        ),
        "candidate_has_no_policy_authorization": "$this->authorize(" not in candidate_method,
        "repair_parent_still_has_no_policy_authorization": (
            "$this->authorize(" not in repair_parent_method
        ),
        "repair_adds_view_authorization": (
            "$this->authorize('view', $cloudToken);" in repair_method
        ),
        "cloud_token_view_policy_requires_admin": bool(
            re.search(
                r"function view\([^)]*CloudProviderToken[^)]*\).*?"
                r"return \$user->isAdmin\(\);",
                cloud_policy,
                re.DOTALL,
            )
        ),
    }


def _evaluate_api_role_origin(
    *,
    candidate_cloud: str,
    candidate_hetzner: str,
    repair_parent_cloud: str,
    repair_parent_hetzner: str,
    repair_cloud: str,
    repair_hetzner: str,
    cloud_policy: str,
    server_policy_before: str,
    server_policy_after: str,
) -> dict[str, bool]:
    cloud_abilities = {
        "show": "view",
        "store": "create",
        "update": "update",
        "destroy": "delete",
    }
    candidate_methods = {
        method: _php_method_region(candidate_cloud, method) for method in cloud_abilities
    }
    repair_parent_methods = {
        method: _php_method_region(repair_parent_cloud, method)
        for method in cloud_abilities
    }
    repair_methods = {
        method: _php_method_region(repair_cloud, method) for method in cloud_abilities
    }
    candidate_create_server = _php_method_region(candidate_hetzner, "createServer")
    repair_parent_create_server = _php_method_region(
        repair_parent_hetzner, "createServer"
    )
    repair_create_server = _php_method_region(repair_hetzner, "createServer")
    return {
        "candidate_cloud_methods_only_team_scope": bool(
            all("getTeamIdFromToken()" in body for body in candidate_methods.values())
            and all("$this->authorize(" not in body for body in candidate_methods.values())
        ),
        "candidate_create_server_has_no_role_authorization": (
            "getTeamIdFromToken()" in candidate_create_server
            and "$this->authorize(" not in candidate_create_server
        ),
        "repair_parent_cloud_methods_still_unauthorized": all(
            "$this->authorize(" not in body for body in repair_parent_methods.values()
        ),
        "repair_parent_create_server_still_unauthorized": (
            "$this->authorize(" not in repair_parent_create_server
        ),
        "repair_authorizes_every_cloud_operation": all(
            f"$this->authorize('{ability}'" in repair_methods[method]
            for method, ability in cloud_abilities.items()
        ),
        "repair_authorizes_server_creation": (
            "$this->authorize('create', [Server::class]);" in repair_create_server
        ),
        "cloud_token_policy_is_admin_only": all(
            f"function {ability}" in cloud_policy
            for ability in ("view", "create", "update", "delete")
        )
        and cloud_policy.count("return $user->isAdmin();") >= 4,
        "server_create_policy_was_open_before_repair": bool(
            re.search(
                r"function create\([^)]*\).*?return true;",
                server_policy_before,
                re.DOTALL,
            )
        ),
        "server_create_policy_requires_admin_after_repair": bool(
            re.search(
                r"function create\([^)]*\).*?return \$user->isAdmin\(\);",
                server_policy_after,
                re.DOTALL,
            )
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    candidate_shas = (WEBHOOK_UI_SHA, VALIDATE_RENAME_SHA, API_ORIGIN_SHA)
    repair_shas = (WEBHOOK_REPAIR_SHA, TEAM_ACCESS_REPAIR_SHA, ROLE_AUTH_REPAIR_SHA)
    metadata = {
        sha: _commit_metadata(repository, sha) for sha in (*candidate_shas, *repair_shas)
    }
    if not all(metadata[sha]["explicit_claude_signal"] is True for sha in candidate_shas):
        raise SystemExit("a candidate lacks an explicit Claude attribution signal")
    edge_pairs = (
        (WEBHOOK_UI_SHA, WEBHOOK_REPAIR_SHA),
        (VALIDATE_RENAME_SHA, TEAM_ACCESS_REPAIR_SHA),
        (API_ORIGIN_SHA, ROLE_AUTH_REPAIR_SHA),
    )
    if not all(_is_ancestor(repository, candidate, repair) for candidate, repair in edge_pairs):
        raise SystemExit("a recovered edge is not ancestral")

    webhook_checks = _evaluate_webhook(
        baseline_view=_text_blob(repository, f"{WEBHOOK_UI_SHA}^", WEBHOOK_VIEW),
        candidate_view=_text_blob(repository, WEBHOOK_UI_SHA, WEBHOOK_VIEW),
        candidate_component=_text_blob(
            repository, WEBHOOK_UI_SHA, WEBHOOK_COMPONENT
        ),
        repair_view=_text_blob(repository, WEBHOOK_REPAIR_SHA, WEBHOOK_VIEW),
        repair_component=_text_blob(
            repository, WEBHOOK_REPAIR_SHA, WEBHOOK_COMPONENT
        ),
        policy=_text_blob(repository, WEBHOOK_REPAIR_SHA, NOTIFICATION_POLICY),
    )

    validate_checks = _evaluate_validate_activation(
        base_controller=_text_blob(
            repository, f"{VALIDATE_RENAME_SHA}^", BASE_CONTROLLER
        ),
        parent_controller=_text_blob(
            repository, f"{VALIDATE_RENAME_SHA}^", CLOUD_CONTROLLER
        ),
        parent_routes=_text_blob(repository, f"{VALIDATE_RENAME_SHA}^", API_ROUTES),
        candidate_controller=_text_blob(
            repository, VALIDATE_RENAME_SHA, CLOUD_CONTROLLER
        ),
        candidate_routes=_text_blob(repository, VALIDATE_RENAME_SHA, API_ROUTES),
        repair_parent_controller=_text_blob(
            repository, f"{TEAM_ACCESS_REPAIR_SHA}^", CLOUD_CONTROLLER
        ),
        repair_controller=_text_blob(
            repository, TEAM_ACCESS_REPAIR_SHA, CLOUD_CONTROLLER
        ),
        cloud_policy=_text_blob(repository, TEAM_ACCESS_REPAIR_SHA, CLOUD_POLICY),
    )

    api_parent_absence = {
        source_path: not _path_exists(repository, f"{API_ORIGIN_SHA}^", source_path)
        for source_path in (CLOUD_CONTROLLER, HETZNER_CONTROLLER)
    }
    api_checks = _evaluate_api_role_origin(
        candidate_cloud=_text_blob(repository, API_ORIGIN_SHA, CLOUD_CONTROLLER),
        candidate_hetzner=_text_blob(repository, API_ORIGIN_SHA, HETZNER_CONTROLLER),
        repair_parent_cloud=_text_blob(
            repository, f"{ROLE_AUTH_REPAIR_SHA}^", CLOUD_CONTROLLER
        ),
        repair_parent_hetzner=_text_blob(
            repository, f"{ROLE_AUTH_REPAIR_SHA}^", HETZNER_CONTROLLER
        ),
        repair_cloud=_text_blob(repository, ROLE_AUTH_REPAIR_SHA, CLOUD_CONTROLLER),
        repair_hetzner=_text_blob(
            repository, ROLE_AUTH_REPAIR_SHA, HETZNER_CONTROLLER
        ),
        cloud_policy=_text_blob(repository, ROLE_AUTH_REPAIR_SHA, CLOUD_POLICY),
        server_policy_before=_text_blob(
            repository, f"{ROLE_AUTH_REPAIR_SHA}^", SERVER_POLICY
        ),
        server_policy_after=_text_blob(
            repository, ROLE_AUTH_REPAIR_SHA, SERVER_POLICY
        ),
    )

    all_checks = {
        "webhook_ui_preservation": webhook_checks,
        "validate_reachability_extension": validate_checks,
        "cloud_api_role_authorization_origin": {
            **api_parent_absence,
            **api_checks,
        },
    }
    witness_passed = all(
        value is True
        for group in all_checks.values()
        for value in group.values()
    )
    if not witness_passed:
        failed = {
            group_name: [name for name, passed in group.items() if passed is not True]
            for group_name, group in all_checks.items()
            if any(passed is not True for passed in group.values())
        }
        raise SystemExit(f"lineage recovery witness failed: {failed}")

    blobs = [
        _blob_record(repository, revision, source_path)
        for revision, source_path in (
            (f"{WEBHOOK_UI_SHA}^", WEBHOOK_VIEW),
            (WEBHOOK_UI_SHA, WEBHOOK_VIEW),
            (WEBHOOK_UI_SHA, WEBHOOK_COMPONENT),
            (WEBHOOK_REPAIR_SHA, WEBHOOK_VIEW),
            (WEBHOOK_REPAIR_SHA, WEBHOOK_COMPONENT),
            (f"{VALIDATE_RENAME_SHA}^", BASE_CONTROLLER),
            (f"{VALIDATE_RENAME_SHA}^", CLOUD_CONTROLLER),
            (VALIDATE_RENAME_SHA, CLOUD_CONTROLLER),
            (TEAM_ACCESS_REPAIR_SHA, CLOUD_CONTROLLER),
            (API_ORIGIN_SHA, CLOUD_CONTROLLER),
            (API_ORIGIN_SHA, HETZNER_CONTROLLER),
            (ROLE_AUTH_REPAIR_SHA, CLOUD_CONTROLLER),
            (ROLE_AUTH_REPAIR_SHA, HETZNER_CONTROLLER),
            (ROLE_AUTH_REPAIR_SHA, CLOUD_POLICY),
            (f"{ROLE_AUTH_REPAIR_SHA}^", SERVER_POLICY),
            (ROLE_AUTH_REPAIR_SHA, SERVER_POLICY),
        )
    ]
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_fix_preimage_lineage_recovery_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "commit_metadata": metadata,
        "confirmed_edges": [
            {
                "candidate_sha": WEBHOOK_UI_SHA,
                "fix_sha": WEBHOOK_REPAIR_SHA,
                "adjudication": "CONFIRMED_AI_UI_PRESERVATION_CONTRIBUTOR",
                "mechanism_group": "webhook_secret_exposure",
                "mechanism_root": False,
            },
            {
                "candidate_sha": VALIDATE_RENAME_SHA,
                "fix_sha": TEAM_ACCESS_REPAIR_SHA,
                "adjudication": "CONFIRMED_AI_REACHABILITY_PATH_EXTENSION",
                "mechanism_group": "hetzner_token_authorization",
                "mechanism_root": False,
            },
            {
                "candidate_sha": API_ORIGIN_SHA,
                "fix_sha": ROLE_AUTH_REPAIR_SHA,
                "adjudication": "CONFIRMED_DIRECT_AI_ROLE_AUTHORIZATION_ORIGIN",
                "mechanism_group": "cloud_provider_api_role_authorization",
                "mechanism_root": True,
            },
        ],
        "checks": all_checks,
        "blob_evidence": blobs,
        "witness_passed": witness_passed,
        "claim_boundary": (
            "This source/compositional witness proves three commit/fix causal edges: "
            "one AI UI preservation contributor to a pre-existing webhook-secret "
            "exposure, one AI method/route rename that makes a stored-credential "
            "validation path operational while preserving its missing policy check, "
            "and one direct AI origin that creates cloud-token CRUD and Hetzner server "
            "creation endpoints without the admin-only policy checks later added by the "
            "repair. These are edge-level contributors, not three distinct "
            "vulnerabilities. No runtime exploit, external provider request, advisory "
            "mapping, or claim about every route in either broad repair is made."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify lineage recovery witness frozen")
    print("  confirmed edges : 3")
    print(f"  output          : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
