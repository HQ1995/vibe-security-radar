#!/usr/bin/env python3
"""Freeze the Coolify AI cloud-settings authorization path-extension witness."""

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
from cohort_coolify_sentinel_command_injection_witness import _blame_line


BASELINE_SHA = "4a4d64ac3132dc5ec200d6541a7638ce9dcd61a8"
AI_CLOUD_FIX_SHA = "acff543e09ae5c7f8da78e5a092ebb1e57f24dc0"
AUTH_REPAIR_SHA = "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e"

UPDATES_PATH = "app/Livewire/Settings/Updates.php"
INDEX_PATH = "app/Livewire/Settings/Index.php"
ROUTES_PATH = "routes/web.php"
POLICY_PATH = "app/Policies/InstanceSettingsPolicy.php"


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


def _line_number(source: str, marker: str, occurrence: int = 1) -> int:
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
    method = _php_method_region(source, method_name)
    offset = method.find(marker)
    if offset < 0:
        raise SystemExit(f"missing marker {marker!r} in {method_name}")
    method_offset = source.find(method)
    return source[: method_offset + offset].count("\n") + 1


def _evaluate_updates(source: str) -> dict[str, bool]:
    mount = _php_method_region(source, "mount")
    instant_save = _php_method_region(source, "instantSave")
    submit = _php_method_region(source, "submit")
    check_manually = _php_method_region(source, "checkManually")
    return {
        "server_is_required_property": "public Server $server;" in source,
        "server_is_nullable_property": "public ?Server $server = null;" in source,
        "mount_unconditionally_requires_server_zero": (
            "$this->server = Server::findOrFail(0);" in mount
            and "if (! isCloud())" not in mount
        ),
        "mount_skips_server_zero_on_cloud": (
            "if (! isCloud())" in mount
            and "$this->server = Server::findOrFail(0);" in mount
        ),
        "mount_has_instance_admin_gate": "if (! isInstanceAdmin())" in mount,
        "uses_authorization_trait": "use AuthorizesRequests;" in source,
        "instant_save_mutates_instance_settings": all(
            marker in instant_save
            for marker in (
                "$this->settings->is_auto_update_enabled =",
                "$this->settings->save();",
            )
        ),
        "instant_save_authorizes_update": (
            "$this->authorize('update', $this->settings);" in instant_save
        ),
        "submit_reaches_instant_save": "$this->instantSave();" in submit,
        "submit_authorizes_update": (
            "$this->authorize('update', $this->settings);" in submit
        ),
        "manual_check_dispatches_instance_job": (
            "CheckForUpdatesJob::dispatchSync();" in check_manually
        ),
        "manual_check_authorizes_update": (
            "$this->authorize('update', $this->settings);" in check_manually
        ),
    }


def _evaluate_neighbor_index(source: str) -> dict[str, bool]:
    mount = _php_method_region(source, "mount")
    return {
        "neighbor_settings_page_has_instance_admin_gate": (
            "if (! isInstanceAdmin())" in mount
            and "return redirect()->route('dashboard');" in mount
        )
    }


def _evaluate_routes(source: str) -> dict[str, bool]:
    route_offset = source.find(
        "Route::get('/settings/updates', SettingsUpdates::class)"
    )
    middleware_offset = source.rfind(
        "Route::middleware(['auth', 'verified'])->group", 0, route_offset
    )
    return {
        "updates_route_exists": route_offset >= 0,
        "route_is_inside_auth_verified_group": (
            middleware_offset >= 0 and middleware_offset < route_offset
        ),
        "route_has_no_instance_admin_middleware": (
            route_offset >= 0
            and "isInstanceAdmin" not in source[route_offset : route_offset + 180]
        ),
    }


def _evaluate_policy(source: str) -> dict[str, bool]:
    update = _php_method_region(source, "update")
    return {
        "instance_settings_update_policy_requires_instance_admin": (
            "return isInstanceAdmin();" in update
        )
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_updates = _text_blob(repository, BASELINE_SHA, UPDATES_PATH)
    candidate_updates = _text_blob(repository, AI_CLOUD_FIX_SHA, UPDATES_PATH)
    candidate_index = _text_blob(repository, AI_CLOUD_FIX_SHA, INDEX_PATH)
    candidate_routes = _text_blob(repository, AI_CLOUD_FIX_SHA, ROUTES_PATH)
    repaired_updates = _text_blob(repository, AUTH_REPAIR_SHA, UPDATES_PATH)
    repaired_policy = _text_blob(repository, AUTH_REPAIR_SHA, POLICY_PATH)

    evaluations = {
        "baseline_updates": _evaluate_updates(baseline_updates),
        "candidate_updates": _evaluate_updates(candidate_updates),
        "candidate_neighbor_index": _evaluate_neighbor_index(candidate_index),
        "candidate_routes": _evaluate_routes(candidate_routes),
        "repaired_updates": _evaluate_updates(repaired_updates),
        "repaired_policy": _evaluate_policy(repaired_policy),
    }
    line_specs = {
        "candidate_nullable_server": (
            AI_CLOUD_FIX_SHA,
            UPDATES_PATH,
            candidate_updates,
            "public ?Server $server = null;",
            None,
            "AI makes server zero optional on cloud",
        ),
        "candidate_cloud_skip": (
            AI_CLOUD_FIX_SHA,
            UPDATES_PATH,
            candidate_updates,
            "if (! isCloud())",
            "mount",
            "AI removes the cloud 404 gate",
        ),
        "preexisting_settings_mutation": (
            AI_CLOUD_FIX_SHA,
            UPDATES_PATH,
            candidate_updates,
            "$this->settings->save();",
            "instantSave",
            "pre-existing instance-settings mutation",
        ),
        "preexisting_updates_route": (
            AI_CLOUD_FIX_SHA,
            ROUTES_PATH,
            candidate_routes,
            "Route::get('/settings/updates', SettingsUpdates::class)",
            None,
            "pre-existing authenticated updates route",
        ),
        "repair_instance_admin_gate": (
            AUTH_REPAIR_SHA,
            UPDATES_PATH,
            repaired_updates,
            "if (! isInstanceAdmin())",
            "mount",
            "repair restores explicit instance-admin gate",
        ),
        "repair_mutation_authorization": (
            AUTH_REPAIR_SHA,
            UPDATES_PATH,
            repaired_updates,
            "$this->authorize('update', $this->settings);",
            "instantSave",
            "repair authorizes instance-settings mutation",
        ),
    }
    line_origins = {}
    for key, (
        revision,
        source_path,
        source,
        marker,
        method,
        label,
    ) in line_specs.items():
        line = (
            _method_line(source, method, marker)
            if method is not None
            else _line_number(source, marker)
        )
        line_origins[key] = _blame_line(
            repository, revision, source_path, line, label
        )

    candidate_metadata = _commit_metadata(repository, AI_CLOUD_FIX_SHA)
    repair_metadata = _commit_metadata(repository, AUTH_REPAIR_SHA)
    ancestry = {
        "baseline_to_candidate": _is_ancestor(
            repository, BASELINE_SHA, AI_CLOUD_FIX_SHA
        ),
        "candidate_to_authorization_repair": _is_ancestor(
            repository, AI_CLOUD_FIX_SHA, AUTH_REPAIR_SHA
        ),
    }
    baseline = evaluations["baseline_updates"]
    candidate = evaluations["candidate_updates"]
    repaired = evaluations["repaired_updates"]
    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"] == [BASELINE_SHA]
        and "fix 404 on /settings for root user on cloud instance"
        in str(candidate_metadata["message"])
        and "only load when not on cloud" in str(candidate_metadata["message"])
        and all(ancestry.values())
        and baseline["server_is_required_property"] is True
        and baseline["mount_unconditionally_requires_server_zero"] is True
        and baseline["mount_skips_server_zero_on_cloud"] is False
        and baseline["mount_has_instance_admin_gate"] is False
        and candidate["server_is_nullable_property"] is True
        and candidate["mount_unconditionally_requires_server_zero"] is False
        and candidate["mount_skips_server_zero_on_cloud"] is True
        and candidate["mount_has_instance_admin_gate"] is False
        and candidate["uses_authorization_trait"] is False
        and candidate["instant_save_mutates_instance_settings"] is True
        and candidate["instant_save_authorizes_update"] is False
        and candidate["submit_reaches_instant_save"] is True
        and candidate["submit_authorizes_update"] is False
        and candidate["manual_check_dispatches_instance_job"] is True
        and candidate["manual_check_authorizes_update"] is False
        and all(evaluations["candidate_neighbor_index"].values())
        and all(evaluations["candidate_routes"].values())
        and repaired["mount_skips_server_zero_on_cloud"] is True
        and repaired["mount_has_instance_admin_gate"] is True
        and repaired["uses_authorization_trait"] is True
        and repaired["instant_save_authorizes_update"] is True
        and repaired["submit_authorizes_update"] is True
        and repaired["manual_check_authorizes_update"] is True
        and all(evaluations["repaired_policy"].values())
        and line_origins["candidate_nullable_server"]["origin_sha"]
        == AI_CLOUD_FIX_SHA
        and line_origins["candidate_cloud_skip"]["origin_sha"]
        == AI_CLOUD_FIX_SHA
        and line_origins["preexisting_settings_mutation"]["origin_sha"]
        != AI_CLOUD_FIX_SHA
        and line_origins["preexisting_updates_route"]["origin_sha"]
        != AI_CLOUD_FIX_SHA
        and line_origins["repair_instance_admin_gate"]["origin_sha"]
        == AUTH_REPAIR_SHA
        and line_origins["repair_mutation_authorization"]["origin_sha"]
        == AUTH_REPAIR_SHA
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_cloud_settings_path_extension_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_CLOUD_FIX_SHA,
        "fix_sha": AUTH_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluations": evaluations,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, BASELINE_SHA, UPDATES_PATH),
            _blob_record(repository, AI_CLOUD_FIX_SHA, UPDATES_PATH),
            _blob_record(repository, AI_CLOUD_FIX_SHA, INDEX_PATH),
            _blob_record(repository, AI_CLOUD_FIX_SHA, ROUTES_PATH),
            _blob_record(repository, AUTH_REPAIR_SHA, UPDATES_PATH),
            _blob_record(repository, AUTH_REPAIR_SHA, POLICY_PATH),
        ],
        "confirmed_edge": {
            "adjudication": (
                "CONFIRMED_DIRECT_AI_CLOUD_SETTINGS_AUTHORIZATION_PATH_EXTENSION"
            ),
            "candidate_sha": AI_CLOUD_FIX_SHA,
            "fix_sha": AUTH_REPAIR_SHA,
            "mechanism_group": "cloud_instance_settings_updates_authorization",
        },
        "counting": {
            "candidate_level_true_positive_count": 1,
            "earliest_self_hosted_authorization_gap_is_ai_not_asserted": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude commit did not create the authenticated updates route or "
            "the older unauthorised InstanceSettings mutations. It specifically "
            "removed the cloud-only 404 gate by making Server(0) optional, while "
            "Settings/Updates still lacked the instance-admin guard already present "
            "on the neighboring Settings/Index component. The later authorization "
            "repair added both an instance-admin mount gate and policy checks to "
            "every sensitive Updates action. This confirms an AI-created cloud "
            "reachability/path extension, not the earliest self-hosted gap and not "
            "a locally executed runtime exploit."
        ),
        "witness_passed": witness_passed,
    }
    _atomic_json(args.output, payload)
    print("Coolify cloud-settings authorization path witness frozen")
    print(f"  witness passed: {witness_passed}")
    print(f"  output        : {args.output}")
    return 0 if witness_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
