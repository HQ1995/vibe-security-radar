#!/usr/bin/env python3
"""Freeze the Coolify AI onboarding resource-creation path witness."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


AI_PATH_EXTENSION_SHA = "04625591eaafac64db412b21b0f4c4c0f82fc8ad"
AUTHORIZATION_REPAIR_SHA = "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e"
SOURCE_PATH = "app/Livewire/Boarding/Index.php"
VIEW_PATH = "resources/views/livewire/boarding/index.blade.php"


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


def _optional_method(source: str, method_name: str) -> str | None:
    try:
        return _php_method_region(source, method_name)
    except ValueError:
        return None


def _line_in_method(source: str, method_name: str, marker: str) -> int:
    lines = source.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if re.search(
            rf"(?:public|private|protected) function {re.escape(method_name)}\s*\(",
            line,
        )
    ]
    if len(starts) != 1:
        raise SystemExit(f"expected one method {method_name}, found {starts}")
    start = starts[0]
    end = next(
        (
            index
            for index, line in enumerate(lines[start + 1 :], start=start + 1)
            if re.search(r"(?:public|private|protected) function \w+\s*\(", line)
        ),
        len(lines),
    )
    matches = [
        index + 1
        for index, line in enumerate(lines[start:end], start=start)
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected one {marker!r} in {method_name}, found {matches}"
        )
    return matches[0]


def _evaluate_versions(
    baseline_source: str,
    candidate_source: str,
    candidate_view: str,
    repair_source: str,
) -> dict[str, bool]:
    baseline_mount = _php_method_region(baseline_source, "mount")
    candidate_mount = _php_method_region(candidate_source, "mount")
    baseline_type = _php_method_region(baseline_source, "setServerType")
    candidate_type = _php_method_region(candidate_source, "setServerType")
    candidate_private_key = _php_method_region(candidate_source, "savePrivateKey")
    candidate_server = _php_method_region(candidate_source, "saveServer")
    repair_private_key = _php_method_region(repair_source, "savePrivateKey")
    repair_server = _php_method_region(repair_source, "saveServer")
    return {
        "baseline_mount_has_conditional_member_redirect": (
            "auth()->user()?->isMember()" in baseline_mount
            and "show_boarding === true" in baseline_mount
        ),
        "candidate_preserves_conditional_member_redirect": (
            "auth()->user()?->isMember()" in candidate_mount
            and "show_boarding === true" in candidate_mount
        ),
        "baseline_existing_server_branch_diverts_from_creation": all(
            marker in baseline_type
            for marker in (
                "Server::ownedByCurrentTeam",
                "$this->currentState = 'select-existing-server';",
                "return;",
            )
        ),
        "baseline_has_select_existing_server_action": (
            _optional_method(baseline_source, "selectExistingServer") is not None
        ),
        "candidate_removes_existing_server_branch": all(
            marker not in candidate_type
            for marker in (
                "Server::ownedByCurrentTeam",
                "$this->currentState = 'select-existing-server';",
            )
        ),
        "candidate_removes_select_existing_server_action": (
            _optional_method(candidate_source, "selectExistingServer") is None
        ),
        "candidate_forces_remote_flow_to_private_key_state": all(
            marker in candidate_type
            for marker in (
                "Onboarding always creates new servers",
                "$this->currentState = 'private-key';",
            )
        ),
        "candidate_creation_forms_are_livewire_reachable": all(
            marker in candidate_view
            for marker in (
                "wire:submit='savePrivateKey'",
                "wire:submit='saveServer'",
            )
        ),
        "candidate_private_key_creation_has_no_method_authorization": (
            "PrivateKey::createAndStore" in candidate_private_key
            and "$this->authorize('create', PrivateKey::class)"
            not in candidate_private_key
        ),
        "candidate_server_creation_has_no_method_authorization": (
            "Server::create" in candidate_server
            and "$this->authorize('create', Server::class)" not in candidate_server
        ),
        "repair_authorizes_private_key_creation": (
            "$this->authorize('create', PrivateKey::class)" in repair_private_key
        ),
        "repair_authorizes_server_creation": (
            "$this->authorize('create', Server::class)" in repair_server
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_revision = f"{AI_PATH_EXTENSION_SHA}^"
    baseline_source = _text_blob(repository, baseline_revision, SOURCE_PATH)
    candidate_source = _text_blob(repository, AI_PATH_EXTENSION_SHA, SOURCE_PATH)
    candidate_view = _text_blob(repository, AI_PATH_EXTENSION_SHA, VIEW_PATH)
    repair_source = _text_blob(repository, AUTHORIZATION_REPAIR_SHA, SOURCE_PATH)
    evaluation = _evaluate_versions(
        baseline_source, candidate_source, candidate_view, repair_source
    )
    candidate_metadata = _commit_metadata(repository, AI_PATH_EXTENSION_SHA)
    repair_metadata = _commit_metadata(repository, AUTHORIZATION_REPAIR_SHA)
    line_origins = {
        "candidate_forced_creation_path": _blame_line(
            repository,
            AI_PATH_EXTENSION_SHA,
            SOURCE_PATH,
            _line_in_method(
                candidate_source,
                "setServerType",
                "Onboarding always creates new servers",
            ),
            "AI removal of existing-server diversion",
        ),
        "repair_private_key_authorization": _blame_line(
            repository,
            AUTHORIZATION_REPAIR_SHA,
            SOURCE_PATH,
            _line_in_method(
                repair_source,
                "savePrivateKey",
                "$this->authorize('create', PrivateKey::class)",
            ),
            "follow-up private-key creation authorization",
        ),
        "repair_server_authorization": _blame_line(
            repository,
            AUTHORIZATION_REPAIR_SHA,
            SOURCE_PATH,
            _line_in_method(
                repair_source,
                "saveServer",
                "$this->authorize('create', Server::class)",
            ),
            "follow-up server creation authorization",
        ),
    }
    ancestry = {
        "candidate_parent_to_candidate": _is_ancestor(
            repository, baseline_revision, AI_PATH_EXTENSION_SHA
        ),
        "candidate_to_repair": _is_ancestor(
            repository, AI_PATH_EXTENSION_SHA, AUTHORIZATION_REPAIR_SHA
        ),
    }
    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"]
        == [_commit_metadata(repository, baseline_revision)["sha"]]
        and "onboarding always creates new servers" in str(
            candidate_metadata["message"]
        ).casefold()
        and "authorization gaps" in str(repair_metadata["message"])
        and all(ancestry.values())
        and all(evaluation.values())
        and line_origins["candidate_forced_creation_path"]["origin_sha"]
        == AI_PATH_EXTENSION_SHA
        and line_origins["repair_private_key_authorization"]["origin_sha"]
        == AUTHORIZATION_REPAIR_SHA
        and line_origins["repair_server_authorization"]["origin_sha"]
        == AUTHORIZATION_REPAIR_SHA
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_onboarding_creation_path_extension_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_PATH_EXTENSION_SHA,
        "fix_sha": AUTHORIZATION_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, baseline_revision, SOURCE_PATH),
            _blob_record(repository, AI_PATH_EXTENSION_SHA, SOURCE_PATH),
            _blob_record(repository, AI_PATH_EXTENSION_SHA, VIEW_PATH),
            _blob_record(repository, AUTHORIZATION_REPAIR_SHA, SOURCE_PATH),
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_AI_ONBOARDING_RESOURCE_CREATION_PATH_EXTENSION"
        ),
        "mechanism_group": "onboarding_resource_creation_authorization",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude commit does not originate the older unguarded savePrivateKey "
            "or saveServer methods. Its explicit parent-to-candidate delta removes "
            "the existing-server selection diversion and forces every remote "
            "onboarding flow into the private-key/new-server creation path, while "
            "both Livewire creation methods remain callable without method-level "
            "create authorization. The later authorization repair adds exact create "
            "checks inside both methods. This counts a vulnerable reachability-path "
            "extension, not a root origin, exploit reproduction, or new advisory."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify onboarding creation-path witness failed")
    print("Coolify onboarding creation-path witness frozen")
    print(f"  candidate: {AI_PATH_EXTENSION_SHA}")
    print(f"  repair   : {AUTHORIZATION_REPAIR_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
