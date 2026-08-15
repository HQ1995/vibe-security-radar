#!/usr/bin/env python3
"""Freeze the Coolify AI API-token permission preservation witness."""

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


BASELINE_SHA = "bff6d853708f3d7c861279586f107739036e67da"
AI_EXPIRATION_SHA = "90ddbb357231ca3808f277eb87a63c8f650417e6"
SECURITY_REPAIR_SHA = "7f135e0f6d87a6065a67b78b8a9976dfd99f3a2a"

COMPONENT_PATH = "app/Livewire/Security/ApiTokens.php"
CANDIDATE_TEST_PATH = "tests/Feature/ApiTokenExpirationTest.php"
REPAIR_TEST_PATH = "tests/Feature/ApiTokenLivewireAuthorizationTest.php"


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


def _evaluate_component(source: str) -> dict[str, bool]:
    updated = _php_method_region(source, "updatedPermissions")
    add_token = _php_method_region(source, "addNewToken")
    return {
        "permissions_are_public_livewire_state": (
            "public array $permissions = ['read'];" in source
        ),
        "root_capability_is_public_livewire_state": (
            "public bool $canUseRootPermissions = false;" in source
        ),
        "write_capability_is_public_livewire_state": (
            "public bool $canUseWritePermissions = false;" in source
        ),
        "root_capability_is_locked": (
            "#[Locked]\n    public bool $canUseRootPermissions" in source
        ),
        "write_capability_is_locked": (
            "#[Locked]\n    public bool $canUseWritePermissions" in source
        ),
        "ui_root_check_uses_cached_public_flag": (
            "! $this->canUseRootPermissions" in updated
        ),
        "ui_write_check_uses_cached_public_flag": (
            "! $this->canUseWritePermissions" in updated
        ),
        "issuance_root_check_uses_cached_public_flag": (
            "! $this->canUseRootPermissions" in add_token
        ),
        "issuance_write_check_uses_cached_public_flag": (
            "! $this->canUseWritePermissions" in add_token
        ),
        "issuance_root_check_uses_fresh_policy": (
            "auth()->user()->can('useRootPermissions', PersonalAccessToken::class)"
            in add_token
        ),
        "issuance_write_check_uses_fresh_policy": (
            "auth()->user()->can('useWritePermissions', PersonalAccessToken::class)"
            in add_token
        ),
        "issues_mutable_permissions_without_expiration": (
            "createToken($this->description, array_values($this->permissions));"
            in add_token
        ),
        "issues_mutable_permissions_with_expiration": (
            "createToken($this->description, array_values($this->permissions), $expiresAt)"
            in add_token
        ),
        "adds_expiration_state_and_validation": all(
            marker in source
            for marker in (
                "public ?int $expiresInDays = 30;",
                "'expiresInDays' => 'nullable|integer|in:7,30,60,90,365'",
                "$expiresAt = $this->expiresInDays ? now()->addDays",
            )
        ),
    }


def _evaluate_candidate_tests(source: str) -> dict[str, bool]:
    return {
        "drives_token_issuance_through_livewire": all(
            marker in source
            for marker in (
                "Livewire::test(ApiTokens::class)",
                "->set('permissions', ['read'])",
                "->call('addNewToken')",
            )
        ),
        "checks_expiration_but_not_permission_tampering": (
            "expires_at" in source
            and "tamper" not in source
            and "permissions', ['root']" not in source
        ),
    }


def _evaluate_repair_tests(source: str) -> dict[str, bool]:
    return {
        "locks_permission_capability_flags": (
            "api token permission flags are locked" in source
        ),
        "tests_root_flag_tampering": (
            "member cannot tamper with root permission flag" in source
            and "->set('canUseRootPermissions', true)" in source
        ),
        "tests_root_permission_payload_tampering": (
            "member cannot create root token through tampered permissions payload"
            in source
            and "->set('permissions', ['root'])" in source
            and "expect($member->tokens()->count())->toBe(0);" in source
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_source = _text_blob(repository, BASELINE_SHA, COMPONENT_PATH)
    candidate_source = _text_blob(repository, AI_EXPIRATION_SHA, COMPONENT_PATH)
    candidate_test = _text_blob(repository, AI_EXPIRATION_SHA, CANDIDATE_TEST_PATH)
    repair_source = _text_blob(repository, SECURITY_REPAIR_SHA, COMPONENT_PATH)
    repair_test = _text_blob(repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH)

    evaluations = {
        "baseline_component": _evaluate_component(baseline_source),
        "candidate_component": _evaluate_component(candidate_source),
        "candidate_tests": _evaluate_candidate_tests(candidate_test),
        "repaired_component": _evaluate_component(repair_source),
        "repair_tests": _evaluate_repair_tests(repair_test),
    }
    line_specs = {
        "candidate_expiration_property": (
            AI_EXPIRATION_SHA,
            candidate_source,
            "$expiresInDays = 30;",
            "AI expiration state",
            None,
        ),
        "candidate_rewritten_issuance_sink": (
            AI_EXPIRATION_SHA,
            candidate_source,
            "createToken($this->description, array_values($this->permissions), $expiresAt)",
            "AI rewrite of permission-bearing token issuance sink",
            "addNewToken",
        ),
        "preexisting_mutable_root_flag": (
            AI_EXPIRATION_SHA,
            candidate_source,
            "public bool $canUseRootPermissions = false;",
            "pre-existing mutable authorization cache",
            None,
        ),
        "preexisting_cached_issuance_check": (
            AI_EXPIRATION_SHA,
            candidate_source,
            "! $this->canUseRootPermissions",
            "pre-existing cached root-permission issuance check",
            "addNewToken",
        ),
        "repair_locked_root_flag": (
            SECURITY_REPAIR_SHA,
            repair_source,
            "#[Locked]",
            "repair locks root capability flag",
            None,
        ),
        "repair_fresh_root_policy_check": (
            SECURITY_REPAIR_SHA,
            repair_source,
            "auth()->user()->can('useRootPermissions', PersonalAccessToken::class)",
            "repair checks root capability at issuance time",
            "addNewToken",
        ),
        "repair_preserves_ai_issuance_sink": (
            SECURITY_REPAIR_SHA,
            repair_source,
            "createToken($this->description, array_values($this->permissions), $expiresAt)",
            "AI-owned issuance sink retained after authorization repair",
            "addNewToken",
        ),
        "repair_permission_payload_test": (
            SECURITY_REPAIR_SHA,
            repair_test,
            "member cannot create root token through tampered permissions payload",
            "repair proves root permission payload tampering",
            None,
        ),
    }
    line_origins = {}
    for key, (revision, source, marker, label, method) in line_specs.items():
        line = (
            _method_line(source, method, marker)
            if method is not None
            else _line_number(source, marker)
        )
        source_path = (
            REPAIR_TEST_PATH if key == "repair_permission_payload_test" else COMPONENT_PATH
        )
        line_origins[key] = _blame_line(
            repository, revision, source_path, line, label
        )

    candidate_metadata = _commit_metadata(repository, AI_EXPIRATION_SHA)
    repair_metadata = _commit_metadata(repository, SECURITY_REPAIR_SHA)
    ancestry = {
        "baseline_to_candidate": _is_ancestor(
            repository, BASELINE_SHA, AI_EXPIRATION_SHA
        ),
        "candidate_to_security_repair": _is_ancestor(
            repository, AI_EXPIRATION_SHA, SECURITY_REPAIR_SHA
        ),
    }
    baseline = evaluations["baseline_component"]
    candidate = evaluations["candidate_component"]
    repaired = evaluations["repaired_component"]
    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"] == [BASELINE_SHA]
        and "support expiration on API tokens" in str(candidate_metadata["message"])
        and all(ancestry.values())
        and baseline["permissions_are_public_livewire_state"] is True
        and baseline["root_capability_is_public_livewire_state"] is True
        and baseline["root_capability_is_locked"] is False
        and baseline["issuance_root_check_uses_cached_public_flag"] is True
        and baseline["issues_mutable_permissions_without_expiration"] is True
        and candidate["permissions_are_public_livewire_state"] is True
        and candidate["root_capability_is_public_livewire_state"] is True
        and candidate["write_capability_is_public_livewire_state"] is True
        and candidate["root_capability_is_locked"] is False
        and candidate["write_capability_is_locked"] is False
        and candidate["issuance_root_check_uses_cached_public_flag"] is True
        and candidate["issuance_write_check_uses_cached_public_flag"] is True
        and candidate["issuance_root_check_uses_fresh_policy"] is False
        and candidate["issuance_write_check_uses_fresh_policy"] is False
        and candidate["issues_mutable_permissions_with_expiration"] is True
        and candidate["adds_expiration_state_and_validation"] is True
        and all(evaluations["candidate_tests"].values())
        and repaired["root_capability_is_locked"] is True
        and repaired["write_capability_is_locked"] is True
        and repaired["issuance_root_check_uses_cached_public_flag"] is False
        and repaired["issuance_write_check_uses_cached_public_flag"] is False
        and repaired["issuance_root_check_uses_fresh_policy"] is True
        and repaired["issuance_write_check_uses_fresh_policy"] is True
        and repaired["issues_mutable_permissions_with_expiration"] is True
        and all(evaluations["repair_tests"].values())
        and line_origins["candidate_expiration_property"]["origin_sha"]
        == AI_EXPIRATION_SHA
        and line_origins["candidate_rewritten_issuance_sink"]["origin_sha"]
        == AI_EXPIRATION_SHA
        and line_origins["preexisting_mutable_root_flag"]["origin_sha"]
        != AI_EXPIRATION_SHA
        and line_origins["preexisting_cached_issuance_check"]["origin_sha"]
        != AI_EXPIRATION_SHA
        and line_origins["repair_locked_root_flag"]["origin_sha"]
        == SECURITY_REPAIR_SHA
        and line_origins["repair_fresh_root_policy_check"]["origin_sha"]
        == SECURITY_REPAIR_SHA
        and line_origins["repair_preserves_ai_issuance_sink"]["origin_sha"]
        == AI_EXPIRATION_SHA
        and line_origins["repair_permission_payload_test"]["origin_sha"]
        == SECURITY_REPAIR_SHA
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_api_token_permission_preservation_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_EXPIRATION_SHA,
        "fix_sha": SECURITY_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluations": evaluations,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, BASELINE_SHA, COMPONENT_PATH),
            _blob_record(repository, AI_EXPIRATION_SHA, COMPONENT_PATH),
            _blob_record(repository, AI_EXPIRATION_SHA, CANDIDATE_TEST_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, COMPONENT_PATH),
            _blob_record(repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH),
        ],
        "confirmed_edge": {
            "adjudication": (
                "CONFIRMED_AI_TOKEN_ISSUANCE_SINK_PRESERVATION_CONTRIBUTOR"
            ),
            "candidate_sha": AI_EXPIRATION_SHA,
            "fix_sha": SECURITY_REPAIR_SHA,
            "mechanism_group": "api_token_mutable_permission_issuance",
        },
        "counting": {
            "candidate_level_true_positive_count": 1,
            "earliest_mechanism_root_is_ai_not_asserted": True,
            "new_vulnerable_route_is_ai_not_asserted": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude expiration feature did not originate the mutable Livewire "
            "permission state or cached authorization flags. It did, however, "
            "directly rewrite the exact permission-bearing createToken sink to add "
            "expiration while preserving those client-hydratable checks and passing "
            "the mutable permissions array into issuance. The later repair locks the "
            "capability flags, rechecks authorization from the authenticated user at "
            "issuance time, and demonstrates both flag and root-permission payload "
            "tampering in tests; the AI-owned sink remains unchanged after that "
            "repair. This is a narrow sink-preservation contributor, not an origin, "
            "activation, new-route, or locally reproduced exploit claim."
        ),
        "witness_passed": witness_passed,
    }
    _atomic_json(args.output, payload)
    print("Coolify API-token permission preservation witness frozen")
    print(f"  witness passed: {witness_passed}")
    print(f"  output        : {args.output}")
    return 0 if witness_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
