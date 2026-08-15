#!/usr/bin/env python3
"""Freeze an AI helper extraction preserving two cloud-token auth defects."""

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


CANDIDATE_SHA = "596b1cb76ecb1a8e3a295f25672586c49dbf71d0"
CREDENTIAL_REPAIR_SHA = "062ad5774041fb3be71abedcff33c4315613152c"
ROLE_REPAIR_SHA = "86b05b902aedbbb074e73bfe233b3ed006f19b39"

CLOUD_CONTROLLER = "app/Http/Controllers/Api/CloudProviderTokensController.php"
CLOUD_POLICY = "app/Policies/CloudProviderTokenPolicy.php"


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


def _admin_policy(policy: str, ability: str) -> bool:
    return bool(
        re.search(
            rf"function {re.escape(ability)}\([^)]*\).*?"
            r"return \$user->isAdmin\(\);",
            policy,
            re.DOTALL,
        )
    )


def _evaluate_preservation(
    *,
    parent: str,
    candidate: str,
    credential_repair_parent: str,
    credential_repair: str,
    role_repair_parent: str,
    role_repair: str,
    policy: str,
) -> dict[str, bool]:
    parent_validate = _php_method_region(parent, "validateToken")
    candidate_validate = _php_method_region(candidate, "validateToken")
    candidate_helper = _php_method_region(candidate, "validateProviderToken")
    credential_parent_validate = _php_method_region(
        credential_repair_parent, "validateToken"
    )
    credential_repaired_validate = _php_method_region(
        credential_repair, "validateToken"
    )
    candidate_store = _php_method_region(candidate, "store")
    candidate_update = _php_method_region(candidate, "update")
    role_parent_store = _php_method_region(role_repair_parent, "store")
    role_parent_update = _php_method_region(role_repair_parent, "update")
    role_repaired_store = _php_method_region(role_repair, "store")
    role_repaired_update = _php_method_region(role_repair, "update")
    return {
        "parent_validation_calls_provider_inline": bool(
            "Http::withHeaders" in parent_validate
            and "$cloudToken->token" in parent_validate
        ),
        "candidate_extracts_provider_sink": bool(
            "private function validateProviderToken" in candidate_helper
            and "Http::withHeaders" in candidate_helper
            and "'Authorization' => 'Bearer '.$token" in candidate_helper
        ),
        "candidate_rewires_stored_token_into_helper": bool(
            "$this->validateProviderToken($cloudToken->provider, $cloudToken->token)"
            in candidate_validate
        ),
        "candidate_validate_still_has_no_policy_check": (
            "$this->authorize(" not in candidate_validate
        ),
        "credential_repair_parent_still_unauthorized": (
            "$this->authorize(" not in credential_parent_validate
        ),
        "credential_repair_adds_view_check": (
            "$this->authorize('view', $cloudToken);" in credential_repaired_validate
        ),
        "candidate_substantially_rewrites_store": bool(
            "$body = $request->json()->all();" in candidate_store
            and "$this->validateProviderToken($body['provider'], $body['token'])"
            in candidate_store
        ),
        "candidate_substantially_rewrites_update": bool(
            "$body = $request->json()->all();" in candidate_update
            and "$request->route('uuid')" in candidate_update
        ),
        "candidate_store_update_still_have_no_policy_checks": (
            "$this->authorize(" not in candidate_store
            and "$this->authorize(" not in candidate_update
        ),
        "role_repair_parent_still_has_no_policy_checks": (
            "$this->authorize(" not in role_parent_store
            and "$this->authorize(" not in role_parent_update
        ),
        "role_repair_adds_create_and_update_checks": bool(
            "$this->authorize('create', [CloudProviderToken::class]);"
            in role_repaired_store
            and "$this->authorize('update', $token);" in role_repaired_update
        ),
        "cloud_token_policy_is_admin_only": (
            _admin_policy(policy, "view")
            and _admin_policy(policy, "create")
            and _admin_policy(policy, "update")
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    metadata = {
        sha: _commit_metadata(repository, sha)
        for sha in (CANDIDATE_SHA, CREDENTIAL_REPAIR_SHA, ROLE_REPAIR_SHA)
    }
    if metadata[CANDIDATE_SHA]["explicit_claude_signal"] is not True:
        raise SystemExit("candidate lacks an explicit Claude attribution signal")
    if not all(
        _is_ancestor(repository, CANDIDATE_SHA, repair)
        for repair in (CREDENTIAL_REPAIR_SHA, ROLE_REPAIR_SHA)
    ):
        raise SystemExit("candidate is not ancestral to both repairs")

    checks = _evaluate_preservation(
        parent=_text_blob(repository, f"{CANDIDATE_SHA}^", CLOUD_CONTROLLER),
        candidate=_text_blob(repository, CANDIDATE_SHA, CLOUD_CONTROLLER),
        credential_repair_parent=_text_blob(
            repository, f"{CREDENTIAL_REPAIR_SHA}^", CLOUD_CONTROLLER
        ),
        credential_repair=_text_blob(
            repository, CREDENTIAL_REPAIR_SHA, CLOUD_CONTROLLER
        ),
        role_repair_parent=_text_blob(
            repository, f"{ROLE_REPAIR_SHA}^", CLOUD_CONTROLLER
        ),
        role_repair=_text_blob(repository, ROLE_REPAIR_SHA, CLOUD_CONTROLLER),
        policy=_text_blob(repository, ROLE_REPAIR_SHA, CLOUD_POLICY),
    )
    witness_passed = all(checks.values())
    if not witness_passed:
        failed = [name for name, passed in checks.items() if passed is not True]
        raise SystemExit(f"cloud-token helper preservation witness failed: {failed}")

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_cloud_token_helper_preservation_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "commit_metadata": metadata,
        "confirmed_edges": [
            {
                "candidate_sha": CANDIDATE_SHA,
                "fix_sha": CREDENTIAL_REPAIR_SHA,
                "adjudication": "CONFIRMED_AI_DATAFLOW_PRESERVATION_CONTRIBUTOR",
                "mechanism_group": "hetzner_token_authorization",
                "mechanism_root": False,
            },
            {
                "candidate_sha": CANDIDATE_SHA,
                "fix_sha": ROLE_REPAIR_SHA,
                "adjudication": "CONFIRMED_AI_MUTATION_PATH_PRESERVATION_CONTRIBUTOR",
                "mechanism_group": "cloud_provider_api_role_authorization",
                "mechanism_root": False,
            },
        ],
        "checks": checks,
        "blob_evidence": [
            _blob_record(repository, revision, CLOUD_CONTROLLER)
            for revision in (
                f"{CANDIDATE_SHA}^",
                CANDIDATE_SHA,
                f"{CREDENTIAL_REPAIR_SHA}^",
                CREDENTIAL_REPAIR_SHA,
                f"{ROLE_REPAIR_SHA}^",
                ROLE_REPAIR_SHA,
            )
        ]
        + [_blob_record(repository, ROLE_REPAIR_SHA, CLOUD_POLICY)],
        "witness_passed": witness_passed,
        "claim_boundary": (
            "This source/compositional witness proves two causal preservation edges "
            "from one explicitly Claude-attributed refactor. The candidate moves "
            "stored provider-token use into a helper and substantially rewrites the "
            "store/update request dataflow while retaining missing policy checks; two "
            "later repairs add the relevant admin-only view/create/update checks. It "
            "does not claim a new mechanism root, a runtime exploit, an advisory "
            "mapping, or that an incidental edit inside a vulnerable method is causal."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify cloud-token helper preservation witness frozen")
    print("  confirmed edges : 2")
    print(f"  output          : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
