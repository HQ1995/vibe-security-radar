#!/usr/bin/env python3
"""Freeze the Coolify Hetzner stored-credential authorization witness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


BASELINE_SHA = "d2a1b965987eb3d74847a22b3a3e8fc8104852b1"
AI_ORIGIN_SHA = "62c394d3a1dba6aa6d4ab1456b7a7911f6b72639"
SECURITY_REPAIR_SHA = "062ad5774041fb3be71abedcff33c4315613152c"

HETZNER_CONTROLLER_PATH = "app/Http/Controllers/Api/HetznerController.php"
TOKEN_CONTROLLER_PATH = (
    "app/Http/Controllers/Api/CloudProviderTokensController.php"
)
ROUTES_PATH = "routes/api.php"
CLOUD_TOKEN_POLICY_PATH = "app/Policies/CloudProviderTokenPolicy.php"
API_TOKEN_POLICY_PATH = "app/Policies/ApiTokenPolicy.php"
AUTH_PROVIDER_PATH = "app/Providers/AuthServiceProvider.php"
REPAIR_TEST_PATH = "tests/Feature/Api/HetznerApiTest.php"

READ_ENDPOINTS = {
    "locations": "/hetzner/locations",
    "serverTypes": "/hetzner/server-types",
    "images": "/hetzner/images",
    "sshKeys": "/hetzner/ssh-keys",
}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _git(
    repository: Path,
    arguments: list[str],
    *,
    text: bool = False,
) -> bytes | str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"git {' '.join(arguments)} failed: {exc}") from exc
    if completed.returncode != 0:
        reason = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"git {' '.join(arguments)} failed: {reason}")
    if text:
        return completed.stdout.decode("utf-8", errors="strict")
    return completed.stdout


def _git_blob(repository: Path, revision: str, source_path: str) -> bytes:
    value = _git(repository, ["show", f"{revision}:{source_path}"])
    assert isinstance(value, bytes)
    if not value:
        raise SystemExit(f"empty Git blob: {revision}:{source_path}")
    return value


def _path_exists(repository: Path, revision: str, source_path: str) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(repository), "cat-file", "-e", f"{revision}:{source_path}"],
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode not in {0, 1, 128}:
        reason = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(
            f"cannot inspect path {revision}:{source_path}: {reason}"
        )
    return completed.returncode == 0


def _explicit_claude_signal(author_name: str, author_email: str, message: str) -> bool:
    normalized = f"{author_name}\n{author_email}\n{message}".lower()
    return bool(
        re.search(r"co-authored-by:\s*claude\b", message, re.IGNORECASE)
        or "generated with [claude code]" in normalized
        or "noreply@anthropic.com" in normalized
    )


def _commit_metadata(repository: Path, revision: str) -> dict[str, object]:
    value = _git(
        repository,
        [
            "show",
            "-s",
            "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%B",
            revision,
        ],
        text=True,
    )
    assert isinstance(value, str)
    fields = value.rstrip("\n").split("\x00", 5)
    if len(fields) != 6:
        raise SystemExit(f"unexpected commit metadata for {revision}")
    sha, parents, author_name, author_email, authored_at, message = fields
    return {
        "sha": sha,
        "parents": parents.split(),
        "author_name": author_name,
        "author_email": author_email,
        "authored_at": authored_at,
        "message": message.rstrip(),
        "explicit_claude_signal": _explicit_claude_signal(
            author_name, author_email, message
        ),
    }


def _is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            ancestor,
            descendant,
        ],
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode not in {0, 1}:
        reason = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"cannot check ancestry {ancestor}..{descendant}: {reason}")
    return completed.returncode == 0


def _without_php_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", source)


def _php_method_region(source: str, method_name: str) -> str:
    start = re.search(
        rf"^\s*public function {re.escape(method_name)}\s*\(",
        source,
        re.MULTILINE,
    )
    if not start:
        raise ValueError(f"public PHP method is absent: {method_name}")
    following = re.search(
        r"^\s*(?:public|private|protected) function \w+\s*\(",
        source[start.end() :],
        re.MULTILINE,
    )
    end = len(source) if following is None else start.end() + following.start()
    return source[start.start() : end]


def _method_returns_true(source: str, method_name: str) -> bool:
    body = _without_php_comments(_php_method_region(source, method_name))
    return bool(re.search(r"return\s+true\s*;", body))


def _cloud_token_policy_contract(source: str) -> dict[str, bool]:
    view = _without_php_comments(_php_method_region(source, "view"))
    return {
        "view_requires_admin": bool(
            re.search(r"return\s+\$user->isAdmin\(\)\s*;", view)
        ),
    }


def _api_token_policy_contract(source: str) -> dict[str, bool]:
    return {
        "authenticated_member_can_create_token": _method_returns_true(
            source, "create"
        ),
        "candidate_member_can_request_write_ability": _method_returns_true(
            source, "useWritePermissions"
        ),
    }


def _route_has_ability(source: str, path: str, ability: str) -> bool:
    route = re.search(
        rf"Route::(?:get|post)\(\s*['\"]{re.escape(path)}['\"].*?;",
        source,
        re.DOTALL,
    )
    if route is None:
        return False
    return bool(
        re.search(
            rf"middleware\(\s*\[\s*['\"]api\.ability:{ability}['\"]\s*\]",
            route.group(0),
        )
    )


def _hetzner_method_contract(source: str, method_name: str) -> dict[str, bool]:
    body = _php_method_region(source, method_name)
    return {
        "team_scoped_cloud_token_lookup": bool(
            re.search(
                r"CloudProviderToken::whereTeamId\(\$teamId\).*?"
                r"->whereUuid\(\$request->cloud_provider_token_id\).*?"
                r"->where\(\s*['\"]provider['\"]\s*,\s*['\"]hetzner['\"]\s*\)",
                body,
                re.DOTALL,
            )
        ),
        "authorizes_cloud_token_view": bool(
            re.search(
                r"\$this->authorize\(\s*['\"]view['\"]\s*,\s*\$token\s*\)",
                body,
            )
        ),
        "uses_stored_secret_as_hetzner_credential": bool(
            re.search(r"new HetznerService\(\$token->token\)", body)
        ),
        "returns_external_provider_data": "return response()->json(" in body,
    }


def _token_validation_contract(source: str) -> dict[str, bool]:
    method_name = (
        "validateToken"
        if re.search(r"^\s*public function validateToken\s*\(", source, re.MULTILINE)
        else "validate"
    )
    body = _php_method_region(source, method_name)
    return {
        "team_scoped_cloud_token_lookup": bool(
            re.search(
                r"CloudProviderToken::whereTeamId\(\$teamId\)"
                r"->whereUuid\(\$request->uuid\)->first\(\)",
                body,
            )
        ),
        "authorizes_cloud_token_view": bool(
            re.search(
                r"\$this->authorize\(\s*['\"]view['\"]\s*,"
                r"\s*\$cloudToken\s*\)",
                body,
            )
        ),
        "uses_stored_provider_secret": bool(
            "$cloudToken->token" in body
            and (
                "Http::withHeaders" in body
                or "$this->validateProviderToken" in body
            )
        ),
    }


def _auth_provider_has_cloud_token_mapping(source: str) -> bool:
    return bool(
        re.search(
            r"(?:\\App\\Models\\)?CloudProviderToken::class\s*=>\s*"
            r"(?:\\App\\Policies\\)?CloudProviderTokenPolicy::class",
            source,
        )
    )


def _evaluate_sources(
    routes_source: str,
    hetzner_controller_source: str,
    token_controller_source: str,
    cloud_token_policy_source: str,
    api_token_policy_source: str,
    auth_provider_source: str,
) -> dict[str, object]:
    routes = {
        method: _route_has_ability(routes_source, path, "read")
        for method, path in READ_ENDPOINTS.items()
    }
    methods = {
        method: _hetzner_method_contract(hetzner_controller_source, method)
        for method in READ_ENDPOINTS
    }
    validation = _token_validation_contract(token_controller_source)
    cloud_policy = _cloud_token_policy_contract(cloud_token_policy_source)
    api_policy = _api_token_policy_contract(api_token_policy_source)
    mapping = _auth_provider_has_cloud_token_mapping(auth_provider_source)
    member_is_admin = False
    member_view_allowed = not cloud_policy["view_requires_admin"] or member_is_admin

    active_methods: dict[str, bool] = {}
    for method, contract in methods.items():
        authorization_passes = (
            not contract["authorizes_cloud_token_view"] or member_view_allowed
        )
        active_methods[method] = bool(
            api_policy["authenticated_member_can_create_token"]
            and routes[method]
            and contract["team_scoped_cloud_token_lookup"]
            and contract["uses_stored_secret_as_hetzner_credential"]
            and contract["returns_external_provider_data"]
            and authorization_passes
        )

    validation_authorization_passes = (
        not validation["authorizes_cloud_token_view"] or member_view_allowed
    )
    validation_active = bool(
        api_policy["authenticated_member_can_create_token"]
        and _route_has_ability(
            routes_source, "/cloud-tokens/{uuid}/validate", "read"
        )
        and validation["team_scoped_cloud_token_lookup"]
        and validation["uses_stored_provider_secret"]
        and validation_authorization_passes
    )
    return {
        "read_routes": routes,
        "hetzner_methods": methods,
        "stored_token_validation": validation,
        "cloud_token_policy": cloud_policy,
        "api_token_policy": api_policy,
        "cloud_token_policy_mapping_present": mapping,
        "same_team_member_is_admin": member_is_admin,
        "same_team_member_view_policy_allowed": member_view_allowed,
        "same_team_member_external_calls": active_methods,
        "same_team_member_token_validation_call": validation_active,
        "same_team_member_stored_credential_use_active": bool(
            any(active_methods.values()) or validation_active
        ),
    }


def _execute_revision(
    repository: Path,
    *,
    label: str,
    revision: str,
) -> dict[str, object]:
    source_paths = (
        ROUTES_PATH,
        HETZNER_CONTROLLER_PATH,
        TOKEN_CONTROLLER_PATH,
        CLOUD_TOKEN_POLICY_PATH,
        API_TOKEN_POLICY_PATH,
        AUTH_PROVIDER_PATH,
    )
    blobs = {
        source_path: _git_blob(repository, revision, source_path)
        for source_path in source_paths
    }
    sources = {
        source_path: blob.decode("utf-8", errors="strict")
        for source_path, blob in blobs.items()
    }
    metadata = _commit_metadata(repository, revision)
    return {
        "label": label,
        "revision": revision,
        "resolved_commit": metadata["sha"],
        "blob_sha256": {
            source_path: hashlib.sha256(blob).hexdigest()
            for source_path, blob in blobs.items()
        },
        "evaluation": _evaluate_sources(
            sources[ROUTES_PATH],
            sources[HETZNER_CONTROLLER_PATH],
            sources[TOKEN_CONTROLLER_PATH],
            sources[CLOUD_TOKEN_POLICY_PATH],
            sources[API_TOKEN_POLICY_PATH],
            sources[AUTH_PROVIDER_PATH],
        ),
    }


def _line_number_after(source: str, marker: str, after: str) -> int:
    lines = source.splitlines()
    starts = [index for index, line in enumerate(lines) if after in line]
    if not starts:
        raise SystemExit(f"scope marker {after!r} is absent")
    matches = [
        index + 1
        for index, line in enumerate(lines)
        if marker in line and any(start <= index for start in starts)
    ]
    if not matches:
        raise SystemExit(f"marker {marker!r} is absent after {after!r}")
    return matches[0]


def _blame_marker(
    repository: Path,
    revision: str,
    source_path: str,
    marker: str,
    *,
    after: str,
) -> dict[str, object]:
    source = _git_blob(repository, revision, source_path).decode("utf-8")
    line = _line_number_after(source, marker, after)
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


def _repair_test_contract(source: str) -> dict[str, bool]:
    return {
        "member_read_token_case_present": (
            "member read token cannot use a stored cloud provider token" in source
        ),
        "member_role_present": "['role' => 'member']" in source,
        "read_ability_present": "createToken('member-read', ['read'])" in source,
        "stored_team_token_used": (
            "cloud_provider_token_id='.$this->hetznerToken->uuid" in source
        ),
        "forbidden_assertion_present": "$response->assertForbidden();" in source,
        "no_external_request_assertion_present": "Http::assertNothingSent();" in source,
    }


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    runs = [
        _execute_revision(
            repository,
            label="direct_ai_origin",
            revision=AI_ORIGIN_SHA,
        ),
        _execute_revision(
            repository,
            label="security_repair",
            revision=SECURITY_REPAIR_SHA,
        ),
    ]
    evaluations = {str(run["label"]): run["evaluation"] for run in runs}
    commits = {
        revision: _commit_metadata(repository, revision)
        for revision in (AI_ORIGIN_SHA, SECURITY_REPAIR_SHA)
    }
    baseline_absence = {
        source_path: not _path_exists(repository, BASELINE_SHA, source_path)
        for source_path in (HETZNER_CONTROLLER_PATH, TOKEN_CONTROLLER_PATH)
    }
    ancestry = {
        "baseline_reaches_ai_origin": _is_ancestor(
            repository, BASELINE_SHA, AI_ORIGIN_SHA
        ),
        "ai_origin_reaches_security_repair": _is_ancestor(
            repository, AI_ORIGIN_SHA, SECURITY_REPAIR_SHA
        ),
    }
    line_origins = {
        "origin_locations_route": _blame_marker(
            repository,
            AI_ORIGIN_SHA,
            ROUTES_PATH,
            "Route::get('/hetzner/locations'",
            after="Route::group([",
        ),
        "origin_locations_stored_credential_use": _blame_marker(
            repository,
            AI_ORIGIN_SHA,
            HETZNER_CONTROLLER_PATH,
            "new HetznerService($token->token);",
            after="public function locations",
        ),
        "repair_locations_view_authorization": _blame_marker(
            repository,
            SECURITY_REPAIR_SHA,
            HETZNER_CONTROLLER_PATH,
            "$this->authorize('view', $token);",
            after="public function locations",
        ),
    }
    repair_test = _repair_test_contract(
        _git_blob(repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH).decode(
            "utf-8"
        )
    )
    origin = evaluations["direct_ai_origin"]
    repair = evaluations["security_repair"]
    witness_passed = bool(
        commits[AI_ORIGIN_SHA]["explicit_claude_signal"] is True
        and commits[SECURITY_REPAIR_SHA]["explicit_claude_signal"] is False
        and commits[AI_ORIGIN_SHA]["parents"] == [BASELINE_SHA]
        and all(baseline_absence.values())
        and all(ancestry.values())
        and all(origin["read_routes"].values())
        and all(
            contract["team_scoped_cloud_token_lookup"]
            and contract["uses_stored_secret_as_hetzner_credential"]
            and not contract["authorizes_cloud_token_view"]
            for contract in origin["hetzner_methods"].values()
        )
        and origin["same_team_member_stored_credential_use_active"] is True
        and all(
            contract["authorizes_cloud_token_view"]
            for contract in repair["hetzner_methods"].values()
        )
        and repair["stored_token_validation"]["authorizes_cloud_token_view"]
        is True
        and repair["cloud_token_policy"]["view_requires_admin"] is True
        and repair["cloud_token_policy_mapping_present"] is True
        and repair["same_team_member_stored_credential_use_active"] is False
        and all(repair_test.values())
        and line_origins["origin_locations_route"]["origin_sha"]
        == AI_ORIGIN_SHA
        and line_origins["origin_locations_stored_credential_use"]["origin_sha"]
        == AI_ORIGIN_SHA
        and line_origins["repair_locations_view_authorization"]["origin_sha"]
        == SECURITY_REPAIR_SHA
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": (
            "coolify_hetzner_cloud_token_authorization_compositional_witness"
        ),
        "repository_identity": "github.com/coollabsio/coolify",
        "baseline_absence": baseline_absence,
        "commit_metadata": commits,
        "ancestry": ancestry,
        "line_origins": line_origins,
        "repair_test_contract": repair_test,
        "runs": runs,
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_COMPOSITIONAL_DIRECT_AI_ROOT",
        "causal_role": "unauthorized_stored_cloud_credential_use",
        "member_ai_authorship_claim": True,
        "direct_ai_root_claim": True,
        "human_activation_required": False,
        "counting": {
            "mechanism_level_true_positive": True,
            "cve_specific_true_positive": False,
            "advisory_linkage_status": "NO_CVE_MAPPING_CLAIMED",
            "reason": (
                "The parent lacks the API, the directly Claude-attributed commit "
                "introduces it without resource authorization, and the later "
                "security repair adds an executable member-forbidden contract."
            ),
        },
        "claim_boundary": (
            "The witness proves a directly AI-originated stored-credential "
            "authorization defect. The parent has no cloud-token or Hetzner API "
            "controllers. The Claude-attributed candidate creates read-capable "
            "Hetzner discovery and token-validation endpoints that resolve a "
            "team token, decrypt it, and use it against the external provider "
            "without authorizing the caller under the admin-only token policy. "
            "The repair adds view authorization to every credential-using entry "
            "point and a feature test requiring a same-team member read token to "
            "receive 403 before any external HTTP request. This proves a "
            "mechanism-level confused-deputy/credential-use finding; it does not "
            "claim raw token disclosure, a CVE mapping, or a real Hetzner request."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify Hetzner cloud-token authorization witness frozen")
    print(
        "  origin member credential use : "
        f"{origin['same_team_member_stored_credential_use_active']}"
    )
    print(
        "  repair member credential use : "
        f"{repair['same_team_member_stored_credential_use_active']}"
    )
    print(f"  repair test contract         : {all(repair_test.values())}")
    print(f"  witness                      : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output                       : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
