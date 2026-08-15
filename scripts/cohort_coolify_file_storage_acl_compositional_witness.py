#!/usr/bin/env python3
"""Freeze the Coolify file-storage mixed-origin authorization witness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


BASELINE_SHA = "07153de68de44ad2601d3683ed5ee6b9fe02ecfc"
LATENT_AI_SHA = "f152ec00ada70757da38e0b789f049b14d813e33"
HUMAN_ACTIVATION_SHA = "86b05b902aedbbb074e73bfe233b3ed006f19b39"
SECURITY_REPAIR_SHA = "c9246559994f5006390c7665825e3bbd60370bb6"

CVE_64420_AFFECTED_BOUNDARY = "v4.0.0-beta.434"
CVE_64420_ADVISORY_URL = (
    "https://github.com/coollabsio/coolify/security/advisories/GHSA-qwxj-qch7-whpc"
)

COMPONENT_PATH = "app/Livewire/Project/Service/FileStorage.php"
BLADE_PATH = "resources/views/livewire/project/service/file-storage.blade.php"
VOLUME_PATH = "app/Models/LocalFileVolume.php"
RESOURCE_POLICY_PATH = "app/Policies/ServiceApplicationPolicy.php"
SERVICE_POLICY_PATH = "app/Policies/ServicePolicy.php"
AUTH_PROVIDER_PATH = "app/Providers/AuthServiceProvider.php"

READ_ONLY_SECTION = "{{-- Read-only view --}}"
LOAD_BUTTON = 'wire:click="loadStorageOnServer"'


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


def _resolve_commit(repository: Path, revision: str) -> str:
    value = _git(repository, ["rev-parse", f"{revision}^{{commit}}"], text=True)
    assert isinstance(value, str)
    resolved = value.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", resolved):
        raise SystemExit(f"unexpected resolved commit for {revision}: {resolved!r}")
    return resolved


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
        ["git", "-C", str(repository), "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode not in {0, 1}:
        reason = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"cannot check ancestry {ancestor}..{descendant}: {reason}")
    return completed.returncode == 0


def _php_method_body(source: str, method_name: str) -> str:
    match = re.search(
        rf"^    public function {re.escape(method_name)}\s*\([^)]*\)"
        rf"(?:\s*:\s*[^\n{{]+)?\s*\n    \{{\n(?P<body>.*?)(?=^    \}}\s*$)",
        source,
        re.DOTALL | re.MULTILINE,
    )
    if not match:
        raise ValueError(f"public PHP method is absent: {method_name}")
    return match.group("body")


def _without_php_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", source)


def _component_load_ability(component_source: str) -> str:
    body = _php_method_body(component_source, "loadStorageOnServer")
    abilities = re.findall(
        r"\$this->authorize\(\s*['\"](?P<ability>[a-zA-Z]+)['\"]\s*,"
        r"\s*\$this->resource\s*\)\s*;",
        body,
    )
    if len(abilities) != 1:
        raise ValueError(f"expected one load authorization, found {abilities}")
    return abilities[0]


def _read_only_button_ability(blade_source: str) -> str | None:
    section_index = blade_source.find(READ_ONLY_SECTION)
    if section_index < 0:
        raise ValueError("read-only Blade section is absent")
    section = blade_source[section_index:]
    button_index = section.find(LOAD_BUTTON)
    if button_index < 0:
        return None
    prefix = section[:button_index]
    gates = re.findall(
        r"@can\(\s*['\"](?P<ability>[a-zA-Z]+)['\"]\s*,\s*\$resource\s*\)",
        prefix,
    )
    if not gates:
        raise ValueError("read-only load button has no preceding @can gate")
    return gates[-1]


def _service_policy_semantics(source: str) -> dict[str, str]:
    semantics: dict[str, str] = {}
    for ability in ("view", "update"):
        body = _without_php_comments(_php_method_body(source, ability))
        if re.search(r"return\s+true\s*;", body):
            semantics[ability] = "allow_all_authenticated"
        elif ability == "view" and "teams->contains('id', $teamId)" in body:
            semantics[ability] = "same_team_member"
        elif ability == "update" and "isAdminOfTeam($teamId)" in body:
            semantics[ability] = "same_team_admin"
        else:
            raise ValueError(f"unsupported ServicePolicy::{ability} body")
    return semantics


def _resource_policy_semantics(source: str) -> dict[str, str]:
    semantics: dict[str, str] = {}
    for ability in ("view", "update"):
        body = _without_php_comments(_php_method_body(source, ability))
        if re.search(r"return\s+true\s*;", body):
            semantics[ability] = "allow_all_authenticated"
            continue
        delegated = re.search(
            r"Gate::allows\(\s*['\"](?P<ability>view|update)['\"]\s*,"
            r"\s*\$serviceApplication->service\s*\)",
            body,
        )
        if not delegated:
            raise ValueError(f"unsupported ServiceApplicationPolicy::{ability} body")
        semantics[ability] = f"delegate_service_{delegated.group('ability')}"
    return semantics


def _same_team_member_allowed(
    ability: str,
    resource_semantics: dict[str, str],
    service_semantics: dict[str, str],
) -> bool:
    resource_rule = resource_semantics[ability]
    if resource_rule == "allow_all_authenticated":
        return True
    prefix = "delegate_service_"
    if not resource_rule.startswith(prefix):
        raise ValueError(f"unsupported resource policy rule: {resource_rule}")
    service_ability = resource_rule.removeprefix(prefix)
    service_rule = service_semantics[service_ability]
    if service_rule in {"allow_all_authenticated", "same_team_member"}:
        return True
    if service_rule == "same_team_admin":
        return False
    raise ValueError(f"unsupported service policy rule: {service_rule}")


def _storage_flow(component_source: str, volume_source: str) -> dict[str, bool]:
    load_body = _php_method_body(component_source, "loadStorageOnServer")
    sync_body = _php_method_body(component_source, "syncData")
    volume_body = _php_method_body(volume_source, "loadStorageOnServer")
    facts = {
        "component_has_public_content_property": bool(
            re.search(r"public\s+\?string\s+\$content\s*=\s*null\s*;", component_source)
        ),
        "component_invokes_volume_loader": (
            "$this->fileStorage->loadStorageOnServer();" in load_body
        ),
        "component_syncs_after_load": "$this->syncData();" in load_body,
        "volume_reads_remote_file": bool(
            re.search(
                r'instant_remote_process\(\["cat \{\$escapedPath\}"\],'
                r"\s*\$server,\s*false\s*\)",
                volume_body,
            )
        ),
        "volume_assigns_remote_content": "$this->content = $content;" in volume_body,
        "sync_copies_model_content_to_public_property": (
            "$this->content = $this->fileStorage->content;" in sync_body
        ),
    }
    facts["remote_file_reaches_public_component_property"] = all(facts.values())
    return facts


def _auth_provider_has_policy_mapping(source: str) -> bool:
    return bool(
        re.search(
            r"\\App\\Models\\ServiceApplication::class\s*=>\s*"
            r"\\App\\Policies\\ServiceApplicationPolicy::class",
            source,
        )
    )


def _evaluate_sources(
    component_source: str,
    blade_source: str,
    volume_source: str,
    resource_policy_source: str,
    service_policy_source: str,
    auth_provider_source: str,
) -> dict[str, object]:
    component_ability = _component_load_ability(component_source)
    button_ability = _read_only_button_ability(blade_source)
    resource_semantics = _resource_policy_semantics(resource_policy_source)
    service_semantics = _service_policy_semantics(service_policy_source)
    member_permissions = {
        ability: _same_team_member_allowed(
            ability, resource_semantics, service_semantics
        )
        for ability in ("view", "update")
    }
    storage_flow = _storage_flow(component_source, volume_source)
    method_allowed = member_permissions[component_ability]
    button_visible = (
        button_ability is not None and member_permissions[button_ability]
    )
    exposure_path = bool(
        method_allowed
        and button_visible
        and storage_flow["remote_file_reaches_public_component_property"]
    )
    view_update_separated = bool(
        member_permissions["view"] and not member_permissions["update"]
    )
    return {
        "component_load_ability": component_ability,
        "read_only_load_button_ability": button_ability,
        "resource_policy_semantics": resource_semantics,
        "service_policy_semantics": service_semantics,
        "same_team_non_admin_permissions": member_permissions,
        "same_team_non_admin_method_allowed": method_allowed,
        "same_team_non_admin_button_visible": button_visible,
        "view_update_roles_are_separated": view_update_separated,
        "storage_flow": storage_flow,
        "same_team_non_admin_remote_content_exposure_path": exposure_path,
        "least_privilege_violation_active": bool(
            exposure_path
            and view_update_separated
            and component_ability == "view"
            and button_ability == "view"
        ),
        "service_application_policy_mapping_present": (
            _auth_provider_has_policy_mapping(auth_provider_source)
        ),
    }


def _execute_revision(
    repository: Path,
    *,
    label: str,
    revision: str,
) -> dict[str, object]:
    source_paths = (
        COMPONENT_PATH,
        BLADE_PATH,
        VOLUME_PATH,
        RESOURCE_POLICY_PATH,
        SERVICE_POLICY_PATH,
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
            sources[COMPONENT_PATH],
            sources[BLADE_PATH],
            sources[VOLUME_PATH],
            sources[RESOURCE_POLICY_PATH],
            sources[SERVICE_POLICY_PATH],
            sources[AUTH_PROVIDER_PATH],
        ),
    }


def _line_number_after(source: str, marker: str, after: str) -> int:
    lines = source.splitlines()
    starts = [index for index, line in enumerate(lines) if after in line]
    if len(starts) != 1:
        raise SystemExit(f"expected one scope marker {after!r}, found {starts}")
    matches = [
        index + 1
        for index, line in enumerate(lines[starts[0] :], start=starts[0])
        if marker in line
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
    origin_sha = value.split(None, 1)[0].lstrip("^")
    return {
        "path": source_path,
        "line": line,
        "marker": marker,
        "origin_sha": origin_sha,
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

    revisions = (
        ("pre_ai_baseline", BASELINE_SHA),
        ("latent_ai_permission_change", LATENT_AI_SHA),
        ("human_policy_activation", HUMAN_ACTIVATION_SHA),
        ("security_repair", SECURITY_REPAIR_SHA),
    )
    runs = [
        _execute_revision(repository, label=label, revision=revision)
        for label, revision in revisions
    ]
    evaluations = {str(run["label"]): run["evaluation"] for run in runs}
    commits = {
        revision: _commit_metadata(repository, revision)
        for revision in (LATENT_AI_SHA, HUMAN_ACTIVATION_SHA, SECURITY_REPAIR_SHA)
    }
    affected_boundary_sha = _resolve_commit(repository, CVE_64420_AFFECTED_BOUNDARY)
    advisory_chronology = {
        "rejected_advisory": "CVE-2025-64420",
        "official_advisory_url": CVE_64420_ADVISORY_URL,
        "official_affected_boundary": CVE_64420_AFFECTED_BOUNDARY,
        "affected_boundary_sha": affected_boundary_sha,
        "affected_boundary_metadata": _commit_metadata(
            repository, affected_boundary_sha
        ),
        "affected_boundary_reaches_latent_ai": _is_ancestor(
            repository, affected_boundary_sha, LATENT_AI_SHA
        ),
        "latent_ai_reaches_affected_boundary": _is_ancestor(
            repository, LATENT_AI_SHA, affected_boundary_sha
        ),
    }
    advisory_linkage_excluded = bool(
        advisory_chronology["affected_boundary_reaches_latent_ai"] is True
        and advisory_chronology["latent_ai_reaches_affected_boundary"] is False
    )
    ancestry = {
        "baseline_reaches_latent_ai": _is_ancestor(
            repository, BASELINE_SHA, LATENT_AI_SHA
        ),
        "latent_ai_reaches_human_activation": _is_ancestor(
            repository, LATENT_AI_SHA, HUMAN_ACTIVATION_SHA
        ),
        "human_activation_reaches_security_repair": _is_ancestor(
            repository, HUMAN_ACTIVATION_SHA, SECURITY_REPAIR_SHA
        ),
    }
    line_origins = {
        "activation_component_view_gate": _blame_marker(
            repository,
            HUMAN_ACTIVATION_SHA,
            COMPONENT_PATH,
            "$this->authorize('view', $this->resource);",
            after="public function loadStorageOnServer()",
        ),
        "activation_read_only_view_button": _blame_marker(
            repository,
            HUMAN_ACTIVATION_SHA,
            BLADE_PATH,
            "@can('view', $resource)",
            after=READ_ONLY_SECTION,
        ),
        "repair_component_update_gate": _blame_marker(
            repository,
            SECURITY_REPAIR_SHA,
            COMPONENT_PATH,
            "$this->authorize('update', $this->resource);",
            after="public function loadStorageOnServer()",
        ),
        "repair_read_only_update_button": _blame_marker(
            repository,
            SECURITY_REPAIR_SHA,
            BLADE_PATH,
            "@can('update', $resource)",
            after=READ_ONLY_SECTION,
        ),
    }

    baseline = evaluations["pre_ai_baseline"]
    latent = evaluations["latent_ai_permission_change"]
    activation = evaluations["human_policy_activation"]
    repair = evaluations["security_repair"]
    witness_passed = bool(
        commits[LATENT_AI_SHA]["explicit_claude_signal"] is True
        and commits[HUMAN_ACTIVATION_SHA]["explicit_claude_signal"] is False
        and commits[SECURITY_REPAIR_SHA]["explicit_claude_signal"] is False
        and commits[LATENT_AI_SHA]["parents"] == [BASELINE_SHA]
        and advisory_linkage_excluded
        and all(ancestry.values())
        and all(
            evaluation["service_application_policy_mapping_present"] is True
            for evaluation in evaluations.values()
        )
        and baseline["component_load_ability"] == "update"
        and baseline["read_only_load_button_ability"] is None
        and baseline["view_update_roles_are_separated"] is False
        and latent["component_load_ability"] == "view"
        and latent["read_only_load_button_ability"] == "view"
        and latent["view_update_roles_are_separated"] is False
        and latent["least_privilege_violation_active"] is False
        and activation["component_load_ability"] == "view"
        and activation["read_only_load_button_ability"] == "view"
        and activation["same_team_non_admin_permissions"]
        == {"view": True, "update": False}
        and activation["storage_flow"]["remote_file_reaches_public_component_property"]
        is True
        and activation["least_privilege_violation_active"] is True
        and repair["component_load_ability"] == "update"
        and repair["read_only_load_button_ability"] == "update"
        and repair["same_team_non_admin_method_allowed"] is False
        and repair["same_team_non_admin_button_visible"] is False
        and repair["least_privilege_violation_active"] is False
        and line_origins["activation_component_view_gate"]["origin_sha"]
        == LATENT_AI_SHA
        and line_origins["activation_read_only_view_button"]["origin_sha"]
        == LATENT_AI_SHA
        and line_origins["repair_component_update_gate"]["origin_sha"]
        == SECURITY_REPAIR_SHA
        and line_origins["repair_read_only_update_button"]["origin_sha"]
        == SECURITY_REPAIR_SHA
    )

    payload = {
        "schema_version": 2,
        "artifact_kind": "coolify_file_storage_acl_compositional_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "commit_metadata": commits,
        "ancestry": ancestry,
        "advisory_chronology": advisory_chronology,
        "line_origins": line_origins,
        "runs": runs,
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_COMPOSITIONAL_AI_SECURITY_CONTRIBUTOR",
        "causal_role": "latent_permission_weakening_with_human_policy_activation",
        "member_ai_authorship_claim": True,
        "direct_ai_root_claim": False,
        "human_activation_required": True,
        "counting": {
            "mechanism_level_true_positive": True,
            "cve_specific_true_positive": False,
            "rejected_advisory": "CVE-2025-64420",
            "advisory_linkage_status": (
                "EXCLUDED_BY_AFFECTED_VERSION_CHRONOLOGY"
            ),
            "reason": (
                "The official advisory ends its affected range at "
                f"{CVE_64420_AFFECTED_BOUNDARY}. That tag is a strict ancestor "
                "of the latent AI permission change, so the AI change cannot have "
                "caused the vulnerability described by CVE-2025-64420."
            ),
        },
        "claim_boundary": (
            "The witness proves a mixed-origin security regression. The directly "
            "Claude-co-authored commit changed the server-side loader and its "
            "read-only UI button from update to view while the policies still "
            "allowed both roles, so it was a latent privilege mistake rather than "
            "an independently differential root. A later non-AI-attributed commit "
            "made same-team view available to members and update admin-only while "
            "preserving the AI-authored gates. That composition let a non-admin "
            "member trigger a remote file read whose content is copied into a "
            "public Livewire property. The sensitive-data repair changes both "
            "gates back to update. No remote command is executed by this witness. "
            "CVE-2025-64420 is explicitly excluded because its last affected tag "
            "is an ancestor of, and therefore predates, the AI-authored change."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify file-storage ACL compositional witness frozen")
    print(f"  latent explicit AI signal : {commits[LATENT_AI_SHA]['explicit_claude_signal']}")
    print(f"  baseline gate             : {baseline['component_load_ability']}")
    print(f"  activated member rights   : {activation['same_team_non_admin_permissions']}")
    print(f"  activated exposure path   : {activation['least_privilege_violation_active']}")
    print(f"  repaired member method    : {repair['same_team_non_admin_method_allowed']}")
    print(f"  CVE-specific count        : {payload['counting']['cve_specific_true_positive']}")
    print(f"  witness                   : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output                    : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
