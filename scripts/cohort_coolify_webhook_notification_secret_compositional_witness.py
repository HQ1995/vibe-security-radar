#!/usr/bin/env python3
"""Freeze the Coolify webhook-secret mixed-origin authorization witness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


BASELINE_SHA = "503da6da216e8d9a069868dfc3c3cd48efbd1d2f"
AI_FEATURE_ORIGIN_SHA = "27879377a07a88d2070a2939b2856cd0273eac52"
AI_POLICY_WIRING_SHA = "eea372d702fae8b99574dd2e690db21634348676"
AI_UI_PRESERVATION_SHA = "0303f529d310df25eece67ee6a5d01a2e8efcf9d"
HUMAN_ACTIVATION_SHA = "86b05b902aedbbb074e73bfe233b3ed006f19b39"
SECURITY_REPAIR_SHA = "5973bb4d4f3c236d76ac25cb77c22e5317d5379f"

COMPONENT_PATH = "app/Livewire/Notifications/Webhook.php"
MODEL_PATH = "app/Models/WebhookNotificationSettings.php"
BLADE_PATH = "resources/views/livewire/notifications/webhook.blade.php"
POLICY_PATH = "app/Policies/NotificationPolicy.php"
AUTH_PROVIDER_PATH = "app/Providers/AuthServiceProvider.php"
ROUTES_PATH = "routes/web.php"
REPAIR_TEST_PATH = "tests/Feature/Authorization/NotificationAuthorizationTest.php"


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


def _notification_policy_semantics(source: str) -> dict[str, str]:
    semantics: dict[str, str] = {}
    for ability in ("view", "update"):
        body = _without_php_comments(_php_method_body(source, ability))
        if re.search(r"return\s+true\s*;", body):
            semantics[ability] = "allow_all_authenticated"
        elif ability == "view" and re.search(
            r"\$user->teams->contains\(\s*['\"]id['\"]\s*,"
            r"\s*\$notificationSettings->team->id\s*\)",
            body,
        ):
            semantics[ability] = "same_team_member"
        elif ability == "update" and "isAdminOfTeam($teamId)" in body:
            semantics[ability] = "same_team_admin"
        else:
            raise ValueError(f"unsupported NotificationPolicy::{ability} body")
    return semantics


def _same_team_non_admin_allowed(rule: str) -> bool:
    if rule in {"allow_all_authenticated", "same_team_member"}:
        return True
    if rule == "same_team_admin":
        return False
    raise ValueError(f"unsupported notification policy rule: {rule}")


def _component_secret_flow(source: str) -> dict[str, bool | str]:
    mount_body = _php_method_body(source, "mount")
    sync_body = _php_method_body(source, "syncData")
    direct_assignment = bool(
        re.search(
            r"\$this->webhookUrl\s*=\s*\$this->settings->webhook_url\s*;",
            sync_body,
        )
    )
    update_gated_assignment = bool(
        re.search(
            r"\$this->webhookUrl\s*=\s*auth\(\)->user\(\)->can\("
            r"\s*['\"]update['\"]\s*,\s*\$this->settings\s*\)\s*"
            r"\?\s*\$this->settings->webhook_url\s*:\s*null\s*;",
            sync_body,
            re.DOTALL,
        )
    )
    if direct_assignment == update_gated_assignment:
        raise ValueError("expected exactly one webhook secret read strategy")
    return {
        "public_webhook_url_property": bool(
            re.search(
                r"public\s+\?string\s+\$webhookUrl\s*=\s*null\s*;",
                source,
            )
        ),
        "mount_uses_current_team_settings": (
            "$this->team = auth()->user()->currentTeam();" in mount_body
            and "$this->settings = $this->team->webhookNotificationSettings;"
            in mount_body
        ),
        "mount_authorizes_view": bool(
            re.search(
                r"\$this->authorize\(\s*['\"]view['\"]\s*,"
                r"\s*\$this->settings\s*\)\s*;",
                mount_body,
            )
        ),
        "mount_calls_sync_data": "$this->syncData();" in mount_body,
        "read_strategy": (
            "unconditional_copy" if direct_assignment else "update_permission_gate"
        ),
        "direct_secret_copy_to_public_property": direct_assignment,
        "update_gated_secret_copy_to_public_property": update_gated_assignment,
    }


def _model_uses_encrypted_cast(source: str) -> bool:
    return bool(
        re.search(
            r"['\"]webhook_url['\"]\s*=>\s*['\"]encrypted['\"]",
            source,
        )
    )


def _auth_provider_has_mapping(source: str) -> bool:
    return bool(
        re.search(
            r"(?:\\App\\Models\\)?WebhookNotificationSettings::class\s*=>\s*"
            r"(?:\\App\\Policies\\)?NotificationPolicy::class",
            source,
        )
    )


def _authenticated_webhook_route(source: str) -> bool:
    middleware = "Route::middleware(['auth', 'verified'])->group(function () {"
    route = (
        "Route::get('/webhook', NotificationWebhook::class)"
        "->name('notifications.webhook');"
    )
    middleware_index = source.find(middleware)
    route_index = source.find(route)
    return middleware_index >= 0 and route_index > middleware_index


def _blade_secret_field(source: str) -> dict[str, bool | str]:
    bound_field = bool(re.search(r"\bid\s*=\s*['\"]webhookUrl['\"]", source))
    gate_index = source.find("@can('update', $settings)")
    field_index = source.find('id="webhookUrl"')
    hidden_index = source.find("Hidden (only admins can view)")
    admin_only = (
        gate_index >= 0
        and field_index > gate_index
        and hidden_index > field_index
        and "@else" in source[field_index:hidden_index]
    )
    return {
        "bound_webhook_url_field_present": bound_field,
        "password_input_type": 'type="password"' in source,
        "admin_only_bound_field": admin_only,
        "non_admin_hidden_placeholder": hidden_index >= 0,
        "visibility": "admin_only" if admin_only else "all_authorized_viewers",
    }


def _evaluate_sources(
    component_source: str,
    model_source: str,
    blade_source: str,
    policy_source: str,
    auth_provider_source: str,
    routes_source: str,
) -> dict[str, object]:
    policy_semantics = _notification_policy_semantics(policy_source)
    member_permissions = {
        ability: _same_team_non_admin_allowed(rule)
        for ability, rule in policy_semantics.items()
    }
    component_flow = _component_secret_flow(component_source)
    model_encrypted = _model_uses_encrypted_cast(model_source)
    policy_mapping = _auth_provider_has_mapping(auth_provider_source)
    authenticated_route = _authenticated_webhook_route(routes_source)
    blade_field = _blade_secret_field(blade_source)
    mount_path_ready = bool(
        component_flow["public_webhook_url_property"]
        and component_flow["mount_uses_current_team_settings"]
        and component_flow["mount_authorizes_view"]
        and component_flow["mount_calls_sync_data"]
        and model_encrypted
        and policy_mapping
        and authenticated_route
        and member_permissions["view"]
    )
    member_secret_copy = bool(
        component_flow["direct_secret_copy_to_public_property"]
        or (
            component_flow["update_gated_secret_copy_to_public_property"]
            and member_permissions["update"]
        )
    )
    member_secret_in_public_state = bool(mount_path_ready and member_secret_copy)
    view_update_separated = bool(
        member_permissions["view"] and not member_permissions["update"]
    )
    return {
        "notification_policy_semantics": policy_semantics,
        "same_team_non_admin_permissions": member_permissions,
        "view_update_roles_are_separated": view_update_separated,
        "component_secret_flow": component_flow,
        "model_webhook_url_uses_encrypted_cast": model_encrypted,
        "webhook_notification_policy_mapping_present": policy_mapping,
        "authenticated_webhook_route_present": authenticated_route,
        "blade_secret_field": blade_field,
        "same_team_non_admin_secret_loaded_into_public_state": (
            member_secret_in_public_state
        ),
        "least_privilege_violation_active": bool(
            member_secret_in_public_state and view_update_separated
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
        MODEL_PATH,
        BLADE_PATH,
        POLICY_PATH,
        AUTH_PROVIDER_PATH,
        ROUTES_PATH,
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
            sources[MODEL_PATH],
            sources[BLADE_PATH],
            sources[POLICY_PATH],
            sources[AUTH_PROVIDER_PATH],
            sources[ROUTES_PATH],
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


def _repair_test_contract(source: str) -> dict[str, bool]:
    return {
        "member_secret_test_present": (
            "test('member cannot view notification secrets'" in source
        ),
        "member_public_property_must_be_null": (
            "->assertSet($property, null)" in source
        ),
        "member_render_must_exclude_secret": "->assertDontSee($value)" in source,
        "generic_webhook_case_present": (
            "'generic webhook'" in source
            and "'webhook_url' => 'https://example.com/secret-webhook'" in source
        ),
        "admin_secret_test_present": (
            "test('admin can view notification secrets'" in source
        ),
        "admin_public_property_keeps_secret": (
            "->assertSet($property, $value)" in source
        ),
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
        ("ai_wired_latent_state", AI_POLICY_WIRING_SHA),
        ("ai_ui_preservation_state", AI_UI_PRESERVATION_SHA),
        ("human_policy_activation", HUMAN_ACTIVATION_SHA),
        ("security_repair", SECURITY_REPAIR_SHA),
    )
    runs = [
        _execute_revision(repository, label=label, revision=revision)
        for label, revision in revisions
    ]
    evaluations = {str(run["label"]): run["evaluation"] for run in runs}
    tracked_commits = (
        AI_FEATURE_ORIGIN_SHA,
        AI_POLICY_WIRING_SHA,
        AI_UI_PRESERVATION_SHA,
        HUMAN_ACTIVATION_SHA,
        SECURITY_REPAIR_SHA,
    )
    commits = {
        revision: _commit_metadata(repository, revision)
        for revision in tracked_commits
    }
    baseline_absence = {
        source_path: not _path_exists(repository, BASELINE_SHA, source_path)
        for source_path in (COMPONENT_PATH, MODEL_PATH, BLADE_PATH)
    }
    ancestry = {
        "baseline_reaches_feature_origin": _is_ancestor(
            repository, BASELINE_SHA, AI_FEATURE_ORIGIN_SHA
        ),
        "feature_origin_reaches_policy_wiring": _is_ancestor(
            repository, AI_FEATURE_ORIGIN_SHA, AI_POLICY_WIRING_SHA
        ),
        "policy_wiring_reaches_ui_preservation": _is_ancestor(
            repository, AI_POLICY_WIRING_SHA, AI_UI_PRESERVATION_SHA
        ),
        "ui_preservation_reaches_human_activation": _is_ancestor(
            repository, AI_UI_PRESERVATION_SHA, HUMAN_ACTIVATION_SHA
        ),
        "human_activation_reaches_security_repair": _is_ancestor(
            repository, HUMAN_ACTIVATION_SHA, SECURITY_REPAIR_SHA
        ),
    }
    line_origins = {
        "activation_public_webhook_url_property": _blame_marker(
            repository,
            HUMAN_ACTIVATION_SHA,
            COMPONENT_PATH,
            "public ?string $webhookUrl = null;",
            after="class Webhook extends Component",
        ),
        "activation_unconditional_secret_copy": _blame_marker(
            repository,
            HUMAN_ACTIVATION_SHA,
            COMPONENT_PATH,
            "$this->webhookUrl = $this->settings->webhook_url;",
            after="public function syncData",
        ),
        "activation_encrypted_model_cast": _blame_marker(
            repository,
            HUMAN_ACTIVATION_SHA,
            MODEL_PATH,
            "'webhook_url' => 'encrypted',",
            after="protected function casts",
        ),
        "activation_policy_mapping": _blame_marker(
            repository,
            HUMAN_ACTIVATION_SHA,
            AUTH_PROVIDER_PATH,
            "\\App\\Models\\WebhookNotificationSettings::class => "
            "\\App\\Policies\\NotificationPolicy::class,",
            after="Notification policies",
        ),
        "activation_bound_secret_field": _blame_marker(
            repository,
            HUMAN_ACTIVATION_SHA,
            BLADE_PATH,
            'required id="webhookUrl" label="Webhook URL (POST)" />',
            after='<div class="flex items-end gap-2">',
        ),
        "repair_update_permission_gate": _blame_marker(
            repository,
            SECURITY_REPAIR_SHA,
            COMPONENT_PATH,
            "auth()->user()->can('update', $this->settings)",
            after="public function syncData",
        ),
        "repair_admin_only_blade_gate": _blame_marker(
            repository,
            SECURITY_REPAIR_SHA,
            BLADE_PATH,
            "@can('update', $settings)",
            after='<div class="flex items-end gap-2">',
        ),
    }
    repair_test_source = _git_blob(
        repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH
    ).decode("utf-8")
    repair_contract = _repair_test_contract(repair_test_source)

    wired = evaluations["ai_wired_latent_state"]
    ui_preservation = evaluations["ai_ui_preservation_state"]
    activation = evaluations["human_policy_activation"]
    repair = evaluations["security_repair"]
    witness_passed = bool(
        commits[AI_FEATURE_ORIGIN_SHA]["explicit_claude_signal"] is True
        and commits[AI_POLICY_WIRING_SHA]["explicit_claude_signal"] is True
        and commits[AI_UI_PRESERVATION_SHA]["explicit_claude_signal"] is True
        and commits[HUMAN_ACTIVATION_SHA]["explicit_claude_signal"] is False
        and commits[SECURITY_REPAIR_SHA]["explicit_claude_signal"] is False
        and commits[AI_FEATURE_ORIGIN_SHA]["parents"] == [BASELINE_SHA]
        and all(baseline_absence.values())
        and all(ancestry.values())
        and wired["same_team_non_admin_permissions"]
        == {"view": True, "update": True}
        and wired["same_team_non_admin_secret_loaded_into_public_state"] is True
        and wired["least_privilege_violation_active"] is False
        and ui_preservation["same_team_non_admin_permissions"]
        == {"view": True, "update": True}
        and ui_preservation["same_team_non_admin_secret_loaded_into_public_state"]
        is True
        and ui_preservation["least_privilege_violation_active"] is False
        and activation["same_team_non_admin_permissions"]
        == {"view": True, "update": False}
        and activation["component_secret_flow"]["read_strategy"]
        == "unconditional_copy"
        and activation["same_team_non_admin_secret_loaded_into_public_state"]
        is True
        and activation["least_privilege_violation_active"] is True
        and repair["same_team_non_admin_permissions"]
        == {"view": True, "update": False}
        and repair["component_secret_flow"]["read_strategy"]
        == "update_permission_gate"
        and repair["same_team_non_admin_secret_loaded_into_public_state"] is False
        and repair["least_privilege_violation_active"] is False
        and repair["blade_secret_field"]["admin_only_bound_field"] is True
        and all(repair_contract.values())
        and line_origins["activation_public_webhook_url_property"]["origin_sha"]
        == AI_FEATURE_ORIGIN_SHA
        and line_origins["activation_unconditional_secret_copy"]["origin_sha"]
        == AI_FEATURE_ORIGIN_SHA
        and line_origins["activation_encrypted_model_cast"]["origin_sha"]
        == AI_FEATURE_ORIGIN_SHA
        and line_origins["activation_policy_mapping"]["origin_sha"]
        == AI_POLICY_WIRING_SHA
        and line_origins["activation_bound_secret_field"]["origin_sha"]
        == AI_UI_PRESERVATION_SHA
        and line_origins["repair_update_permission_gate"]["origin_sha"]
        == SECURITY_REPAIR_SHA
        and line_origins["repair_admin_only_blade_gate"]["origin_sha"]
        == SECURITY_REPAIR_SHA
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": (
            "coolify_webhook_notification_secret_compositional_witness"
        ),
        "repository_identity": "github.com/coollabsio/coolify",
        "baseline_absence": baseline_absence,
        "commit_metadata": commits,
        "ancestry": ancestry,
        "line_origins": line_origins,
        "repair_test_contract": repair_contract,
        "runs": runs,
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_COMPOSITIONAL_AI_SECURITY_CONTRIBUTOR",
        "causal_role": "latent_secret_exposure_with_human_policy_activation",
        "member_ai_authorship_claim": True,
        "direct_ai_root_claim": False,
        "human_activation_required": True,
        "counting": {
            "mechanism_level_true_positive": True,
            "cve_specific_true_positive": False,
            "advisory_linkage_status": "NO_CVE_MAPPING_CLAIMED",
            "reason": (
                "The source and repair tests establish a concrete notification "
                "secret exposure, but this witness does not map it to a CVE."
            ),
        },
        "claim_boundary": (
            "The witness proves a mixed-origin notification-secret exposure. "
            "Directly Claude-attributed commits created the encrypted webhook "
            "setting, copied its decrypted value into a public Livewire property, "
            "registered the shared policy, and preserved the bound UI field. At "
            "that point view and update were both permissive, so the mistake was "
            "latent rather than a role differential. A later non-AI-attributed "
            "policy repair made same-team view member-accessible and update "
            "admin-only while preserving the unconditional secret copy. The "
            "security repair gates the copy on update permission, hides the bound "
            "field, and adds tests requiring the member property to be null while "
            "admins retain the secret. This is a mechanism-level finding only; no "
            "CVE mapping or independently AI-rooted claim is made."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify webhook-secret compositional witness frozen")
    print(
        "  AI feature signal          : "
        f"{commits[AI_FEATURE_ORIGIN_SHA]['explicit_claude_signal']}"
    )
    print(f"  latent member rights       : {wired['same_team_non_admin_permissions']}")
    print(
        "  activated member rights    : "
        f"{activation['same_team_non_admin_permissions']}"
    )
    print(
        "  activated public secret    : "
        f"{activation['least_privilege_violation_active']}"
    )
    print(
        "  repaired member secret     : "
        f"{repair['same_team_non_admin_secret_loaded_into_public_state']}"
    )
    print(f"  witness                    : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output                     : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
