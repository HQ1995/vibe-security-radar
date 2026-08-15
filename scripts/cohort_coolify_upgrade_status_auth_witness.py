#!/usr/bin/env python3
"""Freeze Coolify's short-lived AI-authored upgrade-status disclosure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


BASELINE_SHA = "0aa7e376b29b7b912dc771a2c237a8cd8c65d7eb"
AI_ORIGIN_SHA = "b8cfc3f7c911661efae919c7b3cb9e7d8de8dcca"
AI_DATA_REDUCTION_SHA = "dc9f612df47f2c426cbcd4e80b6ace347ead6edc"
AI_AUTH_REPAIR_SHA = "3cc416a8069eed98bb342c09700a6e5084444a94"
AI_WEB_AUTH_REPAIR_SHA = "43ede6c523da5bef2f5116e371df8e4e9cc52679"

CONTROLLER_PATH = "app/Http/Controllers/Api/OtherController.php"
ROUTES_PATH = "routes/api.php"
UPGRADE_VIEW_PATH = "resources/views/livewire/upgrade.blade.php"

ROUTE_MARKER = "Route::get('/upgrade-status', [OtherController::class, 'upgradeStatus']);"


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


def _top_level_route_groups(source: str) -> list[dict[str, str]]:
    pattern = re.compile(
        r"^Route::group\(\[\n(?P<config>.*?)^\], function \(\) \{\n"
        r"(?P<body>.*?)^\}\);\s*$",
        re.DOTALL | re.MULTILINE,
    )
    return [match.groupdict() for match in pattern.finditer(source)]


def _route_security(source: str) -> dict[str, object]:
    route_lines = [
        line for line in source.splitlines() if ROUTE_MARKER in line
    ]
    group_routes: list[dict[str, object]] = []
    for group in _top_level_route_groups(source):
        if ROUTE_MARKER not in group["body"]:
            continue
        config = group["config"]
        middleware_match = re.search(r"['\"]middleware['\"]\s*=>\s*\[(?P<value>[^]]*)\]", config)
        middleware = []
        if middleware_match:
            middleware = re.findall(r"['\"]([^'\"]+)['\"]", middleware_match.group("value"))
        group_routes.append(
            {
                "middleware": middleware,
                "prefix_v1": bool(
                    re.search(r"['\"]prefix['\"]\s*=>\s*['\"]v1['\"]", config)
                ),
            }
        )
    grouped_count = len(group_routes)
    top_level_direct_count = sum(
        1 for line in route_lines if line.startswith(ROUTE_MARKER)
    )
    protected_group_count = sum(
        1
        for route in group_routes
        if "auth" in route["middleware"] or "auth:sanctum" in route["middleware"]
    )
    unprotected_count = (
        top_level_direct_count + grouped_count - protected_group_count
    )
    return {
        "route_count": len(route_lines),
        "top_level_direct_count": top_level_direct_count,
        "group_routes": group_routes,
        "protected_route_count": protected_group_count,
        "unprotected_route_count": unprotected_count,
        "all_upgrade_status_routes_authenticated": bool(
            route_lines and unprotected_count == 0
        ),
    }


def _controller_security(source: str) -> dict[str, bool]:
    body = _php_method_body(source, "upgradeStatus")
    return {
        "reads_upgrade_status_file": (
            "/data/coolify/source/.upgrade-status" in body
            and (
                "file_get_contents($statusFile)" in body
                or "instant_remote_process" in body
            )
        ),
        "returns_status_message": bool(
            re.search(r"['\"]message['\"]\s*=>\s*\$message", body)
        ),
        "checks_authenticated_user": "$user = auth()->user();" in body,
        "checks_root_team": bool(
            re.search(
                r"!\s*\$user\s*\|\|\s*\$user->currentTeam\(\)->id\s*!==\s*0",
                body,
            )
        ),
        "returns_forbidden": bool(
            re.search(r"response\(\)->json\(.*?,\s*403\s*\)", body, re.DOTALL)
        ),
    }


def _evaluate_sources(controller_source: str, routes_source: str) -> dict[str, object]:
    route_security = _route_security(routes_source)
    controller_security = _controller_security(controller_source)
    controller_guard = bool(
        controller_security["checks_authenticated_user"]
        and controller_security["checks_root_team"]
        and controller_security["returns_forbidden"]
    )
    disclosure = bool(
        route_security["unprotected_route_count"]
        and not controller_guard
        and controller_security["reads_upgrade_status_file"]
        and controller_security["returns_status_message"]
    )
    return {
        "route_security": route_security,
        "controller_security": controller_security,
        "controller_root_team_guard_present": controller_guard,
        "unauthenticated_upgrade_status_disclosure_path": disclosure,
    }


def _execute_revision(
    repository: Path,
    *,
    label: str,
    revision: str,
) -> dict[str, object]:
    blobs = {
        source_path: _git_blob(repository, revision, source_path)
        for source_path in (CONTROLLER_PATH, ROUTES_PATH)
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
            sources[CONTROLLER_PATH], sources[ROUTES_PATH]
        ),
    }


def _marker_lines(source: str, marker: str) -> list[int]:
    return [
        line_number
        for line_number, line in enumerate(source.splitlines(), start=1)
        if marker in line
    ]


def _blame_markers(
    repository: Path,
    revision: str,
    source_path: str,
    marker: str,
) -> list[dict[str, object]]:
    source = _git_blob(repository, revision, source_path).decode("utf-8")
    lines = _marker_lines(source, marker)
    if not lines:
        raise SystemExit(f"marker {marker!r} is absent from {revision}:{source_path}")
    origins: list[dict[str, object]] = []
    for line in lines:
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
        origins.append(
            {
                "path": source_path,
                "line": line,
                "marker": marker,
                "origin_sha": value.split(None, 1)[0].lstrip("^"),
            }
        )
    return origins


def _baseline_absence(repository: Path) -> dict[str, bool]:
    controller = _git_blob(repository, BASELINE_SHA, CONTROLLER_PATH).decode("utf-8")
    routes = _git_blob(repository, BASELINE_SHA, ROUTES_PATH).decode("utf-8")
    view = _git_blob(repository, BASELINE_SHA, UPGRADE_VIEW_PATH).decode("utf-8")
    return {
        "upgrade_status_controller_method_absent": (
            "function upgradeStatus" not in controller
        ),
        "upgrade_status_routes_absent": ROUTE_MARKER not in routes,
        "upgrade_status_frontend_poll_absent": (
            "fetch('/api/upgrade-status" not in view
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
        ("ai_origin", AI_ORIGIN_SHA),
        ("ai_data_reduction_without_auth", AI_DATA_REDUCTION_SHA),
        ("ai_auth_repair", AI_AUTH_REPAIR_SHA),
        ("ai_web_session_auth_repair", AI_WEB_AUTH_REPAIR_SHA),
    )
    runs = [
        _execute_revision(repository, label=label, revision=revision)
        for label, revision in revisions
    ]
    evaluations = {str(run["label"]): run["evaluation"] for run in runs}
    tracked_commits = (
        AI_ORIGIN_SHA,
        AI_DATA_REDUCTION_SHA,
        AI_AUTH_REPAIR_SHA,
        AI_WEB_AUTH_REPAIR_SHA,
    )
    commits = {
        revision: _commit_metadata(repository, revision)
        for revision in tracked_commits
    }
    ancestry = {
        "baseline_reaches_ai_origin": _is_ancestor(
            repository, BASELINE_SHA, AI_ORIGIN_SHA
        ),
        "ai_origin_reaches_data_reduction": _is_ancestor(
            repository, AI_ORIGIN_SHA, AI_DATA_REDUCTION_SHA
        ),
        "data_reduction_reaches_auth_repair": _is_ancestor(
            repository, AI_DATA_REDUCTION_SHA, AI_AUTH_REPAIR_SHA
        ),
        "auth_repair_reaches_web_auth_repair": _is_ancestor(
            repository, AI_AUTH_REPAIR_SHA, AI_WEB_AUTH_REPAIR_SHA
        ),
    }
    baseline_absence = _baseline_absence(repository)
    line_origins = {
        "data_reduction_upgrade_routes": _blame_markers(
            repository, AI_DATA_REDUCTION_SHA, ROUTES_PATH, ROUTE_MARKER
        ),
        "data_reduction_status_file_read": _blame_markers(
            repository,
            AI_DATA_REDUCTION_SHA,
            CONTROLLER_PATH,
            "$statusFile = '/data/coolify/source/.upgrade-status';",
        ),
        "auth_repair_root_guard": _blame_markers(
            repository,
            AI_WEB_AUTH_REPAIR_SHA,
            CONTROLLER_PATH,
            "$user = auth()->user();",
        ),
        "web_auth_repair_middleware": _blame_markers(
            repository,
            AI_WEB_AUTH_REPAIR_SHA,
            ROUTES_PATH,
            "'middleware' => ['web', 'auth'],",
        ),
    }

    origin = evaluations["ai_origin"]
    reduction = evaluations["ai_data_reduction_without_auth"]
    auth_repair = evaluations["ai_auth_repair"]
    web_auth_repair = evaluations["ai_web_session_auth_repair"]
    origin_time = commits[AI_ORIGIN_SHA]["authored_at"]
    auth_repair_time = commits[AI_AUTH_REPAIR_SHA]["authored_at"]
    witness_passed = bool(
        all(commit["explicit_claude_signal"] is True for commit in commits.values())
        and commits[AI_ORIGIN_SHA]["parents"] == [BASELINE_SHA]
        and all(baseline_absence.values())
        and all(ancestry.values())
        and origin["route_security"]["route_count"] == 2
        and origin["route_security"]["unprotected_route_count"] == 2
        and origin["controller_root_team_guard_present"] is False
        and origin["unauthenticated_upgrade_status_disclosure_path"] is True
        and reduction["route_security"]["unprotected_route_count"] == 2
        and reduction["unauthenticated_upgrade_status_disclosure_path"] is True
        and auth_repair["route_security"]["all_upgrade_status_routes_authenticated"]
        is True
        and auth_repair["controller_root_team_guard_present"] is True
        and auth_repair["unauthenticated_upgrade_status_disclosure_path"] is False
        and web_auth_repair["route_security"]["all_upgrade_status_routes_authenticated"]
        is True
        and web_auth_repair["controller_root_team_guard_present"] is True
        and web_auth_repair["unauthenticated_upgrade_status_disclosure_path"]
        is False
        and {
            item["origin_sha"]
            for item in line_origins["data_reduction_upgrade_routes"]
        }
        == {AI_ORIGIN_SHA}
        and {
            item["origin_sha"]
            for item in line_origins["data_reduction_status_file_read"]
        }
        == {AI_ORIGIN_SHA}
        and {
            item["origin_sha"]
            for item in line_origins["auth_repair_root_guard"]
        }
        == {AI_AUTH_REPAIR_SHA}
        and {
            item["origin_sha"]
            for item in line_origins["web_auth_repair_middleware"]
        }
        == {AI_WEB_AUTH_REPAIR_SHA}
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_upgrade_status_auth_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "baseline_absence": baseline_absence,
        "commit_metadata": commits,
        "ancestry": ancestry,
        "line_origins": line_origins,
        "runs": runs,
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_SECURITY_REGRESSION",
        "causal_role": "unauthenticated_upgrade_status_endpoint",
        "member_ai_authorship_claim": True,
        "direct_ai_root_claim": True,
        "human_activation_required": False,
        "exposure_window": {
            "origin_authored_at": origin_time,
            "first_auth_repair_authored_at": auth_repair_time,
            "intervening_commit_count": 1,
            "classification": "SHORT_LIVED_IN_COMMIT_HISTORY",
        },
        "counting": {
            "mechanism_level_true_positive": True,
            "cve_specific_true_positive": False,
            "advisory_linkage_status": "NO_CVE_MAPPING_CLAIMED",
            "release_exposure_claim": False,
            "reason": (
                "The AI-authored origin added two unauthenticated routes that "
                "returned upgrade status messages. A later AI-authored commit "
                "explicitly added authentication and a root-team guard."
            ),
        },
        "claim_boundary": (
            "The witness proves a direct, short-lived AI-authored security "
            "regression in commit history. The origin adds both upgrade-status "
            "routes without middleware and a controller that reads and returns "
            "the upgrade message without an authorization guard. The next commit "
            "describes reducing data exposure but leaves both routes unguarded. "
            "The following repair adds authenticated route groups and a root-team "
            "controller check; a subsequent repair switches browser calls to web "
            "session authentication. All four commits carry explicit Claude "
            "attribution. No CVE, release exposure, deployment, or exploitability "
            "beyond disclosure of the status message is claimed."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify upgrade-status auth witness frozen")
    print(f"  origin unprotected routes : {origin['route_security']['unprotected_route_count']}")
    print(
        "  origin disclosure path    : "
        f"{origin['unauthenticated_upgrade_status_disclosure_path']}"
    )
    print(
        "  repaired route auth       : "
        f"{web_auth_repair['route_security']['all_upgrade_status_routes_authenticated']}"
    )
    print(f"  witness                   : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output                    : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
