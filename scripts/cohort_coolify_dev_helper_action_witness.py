#!/usr/bin/env python3
"""Freeze the Coolify AI-originated dev helper authorization witness."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)


BASELINE_SHA = "3fc626c6da793a65a3cd3f323800fbf61cdb85d9"
AI_ORIGIN_SHA = "18f30b7fabc54938a031867ad34c39a1e9c7c0d7"
SECURITY_REPAIR_SHA = "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e"
SOURCE_PATH = "app/Livewire/Settings/Index.php"
VIEW_PATH = "resources/views/livewire/settings/index.blade.php"
POLICY_PATH = "app/Policies/InstanceSettingsPolicy.php"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _optional_method(source: str, method_name: str) -> str | None:
    try:
        return _php_method_region(source, method_name)
    except ValueError:
        return None


def _evaluate(source: str, view: str) -> dict[str, bool]:
    mount = _optional_method(source, "mount")
    action = _optional_method(source, "buildHelperImage")
    return {
        "mount_has_instance_admin_redirect": bool(
            mount is not None and "if (! isInstanceAdmin())" in mount
        ),
        "public_build_helper_action": bool(
            action is not None
            and re.search(r"public function buildHelperImage\s*\(", action)
        ),
        "action_is_dev_limited": bool(action is not None and "if (! isDev())" in action),
        "action_invokes_remote_process": bool(
            action is not None and "remote_process(" in action
        ),
        "action_builds_host_helper_image": bool(
            action is not None
            and "docker build -t ghcr.io/coollabsio/coolify-helper:" in action
        ),
        "action_has_update_authorization": bool(
            action is not None
            and "$this->authorize('update', $this->settings)" in action
        ),
        "view_invokes_action": 'wire:click="buildHelperImage"' in view,
        "view_action_is_dev_limited": bool(
            re.search(
                r"@if\s*\(\s*isDev\(\)\s*\).*?wire:click=\"buildHelperImage\".*?@endif",
                view,
                re.DOTALL,
            )
        ),
    }


def _evaluate_policy(source: str) -> dict[str, bool]:
    update = _php_method_region(source, "update")
    return {
        "update_policy_present": True,
        "update_requires_instance_admin": "return isInstanceAdmin();" in update,
    }


def _line_in_method(source: str, method_name: str, marker: str) -> int:
    lines = source.splitlines()
    start_matches = [
        index
        for index, line in enumerate(lines)
        if re.search(
            rf"(?:public|private|protected) function {re.escape(method_name)}\s*\(",
            line,
        )
    ]
    if len(start_matches) != 1:
        raise SystemExit(
            f"expected one method marker for {method_name}, found {start_matches}"
        )
    start = start_matches[0]
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


def _line_number(source: str, marker: str) -> int:
    matches = [
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one marker {marker!r}, found {matches}")
    return matches[0]


def _blame_line(
    repository: Path,
    revision: str,
    source_path: str,
    line: int,
    marker: str,
) -> dict[str, object]:
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


def _run(repository: Path, label: str, revision: str) -> dict[str, object]:
    source_blob = _git_blob(repository, revision, SOURCE_PATH)
    view_blob = _git_blob(repository, revision, VIEW_PATH)
    return {
        "label": label,
        "revision": revision,
        "blob_sha256": {
            SOURCE_PATH: hashlib.sha256(source_blob).hexdigest(),
            VIEW_PATH: hashlib.sha256(view_blob).hexdigest(),
        },
        "evaluation": _evaluate(
            source_blob.decode("utf-8"), view_blob.decode("utf-8")
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    runs = [
        _run(repository, "baseline", BASELINE_SHA),
        _run(repository, "direct_ai_origin", AI_ORIGIN_SHA),
        _run(repository, "security_repair", SECURITY_REPAIR_SHA),
    ]
    evaluations = {str(run["label"]): run["evaluation"] for run in runs}
    candidate_source = _git_blob(repository, AI_ORIGIN_SHA, SOURCE_PATH).decode(
        "utf-8"
    )
    candidate_view = _git_blob(repository, AI_ORIGIN_SHA, VIEW_PATH).decode("utf-8")
    repair_source = _git_blob(repository, SECURITY_REPAIR_SHA, SOURCE_PATH).decode(
        "utf-8"
    )
    repair_policy = _git_blob(repository, SECURITY_REPAIR_SHA, POLICY_PATH).decode(
        "utf-8"
    )
    policy = _evaluate_policy(repair_policy)
    line_origins = {
        "candidate_action": _blame_line(
            repository,
            AI_ORIGIN_SHA,
            SOURCE_PATH,
            _line_in_method(
                candidate_source,
                "buildHelperImage",
                "public function buildHelperImage()",
            ),
            "public function buildHelperImage()",
        ),
        "candidate_remote_process": _blame_line(
            repository,
            AI_ORIGIN_SHA,
            SOURCE_PATH,
            _line_in_method(candidate_source, "buildHelperImage", "remote_process("),
            "remote_process(",
        ),
        "candidate_view_trigger": _blame_line(
            repository,
            AI_ORIGIN_SHA,
            VIEW_PATH,
            _line_number(candidate_view, 'wire:click="buildHelperImage"'),
            'wire:click="buildHelperImage"',
        ),
        "repair_action_authorization": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            SOURCE_PATH,
            _line_in_method(
                repair_source,
                "buildHelperImage",
                "$this->authorize('update', $this->settings)",
            ),
            "$this->authorize('update', $this->settings)",
        ),
    }
    metadata = _commit_metadata(repository, AI_ORIGIN_SHA)
    baseline = evaluations["baseline"]
    candidate = evaluations["direct_ai_origin"]
    repair = evaluations["security_repair"]
    witness_passed = bool(
        metadata["explicit_claude_signal"] is True
        and metadata["parents"] == [BASELINE_SHA]
        and _is_ancestor(repository, AI_ORIGIN_SHA, SECURITY_REPAIR_SHA)
        and baseline["public_build_helper_action"] is False
        and baseline["view_invokes_action"] is False
        and candidate["mount_has_instance_admin_redirect"] is True
        and candidate["public_build_helper_action"] is True
        and candidate["action_is_dev_limited"] is True
        and candidate["action_invokes_remote_process"] is True
        and candidate["action_builds_host_helper_image"] is True
        and candidate["action_has_update_authorization"] is False
        and candidate["view_invokes_action"] is True
        and candidate["view_action_is_dev_limited"] is True
        and repair["action_has_update_authorization"] is True
        and policy["update_requires_instance_admin"] is True
        and all(
            value["origin_sha"] == AI_ORIGIN_SHA
            for key, value in line_origins.items()
            if key.startswith("candidate_")
        )
        and line_origins["repair_action_authorization"]["origin_sha"]
        == SECURITY_REPAIR_SHA
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_dev_helper_action_authorization_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_ORIGIN_SHA,
        "fix_sha": SECURITY_REPAIR_SHA,
        "candidate_metadata": metadata,
        "line_origins": line_origins,
        "runs": runs,
        "repair_policy": policy,
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_SENSITIVE_ACTION_ORIGIN",
        "causal_role": "dev_helper_host_build_action_missing_method_authorization",
        "counting": {
            "candidate_level_true_positive": True,
            "mechanism_level_true_positive": False,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude-authored bundled delta introduces a public Livewire action "
            "and UI trigger that execute a helper-image Docker build through the "
            "local server. The candidate method has a development-mode gate and the "
            "component mount redirects non-instance-admin users, but the action has "
            "no method-level policy authorization. The later security repair adds "
            "an update authorization inside this exact method, backed by an "
            "InstanceSettings policy requiring instance-admin status. This proves a "
            "source-level causal authorization-path origin; it does not assert a "
            "locally executed Livewire exploit, production reachability, or a new "
            "advisory/mechanism beyond the existing authorization repair family."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify dev-helper action authorization witness frozen")
    print(f"  baseline action : {baseline['public_build_helper_action']}")
    print(f"  candidate action: {candidate['public_build_helper_action']}")
    print(f"  repair auth     : {repair['action_has_update_authorization']}")
    print(f"  witness         : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output          : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
