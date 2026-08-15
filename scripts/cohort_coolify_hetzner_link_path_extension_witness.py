#!/usr/bin/env python3
"""Freeze the Coolify manual-server Hetzner link authorization path witness."""

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


BASELINE_SHA = "eef0cc94cccaf1adea0e344d4f769760055ca4eb"
AI_PATH_EXTENSION_SHA = "67b1db925460d21351babd9896b12de2b837879b"
SECURITY_REPAIR_SHA = "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e"
SOURCE_PATH = "app/Livewire/Server/Show.php"


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


def _evaluate_source(source: str) -> dict[str, object]:
    link = _optional_method(source, "linkToHetzner")
    search = _optional_method(source, "searchHetznerServer")
    start = _php_method_region(source, "startHetznerServer")
    status = _php_method_region(source, "checkHetznerServerStatus")
    link_contract = {
        "manual_link_method_present": link is not None,
        "link_requires_server_update_permission": bool(
            link is not None
            and "$this->authorize('update', $this->server)" in link
        ),
        "search_requires_server_update_permission": bool(
            search is not None
            and "$this->authorize('update', $this->server)" in search
        ),
        "link_persists_cloud_provider_token": bool(
            link is not None and "'cloud_provider_token_id'" in link
        ),
        "link_persists_hetzner_server_id": bool(
            link is not None and "'hetzner_server_id'" in link
        ),
    }
    control_contract = {
        "start_requires_linked_token_and_server_id": (
            "hetzner_server_id" in start and "cloudProviderToken" in start
        ),
        "start_calls_hetzner_power_on": "powerOnServer" in start,
        "start_has_update_authorization": (
            "$this->authorize('update', $this->server)" in start
        ),
        "status_calls_hetzner_api": "getServer" in status,
        "status_has_view_authorization": (
            "$this->authorize('view', $this->server)" in status
        ),
    }
    return {
        "link_contract": link_contract,
        "control_contract": control_contract,
        "manual_link_to_unguarded_power_control_path_active": bool(
            all(link_contract.values())
            and control_contract["start_requires_linked_token_and_server_id"]
            and control_contract["start_calls_hetzner_power_on"]
            and not control_contract["start_has_update_authorization"]
        ),
        "manual_link_power_control_path_authorized": bool(
            all(link_contract.values())
            and control_contract["start_has_update_authorization"]
            and control_contract["status_has_view_authorization"]
        ),
    }


def _line_in_method(source: str, method_name: str, marker: str) -> int:
    lines = source.splitlines()
    method_starts = [
        index
        for index, line in enumerate(lines)
        if re.search(
            rf"(?:public|private|protected) function {re.escape(method_name)}\s*\(",
            line,
        )
    ]
    if len(method_starts) != 1:
        raise SystemExit(
            f"expected one method marker for {method_name}, found {method_starts}"
        )
    start = method_starts[0]
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


def _blame_line(
    repository: Path, revision: str, line: int, marker: str
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
            SOURCE_PATH,
        ],
        text=True,
    )
    assert isinstance(value, str)
    return {
        "path": SOURCE_PATH,
        "line": line,
        "marker": marker,
        "origin_sha": value.split(None, 1)[0].lstrip("^"),
    }


def _run(repository: Path, label: str, revision: str) -> dict[str, object]:
    blob = _git_blob(repository, revision, SOURCE_PATH)
    return {
        "label": label,
        "revision": revision,
        "blob_sha256": hashlib.sha256(blob).hexdigest(),
        "evaluation": _evaluate_source(blob.decode("utf-8")),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    runs = [
        _run(repository, "baseline", BASELINE_SHA),
        _run(repository, "direct_ai_path_extension", AI_PATH_EXTENSION_SHA),
        _run(repository, "security_repair", SECURITY_REPAIR_SHA),
    ]
    evaluations = {str(run["label"]): run["evaluation"] for run in runs}
    candidate_source = _git_blob(
        repository, AI_PATH_EXTENSION_SHA, SOURCE_PATH
    ).decode("utf-8")
    repair_source = _git_blob(repository, SECURITY_REPAIR_SHA, SOURCE_PATH).decode(
        "utf-8"
    )
    line_origins = {
        "candidate_link_method": _blame_line(
            repository,
            AI_PATH_EXTENSION_SHA,
            _line_in_method(
                candidate_source,
                "linkToHetzner",
                "public function linkToHetzner()",
            ),
            "public function linkToHetzner()",
        ),
        "candidate_token_link": _blame_line(
            repository,
            AI_PATH_EXTENSION_SHA,
            _line_in_method(
                candidate_source,
                "linkToHetzner",
                "'cloud_provider_token_id' => $this->selectedHetznerTokenId",
            ),
            "'cloud_provider_token_id' => $this->selectedHetznerTokenId",
        ),
        "candidate_server_link": _blame_line(
            repository,
            AI_PATH_EXTENSION_SHA,
            _line_in_method(
                candidate_source,
                "linkToHetzner",
                "'hetzner_server_id' => $this->matchedHetznerServer['id']",
            ),
            "'hetzner_server_id' => $this->matchedHetznerServer['id']",
        ),
        "repair_start_authorization": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            _line_in_method(
                repair_source,
                "startHetznerServer",
                "$this->authorize('update', $this->server)",
            ),
            "$this->authorize('update', $this->server)",
        ),
        "repair_status_authorization": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            _line_in_method(
                repair_source,
                "checkHetznerServerStatus",
                "$this->authorize('view', $this->server)",
            ),
            "$this->authorize('view', $this->server)",
        ),
    }
    metadata = _commit_metadata(repository, AI_PATH_EXTENSION_SHA)
    baseline = evaluations["baseline"]
    candidate = evaluations["direct_ai_path_extension"]
    repair = evaluations["security_repair"]
    witness_passed = bool(
        metadata["explicit_claude_signal"] is True
        and metadata["parents"] == [BASELINE_SHA]
        and _is_ancestor(repository, AI_PATH_EXTENSION_SHA, SECURITY_REPAIR_SHA)
        and baseline["link_contract"]["manual_link_method_present"] is False
        and baseline["control_contract"]["start_calls_hetzner_power_on"] is True
        and baseline["control_contract"]["start_has_update_authorization"] is False
        and candidate["manual_link_to_unguarded_power_control_path_active"] is True
        and repair["manual_link_to_unguarded_power_control_path_active"] is False
        and repair["manual_link_power_control_path_authorized"] is True
        and all(
            value["origin_sha"] == AI_PATH_EXTENSION_SHA
            for key, value in line_origins.items()
            if key.startswith("candidate_")
        )
        and all(
            value["origin_sha"] == SECURITY_REPAIR_SHA
            for key, value in line_origins.items()
            if key.startswith("repair_")
        )
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_hetzner_link_path_extension_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_PATH_EXTENSION_SHA,
        "fix_sha": SECURITY_REPAIR_SHA,
        "candidate_metadata": metadata,
        "line_origins": line_origins,
        "runs": runs,
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_EXTENSION",
        "causal_role": "manual_server_link_activates_unguarded_hetzner_power_control",
        "counting": {
            "candidate_level_true_positive": True,
            "mechanism_level_true_positive": False,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude delta adds an update-authorized workflow that persists a "
            "Hetzner token and server ID onto manually added servers. That state "
            "satisfies the prerequisites of a pre-existing public power-on action "
            "that lacks its own update authorization. The later repair adds update "
            "authorization to power-on and view authorization to status refresh. "
            "Hetzner-provisioned servers could already reach the underlying control "
            "methods, so this is a vulnerable affected-surface extension rather than "
            "the earliest mechanism root. This is a compositional source witness, "
            "not a locally executed Laravel/Hetzner exploit."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify Hetzner manual-link path-extension witness frozen")
    print(
        "  baseline manual-link path : "
        f"{baseline['manual_link_to_unguarded_power_control_path_active']}"
    )
    print(
        "  candidate manual-link path: "
        f"{candidate['manual_link_to_unguarded_power_control_path_active']}"
    )
    print(
        "  repair authorized path    : "
        f"{repair['manual_link_power_control_path_authorized']}"
    )
    print(f"  witness                   : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output                    : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
