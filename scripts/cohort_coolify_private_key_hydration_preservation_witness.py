#!/usr/bin/env python3
"""Freeze the Coolify AI private-key hydration preservation witness."""

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
from cohort_coolify_security_frontier_preservation_witness import _blame_line


AI_HYDRATION_SHA = "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd"
AUTHORIZATION_REPAIR_SHA = "f7427fdea03ccd0da20ddce590c6eb6fd2119fd9"
SOURCE_PATH = "app/Livewire/Security/PrivateKey/Show.php"
VIEW_PATH = "resources/views/livewire/security/private-key/show.blade.php"


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


def _unique_marker_line(source: str, marker: str) -> int:
    matches = [
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one {marker!r}, found {matches}")
    return matches[0]


def _first_marker_line(source: str, marker: str) -> int:
    matches = [
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if marker in line
    ]
    if not matches:
        raise SystemExit(f"expected at least one {marker!r}")
    return matches[0]


def _evaluate_versions(
    baseline_source: str,
    baseline_view: str,
    candidate_source: str,
    candidate_view: str,
    repair_source: str,
    repair_view: str,
) -> dict[str, bool]:
    candidate_sync = _php_method_region(candidate_source, "syncData")
    candidate_mount = _php_method_region(candidate_source, "mount")
    repair_sync = _php_method_region(repair_source, "syncData")
    repair_mount = _php_method_region(repair_source, "mount")
    authorization = "$this->authorize('view', $this->private_key);"
    hydration = "$this->privateKeyValue = $this->private_key->private_key;"
    return {
        "baseline_already_exposes_nested_model_binding": (
            "public PrivateKey $private_key;" in baseline_source
            and 'id="private_key.private_key"' in baseline_view
        ),
        "baseline_has_no_explicit_scalar_hydration": (
            "public string $privateKeyValue;" not in baseline_source
            and hydration not in baseline_source
            and 'id="privateKeyValue"' not in baseline_view
        ),
        "candidate_reauthors_secret_into_public_scalar": (
            "public string $privateKeyValue;" in candidate_source
            and hydration in candidate_sync
        ),
        "candidate_mount_reaches_hydration_without_view_authorization": (
            "$this->syncData(false);" in candidate_mount
            and authorization not in candidate_mount
        ),
        "candidate_view_binds_reauthored_secret_scalar": (
            candidate_view.count('id="privateKeyValue"') == 2
            and 'id="private_key.private_key"' not in candidate_view
        ),
        "repair_preserves_candidate_hydration_and_binding": (
            "public string $privateKeyValue;" in repair_source
            and hydration in repair_sync
            and "$this->syncData(false);" in repair_mount
            and repair_view.count('id="privateKeyValue"') == 2
        ),
        "repair_adds_effective_view_authorization_before_hydration": (
            "'team_id'" in repair_mount
            and authorization in repair_mount
            and repair_mount.index(authorization)
            < repair_mount.index("$this->syncData(false);")
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_revision = f"{AI_HYDRATION_SHA}^"
    baseline_source = _text_blob(repository, baseline_revision, SOURCE_PATH)
    baseline_view = _text_blob(repository, baseline_revision, VIEW_PATH)
    candidate_source = _text_blob(repository, AI_HYDRATION_SHA, SOURCE_PATH)
    candidate_view = _text_blob(repository, AI_HYDRATION_SHA, VIEW_PATH)
    repair_source = _text_blob(repository, AUTHORIZATION_REPAIR_SHA, SOURCE_PATH)
    repair_view = _text_blob(repository, AUTHORIZATION_REPAIR_SHA, VIEW_PATH)
    evaluation = _evaluate_versions(
        baseline_source,
        baseline_view,
        candidate_source,
        candidate_view,
        repair_source,
        repair_view,
    )
    candidate_metadata = _commit_metadata(repository, AI_HYDRATION_SHA)
    repair_metadata = _commit_metadata(repository, AUTHORIZATION_REPAIR_SHA)
    hydration_marker = "$this->privateKeyValue = $this->private_key->private_key;"
    binding_marker = 'allowToPeak="false" type="password" rows="10" id="privateKeyValue"'
    authorization_marker = "$this->authorize('view', $this->private_key);"
    line_origins = {
        "candidate_secret_hydration": _blame_line(
            repository,
            AI_HYDRATION_SHA,
            SOURCE_PATH,
            _unique_marker_line(candidate_source, hydration_marker),
            "AI-authored private-key secret hydration",
        ),
        "candidate_public_scalar_binding": _blame_line(
            repository,
            AI_HYDRATION_SHA,
            VIEW_PATH,
            _first_marker_line(candidate_view, binding_marker),
            "AI-authored public private-key scalar binding",
        ),
        "repair_preserved_secret_hydration": _blame_line(
            repository,
            AUTHORIZATION_REPAIR_SHA,
            SOURCE_PATH,
            _unique_marker_line(repair_source, hydration_marker),
            "repair-preserved AI private-key hydration",
        ),
        "repair_preserved_scalar_binding": _blame_line(
            repository,
            AUTHORIZATION_REPAIR_SHA,
            VIEW_PATH,
            _first_marker_line(repair_view, binding_marker),
            "repair-preserved AI private-key binding",
        ),
        "repair_view_authorization": _blame_line(
            repository,
            AUTHORIZATION_REPAIR_SHA,
            SOURCE_PATH,
            _unique_marker_line(repair_source, authorization_marker),
            "follow-up private-key view authorization",
        ),
    }
    ancestry = {
        "candidate_parent_to_candidate": _is_ancestor(
            repository, baseline_revision, AI_HYDRATION_SHA
        ),
        "candidate_to_repair": _is_ancestor(
            repository, AI_HYDRATION_SHA, AUTHORIZATION_REPAIR_SHA
        ),
    }
    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and "legacy model binding migration"
        in str(candidate_metadata["message"]).casefold()
        and all(ancestry.values())
        and all(evaluation.values())
        and line_origins["candidate_secret_hydration"]["origin_sha"]
        == AI_HYDRATION_SHA
        and line_origins["candidate_public_scalar_binding"]["origin_sha"]
        == AI_HYDRATION_SHA
        and line_origins["repair_preserved_secret_hydration"]["origin_sha"]
        == AI_HYDRATION_SHA
        and line_origins["repair_preserved_scalar_binding"]["origin_sha"]
        == AI_HYDRATION_SHA
        and line_origins["repair_view_authorization"]["origin_sha"]
        == AUTHORIZATION_REPAIR_SHA
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_private_key_hydration_preservation_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_HYDRATION_SHA,
        "fix_sha": AUTHORIZATION_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, baseline_revision, SOURCE_PATH),
            _blob_record(repository, baseline_revision, VIEW_PATH),
            _blob_record(repository, AI_HYDRATION_SHA, SOURCE_PATH),
            _blob_record(repository, AI_HYDRATION_SHA, VIEW_PATH),
            _blob_record(repository, AUTHORIZATION_REPAIR_SHA, SOURCE_PATH),
            _blob_record(repository, AUTHORIZATION_REPAIR_SHA, VIEW_PATH),
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_AI_PRIVATE_KEY_HYDRATION_PRESERVATION_CONTRIBUTOR"
        ),
        "mechanism_group": "private_key_secret_view_authorization",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude commit does not originate the older missing view "
            "authorization or the pre-existing nested private-key model binding. "
            "It materially reauthors that sensitive path into an explicit public "
            "Livewire scalar, copies the stored private key into it during mount, "
            "and binds the scalar in the view. Those AI-authored hydration and view "
            "lines survive unchanged when the later repair selects team_id and adds "
            "exact view authorization before hydration. This counts a sensitive-data "
            "path preservation contributor, not a root origin, new security "
            "regression, exploit reproduction, or new advisory."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify private-key hydration preservation witness failed")
    print("Coolify private-key hydration preservation witness frozen")
    print(f"  candidate: {AI_HYDRATION_SHA}")
    print(f"  repair   : {AUTHORIZATION_REPAIR_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
