#!/usr/bin/env python3
"""Freeze the Coolify AI OAuth bulk-mutation preservation witness."""

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


AI_MUTATION_SHA = "b1a68df65caef6df06c9495a817ff4c340a44d39"
AUTHORIZATION_REPAIR_SHA = "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e"
SOURCE_PATH = "app/Livewire/SettingsOauth.php"
VIEW_PATH = "resources/views/livewire/settings-oauth.blade.php"


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


def _bulk_branch(method: str) -> str:
    branches = method.split("} else {", maxsplit=1)
    if len(branches) != 2:
        raise ValueError("OAuth update helper does not have one provider/bulk split")
    return branches[1]


def _method_marker_lines(source: str, method_name: str, marker: str) -> list[int]:
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
    return [
        index + 1
        for index, line in enumerate(lines[start:end], start=start)
        if marker in line
    ]


def _unique_method_marker_line(source: str, method_name: str, marker: str) -> int:
    matches = _method_marker_lines(source, method_name, marker)
    if len(matches) != 1:
        raise SystemExit(
            f"expected one {marker!r} in {method_name}, found {matches}"
        )
    return matches[0]


def _last_method_marker_line(source: str, method_name: str, marker: str) -> int:
    matches = _method_marker_lines(source, method_name, marker)
    if len(matches) < 2:
        raise SystemExit(
            f"expected repeated {marker!r} in {method_name}, found {matches}"
        )
    return matches[-1]


def _evaluate_versions(
    baseline_source: str,
    candidate_source: str,
    candidate_view: str,
    repair_source: str,
) -> dict[str, bool]:
    baseline_helper = _php_method_region(baseline_source, "updateOauthSettings")
    candidate_helper = _php_method_region(candidate_source, "updateOauthSettings")
    repair_helper = _php_method_region(repair_source, "updateOauthSettings")
    baseline_bulk = _bulk_branch(baseline_helper)
    candidate_bulk = _bulk_branch(candidate_helper)
    repair_bulk = _bulk_branch(repair_helper)
    candidate_instant = _php_method_region(candidate_source, "instantSave")
    candidate_submit = _php_method_region(candidate_source, "submit")
    repair_instant = _php_method_region(repair_source, "instantSave")
    repair_submit = _php_method_region(repair_source, "submit")
    authorization = "$this->authorize('update', instanceSettings())"
    return {
        "baseline_bulk_uses_direct_update_sink": (
            "$oauth->update([" in baseline_bulk
            and "'enabled' => $settingData['enabled']" in baseline_bulk
            and "$errors = [];" not in baseline_bulk
        ),
        "candidate_reauthors_bulk_mutation_sink": all(
            marker in candidate_bulk
            for marker in (
                "$errors = [];",
                "$oauth->fill([",
                "$oauth->couldBeEnabled()",
                "$oauth->save();",
                "$this->oauth_settings_map[$oauth->provider] = [",
            )
        ),
        "candidate_removes_old_bulk_update_sink": (
            "$oauth->update([" not in candidate_bulk
        ),
        "candidate_public_entries_reach_mutation_helper": (
            "$this->updateOauthSettings($provider)" in candidate_instant
            and "$this->updateOauthSettings()" in candidate_submit
        ),
        "candidate_public_entries_have_no_authorization": (
            authorization not in candidate_instant
            and authorization not in candidate_submit
        ),
        "candidate_view_exposes_both_livewire_entries": (
            "wire:submit='submit'" in candidate_view
            and "instantSave=\"instantSave('{{ $oauth_setting['provider'] }}')\""
            in candidate_view
        ),
        "repair_preserves_candidate_bulk_mutation": all(
            marker in repair_bulk
            for marker in (
                "$errors = [];",
                "$oauth->fill([",
                "$oauth->couldBeEnabled()",
                "$oauth->save();",
                "$this->oauth_settings_map[$oauth->provider] = [",
            )
        ),
        "repair_authorizes_both_public_entries": (
            authorization in repair_instant and authorization in repair_submit
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_revision = f"{AI_MUTATION_SHA}^"
    baseline_source = _text_blob(repository, baseline_revision, SOURCE_PATH)
    candidate_source = _text_blob(repository, AI_MUTATION_SHA, SOURCE_PATH)
    candidate_view = _text_blob(repository, AI_MUTATION_SHA, VIEW_PATH)
    repair_source = _text_blob(repository, AUTHORIZATION_REPAIR_SHA, SOURCE_PATH)
    evaluation = _evaluate_versions(
        baseline_source, candidate_source, candidate_view, repair_source
    )
    candidate_metadata = _commit_metadata(repository, AI_MUTATION_SHA)
    repair_metadata = _commit_metadata(repository, AUTHORIZATION_REPAIR_SHA)

    candidate_bulk_save_line = _last_method_marker_line(
        candidate_source, "updateOauthSettings", "$oauth->save();"
    )
    repair_bulk_save_line = _last_method_marker_line(
        repair_source, "updateOauthSettings", "$oauth->save();"
    )
    line_origins = {
        "candidate_bulk_mutation_sink": _blame_line(
            repository,
            AI_MUTATION_SHA,
            SOURCE_PATH,
            candidate_bulk_save_line,
            "AI-authored OAuth bulk mutation sink",
        ),
        "repair_preserved_candidate_sink": _blame_line(
            repository,
            AUTHORIZATION_REPAIR_SHA,
            SOURCE_PATH,
            repair_bulk_save_line,
            "preserved AI-authored OAuth bulk mutation sink",
        ),
        "repair_instant_save_authorization": _blame_line(
            repository,
            AUTHORIZATION_REPAIR_SHA,
            SOURCE_PATH,
            _unique_method_marker_line(
                repair_source,
                "instantSave",
                "$this->authorize('update', instanceSettings())",
            ),
            "follow-up instant-save authorization",
        ),
        "repair_submit_authorization": _blame_line(
            repository,
            AUTHORIZATION_REPAIR_SHA,
            SOURCE_PATH,
            _unique_method_marker_line(
                repair_source,
                "submit",
                "$this->authorize('update', instanceSettings())",
            ),
            "follow-up bulk-submit authorization",
        ),
    }
    ancestry = {
        "candidate_parent_to_candidate": _is_ancestor(
            repository, baseline_revision, AI_MUTATION_SHA
        ),
        "candidate_to_repair": _is_ancestor(
            repository, AI_MUTATION_SHA, AUTHORIZATION_REPAIR_SHA
        ),
    }
    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and "oauth bulk update" in str(candidate_metadata["message"]).casefold()
        and "authorization gaps" in str(repair_metadata["message"])
        and all(ancestry.values())
        and all(evaluation.values())
        and line_origins["candidate_bulk_mutation_sink"]["origin_sha"]
        == AI_MUTATION_SHA
        and line_origins["repair_preserved_candidate_sink"]["origin_sha"]
        == AI_MUTATION_SHA
        and line_origins["repair_instant_save_authorization"]["origin_sha"]
        == AUTHORIZATION_REPAIR_SHA
        and line_origins["repair_submit_authorization"]["origin_sha"]
        == AUTHORIZATION_REPAIR_SHA
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_oauth_bulk_mutation_preservation_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_MUTATION_SHA,
        "fix_sha": AUTHORIZATION_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, baseline_revision, SOURCE_PATH),
            _blob_record(repository, AI_MUTATION_SHA, SOURCE_PATH),
            _blob_record(repository, AI_MUTATION_SHA, VIEW_PATH),
            _blob_record(repository, AUTHORIZATION_REPAIR_SHA, SOURCE_PATH),
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_AI_OAUTH_BULK_MUTATION_PRESERVATION_CONTRIBUTOR"
        ),
        "mechanism_group": "oauth_bulk_settings_mutation_authorization",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude commit does not originate the older public Livewire entries "
            "or their missing authorization. It materially reauthors the exact bulk "
            "OAuth write path from a direct update into fill, validation, save, and "
            "state refresh; the AI-authored save sink remains in the repair revision. "
            "Both public entries remain UI-reachable and unguarded after the candidate, "
            "and the later repair adds exact update authorization to both callers. This "
            "counts a sensitive-mutation preservation contributor, not a root origin, "
            "security regression, exploit reproduction, or new advisory."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify OAuth bulk-mutation preservation witness failed")
    print("Coolify OAuth bulk-mutation preservation witness frozen")
    print(f"  candidate: {AI_MUTATION_SHA}")
    print(f"  repair   : {AUTHORIZATION_REPAIR_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
