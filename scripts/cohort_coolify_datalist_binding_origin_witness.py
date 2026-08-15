#!/usr/bin/env python3
"""Freeze the Coolify AI single-select datalist binding-origin witness."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


AI_ORIGIN_SHA = "6297ac6c88a712b8e867d6442ea81aa7abc8cb73"
FOLLOWUP_REPAIR_SHA = "188c86ca45801c7ea2c4a8022b9ed90d73c1068e"
DATALIST_PATH = "resources/views/components/forms/datalist.blade.php"
TERMINAL_PATH = "resources/views/livewire/terminal/index.blade.php"

CANDIDATE_BINDING = (
    "selected: @entangle(($attributes->whereStartsWith('wire:model')->first() ? "
    "$attributes->wire('model')->value() : $id)).live"
)
REPAIR_BINDING = (
    "selected: @entangle(($attributes->whereStartsWith('wire:model')->first() ? "
    "$attributes->wire('model')->value() : $modelBinding)).live"
)


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


def _line_number(source: str, marker: str) -> int:
    matches = [
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one marker {marker!r}, found {matches}")
    return matches[0]


def _evaluate_versions(
    baseline_datalist: str,
    baseline_terminal: str,
    candidate_datalist: str,
    candidate_terminal: str,
    repair_datalist: str,
) -> dict[str, bool]:
    return {
        "baseline_single_select_uses_standard_html_datalist": (
            "Single Selection Mode (Standard HTML5 Datalist)"
            in baseline_datalist
            and "Single Selection Mode with Alpine.js" not in baseline_datalist
        ),
        "baseline_terminal_uses_select_not_datalist": (
            "<x-forms.select" in baseline_terminal
            and "<x-forms.datalist" not in baseline_terminal
        ),
        "candidate_introduces_alpine_single_select": all(
            marker in candidate_datalist
            for marker in (
                "Single Selection Mode with Alpine.js",
                "selectOption(value)",
                "this.selected = value;",
            )
        ),
        "candidate_single_select_fallback_binds_component_id": (
            CANDIDATE_BINDING in candidate_datalist
            and REPAIR_BINDING not in candidate_datalist
        ),
        "candidate_activates_component_in_terminal": (
            "<x-forms.datalist" in candidate_terminal
            and "<x-forms.select" not in candidate_terminal
        ),
        "repair_rebinds_single_select_to_model_binding": (
            REPAIR_BINDING in repair_datalist
            and CANDIDATE_BINDING not in repair_datalist
        ),
        "repair_preserves_alpine_single_select_behavior": all(
            marker in repair_datalist
            for marker in (
                "Single Selection Mode with Alpine.js",
                "selectOption(value)",
                "this.selected = value;",
            )
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline_revision = f"{AI_ORIGIN_SHA}^"
    baseline_datalist = _text_blob(repository, baseline_revision, DATALIST_PATH)
    baseline_terminal = _text_blob(repository, baseline_revision, TERMINAL_PATH)
    candidate_datalist = _text_blob(repository, AI_ORIGIN_SHA, DATALIST_PATH)
    candidate_terminal = _text_blob(repository, AI_ORIGIN_SHA, TERMINAL_PATH)
    repair_datalist = _text_blob(repository, FOLLOWUP_REPAIR_SHA, DATALIST_PATH)
    evaluation = _evaluate_versions(
        baseline_datalist,
        baseline_terminal,
        candidate_datalist,
        candidate_terminal,
        repair_datalist,
    )
    candidate_metadata = _commit_metadata(repository, AI_ORIGIN_SHA)
    repair_metadata = _commit_metadata(repository, FOLLOWUP_REPAIR_SHA)
    line_origins = {
        "candidate_wrong_single_select_binding": _blame_line(
            repository,
            AI_ORIGIN_SHA,
            DATALIST_PATH,
            _line_number(candidate_datalist, CANDIDATE_BINDING),
            "AI single-select fallback binding to component id",
        ),
        "repair_single_select_model_binding": _blame_line(
            repository,
            FOLLOWUP_REPAIR_SHA,
            DATALIST_PATH,
            _line_number(repair_datalist, REPAIR_BINDING),
            "follow-up single-select model binding repair",
        ),
    }
    ancestry = {
        "candidate_parent_to_candidate": _is_ancestor(
            repository, baseline_revision, AI_ORIGIN_SHA
        ),
        "candidate_to_repair": _is_ancestor(
            repository, AI_ORIGIN_SHA, FOLLOWUP_REPAIR_SHA
        ),
    }
    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["parents"]
        == [_commit_metadata(repository, baseline_revision)["sha"]]
        and "Alpine.js-powered dropdown" in str(candidate_metadata["message"])
        and "Fix Alpine.js reactivity" in str(repair_metadata["message"])
        and all(ancestry.values())
        and all(evaluation.values())
        and line_origins["candidate_wrong_single_select_binding"]["origin_sha"]
        == AI_ORIGIN_SHA
        and line_origins["repair_single_select_model_binding"]["origin_sha"]
        == FOLLOWUP_REPAIR_SHA
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_single_select_datalist_binding_origin_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_ORIGIN_SHA,
        "fix_sha": FOLLOWUP_REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "repair_metadata": repair_metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, baseline_revision, DATALIST_PATH),
            _blob_record(repository, baseline_revision, TERMINAL_PATH),
            _blob_record(repository, AI_ORIGIN_SHA, DATALIST_PATH),
            _blob_record(repository, AI_ORIGIN_SHA, TERMINAL_PATH),
            _blob_record(repository, FOLLOWUP_REPAIR_SHA, DATALIST_PATH),
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_AI_SINGLE_SELECT_DATALIST_BINDING_ORIGIN",
        "mechanism_group": "form_datalist_single_select_reactivity",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude commit replaces the pre-existing standard HTML single-select "
            "datalist with an Alpine component, activates it in the terminal, and "
            "authors the fallback entangle expression against the component id. The "
            "later Claude repair changes that exact new fallback to the resolved "
            "Livewire model binding while retaining the new Alpine selection flow. "
            "This proves direct origin of the single-select binding/reactivity defect. "
            "It does not attribute the repair's separate SSH-key filtering change or "
            "the older multi-select branch to this candidate, and it does not claim a "
            "security advisory."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify datalist binding-origin witness failed")
    print("Coolify datalist binding-origin witness frozen")
    print(f"  candidate: {AI_ORIGIN_SHA}")
    print(f"  repair   : {FOLLOWUP_REPAIR_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
