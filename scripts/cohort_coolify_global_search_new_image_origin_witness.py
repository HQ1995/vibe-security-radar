#!/usr/bin/env python3
"""Freeze attribution for Coolify's broken ``new image`` quick action.

The exact-delta recall edge points from an unrelated loading-input change to
the later repair.  This witness proves the command-resolution regression from
frozen source semantics, reattributes it to the earlier frontend migration,
and does not use commit prose or model output as causal evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)


PROPOSED_PARENT_SHA = "64c4ce210e095ac50aadd3806f7b22d85a1854e2"
PROPOSED_CANDIDATE_SHA = "2ce3052378f1dd451b6e79a9179c0a9eebb1549d"
FIX_PARENT_SHA = "6d3c996ef374a8827eaf0e14318570344522420c"
FIX_SHA = "66cff9d9b84def9cf3a600ef637a51a8c35d9a2a"

DIRECT_ORIGIN_PARENT_SHA = "afd10048bda450b6bb6bd56a18fea84c6f25fcf9"
DIRECT_ORIGIN_SHA = "2e6e07bcc310f84838103e14710e27a21e626a51"
SERVER_CONTRACT_ORIGIN_SHA = "adf5bbd91a3100abd120327dd65d2064d2177310"

VIEW_PATH = "resources/views/livewire/global-search.blade.php"
COMPONENT_PATH = "app/Livewire/GlobalSearch.php"
FIX_TEST_PATH = "tests/Unit/GlobalSearchNewImageQuickActionTest.php"

WIRE_MODEL_INPUT = 'wire:model.live.debounce.200ms="searchQuery"'
ALPINE_MODEL_INPUT = 'x-model="searchQuery"'
MATCHER_START = "            const exactMatchCommands = ["
MATCHER_END = "        // Create named handlers"
LEGACY_MATCHER_MARKER = "return itemSearchText === trimmed || itemType === trimmed ||"
FIXED_MATCHER_MARKER = (
    "item.quickcommand && item.quickcommand.toLowerCase().includes(trimmed)"
)
NEW_IMAGE_COMMAND_LINE = (
    "'new dockerfile', 'new docker compose', 'new compose', "
    "'new docker image', 'new image',"
)
DOCKER_IMAGE_ITEM = {
    "name": "Docker Image",
    "type": "docker-image",
    "quickcommand": "(type: new image)",
}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--delta-bridge-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} is not an object")
            rows.append(value)
    return rows


def _source(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _diff(repository: Path, old: str, new: str, *paths: str) -> str:
    value = _git(repository, ["diff", old, new, "--", *paths], text=True)
    assert isinstance(value, str)
    return value


def _changed_paths(repository: Path, old: str, new: str) -> tuple[str, ...]:
    value = _git(repository, ["diff", "--name-only", old, new], text=True)
    assert isinstance(value, str)
    return tuple(line for line in value.splitlines() if line)


def _added_lines(diff: str) -> tuple[str, ...]:
    return tuple(
        line[1:]
        for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )


def _region(source: str, start: str, end: str) -> str:
    start_positions = [
        index for index in range(len(source)) if source.startswith(start, index)
    ]
    if len(start_positions) != 1:
        raise ValueError(f"start marker resolved to {len(start_positions)} positions")
    end_index = source.find(end, start_positions[0])
    if end_index < 0:
        raise ValueError("end marker not found after start marker")
    return source[start_positions[0] : end_index]


def _bridge_edge(
    rows: list[dict[str, object]], candidate_sha: str, fix_sha: str
) -> dict[str, object]:
    matches = [
        row
        for row in rows
        if row.get("candidate_sha") == candidate_sha and row.get("fix_sha") == fix_sha
    ]
    if len(matches) != 1:
        raise ValueError(
            f"bridge edge {candidate_sha}:{fix_sha} resolved to {len(matches)} rows"
        )
    return matches[0]


def _legacy_client_match(command: str, item: Mapping[str, str]) -> bool:
    trimmed = command.strip().casefold()
    item_name = f"new {item['name']}".casefold()
    item_type = f"new {item['type']}".casefold()
    type_with_spaces = item["type"].replace("-", " ").casefold()
    return item_name == trimmed or item_type == trimmed or type_with_spaces in trimmed


def _fixed_client_match(command: str, item: Mapping[str, str]) -> bool:
    trimmed = command.strip().casefold()
    item_name = f"new {item['name']}".casefold()
    item_type = f"new {item['type']}".casefold()
    item_type_with_spaces = f"new {item['type'].replace('-', ' ')}".casefold()
    quickcommand = item.get("quickcommand", "").casefold()
    return (
        item_name == trimmed
        or item_type == trimmed
        or item_type_with_spaces == trimmed
        or trimmed in quickcommand
    )


def _blame_origin(
    repository: Path, revision: str, source_path: str, marker: str
) -> dict[str, object]:
    source = _source(repository, revision, source_path)
    matches = [
        index + 1 for index, line in enumerate(source.splitlines()) if marker in line
    ]
    if len(matches) != 1:
        raise ValueError(f"blame marker {marker!r} resolved to {matches}")
    value = _git(
        repository,
        [
            "blame",
            "--line-porcelain",
            "-L",
            f"{matches[0]},{matches[0]}",
            revision,
            "--",
            source_path,
        ],
        text=True,
    )
    assert isinstance(value, str)
    return {
        "revision": revision,
        "path": source_path,
        "line": matches[0],
        "marker": marker,
        "origin_sha": value.split(None, 1)[0].lstrip("^"),
    }


def build_witness(
    repository: Path,
    *,
    bridge_summary: Mapping[str, object],
    bridge_rows: list[dict[str, object]],
    observed_ai: set[str],
) -> dict[str, object]:
    if bridge_summary.get("all_source_owner_pairs_conserved") is not True:
        raise ValueError("delta bridge is not lossless")
    bridge_row = _bridge_edge(bridge_rows, PROPOSED_CANDIDATE_SHA, FIX_SHA)

    proposed_parent_view = _source(repository, PROPOSED_PARENT_SHA, VIEW_PATH)
    proposed_view = _source(repository, PROPOSED_CANDIDATE_SHA, VIEW_PATH)
    proposed_parent_component = _source(repository, PROPOSED_PARENT_SHA, COMPONENT_PATH)
    proposed_component = _source(repository, PROPOSED_CANDIDATE_SHA, COMPONENT_PATH)
    origin_parent_view = _source(repository, DIRECT_ORIGIN_PARENT_SHA, VIEW_PATH)
    origin_view = _source(repository, DIRECT_ORIGIN_SHA, VIEW_PATH)
    origin_parent_component = _source(
        repository, DIRECT_ORIGIN_PARENT_SHA, COMPONENT_PATH
    )
    origin_component = _source(repository, DIRECT_ORIGIN_SHA, COMPONENT_PATH)
    fix_parent_view = _source(repository, FIX_PARENT_SHA, VIEW_PATH)
    fixed_view = _source(repository, FIX_SHA, VIEW_PATH)
    fix_test = _source(repository, FIX_SHA, FIX_TEST_PATH)

    proposed_diff = _diff(
        repository, PROPOSED_PARENT_SHA, PROPOSED_CANDIDATE_SHA, VIEW_PATH
    )
    fix_diff = _diff(repository, FIX_PARENT_SHA, FIX_SHA, VIEW_PATH, COMPONENT_PATH)
    proposed_additions = _added_lines(proposed_diff)
    fix_additions = _added_lines(fix_diff)
    proposed_metadata = _commit_metadata(repository, PROPOSED_CANDIDATE_SHA)
    fix_metadata = _commit_metadata(repository, FIX_SHA)
    origin_metadata = _commit_metadata(repository, DIRECT_ORIGIN_SHA)

    matcher_origins = {
        "exact_command_list": _blame_origin(
            repository, FIX_PARENT_SHA, VIEW_PATH, NEW_IMAGE_COMMAND_LINE
        ),
        "client_name_matcher": _blame_origin(
            repository,
            FIX_PARENT_SHA,
            VIEW_PATH,
            "const itemSearchText = `new ${item.name}`.toLowerCase();",
        ),
        "docker_image_quickcommand_data": _blame_origin(
            repository,
            FIX_PARENT_SHA,
            COMPONENT_PATH,
            "'quickcommand' => '(type: new image)',",
        ),
    }
    backend_methods_unchanged = {
        method: _php_method_region(origin_parent_component, method)
        == _php_method_region(origin_component, method)
        for method in (
            "updatedSearchQuery",
            "detectSpecificResource",
            "navigateToResourceCreation",
            "completeResourceCreation",
        )
    }
    command_matrix = {
        command: {
            "pre_fix_client_match": _legacy_client_match(command, DOCKER_IMAGE_ITEM),
            "fixed_client_match": _fixed_client_match(command, DOCKER_IMAGE_ITEM),
        }
        for command in ("new image", "new docker image")
    }

    proposed_checks = {
        "recall_edge_retained": bridge_row.get("retained") is True,
        "exact_delta_tier_zero": int(bridge_row.get("delta_bridge_tier", -1)) == 0,
        "bidirectional_exact_reversal_class": bridge_row.get("delta_bridge_class")
        == "B0_BIDIRECTIONAL_EXACT_REVERSAL",
        "bridge_reports_seventy_two_meaningful_exact_lines": int(
            bridge_row.get("meaningful_exact_same_path_delta_count", -1)
        )
        == 72,
        "promoted_candidate_and_fix_are_observed_ai": {
            PROPOSED_CANDIDATE_SHA,
            FIX_SHA,
        }.issubset(observed_ai),
        "promoted_candidate_has_expected_parent": proposed_metadata.get("parents")
        == [PROPOSED_PARENT_SHA],
        "fix_has_expected_parent": fix_metadata.get("parents") == [FIX_PARENT_SHA],
        "promoted_candidate_strictly_precedes_fix": _is_ancestor(
            repository, PROPOSED_CANDIDATE_SHA, FIX_SHA
        ),
        "promoted_candidate_only_changes_global_search_view": _changed_paths(
            repository, PROPOSED_PARENT_SHA, PROPOSED_CANDIDATE_SHA
        )
        == (VIEW_PATH,),
        "client_command_matcher_is_byte_identical_across_promoted_candidate": (
            _region(proposed_parent_view, MATCHER_START, MATCHER_END)
            == _region(proposed_view, MATCHER_START, MATCHER_END)
        ),
        "backend_creation_contract_is_byte_identical_across_promoted_candidate": (
            proposed_parent_component == proposed_component
        ),
        "promoted_delta_adds_only_loading_guard_near_search_contract": (
            sum("if (this.isLoadingInitialData)" in line for line in proposed_additions)
            == 2
            and not any(
                "quickcommand.toLowerCase" in line for line in proposed_additions
            )
            and not any(
                "navigateToResourceCreation" in line for line in proposed_additions
            )
        ),
    }

    replacement_checks = {
        "direct_origin_has_expected_parent": origin_metadata.get("parents")
        == [DIRECT_ORIGIN_PARENT_SHA],
        "direct_origin_is_not_observed_ai_under_frozen_scan": DIRECT_ORIGIN_SHA
        not in observed_ai,
        "server_contract_origin_is_not_observed_ai_under_frozen_scan": (
            SERVER_CONTRACT_ORIGIN_SHA not in observed_ai
        ),
        "direct_origin_strictly_precedes_promoted_candidate_and_fix": (
            _is_ancestor(repository, DIRECT_ORIGIN_SHA, PROPOSED_CANDIDATE_SHA)
            and _is_ancestor(repository, DIRECT_ORIGIN_SHA, FIX_SHA)
        ),
        "origin_parent_input_uses_working_livewire_model_path": (
            WIRE_MODEL_INPUT in origin_parent_view
            and ALPINE_MODEL_INPUT not in origin_parent_view
            and "'new image' => 'docker-image'," in origin_parent_component
        ),
        "origin_replaces_wire_model_with_client_only_matcher": (
            WIRE_MODEL_INPUT not in origin_view
            and ALPINE_MODEL_INPUT in origin_view
            and MATCHER_START in origin_view
            and LEGACY_MATCHER_MARKER in origin_view
            and "$wire.navigateToResource(matchingItem.type);" in origin_view
        ),
        "working_backend_command_contract_survives_frontend_migration": all(
            backend_methods_unchanged.values()
        ),
        "new_image_fails_but_new_docker_image_succeeds_before_fix": (
            command_matrix["new image"]["pre_fix_client_match"] is False
            and command_matrix["new docker image"]["pre_fix_client_match"] is True
        ),
        "fix_makes_both_aliases_resolve": all(
            row["fixed_client_match"] is True for row in command_matrix.values()
        ),
        "origin_matcher_survives_unchanged_to_fix_parent": (
            _region(origin_view, MATCHER_START, MATCHER_END)
            == _region(fix_parent_view, MATCHER_START, MATCHER_END)
        ),
        "blame_attributes_client_matcher_to_direct_origin": all(
            matcher_origins[key]["origin_sha"] == DIRECT_ORIGIN_SHA
            for key in ("exact_command_list", "client_name_matcher")
        ),
        "blame_attributes_item_contract_to_older_server_origin": (
            matcher_origins["docker_image_quickcommand_data"]["origin_sha"]
            == SERVER_CONTRACT_ORIGIN_SHA
        ),
        "fix_adds_quickcommand_resolution_and_targeted_contract_test": (
            any(FIXED_MATCHER_MARKER in line for line in fix_additions)
            and FIXED_MATCHER_MARKER in fixed_view
            and "quickcommand.toLowerCase().includes(trimmed)" in fix_test
            and "'quickcommand' => '(type: new image)'" in fix_test
        ),
    }

    proposed_result = {
        "candidate_sha": PROPOSED_CANDIDATE_SHA,
        "fix_sha": FIX_SHA,
        "adjudication": "REJECTED_FORMATTING_REVERSAL_WRONG_ORIGIN",
        "candidate_retained": True,
        "bridge_class": bridge_row.get("delta_bridge_class"),
        "source_pair_sha256": bridge_row.get("source_pair_sha256"),
        "checks": proposed_checks,
        "witness_passed": all(proposed_checks.values()),
        "reason": (
            "The promoted AI commit changes loading-time input behavior while the "
            "client quick-command matcher and the PHP creation contract remain "
            "byte-identical. Its 72-line exact reversal is broad template formatting "
            "overlap, not ownership of the new-image dispatch failure."
        ),
    }
    replacement_result = {
        "candidate_sha": DIRECT_ORIGIN_SHA,
        "fix_sha": FIX_SHA,
        "adjudication": "CONFIRMED_DIRECT_FRONTEND_MATCHER_REGRESSION",
        "observed_ai": False,
        "counted_ai_true_positive": False,
        "causal_role": "DIRECT_ORIGIN",
        "mechanism_group": "global_search_new_image_client_alias_resolution",
        "checks": replacement_checks,
        "witness_passed": all(replacement_checks.values()),
        "command_matrix": command_matrix,
        "line_origins": matcher_origins,
        "backend_methods_unchanged": backend_methods_unchanged,
        "claim": (
            "The frontend-heavy migration disconnects the input from the working "
            "Livewire resource map and introduces a client matcher that accepts "
            "the literal command 'new image' but cannot match it to the frozen "
            "Docker Image item. The later repair adds the missing quickcommand "
            "resolution."
        ),
    }
    witness_passed = bool(
        proposed_result["witness_passed"] is True
        and replacement_result["witness_passed"] is True
    )
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_global_search_new_image_origin_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "proposed_edge_result": proposed_result,
        "replacement_origin": replacement_result,
        "summary": {
            "audited_promoted_edge_count": 1,
            "confirmed_promoted_edge_count": 0,
            "rejected_promoted_edge_count": 1,
            "confirmed_replacement_origin_count": 1,
            "confirmed_replacement_ai_true_positive_count": 0,
            "retained_review_candidate_count": 1,
            "model_call_count": 0,
            "ledger_mutation_count": 0,
        },
        "source_blobs": {
            "origin_parent_view_sha256": hashlib.sha256(
                origin_parent_view.encode("utf-8")
            ).hexdigest(),
            "origin_view_sha256": hashlib.sha256(
                origin_view.encode("utf-8")
            ).hexdigest(),
            "fix_parent_view_sha256": hashlib.sha256(
                fix_parent_view.encode("utf-8")
            ).hexdigest(),
            "fixed_view_sha256": hashlib.sha256(fixed_view.encode("utf-8")).hexdigest(),
        },
        "witness_passed": witness_passed,
        "claim_boundary": (
            "This witness confirms only the concrete 'new image' alias-dispatch "
            "regression. It rejects the promoted loading-input commit without "
            "deleting it from the recall universe and reattributes the mechanism "
            "to the earlier, unobserved-AI frontend migration. It therefore adds "
            "no AI true positive. The repair's separate search-query clearing and "
            "Livewire redirect edits are older mechanisms and are not claimed here. "
            "Commit messages are recorded only as metadata and are not required by "
            "any causal check."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    ai_path = args.ai_scan_dir.resolve() / "commits.jsonl"
    bridge_dir = args.delta_bridge_dir.resolve()
    bridge_summary_path = bridge_dir / "summary.json"
    bridge_pairs_path = bridge_dir / "delta_bridge_pairs.jsonl"
    ai_rows = _load_jsonl(ai_path)
    payload = build_witness(
        repository,
        bridge_summary=_load_json(bridge_summary_path),
        bridge_rows=_load_jsonl(bridge_pairs_path),
        observed_ai={str(row.get("sha") or "") for row in ai_rows},
    )
    payload["source_artifacts"] = {
        "ai_commits": {"path": str(ai_path), "sha256": _sha256(ai_path)},
        "delta_bridge_summary": {
            "path": str(bridge_summary_path),
            "sha256": _sha256(bridge_summary_path),
        },
        "delta_bridge_pairs": {
            "path": str(bridge_pairs_path),
            "sha256": _sha256(bridge_pairs_path),
        },
    }
    if payload["witness_passed"] is not True:
        failures = {
            key: sorted(
                check
                for check, passed in dict(result["checks"]).items()
                if passed is not True
            )
            for key, result in (
                ("proposed_edge", payload["proposed_edge_result"]),
                ("replacement_origin", payload["replacement_origin"]),
            )
            if result["witness_passed"] is not True
        }
        raise SystemExit(f"global-search attribution witness failed: {failures}")

    output = args.output.resolve()
    _atomic_json(output, payload)
    print("Coolify global-search new-image origin witness frozen")
    print("  promoted edge : rejected")
    print(f"  causal origin : {DIRECT_ORIGIN_SHA}")
    print("  AI TP added   : 0")
    print(f"  output        : {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
