#!/usr/bin/env python3
"""Freeze a conservative attribution audit for a silent Coolify datalist revert.

The recall bridge promotes an exact-delta edge from ``84559a0`` to ``62d99b0``.
This witness follows the immediate three-commit chain and separates exact source
ownership from demonstrated defect causality.  It never consumes model output or
mutates the causal ledger.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
)


BASELINE_SHA = "58864b9b20d6a5ba09426c68a3ad6255a43cc1a1"
PROMOTED_CANDIDATE_SHA = "84559a0e7d71c05be9a123a96cf589d0719500c7"
INTERVENING_CANDIDATE_SHA = "e1fe58639756cf7b232458eddd6978e4ed0031f5"
FIX_SHA = "62d99b0b8bab570a79e5740f459bb94eb3238203"

DATALIST_PATH = "resources/views/components/forms/datalist.blade.php"
HETZNER_VIEW_PATH = "resources/views/livewire/server/new/by-hetzner.blade.php"
TERMINAL_VIEW_PATH = "resources/views/livewire/terminal/index.blade.php"

BASE_SELECTED_LOOP = '<template x-for="value in selected" :key="value">'
GUARDED_SELECTED_LOOP = '<template x-for="value in (selected || [])" :key="value">'
BASE_EMPTY_CHECK = '<template x-if="filteredOptions.length === 0">'
GUARDED_EMPTY_CHECK = '<template x-if="(filteredOptions || []).length === 0">'
BASE_OPTION_LOOP = '<template x-for="option in filteredOptions" :key="option.value">'
GUARDED_OPTION_LOOP = (
    '<template x-for="option in (filteredOptions || [])" :key="option.value">'
)
FALLBACK_OPTION_LOOP = (
    '<template x-for="(option, index) in (filteredOptions || [])" '
    ':key="option?.value || index">'
)


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


def _patch_lines(diff: str, prefix: str) -> Counter[str]:
    if prefix not in {"+", "-"}:
        raise ValueError("patch prefix must be '+' or '-'")
    header = prefix * 3
    return Counter(
        line[1:].strip()
        for line in diff.splitlines()
        if line.startswith(prefix) and not line.startswith(header)
    )


def _exact_line_delta(
    diff: str,
    *,
    added: Mapping[str, int],
    removed: Mapping[str, int],
) -> bool:
    return _patch_lines(diff, "+") == Counter(added) and _patch_lines(
        diff, "-"
    ) == Counter(removed)


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


def _bridge_checks(row: Mapping[str, object], expected_class: str) -> dict[str, bool]:
    return {
        "recall_edge_retained": row.get("retained") is True,
        "exact_delta_tier_zero": int(row.get("delta_bridge_tier", -1)) == 0,
        "expected_exact_delta_class": row.get("delta_bridge_class") == expected_class,
        "direct_runtime_preimage_priority": row.get("source_priority_class")
        == "P0_DIRECT_RUNTIME_PREIMAGE_OWNER",
    }


def _component_contract(source: str) -> dict[str, bool]:
    """Check only source-visible array/object construction contracts."""

    return {
        "both_modes_initialize_options_as_arrays": source.count("options: [],") == 2,
        "both_modes_initialize_filtered_options_as_arrays": source.count(
            "filteredOptions: [],"
        )
        == 2,
        "multiple_mode_normalizes_selected_to_array": all(
            marker in source
            for marker in (
                "if (!Array.isArray(this.selected)) {",
                "this.selected = [];",
            )
        ),
        "multiple_mode_maps_each_dom_option_to_object": all(
            marker in source
            for marker in (
                "this.options = Array.from(this.$refs.datalist.querySelectorAll('option')).map(opt => {",
                "value: value,",
                "text: opt.textContent.trim()",
            )
        ),
        "single_mode_filters_disabled_null_entries": all(
            marker in source
            for marker in (
                "if (opt.disabled) {",
                "return null;",
                "}).filter(opt => opt !== null);",
            )
        ),
        "filtered_options_are_assigned_from_materialized_options": source.count(
            "this.filteredOptions = this.options;"
        )
        >= 2,
    }


def _datalist_callsites(repository: Path, revision: str) -> tuple[str, ...]:
    value = _git(
        repository,
        [
            "grep",
            "-l",
            "<x-forms.datalist",
            revision,
            "--",
            "resources/views",
        ],
        text=True,
    )
    assert isinstance(value, str)
    prefix = f"{revision}:"
    paths = [line.removeprefix(prefix) for line in value.splitlines() if line]
    return tuple(sorted(paths))


def _consumer_contract(hetzner: str, terminal: str) -> dict[str, bool]:
    hetzner_blocks = re.findall(
        r"<x-forms\.datalist\b.*?</x-forms\.datalist>", hetzner, re.DOTALL
    )
    terminal_blocks = re.findall(
        r"<x-forms\.datalist\b.*?</x-forms\.datalist>", terminal, re.DOTALL
    )
    hetzner_datalist = "\n".join(hetzner_blocks)
    terminal_datalist = "\n".join(terminal_blocks)
    combined = f"{hetzner_datalist}\n{terminal_datalist}"
    enabled_falsy_literal = re.search(
        r"<option\b(?![^>]*\bdisabled\b)[^>]*\bvalue\s*=\s*(['\"])(?:0|)\1",
        combined,
        re.IGNORECASE,
    )
    return {
        "one_datalist_component_per_consumer_view": (
            len(hetzner_blocks) == 1 and len(terminal_blocks) == 1
        ),
        "multiple_consumer_uses_hetzner_key_id": (
            "<x-forms.datalist" in hetzner_datalist
            and ':multiple="true"' in hetzner_datalist
            and "<option value=\"{{ $sshKey['id'] }}\">" in hetzner_datalist
        ),
        "single_consumer_uses_server_and_container_uuids": all(
            marker in terminal_datalist
            for marker in (
                '<option value="{{ $server->uuid }}">',
                "<option value=\"{{ $container['uuid'] }}\">",
            )
        ),
        "single_consumer_filters_literal_default_with_disabled": (
            '<option disabled value="default">' in terminal_datalist
        ),
        "no_concrete_enabled_literal_zero_or_empty_fixture": enabled_falsy_literal
        is None,
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

    proposed_bridge = _bridge_edge(bridge_rows, PROMOTED_CANDIDATE_SHA, FIX_SHA)
    alternative_bridge = _bridge_edge(bridge_rows, INTERVENING_CANDIDATE_SHA, FIX_SHA)
    baseline = _source(repository, BASELINE_SHA, DATALIST_PATH)
    promoted = _source(repository, PROMOTED_CANDIDATE_SHA, DATALIST_PATH)
    intervening = _source(repository, INTERVENING_CANDIDATE_SHA, DATALIST_PATH)
    fixed = _source(repository, FIX_SHA, DATALIST_PATH)

    promoted_diff = _diff(
        repository, BASELINE_SHA, PROMOTED_CANDIDATE_SHA, DATALIST_PATH
    )
    intervening_diff = _diff(
        repository,
        PROMOTED_CANDIDATE_SHA,
        INTERVENING_CANDIDATE_SHA,
        DATALIST_PATH,
    )
    fix_diff = _diff(repository, INTERVENING_CANDIDATE_SHA, FIX_SHA, DATALIST_PATH)
    fix_metadata = _commit_metadata(repository, FIX_SHA)
    promoted_metadata = _commit_metadata(repository, PROMOTED_CANDIDATE_SHA)
    intervening_metadata = _commit_metadata(repository, INTERVENING_CANDIDATE_SHA)

    expected_callsites = tuple(sorted((HETZNER_VIEW_PATH, TERMINAL_VIEW_PATH)))
    callsites = _datalist_callsites(repository, FIX_SHA)
    consumer_checks = _consumer_contract(
        _source(repository, FIX_SHA, HETZNER_VIEW_PATH),
        _source(repository, FIX_SHA, TERMINAL_VIEW_PATH),
    )
    contract_checks = _component_contract(intervening)

    chain_checks = {
        "all_three_commits_are_observed_ai": {
            PROMOTED_CANDIDATE_SHA,
            INTERVENING_CANDIDATE_SHA,
            FIX_SHA,
        }.issubset(observed_ai),
        "promoted_candidate_parent_is_frozen_baseline": promoted_metadata.get("parents")
        == [BASELINE_SHA],
        "intervening_candidate_is_immediate_child": intervening_metadata.get("parents")
        == [PROMOTED_CANDIDATE_SHA],
        "fix_is_immediate_child_of_intervening_candidate": fix_metadata.get("parents")
        == [INTERVENING_CANDIDATE_SHA],
        "promoted_candidate_strictly_precedes_fix": (
            PROMOTED_CANDIDATE_SHA != FIX_SHA
            and _is_ancestor(repository, PROMOTED_CANDIDATE_SHA, FIX_SHA)
        ),
    }
    immediate_parent_chain = bool(
        chain_checks["promoted_candidate_parent_is_frozen_baseline"]
        and chain_checks["intervening_candidate_is_immediate_child"]
        and chain_checks["fix_is_immediate_child_of_intervening_candidate"]
    )

    promoted_checks = {
        **_bridge_checks(proposed_bridge, "B0_BIDIRECTIONAL_EXACT_REVERSAL"),
        **chain_checks,
        "promoted_datalist_delta_only_adds_nullish_array_wrappers": (
            _exact_line_delta(
                promoted_diff,
                added={
                    GUARDED_SELECTED_LOOP: 1,
                    GUARDED_EMPTY_CHECK: 2,
                    GUARDED_OPTION_LOOP: 2,
                },
                removed={
                    BASE_SELECTED_LOOP: 1,
                    BASE_EMPTY_CHECK: 2,
                    BASE_OPTION_LOOP: 2,
                },
            )
        ),
        "promoted_state_preserves_source_visible_array_contracts": all(
            _component_contract(promoted).values()
        ),
        "fix_restores_baseline_datalist_byte_for_byte": fixed == baseline,
        "fix_is_silent_single_file_revert_without_test_delta": (
            _changed_paths(repository, INTERVENING_CANDIDATE_SHA, FIX_SHA)
            == (DATALIST_PATH,)
            and str(fix_metadata.get("message") or "").strip()
            == "Changes auto-committed by Conductor"
        ),
    }

    alternative_checks = {
        **_bridge_checks(alternative_bridge, "B0_CANDIDATE_ADDITION_EXACTLY_REMOVED"),
        **chain_checks,
        "intervening_delta_only_adds_optional_value_index_key_fallback": (
            _exact_line_delta(
                intervening_diff,
                added={FALLBACK_OPTION_LOOP: 2},
                removed={GUARDED_OPTION_LOOP: 2},
            )
        ),
        "fix_removes_both_generations_and_restores_original_lines": (
            _exact_line_delta(
                fix_diff,
                added={
                    BASE_SELECTED_LOOP: 1,
                    BASE_EMPTY_CHECK: 2,
                    BASE_OPTION_LOOP: 2,
                },
                removed={
                    GUARDED_SELECTED_LOOP: 1,
                    GUARDED_EMPTY_CHECK: 2,
                    FALLBACK_OPTION_LOOP: 2,
                },
            )
        ),
        "option_construction_excludes_null_loop_entries": all(contract_checks.values()),
        "frozen_fix_callsites_are_exactly_two_known_consumers": callsites
        == expected_callsites,
        "frozen_consumers_supply_ids_or_uuids_without_falsy_literal_fixture": all(
            consumer_checks.values()
        ),
        "no_commit_or_test_evidence_names_a_key_failure": (
            str(fix_metadata.get("message") or "").strip()
            == "Changes auto-committed by Conductor"
            and not any(
                path.startswith("tests/")
                for path in _changed_paths(
                    repository, INTERVENING_CANDIDATE_SHA, FIX_SHA
                )
            )
        ),
    }

    proposed_result = {
        "candidate_sha": PROMOTED_CANDIDATE_SHA,
        "fix_sha": FIX_SHA,
        "adjudication": "REJECTED_NO_DEMONSTRATED_DEFECT_IN_CANDIDATE_DELTA",
        "candidate_retained": True,
        "bridge_class": proposed_bridge.get("delta_bridge_class"),
        "source_pair_sha256": proposed_bridge.get("source_pair_sha256"),
        "checks": promoted_checks,
        "witness_passed": all(promoted_checks.values()),
        "reason": (
            "The promoted commit only wraps already source-initialized arrays with "
            "fallback arrays. The later generic commit restores the old template "
            "byte-for-byte, but provides no failing contract, test, or rationale "
            "that makes the wrapper delta a demonstrated defect."
        ),
    }
    alternative_result = {
        "candidate_sha": INTERVENING_CANDIDATE_SHA,
        "fix_sha": FIX_SHA,
        "adjudication": "ABSTAIN_UNPROVEN_FALSY_KEY_FALLBACK_REGRESSION",
        "candidate_retained": True,
        "bridge_class": alternative_bridge.get("delta_bridge_class"),
        "source_pair_sha256": alternative_bridge.get("source_pair_sha256"),
        "checks": alternative_checks,
        "witness_passed": all(alternative_checks.values()),
        "reason": (
            "The immediate parent introduces option?.value || index, which can "
            "change Alpine key semantics for a falsy option value. The component "
            "materializes non-null option objects, however, and the two frozen "
            "callsites expose IDs or UUIDs with no concrete enabled falsy fixture. "
            "Without a failing input, test, or repair rationale this remains a "
            "retained hypothesis rather than a claim-grade origin."
        ),
    }
    witness_passed = bool(
        proposed_result["witness_passed"] is True
        and alternative_result["witness_passed"] is True
    )
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_conductor_datalist_revert_attribution_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "chain": {
            "baseline_sha": BASELINE_SHA,
            "promoted_candidate_sha": PROMOTED_CANDIDATE_SHA,
            "intervening_candidate_sha": INTERVENING_CANDIDATE_SHA,
            "fix_sha": FIX_SHA,
            "immediate_parent_chain": immediate_parent_chain,
        },
        "proposed_edge_result": proposed_result,
        "alternative_hypothesis": alternative_result,
        "component_contract_checks": contract_checks,
        "consumer_contract_checks": consumer_checks,
        "frozen_datalist_callsites": list(callsites),
        "source_blobs": {
            "baseline_datalist_sha256": hashlib.sha256(
                baseline.encode("utf-8")
            ).hexdigest(),
            "promoted_datalist_sha256": hashlib.sha256(
                promoted.encode("utf-8")
            ).hexdigest(),
            "intervening_datalist_sha256": hashlib.sha256(
                intervening.encode("utf-8")
            ).hexdigest(),
            "fixed_datalist_sha256": hashlib.sha256(fixed.encode("utf-8")).hexdigest(),
        },
        "summary": {
            "audited_promoted_edge_count": 1,
            "confirmed_promoted_edge_count": 0,
            "rejected_promoted_edge_count": 1,
            "alternative_hypothesis_count": 1,
            "confirmed_alternative_edge_count": 0,
            "abstained_alternative_hypothesis_count": 1,
            "retained_review_candidate_count": 2,
            "claim_grade_positive_edge_count": 0,
            "model_call_count": 0,
            "ledger_mutation_count": 0,
        },
        "witness_passed": witness_passed,
        "claim_boundary": (
            "The exact-delta bridge correctly recovers a finite three-commit "
            "revert chain and remains useful for recall. Exact source reversal "
            "establishes deleted-line ownership, not defect causality. The promoted "
            "84559a edge is rejected as a claim-grade positive because its nullish "
            "wrappers have no demonstrated failing contract. The immediate e1fe58 "
            "key-fallback delta remains visible as an abstained hypothesis because "
            "a falsy-key risk is theoretically possible but no frozen consumer, "
            "test, commit rationale, or runtime witness establishes it. Neither "
            "candidate is removed from the recall universe."
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
                ("alternative", payload["alternative_hypothesis"]),
            )
            if result["witness_passed"] is not True
        }
        raise SystemExit(f"datalist revert attribution witness failed: {failures}")

    output = args.output.resolve()
    _atomic_json(output, payload)
    print("Coolify Conductor datalist revert attribution witness frozen")
    print("  promoted edge : rejected")
    print("  alternative   : abstained")
    print("  claim-grade TP: 0")
    print(f"  output        : {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
