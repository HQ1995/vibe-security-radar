#!/usr/bin/env python3
"""Freeze deterministic attribution for four promoted Coolify UI edges.

The exact-delta frontier is intentionally recall-first.  This witness checks the
candidate preimage and intervening history before making a causal claim.  It
does not consume model output or mutate the causal ledger.
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
)


FORM_CANDIDATE_SHA = "2a8f02ed58509ff4619517411a0b00cec9971c1f"
DIRTY_FIX_SHA = "a5c6f53b583c93b1871ac1099632d47d157a0341"
PASSWORD_FIX_SHA = "a3c80c9778d2c4b744afafb8d88dc47f51c448aa"
BINDING_FIX_SHA = "7c14cd24dc923a997dec733d5038a306f1cac36a"

ONBOARDING_CANDIDATE_SHA = "ac653ddcbc15019e9617e719bf687f10f25a80f2"
ONBOARDING_FIX_SHA = "2e71ef4f1111421a67dabfb506387c938b320b80"

DIRTY_MERGE_ORIGIN_SHA = "837a0f4545f4b0bb68ecd222af21be50a4f4530f"
DIRTY_BINDING_BRANCH_SHA = "a514c837b6a28179589025ab765184e786a40c22"
PASSWORD_BUTTON_ORIGIN_SHA = "a5840501b41a90ff453b7f8fb28e872a659e2813"
BINDING_CONTRACT_ORIGIN_SHA = "e2c254a5a8518c8dd9d31df60c9009fad119226d"
ONBOARDING_MODAL_ORIGIN_SHA = "04625591eaafac64db412b21b0f4c4c0f82fc8ad"

INPUT_PATH = "resources/views/components/forms/input.blade.php"
TEXTAREA_PATH = "resources/views/components/forms/textarea.blade.php"
PASSWORD_TEST_PATH = "tests/Feature/PasswordVisibilityComponentTest.php"
GENERAL_VIEW_PATH = "resources/views/livewire/project/application/general.blade.php"
GENERAL_COMPONENT_PATH = "app/Livewire/Project/Application/General.php"
BOARDING_VIEW_PATH = "resources/views/livewire/boarding/index.blade.php"
HETZNER_COMPONENT_PATH = "app/Livewire/Server/New/ByHetzner.php"

DIRTY_BORDER = (
    'wire:dirty.class="dark:border-l-warning border-l-coollabs border-l-4"'
)
DIRTY_RING = 'wire:dirty.class="dark:ring-warning ring-warning"'
MODEL_BINDING = (
    "@if ($modelBinding !== 'null') wire:model={{ $modelBinding }} @endif"
)
MODEL_BINDING_WITH_DIRTY = (
    "@if ($modelBinding !== 'null') wire:model={{ $modelBinding }} "
    f"{DIRTY_BORDER} @endif"
)
HETZNER_CALL = (
    '<livewire:server.new.by-hetzner :private_keys="$this->privateKeys" '
    ':limit_reached="false" />'
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


def _source(repository: Path, revision: str, path: str) -> str:
    return _git_blob(repository, revision, path).decode("utf-8")


def _diff(repository: Path, old: str, new: str, *paths: str) -> str:
    value = _git(
        repository,
        ["diff", old, new, "--", *paths],
        text=True,
    )
    assert isinstance(value, str)
    return value


def _added_lines(diff: str) -> tuple[str, ...]:
    return tuple(
        line[1:]
        for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )


def _strict_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    return ancestor != descendant and _is_ancestor(repository, ancestor, descendant)


def _position_before(source: str, first: str, second: str) -> bool:
    first_index = source.find(first)
    second_index = source.find(second)
    return first_index >= 0 and second_index >= 0 and first_index < second_index


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


def _bridge_checks(row: Mapping[str, object]) -> dict[str, bool]:
    return {
        "recall_edge_retained": row.get("retained") is True,
        "exact_delta_tier_zero": int(row.get("delta_bridge_tier", -1)) == 0,
        "candidate_addition_exactly_removed": row.get("delta_bridge_class")
        == "B0_CANDIDATE_ADDITION_EXACTLY_REMOVED",
    }


def _result(
    *,
    key: str,
    candidate_sha: str,
    fix_sha: str,
    disposition: str,
    reason: str,
    bridge_row: Mapping[str, object],
    checks: Mapping[str, bool],
    replacement: Mapping[str, object] | None,
) -> dict[str, object]:
    all_checks = {**_bridge_checks(bridge_row), **checks}
    return {
        "key": key,
        "promoted_candidate_sha": candidate_sha,
        "fix_sha": fix_sha,
        "adjudication": disposition,
        "candidate_retained": True,
        "reason": reason,
        "bridge_class": bridge_row.get("delta_bridge_class"),
        "source_pair_sha256": bridge_row.get("source_pair_sha256"),
        "replacement": replacement,
        "checks": all_checks,
        "witness_passed": all(all_checks.values()),
    }


def _dirty_merge_case(
    repository: Path,
    bridge_row: Mapping[str, object],
    observed_ai: set[str],
) -> dict[str, object]:
    candidate_parent = f"{FORM_CANDIDATE_SHA}^"
    before = _source(repository, candidate_parent, INPUT_PATH)
    candidate = _source(repository, FORM_CANDIDATE_SHA, INPUT_PATH)
    binding_branch = _source(repository, DIRTY_BINDING_BRANCH_SHA, INPUT_PATH)
    merge = _source(repository, DIRTY_MERGE_ORIGIN_SHA, INPUT_PATH)
    repaired = _source(repository, DIRTY_FIX_SHA, INPUT_PATH)
    candidate_additions = _added_lines(
        _diff(repository, candidate_parent, FORM_CANDIDATE_SHA, INPUT_PATH)
    )
    fix_metadata = _commit_metadata(repository, DIRTY_FIX_SHA)
    checks = {
        "promoted_candidate_is_observed_ai": FORM_CANDIDATE_SHA in observed_ai,
        "promoted_candidate_strictly_precedes_fix": _strict_ancestor(
            repository, FORM_CANDIDATE_SHA, DIRTY_FIX_SHA
        ),
        "candidate_parent_already_has_equivalent_unconditional_dirty_directive": (
            DIRTY_RING in before
            and DIRTY_BORDER in candidate
            and MODEL_BINDING not in before
            and MODEL_BINDING not in candidate
        ),
        "candidate_only_changes_dirty_visual_style": (
            any(DIRTY_BORDER in line for line in candidate_additions)
            and not any("$modelBinding" in line for line in candidate_additions)
            and not any(
                DIRTY_BORDER in line and "wire:model" in line
                for line in candidate_additions
            )
        ),
        "sibling_ai_branch_introduces_model_binding_with_old_style": (
            DIRTY_BINDING_BRANCH_SHA in observed_ai
            and MODEL_BINDING in binding_branch
            and DIRTY_RING in binding_branch
            and DIRTY_BORDER not in binding_branch
        ),
        "ai_merge_combines_binding_and_unconditional_border": (
            DIRTY_MERGE_ORIGIN_SHA in observed_ai
            and MODEL_BINDING in merge
            and DIRTY_BORDER in merge
            and MODEL_BINDING_WITH_DIRTY not in merge
            and _strict_ancestor(
                repository, FORM_CANDIDATE_SHA, DIRTY_MERGE_ORIGIN_SHA
            )
            and _strict_ancestor(
                repository, DIRTY_BINDING_BRANCH_SHA, DIRTY_MERGE_ORIGIN_SHA
            )
        ),
        "merge_is_immediate_fix_parent": fix_metadata.get("parents")
        == [DIRTY_MERGE_ORIGIN_SHA],
        "fix_co_locates_dirty_with_livewire_binding": (
            MODEL_BINDING_WITH_DIRTY in repaired
            and MODEL_BINDING not in repaired
        ),
        "fix_message_names_unbound_readonly_dirty_indicator": all(
            fragment in str(fix_metadata.get("message") or "").casefold()
            for fragment in ("wire:dirty", "readonly", "without wire:model")
        ),
    }
    replacement = {
        "candidate_sha": DIRTY_MERGE_ORIGIN_SHA,
        "fix_sha": DIRTY_FIX_SHA,
        "adjudication": "CONFIRMED_AI_MERGE_COMPOSITIONAL_ORIGIN",
        "causal_role": "MERGE_COMPOSITION_ORIGIN",
        "mechanism_group": "unbound_form_dirty_indicator_merge_composition",
        "claim": (
            "the AI-authored conflict-resolution merge combined the modelBinding "
            "branch with the new dirty-border branch and left wire:dirty outside "
            "the binding guard; its immediate child moved the directive inside"
        ),
    }
    return _result(
        key="wire_dirty_readonly_wrong_premerge_owner",
        candidate_sha=FORM_CANDIDATE_SHA,
        fix_sha=DIRTY_FIX_SHA,
        disposition="REJECTED_WRONG_ORIGIN_MERGE_COMPOSITION",
        reason=(
            "The promoted branch changed the dirty indicator's style but did not "
            "introduce modelBinding or the unbound-field composition. The later "
            "AI merge explicitly combined those independent branch states and is "
            "the repair's immediate parent."
        ),
        bridge_row=bridge_row,
        checks=checks,
        replacement=replacement,
    )


def _password_order_case(
    repository: Path,
    bridge_row: Mapping[str, object],
    observed_ai: set[str],
) -> dict[str, object]:
    candidate_parent = f"{FORM_CANDIDATE_SHA}^"
    before_input = _source(repository, candidate_parent, INPUT_PATH)
    candidate_input = _source(repository, FORM_CANDIDATE_SHA, INPUT_PATH)
    candidate_textarea = _source(repository, FORM_CANDIDATE_SHA, TEXTAREA_PATH)
    origin_parent_input = _source(
        repository, f"{PASSWORD_BUTTON_ORIGIN_SHA}^", INPUT_PATH
    )
    origin_input = _source(repository, PASSWORD_BUTTON_ORIGIN_SHA, INPUT_PATH)
    fix_parent_input = _source(repository, f"{PASSWORD_FIX_SHA}^", INPUT_PATH)
    fixed_input = _source(repository, PASSWORD_FIX_SHA, INPUT_PATH)
    candidate_diff = _diff(
        repository,
        candidate_parent,
        FORM_CANDIDATE_SHA,
        INPUT_PATH,
        TEXTAREA_PATH,
    )
    origin_diff = _diff(
        repository,
        f"{PASSWORD_BUTTON_ORIGIN_SHA}^",
        PASSWORD_BUTTON_ORIGIN_SHA,
        INPUT_PATH,
        TEXTAREA_PATH,
    )
    fix_diff = _diff(
        repository,
        f"{PASSWORD_FIX_SHA}^",
        PASSWORD_FIX_SHA,
        INPUT_PATH,
        TEXTAREA_PATH,
        PASSWORD_TEST_PATH,
    )
    fix_metadata = _commit_metadata(repository, PASSWORD_FIX_SHA)
    old_toggle = '<div x-on:click="changePasswordFieldType'
    button = '<button type="button"'
    input_field = '<input autocomplete="{{ $autocomplete }}"'
    checks = {
        "promoted_candidate_is_observed_ai": FORM_CANDIDATE_SHA in observed_ai,
        "promoted_candidate_strictly_precedes_fix": _strict_ancestor(
            repository, FORM_CANDIDATE_SHA, PASSWORD_FIX_SHA
        ),
        "candidate_parent_and_candidate_use_nonfocusable_toggle": (
            _position_before(before_input, old_toggle, input_field)
            and _position_before(candidate_input, old_toggle, input_field)
            and button not in candidate_input
        ),
        "candidate_delta_does_not_add_focusable_toggle": (
            button not in "\n".join(_added_lines(candidate_diff))
            and 'x-ref="autofocusInput"' in candidate_textarea
        ),
        "intervening_origin_changes_toggle_to_button_before_input": (
            _position_before(origin_parent_input, old_toggle, input_field)
            and _position_before(origin_input, button, input_field)
            and button in "\n".join(_added_lines(origin_diff))
            and _strict_ancestor(
                repository, PASSWORD_BUTTON_ORIGIN_SHA, PASSWORD_FIX_SHA
            )
        ),
        "intervening_origin_is_not_observed_ai": PASSWORD_BUTTON_ORIGIN_SHA
        not in observed_ai,
        "bad_button_order_survives_to_fix_parent": _position_before(
            fix_parent_input, button, input_field
        ),
        "fix_places_input_before_toggle": _position_before(
            fixed_input, input_field, button
        ),
        "fix_adds_explicit_tab_order_tests": all(
            fragment in fix_diff
            for fragment in (
                "renders password input before visibility toggle in tab order",
                "renders password textarea input before visibility toggle in tab order",
                "toBeLessThan",
            )
        ),
        "fix_message_names_field_before_toggle_contract": all(
            fragment in str(fix_metadata.get("message") or "").casefold()
            for fragment in ("password fields", "before", "visibility toggles")
        ),
    }
    replacement = {
        "candidate_sha": PASSWORD_BUTTON_ORIGIN_SHA,
        "fix_sha": PASSWORD_FIX_SHA,
        "adjudication": "NOT_AN_AI_TRUE_POSITIVE_UNDER_CURRENT_SCAN",
        "observed_ai": False,
        "mechanism_group": "focusable_password_toggle_precedes_editable_field",
        "claim": (
            "the intervening commit made the previously nonfocusable toggle a "
            "button before the editable field; the fix reverses that DOM order "
            "and adds explicit tab-order tests"
        ),
    }
    return _result(
        key="password_focus_toggle_incidental_exact_overlap",
        candidate_sha=FORM_CANDIDATE_SHA,
        fix_sha=PASSWORD_FIX_SHA,
        disposition="REJECTED_INTERVENING_UNOBSERVED_AI_ORIGIN",
        reason=(
            "The promoted candidate still rendered a nonfocusable div toggle. "
            "A later commit changed it to a focusable button before the input; "
            "that later state is exactly what the repair and its tests reverse."
        ),
        bridge_row=bridge_row,
        checks=checks,
        replacement=replacement,
    )


def _binding_contract_case(
    repository: Path,
    bridge_row: Mapping[str, object],
    observed_ai: set[str],
) -> dict[str, object]:
    candidate_parent = f"{FORM_CANDIDATE_SHA}^"
    before_view = _source(repository, candidate_parent, GENERAL_VIEW_PATH)
    candidate_view = _source(repository, FORM_CANDIDATE_SHA, GENERAL_VIEW_PATH)
    origin_parent_component = _source(
        repository, f"{BINDING_CONTRACT_ORIGIN_SHA}^", GENERAL_COMPONENT_PATH
    )
    origin_component = _source(
        repository, BINDING_CONTRACT_ORIGIN_SHA, GENERAL_COMPONENT_PATH
    )
    origin_view = _source(repository, BINDING_CONTRACT_ORIGIN_SHA, GENERAL_VIEW_PATH)
    fix_parent_view = _source(repository, f"{BINDING_FIX_SHA}^", GENERAL_VIEW_PATH)
    fix_parent_component = _source(
        repository, f"{BINDING_FIX_SHA}^", GENERAL_COMPONENT_PATH
    )
    fixed_view = _source(repository, BINDING_FIX_SHA, GENERAL_VIEW_PATH)
    fixed_component = _source(repository, BINDING_FIX_SHA, GENERAL_COMPONENT_PATH)
    candidate_diff = _diff(
        repository,
        candidate_parent,
        FORM_CANDIDATE_SHA,
        GENERAL_VIEW_PATH,
        GENERAL_COMPONENT_PATH,
    )
    origin_diff = _diff(
        repository,
        f"{BINDING_CONTRACT_ORIGIN_SHA}^",
        BINDING_CONTRACT_ORIGIN_SHA,
        GENERAL_VIEW_PATH,
        GENERAL_COMPONENT_PATH,
    )
    fix_metadata = _commit_metadata(repository, BINDING_FIX_SHA)
    nested_blur = 'wire:model.blur="application.fqdn"'
    nested_plain = 'wire:model="application.fqdn"'
    property_plain = 'wire:model="fqdn"'
    trait = "use SynchronizesModelData;"
    mapping = "'fqdn' => 'application.fqdn'"
    checks = {
        "promoted_candidate_is_observed_ai": FORM_CANDIDATE_SHA in observed_ai,
        "promoted_candidate_strictly_precedes_fix": _strict_ancestor(
            repository, FORM_CANDIDATE_SHA, BINDING_FIX_SHA
        ),
        "candidate_only_removes_blur_modifier_from_preexisting_target": (
            nested_blur in before_view
            and nested_plain in candidate_view
            and nested_plain in "\n".join(_added_lines(candidate_diff))
            and trait not in candidate_diff
            and mapping not in candidate_diff
        ),
        "intervening_ai_commit_changes_component_binding_contract": (
            BINDING_CONTRACT_ORIGIN_SHA in observed_ai
            and trait not in origin_parent_component
            and trait in origin_component
            and mapping in origin_component
            and trait in "\n".join(_added_lines(origin_diff))
            and mapping in "\n".join(_added_lines(origin_diff))
            and nested_plain in origin_view
            and _strict_ancestor(
                repository, BINDING_CONTRACT_ORIGIN_SHA, BINDING_FIX_SHA
            )
        ),
        "mismatched_contract_survives_to_fix_parent": (
            nested_plain in fix_parent_view
            and trait in fix_parent_component
            and mapping in fix_parent_component
        ),
        "fix_binds_view_to_canonical_component_property": (
            property_plain in fixed_view
            and nested_plain not in fixed_view
            and trait in fixed_component
            and mapping in fixed_component
        ),
        "fix_message_names_binding_error_and_canonical_property": all(
            fragment in str(fix_metadata.get("message") or "").casefold()
            for fragment in (
                "wire:model binding error",
                'application.fqdn',
                '"fqdn"',
                "synchronizesmodeldata",
            )
        ),
    }
    replacement = {
        "candidate_sha": BINDING_CONTRACT_ORIGIN_SHA,
        "fix_sha": BINDING_FIX_SHA,
        "adjudication": "CONFIRMED_DIRECT_AI_CROSS_FILE_BINDING_CONTRACT_REGRESSION",
        "causal_role": "DIRECT_ORIGIN",
        "mechanism_group": "livewire_fqdn_binding_contract_mismatch",
        "claim": (
            "the Conductor commit made fqdn the canonical Livewire component "
            "property through SynchronizesModelData but left the view bound to "
            "application.fqdn; the fix binds the view to fqdn"
        ),
    }
    return _result(
        key="application_fqdn_wrong_precontract_owner",
        candidate_sha=FORM_CANDIDATE_SHA,
        fix_sha=BINDING_FIX_SHA,
        disposition="REJECTED_WRONG_ORIGIN_INTERVENING_AI_CONTRACT_REFACTOR",
        reason=(
            "The promoted candidate only removed the blur modifier from an "
            "existing target. A later Conductor refactor introduced the canonical "
            "fqdn-to-model synchronization contract without updating that view."
        ),
        bridge_row=bridge_row,
        checks=checks,
        replacement=replacement,
    )


def _onboarding_redirect_case(
    repository: Path,
    bridge_row: Mapping[str, object],
    observed_ai: set[str],
) -> dict[str, object]:
    candidate_parent = f"{ONBOARDING_CANDIDATE_SHA}^"
    before_view = _source(repository, candidate_parent, BOARDING_VIEW_PATH)
    candidate_view = _source(repository, ONBOARDING_CANDIDATE_SHA, BOARDING_VIEW_PATH)
    before_component = _source(repository, candidate_parent, HETZNER_COMPONENT_PATH)
    candidate_component = _source(
        repository, ONBOARDING_CANDIDATE_SHA, HETZNER_COMPONENT_PATH
    )
    origin_parent_view = _source(
        repository, f"{ONBOARDING_MODAL_ORIGIN_SHA}^", BOARDING_VIEW_PATH
    )
    origin_view = _source(
        repository, ONBOARDING_MODAL_ORIGIN_SHA, BOARDING_VIEW_PATH
    )
    origin_component = _source(
        repository, ONBOARDING_MODAL_ORIGIN_SHA, HETZNER_COMPONENT_PATH
    )
    fix_parent_view = _source(repository, f"{ONBOARDING_FIX_SHA}^", BOARDING_VIEW_PATH)
    fix_parent_component = _source(
        repository, f"{ONBOARDING_FIX_SHA}^", HETZNER_COMPONENT_PATH
    )
    fixed_view = _source(repository, ONBOARDING_FIX_SHA, BOARDING_VIEW_PATH)
    fixed_component = _source(
        repository, ONBOARDING_FIX_SHA, HETZNER_COMPONENT_PATH
    )
    candidate_diff = _diff(
        repository,
        candidate_parent,
        ONBOARDING_CANDIDATE_SHA,
        BOARDING_VIEW_PATH,
        HETZNER_COMPONENT_PATH,
    )
    origin_diff = _diff(
        repository,
        f"{ONBOARDING_MODAL_ORIGIN_SHA}^",
        ONBOARDING_MODAL_ORIGIN_SHA,
        BOARDING_VIEW_PATH,
        HETZNER_COMPONENT_PATH,
    )
    fix_metadata = _commit_metadata(repository, ONBOARDING_FIX_SHA)
    modal = '<x-modal-input title="Connect a Hetzner Server" isFullWidth>'
    standard_redirect = "return redirect()->route('server.show', $server->uuid);"
    onboarding_prop = ':from_onboarding="true"'
    livewire_redirect = "return $this->redirect(route('server.show', $server->uuid));"
    checks = {
        "promoted_candidate_is_observed_ai": ONBOARDING_CANDIDATE_SHA in observed_ai,
        "promoted_candidate_strictly_precedes_fix": _strict_ancestor(
            repository, ONBOARDING_CANDIDATE_SHA, ONBOARDING_FIX_SHA
        ),
        "modal_context_and_standard_redirect_predate_candidate": (
            modal in before_view
            and HETZNER_CALL in before_view
            and standard_redirect in before_component
            and modal in candidate_view
            and HETZNER_CALL in candidate_view
            and standard_redirect in candidate_component
        ),
        "candidate_does_not_change_redirect_component": (
            HETZNER_COMPONENT_PATH not in candidate_diff
            and onboarding_prop not in candidate_diff
            and livewire_redirect not in candidate_diff
        ),
        "earlier_ai_commit_introduces_onboarding_modal_call": (
            ONBOARDING_MODAL_ORIGIN_SHA in observed_ai
            and HETZNER_CALL not in origin_parent_view
            and modal in origin_view
            and HETZNER_CALL in origin_view
            and HETZNER_CALL in "\n".join(_added_lines(origin_diff))
            and standard_redirect in origin_component
            and _strict_ancestor(
                repository, ONBOARDING_MODAL_ORIGIN_SHA, ONBOARDING_FIX_SHA
            )
        ),
        "bad_modal_redirect_contract_survives_to_fix_parent": (
            modal in fix_parent_view
            and HETZNER_CALL in fix_parent_view
            and onboarding_prop not in fix_parent_view
            and standard_redirect in fix_parent_component
            and livewire_redirect not in fix_parent_component
        ),
        "fix_marks_onboarding_context_and_uses_livewire_redirect": (
            onboarding_prop in fixed_view
            and "public bool $from_onboarding = false;" in fixed_component
            and livewire_redirect in fixed_component
            and standard_redirect in fixed_component
        ),
        "fix_message_names_modal_navigation_failure": all(
            fragment in str(fix_metadata.get("message") or "").casefold()
            for fragment in ("hetzner server redirect", "onboarding", "modal")
        ),
    }
    replacement = {
        "candidate_sha": ONBOARDING_MODAL_ORIGIN_SHA,
        "fix_sha": ONBOARDING_FIX_SHA,
        "adjudication": "CONFIRMED_DIRECT_AI_ONBOARDING_MODAL_REDIRECT_REGRESSION",
        "causal_role": "DIRECT_ORIGIN",
        "mechanism_group": "hetzner_onboarding_modal_standard_redirect",
        "claim": (
            "the Claude-assisted onboarding feature first mounted ByHetzner "
            "inside the onboarding modal while the component retained its standard "
            "redirect; the fix adds an onboarding flag and Livewire redirect"
        ),
    }
    return _result(
        key="hetzner_onboarding_wrong_later_owner",
        candidate_sha=ONBOARDING_CANDIDATE_SHA,
        fix_sha=ONBOARDING_FIX_SHA,
        disposition="REJECTED_PREEXISTING_ONBOARDING_MODAL_CONTEXT",
        reason=(
            "The modal component call and standard redirect both predate the "
            "promoted candidate. An earlier AI-assisted onboarding commit first "
            "introduced that incompatible composition."
        ),
        bridge_row=bridge_row,
        checks=checks,
        replacement=replacement,
    )


def build_witness(
    repository: Path,
    *,
    bridge_summary: Mapping[str, object],
    bridge_rows: list[dict[str, object]],
    observed_ai: set[str],
) -> dict[str, object]:
    if bridge_summary.get("all_source_owner_pairs_conserved") is not True:
        raise ValueError("delta bridge is not lossless")
    results = [
        _dirty_merge_case(
            repository,
            _bridge_edge(bridge_rows, FORM_CANDIDATE_SHA, DIRTY_FIX_SHA),
            observed_ai,
        ),
        _password_order_case(
            repository,
            _bridge_edge(bridge_rows, FORM_CANDIDATE_SHA, PASSWORD_FIX_SHA),
            observed_ai,
        ),
        _binding_contract_case(
            repository,
            _bridge_edge(bridge_rows, FORM_CANDIDATE_SHA, BINDING_FIX_SHA),
            observed_ai,
        ),
        _onboarding_redirect_case(
            repository,
            _bridge_edge(
                bridge_rows, ONBOARDING_CANDIDATE_SHA, ONBOARDING_FIX_SHA
            ),
            observed_ai,
        ),
    ]
    confirmed_replacements = [
        result["replacement"]
        for result in results
        if isinstance(result.get("replacement"), Mapping)
        and str(result["replacement"].get("adjudication") or "").startswith(
            "CONFIRMED_"
        )
    ]
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_conductor_form_onboarding_attribution_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "promoted_edge_results": results,
        "confirmed_replacement_edges": confirmed_replacements,
        "summary": {
            "audited_promoted_edge_count": len(results),
            "confirmed_promoted_edge_count": 0,
            "rejected_promoted_edge_count": len(results),
            "confirmed_replacement_edge_count": len(confirmed_replacements),
            "unique_confirmed_replacement_candidate_count": len(
                {
                    str(row.get("candidate_sha") or "")
                    for row in confirmed_replacements
                }
            ),
            "unobserved_ai_actual_origin_count": sum(
                isinstance(result.get("replacement"), Mapping)
                and result["replacement"].get("observed_ai") is False
                for result in results
            ),
            "model_call_count": 0,
            "ledger_mutation_count": 0,
        },
        "witness_passed": bool(results)
        and all(result["witness_passed"] is True for result in results),
        "claim_boundary": (
            "Exact reversal and strict ancestry retain an edge for review but do not "
            "establish causal ownership. A promoted edge is rejected when the repaired "
            "state predates its candidate or an intervening commit introduces the "
            "mechanism. Replacement positives require observed-AI membership, strict "
            "ancestry, a mechanism-specific preimage transition, survival to the fix "
            "parent, and a corrective fix delta. No model output or ledger label is "
            "used as causal evidence."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
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
        failed = {
            str(row["key"]): sorted(
                str(check)
                for check, passed in dict(row["checks"]).items()
                if passed is not True
            )
            for row in payload["promoted_edge_results"]
            if row["witness_passed"] is not True
        }
        raise SystemExit(f"attribution witness failed: {failed}")
    output = args.output.resolve()
    _atomic_json(output, payload)
    print("Coolify Conductor form/onboarding attribution witness frozen")
    print(
        "  rejected promoted : "
        f"{payload['summary']['rejected_promoted_edge_count']}"
    )
    print(
        "  replacement TP    : "
        f"{payload['summary']['confirmed_replacement_edge_count']}"
    )
    print(f"  output            : {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
