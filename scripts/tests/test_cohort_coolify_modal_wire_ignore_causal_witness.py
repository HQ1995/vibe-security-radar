"""Tests for the Coolify modal wire:ignore causal witness."""

from __future__ import annotations

import cohort_coolify_modal_wire_ignore_causal_witness as witness


def _modal(*, isolated: bool) -> str:
    root = witness.ISOLATED_MODAL_ROOT if isolated else witness.UNISOLATED_MODAL_ROOT
    return f"""<div x-data="{{ modalOpen: false }}"
    x-init="$watch('modalOpen', value => {{ $wire.dispatch('modalClosed') }})"
    {root}
    <template x-teleport="body">
        <div x-show="modalOpen">
            <div x-trap.inert.noscroll="modalOpen">{{{{ $slot }}}}</div>
        </div>
    </template>
</div>
"""


def _stack(*, keyed: bool) -> str:
    child = witness.KEYED_EDIT_COMPOSE if keyed else witness.UNKEYED_EDIT_COMPOSE
    return f"""<x-modal-input buttonTitle="Edit Compose File">
    {child}
</x-modal-input>
"""


def test_contract_accepts_surviving_selective_revert() -> None:
    parent_modal = _modal(isolated=True)
    parent_stack = _stack(keyed=False)
    candidate_modal = _modal(isolated=False)
    candidate_stack = _stack(keyed=True)

    result = witness._evaluate_contract_versions(
        parent_modal,
        parent_stack,
        candidate_modal,
        candidate_stack,
        candidate_modal,
        candidate_stack,
        parent_modal,
        candidate_stack,
    )

    assert all(result["checks"].values())


def test_contract_rejects_candidate_that_keeps_modal_isolation() -> None:
    parent_modal = _modal(isolated=True)
    parent_stack = _stack(keyed=False)
    candidate_stack = _stack(keyed=True)
    result = witness._evaluate_contract_versions(
        parent_modal,
        parent_stack,
        parent_modal,
        candidate_stack,
        parent_modal,
        candidate_stack,
        parent_modal,
        candidate_stack,
    )

    assert (
        result["checks"]["candidate_removes_only_modal_root_isolation_state"] is False
    )


def test_contract_rejects_fix_that_also_removes_candidate_key() -> None:
    parent_modal = _modal(isolated=True)
    parent_stack = _stack(keyed=False)
    candidate_modal = _modal(isolated=False)
    candidate_stack = _stack(keyed=True)
    result = witness._evaluate_contract_versions(
        parent_modal,
        parent_stack,
        candidate_modal,
        candidate_stack,
        candidate_modal,
        candidate_stack,
        parent_modal,
        parent_stack,
    )

    assert result["checks"]["fix_preserves_candidate_keyed_child_byte_exact"] is False


def _delta(
    *,
    before_blob: str,
    after_blob: str,
    added: list[str] | None = None,
    removed: list[str] | None = None,
    empty: bool = False,
) -> dict[str, object]:
    return {
        "before_blob_oid": before_blob,
        "after_blob_oid": after_blob,
        "added_lines": added or [],
        "removed_lines": removed or [],
        "empty": empty,
    }


def _valid_deltas() -> tuple[dict[str, object], ...]:
    parent_modal_blob = "1" * 40
    candidate_modal_blob = "2" * 40
    parent_stack_blob = "3" * 40
    candidate_stack_blob = "4" * 40
    return (
        _delta(
            before_blob=parent_modal_blob,
            after_blob=candidate_modal_blob,
            added=[witness.UNISOLATED_MODAL_ROOT],
            removed=[witness.ISOLATED_MODAL_ROOT],
        ),
        _delta(
            before_blob=parent_stack_blob,
            after_blob=candidate_stack_blob,
            added=[witness.KEYED_EDIT_COMPOSE],
            removed=[witness.UNKEYED_EDIT_COMPOSE],
        ),
        _delta(
            before_blob=candidate_modal_blob,
            after_blob=parent_modal_blob,
            added=[witness.ISOLATED_MODAL_ROOT],
            removed=[witness.UNISOLATED_MODAL_ROOT],
        ),
        _delta(
            before_blob=candidate_stack_blob,
            after_blob=candidate_stack_blob,
            empty=True,
        ),
    )


def test_exact_deltas_accept_only_selective_reversal() -> None:
    checks = witness._evaluate_exact_deltas(
        *_valid_deltas(),
        [witness.MODAL_PATH, witness.STACK_PATH],
        [witness.MODAL_PATH],
    )

    assert all(checks.values())


def test_exact_deltas_reject_extra_fix_line_and_path() -> None:
    candidate_modal, candidate_stack, fix_modal, fix_stack = _valid_deltas()
    fix_modal["added_lines"] = [
        witness.ISOLATED_MODAL_ROOT,
        "unrelated refactor",
    ]
    checks = witness._evaluate_exact_deltas(
        candidate_modal,
        candidate_stack,
        fix_modal,
        fix_stack,
        [witness.MODAL_PATH, witness.STACK_PATH],
        [witness.MODAL_PATH, witness.STACK_PATH],
    )

    assert checks["fix_modal_delta_exactly_reverses_isolation_removal"] is False
    assert checks["fix_changes_only_modal_path"] is False
