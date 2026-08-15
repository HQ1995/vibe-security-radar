"""Tests for the Coolify buildtime.env duplicate reattribution witness."""

from __future__ import annotations

import cohort_coolify_buildtime_env_duplicate_reattribution_witness as witness


def _state(*, plan: bool, filtered: bool, dictionary: bool) -> str:
    if dictionary:
        return "\n".join(
            (
                witness.DICT_INIT,
                witness.PLAN_LOOKUP,
                witness.PLAN_LOOP,
                witness.PLAN_DICT_ASSIGNMENT,
                witness.USER_DICT_ASSIGNMENT,
                witness.USER_DICT_ASSIGNMENT,
                witness.DICT_COLLECTION_LOOP,
            )
        )
    lines = [witness.SEQUENTIAL_INIT]
    if plan:
        lines.extend((witness.PLAN_LOOKUP, witness.PLAN_LOOP, witness.PLAN_PUSH))
    if filtered:
        lines.extend((witness.NIXPACKS_FILTER, witness.NIXPACKS_FILTER))
    lines.extend((witness.USER_PUSH, witness.USER_PUSH))
    return "\n".join(lines)


def test_states_reattribute_first_duplicate_mechanism_to_intervening_origin() -> None:
    safe = _state(plan=False, filtered=True, dictionary=False)
    broken = _state(plan=True, filtered=False, dictionary=False)
    fixed = _state(plan=True, filtered=False, dictionary=True)

    result = witness._evaluate_states(safe, safe, safe, broken, broken, fixed)

    assert all(result["checks"].values())


def test_states_reject_origin_that_keeps_nixpacks_user_filters() -> None:
    safe = _state(plan=False, filtered=True, dictionary=False)
    not_broken = _state(plan=True, filtered=True, dictionary=False)
    fixed = _state(plan=True, filtered=False, dictionary=True)

    result = witness._evaluate_states(safe, safe, safe, not_broken, not_broken, fixed)

    assert (
        result["checks"]["intervening_origin_activates_plan_user_duplicate_mechanism"]
        is False
    )


def test_states_reject_fix_that_keeps_sequential_pushes() -> None:
    safe = _state(plan=False, filtered=True, dictionary=False)
    broken = _state(plan=True, filtered=False, dictionary=False)

    result = witness._evaluate_states(safe, safe, safe, broken, broken, broken)

    assert (
        result["checks"][
            "fix_replaces_duplicate_sequence_with_unique_key_override_contract"
        ]
        is False
    )


def _patch(added: list[str], removed: list[str]) -> str:
    return "\n".join(
        ["--- a/file", "+++ b/file"]
        + [f"-{line}" for line in removed]
        + [f"+{line}" for line in added]
    )


def test_transitions_require_exact_overlap_but_assign_mechanism_to_origin() -> None:
    candidate = _patch(list(witness.EXPECTED_OVERLAP_LINES), ["old values"])
    origin = _patch(
        [witness.PLAN_LOOKUP, witness.PLAN_LOOP, witness.PLAN_PUSH],
        [witness.NIXPACKS_FILTER, witness.NIXPACKS_FILTER],
    )
    fixed = _patch(
        [witness.PLAN_DICT_ASSIGNMENT, witness.USER_DICT_ASSIGNMENT],
        list(witness.EXPECTED_OVERLAP_LINES) + [witness.PLAN_PUSH, witness.USER_PUSH],
    )

    result = witness._evaluate_transitions(candidate, origin, fixed)

    assert all(result["checks"].values())


def test_transitions_reject_candidate_as_origin_when_plan_source_is_in_its_delta() -> (
    None
):
    candidate = _patch(
        list(witness.EXPECTED_OVERLAP_LINES) + [witness.PLAN_LOOKUP],
        ["old values"],
    )
    origin = _patch(
        [witness.PLAN_LOOKUP, witness.PLAN_LOOP, witness.PLAN_PUSH],
        [witness.NIXPACKS_FILTER, witness.NIXPACKS_FILTER],
    )
    fixed = _patch(
        [witness.PLAN_DICT_ASSIGNMENT, witness.USER_DICT_ASSIGNMENT],
        list(witness.EXPECTED_OVERLAP_LINES) + [witness.PLAN_PUSH, witness.USER_PUSH],
    )

    result = witness._evaluate_transitions(candidate, origin, fixed)

    assert (
        result["checks"]["promoted_candidate_delta_does_not_add_plan_source"] is False
    )


def test_ai_membership_keeps_non_observed_origin_out_of_ai_tp() -> None:
    checks = witness._evaluate_ai_membership(
        {witness.PROMOTED_CANDIDATE_SHA, witness.FIX_SHA}
    )

    assert all(checks.values())
