"""Fail-closed publication admission for causal-adjudication rows."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from copy import deepcopy


GATE_FIELDS = (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
)
GATE_VALUES = frozenset({"PASS", "FAIL", "NARROW", "UNKNOWN", "BLOCKED", "NA"})
VERDICTS = frozenset({"CONFIRM", "NARROW", "FALSE_POSITIVE", "UNKNOWN", "BLOCKED"})
CONFIDENCE = frozenset({"HIGH", "MEDIUM", "LOW"})
RELEASED_SOURCE_TIERS = frozenset({"STRICT_RELEASED", "INCOMPLETE_RELEASED"})


def _closed_gate(value: object) -> bool:
    return value == "PASS" or value == "NA"


def _public_ids(value: object, field: str, errors: list[str]) -> set[str]:
    if not isinstance(value, list) or any(
        not isinstance(public_id, str) or not public_id.strip() for public_id in value
    ):
        errors.append(f"{field} must be a list of non-empty strings")
        return set()
    if len(value) != len(set(value)):
        errors.append(f"{field} must not contain duplicates")
    return set(value)


def evaluate_publication_admission(
    row: Mapping[str, object],
    *,
    source_public_ids: Collection[str] | None = None,
    source_tier: str | None = None,
) -> dict[str, object]:
    """Retain one candidate and decide whether its adjudication may be published."""

    candidate = deepcopy(dict(row))
    errors: list[str] = []
    verdict = candidate.get("verdict")
    confidence = candidate.get("confidence")
    publication_tier = (
        source_tier if source_tier is not None else candidate.get("source_tier")
    )
    if not isinstance(verdict, str) or verdict not in VERDICTS:
        errors.append("verdict is invalid")
    if not isinstance(confidence, str) or confidence not in CONFIDENCE:
        errors.append("confidence is invalid")

    gates = {field: candidate.get(field) for field in GATE_FIELDS}
    for field, value in gates.items():
        if not isinstance(value, str) or value not in GATE_VALUES:
            errors.append(f"{field} is invalid")

    kept = _public_ids(candidate.get("public_ids_keep"), "public_ids_keep", errors)
    removed = _public_ids(
        candidate.get("public_ids_remove"), "public_ids_remove", errors
    )
    if kept & removed:
        errors.append("public_ids_keep and public_ids_remove must be disjoint")

    public_ids_conserved: bool | None = None
    if source_public_ids is not None:
        if isinstance(source_public_ids, (str, bytes)) or any(
            not isinstance(public_id, str) or not public_id.strip()
            for public_id in source_public_ids
        ):
            errors.append("source_public_ids must contain non-empty strings")
            public_ids_conserved = False
        else:
            public_ids_conserved = kept | removed == set(source_public_ids)
            if not public_ids_conserved:
                errors.append(
                    "kept and removed public IDs do not conserve the source set"
                )

    duplicate_of = candidate.get("duplicate_of")
    has_duplicate = isinstance(duplicate_of, str) and bool(duplicate_of.strip())
    if duplicate_of is not None and not has_duplicate:
        errors.append("duplicate_of must be null or a non-empty row key")
    uniqueness_failed = gates["uniqueness_gate"] == "FAIL"
    if has_duplicate != uniqueness_failed:
        errors.append("duplicate_of requires, and is required by, uniqueness_gate FAIL")
    if has_duplicate and duplicate_of == candidate.get("row_key"):
        errors.append("duplicate_of cannot reference the same row")
    if has_duplicate and verdict != "FALSE_POSITIVE":
        errors.append("a duplicate row must have verdict FALSE_POSITIVE")

    if verdict == "CONFIRM" and not all(map(_closed_gate, gates.values())):
        errors.append("CONFIRM requires all seven gates to be PASS or NA")
    elif verdict == "NARROW":
        if "NARROW" not in gates.values():
            errors.append("NARROW requires at least one explicitly NARROW gate")
        if any(value in {"FAIL", "BLOCKED"} for value in gates.values()):
            errors.append("NARROW cannot contain a FAIL or BLOCKED gate")
    elif verdict == "FALSE_POSITIVE":
        false_positive_class = candidate.get("false_positive_class")
        if (
            not isinstance(false_positive_class, str)
            or not false_positive_class.strip()
        ):
            errors.append("FALSE_POSITIVE requires false_positive_class")
        if "FAIL" not in gates.values():
            errors.append("FALSE_POSITIVE requires a fatal FAIL gate")
    elif (verdict == "UNKNOWN" or verdict == "BLOCKED") and all(
        map(_closed_gate, gates.values())
    ):
        errors.append(f"{verdict} requires an unresolved or failed gate")

    causal_valid = not errors and verdict in {"CONFIRM", "NARROW"}
    strict_confirmed = (
        causal_valid
        and verdict == "CONFIRM"
        and confidence == "HIGH"
        and all(map(_closed_gate, gates.values()))
    )
    released_publication_admitted = (
        strict_confirmed
        and isinstance(publication_tier, str)
        and publication_tier in RELEASED_SOURCE_TIERS
        and gates["release_gate"] == "PASS"
    )
    if errors:
        admission, reason = "HOLD", "invalid_adjudication"
    elif released_publication_admitted:
        admission, reason = "ADMIT", "strict_confirm_high_all_gates_closed"
    elif verdict == "FALSE_POSITIVE":
        admission, reason = "EXCLUDE", "false_positive"
    elif verdict == "NARROW":
        admission, reason = "HOLD", "narrowed_causal_scope_requires_review"
    elif verdict in {"UNKNOWN", "BLOCKED"}:
        admission, reason = "HOLD", f"unresolved_{str(verdict).lower()}"
    elif strict_confirmed and publication_tier is None:
        admission, reason = "HOLD", "released_source_tier_required"
    elif strict_confirmed and (
        not isinstance(publication_tier, str)
        or publication_tier not in RELEASED_SOURCE_TIERS
    ):
        admission, reason = "HOLD", "commit_only_not_released"
    elif strict_confirmed:
        admission, reason = "HOLD", "release_gate_must_pass"
    else:
        admission, reason = "HOLD", "confirm_requires_high_confidence"

    return {
        "schema_version": 1,
        "admission": admission,
        "reason": reason,
        "may_publish": released_publication_admitted,
        "released_publication_admitted": released_publication_admitted,
        "released_publication_reason": reason,
        "strict_confirmed": strict_confirmed,
        "causal_valid": causal_valid,
        "public_ids_conserved": public_ids_conserved,
        "errors": errors,
        "gates": gates,
        "recall_candidate": candidate,
    }
