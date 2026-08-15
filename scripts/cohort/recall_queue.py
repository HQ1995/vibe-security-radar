"""Recall-preserving priority overlays for prospective origin analysis."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


class RecallQueueContractError(ValueError):
    """A priority input would lose or ambiguously rank a candidate."""


ROOT_PRIORITY = "R0_MODEL_OR_EXPLICIT_CONTROL"
ROOT_CORROBORATED = "R1_CORROBORATED_SOURCE"
ROOT_CARRIER = "R2_OTHER_SOURCE_CARRIER"

COMMIT_PRIORITIES = (
    "P0_AI_PRIORITY_ROOT_ANCESTOR",
    "P1_UNLABELED_PRIORITY_ROOT_ANCESTOR",
    "P2_AI_ANY_ROOT_ANCESTOR",
    "P3_UNLABELED_ANY_ROOT_ANCESTOR",
    "P4_AI_REPOSITORY_FALLBACK",
    "P5_UNLABELED_REPOSITORY_FALLBACK",
)


def build_root_priorities(
    roots: Sequence[Mapping[str, object]],
    priority_reasons_by_root: Mapping[tuple[str, str], Sequence[str]],
) -> list[dict[str, object]]:
    """Assign every source root exactly one non-deleting queue class."""

    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    root_keys: set[tuple[str, str]] = set()
    for raw in roots:
        root_id = str(raw.get("root_id") or "")
        repository = str(raw.get("repository_identity") or "")
        sha = str(raw.get("root_sha") or "").lower()
        evidence = raw.get("evidence_kinds")
        if (
            not root_id
            or root_id in seen
            or len(sha) != 40
            or not isinstance(evidence, list)
        ):
            raise RecallQueueContractError("source root rows are malformed")
        seen.add(root_id)
        root_key = (repository, sha)
        root_keys.add(root_key)
        reasons = sorted(
            set(str(value) for value in priority_reasons_by_root.get(root_key, []))
        )
        kinds = sorted(set(str(value) for value in evidence))
        if reasons:
            priority = ROOT_PRIORITY
        elif {"repository_reference_carrier", "enriched_selected"} & set(kinds):
            priority = ROOT_CORROBORATED
        else:
            priority = ROOT_CARRIER
        rows.append(
            {
                "root_id": root_id,
                "repository_identity": repository,
                "root_sha": sha,
                "bit_index": raw.get("bit_index"),
                "root_coverage_status": str(raw.get("status") or ""),
                "evidence_kinds": kinds,
                "priority_class": priority,
                "priority_reasons": reasons,
                "retained": True,
            }
        )
    unknown = set(priority_reasons_by_root) - root_keys
    if unknown:
        raise RecallQueueContractError("priority decisions reference unknown roots")
    rows.sort(key=lambda row: (str(row["repository_identity"]), str(row["root_sha"])))
    return rows


def commit_priority(
    *,
    observed_ai_unit: bool,
    root_mask: int,
    priority_root_mask: int,
) -> str:
    """Rank one commit while retaining every possible mask/fallback state."""

    if root_mask < 0 or priority_root_mask < 0:
        raise RecallQueueContractError("root masks cannot be negative")
    if observed_ai_unit:
        if root_mask & priority_root_mask:
            return COMMIT_PRIORITIES[0]
        if root_mask:
            return COMMIT_PRIORITIES[2]
        return COMMIT_PRIORITIES[4]
    if root_mask & priority_root_mask:
        return COMMIT_PRIORITIES[1]
    if root_mask:
        return COMMIT_PRIORITIES[3]
    return COMMIT_PRIORITIES[5]
