"""Proof-carrying inventory of every pre-fix ancestor candidate.

Exact Git reachability defines membership. AI attribution, SZZ, and the other
origin signals only annotate and rank retained candidates.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from cohort.origin_signals import (
    AI_ANCESTRY_FALLBACK_SIGNAL,
    ATTRIBUTION_UNKNOWN_FAIL_OPEN_SIGNAL,
    prioritize_candidate_rows,
)
from cohort.root_adjudication import canonical_sha256


_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class OriginReductionContractError(ValueError):
    """A reduction input cannot support a recall-preserving partition."""


def _sha(value: object, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _FULL_SHA_RE.fullmatch(normalized):
        raise OriginReductionContractError(f"{label} must be a full Git SHA")
    return normalized


def _sha_set(values: Iterable[object], label: str) -> set[str]:
    return {_sha(value, label) for value in values}


def _row_index(
    rows: Iterable[Mapping[str, object]],
    *,
    label: str,
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for raw in rows:
        row = dict(raw)
        sha = _sha(row.get("sha"), f"{label} sha")
        if sha in result and result[sha] != row:
            raise OriginReductionContractError(f"conflicting {label} row: {sha}")
        result[sha] = row
    return result


def reduce_origin_candidates(
    ancestor_shas: Iterable[object],
    observed_ai_rows: Iterable[Mapping[str, object]],
    structural_rows: Iterable[Mapping[str, object]],
    *,
    observation_complete: bool,
) -> dict[str, object]:
    """Retain every pre-fix ancestor and use AI observations only for ranking.

    ``observation_complete`` describes whether the metadata scan finished; it
    cannot establish that every AI-assisted commit left observable metadata.
    Therefore it never grants deletion authority.
    """

    ancestors = _sha_set(ancestor_shas, "ancestor")
    if not ancestors:
        raise OriginReductionContractError("pre-fix ancestry cannot be empty")
    observed = _row_index(observed_ai_rows, label="observed AI")
    structural = _row_index(structural_rows, label="structural")
    outside_ancestry = set(structural) - ancestors
    if outside_ancestry:
        raise OriginReductionContractError(
            "structural signal escaped pre-fix ancestry: "
            f"{sorted(outside_ancestry)[:3]}"
        )

    observed_ancestor_shas = set(observed) & ancestors
    certified_non_ancestor_shas = set(observed) - ancestors
    unobserved_ancestor_shas = ancestors - set(observed)
    retained_shas = set(ancestors)

    raw_candidates: list[dict[str, object]] = []
    for candidate_sha in sorted(retained_shas):
        structural_row = structural.get(candidate_sha)
        raw_signals = structural_row.get("signals") if structural_row else None
        if raw_signals is not None and (
            not isinstance(raw_signals, list)
            or not raw_signals
            or any(not isinstance(signal, str) for signal in raw_signals)
        ):
            raise OriginReductionContractError(
                f"structural signals are malformed: {candidate_sha}"
            )
        observed_ai_unit = candidate_sha in observed
        if raw_signals:
            signals = sorted(set(raw_signals))
            materialization = "structural_signal"
        elif observed_ai_unit:
            signals = [AI_ANCESTRY_FALLBACK_SIGNAL]
            materialization = "exact_ai_ancestry_fallback"
        else:
            signals = [ATTRIBUTION_UNKNOWN_FAIL_OPEN_SIGNAL]
            materialization = "attribution_unobserved_fail_open"
        row: dict[str, object] = {
            "sha": candidate_sha,
            "signals": signals,
            "observed_ai_unit": observed_ai_unit,
            "retained": True,
            "materialization": materialization,
            "ancestry_certificate": "reachable_from_pre_fix_parent",
        }
        if structural_row is not None:
            row["structural_priority_rank"] = structural_row.get("priority_rank")
        observation = observed.get(candidate_sha)
        if observation is not None:
            for field in (
                "agent_kinds",
                "authored_date",
                "merge_topology",
                "pr_number",
                "signal_types",
                "source_modules",
                "squash_attribution_only",
                "tools",
            ):
                if field in observation:
                    row[field] = observation[field]
        raw_candidates.append(row)

    candidates = prioritize_candidate_rows(raw_candidates)
    if {str(row["sha"]) for row in candidates} != retained_shas:
        raise OriginReductionContractError("candidate ranking changed inventory")
    if set(observed) != observed_ancestor_shas | certified_non_ancestor_shas:
        raise OriginReductionContractError("observed AI conservation failed")
    if ancestors != observed_ancestor_shas | unobserved_ancestor_shas:
        raise OriginReductionContractError("ancestor scope conservation failed")
    if retained_shas != ancestors:
        raise OriginReductionContractError("pre-fix ancestry inventory was reduced")

    return {
        "status": "RESOLVED" if observation_complete else "BLOCKED",
        "candidates": candidates,
        "certified_non_ancestor_shas": sorted(certified_non_ancestor_shas),
        "ancestor_count": len(ancestors),
        "ancestor_shas_sha256": canonical_sha256(sorted(ancestors)),
        "observed_ai_count": len(observed),
        "observed_ai_ancestor_count": len(observed_ancestor_shas),
        "certified_non_ancestor_count": len(certified_non_ancestor_shas),
        "unobserved_ancestor_count": len(unobserved_ancestor_shas),
        "unobserved_ancestor_shas_sha256": canonical_sha256(
            sorted(unobserved_ancestor_shas)
        ),
        "retained_candidate_count": len(candidates),
        "fail_open_candidate_count": sum(
            row["materialization"] == "attribution_unobserved_fail_open"
            for row in candidates
        ),
        "all_retained": all(row.get("retained") is True for row in candidates),
        "candidate_shas_sha256": canonical_sha256(
            sorted(str(row["sha"]) for row in candidates)
        ),
    }
