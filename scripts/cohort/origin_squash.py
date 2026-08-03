"""Recall-safe expansion of landed squash candidates to real PR members."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence

from cohort.origin_signals import (
    SQUASH_INTERNAL_BLAME_SIGNAL,
    SQUASH_PR_MEMBER_SIGNAL,
    prioritize_candidate_rows,
)
from cohort.relations import COMPOSITE_RELATION, PULL_MEMBER_RELATION


DIRECT_RELATION = "reachable_ancestor"
PULL_MEMBER_TO_FIX_CERTIFICATE = COMPOSITE_RELATION
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_PRIORITY_FIELDS = (
    "primary_lane",
    "priority_class",
    "priority_rank",
    "within_priority_class_rank",
)
_ORIGIN_METADATA_FIELDS = (
    "additions",
    "agent_kinds",
    "authored_date",
    "changed_files",
    "code_files_changed",
    "commit_subject",
    "deletions",
    "empty_commit",
    "signal_types",
    "source_modules",
    "tools",
)
_LANDED_ONLY_FIELDS = (
    "pr_number",
    "squash_attribution_only",
)


class OriginSquashContractError(ValueError):
    """Squash relations cannot be expanded without losing provenance."""


def _sha(value: object, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _FULL_SHA_RE.fullmatch(normalized):
        raise OriginSquashContractError(f"{label} must be a full Git SHA")
    return normalized


def _identity(value: object) -> str:
    normalized = str(value or "").strip().lower()
    if not normalized or "/" not in normalized:
        raise OriginSquashContractError("repository identity is malformed")
    return normalized


def _pair_key(row: Mapping[str, object]) -> tuple[str, str, str, str]:
    advisory = str(row.get("advisory") or "").strip()
    if not advisory:
        raise OriginSquashContractError("candidate advisory is missing")
    return (
        advisory,
        _identity(row.get("repository_identity")),
        _sha(row.get("fix_sha"), "fix sha"),
        _sha(row.get("sha"), "candidate sha"),
    )


def _canonical_evidence(
    rows: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    unique: dict[str, dict[str, object]] = {}
    for raw in rows:
        row = dict(raw)
        encoded = json.dumps(
            row,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        unique[encoded] = row
    return [unique[key] for key in sorted(unique)]


def _direct_evidence(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "relation": DIRECT_RELATION,
        "relation_path": [DIRECT_RELATION],
        "candidate_sha": _sha(row.get("sha"), "candidate sha"),
    }


def _normalize_direct(row: Mapping[str, object]) -> dict[str, object]:
    normalized = dict(row)
    _pair_key(normalized)
    if normalized.get("retained") is not True:
        raise OriginSquashContractError("parent candidate is not retained")
    signals = normalized.get("signals")
    if (
        not isinstance(signals, list)
        or not signals
        or any(not isinstance(signal, str) for signal in signals)
    ):
        raise OriginSquashContractError("parent candidate signals are malformed")
    normalized["signals"] = sorted(set(signals))
    normalized["parent_priority_rank"] = int(normalized.get("priority_rank") or 0)
    existing_evidence = normalized.get("relation_evidence")
    if existing_evidence is None:
        normalized["relation_evidence"] = [_direct_evidence(normalized)]
    elif not isinstance(existing_evidence, list) or any(
        not isinstance(evidence, Mapping) for evidence in existing_evidence
    ):
        raise OriginSquashContractError("parent relation evidence is malformed")
    else:
        normalized["relation_evidence"] = _canonical_evidence(existing_evidence)
    if normalized.get("observed_ai_unit") is True:
        normalized["ai_exposure_supported"] = True
        normalized.setdefault("ai_exposure_basis", "direct_commit_signal")
    return normalized


def _relation_evidence(relation: Mapping[str, object]) -> dict[str, object]:
    if relation.get("relation") != PULL_MEMBER_RELATION:
        raise OriginSquashContractError(
            f"unsupported squash relation: {relation.get('relation')}"
        )
    pr_number = relation.get("pr_number")
    if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
        raise OriginSquashContractError("squash relation PR number is malformed")
    relation_id = str(relation.get("relation_id") or "")
    if not relation_id:
        raise OriginSquashContractError("squash relation ID is missing")
    return {
        "relation": COMPOSITE_RELATION,
        "relation_path": [PULL_MEMBER_RELATION, DIRECT_RELATION],
        "origin_relation_id": relation_id,
        "landed_sha": _sha(relation.get("landed_sha"), "landed sha"),
        "relation_pr_number": pr_number,
        "origin_observed_in_cohort": (
            relation.get("origin_observed_in_cohort") is True
        ),
    }


def _composed_relation_evidence(
    landed: Mapping[str, object], relation: Mapping[str, object]
) -> list[dict[str, object]]:
    """Prepend one recovered PR-member edge to every downstream proof path.

    The first squash expansion historically emitted a two-hop proof path:
    PR member -> landed squash -> reachable fix ancestor.  A recovered member
    can itself be a landed squash, so later expansions must retain the whole
    chain instead of replacing the outer proof with the newest edge.
    """

    base = _relation_evidence(relation)
    downstream = landed.get("relation_evidence")
    if downstream is None:
        return [base]
    if not isinstance(downstream, list) or any(
        not isinstance(row, Mapping) for row in downstream
    ):
        raise OriginSquashContractError("landed relation evidence is malformed")

    composed: list[dict[str, object]] = []
    for raw in downstream:
        row = dict(raw)
        raw_path = row.get("relation_path")
        if not isinstance(raw_path, list) or any(
            not isinstance(step, str) for step in raw_path
        ):
            raise OriginSquashContractError("landed relation path is malformed")
        # The original direct candidate proof is already represented by the
        # one-level composite shape.  Preserve that wire format for existing
        # consumers and tests.
        if raw_path == [DIRECT_RELATION]:
            composed.append(base)
            continue
        nested = dict(base)
        nested["relation_path"] = [PULL_MEMBER_RELATION, *raw_path]
        nested["downstream_relation_evidence"] = row
        nested["squash_depth"] = sum(
            step == PULL_MEMBER_RELATION for step in nested["relation_path"]
        )
        composed.append(nested)
    return _canonical_evidence(composed)


def _member_candidate(
    landed: Mapping[str, object],
    relation: Mapping[str, object],
    member_metadata: Mapping[str, object],
    fix_changed_files: Sequence[str],
    internal_blame_evidence: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    candidate = dict(landed)
    origin_sha = _sha(relation.get("origin_sha"), "origin sha")
    landed_sha = _sha(relation.get("landed_sha"), "landed sha")
    if _sha(landed.get("sha"), "landed candidate sha") != landed_sha:
        raise OriginSquashContractError("relation landed SHA does not match candidate")

    for field in (*_PRIORITY_FIELDS, *_ORIGIN_METADATA_FIELDS, *_LANDED_ONLY_FIELDS):
        candidate.pop(field, None)
    member_ai_observed = member_metadata.get("observed_ai_unit") is True
    carrier_ai_observed = landed.get("observed_ai_unit") is True
    member_files = {str(path) for path in member_metadata.get("changed_files", [])}
    member_code_files = {
        str(path) for path in member_metadata.get("code_files_changed", [])
    }
    fix_files = {str(path) for path in fix_changed_files}
    file_overlap = sorted(member_files & fix_files)
    code_file_overlap = sorted(member_code_files & fix_files)
    canonical_internal_blame = _canonical_evidence(internal_blame_evidence)
    member_signals = [SQUASH_PR_MEMBER_SIGNAL]
    if canonical_internal_blame:
        member_signals.append(SQUASH_INTERNAL_BLAME_SIGNAL)
    relation_evidence = _composed_relation_evidence(landed, relation)
    relation_depth = max(
        sum(step == PULL_MEMBER_RELATION for step in evidence["relation_path"])
        for evidence in relation_evidence
    )
    squash_group_ids = sorted(
        {
            landed_sha,
            *(str(value) for value in landed.get("squash_group_ids", [])),
        }
    )
    candidate.update(
        {
            "sha": origin_sha,
            # Landed-squash signals are carrier-level evidence. Copying them
            # into the member's ranking lanes would let one large PR occupy
            # add-check, pickaxe, and SZZ lanes simultaneously. Keep them for
            # the model, but rank the member only on the explicit relation.
            "signals": sorted(member_signals),
            "landed_signals": sorted(
                {str(signal) for signal in landed.get("signals", [])}
            ),
            "squash_group_ids": squash_group_ids,
            "fix_file_overlap": file_overlap,
            "fix_file_overlap_count": len(file_overlap),
            "fix_code_file_overlap_count": len(code_file_overlap),
            # Cohort membership and AI attribution are different facts. In an
            # all-commit inventory an atomic member may already be present
            # without carrying any AI signal, so relation membership must not
            # silently promote it to AI-authored.
            "observed_ai_unit": member_ai_observed,
            "ai_exposure_supported": member_ai_observed or carrier_ai_observed,
            "ai_exposure_basis": (
                "member_commit_signal"
                if member_ai_observed
                else (
                    "ai_attributed_landed_squash"
                    if carrier_ai_observed
                    else "no_observed_ai_attribution"
                )
            ),
            "carrier_ai_attribution": carrier_ai_observed,
            "origin_observed_in_cohort": (
                relation.get("origin_observed_in_cohort") is True
            ),
            "merge_topology": "pull_request_member",
            "materialization": "squash_pr_member_relation",
            "parent_materialization": str(landed.get("materialization") or ""),
            "parent_priority_rank": int(landed.get("priority_rank") or 0),
            "signal_inheritance": "landed_squash_candidate_edge",
            "ancestry_certificate": (
                PULL_MEMBER_TO_FIX_CERTIFICATE
                if relation_depth == 1
                else "recursive_pull_request_member_landed_as_squash_then_"
                "reachable_ancestor"
            ),
            "squash_relation_depth": relation_depth,
            "relation_evidence": relation_evidence,
            "retained": True,
        }
    )
    if canonical_internal_blame:
        candidate["squash_internal_blame_evidence"] = canonical_internal_blame
        candidate["squash_internal_blame_line_count"] = len(canonical_internal_blame)
        candidate["squash_internal_blame_paths"] = sorted(
            {str(row["path"]) for row in canonical_internal_blame}
        )
    for field in _ORIGIN_METADATA_FIELDS:
        if field in member_metadata:
            candidate[field] = member_metadata[field]
    return candidate


def _merge_pair(
    existing: dict[str, object], incoming: Mapping[str, object]
) -> dict[str, object]:
    """Merge multiple proof paths for one candidate/fix pair."""

    if _pair_key(existing) != _pair_key(incoming):
        raise OriginSquashContractError("cannot merge different candidate pairs")
    merged = dict(existing)
    existing_signals = merged.get("signals")
    incoming_signals = incoming.get("signals")
    if not isinstance(existing_signals, list) or not isinstance(incoming_signals, list):
        raise OriginSquashContractError("merged candidate signals are malformed")
    merged["signals"] = sorted(
        {str(value) for value in [*existing_signals, *incoming_signals]}
    )
    merged["landed_signals"] = sorted(
        {
            str(value)
            for value in (
                *(merged.get("landed_signals") or []),
                *(incoming.get("landed_signals") or []),
            )
        }
    )
    merged["squash_group_ids"] = sorted(
        {
            str(value)
            for value in (
                *(merged.get("squash_group_ids") or []),
                *(incoming.get("squash_group_ids") or []),
            )
        }
    )
    merged["fix_file_overlap"] = sorted(
        {
            str(value)
            for value in (
                *(merged.get("fix_file_overlap") or []),
                *(incoming.get("fix_file_overlap") or []),
            )
        }
    )
    merged["fix_file_overlap_count"] = len(merged["fix_file_overlap"])
    merged["fix_code_file_overlap_count"] = max(
        int(merged.get("fix_code_file_overlap_count") or 0),
        int(incoming.get("fix_code_file_overlap_count") or 0),
    )
    merged_internal = merged.get("squash_internal_blame_evidence") or []
    incoming_internal = incoming.get("squash_internal_blame_evidence") or []
    if not isinstance(merged_internal, list) or not isinstance(incoming_internal, list):
        raise OriginSquashContractError("merged internal blame evidence is malformed")
    if merged_internal or incoming_internal:
        if any(
            not isinstance(row, Mapping)
            for row in [*merged_internal, *incoming_internal]
        ):
            raise OriginSquashContractError(
                "merged internal blame evidence rows are malformed"
            )
        canonical_internal = _canonical_evidence([*merged_internal, *incoming_internal])
        merged["squash_internal_blame_evidence"] = canonical_internal
        merged["squash_internal_blame_line_count"] = len(canonical_internal)
        merged["squash_internal_blame_paths"] = sorted(
            {str(row["path"]) for row in canonical_internal}
        )
    existing_evidence = merged.get("relation_evidence")
    incoming_evidence = incoming.get("relation_evidence")
    if not isinstance(existing_evidence, list) or not isinstance(
        incoming_evidence, list
    ):
        raise OriginSquashContractError("merged relation evidence is malformed")
    merged["relation_evidence"] = _canonical_evidence(
        [*existing_evidence, *incoming_evidence]
    )
    merged["ai_exposure_supported"] = bool(
        merged.get("ai_exposure_supported") is True
        or incoming.get("ai_exposure_supported") is True
    )
    merged["origin_observed_in_cohort"] = bool(
        merged.get("origin_observed_in_cohort") is True
        or incoming.get("origin_observed_in_cohort") is True
    )
    if incoming.get("observed_ai_unit") is True:
        merged["observed_ai_unit"] = True
        for field in _ORIGIN_METADATA_FIELDS:
            if field in incoming:
                merged[field] = incoming[field]
        merged["ai_exposure_basis"] = "member_commit_signal"
    materializations = {
        str(value)
        for value in (
            merged.get("materialization"),
            incoming.get("materialization"),
            *(merged.get("materialization_paths") or []),
        )
        if value
    }
    merged["materialization_paths"] = sorted(materializations)
    if len(materializations) > 1:
        merged["materialization"] = "multiple_relation_paths"
    parent_ranks = {
        int(value)
        for value in (
            merged.get("parent_priority_rank"),
            incoming.get("parent_priority_rank"),
            *(merged.get("parent_priority_ranks") or []),
        )
        if isinstance(value, int)
    }
    if parent_ranks:
        merged["parent_priority_rank"] = min(parent_ranks)
        merged["parent_priority_ranks"] = sorted(parent_ranks)
    return merged


def expand_squash_candidate_pairs(
    candidate_rows: Sequence[Mapping[str, object]],
    relations: Sequence[Mapping[str, object]],
    member_metadata: Mapping[tuple[str, str], Mapping[str, object]],
    fix_changed_files: Mapping[tuple[str, str], Sequence[str]] | None = None,
    internal_blame_evidence: Mapping[
        tuple[str, str, str, str], Sequence[Mapping[str, object]]
    ]
    | None = None,
) -> dict[str, object]:
    """Retain every landed pair and add every recovered PR-member pair.

    ``member_metadata`` is deliberately independent of relation membership.
    Every member is retained even when no member-level AI signal was observed.
    """

    fix_files = fix_changed_files or {}
    internal_evidence = internal_blame_evidence or {}
    pairs: dict[tuple[str, str, str, str], dict[str, object]] = {}
    landed_rows: defaultdict[tuple[str, str], list[dict[str, object]]] = defaultdict(
        list
    )
    for raw in candidate_rows:
        row = _normalize_direct(raw)
        key = _pair_key(row)
        if key in pairs:
            raise OriginSquashContractError(f"duplicate parent candidate pair: {key}")
        pairs[key] = row
        landed_rows[(key[1], key[3])].append(row)

    direct_keys = set(pairs)
    attempted_member_pairs = 0
    for relation in relations:
        identity = _identity(relation.get("repository_identity"))
        landed_sha = _sha(relation.get("landed_sha"), "landed sha")
        origin_sha = _sha(relation.get("origin_sha"), "origin sha")
        targets = landed_rows.get((identity, landed_sha), [])
        if not targets:
            raise OriginSquashContractError(
                f"squash relation has no retained landed candidate: {identity}@{landed_sha}"
            )
        metadata = member_metadata.get((identity, origin_sha), {})
        for landed in targets:
            attempted_member_pairs += 1
            incoming = _member_candidate(
                landed,
                relation,
                metadata,
                fix_files.get(
                    (
                        identity,
                        _sha(landed.get("fix_sha"), "fix sha"),
                    ),
                    (),
                ),
                internal_evidence.get(
                    (
                        identity,
                        landed_sha,
                        _sha(landed.get("fix_sha"), "fix sha"),
                        origin_sha,
                    ),
                    (),
                ),
            )
            key = _pair_key(incoming)
            if key in pairs:
                pairs[key] = _merge_pair(pairs[key], incoming)
            else:
                pairs[key] = incoming

    grouped: defaultdict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(
        list
    )
    for key, row in pairs.items():
        grouped[key[:3]].append(row)

    ranked: list[dict[str, object]] = []
    for fix_key in sorted(grouped):
        group = grouped[fix_key]
        for row in group:
            for field in _PRIORITY_FIELDS:
                row.pop(field, None)
        ranked.extend(prioritize_candidate_rows(group))
    ranked.sort(
        key=lambda row: (
            str(row["advisory"]),
            str(row["repository_identity"]),
            str(row["fix_sha"]),
            int(row["priority_rank"]),
            str(row["sha"]),
        )
    )
    output_keys = {_pair_key(row) for row in ranked}
    if not direct_keys <= output_keys or len(output_keys) != len(ranked):
        raise OriginSquashContractError("expanded candidate conservation failed")
    return {
        "candidates": ranked,
        "direct_candidate_pair_count": len(direct_keys),
        "expanded_candidate_pair_count": len(ranked),
        "added_atomic_member_pair_count": len(output_keys - direct_keys),
        "attempted_atomic_member_pair_count": attempted_member_pairs,
        "collapsed_duplicate_member_pair_count": (
            attempted_member_pairs - len(output_keys - direct_keys)
        ),
        "all_parent_candidate_pairs_retained": direct_keys <= output_keys,
    }
