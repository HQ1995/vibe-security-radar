"""Lossless folding and packetization of retained origin candidates."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping


_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class OriginPacketContractError(ValueError):
    """Candidate work units cannot be folded without losing provenance."""


def _sha(value: object, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _FULL_SHA_RE.fullmatch(normalized):
        raise OriginPacketContractError(f"{label} must be a full Git SHA")
    return normalized


def _identifier(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest}"


def fold_candidate_fix_pairs(
    rows: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Fold repeated fix edges into one advisory/candidate work unit."""

    groups: defaultdict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(
        list
    )
    pair_keys: set[tuple[str, str, str, str]] = set()
    for raw in rows:
        row = dict(raw)
        advisory = str(row.get("advisory") or "").strip()
        identity = str(row.get("repository_identity") or "").strip().lower()
        candidate_sha = _sha(row.get("sha"), "candidate sha")
        fix_sha = _sha(row.get("fix_sha"), "fix sha")
        if not advisory or not identity or row.get("retained") is not True:
            raise OriginPacketContractError(
                "candidate pair is incomplete or not retained"
            )
        pair_key = (advisory, identity, fix_sha, candidate_sha)
        if pair_key in pair_keys:
            raise OriginPacketContractError(f"duplicate candidate pair: {pair_key}")
        pair_keys.add(pair_key)
        groups[(advisory, identity, candidate_sha)].append(row)

    units: list[dict[str, object]] = []
    for (advisory, identity, candidate_sha), group in groups.items():
        edges: list[dict[str, object]] = []
        aggregate_signals: set[str] = set()
        for row in sorted(group, key=lambda value: str(value["fix_sha"])):
            signals = row.get("signals")
            if not isinstance(signals, list) or any(
                not isinstance(signal, str) for signal in signals
            ):
                raise OriginPacketContractError("candidate signals are malformed")
            aggregate_signals.update(signals)
            edges.append(
                {
                    "fix_sha": _sha(row.get("fix_sha"), "fix sha"),
                    "priority_rank": int(row.get("priority_rank") or 0),
                    "signals": sorted(set(signals)),
                    "materialization": str(row.get("materialization") or ""),
                    **(
                        {"relation_evidence": row["relation_evidence"]}
                        if "relation_evidence" in row
                        else {}
                    ),
                    **(
                        {
                            "ancestry_certificate": str(
                                row.get("ancestry_certificate") or ""
                            )
                        }
                        if "ancestry_certificate" in row
                        else {}
                    ),
                    **(
                        {"parent_priority_rank": int(row["parent_priority_rank"])}
                        if "parent_priority_rank" in row
                        else {}
                    ),
                    **(
                        {"landed_signals": row["landed_signals"]}
                        if "landed_signals" in row
                        else {}
                    ),
                    **(
                        {"fix_file_overlap": row["fix_file_overlap"]}
                        if "fix_file_overlap" in row
                        else {}
                    ),
                    **(
                        {"fix_file_overlap_count": int(row["fix_file_overlap_count"])}
                        if "fix_file_overlap_count" in row
                        else {}
                    ),
                    **(
                        {
                            "fix_code_file_overlap_count": int(
                                row["fix_code_file_overlap_count"]
                            )
                        }
                        if "fix_code_file_overlap_count" in row
                        else {}
                    ),
                    **(
                        {
                            "squash_internal_blame_evidence": row[
                                "squash_internal_blame_evidence"
                            ],
                            "squash_internal_blame_line_count": int(
                                row["squash_internal_blame_line_count"]
                            ),
                            "squash_internal_blame_paths": row[
                                "squash_internal_blame_paths"
                            ],
                        }
                        if "squash_internal_blame_evidence" in row
                        else {}
                    ),
                }
            )
        unit: dict[str, object] = {
            "unit_id": _identifier("origin-unit", identity, advisory, candidate_sha),
            "advisory": advisory,
            "repository_identity": identity,
            "candidate_sha": candidate_sha,
            "fix_edges": edges,
            "fix_edge_count": len(edges),
            "best_priority_rank": min(int(edge["priority_rank"]) for edge in edges),
            "signals": sorted(aggregate_signals),
            "retained": True,
        }
        for field in (
            "agent_kinds",
            "additions",
            "ai_exposure_basis",
            "ai_exposure_supported",
            "authored_date",
            "changed_files",
            "code_files_changed",
            "commit_subject",
            "deletions",
            "empty_commit",
            "merge_topology",
            "member_attribution_status",
            "member_diff_metadata_complete",
            "member_parent_metadata_complete",
            "member_record_metadata_complete",
            "origin_observed_in_cohort",
            "pr_number",
            "signal_types",
            "signal_inheritance",
            "source_modules",
            "squash_group_ids",
            "squash_attribution_only",
            "tools",
        ):
            values = [row[field] for row in group if field in row]
            if values:
                if any(value != values[0] for value in values[1:]):
                    raise OriginPacketContractError(
                        f"candidate metadata conflicts across fixes: {candidate_sha}"
                    )
                unit[field] = values[0]
        units.append(unit)

    units.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["advisory"]),
            int(row["best_priority_rank"]),
            str(row["candidate_sha"]),
        )
    )
    if sum(int(row["fix_edge_count"]) for row in units) != len(pair_keys):
        raise OriginPacketContractError("candidate/fix pair conservation failed")
    return units


def packetize_candidate_units(
    units: Iterable[Mapping[str, object]],
    *,
    max_candidates: int,
) -> list[dict[str, object]]:
    """Put every folded unit in exactly one bounded advisory packet."""

    if max_candidates < 1:
        raise OriginPacketContractError("max_candidates must be positive")
    groups: defaultdict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    unit_ids: set[str] = set()
    for raw in units:
        unit = dict(raw)
        unit_id = str(unit.get("unit_id") or "")
        advisory = str(unit.get("advisory") or "")
        identity = str(unit.get("repository_identity") or "").lower()
        _sha(unit.get("candidate_sha"), "candidate sha")
        if (
            not unit_id
            or not advisory
            or not identity
            or unit.get("retained") is not True
        ):
            raise OriginPacketContractError("candidate unit is incomplete")
        if unit_id in unit_ids:
            raise OriginPacketContractError(f"duplicate candidate unit: {unit_id}")
        unit_ids.add(unit_id)
        groups[(advisory, identity)].append(unit)

    packets: list[dict[str, object]] = []
    sequence = 0
    memberships: set[str] = set()
    for (advisory, identity), group in sorted(groups.items()):
        ordered = sorted(
            group,
            key=lambda row: (
                int(row.get("best_priority_rank") or 0),
                str(row.get("candidate_sha") or ""),
            ),
        )
        for offset in range(0, len(ordered), max_candidates):
            chunk = ordered[offset : offset + max_candidates]
            sequence += 1
            chunk_ids = [str(row["unit_id"]) for row in chunk]
            duplicate_memberships = memberships & set(chunk_ids)
            if duplicate_memberships:
                raise OriginPacketContractError(
                    f"candidate unit assigned twice: {sorted(duplicate_memberships)[0]}"
                )
            memberships.update(chunk_ids)
            fix_shas = sorted(
                {
                    str(edge["fix_sha"])
                    for row in chunk
                    for edge in row["fix_edges"]  # type: ignore[union-attr]
                }
            )
            packets.append(
                {
                    "packet_id": _identifier(
                        "origin-packet",
                        identity,
                        advisory,
                        *chunk_ids,
                    ),
                    "sequence": sequence,
                    "advisory": advisory,
                    "repository_identity": identity,
                    "candidate_unit_ids": chunk_ids,
                    "candidate_shas": [str(row["candidate_sha"]) for row in chunk],
                    "candidate_count": len(chunk),
                    "fix_shas": fix_shas,
                    "fix_edge_count": sum(int(row["fix_edge_count"]) for row in chunk),
                    "response_contract": "exactly_one_disposition_per_candidate_unit_id",
                }
            )
    if memberships != unit_ids:
        raise OriginPacketContractError("packet membership conservation failed")
    return packets
