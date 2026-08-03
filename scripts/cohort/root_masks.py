"""Attach source-root hints to all-commit universes with bit masks."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence


class RootMaskContractError(ValueError):
    """A source observation or commit universe violates the mask contract."""


def canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _full_sha(value: object, field: str) -> str:
    sha = str(value or "").strip().lower()
    if len(sha) != 40 or any(
        character not in "0123456789abcdef" for character in sha
    ):
        raise RootMaskContractError(f"{field} must be a full commit SHA")
    return sha


def _root_groups(
    repository_identity: str,
    observations: Sequence[Mapping[str, object]],
) -> tuple[dict[str, dict[str, set[str]]], list[dict[str, object]]]:
    grouped: dict[str, dict[str, set[str]]] = {}
    blocked: list[dict[str, object]] = []
    for raw in observations:
        identity = str(raw.get("repository_identity") or "").strip().lower()
        if identity != repository_identity:
            raise RootMaskContractError("source observation repository mismatch")
        advisory = str(raw.get("advisory") or "").strip()
        observation_id = str(raw.get("observation_id") or "").strip()
        evidence_kind = str(raw.get("evidence_kind") or "").strip()
        status = str(raw.get("resolution_status") or "").strip()
        if not advisory or not observation_id or not evidence_kind:
            raise RootMaskContractError("source observation is malformed")
        if status == "BLOCKED":
            blocked.append(
                {
                    "repository_identity": repository_identity,
                    "advisory": advisory,
                    "observation_id": observation_id,
                    "fix_ref": str(raw.get("fix_ref") or "").strip().lower(),
                    "evidence_kind": evidence_kind,
                    "status": "BLOCKED",
                    "reason": str(raw.get("resolution_reason") or "")
                    or "source_reference_unresolved",
                }
            )
            continue
        if status != "RESOLVED":
            raise RootMaskContractError("source observation has unknown resolution status")
        fix_sha = _full_sha(raw.get("fix_sha"), "resolved source root")
        group = grouped.setdefault(
            fix_sha,
            {
                "advisories": set(),
                "evidence_kinds": set(),
                "observation_ids": set(),
            },
        )
        group["advisories"].add(advisory)
        group["evidence_kinds"].add(evidence_kind)
        group["observation_ids"].add(observation_id)
    blocked.sort(key=lambda row: str(row["observation_id"]))
    return grouped, blocked


def build_repository_root_masks(
    universe_summary: Mapping[str, object],
    commit_rows: Sequence[Mapping[str, object]],
    observations: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Propagate every root bit once; absent bits never delete fallback commits."""

    identity = str(universe_summary.get("repository_identity") or "").strip().lower()
    if not identity:
        raise RootMaskContractError("universe summary requires repository_identity")
    records: dict[str, list[str]] = {}
    for raw in commit_rows:
        if str(raw.get("repository_identity") or "").strip().lower() != identity:
            raise RootMaskContractError("commit row repository mismatch")
        sha = _full_sha(raw.get("sha"), "universe commit")
        raw_parents = raw.get("parents", [])
        if not isinstance(raw_parents, list):
            raise RootMaskContractError("universe commit parents are malformed")
        parents = sorted({_full_sha(parent, "universe parent") for parent in raw_parents})
        if sha in records:
            raise RootMaskContractError("duplicate universe commit")
        records[sha] = parents
    grouped, blocked_observations = _root_groups(identity, observations)
    roots = sorted(grouped)
    root_bits = {root: 1 << index for index, root in enumerate(roots)}
    masks: dict[str, int] = {}
    sent: dict[str, int] = {}
    pending: deque[str] = deque()
    root_reasons: dict[str, set[str]] = defaultdict(set)
    universe_blocked = universe_summary.get("status") != "RESOLVED"
    for root in roots:
        if universe_blocked:
            root_reasons[root].add("repository_universe_incomplete")
        if root not in records:
            root_reasons[root].add("source_root_not_in_commit_universe")
            continue
        masks[root] = masks.get(root, 0) | root_bits[root]
        pending.append(root)

    while pending:
        current = pending.popleft()
        delta = masks.get(current, 0) & ~sent.get(current, 0)
        if not delta:
            continue
        sent[current] = sent.get(current, 0) | delta
        for parent in records.get(current, []):
            if parent not in records:
                for root, bit in root_bits.items():
                    if delta & bit:
                        root_reasons[root].add("parent_closure_incomplete")
                continue
            before = masks.get(parent, 0)
            after = before | delta
            if after != before:
                masks[parent] = after
                pending.append(parent)

    root_rows: list[dict[str, object]] = []
    for root in roots:
        group = grouped[root]
        reasons = sorted(root_reasons[root])
        bit = root_bits[root]
        reachable_count = sum(bool(mask & bit) for mask in masks.values())
        root_rows.append(
            {
                "root_id": "source-root-"
                + canonical_sha256(
                    {"repository_identity": identity, "root_sha": root}
                ),
                "repository_identity": identity,
                "root_sha": root,
                "bit_index": roots.index(root),
                "advisories": sorted(group["advisories"]),
                "evidence_kinds": sorted(group["evidence_kinds"]),
                "observation_ids": sorted(group["observation_ids"]),
                "source_role": "candidate_root_hint_not_causal_adjudication",
                "status": "BLOCKED" if reasons else "RESOLVED",
                "block_reasons": reasons,
                "reachable_commit_count": reachable_count,
            }
        )
    membership_rows = [
        {
            "repository_identity": identity,
            "sha": sha,
            "root_mask_hex": format(mask, "x"),
            "reachable_root_count": mask.bit_count(),
        }
        for sha, mask in sorted(masks.items())
        if mask
    ]
    summary: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "repository_source_root_mask_overlay",
        "repository_identity": identity,
        "universe_id": universe_summary.get("universe_id", ""),
        "universe_status": universe_summary.get("status", ""),
        "source_observation_count": len(observations),
        "resolved_root_hint_count": len(root_rows),
        "blocked_source_observation_count": len(blocked_observations),
        "resolved_root_coverage_count": sum(
            row["status"] == "RESOLVED" for row in root_rows
        ),
        "blocked_root_coverage_count": sum(
            row["status"] == "BLOCKED" for row in root_rows
        ),
        "membership_row_count": len(membership_rows),
        "membership_rows_sha256": canonical_sha256(membership_rows),
        "root_rows_sha256": canonical_sha256(root_rows),
        "fallback_scope_unchanged": True,
    }
    summary["summary_sha256"] = canonical_sha256(summary)
    return {
        "summary": summary,
        "root_rows": root_rows,
        "membership_rows": membership_rows,
        "blocked_observations": blocked_observations,
    }
