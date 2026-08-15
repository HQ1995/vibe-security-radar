"""Recall-first advisory candidates for the forward cohort.

This module deliberately stops at graph reachability.  SZZ, paths, messages,
time distance, and model scores may later route an edge, but none of them may
remove it from the immutable inventory built here.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, deque
from collections.abc import Iterable, Mapping, Sequence


RELATION = "reachable_ancestor"
SQUASH_RELATION = "squash_pr_member"


class CandidateContractError(ValueError):
    """An input would violate the candidate or routing conservation contract."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _order_insensitive_json(value: object) -> object:
    """Canonicalize the set-like lists used by a parent-index artifact."""

    if isinstance(value, Mapping):
        return {
            str(key): _order_insensitive_json(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list):
        normalized = [_order_insensitive_json(item) for item in value]
        return sorted(normalized, key=_canonical_json)
    return value


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256()
    digest.update(prefix.encode("ascii"))
    for part in parts:
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return f"{prefix}-{digest.hexdigest()}"


def _full_sha(value: object, *, field: str) -> str:
    normalized = str(value or "").strip().lower()
    if len(normalized) != 40 or any(character not in "0123456789abcdef" for character in normalized):
        raise CandidateContractError(f"{field} must be a full 40-hex commit SHA")
    return normalized


def _normalize_units(
    repository_identity: str,
    units: Iterable[Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    normalized: dict[str, dict[str, object]] = {}
    for raw in units:
        identity = str(raw.get("repository_identity") or "").strip().lower()
        if identity != repository_identity:
            raise CandidateContractError(
                "candidate unit repository_identity does not match inventory repository"
            )
        sha = _full_sha(raw.get("sha"), field="candidate unit sha")
        tools = raw.get("tools", [])
        if not isinstance(tools, list) or any(not isinstance(tool, str) for tool in tools):
            raise CandidateContractError("candidate unit tools must be a list of strings")
        unit: dict[str, object] = {
            "repository_identity": repository_identity,
            "sha": sha,
            "authored_date": str(raw.get("authored_date") or ""),
            "route": str(raw.get("route") or ""),
            "tier": str(raw.get("tier") or ""),
            "tools": sorted(set(tools)),
        }
        raw_members = raw.get("member_shas")
        raw_ai_members = raw.get("ai_member_shas")
        if raw_members is not None or raw_ai_members is not None:
            if not isinstance(raw_members, list) or not isinstance(raw_ai_members, list):
                raise CandidateContractError(
                    "squash member_shas and ai_member_shas must be lists"
                )
            members = sorted(
                {_full_sha(value, field="squash member sha") for value in raw_members}
            )
            ai_members = sorted(
                {_full_sha(value, field="AI squash member sha") for value in raw_ai_members}
            )
            if not set(ai_members) <= set(members):
                raise CandidateContractError("AI squash members must belong to member_shas")
            raw_tools = raw.get("member_ai_tools", {})
            if not isinstance(raw_tools, Mapping):
                raise CandidateContractError("member_ai_tools must be an object")
            member_ai_tools: dict[str, list[str]] = {}
            for raw_member, raw_member_tools in raw_tools.items():
                member = _full_sha(raw_member, field="member_ai_tools sha")
                if member not in ai_members or not isinstance(raw_member_tools, list) or any(
                    not isinstance(tool, str) for tool in raw_member_tools
                ):
                    raise CandidateContractError("member_ai_tools must bind AI members to strings")
                member_ai_tools[member] = sorted(set(raw_member_tools))
            unit["member_shas"] = members
            unit["ai_member_shas"] = ai_members
            unit["member_ai_tools"] = member_ai_tools
        # Preserve stable exposure facts when the classifier supplied them.
        for key in (
            "ai_ratio",
            "files_changed",
            "merge_topology",
            "n_ai_members",
            "n_members",
            "observed_repository_identity",
            "pr_number",
            "squash_attribution_only",
        ):
            if key in raw:
                unit[key] = raw[key]
        prior = normalized.get(sha)
        if prior is not None and prior != unit:
            raise CandidateContractError(f"conflicting duplicate candidate unit: {sha}")
        normalized[sha] = unit
    return normalized


def _normalize_fixes(
    fixes: Iterable[Mapping[str, object]],
) -> dict[str, list[dict[str, str]]]:
    by_fix: dict[str, dict[str, str]] = {}
    for raw in fixes:
        fix_sha = _full_sha(raw.get("fix_sha"), field="advisory fix sha")
        advisory = str(raw.get("advisory") or "").strip()
        if not advisory:
            raise CandidateContractError("advisory fix must name an advisory")
        published = str(raw.get("published") or "").strip()
        grouped = by_fix.setdefault(fix_sha, {})
        prior = grouped.get(advisory)
        if prior is None or (published and (not prior or published < prior)):
            grouped[advisory] = published
    return {
        fix_sha: [
            {"id": advisory, "published": advisories[advisory]}
            for advisory in sorted(advisories)
        ]
        for fix_sha, advisories in sorted(by_fix.items())
    }


def _normalize_fix_references(
    fixes: Iterable[Mapping[str, object]],
) -> dict[str, list[dict[str, str]]]:
    by_ref: dict[str, dict[str, str]] = {}
    for raw in fixes:
        fix_ref = str(raw.get("fix_sha") or "").strip().lower()
        if not 7 <= len(fix_ref) <= 40 or any(
            character not in "0123456789abcdef" for character in fix_ref
        ):
            raise CandidateContractError(
                "blocked advisory fix reference must be 7-40 hexadecimal characters"
            )
        advisory = str(raw.get("advisory") or "").strip()
        if not advisory:
            raise CandidateContractError("advisory fix must name an advisory")
        published = str(raw.get("published") or "").strip()
        advisories = by_ref.setdefault(fix_ref, {})
        prior = advisories.get(advisory)
        if prior is None or (published and (not prior or published < prior)):
            advisories[advisory] = published
    return {
        fix_ref: [
            {"id": advisory, "published": advisories[advisory]}
            for advisory in sorted(advisories)
        ]
        for fix_ref, advisories in sorted(by_ref.items())
    }


def _blocked_reason_for_index(
    repository_identity: str,
    units: Mapping[str, Mapping[str, object]],
    parent_index: Mapping[str, object],
) -> str:
    if parent_index.get("complete") is not True:
        reason = parent_index.get("error")
        return str(reason) if isinstance(reason, str) and reason else "parent_index_incomplete"
    index_identity = str(parent_index.get("repository_identity") or "").strip().lower()
    if index_identity != repository_identity:
        return "parent_index_repository_mismatch"
    since = str(parent_index.get("since") or "").strip()
    if since and units:
        dates = [str(unit.get("authored_date") or "")[:10] for unit in units.values()]
        if any(len(value) != 10 for value in dates):
            return "candidate_authored_date_missing"
        if since[:10] > min(dates):
            return "parent_index_cutoff_after_candidate"
    return ""


def _normalize_parent_records(
    parent_index: Mapping[str, object],
) -> tuple[dict[str, dict[str, object]], set[str], str]:
    raw_commits = parent_index.get("commits", [])
    raw_refs_view = parent_index.get("refs_view", {})
    if not isinstance(raw_commits, list) or not isinstance(raw_refs_view, Mapping):
        return {}, set(), "parent_index_malformed"
    raw_shallow = raw_refs_view.get("shallow_commits", [])
    if not isinstance(raw_shallow, list):
        return {}, set(), "parent_index_malformed"
    shallow: set[str] = set()
    try:
        for value in raw_shallow:
            shallow.add(_full_sha(value, field="shallow commit"))
    except CandidateContractError:
        return {}, set(), "parent_index_malformed"

    records: dict[str, dict[str, object]] = {}
    try:
        for raw in raw_commits:
            if not isinstance(raw, Mapping):
                return {}, set(), "parent_index_malformed"
            sha = _full_sha(raw.get("sha"), field="parent record sha")
            raw_parents = raw.get("parents", [])
            if not isinstance(raw_parents, list):
                return {}, set(), "parent_index_malformed"
            parents = sorted(
                {_full_sha(parent, field="parent sha") for parent in raw_parents}
            )
            record = {
                "sha": sha,
                "parents": parents,
                "cutoff_boundary": raw.get("cutoff_boundary") is True,
            }
            if sha in records:
                return {}, set(), "parent_index_duplicate_record"
            records[sha] = record
    except CandidateContractError:
        return {}, set(), "parent_index_malformed"
    return records, shallow, ""


def _reachability_masks(
    roots: Sequence[str],
    records: Mapping[str, Mapping[str, object]],
    shallow: set[str],
) -> tuple[dict[str, int], dict[str, str]]:
    """Propagate all fix-root identities backwards through the graph once."""

    root_bit = {root: 1 << index for index, root in enumerate(roots)}
    blocked: dict[str, str] = {}
    masks: dict[str, int] = {}
    sent: dict[str, int] = {}
    pending: deque[str] = deque()

    for root in roots:
        if root not in records:
            blocked[root] = "fix_sha_not_in_parent_index"
            continue
        masks[root] = masks.get(root, 0) | root_bit[root]
        pending.append(root)

    def block(mask: int, reason: str) -> None:
        for root in roots:
            if mask & root_bit[root]:
                blocked.setdefault(root, reason)

    while pending:
        current = pending.popleft()
        delta = masks.get(current, 0) & ~sent.get(current, 0)
        if not delta:
            continue
        sent[current] = sent.get(current, 0) | delta
        record = records.get(current)
        if record is None:
            block(delta, "parent_index_parent_missing")
            continue
        if record.get("cutoff_boundary") is True:
            continue
        if current in shallow:
            block(delta, "shallow_history_boundary")
            continue
        raw_parents = record.get("parents", [])
        if not isinstance(raw_parents, list):
            block(delta, "parent_index_malformed")
            continue
        for parent in raw_parents:
            parent_sha = str(parent)
            before = masks.get(parent_sha, 0)
            after = before | delta
            if after != before:
                masks[parent_sha] = after
                pending.append(parent_sha)
    return masks, blocked


def _root_record(
    repository_identity: str,
    fix_sha: str,
    advisories: list[dict[str, str]],
    unit_shas: Sequence[str],
    edges: Sequence[Mapping[str, object]],
    reason: str,
) -> dict[str, object]:
    edge_ids = sorted(str(edge["edge_id"]) for edge in edges)
    return {
        "root_id": _stable_id("fix-root", repository_identity, fix_sha),
        "repository_identity": repository_identity,
        "fix_sha": fix_sha,
        "advisories": advisories,
        "status": "BLOCKED" if reason else "RESOLVED",
        "reason": reason,
        "candidate_unit_count": len(unit_shas),
        "candidate_unit_sha256": _sha256_json(list(unit_shas)),
        "candidate_edge_count": len(edge_ids),
        "candidate_edge_sha256": _sha256_json(edge_ids),
    }


def build_repository_inventory(
    repository_identity: str,
    units: Iterable[Mapping[str, object]],
    fixes: Iterable[Mapping[str, object]],
    parent_index: Mapping[str, object],
) -> dict[str, object]:
    """Build an uncapped, deterministic candidate inventory for one repository."""

    identity = str(repository_identity).strip().lower()
    if not identity:
        raise CandidateContractError("repository_identity is required")
    normalized_units = _normalize_units(identity, units)
    fixes_by_sha = _normalize_fixes(fixes)
    root_shas = sorted(fixes_by_sha)
    unit_shas = sorted(normalized_units)

    global_reason = _blocked_reason_for_index(identity, normalized_units, parent_index)
    records: dict[str, dict[str, object]] = {}
    shallow: set[str] = set()
    if not global_reason:
        records, shallow, global_reason = _normalize_parent_records(parent_index)

    masks: dict[str, int] = {}
    blocked: dict[str, str] = {}
    if global_reason:
        blocked = {root: global_reason for root in root_shas}
    else:
        masks, blocked = _reachability_masks(root_shas, records, shallow)

    root_bit = {root: 1 << index for index, root in enumerate(root_shas)}
    candidate_edges_by_id: dict[str, dict[str, object]] = {}
    for candidate_sha in unit_shas:
        unit = normalized_units[candidate_sha]
        mask = masks.get(candidate_sha, 0)
        for fix_sha in root_shas:
            if (
                candidate_sha == fix_sha
                or not (mask & root_bit[fix_sha])
            ):
                continue
            root_reason = blocked.get(fix_sha, "")
            edge_id = _stable_id(
                "cohort-edge", identity, candidate_sha, fix_sha, RELATION
            )
            edge: dict[str, object] = {
                "edge_id": edge_id,
                "repository_identity": identity,
                "candidate_sha": candidate_sha,
                "fix_sha": fix_sha,
                "relation": RELATION,
                "advisories": fixes_by_sha[fix_sha],
                "root_coverage_status": "BLOCKED" if root_reason else "RESOLVED",
                "root_coverage_reason": root_reason,
                "initial_status": "DEFER",
                "initial_reason": "awaiting_screening",
            }
            for key in (
                "ai_ratio",
                "authored_date",
                "files_changed",
                "merge_topology",
                "n_ai_members",
                "n_members",
                "observed_repository_identity",
                "pr_number",
                "route",
                "squash_attribution_only",
                "tier",
                "tools",
            ):
                if key in unit:
                    edge[key] = unit[key]
            candidate_edges_by_id[edge_id] = edge

            members = unit.get("member_shas", [])
            ai_members = set(unit.get("ai_member_shas", []))
            member_ai_tools = unit.get("member_ai_tools", {})
            if not isinstance(members, list) or not isinstance(member_ai_tools, Mapping):
                continue
            for member_sha in members:
                member_edge_id = _stable_id(
                    "cohort-edge", identity, str(member_sha), fix_sha, SQUASH_RELATION
                )
                existing = candidate_edges_by_id.get(member_edge_id)
                if existing is not None:
                    carriers = set(existing.get("carrier_shas", []))
                    carriers.add(candidate_sha)
                    existing["carrier_shas"] = sorted(carriers)
                    continue
                member_tools = member_ai_tools.get(str(member_sha), [])
                candidate_edges_by_id[member_edge_id] = {
                    "edge_id": member_edge_id,
                    "repository_identity": identity,
                    "candidate_sha": str(member_sha),
                    "fix_sha": fix_sha,
                    "relation": SQUASH_RELATION,
                    "carrier_shas": [candidate_sha],
                    "carrier_tools": unit["tools"],
                    "member_ai_attributed": member_sha in ai_members,
                    "tools": list(member_tools) if isinstance(member_tools, list) else [],
                    "advisories": fixes_by_sha[fix_sha],
                    "root_coverage_status": "BLOCKED" if root_reason else "RESOLVED",
                    "root_coverage_reason": root_reason,
                    "initial_status": "DEFER",
                    "initial_reason": "awaiting_screening",
                }
    candidate_edges = [candidate_edges_by_id[key] for key in sorted(candidate_edges_by_id)]

    edges_by_fix: dict[str, list[dict[str, object]]] = {root: [] for root in root_shas}
    for edge in candidate_edges:
        edges_by_fix[str(edge["fix_sha"])].append(edge)
    fix_roots = [
        _root_record(
            identity,
            fix_sha,
            fixes_by_sha[fix_sha],
            unit_shas,
            edges_by_fix[fix_sha],
            blocked.get(fix_sha, ""),
        )
        for fix_sha in root_shas
    ]
    resolved_count = sum(root["status"] == "RESOLVED" for root in fix_roots)
    blocked_count = sum(root["status"] == "BLOCKED" for root in fix_roots)
    conservation = {
        "fix_root_count": len(fix_roots),
        "resolved_fix_root_count": resolved_count,
        "blocked_fix_root_count": blocked_count,
        "fix_roots_conserved": len(fix_roots) == resolved_count + blocked_count,
    }
    inventory: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "forward_cohort_advisory_candidate_inventory",
        "repository_identity": identity,
        "coverage_complete": blocked_count == 0,
        "candidate_edges": candidate_edges,
        "fix_roots": fix_roots,
        "candidate_edges_sha256": _sha256_json(candidate_edges),
        "fix_roots_sha256": _sha256_json(fix_roots),
        "parent_index_sha256": _sha256_json(_order_insensitive_json(parent_index)),
        "conservation": conservation,
    }
    inventory["inventory_sha256"] = _sha256_json(inventory)
    return inventory


def build_blocked_repository_inventory(
    repository_identity: str,
    units: Iterable[Mapping[str, object]],
    fixes: Iterable[Mapping[str, object]],
    *,
    reason: str,
) -> dict[str, object]:
    """Preserve fix references that cannot safely enter the ancestry walk."""

    identity = str(repository_identity).strip().lower()
    if not identity:
        raise CandidateContractError("repository_identity is required")
    blocked_reason = str(reason).strip()
    if not blocked_reason:
        raise CandidateContractError("blocked repository inventory requires a reason")
    normalized_units = _normalize_units(identity, units)
    fixes_by_ref = _normalize_fix_references(fixes)
    unit_shas = sorted(normalized_units)
    fix_roots: list[dict[str, object]] = []
    for fix_ref, advisories in fixes_by_ref.items():
        root: dict[str, object] = {
            "root_id": _stable_id("fix-root", identity, fix_ref),
            "repository_identity": identity,
            "fix_ref": fix_ref,
            "advisories": advisories,
            "status": "BLOCKED",
            "reason": blocked_reason,
            "candidate_unit_count": len(unit_shas),
            "candidate_unit_sha256": _sha256_json(unit_shas),
            "candidate_edge_count": 0,
            "candidate_edge_sha256": _sha256_json([]),
        }
        if len(fix_ref) == 40:
            root["fix_sha"] = fix_ref
        fix_roots.append(root)
    conservation = {
        "fix_root_count": len(fix_roots),
        "resolved_fix_root_count": 0,
        "blocked_fix_root_count": len(fix_roots),
        "fix_roots_conserved": True,
    }
    inventory: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "forward_cohort_advisory_candidate_inventory",
        "repository_identity": identity,
        "coverage_complete": not fix_roots,
        "candidate_edges": [],
        "fix_roots": fix_roots,
        "candidate_edges_sha256": _sha256_json([]),
        "fix_roots_sha256": _sha256_json(fix_roots),
        "conservation": conservation,
    }
    inventory["inventory_sha256"] = _sha256_json(inventory)
    return inventory


def build_routing_manifest(
    candidate_edges: Sequence[Mapping[str, object]],
    *,
    promoted_edge_ids: Iterable[str] = (),
    blocked_edges: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Route every immutable edge exactly once without interpreting DEFER as no."""

    edges_by_id: dict[str, Mapping[str, object]] = {}
    for edge in candidate_edges:
        edge_id = str(edge.get("edge_id") or "")
        if not edge_id:
            raise CandidateContractError("candidate edge is missing edge_id")
        if edge_id in edges_by_id:
            raise CandidateContractError(f"duplicate candidate edge id: {edge_id}")
        edges_by_id[edge_id] = edge

    promoted_list = [str(edge_id) for edge_id in promoted_edge_ids]
    if len(promoted_list) != len(set(promoted_list)):
        raise CandidateContractError("duplicate edge in PROMOTE disposition")
    promoted = set(promoted_list)
    blocked = {str(edge_id): str(reason) for edge_id, reason in (blocked_edges or {}).items()}
    unknown = sorted((promoted | set(blocked)) - set(edges_by_id))
    if unknown:
        raise CandidateContractError(f"model returned unknown edge id: {unknown[0]}")
    overlap = sorted(promoted & set(blocked))
    if overlap:
        raise CandidateContractError(
            f"edge cannot be both PROMOTE and BLOCKED: {overlap[0]}"
        )
    if any(not reason.strip() for reason in blocked.values()):
        raise CandidateContractError("BLOCKED disposition requires a reason")

    routes: list[dict[str, str]] = []
    counts = {"PROMOTE": 0, "DEFER": 0, "BLOCKED": 0}
    for edge_id in sorted(edges_by_id):
        if edge_id in promoted:
            status, reason = "PROMOTE", "selected_for_deep_review"
        elif edge_id in blocked:
            status, reason = "BLOCKED", blocked[edge_id]
        else:
            status, reason = "DEFER", "not_selected_yet"
        counts[status] += 1
        routes.append({"edge_id": edge_id, "status": status, "reason": reason})

    edge_ids = sorted(edges_by_id)
    conservation = {
        "candidate_edge_count": len(edge_ids),
        "promoted_edge_count": counts["PROMOTE"],
        "deferred_edge_count": counts["DEFER"],
        "blocked_edge_count": counts["BLOCKED"],
        "candidate_edges_conserved": len(edge_ids) == sum(counts.values()),
        "candidate_edge_ids_sha256": _sha256_json(edge_ids),
    }
    manifest: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "forward_cohort_advisory_candidate_routing",
        "counts": counts,
        "routes": routes,
        "conservation": conservation,
    }
    manifest["routing_sha256"] = _sha256_json(manifest)
    return manifest


def build_campaign_artifacts(
    repository_inventories: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    """Flatten repository results and re-check both conservation equations."""

    edges_by_id: dict[str, Mapping[str, object]] = {}
    roots_by_id: dict[str, Mapping[str, object]] = {}
    inventory_ids: list[str] = []
    for inventory in repository_inventories:
        conservation = inventory.get("conservation")
        if not isinstance(conservation, Mapping) or conservation.get("fix_roots_conserved") is not True:
            raise CandidateContractError("repository inventory does not conserve fix roots")
        inventory_sha = str(inventory.get("inventory_sha256") or "")
        if not inventory_sha:
            raise CandidateContractError("repository inventory is missing its identity")
        inventory_ids.append(inventory_sha)
        raw_edges = inventory.get("candidate_edges", [])
        raw_roots = inventory.get("fix_roots", [])
        if not isinstance(raw_edges, list) or not isinstance(raw_roots, list):
            raise CandidateContractError("repository inventory is malformed")
        for edge in raw_edges:
            if not isinstance(edge, Mapping):
                raise CandidateContractError("candidate edge is malformed")
            edge_id = str(edge.get("edge_id") or "")
            if not edge_id or edge_id in edges_by_id:
                raise CandidateContractError(f"duplicate candidate edge id: {edge_id}")
            edges_by_id[edge_id] = edge
        for root in raw_roots:
            if not isinstance(root, Mapping):
                raise CandidateContractError("fix root is malformed")
            root_id = str(root.get("root_id") or "")
            if not root_id or root_id in roots_by_id:
                raise CandidateContractError(f"duplicate fix root id: {root_id}")
            roots_by_id[root_id] = root

    candidates = [dict(edges_by_id[key]) for key in sorted(edges_by_id)]
    fix_roots = [dict(roots_by_id[key]) for key in sorted(roots_by_id)]
    routing = build_routing_manifest(candidates)
    root_counts = Counter(str(root.get("status") or "") for root in fix_roots)
    route_conservation = routing["conservation"]
    assert isinstance(route_conservation, Mapping)
    conservation = {
        "fix_root_count": len(fix_roots),
        "resolved_fix_root_count": root_counts["RESOLVED"],
        "blocked_fix_root_count": root_counts["BLOCKED"],
        "fix_roots_conserved": (
            len(fix_roots) == root_counts["RESOLVED"] + root_counts["BLOCKED"]
        ),
        "candidate_edge_count": len(candidates),
        "promoted_edge_count": int(route_conservation["promoted_edge_count"]),
        "deferred_edge_count": int(route_conservation["deferred_edge_count"]),
        "blocked_edge_count": int(route_conservation["blocked_edge_count"]),
        "candidate_edges_conserved": route_conservation["candidate_edges_conserved"] is True,
    }
    if not conservation["fix_roots_conserved"] or not conservation["candidate_edges_conserved"]:
        raise CandidateContractError("campaign conservation equation failed")
    summary: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "forward_cohort_advisory_candidate_campaign",
        "coverage_complete": root_counts["BLOCKED"] == 0,
        "repository_inventory_count": len(inventory_ids),
        "repository_inventories_sha256": _sha256_json(sorted(inventory_ids)),
        "candidate_edges_sha256": _sha256_json(candidates),
        "fix_roots_sha256": _sha256_json(fix_roots),
        "routing_sha256": routing["routing_sha256"],
        "blocked_fix_root_reasons": dict(
            sorted(
                Counter(
                    str(root.get("reason") or "unspecified")
                    for root in fix_roots
                    if root.get("status") == "BLOCKED"
                ).items()
            )
        ),
        "conservation": conservation,
    }
    summary["summary_sha256"] = _sha256_json(summary)
    return {
        "candidates": candidates,
        "fix_roots": fix_roots,
        "routing": routing,
        "summary": summary,
    }


def build_bidirectional_ledger(
    candidate_edges: Sequence[Mapping[str, object]],
    units_by_repository: Mapping[str, Sequence[Mapping[str, object]]],
    introductions_by_repository: Mapping[str, Sequence[Mapping[str, object]]],
) -> dict[str, object]:
    """Join fix-first ancestry edges with exact AI-first OSV introductions."""

    bindings: dict[tuple[str, str], dict[str, object]] = {}
    for raw_identity, raw_units in sorted(units_by_repository.items()):
        identity = str(raw_identity).strip().lower()
        units = _normalize_units(identity, raw_units)
        for sha, unit in units.items():
            bindings[(identity, sha)] = {
                "binding": "observed_ai_commit",
                "tools": unit["tools"],
            }
            member_tools = unit.get("member_ai_tools", {})
            if not isinstance(member_tools, Mapping):
                continue
            for member_sha in unit.get("ai_member_shas", []):
                bindings[(identity, str(member_sha))] = {
                    "binding": "observed_ai_squash_member",
                    "tools": list(member_tools.get(str(member_sha), [])),
                    "carrier_sha": sha,
                }

    reverse_evidence: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    for raw_identity, observations in sorted(introductions_by_repository.items()):
        identity = str(raw_identity).strip().lower()
        for observation in observations:
            candidate_sha = _full_sha(
                observation.get("introduced_sha"), field="OSV introduced sha"
            )
            if (identity, candidate_sha) not in bindings:
                continue
            raw_public_ids = observation.get("public_ids", [])
            if not isinstance(raw_public_ids, list) or any(
                not isinstance(value, str) for value in raw_public_ids
            ):
                raise CandidateContractError("OSV introduced public_ids must be strings")
            record_id = str(observation.get("record_id") or "").strip()
            advisory_ids = {
                value.strip().upper() for value in raw_public_ids if value.strip()
            }
            if record_id:
                advisory_ids.add(record_id.upper())
            evidence = {
                "record_id": record_id,
                "public_ids": sorted(advisory_ids),
                "published": str(observation.get("published") or ""),
            }
            for advisory in sorted(advisory_ids):
                rows = reverse_evidence.setdefault(
                    (identity, candidate_sha, advisory), []
                )
                if evidence not in rows:
                    rows.append(evidence)

    consumed: dict[tuple[str, str, str], set[str]] = {
        key: set() for key in reverse_evidence
    }
    ledger: list[dict[str, object]] = []
    forward_count = 0
    for edge in sorted(candidate_edges, key=lambda item: str(item.get("edge_id") or "")):
        edge_id = str(edge.get("edge_id") or "")
        identity = str(edge.get("repository_identity") or "").strip().lower()
        candidate_sha = _full_sha(edge.get("candidate_sha"), field="candidate sha")
        fix_sha = _full_sha(edge.get("fix_sha"), field="fix sha")
        raw_advisories = edge.get("advisories", [])
        if not edge_id or not isinstance(raw_advisories, list):
            raise CandidateContractError("candidate edge has malformed advisories")
        advisory_ids = sorted(
            {
                str(advisory.get("id") or "").strip().upper()
                for advisory in raw_advisories
                if isinstance(advisory, Mapping) and advisory.get("id")
            }
        )
        for advisory in advisory_ids:
            forward_count += 1
            reverse_key = (identity, candidate_sha, advisory)
            reverse = reverse_evidence.get(reverse_key, [])
            if reverse:
                consumed[reverse_key].add(edge_id)
            binding = bindings.get((identity, candidate_sha))
            if binding is None and edge.get("relation") == SQUASH_RELATION:
                binding = {
                    "binding": "squash_carrier_only",
                    "carrier_shas": edge.get("carrier_shas", []),
                    "tools": edge.get("carrier_tools", []),
                }
            status = "BOTH_ENDS" if reverse else "FIX_END_ONLY"
            ledger.append(
                {
                    "ledger_id": _stable_id(
                        "bidirectional-edge", edge_id, advisory
                    ),
                    "repository_identity": identity,
                    "candidate_sha": candidate_sha,
                    "advisory": advisory,
                    "fix_sha": fix_sha,
                    "relation": str(edge.get("relation") or ""),
                    "confirmation_status": status,
                    "evidence_ends": ["AI_END", "FIX_END"] if reverse else ["FIX_END"],
                    "candidate_binding": binding,
                    "fix_end": {
                        "edge_id": edge_id,
                        "root_coverage_status": edge.get("root_coverage_status"),
                        "root_coverage_reason": edge.get("root_coverage_reason"),
                    },
                    "ai_end": (
                        {
                            "source": "official_osv_git_range_introduced_event",
                            "observations": reverse,
                        }
                        if reverse
                        else None
                    ),
                    "routing_status": "DEFER",
                }
            )

    reverse_matches: list[dict[str, object]] = []
    for key in sorted(reverse_evidence):
        identity, candidate_sha, advisory = key
        forward_edge_ids = sorted(consumed[key])
        match = {
            "repository_identity": identity,
            "candidate_sha": candidate_sha,
            "advisory": advisory,
            "source": "official_osv_git_range_introduced_event",
            "candidate_binding": bindings[(identity, candidate_sha)],
            "observations": reverse_evidence[key],
            "matched_forward_edge_ids": forward_edge_ids,
            "confirmation_status": "BOTH_ENDS" if forward_edge_ids else "AI_END_ONLY",
        }
        reverse_matches.append(match)
        if forward_edge_ids:
            continue
        ledger.append(
            {
                "ledger_id": _stable_id(
                    "bidirectional-edge", identity, candidate_sha, advisory, "AI_END_ONLY"
                ),
                "repository_identity": identity,
                "candidate_sha": candidate_sha,
                "advisory": advisory,
                "fix_sha": "",
                "relation": "osv_git_introduced",
                "confirmation_status": "AI_END_ONLY",
                "evidence_ends": ["AI_END"],
                "candidate_binding": bindings[(identity, candidate_sha)],
                "fix_end": None,
                "ai_end": {
                    "source": "official_osv_git_range_introduced_event",
                    "observations": reverse_evidence[key],
                },
                "routing_status": "DEFER",
            }
        )

    ledger.sort(key=lambda row: str(row["ledger_id"]))
    status_counts = Counter(str(row["confirmation_status"]) for row in ledger)
    reverse_only_count = status_counts["AI_END_ONLY"]
    conservation = {
        "forward_advisory_edge_count": forward_count,
        "reverse_exact_pair_count": len(reverse_matches),
        "reverse_pairs_with_forward_count": sum(bool(value) for value in consumed.values()),
        "reverse_pairs_without_forward_count": reverse_only_count,
        "ledger_row_count": len(ledger),
        "ledger_rows_conserved": len(ledger) == forward_count + reverse_only_count,
        "forward_rows_conserved": forward_count
        == status_counts["BOTH_ENDS"] + status_counts["FIX_END_ONLY"],
        "reverse_pairs_conserved": len(reverse_matches)
        == sum(bool(value) for value in consumed.values()) + reverse_only_count,
    }
    if not all(
        conservation[key] is True
        for key in (
            "ledger_rows_conserved",
            "forward_rows_conserved",
            "reverse_pairs_conserved",
        )
    ):
        raise CandidateContractError("bidirectional ledger conservation failed")
    summary: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "forward_cohort_bidirectional_candidate_ledger",
        "status_counts": dict(sorted(status_counts.items())),
        "ledger_sha256": _sha256_json(ledger),
        "reverse_matches_sha256": _sha256_json(reverse_matches),
        "conservation": conservation,
        "claim_boundary": (
            "BOTH_ENDS means the same repository, candidate SHA, and advisory ID were "
            "observed by fix-first ancestry and an exact official OSV introduced event; "
            "it routes causal review and is not itself an AI-causality verdict"
        ),
    }
    summary["summary_sha256"] = _sha256_json(summary)
    return {"ledger": ledger, "reverse_matches": reverse_matches, "summary": summary}
