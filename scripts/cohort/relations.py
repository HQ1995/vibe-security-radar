"""Repository and atomic-to-landed relation closure for recall-first candidates."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence


PULL_MEMBER_RELATION = "pull_request_member_landed_as_squash"
COMPOSITE_RELATION = (
    "pull_request_member_landed_as_squash_then_reachable_ancestor"
)
_UNIT_METADATA_KEYS = (
    "agent_kinds",
    "ai_ratio",
    "ai_exposure_basis",
    "ai_exposure_supported",
    "authored_date",
    "files_changed",
    "merge_topology",
    "n_ai_members",
    "n_members",
    "observed_repository_identity",
    "observed_ai_unit",
    "pr_number",
    "route",
    "squash_attribution_only",
    "signal_types",
    "source_modules",
    "tier",
    "tools",
)
_PULL_MEMBER_GAP_FIELDS = (
    "member_parent_metadata_gap_shas",
    "member_record_metadata_gap_shas",
    "member_diff_metadata_gap_shas",
)


class RelationContractError(ValueError):
    """Relation evidence is malformed, ambiguous, or non-conservative."""


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


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256(prefix.encode("ascii"))
    for part in parts:
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return f"{prefix}-{digest.hexdigest()}"


def _identity(value: object, *, field: str) -> str:
    normalized = str(value or "").strip().lower().removesuffix(".git")
    if not normalized or "/" not in normalized or any(
        character in normalized for character in "\x00\r\n"
    ):
        raise RelationContractError(f"{field} is not a repository identity")
    return normalized


def _full_sha(value: object, *, field: str) -> str:
    normalized = str(value or "").strip().lower()
    if len(normalized) != 40 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise RelationContractError(f"{field} must be a full 40-hex commit SHA")
    return normalized


def normalize_repository_aliases(
    rows: Iterable[Mapping[str, object]],
) -> dict[str, str]:
    """Return alias -> final canonical identity, rejecting conflicts and cycles."""

    direct: dict[str, str] = {}
    for row in rows:
        alias = _identity(row.get("alias"), field="alias")
        canonical = _identity(row.get("canonical"), field="canonical")
        prior = direct.get(alias)
        if prior is not None and prior != canonical:
            raise RelationContractError(f"conflicting repository alias: {alias}")
        if alias != canonical:
            direct[alias] = canonical

    flattened: dict[str, str] = {}
    for alias in sorted(direct):
        path: list[str] = []
        current = alias
        while current in direct:
            if current in path:
                cycle = " -> ".join([*path[path.index(current) :], current])
                raise RelationContractError(f"repository alias cycle: {cycle}")
            path.append(current)
            current = direct[current]
        for member in path:
            flattened[member] = current
    return flattened


def canonical_repository_identity(identity: str, aliases: Mapping[str, str]) -> str:
    normalized = _identity(identity, field="repository identity")
    seen: set[str] = set()
    while normalized in aliases:
        if normalized in seen:
            raise RelationContractError("repository alias cycle")
        seen.add(normalized)
        normalized = _identity(aliases[normalized], field="canonical repository identity")
    return normalized


def _unit_metadata(unit: Mapping[str, object]) -> dict[str, object]:
    return {key: unit[key] for key in _UNIT_METADATA_KEYS if key in unit}


def build_pull_relation_inventory(
    repository_identity: str,
    units: Iterable[Mapping[str, object]],
    pull_results: Mapping[int, Mapping[str, object]],
    *,
    landed_candidate_shas: Iterable[str] | None = None,
) -> dict[str, object]:
    """Map every PR-head member to its landed squash commit.

    Membership is structural evidence, while presence in ``units`` is only
    metadata evidence.  Intersecting the two would erase the ordinary case in
    which an atomic PR commit disappears from mainline after a squash.  The
    inventory therefore retains unobserved members for later screening and
    marks whether cohort metadata was available.
    """

    identity = _identity(repository_identity, field="repository identity")
    target_landed = (
        {
            _full_sha(sha, field="landed candidate sha")
            for sha in landed_candidate_shas
        }
        if landed_candidate_shas is not None
        else None
    )
    units_by_sha: dict[str, dict[str, object]] = {}
    squashes_by_pr: dict[int, set[str]] = {}
    for raw in units:
        unit_identity = _identity(
            raw.get("repository_identity"), field="unit repository identity"
        )
        if unit_identity != identity:
            raise RelationContractError("unit repository does not match relation inventory")
        sha = _full_sha(raw.get("sha"), field="unit sha")
        unit = dict(raw)
        unit["repository_identity"] = identity
        unit["sha"] = sha
        prior = units_by_sha.get(sha)
        if prior is not None and prior != unit:
            raise RelationContractError(f"conflicting duplicate unit: {sha}")
        units_by_sha[sha] = unit
        if raw.get("merge_topology") != "squash":
            continue
        if target_landed is not None and sha not in target_landed:
            continue
        pr_number = raw.get("pr_number")
        if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
            raise RelationContractError(f"squash unit {sha} lacks a usable PR number")
        squashes_by_pr.setdefault(pr_number, set()).add(sha)

    if target_landed is not None:
        observed_landed = {
            sha for landed_shas in squashes_by_pr.values() for sha in landed_shas
        }
        missing = sorted(target_landed - observed_landed)
        if missing:
            raise RelationContractError(
                f"landed candidate is not an observed squash unit: {missing[0]}"
            )

    relations: list[dict[str, object]] = []
    pull_roots: list[dict[str, object]] = []
    for pr_number, landed_shas in sorted(squashes_by_pr.items()):
        raw_result = pull_results.get(pr_number)
        member_gaps: dict[str, list[str]] = {}
        if raw_result is None:
            status, reason, members = "BLOCKED", "pull_result_missing", []
        else:
            status = str(raw_result.get("status") or "")
            reason = str(raw_result.get("reason") or "")
            raw_members = raw_result.get("members", [])
            if status not in {"RESOLVED", "BLOCKED"} or not isinstance(
                raw_members, list
            ):
                raise RelationContractError(f"malformed pull result for PR {pr_number}")
            if status == "BLOCKED" and not reason:
                raise RelationContractError(f"blocked pull result lacks reason: PR {pr_number}")
            try:
                members = sorted(
                    {_full_sha(member, field="pull member sha") for member in raw_members}
                )
            except RelationContractError as exc:
                raise RelationContractError(
                    f"malformed pull member for PR {pr_number}"
                ) from exc
            for field in _PULL_MEMBER_GAP_FIELDS:
                raw_gaps = raw_result.get(field, [])
                if not isinstance(raw_gaps, list):
                    raise RelationContractError(
                        f"malformed {field} for PR {pr_number}"
                    )
                gaps = sorted(
                    {_full_sha(sha, field=field) for sha in raw_gaps}
                )
                if gaps:
                    member_gaps[field] = gaps
        ambiguous_fanout = len(landed_shas) > 1
        for landed_sha in sorted(landed_shas):
            eligible = (
                sorted(set(members) - {landed_sha})
                if status == "RESOLVED"
                else []
            )
            observed = sorted(set(eligible) & set(units_by_sha))
            for origin_sha in eligible:
                origin_unit = units_by_sha.get(origin_sha)
                relation = {
                    "relation_id": _stable_id(
                        "cohort-relation",
                        identity,
                        origin_sha,
                        landed_sha,
                        PULL_MEMBER_RELATION,
                    ),
                    "repository_identity": identity,
                    "origin_sha": origin_sha,
                    "landed_sha": landed_sha,
                    "pr_number": pr_number,
                    "relation": PULL_MEMBER_RELATION,
                    "origin_observed_in_cohort": origin_unit is not None,
                    "origin_unit": (
                        _unit_metadata(origin_unit)
                        if origin_unit is not None
                        else {}
                    ),
                    "landed_unit": _unit_metadata(units_by_sha[landed_sha]),
                }
                if ambiguous_fanout:
                    relation["ambiguous_pr_fanout"] = True
                    relation["landed_variant_count"] = len(landed_shas)
                relations.append(relation)
            root = {
                "root_id": _stable_id(
                    "pull-root", identity, str(pr_number), landed_sha
                ),
                "repository_identity": identity,
                "pr_number": pr_number,
                "landed_sha": landed_sha,
                "status": status,
                "reason": (
                    "ambiguous_pr_fanout"
                    if status == "RESOLVED" and ambiguous_fanout
                    else reason
                ),
                "member_count": len(members),
                "eligible_origin_count": len(eligible),
                "eligible_origins_sha256": _sha256_json(eligible),
                "observed_origin_count": len(observed),
                "unobserved_origin_count": len(eligible) - len(observed),
            }
            if ambiguous_fanout:
                root["ambiguous_pr_fanout"] = True
                root["landed_variant_count"] = len(landed_shas)
            root.update(member_gaps)
            pull_roots.append(root)
    relations.sort(key=lambda row: str(row["relation_id"]))
    pull_roots.sort(key=lambda row: str(row["root_id"]))
    resolved = sum(root["status"] == "RESOLVED" for root in pull_roots)
    blocked = sum(root["status"] == "BLOCKED" for root in pull_roots)
    conservation = {
        "pull_root_count": len(pull_roots),
        "resolved_pull_root_count": resolved,
        "blocked_pull_root_count": blocked,
        "pull_roots_conserved": len(pull_roots) == resolved + blocked,
    }
    inventory: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "forward_cohort_pull_relation_inventory",
        "repository_identity": identity,
        "coverage_complete": blocked == 0,
        "relations": relations,
        "pull_roots": pull_roots,
        "relations_sha256": _sha256_json(relations),
        "pull_roots_sha256": _sha256_json(pull_roots),
        "conservation": conservation,
    }
    inventory["inventory_sha256"] = _sha256_json(inventory)
    return inventory


def expand_candidate_edges(
    candidate_edges: Sequence[Mapping[str, object]],
    relations: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Add atomic-origin edges wherever the landed squash already reaches a fix."""

    edges_by_id: dict[str, dict[str, object]] = {}
    for raw in candidate_edges:
        edge_id = str(raw.get("edge_id") or "")
        if not edge_id or edge_id in edges_by_id:
            raise RelationContractError(f"duplicate or missing candidate edge id: {edge_id}")
        edges_by_id[edge_id] = dict(raw)

    relations_by_landed: dict[tuple[str, str], list[Mapping[str, object]]] = {}
    seen_relations: set[str] = set()
    for relation in relations:
        relation_id = str(relation.get("relation_id") or "")
        if not relation_id or relation_id in seen_relations:
            raise RelationContractError(
                f"duplicate or missing relation id: {relation_id}"
            )
        seen_relations.add(relation_id)
        if relation.get("relation") != PULL_MEMBER_RELATION:
            raise RelationContractError(f"unsupported relation: {relation.get('relation')}")
        identity = _identity(
            relation.get("repository_identity"), field="relation repository identity"
        )
        landed_sha = _full_sha(relation.get("landed_sha"), field="landed sha")
        _full_sha(relation.get("origin_sha"), field="origin sha")
        relations_by_landed.setdefault((identity, landed_sha), []).append(relation)

    direct_edges = list(edges_by_id.values())
    for direct in direct_edges:
        if direct.get("relation") != "reachable_ancestor":
            continue
        identity = _identity(
            direct.get("repository_identity"), field="edge repository identity"
        )
        landed_sha = _full_sha(direct.get("candidate_sha"), field="candidate sha")
        fix_sha = _full_sha(direct.get("fix_sha"), field="fix sha")
        for origin_relation in relations_by_landed.get((identity, landed_sha), []):
            origin_sha = _full_sha(origin_relation.get("origin_sha"), field="origin sha")
            composite_id = _stable_id(
                "cohort-edge",
                identity,
                origin_sha,
                landed_sha,
                fix_sha,
                COMPOSITE_RELATION,
            )
            composite = dict(direct)
            origin_unit = origin_relation.get("origin_unit")
            landed_unit = origin_relation.get("landed_unit")
            if not isinstance(origin_unit, Mapping) or not isinstance(
                landed_unit, Mapping
            ):
                raise RelationContractError("pull relation lacks unit metadata")
            for key in _UNIT_METADATA_KEYS:
                composite.pop(key, None)
            composite.update(
                {
                    "edge_id": composite_id,
                    "candidate_sha": origin_sha,
                    "landed_sha": landed_sha,
                    "relation": COMPOSITE_RELATION,
                    "relation_path": [PULL_MEMBER_RELATION, "reachable_ancestor"],
                    "origin_relation_id": str(origin_relation["relation_id"]),
                    "origin_observed_in_cohort": (
                        origin_relation.get("origin_observed_in_cohort") is True
                    ),
                    "relation_pr_number": int(origin_relation["pr_number"]),
                    "landed_unit": _unit_metadata(landed_unit),
                    "initial_status": "DEFER",
                    "initial_reason": "awaiting_screening",
                }
            )
            composite.update(_unit_metadata(origin_unit))
            prior = edges_by_id.get(composite_id)
            if prior is not None and prior != composite:
                raise RelationContractError(f"conflicting composite edge: {composite_id}")
            edges_by_id[composite_id] = composite
    return [edges_by_id[edge_id] for edge_id in sorted(edges_by_id)]
