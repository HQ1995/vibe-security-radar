"""Pure selection, budgeting, and recall-safe routing for an AI pilot."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal, ROUND_CEILING


class RoutingPilotContractError(ValueError):
    """A pilot input would make selection, cost, or routing ambiguous."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256(prefix.encode("ascii"))
    for part in parts:
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return f"{prefix}-{digest.hexdigest()}"


def _date_distance(left: object, right: object) -> int:
    try:
        left_date = datetime.fromisoformat(str(left).replace("Z", "+00:00"))
        right_date = datetime.fromisoformat(str(right).replace("Z", "+00:00"))
    except ValueError:
        return 10**12
    if left_date.tzinfo is None:
        left_date = left_date.replace(tzinfo=right_date.tzinfo)
    if right_date.tzinfo is None:
        right_date = right_date.replace(tzinfo=left_date.tzinfo)
    return int(abs((left_date - right_date).total_seconds()))


def select_blind_pilot_edges(
    expanded_edges: Sequence[Mapping[str, object]],
    controls: Sequence[Mapping[str, object]],
    *,
    comparators_per_control: int,
    require_full_comparators: bool = True,
) -> list[dict[str, object]]:
    """Select controls plus up to N same-fix comparators without prompt labels.

    Sparse fixes must never make a positive control disappear.  Strict mode is
    retained for paired development experiments; held-out recall experiments
    can keep the control and report the smaller comparator stratum.
    """

    if comparators_per_control < 0:
        raise RoutingPilotContractError("comparators_per_control cannot be negative")
    edges = [dict(edge) for edge in expanded_edges]
    selected: list[dict[str, object]] = []
    used_edge_ids: set[str] = set()
    used_candidates: set[tuple[str, str, str]] = set()
    resolved_controls: list[
        tuple[
            Mapping[str, object],
            dict[str, object],
            str,
            str,
            str,
            str,
        ]
    ] = []

    # Resolve and reserve every control before selecting any comparator.  This
    # matters for multi-origin controls that share a fix: a later control must
    # never be consumed as an earlier control's nominally unlabeled comparator.
    for control in controls:
        identity = str(control.get("repository_identity") or "").strip().lower()
        origin = str(control.get("atomic_origin_sha") or "").strip().lower()
        fix = str(control.get("fix_sha") or "").strip().lower()
        relation = str(control.get("expected_relation") or "")
        landed = str(control.get("expected_landed_sha") or "").strip().lower()
        matches = [
            edge
            for edge in edges
            if str(edge.get("repository_identity") or "").lower() == identity
            and str(edge.get("candidate_sha") or "").lower() == origin
            and str(edge.get("fix_sha") or "").lower() == fix
            and str(edge.get("relation") or "") == relation
            and (
                not landed
                or str(edge.get("landed_sha") or "").lower() == landed
            )
        ]
        if len(matches) != 1:
            raise RoutingPilotContractError(
                f"control edge must resolve exactly once: {identity}@{origin}->{fix}"
            )
        control_edge = matches[0]
        control_id = str(control_edge.get("edge_id") or "")
        if not control_id or control_id in used_edge_ids:
            raise RoutingPilotContractError("control edge identity is missing or duplicated")
        selected.append(
            {
                "pilot_item_id": _stable_id("routing-pilot-item", control_id),
                "evaluation_role": "control",
                "control_advisory": str(control.get("advisory") or ""),
                "edge": control_edge,
            }
        )
        used_edge_ids.add(control_id)
        used_candidates.add((identity, origin, fix))
        resolved_controls.append(
            (control, control_edge, identity, origin, fix, relation)
        )

    if comparators_per_control == 0:
        return sorted(selected, key=lambda row: str(row["pilot_item_id"]))

    for control, control_edge, identity, origin, fix, relation in resolved_controls:
        candidates = [
            edge
            for edge in edges
            if str(edge.get("repository_identity") or "").lower() == identity
            and str(edge.get("fix_sha") or "").lower() == fix
            and str(edge.get("candidate_sha") or "").lower() != origin
        ]
        candidates.sort(
            key=lambda edge: (
                str(edge.get("relation") or "") != relation,
                _date_distance(
                    edge.get("authored_date"), control_edge.get("authored_date")
                ),
                str(edge.get("candidate_sha") or ""),
                str(edge.get("edge_id") or ""),
            )
        )
        added = 0
        for candidate in candidates:
            edge_id = str(candidate.get("edge_id") or "")
            candidate_key = (
                identity,
                str(candidate.get("candidate_sha") or "").lower(),
                fix,
            )
            if not edge_id or edge_id in used_edge_ids or candidate_key in used_candidates:
                continue
            selected.append(
                {
                    "pilot_item_id": _stable_id("routing-pilot-item", edge_id),
                    "evaluation_role": "unlabeled_comparator",
                    "matched_control_advisory": str(control.get("advisory") or ""),
                    "edge": candidate,
                }
            )
            used_edge_ids.add(edge_id)
            used_candidates.add(candidate_key)
            added += 1
            if added == comparators_per_control:
                break
        if require_full_comparators and added != comparators_per_control:
            raise RoutingPilotContractError(
                f"not enough same-fix comparators for {identity}@{fix}"
            )
    return sorted(selected, key=lambda row: str(row["pilot_item_id"]))


def build_budget_contract(
    prompts: Sequence[Mapping[str, object]],
    *,
    input_usd_per_million: str,
    output_usd_per_million: str,
    max_output_tokens: int,
    max_cost_usd: str,
) -> dict[str, object]:
    """Reserve against a byte-safe input ceiling before any model call."""

    if max_output_tokens < 1:
        raise RoutingPilotContractError("max_output_tokens must be positive")
    input_price = Decimal(input_usd_per_million)
    output_price = Decimal(output_usd_per_million)
    cap = Decimal(max_cost_usd)
    if min(input_price, output_price, cap) < 0 or cap == 0:
        raise RoutingPilotContractError("prices and cap must be non-negative; cap positive")
    reservations: list[dict[str, object]] = []
    total_microusd = 0
    for prompt in prompts:
        item_id = str(prompt.get("pilot_item_id") or "")
        system = str(prompt.get("system_prompt") or "")
        user = str(prompt.get("user_prompt") or "")
        if not item_id or not system or not user:
            raise RoutingPilotContractError("every prompt requires identity and content")
        # Byte fallback makes this deliberately looser than any normal tokenizer.
        input_ceiling = len(system.encode("utf-8")) + len(user.encode("utf-8")) + 1024
        cost_usd = (
            Decimal(input_ceiling) * input_price
            + Decimal(max_output_tokens) * output_price
        ) / Decimal(1_000_000)
        microusd = int(
            (cost_usd * Decimal(1_000_000)).to_integral_value(
                rounding=ROUND_CEILING
            )
        )
        total_microusd += microusd
        reservations.append(
            {
                "pilot_item_id": item_id,
                "max_input_tokens": input_ceiling,
                "max_output_tokens": max_output_tokens,
                "reservation_microusd": microusd,
            }
        )
    cap_microusd = int(
        (cap * Decimal(1_000_000)).to_integral_value(rounding=ROUND_CEILING)
    )
    if total_microusd > cap_microusd:
        raise RoutingPilotContractError(
            f"worst-case reservation exceeds cap: {total_microusd}>{cap_microusd} microusd"
        )
    return {
        "input_usd_per_million_tokens": format(input_price, "f"),
        "output_usd_per_million_tokens": format(output_price, "f"),
        "max_output_tokens_per_request": max_output_tokens,
        "max_physical_requests": len(prompts),
        "max_cost_microusd": cap_microusd,
        "worst_case_reservation_microusd": total_microusd,
        "reservations": reservations,
    }


def evaluate_pilot_results(
    items: Sequence[Mapping[str, object]],
    results: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Route every pilot edge once; low scores remain DEFER, never deleted."""

    item_by_id = {str(item.get("pilot_item_id") or ""): item for item in items}
    if "" in item_by_id or len(item_by_id) != len(items):
        raise RoutingPilotContractError("pilot item identities are missing or duplicated")
    result_by_id = {str(row.get("pilot_item_id") or ""): row for row in results}
    if "" in result_by_id or len(result_by_id) != len(results):
        raise RoutingPilotContractError("pilot result identities are missing or duplicated")
    if set(result_by_id) - set(item_by_id):
        raise RoutingPilotContractError("result names an unknown pilot item")

    routes: list[dict[str, object]] = []
    control_total = 0
    control_promoted = 0
    comparator_total = 0
    comparator_promoted = 0
    counts: Counter[str] = Counter()
    for item_id in sorted(item_by_id):
        item = item_by_id[item_id]
        result = result_by_id.get(item_id)
        causality = str((result or {}).get("causality") or "").lower()
        result_status = str((result or {}).get("result_status") or "missing")
        if result is None or result_status != "completed" or causality not in {
            "likely",
            "possible",
            "unlikely",
            "insufficient",
        }:
            status, reason = "BLOCKED", f"model_result_{result_status}"
        elif causality in {"likely", "possible"}:
            status, reason = "PROMOTE", f"model_{causality}"
        else:
            status, reason = "DEFER", f"model_{causality}"
        role = str(item.get("evaluation_role") or "")
        if role == "control":
            control_total += 1
            control_promoted += status == "PROMOTE"
        elif role == "unlabeled_comparator":
            comparator_total += 1
            comparator_promoted += status == "PROMOTE"
        else:
            raise RoutingPilotContractError(f"unknown evaluation role: {role}")
        edge = item.get("edge")
        if not isinstance(edge, Mapping):
            raise RoutingPilotContractError("pilot item lacks an edge")
        counts[status] += 1
        routes.append(
            {
                "pilot_item_id": item_id,
                "edge_id": str(edge.get("edge_id") or ""),
                "evaluation_role": role,
                "status": status,
                "reason": reason,
                "causality": causality,
            }
        )
    return {
        "routes": routes,
        "counts": {key: counts[key] for key in ("PROMOTE", "DEFER", "BLOCKED")},
        "control_count": control_total,
        "control_promoted_count": control_promoted,
        "control_routing_recall": (
            control_promoted / control_total if control_total else 0.0
        ),
        "unlabeled_comparator_count": comparator_total,
        "unlabeled_comparator_promoted_count": comparator_promoted,
        "unlabeled_comparator_promotion_rate": (
            comparator_promoted / comparator_total if comparator_total else 0.0
        ),
        "routing_conserved": len(routes) == sum(counts.values()),
        "scale_gate_passed": bool(control_total) and control_promoted == control_total,
    }
