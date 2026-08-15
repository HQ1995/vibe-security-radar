#!/usr/bin/env python3
"""Build a lossless, label-neutral source-review queue for Coolify guard history."""

from __future__ import annotations

import argparse
import hashlib
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path

from cohort.root_adjudication import canonical_sha256
from cohort_coolify_guard_history_route_recall import (
    _compatibility_activation_rescue_edges,
    _index,
    _load_json,
    _load_jsonl,
    _load_route,
)
from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
)


REPOSITORY_IDENTITY = "github.com/coollabsio/coolify"

ROUTED_LANE_ORDER = (
    "removed_control_or_reachability_gate",
    "additive_method_or_file",
    "new_sink_or_exposure",
    "same_method_guard_history",
    "whole_file_or_carrier",
    "dual_route_consensus",
    "deterministic_compatibility_activation",
    "strict_only_promotion",
    "other_contributor",
    "other_routed_promotion",
)

BACKLOG_LANE_ORDER = (
    "removed_control_or_reachability_gate",
    "additive_method_or_file",
    "new_sink_or_exposure",
    "same_method_guard_history",
    "whole_file_or_carrier",
    "retained_guard_history_backlog",
)


Edge = tuple[str, str]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-inventory-dir", type=Path, required=True)
    parser.add_argument("--strict-route", type=Path, required=True)
    parser.add_argument("--contributor-route", type=Path, required=True)
    parser.add_argument("--recall", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--method-schedule", type=Path, required=True)
    parser.add_argument("--surface-schedule", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _edge_record(edge: Edge) -> dict[str, str]:
    return {"candidate_sha": edge[0], "fix_sha": edge[1]}


def _row_edge(row: Mapping[str, object]) -> Edge:
    candidate = str(row.get("candidate_sha") or "")
    fix = str(row.get("fix_sha") or "")
    if len(candidate) != 40 or len(fix) != 40:
        raise SystemExit(f"malformed edge: {candidate}->{fix}")
    return candidate, fix


def _index_rows(rows: Iterable[Mapping[str, object]]) -> dict[Edge, Mapping[str, object]]:
    index: dict[Edge, Mapping[str, object]] = {}
    for row in rows:
        edge = _row_edge(row)
        if edge in index:
            raise SystemExit(f"duplicate edge: {edge[0]}->{edge[1]}")
        index[edge] = row
    return index


def _group_schedule_rows(
    rows: Iterable[Mapping[str, object]], expected_edges: set[Edge]
) -> dict[Edge, list[Mapping[str, object]]]:
    grouped: dict[Edge, list[Mapping[str, object]]] = defaultdict(list)
    for row in rows:
        edge = _row_edge(row)
        if edge in expected_edges:
            grouped[edge].append(row)
    return dict(grouped)


def _is_additive_delta(row: Mapping[str, object]) -> bool:
    delta_kind = str(row.get("delta_kind") or "")
    return delta_kind.startswith("ADD_") or row.get("whole_file_addition") is True


def _structural_lanes(
    method_rows: Iterable[Mapping[str, object]],
    surface_rows: Iterable[Mapping[str, object]],
) -> set[str]:
    methods = list(method_rows)
    surfaces = list(surface_rows)
    lanes: set[str] = set()
    if any(
        int(row.get("candidate_removed_control_line_count") or 0) > 0
        or row.get("candidate_removed_reachability_gate") is True
        for row in methods
    ):
        lanes.add("removed_control_or_reachability_gate")
    if any(_is_additive_delta(row) for row in [*methods, *surfaces]):
        lanes.add("additive_method_or_file")
    if methods:
        lanes.add("same_method_guard_history")
    if any(
        int(row.get("candidate_added_sink_line_count") or 0) > 0
        or int(row.get("candidate_novel_sink_line_count") or 0) > 0
        for row in methods
    ) or any(
        int(row.get("candidate_exposure_line_count") or 0) > 0
        for row in surfaces
    ):
        lanes.add("new_sink_or_exposure")
    if any(
        row.get("whole_file_addition") is True or row.get("carrier_risk") is True
        for row in [*methods, *surfaces]
    ):
        lanes.add("whole_file_or_carrier")
    return lanes


def _route_lanes(
    edge: Edge,
    *,
    strict_promoted: set[Edge],
    contributor_promoted: set[Edge],
    activation_rescued: set[Edge],
) -> set[str]:
    lanes: set[str] = set()
    strict = edge in strict_promoted
    contributor = edge in contributor_promoted
    rescued = edge in activation_rescued
    if strict and contributor:
        lanes.add("dual_route_consensus")
    if strict and not contributor:
        lanes.add("strict_only_promotion")
    if contributor and not strict:
        lanes.add("other_contributor")
    if rescued:
        lanes.add("deterministic_compatibility_activation")
    if (strict or contributor or rescued) and not lanes:
        lanes.add("other_routed_promotion")
    return lanes


def _round_robin(
    lane_order: Iterable[str],
    lane_edges: Mapping[str, list[Edge]],
    universe: set[Edge],
) -> list[Edge]:
    """Take one unseen edge per lane per cycle, then append any remainder."""

    ordered_lanes = list(lane_order)
    offsets = {lane: 0 for lane in ordered_lanes}
    seen: set[Edge] = set()
    result: list[Edge] = []
    while True:
        progressed = False
        for lane in ordered_lanes:
            rows = lane_edges.get(lane, [])
            offset = offsets[lane]
            while offset < len(rows) and rows[offset] in seen:
                offset += 1
            offsets[lane] = offset
            if offset >= len(rows):
                continue
            edge = rows[offset]
            offsets[lane] += 1
            if edge not in universe:
                raise SystemExit(f"lane {lane} contains an out-of-universe edge")
            seen.add(edge)
            result.append(edge)
            progressed = True
        if not progressed:
            break
    result.extend(sorted(universe - seen))
    return result


def _neutral_method_evidence(row: Mapping[str, object]) -> dict[str, object]:
    fields = (
        "path",
        "method",
        "delta_kind",
        "whole_file_addition",
        "carrier_risk",
        "candidate_added_lines",
        "candidate_removed_lines",
        "candidate_added_sink_lines",
        "candidate_novel_sink_lines",
        "candidate_removed_sink_lines",
        "candidate_removed_control_lines",
        "candidate_removed_reachability_gate",
        "repair_added_lines",
    )
    return {field: row.get(field) for field in fields}


def _neutral_surface_evidence(row: Mapping[str, object]) -> dict[str, object]:
    fields = (
        "path",
        "surface_kind",
        "delta_kind",
        "whole_file_addition",
        "carrier_risk",
        "candidate_added_lines",
        "candidate_removed_lines",
        "candidate_exposure_lines",
        "repair_added_lines",
        "repair_has_explicit_surface_control",
    )
    return {field: row.get(field) for field in fields}


def _row_sort_key(row: Mapping[str, object]) -> tuple[object, ...]:
    lanes = set(row.get("lanes") or [])
    lane_index = min(
        (
            ROUTED_LANE_ORDER.index(lane)
            for lane in lanes
            if lane in ROUTED_LANE_ORDER
        ),
        default=len(ROUTED_LANE_ORDER),
    )
    method_rows = list(row.get("method_evidence") or [])
    surface_rows = list(row.get("surface_evidence") or [])
    removed_count = sum(
        len(evidence.get("candidate_removed_control_lines") or [])
        for evidence in method_rows
        if isinstance(evidence, Mapping)
    )
    sink_or_exposure_count = sum(
        len(evidence.get("candidate_added_sink_lines") or [])
        + len(evidence.get("candidate_novel_sink_lines") or [])
        for evidence in method_rows
        if isinstance(evidence, Mapping)
    ) + sum(
        len(evidence.get("candidate_exposure_lines") or [])
        for evidence in surface_rows
        if isinstance(evidence, Mapping)
    )
    return (
        lane_index,
        -removed_count,
        -sink_or_exposure_count,
        str(row.get("fix_sha") or ""),
        str(row.get("candidate_sha") or ""),
    )


def _primary_lane(lanes: set[str], order: Iterable[str]) -> str:
    for lane in order:
        if lane in lanes:
            return lane
    raise SystemExit("edge has no review lane")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    model_dir = args.model_inventory_dir.resolve()
    model_summary = _load_json(model_dir / "summary.json")
    model_candidates = _load_jsonl(model_dir / "candidates.jsonl")
    if model_summary.get("label_neutral") is not True:
        raise SystemExit("model inventory is not label-neutral")
    if canonical_sha256(model_candidates) != model_summary.get(
        "candidate_rows_sha256"
    ):
        raise SystemExit("model inventory digest mismatch")
    model_index = _index(model_candidates)
    expected_edges = set(model_index)
    if len(expected_edges) != 365:
        raise SystemExit(f"expected frozen 365-edge universe, got {len(expected_edges)}")

    route_sources: dict[str, dict[str, object]] = {}
    route_indexes: dict[str, dict[Edge, dict[str, object]]] = {}
    for name, directory in (
        ("strict", args.strict_route.resolve()),
        ("contributor", args.contributor_route.resolve()),
    ):
        route_sources[name], route_indexes[name] = _load_route(
            name,
            directory,
            model_summary=model_summary,
            model_candidates=model_candidates,
            expected_edges=expected_edges,
        )

    strict_promoted = {
        edge
        for edge, row in route_indexes["strict"].items()
        if row.get("disposition") == "PROMOTE"
    }
    contributor_promoted = {
        edge
        for edge, row in route_indexes["contributor"].items()
        if row.get("disposition") == "PROMOTE"
    }
    activation_rescued = _compatibility_activation_rescue_edges(model_index)
    combined_promoted = strict_promoted | contributor_promoted | activation_rescued

    recall_path = args.recall.resolve()
    recall = _load_json(recall_path)
    recalled_rescues = {
        (str(row["candidate_sha"]), str(row["fix_sha"]))
        for row in recall.get("comparison", {}).get(
            "activation_rescue_edges", []
        )
        if isinstance(row, Mapping)
    }
    if recall.get("evaluation_gate", {}).get("passed") is not True:
        raise SystemExit("recall artifact did not pass its evaluation gate")
    if recalled_rescues != activation_rescued:
        raise SystemExit("recall artifact and deterministic rescue disagree")

    ledger_path = args.ledger.resolve()
    ledger = _load_json(ledger_path)
    if ledger.get("conservation", {}).get("passed") is not True:
        raise SystemExit("ledger conservation gate failed")
    ledger_rows = ledger.get("edge_ledger")
    if not isinstance(ledger_rows, list):
        raise SystemExit("ledger edge_ledger is missing")
    ledger_index = _index_rows(ledger_rows)
    if not expected_edges <= set(ledger_index):
        raise SystemExit("ledger is missing model-facing edges")

    method_path = args.method_schedule.resolve()
    surface_path = args.surface_schedule.resolve()
    method_schedule = _load_json(method_path)
    surface_schedule = _load_json(surface_path)
    for name, schedule in (
        ("method", method_schedule),
        ("surface", surface_schedule),
    ):
        conservation = schedule.get("conservation", {})
        if (
            conservation.get("schedule_is_additive") is not True
            or conservation.get("all_scheduled_rows_retained") is not True
        ):
            raise SystemExit(f"{name} schedule is not recall-conserving")
    method_rows = method_schedule.get("rows")
    surface_rows = surface_schedule.get("rows")
    if not isinstance(method_rows, list) or not isinstance(surface_rows, list):
        raise SystemExit("schedule rows are missing")
    methods_by_edge = _group_schedule_rows(method_rows, expected_edges)
    surfaces_by_edge = _group_schedule_rows(surface_rows, expected_edges)

    confirmed_candidates = {
        edge[0]
        for edge, row in ledger_index.items()
        if row.get("status") == "CONFIRMED_TRUE_POSITIVE"
    }
    route_neutral_rows: list[dict[str, object]] = []
    for edge in sorted(expected_edges):
        model_row = model_index[edge]
        neutral_methods = [
            _neutral_method_evidence(row)
            for row in methods_by_edge.get(edge, [])
        ]
        neutral_surfaces = [
            _neutral_surface_evidence(row)
            for row in surfaces_by_edge.get(edge, [])
        ]
        structural = _structural_lanes(
            methods_by_edge.get(edge, []), surfaces_by_edge.get(edge, [])
        )
        routed = _route_lanes(
            edge,
            strict_promoted=strict_promoted,
            contributor_promoted=contributor_promoted,
            activation_rescued=activation_rescued,
        )
        lanes = structural | routed
        routed_stage = edge in combined_promoted
        if not routed_stage:
            lanes.add("retained_guard_history_backlog")
        lane_order = ROUTED_LANE_ORDER if routed_stage else BACKLOG_LANE_ORDER
        row = {
            **_edge_record(edge),
            "advisory": model_row.get("advisory"),
            "candidate_subject": model_row.get("commit_subject"),
            "candidate_authored_date": model_row.get("authored_date"),
            "candidate_changed_files": model_row.get("changed_files"),
            "fix_file_overlap": model_row.get("fix_file_overlap"),
            "signals": model_row.get("signals"),
            "guard_history_lanes": model_row.get("guard_history_lanes"),
            "strict_route": {
                "disposition": route_indexes["strict"][edge].get("disposition"),
                "causality": route_indexes["strict"][edge].get("causality"),
                "reason": route_indexes["strict"][edge].get("reason"),
            },
            "contributor_route": {
                "disposition": route_indexes["contributor"][edge].get(
                    "disposition"
                ),
                "causality": route_indexes["contributor"][edge].get("causality"),
                "reason": route_indexes["contributor"][edge].get("reason"),
            },
            "deterministic_compatibility_activation": (
                edge in activation_rescued
            ),
            "routing_stage": (
                "ROUTED_PROMOTION" if routed_stage else "RETAINED_BACKLOG"
            ),
            "lanes": [lane for lane in lane_order if lane in lanes],
            "primary_lane": _primary_lane(lanes, lane_order),
            "method_evidence": neutral_methods,
            "surface_evidence": neutral_surfaces,
            "retained_for_source_review": True,
        }
        route_neutral_rows.append(row)

    row_index = {
        _row_edge(row): row for row in route_neutral_rows
    }
    routed_lane_edges: dict[str, list[Edge]] = {}
    backlog_lane_edges: dict[str, list[Edge]] = {}
    for lane_order, universe, target in (
        (ROUTED_LANE_ORDER, combined_promoted, routed_lane_edges),
        (BACKLOG_LANE_ORDER, expected_edges - combined_promoted, backlog_lane_edges),
    ):
        for lane in lane_order:
            members = [
                edge
                for edge in universe
                if lane in set(row_index[edge]["lanes"])
            ]
            target[lane] = sorted(members, key=lambda edge: _row_sort_key(row_index[edge]))

    routed_order = _round_robin(
        ROUTED_LANE_ORDER, routed_lane_edges, combined_promoted
    )
    backlog_order = _round_robin(
        BACKLOG_LANE_ORDER,
        backlog_lane_edges,
        expected_edges - combined_promoted,
    )
    route_neutral_order = routed_order + backlog_order
    if len(route_neutral_order) != len(set(route_neutral_order)):
        raise SystemExit("review order contains duplicate edges")
    if set(route_neutral_order) != expected_edges:
        raise SystemExit("review order does not conserve the edge universe")

    post_route_rows: list[dict[str, object]] = []
    pending_order: list[dict[str, object]] = []
    confirmed_order: list[dict[str, object]] = []
    rejected_order: list[dict[str, object]] = []
    for neutral_rank, edge in enumerate(route_neutral_order, start=1):
        ledger_row = ledger_index[edge]
        post_route = {
            **_edge_record(edge),
            "route_neutral_rank": neutral_rank,
            "routing_stage": row_index[edge]["routing_stage"],
            "primary_lane": row_index[edge]["primary_lane"],
            "lanes": row_index[edge]["lanes"],
            "ledger_status": ledger_row.get("status"),
            "ledger_adjudication": ledger_row.get("adjudication"),
            "candidate_confirmed_anywhere": edge[0] in confirmed_candidates,
        }
        post_route_rows.append(post_route)
        status = str(ledger_row.get("status") or "")
        if status == "CONFIRMED_TRUE_POSITIVE":
            confirmed_order.append(post_route)
        elif status == "REJECTED_NONCAUSAL":
            rejected_order.append(post_route)
        else:
            pending_order.append(post_route)
    for rank, row in enumerate(pending_order, start=1):
        row["pending_rank"] = rank

    status_counts = Counter(
        str(ledger_index[edge].get("status") or "") for edge in expected_edges
    )
    lane_counts = Counter(
        lane for row in route_neutral_rows for lane in row["lanes"]
    )
    routed_pending = sum(
        row["routing_stage"] == "ROUTED_PROMOTION" for row in pending_order
    )
    novel_pending = [
        row for row in pending_order if row["candidate_confirmed_anywhere"] is False
    ]
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_label_neutral_source_review_queue",
        "repository_identity": REPOSITORY_IDENTITY,
        "inputs": {
            "model_inventory_directory": str(model_dir),
            "model_candidate_rows_sha256": canonical_sha256(model_candidates),
            "strict_route": route_sources["strict"],
            "contributor_route": route_sources["contributor"],
            "recall": {"path": str(recall_path), "sha256": _sha256(recall_path)},
            "ledger": {"path": str(ledger_path), "sha256": _sha256(ledger_path)},
            "method_schedule": {
                "path": str(method_path),
                "sha256": _sha256(method_path),
            },
            "surface_schedule": {
                "path": str(surface_path),
                "sha256": _sha256(surface_path),
            },
        },
        "summary": {
            "finite_model_edge_count": len(expected_edges),
            "strict_promoted_edge_count": len(strict_promoted),
            "contributor_promoted_edge_count": len(contributor_promoted),
            "deterministic_rescue_edge_count": len(activation_rescued),
            "strict_only_promoted_edge_count": len(
                strict_promoted - contributor_promoted - activation_rescued
            ),
            "routed_union_edge_count": len(combined_promoted),
            "retained_backlog_edge_count": len(expected_edges - combined_promoted),
            "post_route_status_counts": dict(sorted(status_counts.items())),
            "pending_edge_count": len(pending_order),
            "pending_routed_edge_count": routed_pending,
            "pending_backlog_edge_count": len(pending_order) - routed_pending,
            "pending_novel_candidate_edge_count": len(novel_pending),
            "pending_novel_candidate_count": len(
                {row["candidate_sha"] for row in novel_pending}
            ),
            "lane_membership_counts": dict(sorted(lane_counts.items())),
        },
        "lane_contract": {
            "routed_stage_lane_order": list(ROUTED_LANE_ORDER),
            "backlog_stage_lane_order": list(BACKLOG_LANE_ORDER),
            "round_robin_one_unseen_edge_per_lane_per_cycle": True,
            "deletion_only_and_additive_lanes_are_independent": True,
            "labels_do_not_affect_route_neutral_order": True,
        },
        "conservation": {
            "input_edge_count": len(expected_edges),
            "row_count": len(route_neutral_rows),
            "route_neutral_order_count": len(route_neutral_order),
            "route_neutral_order_unique_count": len(set(route_neutral_order)),
            "routed_union_plus_backlog_count": (
                len(combined_promoted) + len(expected_edges - combined_promoted)
            ),
            "post_route_partition_count": (
                len(pending_order) + len(confirmed_order) + len(rejected_order)
            ),
            "hard_delete_count": 0,
            "model_defer_as_negative_count": 0,
            "all_rows_retained": all(
                row["retained_for_source_review"] is True
                for row in route_neutral_rows
            ),
            "passed": (
                len(route_neutral_rows)
                == len(route_neutral_order)
                == len(set(route_neutral_order))
                == len(expected_edges)
                and len(pending_order) + len(confirmed_order) + len(rejected_order)
                == len(expected_edges)
            ),
        },
        "route_neutral_rows": route_neutral_rows,
        "route_neutral_review_order": [
            {
                **_edge_record(edge),
                "rank": rank,
                "routing_stage": row_index[edge]["routing_stage"],
                "primary_lane": row_index[edge]["primary_lane"],
                "lanes": row_index[edge]["lanes"],
            }
            for rank, edge in enumerate(route_neutral_order, start=1)
        ],
        "post_route_rows": post_route_rows,
        "pending_review_order": pending_order,
        "pending_novel_candidate_order": novel_pending,
        "confirmed_edge_order": confirmed_order,
        "rejected_edge_order": rejected_order,
        "claim_boundary": (
            "This artifact schedules source review; it is not a causal label set. "
            "The 365-edge ordering is computed from label-neutral route outputs and "
            "raw structural deltas only. Ledger labels are joined afterward solely "
            "to partition already confirmed, rejected, and pending work. Strict, "
            "contributor, and deterministic promotions are unioned, while every "
            "model DEFER or BLOCKED edge remains in the second-stage backlog. A "
            "source-level witness is required before adding any true-positive edge."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify label-neutral source-review queue frozen")
    print(f"  finite edges      : {len(expected_edges)}")
    print(f"  routed union      : {len(combined_promoted)}")
    print(f"  retained backlog  : {len(expected_edges - combined_promoted)}")
    print(f"  pending routed    : {routed_pending}")
    print(f"  pending novel AI  : {len(novel_pending)} edges")
    print(f"  conservation      : {payload['conservation']['passed']}")
    print(f"  output            : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
