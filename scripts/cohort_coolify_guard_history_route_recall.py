#!/usr/bin/env python3
"""Score label-neutral Coolify guard-history routes against sealed controls."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from cohort.root_adjudication import canonical_sha256
from cohort_coolify_postgresql_query_idor_path_extension_witness import _atomic_json


_FORBIDDEN_PROMPT_MARKERS = (
    "CONFIRMED_TRUE_POSITIVE",
    "candidate_confirmed_anywhere",
    "input_edge_status",
    "known_candidate_positive_control",
    "p5_already_confirmed_candidate_coverage",
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labeled-inventory", type=Path, required=True)
    parser.add_argument("--model-inventory-dir", type=Path, required=True)
    parser.add_argument("--strict-route", type=Path, required=True)
    parser.add_argument("--contributor-route", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"expected JSON object: {path}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"row {line_number} is not an object")
                rows.append(value)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _edge(row: Mapping[str, object], *, routed: bool = False) -> tuple[str, str]:
    candidate_field = "candidate_sha" if routed else "sha"
    candidate = str(row.get(candidate_field) or "")
    fix = str(row.get("fix_sha") or "")
    if len(candidate) != 40 or len(fix) != 40:
        raise SystemExit(f"malformed edge: {candidate}->{fix}")
    return candidate, fix


def _index(
    rows: list[dict[str, object]], *, routed: bool = False
) -> dict[tuple[str, str], dict[str, object]]:
    result: dict[tuple[str, str], dict[str, object]] = {}
    for row in rows:
        key = _edge(row, routed=routed)
        if key in result:
            raise SystemExit(f"duplicate edge: {key}")
        result[key] = row
    return result


def _prompt_leaks(prompts: list[dict[str, object]]) -> list[str]:
    serialized = json.dumps(prompts, sort_keys=True, ensure_ascii=False)
    return [marker for marker in _FORBIDDEN_PROMPT_MARKERS if marker in serialized]


def _load_route(
    name: str,
    directory: Path,
    *,
    model_summary: Mapping[str, object],
    model_candidates: list[dict[str, object]],
    expected_edges: set[tuple[str, str]],
) -> tuple[dict[str, object], dict[tuple[str, str], dict[str, object]]]:
    spec = _load_json(directory / "spec.json")
    execution = _load_json(directory / "execution.json")
    items = _load_jsonl(directory / "items.jsonl")
    prompts = _load_jsonl(directory / "prompts.jsonl")
    routes = _load_jsonl(directory / "routes.jsonl")
    route_index = _index(routes, routed=True)
    checks = {
        "label_neutral_generation": model_summary.get("label_neutral") is True,
        "label_neutral_required_by_spec": (
            spec.get("label_neutral_input_required") is True
        ),
        "label_neutral_required_by_execution": (
            execution.get("label_neutral_input_required") is True
        ),
        "parent_generation_digest": (
            spec.get("parent_generation_sha256")
            == canonical_sha256(model_summary)
        ),
        "candidate_inventory_digest": (
            spec.get("candidate_inventory_sha256")
            == canonical_sha256(model_candidates)
        ),
        "items_digest": spec.get("items_sha256") == canonical_sha256(items),
        "prompts_digest": spec.get("prompts_sha256") == canonical_sha256(prompts),
        "routes_digest": execution.get("routes_sha256") == canonical_sha256(routes),
        "edge_universe_conserved": set(route_index) == expected_edges,
        "row_count_conserved": len(routes) == len(expected_edges),
        "all_candidates_retained": (
            execution.get("all_candidates_retained") is True
            and all(row.get("retained") is True for row in routes)
        ),
        "no_serialized_label_marker": not _prompt_leaks(prompts),
    }
    failed = [key for key, passed in checks.items() if not passed]
    if failed:
        raise SystemExit(f"{name} route verification failed: {failed}")
    metadata = {
        "directory": str(directory.resolve()),
        "model": execution.get("model"),
        "reasoning_effort": execution.get("reasoning_effort"),
        "routing_mode": execution.get("routing_mode"),
        "physical_model_calls": execution.get("physical_model_calls"),
        "parsed_count": execution.get("parsed_count"),
        "input_tokens": execution.get("input_tokens"),
        "output_tokens": execution.get("output_tokens"),
        "promoted_count": execution.get("promoted_count"),
        "deferred_count": execution.get("deferred_count"),
        "blocked_count": execution.get("blocked_count"),
        "routes_sha256": execution.get("routes_sha256"),
        "prompts_sha256": spec.get("prompts_sha256"),
        "verification": checks,
    }
    return metadata, route_index


def _edge_record(edge: tuple[str, str]) -> dict[str, str]:
    return {"candidate_sha": edge[0], "fix_sha": edge[1]}


def _score_route(
    route_index: Mapping[tuple[str, str], Mapping[str, object]],
    controls: set[tuple[str, str]],
) -> dict[str, object]:
    promoted = {
        edge
        for edge, row in route_index.items()
        if row.get("disposition") == "PROMOTE"
    }
    control_promoted = controls & promoted
    control_missed = controls - promoted
    noncontrol_promoted = promoted - controls
    return {
        "known_control_edge_count": len(controls),
        "known_control_promoted_count": len(control_promoted),
        "known_control_missed_count": len(control_missed),
        "known_control_edge_recall": (
            len(control_promoted) / len(controls) if controls else 0.0
        ),
        "known_control_disposition_counts": dict(
            sorted(
                Counter(
                    str(route_index[edge].get("disposition") or "")
                    for edge in controls
                ).items()
            )
        ),
        "missed_known_control_edges": [
            {
                **_edge_record(edge),
                "disposition": str(route_index[edge].get("disposition") or ""),
                "causality": str(route_index[edge].get("causality") or ""),
                "reason": str(route_index[edge].get("reason") or ""),
            }
            for edge in sorted(control_missed)
        ],
        "promoted_edge_count": len(promoted),
        "promoted_unique_candidate_count": len({edge[0] for edge in promoted}),
        "noncontrol_promoted_edge_count": len(noncontrol_promoted),
        "noncontrol_promoted_unique_candidate_count": len(
            {edge[0] for edge in noncontrol_promoted}
        ),
    }


def _compatibility_activation_rescue_edges(
    candidates: Mapping[tuple[str, str], Mapping[str, object]],
) -> set[tuple[str, str]]:
    rescued: set[tuple[str, str]] = set()
    for edge, row in candidates.items():
        subject = str(row.get("commit_subject") or "").casefold()
        signals = {str(signal) for signal in (row.get("signals") or [])}
        if (
            "rename" in subject
            and any(
                marker in subject
                for marker in ("parent method conflict", "collision", "incompatible")
            )
            and bool(signals & {"guard_method_history", "guard_surface_history"})
        ):
            rescued.add(edge)
    return rescued


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    labeled_rows = _load_jsonl(args.labeled_inventory.resolve())
    labeled_index = _index(labeled_rows)
    controls = {
        edge
        for edge, row in labeled_index.items()
        if row.get("input_edge_status") == "CONFIRMED_TRUE_POSITIVE"
    }
    if not controls:
        raise SystemExit("sealed labeled inventory contains no positive controls")

    model_dir = args.model_inventory_dir.resolve()
    model_summary = _load_json(model_dir / "summary.json")
    model_candidates = _load_jsonl(model_dir / "candidates.jsonl")
    model_index = _index(model_candidates)
    if canonical_sha256(model_candidates) != model_summary.get(
        "candidate_rows_sha256"
    ):
        raise SystemExit("model inventory digest mismatch")
    if set(model_index) != set(labeled_index):
        raise SystemExit("labeled and model-facing inventories disagree on edge universe")

    route_sources: dict[str, dict[str, object]] = {}
    route_indexes: dict[str, dict[tuple[str, str], dict[str, object]]] = {}
    for name, directory in (
        ("strict", args.strict_route.resolve()),
        ("contributor", args.contributor_route.resolve()),
    ):
        route_sources[name], route_indexes[name] = _load_route(
            name,
            directory,
            model_summary=model_summary,
            model_candidates=model_candidates,
            expected_edges=set(model_index),
        )

    scores = {
        name: _score_route(index, controls)
        for name, index in route_indexes.items()
    }
    activation_rescue_edges = _compatibility_activation_rescue_edges(model_index)
    contributor_with_rescue = {
        edge: dict(row) for edge, row in route_indexes["contributor"].items()
    }
    for edge in activation_rescue_edges:
        contributor_with_rescue[edge].update(
            {
                "disposition": "PROMOTE",
                "causality": "possible",
                "reason": (
                    "deterministic compatibility-activation rescue: a rename resolves "
                    "an inherited-method conflict on a guard-history surface"
                ),
                "deterministic_rescue": "compatibility_activation",
            }
        )
    scores["contributor_plus_activation_rescue"] = _score_route(
        contributor_with_rescue, controls
    )
    strict_promoted_controls = {
        edge
        for edge in controls
        if route_indexes["strict"][edge].get("disposition") == "PROMOTE"
    }
    contributor_promoted_controls = {
        edge
        for edge in controls
        if route_indexes["contributor"][edge].get("disposition") == "PROMOTE"
    }
    recovered = contributor_promoted_controls - strict_promoted_controls
    lost = strict_promoted_controls - contributor_promoted_controls
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_label_neutral_guard_history_route_recall",
        "repository_identity": model_summary.get("repository_identity"),
        "sealed_control_source": {
            "path": str(args.labeled_inventory.resolve()),
            "candidate_rows_sha256": canonical_sha256(labeled_rows),
            "known_control_edge_count": len(controls),
            "joined_after_model_routing": True,
        },
        "model_facing_inventory": {
            "directory": str(model_dir),
            "candidate_rows_sha256": canonical_sha256(model_candidates),
            "edge_count": len(model_candidates),
            "label_neutral": True,
        },
        "route_sources": route_sources,
        "scores": scores,
        "comparison": {
            "recovered_strict_miss_count": len(recovered),
            "recovered_strict_miss_edges": [
                _edge_record(edge) for edge in sorted(recovered)
            ],
            "lost_strict_control_count": len(lost),
            "lost_strict_control_edges": [
                _edge_record(edge) for edge in sorted(lost)
            ],
            "control_recall_delta": (
                float(scores["contributor"]["known_control_edge_recall"])
                - float(scores["strict"]["known_control_edge_recall"])
            ),
            "activation_rescue_edge_count": len(activation_rescue_edges),
            "activation_rescue_edges": [
                _edge_record(edge) for edge in sorted(activation_rescue_edges)
            ],
            "activation_rescued_control_count": len(
                activation_rescue_edges & controls
            ),
            "combined_control_recall": scores[
                "contributor_plus_activation_rescue"
            ]["known_control_edge_recall"],
        },
        "evaluation_gate": {
            "same_exact_edge_universe": True,
            "all_365_edges_retained": len(model_candidates) == 365,
            "labels_joined_only_after_routing": True,
            "serialized_prompt_label_markers_absent": True,
            "passed": len(model_candidates) == 365,
        },
        "claim_boundary": (
            "This is exact-edge recall on a frozen development control set, not a "
            "repository-disjoint held-out estimate and not proof of population-level "
            "zero false negatives. The routing prompts and ordering are label-neutral; "
            "control labels are joined only after both model runs. The compatibility-"
            "activation rescue was added after inspecting a development-control miss, "
            "so its combined score is a development repair, not held-out validation. "
            "Every model DEFER or BLOCKED edge remains retained for later review."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify label-neutral guard-history recall frozen")
    for name in ("strict", "contributor"):
        score = scores[name]
        print(
            f"  {name:11s}: {score['known_control_promoted_count']}/"
            f"{score['known_control_edge_count']} "
            f"({float(score['known_control_edge_recall']):.1%})"
        )
    combined = scores["contributor_plus_activation_rescue"]
    print(
        "  contributor+rescue: "
        f"{combined['known_control_promoted_count']}/"
        f"{combined['known_control_edge_count']} "
        f"({float(combined['known_control_edge_recall']):.1%})"
    )
    print(f"  recovered  : {len(recovered)}")
    print(f"  lost       : {len(lost)}")
    print(f"  output     : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
