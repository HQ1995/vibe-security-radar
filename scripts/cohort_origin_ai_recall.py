#!/usr/bin/env python3
"""Evaluate frozen origin-routing artifacts against separately loaded controls."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path

from cohort.origin_controls import flatten_origin_controls
from cohort.root_adjudication import canonical_sha256


_BUDGETS = (1, 5, 10, 25, 50, 100)
_DISPOSITION_ORDER = {"PROMOTE": 0, "BLOCKED": 1, "DEFER": 2}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-dir", type=Path, required=True)
    parser.add_argument("--controls", type=Path, required=True)
    parser.add_argument(
        "--route",
        action="append",
        required=True,
        metavar="NAME=DIR",
        help="A unique comparison name and frozen cohort_origin_ai_route output.",
    )
    parser.add_argument("--repository-identity")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain an object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _candidate_key(row: Mapping[str, object], *, routed: bool = False) -> tuple[str, ...]:
    sha_field = "candidate_sha" if routed else "sha"
    return (
        str(row.get("advisory") or ""),
        str(row.get("repository_identity") or ""),
        str(row.get("fix_sha") or ""),
        str(row.get(sha_field) or ""),
    )


def _fix_key(row: Mapping[str, object]) -> tuple[str, ...]:
    return (
        str(row.get("advisory") or ""),
        str(row.get("repository_identity") or ""),
        str(row.get("fix_sha") or ""),
    )


def _route_specs(specifications: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for specification in specifications:
        name, separator, path_text = specification.partition("=")
        name = name.strip()
        if not separator or not name or not path_text.strip():
            raise SystemExit("route must use NAME=DIR")
        if name in result:
            raise SystemExit(f"duplicate route name: {name}")
        path = Path(path_text).resolve()
        if not path.is_dir():
            raise SystemExit(f"route directory unavailable: {path}")
        result[name] = path
    return result


def _rank_map(
    candidates: list[dict[str, object]],
    routes: Mapping[tuple[str, ...], Mapping[str, object]] | None = None,
) -> dict[tuple[str, ...], int]:
    grouped: dict[tuple[str, ...], list[dict[str, object]]] = {}
    for candidate in candidates:
        grouped.setdefault(_fix_key(candidate), []).append(candidate)
    result: dict[tuple[str, ...], int] = {}
    for rows in grouped.values():
        def ordering(row: Mapping[str, object]) -> tuple[int, int, str]:
            key = _candidate_key(row)
            if routes is None:
                tier = 0
            else:
                disposition = str(routes[key].get("disposition") or "")
                if disposition not in _DISPOSITION_ORDER:
                    raise SystemExit(f"unknown routing disposition: {disposition!r}")
                tier = _DISPOSITION_ORDER[disposition]
            return tier, int(row.get("priority_rank") or 0), key[-1]

        for rank, candidate in enumerate(sorted(rows, key=ordering), start=1):
            result[_candidate_key(candidate)] = rank
    return result


def _ensemble_rank_map(
    candidates: list[dict[str, object]],
    route_indexes: Mapping[str, Mapping[tuple[str, ...], Mapping[str, object]]],
) -> dict[tuple[str, ...], int]:
    grouped: dict[tuple[str, ...], list[dict[str, object]]] = {}
    for candidate in candidates:
        grouped.setdefault(_fix_key(candidate), []).append(candidate)
    result: dict[tuple[str, ...], int] = {}
    for rows in grouped.values():
        def ordering(row: Mapping[str, object]) -> tuple[int, int, str]:
            key = _candidate_key(row)
            dispositions = {
                str(index[key].get("disposition") or "")
                for index in route_indexes.values()
            }
            if not dispositions <= set(_DISPOSITION_ORDER):
                raise SystemExit(f"unknown ensemble disposition: {sorted(dispositions)!r}")
            if dispositions == {"PROMOTE"}:
                tier = 0
            elif "PROMOTE" in dispositions:
                tier = 1
            elif "BLOCKED" in dispositions:
                tier = 2
            else:
                tier = 3
            return tier, int(row.get("priority_rank") or 0), key[-1]

        for rank, candidate in enumerate(sorted(rows, key=ordering), start=1):
            result[_candidate_key(candidate)] = rank
    return result


def _recall_at_budget(ranks: list[int | None]) -> dict[str, float]:
    denominator = len(ranks)
    return {
        str(budget): (
            sum(rank is not None and rank <= budget for rank in ranks) / denominator
            if denominator
            else 0.0
        )
        for budget in _BUDGETS
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    generated_summary = _load_json(args.generated_dir / "summary.json")
    candidates = _load_jsonl(args.generated_dir / "candidates.jsonl")
    if canonical_sha256(candidates) != generated_summary.get("candidate_rows_sha256"):
        raise SystemExit("generated candidate digest mismatch")
    candidate_keys = [_candidate_key(row) for row in candidates]
    if len(candidate_keys) != len(set(candidate_keys)):
        raise SystemExit("generated candidate inventory contains duplicate keys")
    candidate_key_set = set(candidate_keys)

    route_indexes: dict[str, dict[tuple[str, ...], dict[str, object]]] = {}
    route_summaries: dict[str, dict[str, object]] = {}
    for name, directory in _route_specs(args.route).items():
        spec = _load_json(directory / "spec.json")
        execution = _load_json(directory / "execution.json")
        routes = _load_jsonl(directory / "routes.jsonl")
        if spec.get("parent_generation_sha256") != canonical_sha256(generated_summary):
            raise SystemExit(f"{name}: parent generation digest mismatch")
        if spec.get("candidate_inventory_sha256") != canonical_sha256(candidates):
            raise SystemExit(f"{name}: candidate inventory digest mismatch")
        if execution.get("routes_sha256") != canonical_sha256(routes):
            raise SystemExit(f"{name}: route digest mismatch")
        route_keys = [_candidate_key(row, routed=True) for row in routes]
        if len(route_keys) != len(set(route_keys)):
            raise SystemExit(f"{name}: route inventory contains duplicate keys")
        if set(route_keys) != candidate_key_set:
            raise SystemExit(f"{name}: route inventory does not conserve candidates")
        if execution.get("all_candidates_retained") is not True or not all(
            row.get("retained") is True for row in routes
        ):
            raise SystemExit(f"{name}: route inventory contains a dropped candidate")
        route_indexes[name] = dict(zip(route_keys, routes, strict=True))
        route_summaries[name] = {
            "model": execution.get("model"),
            "reasoning_effort": execution.get("reasoning_effort"),
            "physical_model_calls": execution.get("physical_model_calls"),
            "parsed_count": execution.get("parsed_count"),
            "promoted_count": execution.get("promoted_count"),
            "blocked_count": execution.get("blocked_count"),
            "input_tokens": execution.get("input_tokens"),
            "output_tokens": execution.get("output_tokens"),
            "route_execution_sha256": canonical_sha256(execution),
        }

    controls_payload = _load_json(args.controls)
    requested_identity = str(args.repository_identity or "").strip().lower()
    controls = [
        row
        for row in flatten_origin_controls(controls_payload)
        if not requested_identity or row.get("repository_identity") == requested_identity
    ]
    if not controls:
        raise SystemExit("no controls match evaluation scope")

    base_ranks = _rank_map(candidates)
    routed_ranks = {
        name: _rank_map(candidates, index) for name, index in route_indexes.items()
    }
    ensemble_ranks = _ensemble_rank_map(candidates, route_indexes)
    rows: list[dict[str, object]] = []
    for control in controls:
        assert isinstance(control, Mapping)
        origin_sha = str(
            control.get("expected_landed_sha")
            or control.get("atomic_origin_sha")
            or ""
        )
        key = (*_fix_key(control), origin_sha)
        route_values: dict[str, dict[str, object]] = {}
        for name, ranks in routed_ranks.items():
            index = route_indexes[name]
            route_values[name] = {
                "rank": ranks.get(key),
                "disposition": str(index[key].get("disposition") or "")
                if key in index
                else "MISSING",
                "causality": str(index[key].get("causality") or "")
                if key in index
                else "",
            }
        rows.append(
            {
                "advisory": str(control.get("advisory") or ""),
                "repository_identity": str(control.get("repository_identity") or ""),
                "fix_sha": str(control.get("fix_sha") or ""),
                "origin_sha": origin_sha,
                "materialized": key in candidate_key_set,
                "base_rank": base_ranks.get(key),
                "route_results": route_values,
                "ensemble_rank": ensemble_ranks.get(key),
            }
        )

    base_recall = _recall_at_budget([row["base_rank"] for row in rows])
    for name in route_summaries:
        ranks = [row["route_results"][name]["rank"] for row in rows]
        route_summaries[name]["recall_at_candidate_budget"] = _recall_at_budget(ranks)
    ensemble_recall = _recall_at_budget([row["ensemble_rank"] for row in rows])
    output = {
        "schema_version": 1,
        "artifact_kind": "origin_ai_recall_comparison",
        "split_id": controls_payload.get("split_id"),
        "requested_repository_identity": requested_identity,
        "generation_summary_sha256": canonical_sha256(generated_summary),
        "candidate_inventory_sha256": canonical_sha256(candidates),
        "candidate_count": len(candidates),
        "candidate_conservation_gate": True,
        "control_count": len(rows),
        "materialized_control_count": sum(row["materialized"] is True for row in rows),
        "base": {"recall_at_candidate_budget": base_recall},
        "routes": route_summaries,
        "ensemble": {
            "policy": (
                "all_models_promote, any_model_promotes, any_model_blocked, "
                "all_models_defer; preserve structural rank within each tier"
            ),
            "recall_at_candidate_budget": ensemble_recall,
        },
        "rows": rows,
        "claim_boundary": (
            "This joins gold origins only after generation and model routing are "
            "frozen. It measures selected-control recall and rank, not population "
            "recall or precision. Model negatives never delete candidates."
        ),
    }
    _atomic_json(args.output, output)
    print("origin AI recall comparison frozen")
    print(f"  controls    : {len(rows)}")
    print(f"  candidates  : {len(candidates)}")
    print(f"  base R@5    : {base_recall['5']:.3f}")
    for name, summary in route_summaries.items():
        recall = summary["recall_at_candidate_budget"]
        print(f"  {name} R@5: {recall['5']:.3f}")
    print(f"  ensemble R@5: {ensemble_recall['5']:.3f}")
    print(f"  output      : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
