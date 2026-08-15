#!/usr/bin/env python3
"""Freeze one review lane while proving that the parent repair inventory is conserved."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from cohort.fix_manifest import normalize_fix_manifest
from cohort.root_adjudication import canonical_sha256


class RepairLaneError(ValueError):
    """A staged repair lane cannot be bound to its parent inventory."""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expanded-manifest", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--review-lane", action="append", required=True)
    parser.add_argument(
        "--max-roots",
        type=int,
        default=0,
        help="take the first N scheduled roots across requested lanes (0 = all)",
    )
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--frozen-at", required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    parser.add_argument("--output-provenance", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(source_path: Path) -> dict[str, object]:
    try:
        value = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {source_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{source_path} must contain an object")
    return value


def _fix_key(row: Mapping[str, object]) -> tuple[str, str, str]:
    return (
        str(row.get("advisory") or ""),
        str(row.get("repository_identity") or ""),
        str(row.get("fix_sha") or ""),
    )


def prepare_repair_lane(
    manifest: Mapping[str, object],
    provenance: Mapping[str, object],
    *,
    review_lanes: set[str],
    max_roots: int = 0,
    split_id: str,
    frozen_at: str,
) -> tuple[dict[str, object], dict[str, object]]:
    """Select scheduled lanes and retain a proof that all other roots remain deferred."""

    normalized = normalize_fix_manifest(manifest, {})
    if provenance.get("artifact_kind") != "semantic_repair_chain_expansion":
        raise RepairLaneError("unsupported repair-chain provenance")
    if provenance.get("expanded_manifest_sha256") != canonical_sha256(normalized):
        raise RepairLaneError("expanded manifest does not match repair-chain provenance")
    if not review_lanes or any(not lane.strip() for lane in review_lanes):
        raise RepairLaneError("at least one non-empty review lane is required")
    if max_roots < 0:
        raise RepairLaneError("max roots must be non-negative")

    raw_schedule = provenance.get("repair_schedule")
    if not isinstance(raw_schedule, list):
        raise RepairLaneError("repair-chain provenance has no review schedule")
    schedule: list[dict[str, object]] = []
    for raw_row in raw_schedule:
        if not isinstance(raw_row, Mapping):
            raise RepairLaneError("repair review schedule contains a malformed row")
        row = dict(raw_row)
        key = _fix_key(row)
        if not all(key) or not isinstance(row.get("review_lane"), str):
            raise RepairLaneError("repair review schedule row is incomplete")
        schedule.append(row)

    manifest_rows = normalized.get("fixes")
    if not isinstance(manifest_rows, list):
        raise RepairLaneError("expanded manifest fixes are malformed")
    manifest_keys = {_fix_key(row) for row in manifest_rows}
    scheduled_keys = {_fix_key(row) for row in schedule}
    if len(schedule) != len(scheduled_keys) or scheduled_keys != manifest_keys:
        raise RepairLaneError("repair review schedule does not conserve the parent fixes")

    available_lanes = {str(row["review_lane"]) for row in schedule}
    unknown_lanes = sorted(review_lanes - available_lanes)
    if unknown_lanes:
        raise RepairLaneError(f"unknown review lanes: {unknown_lanes}")
    selected_rows = [
        row for row in schedule if str(row["review_lane"]) in review_lanes
    ]
    if max_roots:
        selected_rows = selected_rows[:max_roots]
    selected_keys = {_fix_key(row) for row in selected_rows}
    deferred_keys = manifest_keys - selected_keys
    if not selected_rows or selected_keys | deferred_keys != manifest_keys:
        raise RepairLaneError("repair lane selection failed to account for every root")

    selected_manifest = normalize_fix_manifest(
        {
            "schema_version": 1,
            "artifact_kind": "sealed_fix_manifest",
            "split_id": split_id,
            "frozen_at": frozen_at,
            "fixes": [
                {
                    "advisory": advisory,
                    "repository_identity": identity,
                    "fix_sha": fix_sha,
                }
                for advisory, identity, fix_sha in sorted(selected_keys)
            ],
        },
        {},
    )
    lane_counts = Counter(str(row["review_lane"]) for row in schedule)
    lane_provenance = {
        "schema_version": 1,
        "artifact_kind": "staged_repair_review_lane",
        "split_id": split_id,
        "parent_manifest_sha256": canonical_sha256(normalized),
        "parent_repair_schedule_sha256": canonical_sha256(schedule),
        "selected_manifest_sha256": canonical_sha256(selected_manifest),
        "requested_review_lanes": sorted(review_lanes),
        "max_selected_roots": max_roots,
        "parent_root_count": len(manifest_keys),
        "selected_root_count": len(selected_keys),
        "deferred_root_count": len(deferred_keys),
        "all_parent_roots_accounted_for": (
            selected_keys.isdisjoint(deferred_keys)
            and selected_keys | deferred_keys == manifest_keys
        ),
        "parent_lane_counts": dict(sorted(lane_counts.items())),
        "selected_schedule": selected_rows,
        "selected_schedule_sha256": canonical_sha256(selected_rows),
        "deferred_root_keys_sha256": canonical_sha256(
            [list(key) for key in sorted(deferred_keys)]
        ),
        "claim_boundary": (
            "This artifact changes processing order only. Selected roots enter the "
            "current model batch; deferred roots remain conserved in the bound parent "
            "manifest and must be processed by later lanes before closure."
        ),
    }
    return selected_manifest, lane_provenance


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit(f"output already exists: {path}")
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


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        manifest, provenance = prepare_repair_lane(
            _load_json(args.expanded_manifest),
            _load_json(args.provenance),
            review_lanes=set(args.review_lane),
            max_roots=args.max_roots,
            split_id=args.split_id,
            frozen_at=args.frozen_at,
        )
    except RepairLaneError as exc:
        raise SystemExit(f"repair lane preparation failed: {exc}") from exc
    _atomic_json(args.output_manifest, manifest)
    _atomic_json(args.output_provenance, provenance)
    print("staged repair review lane frozen")
    print(f"  selected roots: {provenance['selected_root_count']}")
    print(f"  deferred roots: {provenance['deferred_root_count']}")
    print(f"  manifest      : {args.output_manifest}")
    print(f"  provenance    : {args.output_provenance}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
