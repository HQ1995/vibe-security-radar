#!/usr/bin/env python3
"""Losslessly fold origin fix edges and create bounded model work packets."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from cohort.origin_packets import fold_candidate_fix_pairs, packetize_candidate_units
from cohort.root_adjudication import canonical_sha256


def _nonnegative_int(summary: dict[str, object], field: str) -> int:
    value = summary.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SystemExit(f"squash summary {field} must be a non-negative integer")
    return value


def _squash_surface_fields(summary: dict[str, object]) -> dict[str, object]:
    blocked = _nonnegative_int(summary, "blocked_squash_relation_root_count")
    carrier_only = _nonnegative_int(summary, "carrier_only_squash_relation_root_count")
    atomic_gaps = _nonnegative_int(summary, "atomic_provenance_gap_count")
    uncovered = _nonnegative_int(summary, "candidate_surface_uncovered_count")
    complete = summary.get("candidate_surface_coverage_complete")
    if complete is not (uncovered == 0):
        raise SystemExit("squash summary candidate-surface fields contradict")
    if atomic_gaps != carrier_only + blocked:
        raise SystemExit("squash summary atomic provenance counts contradict")
    if uncovered != blocked:
        raise SystemExit("squash summary lacks a certificate for blocked-root coverage")
    if (
        summary.get("all_parent_candidates_retained") is not True
        or summary.get("all_relation_roots_conserved") is not True
    ):
        raise SystemExit("squash summary conservation failed")
    return {
        "blocked_squash_relation_root_count": blocked,
        "carrier_only_squash_relation_root_count": carrier_only,
        "atomic_provenance_gap_count": atomic_gaps,
        "candidate_surface_uncovered_count": uncovered,
        "candidate_surface_coverage_complete": complete,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-dir", type=Path, required=True)
    parser.add_argument("--max-candidates", type=int, default=8)
    parser.add_argument("--output-dir", type=Path, required=True)
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


def _atomic_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
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
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    summary = _load_json(args.generated_dir / "summary.json")
    candidates = _load_jsonl(args.generated_dir / "candidates.jsonl")
    if summary.get("artifact_kind") not in {
        "proof_carrying_origin_candidate_reduction",
        "proof_carrying_origin_squash_relation_closure",
    }:
        raise SystemExit("packetization requires a proof-carrying reduction")
    if canonical_sha256(candidates) != summary.get("candidate_rows_sha256"):
        raise SystemExit("reduced candidate digest mismatch")
    closure_applied = (
        summary.get("artifact_kind") == "proof_carrying_origin_squash_relation_closure"
    )
    surface_fields = _squash_surface_fields(summary) if closure_applied else {}
    units = fold_candidate_fix_pairs(candidates)
    packets = packetize_candidate_units(units, max_candidates=args.max_candidates)
    pair_count = sum(int(unit["fix_edge_count"]) for unit in units)
    membership_count = sum(int(packet["candidate_count"]) for packet in packets)
    if pair_count != len(candidates) or membership_count != len(units):
        raise SystemExit("packetization conservation failed")
    packet_summary = {
        "schema_version": 2,
        "artifact_kind": "lossless_origin_candidate_packets",
        "parent_generation_sha256": canonical_sha256(summary),
        "candidate_inventory_sha256": canonical_sha256(candidates),
        "candidate_fix_pair_count": len(candidates),
        "candidate_unit_count": len(units),
        "packet_count": len(packets),
        "max_candidates_per_packet": args.max_candidates,
        "candidate_units_sha256": canonical_sha256(units),
        "packets_sha256": canonical_sha256(packets),
        "all_fix_edges_conserved": pair_count == len(candidates),
        "all_candidate_units_assigned_once": membership_count == len(units),
        "negative_disposition": "DEFER_not_delete",
        "missing_response_disposition": "BLOCKED_split_and_retry",
        "squash_relation_closure_applied": closure_applied,
        **surface_fields,
    }
    args.output_dir.mkdir(parents=True)
    _atomic_jsonl(args.output_dir / "candidate_units.jsonl", units)
    _atomic_jsonl(args.output_dir / "packets.jsonl", packets)
    _atomic_json(args.output_dir / "summary.json", packet_summary)
    print(json.dumps(packet_summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
