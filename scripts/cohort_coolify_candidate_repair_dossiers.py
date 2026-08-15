#!/usr/bin/env python3
"""Group retained Coolify repair edges into candidate-level review dossiers.

One candidate remains one scheduling unit, but every retained repair edge stays
visible.  A small prefix is marked for expanded semantic review; the remaining
edges are compact rescue references rather than discarded alternatives.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path


_ADJUDICATED_STATUSES = {
    "CONFIRMED_TRUE_POSITIVE",
    "REJECTED_NONCAUSAL",
    "PATCH_EQUIVALENT_ALIAS",
}


class CandidateDossierError(RuntimeError):
    """Raised when retained edge conservation cannot be proved."""


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise CandidateDossierError(f"expected JSON object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise CandidateDossierError(f"expected JSON object at {path}:{line_number}")
        rows.append(value)
    return rows


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _compact_edge(
    row: Mapping[str, object],
    *,
    dossier_edge_position: int,
    expansion_lane: str,
) -> dict[str, object]:
    return {
        "dossier_edge_position": dossier_edge_position,
        "review_expansion_lane": expansion_lane,
        "candidate_sha": row.get("candidate_sha"),
        "fix_sha": row.get("fix_sha"),
        "fix_subject": row.get("fix_subject"),
        "fix_authored_at": row.get("fix_authored_at"),
        "delta_bridge_rank": row.get("delta_bridge_rank"),
        "delta_bridge_tier": row.get("delta_bridge_tier"),
        "delta_bridge_class": row.get("delta_bridge_class"),
        "delta_bridge_score": row.get("delta_bridge_score"),
        "source_review_priority_rank": row.get("source_review_priority_rank"),
        "source_priority_class": row.get("source_priority_class"),
        "ledger_edge_status": row.get("ledger_edge_status"),
        "meaningful_exact_same_path_delta_count": row.get(
            "meaningful_exact_same_path_delta_count"
        ),
        "control_like_exact_same_path_delta_count": row.get(
            "control_like_exact_same_path_delta_count"
        ),
        "delta_match_counts": row.get("delta_match_counts"),
        "source_addition_match_counts": row.get("source_addition_match_counts"),
        "source_pair_sha256": row.get("source_pair_sha256"),
        "retained": row.get("retained"),
    }


def build_dossiers(
    rows: Sequence[Mapping[str, object]],
    *,
    expanded_edges_per_candidate: int,
) -> dict[str, object]:
    """Create active dossiers without collapsing secondary repair edges."""

    if expanded_edges_per_candidate < 1:
        raise CandidateDossierError("expanded_edges_per_candidate must be positive")
    grouped: dict[str, list[Mapping[str, object]]] = defaultdict(list)
    input_edges: set[tuple[str, str]] = set()
    for row in rows:
        candidate_sha = str(row.get("candidate_sha") or "")
        fix_sha = str(row.get("fix_sha") or "")
        if not candidate_sha or not fix_sha:
            raise CandidateDossierError("input contains an incomplete edge")
        edge = (candidate_sha, fix_sha)
        if edge in input_edges:
            raise CandidateDossierError(f"duplicate input edge: {edge}")
        if row.get("retained") is not True:
            raise CandidateDossierError(f"input edge is not retained: {edge}")
        rank = row.get("delta_bridge_rank")
        if not isinstance(rank, int) or rank < 1:
            raise CandidateDossierError(f"input edge has invalid rank: {edge}")
        input_edges.add(edge)
        grouped[candidate_sha].append(row)

    dossiers: list[dict[str, object]] = []
    output_edges: set[tuple[str, str]] = set()
    for candidate_sha, candidate_rows in grouped.items():
        ordered = sorted(
            candidate_rows,
            key=lambda row: (
                int(row["delta_bridge_rank"]),
                str(row["fix_sha"]),
            ),
        )
        review_rows = [
            row
            for row in ordered
            if str(row.get("ledger_edge_status") or "") not in _ADJUDICATED_STATUSES
        ]
        expanded_edges = {
            (str(row["candidate_sha"]), str(row["fix_sha"]))
            for row in review_rows[:expanded_edges_per_candidate]
        }
        compact_edges: list[dict[str, object]] = []
        for position, row in enumerate(ordered, start=1):
            edge = (str(row["candidate_sha"]), str(row["fix_sha"]))
            status = str(row.get("ledger_edge_status") or "")
            if status in _ADJUDICATED_STATUSES:
                lane = "adjudicated_reference"
            elif edge in expanded_edges:
                lane = "expanded_review"
            else:
                lane = "compact_rescue"
            compact_edges.append(
                _compact_edge(
                    row,
                    dossier_edge_position=position,
                    expansion_lane=lane,
                )
            )
            output_edges.add(edge)
        first_review_rank = (
            min(int(row["delta_bridge_rank"]) for row in review_rows)
            if review_rows
            else None
        )
        dossiers.append(
            {
                "candidate_sha": candidate_sha,
                "candidate_subject": ordered[0].get("candidate_subject"),
                "candidate_authored_at": ordered[0].get("candidate_authored_at"),
                "active_review": bool(review_rows),
                "dossier_rank": None,
                "first_unadjudicated_delta_bridge_rank": first_review_rank,
                "retained_repair_edge_count": len(ordered),
                "unadjudicated_repair_edge_count": len(review_rows),
                "expanded_review_edge_count": len(expanded_edges),
                "compact_rescue_edge_count": max(
                    len(review_rows) - len(expanded_edges), 0
                ),
                "adjudicated_reference_edge_count": (len(ordered) - len(review_rows)),
                "repair_edges": compact_edges,
                "all_candidate_edges_retained": True,
            }
        )

    dossiers.sort(
        key=lambda row: (
            row["active_review"] is not True,
            int(row["first_unadjudicated_delta_bridge_rank"] or 10**12),
            str(row["candidate_sha"]),
        )
    )
    for dossier_rank, dossier in enumerate(dossiers, start=1):
        dossier["dossier_rank"] = dossier_rank
    if output_edges != input_edges:
        raise CandidateDossierError(
            "candidate grouping failed retained-edge conservation"
        )
    lane_counts = Counter(
        str(edge["review_expansion_lane"])
        for dossier in dossiers
        for edge in dossier["repair_edges"]
    )
    active_dossiers = [row for row in dossiers if row["active_review"] is True]
    return {
        "dossiers": dossiers,
        "summary": {
            "retained_input_edge_count": len(input_edges),
            "retained_output_edge_count": len(output_edges),
            "candidate_dossier_count": len(dossiers),
            "active_candidate_dossier_count": len(active_dossiers),
            "fully_adjudicated_candidate_dossier_count": (
                len(dossiers) - len(active_dossiers)
            ),
            "expanded_edges_per_candidate_limit": (expanded_edges_per_candidate),
            "edge_lane_counts": dict(sorted(lane_counts.items())),
            "multi_edge_candidate_dossier_count": sum(
                int(row["retained_repair_edge_count"]) > 1 for row in dossiers
            ),
            "active_multi_edge_candidate_dossier_count": sum(
                int(row["unadjudicated_repair_edge_count"]) > 1
                for row in active_dossiers
            ),
            "max_retained_repair_edges_per_candidate": max(
                int(row["retained_repair_edge_count"]) for row in dossiers
            ),
        },
        "conservation": {
            "all_input_edges_represented_once": output_edges == input_edges,
            "hard_filter_count": 0,
            "compact_rescue_edges_retained": True,
            "adjudicated_edges_retained_as_references": True,
            "passed": output_edges == input_edges,
        },
    }


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delta-bridge-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expanded-edges-per-candidate", type=int, default=3)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    bridge_dir = args.delta_bridge_dir.resolve()
    summary_path = bridge_dir / "summary.json"
    pairs_path = bridge_dir / "delta_bridge_pairs.jsonl"
    bridge_summary = _read_json(summary_path)
    pairs = _read_jsonl(pairs_path)
    if bridge_summary.get("all_source_owner_pairs_conserved") is not True:
        raise SystemExit("delta bridge did not conserve every source-owner pair")
    expected_pairs_hash = (
        bridge_summary.get("output_artifacts", {})
        .get("delta_bridge_pairs", {})
        .get("sha256")
        if isinstance(bridge_summary.get("output_artifacts"), Mapping)
        else None
    )
    if expected_pairs_hash != _sha256(pairs_path):
        raise SystemExit("delta bridge pair checksum drift")
    result = build_dossiers(
        pairs,
        expanded_edges_per_candidate=args.expanded_edges_per_candidate,
    )
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    dossiers_path = output_dir / "candidate_dossiers.jsonl"
    dossiers_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in result["dossiers"]),
        encoding="utf-8",
    )
    output_summary = {
        "schema_version": 1,
        "artifact_kind": "coolify_candidate_repair_dossiers",
        **result["summary"],
        "source_artifacts": {
            "delta_bridge_summary": {
                "path": str(summary_path),
                "sha256": _sha256(summary_path),
            },
            "delta_bridge_pairs": {
                "path": str(pairs_path),
                "sha256": _sha256(pairs_path),
            },
        },
        "output_artifacts": {
            "candidate_dossiers": {
                "path": str(dossiers_path),
                "sha256": _sha256(dossiers_path),
            }
        },
        "conservation": result["conservation"],
        "claim_boundary": (
            "Dossiers are scheduling views, not causal labels. Each candidate "
            "pays the primary context cost once, while up to the configured "
            "number of repair edges receive expanded review. Remaining repair "
            "edges stay as compact rescue references and are never negative "
            "labels or hard-filtered exclusions."
        ),
    }
    summary_output_path = output_dir / "summary.json"
    summary_output_path.write_text(
        json.dumps(output_summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("Coolify candidate repair dossiers frozen")
    print(f"  candidates     : {result['summary']['candidate_dossier_count']}")
    print(f"  active dossiers: {result['summary']['active_candidate_dossier_count']}")
    print(f"  retained edges : {result['summary']['retained_output_edge_count']}")
    print(f"  output          : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
