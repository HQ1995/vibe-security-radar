#!/usr/bin/env python3
"""Filter a frozen candidate ledger through exhaustive causal adjudications."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from cohort.root_adjudication import canonical_sha256
from cohort_atomic_mechanism_review import _atomic_json, _atomic_jsonl, _jsonl


_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_AI_MARKER = re.compile(
    r"(?:co[- ]?authored|generated with|claude|copilot|jules|rovo|codex|cursor|gemini|chatgpt|\[bot\])",
    re.IGNORECASE,
)
_ORIGIN_KINDS = frozenset(
    {"direct_commit", "squash_member", "upstream_atomic", "branch_copy"}
)
_CARRIER_KINDS = frozenset({"squash_member", "upstream_atomic"})
_NONCAUSAL_ROLES = frozenset(
    {"wrong_edge", "refactor_preservation", "incomplete_hardening"}
)
_EDGE_REJECTION_ROLES = _NONCAUSAL_ROLES | {"insufficient_fix_reversal"}


def _args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adjudications", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_source_edge(edge: object, component_id: str) -> dict[str, str]:
    if not isinstance(edge, Mapping):
        raise SystemExit(f"malformed source edge: {component_id}")
    candidate = str(edge.get("candidate_sha") or "").lower()
    fix = str(edge.get("fix_sha") or "").lower()
    carrier = str(edge.get("carrier_sha") or "").lower()
    origin_kind = str(edge.get("origin_kind") or "")
    ai_signal = str(edge.get("ai_signal") or "").strip()
    if (
        not _SHA40.fullmatch(candidate)
        or not _SHA40.fullmatch(fix)
        or candidate == fix
        or origin_kind not in _ORIGIN_KINDS
        or not _AI_MARKER.search(ai_signal)
        or bool(carrier) != (origin_kind in _CARRIER_KINDS)
        or (carrier and (not _SHA40.fullmatch(carrier) or carrier in {candidate, fix}))
    ):
        raise SystemExit(f"malformed source edge: {component_id}")
    return {
        "candidate_sha": candidate,
        "fix_sha": fix,
        "origin_kind": origin_kind,
        "ai_signal": ai_signal,
        **({"carrier_sha": carrier} if carrier else {}),
    }


def _source_edges(row: Mapping[str, object]) -> list[dict[str, str]]:
    component_id = str(row.get("component_id") or row.get("class_id") or "")
    edges = [
        _validate_source_edge(edge, component_id)
        for evidence in row.get("evidence", [])
        if isinstance(evidence, Mapping)
        for edge in evidence.get("accepted_edges", [])
    ]
    pairs = {(edge["candidate_sha"], edge["fix_sha"]) for edge in edges}
    if not edges or len(pairs) != len(edges):
        raise SystemExit(f"source component lacks unique accepted edges: {component_id}")
    return edges


def _filter_edges(
    row: Mapping[str, object], rejected_pairs: set[tuple[str, str]]
) -> tuple[dict[str, object], list[dict[str, str]]]:
    if not rejected_pairs:
        return dict(row), _source_edges(row)
    evidence_out: list[object] = []
    for evidence in row.get("evidence", []):
        if not isinstance(evidence, Mapping) or "accepted_edges" not in evidence:
            evidence_out.append(evidence)
            continue
        accepted_edges = evidence.get("accepted_edges")
        if not isinstance(accepted_edges, list):
            raise SystemExit("accepted_edges must be a list")
        evidence_out.append(
            {
                **evidence,
                "accepted_edges": [
                    edge
                    for edge in accepted_edges
                    if (
                        str(edge.get("candidate_sha") or "").lower(),
                        str(edge.get("fix_sha") or "").lower(),
                    )
                    not in rejected_pairs
                ],
            }
        )
    filtered = {**row, "evidence": evidence_out}
    edges = _source_edges(filtered)
    if len(_source_edges(row)) != len(edges) + len(rejected_pairs):
        raise SystemExit("rejected edge was not removed exactly once")
    return filtered, edges


def _component_ids(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SystemExit(f"{label} must be a component-id list")
    if len(value) != len(set(value)):
        raise SystemExit(f"duplicate component in {label}")
    return value


def _validate_partition(
    source_ids: set[str], direct_ids: list[str], contributor_ids: list[str], rejected_ids: list[str]
) -> None:
    groups = [set(direct_ids), set(contributor_ids), set(rejected_ids)]
    if any(groups[i] & groups[j] for i in range(3) for j in range(i + 1, 3)):
        raise SystemExit("causal adjudication groups overlap")
    if set().union(*groups) != source_ids:
        raise SystemExit("causal adjudications do not cover the frozen source ledger")


def build(
    path: Path,
) -> tuple[
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
    dict[str, object],
]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, Mapping)
        or payload.get("schema_version") != 2
        or payload.get("artifact_kind") != "strict_causal_component_adjudications"
    ):
        raise SystemExit("invalid causal adjudication artifact")

    source = payload.get("source_ledger")
    report = payload.get("source_report")
    if not isinstance(source, Mapping) or not isinstance(report, Mapping):
        raise SystemExit("causal adjudications require frozen ledger and report")
    source_path = Path(str(source.get("path") or ""))
    report_path = Path(str(report.get("path") or ""))
    if (
        not source_path.is_file()
        or _sha256(source_path) != source.get("sha256")
        or not report_path.is_file()
        or _sha256(report_path) != report.get("sha256")
    ):
        raise SystemExit("frozen ledger or source report hash mismatch")

    source_rows = _jsonl(source_path)
    source_public_ids = sum(len(row.get("public_ids", [])) for row in source_rows)
    if (
        len(source_rows) != source.get("semantic_component_count")
        or source_public_ids != source.get("public_id_count")
    ):
        raise SystemExit("frozen ledger census mismatch")
    rows_by_id = {
        str(row.get("component_id") or row.get("class_id") or ""): row
        for row in source_rows
    }
    if "" in rows_by_id or len(rows_by_id) != len(source_rows):
        raise SystemExit("source ledger component IDs are missing or duplicated")

    edges_by_id = {component_id: _source_edges(row) for component_id, row in rows_by_id.items()}
    direct_ids = _component_ids(
        payload.get("direct_root_or_reintroduction_component_ids"), "direct roots"
    )
    contributor_ids = _component_ids(
        payload.get("new_surface_contributor_component_ids"), "contributors"
    )
    raw_rejected = payload.get("rejected_components")
    if not isinstance(raw_rejected, list):
        raise SystemExit("rejected components must be a list")
    rejected: dict[str, dict[str, str]] = {}
    for raw in raw_rejected:
        if not isinstance(raw, Mapping):
            raise SystemExit("malformed rejected component")
        component_id = str(raw.get("component_id") or "")
        role = str(raw.get("noncausal_role") or "")
        reason = str(raw.get("reason") or "").strip()
        audit_row = str(raw.get("audit_row") or "")
        primary_id = str(raw.get("primary_id") or "").upper()
        source_row = rows_by_id.get(component_id)
        if (
            not component_id
            or component_id in rejected
            or role not in _NONCAUSAL_ROLES
            or not reason
            or not re.fullmatch(r"U\d{3}", audit_row)
            or not source_row
            or primary_id != str(source_row.get("primary_id") or "").upper()
        ):
            raise SystemExit(f"malformed rejected component: {component_id}")
        rejected[component_id] = {
            "audit_row": audit_row,
            "primary_id": primary_id,
            "noncausal_role": role,
            "reason": reason,
        }

    raw_rejected_edges = payload.get("rejected_edges", [])
    if not isinstance(raw_rejected_edges, list):
        raise SystemExit("rejected edges must be a list")
    rejected_edges: dict[tuple[str, str, str], dict[str, str]] = {}
    for raw in raw_rejected_edges:
        if not isinstance(raw, Mapping):
            raise SystemExit("malformed rejected edge")
        component_id = str(raw.get("component_id") or "")
        candidate = str(raw.get("candidate_sha") or "").lower()
        fix = str(raw.get("fix_sha") or "").lower()
        role = str(raw.get("rejection_role") or "")
        reason = str(raw.get("reason") or "").strip()
        key = (component_id, candidate, fix)
        source_pairs = {
            (edge["candidate_sha"], edge["fix_sha"])
            for edge in edges_by_id.get(component_id, [])
        }
        if (
            not component_id
            or component_id in rejected
            or key in rejected_edges
            or not _SHA40.fullmatch(candidate)
            or not _SHA40.fullmatch(fix)
            or (candidate, fix) not in source_pairs
            or role not in _EDGE_REJECTION_ROLES
            or not reason
        ):
            raise SystemExit(f"malformed rejected edge: {component_id}")
        rejected_edges[key] = {"rejection_role": role, "reason": reason}

    rejected_pairs_by_id: dict[str, set[tuple[str, str]]] = {}
    for component_id, candidate, fix in rejected_edges:
        rejected_pairs_by_id.setdefault(component_id, set()).add((candidate, fix))
    if any(
        len(pairs) >= len(edges_by_id[component_id])
        for component_id, pairs in rejected_pairs_by_id.items()
    ):
        raise SystemExit("edge-level rejection would empty an accepted component")

    _validate_partition(set(rows_by_id), direct_ids, contributor_ids, list(rejected))
    source_edge_count = sum(map(len, edges_by_id.values()))
    rejected_component_edge_count = sum(len(edges_by_id[value]) for value in rejected)
    rejected_edge_count = rejected_component_edge_count + len(rejected_edges)
    expected = payload.get("expected_counts")
    computed = {
        "source_components": len(source_rows),
        "direct_root_or_reintroduction": len(direct_ids),
        "new_surface_contributor": len(contributor_ids),
        "rejected": len(rejected),
        "source_edges": source_edge_count,
        "accepted_edges": source_edge_count - rejected_edge_count,
        "rejected_edges": rejected_edge_count,
    }
    if expected != computed:
        raise SystemExit(f"causal adjudication count mismatch: {computed}")

    direct_set = set(direct_ids)
    accepted: list[dict[str, object]] = []
    rejected_rows: list[dict[str, object]] = []
    rejected_edge_rows: list[dict[str, object]] = []
    accepted_origin_kinds: Counter[str] = Counter()
    accepted_edge_pairs: set[tuple[str, str]] = set()
    report_ref = {"path": str(report_path), "sha256": _sha256(report_path)}
    for index, row in enumerate(source_rows, start=1):
        component_id = str(row.get("component_id") or row.get("class_id"))
        edges = edges_by_id[component_id]
        audit_row = f"U{index:03d}"
        if component_id in rejected:
            decision = rejected[component_id]
            if decision["audit_row"] != audit_row:
                raise SystemExit(f"rejected audit row mismatch: {component_id}")
            rejected_rows.append(
                {
                    "component_id": component_id,
                    "class_id": row.get("class_id"),
                    "primary_id": row["primary_id"],
                    "public_ids": row["public_ids"],
                    "verdict": "FAIL",
                    **decision,
                    "rejected_edges": edges,
                    "source_report": report_ref,
                }
            )
            rejected_edge_rows.extend(
                {
                    "component_id": component_id,
                    "primary_id": row["primary_id"],
                    "public_ids": row["public_ids"],
                    "audit_row": audit_row,
                    "rejection_scope": "component",
                    **decision,
                    **edge,
                    "source_report": report_ref,
                }
                for edge in edges
            )
            continue
        pairs = rejected_pairs_by_id.get(component_id, set())
        row, edges = _filter_edges(row, pairs)
        for candidate, fix in sorted(pairs):
            decision = rejected_edges[(component_id, candidate, fix)]
            edge = next(
                edge
                for edge in edges_by_id[component_id]
                if (edge["candidate_sha"], edge["fix_sha"]) == (candidate, fix)
            )
            rejected_edge_rows.append(
                {
                    "component_id": component_id,
                    "primary_id": row["primary_id"],
                    "public_ids": row["public_ids"],
                    "audit_row": audit_row,
                    "rejection_scope": "edge",
                    **decision,
                    **edge,
                    "source_report": report_ref,
                }
            )
        causal_role = (
            "direct_root_or_reintroduction"
            if component_id in direct_set
            else "new_surface_contributor"
        )
        accepted_origin_kinds.update(edge["origin_kind"] for edge in edges)
        accepted_edge_pairs.update((edge["candidate_sha"], edge["fix_sha"]) for edge in edges)
        accepted.append(
            {
                **row,
                "evidence": [
                    *row["evidence"],
                    {
                        "kind": "strict_causal_v2_adjudication",
                        "verdict": "PASS",
                        "causal_role": causal_role,
                        "audit_row": audit_row,
                        "source_report": report_ref,
                    },
                ],
            }
        )

    public_ids = [value for row in accepted for value in row["public_ids"]]
    if len(public_ids) != len(set(public_ids)):
        raise SystemExit("accepted components contain duplicate public IDs")
    minimum = int(payload.get("minimum_public_id_count") or 150)
    summary = {
        "schema_version": 2,
        "artifact_kind": "strict_atomic_ai_causal_vulnerability_ledger",
        "claim_boundary": payload["claim_boundary"],
        "positive_semantic_component_count": len(accepted),
        "public_id_count": len(public_ids),
        "cve_count": sum(value.startswith("CVE-") for value in public_ids),
        "ghsa_count": sum(value.startswith("GHSA-") for value in public_ids),
        "causal_role_counts": {
            "direct_root_or_reintroduction": len(direct_ids),
            "new_surface_contributor": len(contributor_ids),
        },
        "rejected_component_count": len(rejected_rows),
        "rejected_public_id_count": sum(len(row["public_ids"]) for row in rejected_rows),
        "source_edge_occurrence_count": source_edge_count,
        "source_unique_edge_pair_count": len(
            {
                (edge["candidate_sha"], edge["fix_sha"])
                for edges in edges_by_id.values()
                for edge in edges
            }
        ),
        "accepted_edge_occurrence_count": sum(accepted_origin_kinds.values()),
        "accepted_unique_edge_pair_count": len(accepted_edge_pairs),
        "rejected_edge_occurrence_count": len(rejected_edge_rows),
        "rejected_unique_edge_pair_count": len(
            {(row["candidate_sha"], row["fix_sha"]) for row in rejected_edge_rows}
        ),
        "rejected_edge_role_counts": dict(
            sorted(
                Counter(
                    str(row.get("rejection_role") or row.get("noncausal_role"))
                    for row in rejected_edge_rows
                ).items()
            )
        ),
        "accepted_origin_kind_counts": dict(sorted(accepted_origin_kinds.items())),
        "minimum_public_id_count": minimum,
        "minimum_met": len(public_ids) >= minimum,
        "inputs": {
            "source_ledger": {"path": str(source_path), "sha256": _sha256(source_path)},
            "causal_adjudications": {"path": str(path), "sha256": _sha256(path)},
            "source_report": report_ref,
        },
        "ledger_sha256": canonical_sha256(accepted),
    }
    if source_edge_count != sum(accepted_origin_kinds.values()) + len(rejected_edge_rows):
        raise SystemExit("edge census is not conserved")
    return accepted, rejected_rows, rejected_edge_rows, summary


def main(argv: list[str] | None = None) -> int:
    args = _args(argv)
    accepted, rejected, rejected_edges, summary = build(args.adjudications)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    _atomic_jsonl(args.output_dir / "ledger.jsonl", accepted)
    _atomic_jsonl(args.output_dir / "rejected.jsonl", rejected)
    _atomic_jsonl(args.output_dir / "rejected_edges.jsonl", rejected_edges)
    _atomic_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["minimum_met"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
