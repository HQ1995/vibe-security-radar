#!/usr/bin/env python3
"""Build and score a blind, repo-disjoint Source v3 audit packet."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from cve_analyzer.source_matcher import MATCHER_CONTRACT

SCHEMA_VERSION = 1
SELECTION_SEED = "ai-slop-source-v3-audit-v1"
MODULES = ("author_identity", "coauthor_trailer", "explicit_attribution")
LANES = ("accepted", "hard_negative")
DEFAULT_PER_CELL = 100


class SourceAuditError(ValueError):
    """An audit input cannot support a source-quality claim."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _selection_key(row: Mapping[str, Any]) -> tuple[str, str]:
    material = "\0".join(
        (
            SELECTION_SEED,
            str(row["source_module"]),
            str(row["lane"]),
            str(row["repository_identity"]),
            str(row["commit_sha"]),
        )
    )
    return hashlib.sha256(material.encode()).hexdigest(), str(row["case_id"])


def build_packet(
    source: Mapping[str, Any],
    *,
    per_cell: int = DEFAULT_PER_CELL,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Select at most one case per repository across all audit cells."""

    rows = source.get("rows")
    if (
        source.get("schema_version") != SCHEMA_VERSION
        or source.get("matcher_contract") != MATCHER_CONTRACT
        or not isinstance(rows, list)
        or per_cell <= 0
    ):
        raise SourceAuditError("source audit input contract is invalid")
    validated: list[dict[str, Any]] = []
    seen_cases: set[str] = set()
    for raw in rows:
        required = {
            "case_id",
            "repository_identity",
            "commit_sha",
            "source_module",
            "lane",
            "commit",
        }
        if not isinstance(raw, dict) or set(raw) != required:
            raise SourceAuditError("source audit row schema is invalid")
        case_id = raw["case_id"]
        repository = raw["repository_identity"]
        commit_sha = raw["commit_sha"]
        module = raw["source_module"]
        lane = raw["lane"]
        commit = raw["commit"]
        if (
            not isinstance(case_id, str)
            or not case_id
            or case_id in seen_cases
            or not isinstance(repository, str)
            or not repository
            or not isinstance(commit_sha, str)
            or len(commit_sha) != 40
            or any(character not in "0123456789abcdef" for character in commit_sha)
            or module not in MODULES
            or lane not in LANES
            or not isinstance(commit, dict)
        ):
            raise SourceAuditError("source audit row values are invalid")
        seen_cases.add(case_id)
        validated.append(dict(raw))

    selected: list[dict[str, Any]] = []
    used_repositories: set[str] = set()
    cell_counts: dict[str, int] = {}
    for module in MODULES:
        for lane in LANES:
            cell = f"{module}:{lane}"
            candidates = sorted(
                (
                    row
                    for row in validated
                    if row["source_module"] == module and row["lane"] == lane
                ),
                key=_selection_key,
            )
            count = 0
            for row in candidates:
                repository = str(row["repository_identity"])
                if repository in used_repositories:
                    continue
                selected.append(row)
                used_repositories.add(repository)
                count += 1
                if count == per_cell:
                    break
            cell_counts[cell] = count

    blind_cases = [
        {
            "case_id": row["case_id"],
            "repository_identity": row["repository_identity"],
            "commit_sha": row["commit_sha"],
            "commit": row["commit"],
        }
        for row in selected
    ]
    packet_core = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": "blind_source_audit_packet",
        "matcher_contract": MATCHER_CONTRACT,
        "selection_seed": SELECTION_SEED,
        "repo_disjoint": True,
        "requested_per_cell": per_cell,
        "cell_counts": cell_counts,
        "case_count": len(blind_cases),
        "cases": blind_cases,
    }
    packet_sha256 = _digest(packet_core)
    packet = {**packet_core, "packet_sha256": packet_sha256}
    predictions = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": "sealed_source_predictions",
        "packet_sha256": packet_sha256,
        "predictions": {
            row["case_id"]: {
                "source_module": row["source_module"],
                "predicted_positive": row["lane"] == "accepted",
            }
            for row in selected
        },
    }
    predictions["predictions_sha256"] = _digest(predictions["predictions"])
    return packet, predictions


def evaluate_labels(
    packet: Mapping[str, Any],
    predictions: Mapping[str, Any],
    first: Mapping[str, Any],
    second: Mapping[str, Any],
) -> dict[str, Any]:
    """Score only complete, independent, agreeing dual adjudications."""

    packet_core = dict(packet)
    supplied_packet_digest = packet_core.pop("packet_sha256", None)
    cases = packet.get("cases")
    sealed = predictions.get("predictions")
    if (
        packet.get("schema_version") != SCHEMA_VERSION
        or packet.get("artifact_kind") != "blind_source_audit_packet"
        or supplied_packet_digest != _digest(packet_core)
        or not isinstance(cases, list)
        or predictions.get("packet_sha256") != supplied_packet_digest
        or not isinstance(sealed, dict)
        or predictions.get("predictions_sha256") != _digest(sealed)
    ):
        raise SourceAuditError("audit packet or sealed predictions are invalid")
    expected_ids = {
        case.get("case_id")
        for case in cases
        if isinstance(case, dict) and isinstance(case.get("case_id"), str)
    }
    if len(expected_ids) != len(cases) or set(sealed) != expected_ids:
        raise SourceAuditError("audit packet identities are inconsistent")

    def labels(payload: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]]:
        adjudicator = payload.get("adjudicator_id")
        raw_labels = payload.get("labels")
        if (
            payload.get("schema_version") != SCHEMA_VERSION
            or payload.get("packet_sha256") != supplied_packet_digest
            or not isinstance(adjudicator, str)
            or not adjudicator
            or not isinstance(raw_labels, dict)
            or set(raw_labels) != expected_ids
            or any(value not in {True, False, "inconclusive"} for value in raw_labels.values())
        ):
            raise SourceAuditError("adjudication contract is invalid")
        return adjudicator, raw_labels

    first_id, first_labels = labels(first)
    second_id, second_labels = labels(second)
    if first_id == second_id:
        raise SourceAuditError("adjudicators must be independent")
    disagreements = sorted(
        case_id
        for case_id in expected_ids
        if first_labels[case_id] != second_labels[case_id]
    )
    inconclusive = sorted(
        case_id
        for case_id in expected_ids
        if first_labels[case_id] == "inconclusive"
        or second_labels[case_id] == "inconclusive"
    )
    confusion = {
        module: {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        for module in MODULES
    }
    if not disagreements and not inconclusive:
        for case_id in sorted(expected_ids):
            prediction = sealed[case_id]
            module = prediction["source_module"]
            predicted = prediction["predicted_positive"]
            actual = first_labels[case_id]
            bucket = (
                "tp"
                if predicted and actual
                else "fp"
                if predicted
                else "fn"
                if actual
                else "tn"
            )
            confusion[module][bucket] += 1
    ready = not disagreements and not inconclusive
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": "source_audit_report",
        "packet_sha256": supplied_packet_digest,
        "case_count": len(expected_ids),
        "adjudicator_ids": sorted((first_id, second_id)),
        "disagreement_ids": disagreements,
        "inconclusive_ids": inconclusive,
        "confusion_by_module": confusion if ready else None,
        "quality_claim_ready": ready,
    }


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    select = subparsers.add_parser("select")
    select.add_argument("--input", type=Path, required=True)
    select.add_argument("--output-dir", type=Path, required=True)
    select.add_argument("--per-cell", type=int, default=DEFAULT_PER_CELL)
    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("--packet", type=Path, required=True)
    evaluate.add_argument("--predictions", type=Path, required=True)
    evaluate.add_argument("--labels", type=Path, action="append", required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "select":
            source = json.loads(args.input.read_bytes())
            packet, predictions = build_packet(source, per_cell=args.per_cell)
            _write_json(args.output_dir / "packet.json", packet)
            _write_json(args.output_dir / "sealed-predictions.json", predictions)
            return 0
        if len(args.labels) != 2:
            raise SourceAuditError("evaluate requires exactly two label files")
        packet = json.loads(args.packet.read_bytes())
        predictions = json.loads(args.predictions.read_bytes())
        label_payloads = [json.loads(path.read_bytes()) for path in args.labels]
        report = evaluate_labels(
            packet,
            predictions,
            label_payloads[0],
            label_payloads[1],
        )
        _write_json(args.output, report)
        return 0 if report["quality_claim_ready"] else 2
    except (OSError, UnicodeError, json.JSONDecodeError, SourceAuditError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
