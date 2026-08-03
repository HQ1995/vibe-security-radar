#!/usr/bin/env python3
"""Reconcile blinded fix-root reviews and open only the retained root IDs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path

from cohort.fix_manifest import normalize_fix_manifest
from cohort.root_adjudication import canonical_sha256, parse_model_decision


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", type=Path, required=True)
    parser.add_argument("--review-a", type=Path, required=True)
    parser.add_argument("--review-b", type=Path, required=True)
    parser.add_argument("--review-c", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--frozen-at", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"JSON root is not an object: {path}")
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: object) -> None:
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


def _validated_reviews(
    path: Path,
    candidate_ids_by_packet: dict[str, set[str]],
) -> dict[str, dict[str, object]]:
    reviews: dict[str, dict[str, object]] = {}
    for raw in _load_jsonl(path):
        packet_id = str(raw.get("packet_id") or "")
        if packet_id not in candidate_ids_by_packet or packet_id in reviews:
            raise SystemExit(f"{path}: unknown or duplicate packet {packet_id}")
        decision = parse_model_decision(
            {key: value for key, value in raw.items() if key != "packet_id"},
            candidate_ids_by_packet[packet_id],
        )
        reviews[packet_id] = decision
    return reviews


def _review_signature(decision: dict[str, object]) -> tuple[str, tuple[str, ...]]:
    return (
        str(decision["decision"]),
        tuple(sorted(str(value) for value in decision["selected_ids"])),
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    selection = _load_json(args.selection)
    protocol = _load_json(args.protocol)
    packets_path = args.packet_dir / "packets.jsonl"
    sealed = _load_json(args.packet_dir / "sealed_candidate_map.json")
    packets = _load_jsonl(packets_path)
    sealed_rows = sealed.get("rows")
    if not isinstance(sealed_rows, list) or any(
        not isinstance(row, dict) for row in sealed_rows
    ):
        raise SystemExit("sealed candidate map rows are malformed")
    expected_packet_hash = str(protocol.get("root_packets_jsonl_sha256") or "")
    if (
        selection.get("split_id") != protocol.get("split_id")
        or _sha256_file(packets_path) != expected_packet_hash
        or selection.get("prelabel_artifacts", {}).get("root_packets_jsonl_sha256")
        != expected_packet_hash
    ):
        raise SystemExit("selection, protocol, and packet hashes do not agree")

    packet_by_id = {str(row.get("packet_id") or ""): row for row in packets}
    sealed_by_id = {str(row.get("packet_id") or ""): row for row in sealed_rows}
    if (
        len(packet_by_id) != len(packets)
        or len(sealed_by_id) != len(sealed_rows)
        or set(packet_by_id) != set(sealed_by_id)
    ):
        raise SystemExit("packet and sealed-map identity conservation failed")
    candidate_ids_by_packet = {
        packet_id: {
            str(candidate.get("candidate_id") or "")
            for candidate in packet.get("candidates", [])
            if isinstance(candidate, dict)
        }
        for packet_id, packet in packet_by_id.items()
    }
    reviews_a = _validated_reviews(args.review_a, candidate_ids_by_packet)
    reviews_b = _validated_reviews(args.review_b, candidate_ids_by_packet)
    if set(reviews_a) != set(packet_by_id) or set(reviews_b) != set(packet_by_id):
        raise SystemExit("both primary reviews must cover every frozen packet")
    disputed = {
        packet_id
        for packet_id in packet_by_id
        if _review_signature(reviews_a[packet_id])
        != _review_signature(reviews_b[packet_id])
    }
    reviews_c = _validated_reviews(args.review_c, candidate_ids_by_packet)
    if set(reviews_c) != disputed:
        raise SystemExit("third review must cover exactly the disputed packets")

    fixes: list[dict[str, str]] = []
    rows: list[dict[str, object]] = []
    for packet_id in sorted(packet_by_id):
        secret = sealed_by_id[packet_id]
        candidates = secret.get("candidates")
        if not isinstance(candidates, list):
            raise SystemExit("sealed candidate rows are malformed")
        sha_by_id = {
            str(candidate.get("candidate_id") or ""): str(candidate.get("sha") or "")
            for candidate in candidates
            if isinstance(candidate, dict)
        }
        if packet_id not in disputed:
            selected_ids = list(reviews_a[packet_id]["selected_ids"])
            reconciliation = "exact_primary_agreement"
        else:
            votes = Counter(
                candidate_id
                for review in (reviews_a[packet_id], reviews_b[packet_id], reviews_c[packet_id])
                for candidate_id in review["selected_ids"]
            )
            selected_ids = sorted(
                candidate_id for candidate_id, count in votes.items() if count >= 2
            )
            reconciliation = "third_review_two_of_three_vote"
        selected_shas = [sha_by_id[candidate_id] for candidate_id in selected_ids]
        status = "RESOLVED" if selected_ids else "UNRESOLVED"
        repository = str(secret.get("repository_identity") or "")
        advisory = str(secret.get("advisory") or "")
        for sha in selected_shas:
            fixes.append(
                {
                    "advisory": advisory,
                    "repository_identity": repository,
                    "fix_sha": sha,
                }
            )
        rows.append(
            {
                "packet_id": packet_id,
                "repository_identity": repository,
                "advisory": advisory,
                "primary_disagreement": packet_id in disputed,
                "reconciliation": reconciliation,
                "status": status,
                "selected_ids": sorted(selected_ids),
                "selected_fix_shas": sorted(selected_shas),
            }
        )

    split_id = str(selection["split_id"])
    manifest = normalize_fix_manifest(
        {
            "schema_version": 1,
            "artifact_kind": "sealed_fix_manifest",
            "split_id": split_id,
            "frozen_at": args.frozen_at,
            "fixes": fixes,
        },
        {},
    )
    resolved = sum(row["status"] == "RESOLVED" for row in rows)
    result: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "blinded_root_review_reconciliation",
        "split_id": split_id,
        "frozen_at": args.frozen_at,
        "selected_case_count": len(rows),
        "primary_disagreement_count": len(disputed),
        "resolved_case_count": resolved,
        "unresolved_case_count": len(rows) - resolved,
        "resolved_fix_count": len(manifest["fixes"]),
        "model_api_calls": 0,
        "review_sha256": {
            "a": _sha256_file(args.review_a),
            "b": _sha256_file(args.review_b),
            "c": _sha256_file(args.review_c),
        },
        "packet_sha256": expected_packet_hash,
        "selection_sha256": _sha256_file(args.selection),
        "protocol_sha256": _sha256_file(args.protocol),
        "fix_manifest_sha256": canonical_sha256(manifest),
        "claim_boundary": (
            "UNRESOLVED cases remain unknown in the all-selected denominator and are "
            "excluded from conditional origin recall; they are never negatives or replacements."
        ),
        "rows": rows,
    }
    result["result_sha256"] = canonical_sha256(result)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    _atomic_json(args.output_dir / "fix_manifest.json", manifest)
    _atomic_json(args.output_dir / "result.json", result)
    print("blinded root reviews reconciled")
    print(f"  resolved cases : {resolved}/{len(rows)}")
    print(f"  resolved fixes : {len(manifest['fixes'])}")
    print(f"  output         : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
