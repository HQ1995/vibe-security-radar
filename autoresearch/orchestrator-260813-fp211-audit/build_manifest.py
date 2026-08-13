#!/usr/bin/env python3
"""Freeze the 211 canonical components into deterministic audit shards."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LEDGER = ROOT / "autoresearch/orchestrator-260812-posthold-canonical/ledger.jsonl"
SHARD_COUNT = 6


def compact(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build() -> tuple[str, str, dict[str, str]]:
    ledger_sha256 = hashlib.sha256(LEDGER.read_bytes()).hexdigest()
    rows = [
        json.loads(line)
        for line in LEDGER.read_text().splitlines()
        if line.strip()
    ]
    rows = [
        row for row in rows
        if row["record_kind"] == "COMPONENT_ROW" and row["counting"]["canonical_instance"]
    ]
    assert len(rows) == len({row["row_key"] for row in rows}) == 211

    manifest_rows = []
    shards = {f"shard-{number:02d}": [] for number in range(1, SHARD_COUNT + 1)}
    for ordinal, row in enumerate(rows, 1):
        shard_number = min((ordinal - 1) // 36 + 1, SHARD_COUNT)
        record = {
            "schema_version": 1,
            "ordinal": ordinal,
            "shard": f"shard-{shard_number:02d}",
            "row_key": row["row_key"],
            "canonical_component_id": row["canonical_component_id"],
            "baseline_state": row["row_state"],
            "source_tier": row["source_tier"],
            "public_ids": row["public_ids"],
            "repository": row.get("repository"),
            "mechanism": row.get("mechanism"),
            "mechanism_key": row.get("mechanism_key"),
            "causal_class": row.get("causal_class"),
            "candidate_fix_edges": row.get("candidate_fix_edges", []),
            "atomic_fix_members": row.get("atomic_fix_members", []),
            "ai_provenance": row.get("ai_provenance"),
            "release_evidence": row.get("release_evidence"),
            "identity_relation": row.get("identity_relation"),
            "source_refs": row.get("source_refs", []),
        }
        manifest_rows.append(record)
        shards[record["shard"]].append(record)

    manifest_text = "".join(compact(row) + "\n" for row in manifest_rows)
    meta = {
        "schema_version": 1,
        "pinned_head": "cd97a295956a8d3d46330bf9b0300ddded21f737",
        "ledger_path": str(LEDGER.relative_to(ROOT)),
        "ledger_sha256": ledger_sha256,
        "manifest_sha256": hashlib.sha256(manifest_text.encode()).hexdigest(),
        "canonical_components": len(manifest_rows),
        "shard_count": SHARD_COUNT,
        "shards": {
            name: {
                "count": len(items),
                "ordinal_start": items[0]["ordinal"],
                "ordinal_end": items[-1]["ordinal"],
            }
            for name, items in shards.items()
        },
        "status": "IN_PROGRESS",
        "claim_boundary": "211 canonical hypotheses queued for falsification; not 211 confirmed cases.",
    }
    shard_texts = {
        name: "".join(compact(row) + "\n" for row in items)
        for name, items in shards.items()
    }
    return manifest_text, json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + "\n", shard_texts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    manifest, metadata, shards = build()
    expected = {
        HERE / "manifest.jsonl": manifest,
        HERE / "manifest.json": metadata,
        **{HERE / "inputs" / f"{name}.jsonl": text for name, text in shards.items()},
    }
    if args.check:
        for path, text in expected.items():
            assert path.is_file() and path.read_text() == text, f"stale: {path}"
        print("PASS: 211 canonical components frozen into 6 byte-identical shards")
        return
    for path, text in expected.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    print("WROTE: manifest.json manifest.jsonl inputs/shard-01..06.jsonl")


if __name__ == "__main__":
    main()
