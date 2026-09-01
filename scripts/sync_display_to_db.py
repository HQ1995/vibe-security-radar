#!/usr/bin/env python3
"""Sync publication display content from research/ sources into the Neon ledger_display table.

Each source becomes one row keyed by a stable "kind". publish_tp_ledger.py reads
this table first and falls back to the research/ files for development only.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from ledger_store import connect  # noqa: E402

SOURCES = [
    ("ai_summaries", "research/gate-campaign-20260830/summaries-by-alias.json", "json"),
    ("annotation_fulltext", "research/gate-campaign-20260830/annotation-fulltext.json", "json"),
    ("ir_chains", "research/orchestrator-260814-irchains-sol/ir-chains.jsonl", "jsonl"),
    ("ir_chain_updates", "research/ir-chain-origin-rereview-20260830/ir-chain-updates.jsonl", "jsonl"),
    ("advisory_dates_fallback", "research/orchestrator-260814-ghsa200-canvas/sweep/ghsa-first-party-dates.json", "json"),
    ("ai_commit_census", "research/ai-commit-census-current/ai-commit-census.json", "json"),
    ("round9_adjudication", "research/round9-top200-20260828/adjudication", "dir-json"),
    ("finalize_patches", "research/round9-top200-20260828/finalize-patches.jsonl", "jsonl"),
]


def load(kind: str, path: Path, kind_type: str) -> dict:
    if kind_type == "jsonl":
        out = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            key = str(
                row.get("case_id")
                or (row.get("row") or {}).get("class_id")
                or (row.get("row") or {}).get("case_id")
                or ""
            ).upper()
            if not key:
                key = str(abs(hash(str(sorted(row.items())))))
            if key:
                out[key] = row
        return out
    if kind_type == "dir-json":
        out = {}
        for fp in sorted(path.glob("*.json")):
            out[fp.stem] = json.loads(fp.read_text(encoding="utf-8"))
        return out
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return payload


def main() -> None:
    actor = "display-sync"
    values = {kind: load(kind, ROOT / rel, kind_type) for kind, rel, kind_type in SOURCES}
    with connect(direct=True) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ledger_display (
                kind text PRIMARY KEY,
                value_json jsonb NOT NULL,
                source text NOT NULL,
                updated_at timestamptz NOT NULL DEFAULT now(),
                updated_by text NOT NULL
            )
        """)
        now = datetime.now(timezone.utc)
        for kind, rel, kind_type in SOURCES:
            conn.execute(
                """
                INSERT INTO ledger_display(kind, value_json, source, updated_at, updated_by)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (kind) DO UPDATE
                SET value_json = EXCLUDED.value_json,
                    source = EXCLUDED.source,
                    updated_at = EXCLUDED.updated_at,
                    updated_by = EXCLUDED.updated_by
                """,
                (kind, json.dumps(values[kind]), rel, now, actor),
            )
    print("synced display kinds:", ", ".join(sorted(values)))


if __name__ == "__main__":
    main()
