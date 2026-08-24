#!/usr/bin/env python3
"""Conservation and ASCII checks for the next-pool map. Read-only besides asserts."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OUT = ROOT / "autoresearch/herdr-260814-next-pool-map-grok46-low"
CANON = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical85"
GHSA_RE = re.compile(r"GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}", re.I)


def ascii_file(path: Path) -> None:
    data = path.read_bytes()
    text = data.decode("ascii")
    assert all(ord(c) < 128 for c in text), path


def jsonl(path: Path) -> list:
    rows = []
    for line in path.read_text(encoding="ascii").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def main() -> int:
    for name in ("result.json", "queue.jsonl", "excluded.jsonl", "report.md", "inventory.py", "replay.sh", "check.py"):
        ascii_file(OUT / name)
    r = json.loads((OUT / "result.json").read_text(encoding="ascii"))
    assert r["inventory_only"] is True
    assert r["this_packet_does_not_claim_a_case_count"] is True
    assert r["this_packet_does_not_claim_pass"] is True
    assert r["causal_admission"] is False
    assert r["canonical_ledger_edited"] is False
    assert r["public_200_claim_supported"] is False
    assert r["authoritative_snapshot"]["counted_first_party_ghsa"] == 85
    assert r["conservation"]["fp211_hypotheses"] == 211
    assert r["conservation"]["fp211_source_ghsa_cases"] == 212
    assert r["conservation"]["id_conservation"] is True
    assert r["conservation"]["holds"] is True
    assert r["conservation"]["shared_sha_alone_is_not_duplication"] is True
    counted = set(r["authoritative_snapshot"]["counted_ids"])
    assert len(counted) == 85
    ledger_ids = []
    for line in (CANON / "ledger.jsonl").read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("record_kind") == "STRICT_RELEASED_CASE" and row.get("counted") is True:
            m = GHSA_RE.search(row["case_id"])
            ledger_ids.append(m.group(0).upper())
    assert set(ledger_ids) == counted
    queue = jsonl(OUT / "queue.jsonl")
    excluded = jsonl(OUT / "excluded.jsonl")
    qids = [row["case_id"] for row in queue]
    eids = [row["case_id"] for row in excluded]
    assert len(qids) == len(set(qids))
    assert len(eids) == len(set(eids))
    assert not (set(qids) & counted)
    assert r["queue_count"] == len(queue)
    assert r["excluded_count"] == len(excluded)
    a = r["buckets"]["A_independent_keep_not_integrated"]
    b = r["buckets"]["B_worker_proposal_needs_hostile_review"]
    c = r["buckets"]["C_narrow_or_unknown"]
    d = r["buckets"]["D_reject_or_duplicate"]
    assert qids == a + b + c
    assert set(d) <= set(eids)
    cons = r["conservation"]
    assert cons["pool_pass_keep_identities"] == (
        cons["already_counted_among_pool"] + cons["A"] + cons["B"] + cons["C"] + cons["D"]
    )
    for row in queue + excluded:
        assert row["counted"] is False or row["reason"] == "ALREADY_COUNTED"
        assert row["causal_admission"] is False
        assert row["labels_not_inherited"] is True
        assert "primary_source_path" in row and "primary_source_sha256" in row
        assert len(row["primary_source_sha256"]) == 64
        assert row["bucket"] in {"A", "B", "C", "D", "EXCLUDED"}
    report = (OUT / "report.md").read_text(encoding="ascii")
    assert "does not claim" in report
    assert "canonical85" in report.lower() or "Canonical85" in report
    print("check: PASS")
    print("queue", qids)
    print("A", a, "B", b, "C", c, "D", d)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
