#!/usr/bin/env python3
"""Collect primary records, gate them, and write roster/coverage snapshots."""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round11-top500-20260829"
sys.path.insert(0, str(ROOT / "scripts"))
from audit_record_gates import check_record  # noqa: E402

EXPECTED = [
    "class_id", "case_id", "repo", "advisory_ids", "bug_semantics", "flaw_origin",
    "introducer_sha", "introducer_parent", "introducer_parent_absent", "squash_decomposed",
    "decomposed_shas", "ai_marker", "verdict", "fix_sha", "direct_fix_sha", "evidence",
    "reasoning", "remaining_gap",
]


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> int:
    manifest = jsonl(LANE / "manifest.jsonl")
    records = []
    missing = []
    problems = []
    roster = []
    for item in manifest:
        path = ROOT / item["primary_out"]
        entry = {
            "worker": item["worker"],
            "class_id": item["class_id"],
            "repo": item["repo"],
            "advisory_ids": item["advisory_ids"],
            "output": item["primary_out"],
            "exists": path.exists(),
        }
        if not path.exists():
            missing.append(item["worker"])
            entry["status"] = "missing"
            roster.append(entry)
            continue
        record = json.loads(path.read_text())
        entry["status"] = "present"
        entry["verdict"] = record.get("verdict")
        if list(record)[: len(EXPECTED)] != EXPECTED:
            problems.append(f"{item['worker']}: key order mismatch")
        if record.get("class_id") != item["class_id"]:
            problems.append(f"{item['worker']}: class_id mismatch")
        if record.get("repo") != item["repo"]:
            problems.append(f"{item['worker']}: repo mismatch")
        if record.get("advisory_ids") != item["advisory_ids"]:
            problems.append(f"{item['worker']}: advisory_ids mismatch")
        if not str(record.get("evidence") or "").strip():
            problems.append(f"{item['worker']}: empty evidence")
        problems.extend(f"{item['worker']}: {p}" for p in check_record(record))
        records.append(record)
        roster.append(entry)

    (LANE / "records.jsonl").write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records)
    )
    (LANE / "worker-roster.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in roster)
    )
    summary = {
        "selected": len(manifest),
        "present": len(records),
        "missing": len(missing),
        "missing_workers": missing,
        "problems": len(problems),
        "verdict_histogram": dict(Counter(r.get("verdict") for r in records)),
        "ledger_sha256_at_freeze": json.loads((LANE / "selection-summary.json").read_text())[
            "ledger_sha256_at_freeze"
        ],
        "ledger_sha256_live": hashlib.sha256(
            (ROOT / "artifacts/funnel-account-20260817.jsonl").read_bytes()
        ).hexdigest(),
    }
    print(json.dumps(summary))
    if problems:
        print("\n".join(problems[:50]), file=sys.stderr)
    return 0 if not missing and not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
