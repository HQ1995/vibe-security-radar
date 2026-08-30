#!/usr/bin/env python3
"""Aggregate 7-gate campaign verdicts into the funnel ledger.

Reads research/gate-campaign-20260830/verdicts/wave-*.jsonl, validates each row
against the campaign manifest, and writes gates + site_tier back to
artifacts/funnel-account-20260817.jsonl for the 148 provisional cases.

Rules:
- 7/7 PASS           -> site_tier="ALL_GATES_PASS"
- any NARROW, no FAIL -> site_tier="PARTIAL_EVIDENCE" (qualified)
- any FAIL           -> left untouched (stays provisional) + reason recorded
- UltraDAGcom (CVE-2026-42278/40583): explicitly left provisional
- rows already carrying site_tier (19 exclusions) are not overwritten

Run AFTER all 10 waves have landed. Idempotent.
"""

from __future__ import annotations

import json
import shutil
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAMPAIGN = ROOT / "research/gate-campaign-20260830"
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
MANIFEST = CAMPAIGN / "manifest.jsonl"
VERDICTS = CAMPAIGN / "verdicts"
EXPECTED_WAVES = 10

GATE_KEYS = {
    "identity",
    "ai_hunk",
    "topology",
    "but_for",
    "fix_reversal",
    "release",
    "uniqueness",
}

ULTRADAG = {"CVE-2026-42278", "CVE-2026-40583"}


def main() -> int:
    manifest = {
        m["case_id"]: m
        for m in (json.loads(l) for l in MANIFEST.read_text().splitlines() if l.strip())
    }

    verdict_files = sorted(VERDICTS.glob("wave-*.jsonl"))
    if len(verdict_files) < EXPECTED_WAVES:
        print(
            f"refusing to write back: only {len(verdict_files)}/{EXPECTED_WAVES} "
            "verdict files present"
        )
        return 1

    verdicts: dict[str, dict] = {}
    for path in verdict_files:
        rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
        for row in rows:
            cid = row.get("case_id")
            if cid not in manifest:
                print(f"WAVE {path.name}: unknown case_id {cid}")
                return 1
            if set(row.get("gates") or {}) != GATE_KEYS:
                print(f"{cid}: gate keys mismatch")
                return 1
            verdicts[cid] = row

    missing = sorted(set(manifest) - set(verdicts) - ULTRADAG)
    if missing:
        print(f"refusing to write back: {len(missing)} cases without verdicts")
        for cid in missing[:10]:
            print(" ", cid)
        return 1

    lines = LEDGER.read_text().splitlines()
    rows_by_class: dict[str, list[int]] = {}
    parsed = []
    for n, line in enumerate(lines):
        row = json.loads(line)
        parsed.append(row)
        rows_by_class.setdefault(row.get("class_id"), []).append(n)

    backup = LEDGER.with_suffix(
        LEDGER.suffix + ".bak-gate-writeback-" + __import__("datetime").date.today().isoformat()
    )
    if not backup.exists():
        shutil.copy2(LEDGER, backup)

    tier_counts: Counter = Counter()
    skipped: list[tuple[str, str]] = []
    changed = 0
    for cid, verdict in sorted(verdicts.items()):
        gates = verdict["gates"]
        values = set(gates.values())
        if "FAIL" in values or cid in ULTRADAG:
            skipped.append((cid, "FAIL" in values and "gate FAIL" or "ultradagcom hold"))
            continue
        tier = "ALL_GATES_PASS" if values == {"PASS"} else "PARTIAL_EVIDENCE"
        for n in rows_by_class.get(manifest[cid]["class_id"], []):
            row = parsed[n]
            if row.get("site_tier"):
                skipped.append((cid, f"already {row['site_tier']}"))
                continue
            row["site_tier"] = tier
            row["gates"] = gates
            row["gates_source"] = f"gate-campaign-20260830/{verdict.get('wave', 'wave')}"
            lines[n] = json.dumps(row, ensure_ascii=False)
            changed += 1
            tier_counts[tier] += 1

    LEDGER.write_text("\n".join(lines) + "\n")
    print(f"rows updated: {changed}")
    print(f"tiers applied: {dict(tier_counts)}")
    if skipped:
        print(f"skipped ({len(skipped)}):")
        for cid, why in skipped:
            print(f"  {cid}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
