#!/usr/bin/env python3
"""Build NOT_AI + EVIDENCE_GAP patches from round15 records for ledger apply."""
from __future__ import annotations

import json
import os

import psycopg

BASE = "research/round15-next100-20260905"


def main() -> None:
    records = []
    with open(f"{BASE}/records.jsonl") as fh:
        for line in fh:
            row = json.loads(line)
            if row["verdict"] != "AI_ROOT_CAUSE":
                records.append(row)

    ledger_by_class = {}
    with open("artifacts/funnel-account-20260817.jsonl") as fh:
        for line in fh:
            row = json.loads(line)
            ledger_by_class[row["class_id"]] = row

    conn = psycopg.connect(
        conninfo=os.environ["DATABASE_URL_OWNER"],
        row_factory=psycopg.rows.dict_row,
    )
    rows = conn.execute(
        "SELECT assessment_id, class_id FROM case_assessments"
        " WHERE run_id = 'round15-notai-20260908'"
    ).fetchall()
    by_class = {r["class_id"]: r["assessment_id"] for r in rows}
    conn.close()

    patches = []
    for record in records:
        cid = record["class_id"]
        status = record["verdict"]
        ledger_row = ledger_by_class.get(cid)
        if not ledger_row:
            continue
        evidence = " | ".join(
            str(x) for x in (record.get("evidence") or [])[:6]
        )[:3000]
        ai_marker = record.get("ai_marker")
        if isinstance(ai_marker, dict):
            ai_marker = json.dumps(ai_marker, ensure_ascii=False)
        if not isinstance(ai_marker, str):
            ai_marker = str(ai_marker)
        causal = {
            "verdict": status,
            "class_id": cid,
            "case_id": record.get("case_id"),
            "repo": record.get("repo") or ledger_row.get("repo"),
            "advisory_ids": record.get("advisory_ids") or ledger_row.get("advisory_ids"),
            "bug_semantics": (record.get("bug_semantics") or "")[:800],
            "flaw_origin": (record.get("flaw_origin") or "")[:800],
            "introducer_sha": record.get("introducer_sha"),
            "direct_fix_sha": record.get("direct_fix_sha") or record.get("fix_sha"),
            "ai_marker": ai_marker[:500],
            "evidence": "round15 independent blind audit: " + evidence,
            "remaining_gap": record.get("remaining_gap"),
            "fix_ai_marker": record.get("fix_ai_marker"),
        }
        if record.get("unpatched"):
            causal["unpatched"] = record["unpatched"]
        row = {
            "class_id": cid,
            "status": status,
            "repo": record.get("repo") or ledger_row.get("repo"),
            "advisory_ids": record.get("advisory_ids") or ledger_row.get("advisory_ids"),
            "advisory_ids_source": "round15-blind-20260906",
            "dossier_best": None,
            "ledger_best": None,
            "site_scope": None,
            "site_tier": None,
            "round15_research": {
                "verdict": status,
                "case_id": record.get("case_id"),
                "introducer_sha": record.get("introducer_sha"),
                "fix_sha": record.get("fix_sha"),
                "direct_fix_sha": record.get("direct_fix_sha"),
                "unpatched": record.get("unpatched"),
                "remaining_gap": record.get("remaining_gap"),
                "evidence": evidence[:2000],
            },
            "causal_research": causal,
        }
        aid = by_class.get(cid, "")
        patches.append(
            {"expected_revision": 1, "row": row, "assessment_ids": [aid] if aid else []}
        )

    with open(f"{BASE}/notai-patches.jsonl", "w") as fh:
        for patch in patches:
            fh.write(json.dumps(patch, ensure_ascii=False) + chr(10))
    print("patches:", len(patches))


if __name__ == "__main__":
    main()
