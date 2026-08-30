#!/usr/bin/env python3
"""End-to-end proof for the round9 200-case report and Neon landing."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round9-top200-20260828"
sys.path.insert(0, str(ROOT / "scripts"))
from audit_envelope import TERMINAL, violations
from audit_record_gates import check_record
from merge_funnel_lane import detect_duplicate_tps


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def env() -> dict[str, str]:
    values = {}
    for line in (ROOT / ".env.local").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"').strip("'")
    return values


def main() -> None:
    import psycopg

    manifest = jsonl(LANE / "manifest.jsonl")
    finals = jsonl(LANE / "final-records.jsonl")
    comparisons = jsonl(LANE / "comparison.jsonl")
    corrections = jsonl(LANE / "correction-index.jsonl")
    corrections2 = jsonl(LANE / "correction2-index.jsonl")
    ledger = jsonl(ROOT / "artifacts/funnel-account-20260817.jsonl")
    report = (LANE / "report.md").read_text()
    assert len(manifest) == len(finals) == len(comparisons) == 200
    assert len({row["class_id"] for row in manifest}) == 200
    assert len(list((LANE / "primary").glob("w*.json"))) == 200
    assert len(list((LANE / "review").glob("w*.json"))) == 200
    assert len(list((LANE / "adjudication").glob("w*.json"))) == 86
    assert len(corrections) == 28
    assert len(corrections2) == 12
    assert len(re.findall(r"^### \d+\.", report, re.M)) == 200
    manifest_ids = [row["class_id"] for row in manifest]
    final_by_class = {row["class_id"]: row for row in finals}
    assert set(final_by_class) == set(manifest_ids)
    ledger_by_class = {row["class_id"]: row for row in ledger}
    for class_id in manifest_ids:
        final = final_by_class[class_id]
        row = ledger_by_class[class_id]
        assert class_id in report
        assert final["audit_record"]["case_id"] in report
        assert not check_record(final["audit_record"])
        assert row["causal_research"] == final["audit_record"]
        assert row["status"] == final["ledger_status"]
        assert row["round9_assessment_ids"] == final["assessment_ids"]
        if row["status"] in TERMINAL:
            assert not violations(row)
    assert not detect_duplicate_tps(ledger)

    values = env()
    with psycopg.connect(values["DATABASE_URL"]) as connection:
        rows = connection.execute(
            """
            SELECT class_id, revision, status, raw_json
            FROM ledger_rows WHERE class_id = ANY(%s)
            """,
            (manifest_ids,),
        ).fetchall()
        assert len(rows) == 200
        revision_counts = {}
        for class_id, revision, status, raw in rows:
            revision_counts[revision] = revision_counts.get(revision, 0) + 1
            assert status == final_by_class[class_id]["ledger_status"]
            assert json.loads(raw) == ledger_by_class[class_id]
        assert revision_counts == {2: 188, 3: 12}
        runs = connection.execute(
            """
            SELECT run_id, completed_at FROM scan_runs
            WHERE run_id LIKE 'round9-top200-%-20260828'
            """
        ).fetchall()
        assert len(runs) == 5 and all(row[1] is not None for row in runs)
        assessments = connection.execute(
            """
            SELECT assessment_id, class_id FROM case_assessments
            WHERE assessment_id LIKE 'round9-%'
            """
        ).fetchall()
        assert len(assessments) == 526
        assert len({row[0] for row in assessments}) == 526
    print(
        json.dumps(
            {
                "cases": 200,
                "primary": 200,
                "review": 200,
                "adjudication": 86,
                "corrections": 28,
                "postfinal_corrections": 12,
                "assessments": 526,
                "neon_revisions": {"2": 188, "3": 12},
                "report_sections": 200,
                "record_gates": "PASS",
                "envelope_gate": "PASS",
                "duplicate_tp_gate": "PASS",
            }
        )
    )


if __name__ == "__main__":
    main()
