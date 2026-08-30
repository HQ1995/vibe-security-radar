#!/usr/bin/env python3
"""Build the Neon assessment and finalize batches for Round11."""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "scripts"))
import ledger_store  # noqa: E402
from audit_envelope import violations  # noqa: E402
from audit_record_gates import check_record  # noqa: E402
from merge_funnel_lane import detect_duplicate_tps  # noqa: E402


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows))


def status_for(verdict: str) -> str:
    return "PARTIALLY_ANALYZED" if verdict == "EVIDENCE_GAP" else verdict


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    uuid.UUID(args.run_id)

    manifest = read_jsonl(LANE / "manifest.jsonl")
    records = read_jsonl(LANE / "records.jsonl")
    assert len(manifest) == len(records) == 500
    by_worker = {item["worker"]: record for item, record in zip(manifest, records, strict=True)}
    assert all(item["class_id"] == by_worker[item["worker"]]["class_id"] for item in manifest)

    ids = [item["class_id"] for item in manifest]
    with ledger_store.connect() as conn:
        db_rows = conn.execute(
            "SELECT class_id, revision, raw_json FROM ledger_rows WHERE class_id = ANY(%s)",
            (ids,),
        ).fetchall()
        existing_assessments = {
            row[0]
            for row in conn.execute(
                "SELECT assessment_id FROM case_assessments WHERE assessment_id = ANY(%s)",
                ([str(uuid.uuid5(uuid.NAMESPACE_URL, f"ai-slop/round11/{cid}")) for cid in ids],),
            ).fetchall()
        }
        all_db = [json.loads(row[0]) for row in conn.execute("SELECT raw_json FROM ledger_rows ORDER BY ordinal")]
    assert len(db_rows) == 500
    assert not existing_assessments, f"assessment ids already exist: {len(existing_assessments)}"
    current = {cid: (revision, json.loads(raw)) for cid, revision, raw in db_rows}

    assessments = []
    patches = []
    prospective = {row["class_id"]: row for row in all_db}
    for item in manifest:
        worker = item["worker"]
        rec = by_worker[worker]
        problems = check_record(rec)
        assert not problems, f"{worker}: {problems}"
        revision, old = current[item["class_id"]]
        assert old["status"] == item["status_at_selection"], (
            worker, item["status_at_selection"], old["status"]
        )
        assert "round11_research" not in old

        review_rel = (
            f"research/round11-top500-20260829/independent-review/{worker}.json"
            if (LANE / "independent-review" / f"{worker}.json").exists()
            else f"research/round11-top500-20260829/independent-review-111/{worker}.json"
        )
        primary_rel = f"research/round11-top500-20260829/primary/{worker}.json"
        assessment_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ai-slop/round11/{rec['class_id']}"))
        assessments.append({
            "assessment_id": assessment_id,
            "run_id": args.run_id,
            "class_id": rec["class_id"],
            "base_ledger_revision": revision,
            "verdict": rec["verdict"],
            "confidence": None,
            "reasoning": rec["reasoning"],
            "causal_chain": {
                "introducer_sha": rec.get("introducer_sha"),
                "introducer_parent": rec.get("introducer_parent"),
                "introducer_parent_absent": rec.get("introducer_parent_absent"),
                "fix_sha": rec.get("fix_sha"),
                "direct_fix_sha": rec.get("direct_fix_sha"),
                "ai_marker": rec.get("ai_marker"),
            },
            "evidence": {
                "record": rec.get("evidence"),
                "primary_source": primary_rel,
                "independent_review_source": review_rel,
                "reconciliation_source": "research/round11-top500-20260829/review-111-reconciliation.jsonl",
            },
            "raw_output": json.dumps(rec, ensure_ascii=False),
            "agent_id": worker,
            "metadata": {
                "round": 11,
                "protocol": "docs/AUDIT-PROTOCOL.md",
                "primary_source": primary_rel,
                "independent_review_source": review_rel,
            },
        })

        new = dict(old)
        new.update({
            "status": status_for(rec["verdict"]),
            "round11_research": rec,
            "round11_verdict": rec["verdict"],
            "round11_research_source": primary_rel,
            "round11_independent_review_source": review_rel,
            "round11_reconciliation_source": "research/round11-top500-20260829/review-111-reconciliation.jsonl",
        })
        envelope = violations(new)
        assert not envelope, f"{worker}: envelope {envelope}"
        patches.append({
            "expected_revision": revision,
            "assessment_ids": [assessment_id],
            "row": new,
        })
        prospective[rec["class_id"]] = new

    dupes = detect_duplicate_tps(list(prospective.values()))
    assert not dupes, "duplicate TP gate: " + "; ".join(dupes[:10])
    write_jsonl(LANE / "ledger-assessments.jsonl", assessments)
    write_jsonl(LANE / "ledger-finalize.jsonl", patches)
    plan = {
        "run_id": args.run_id,
        "rows": 500,
        "base_revisions": dict(Counter(item["expected_revision"] for item in patches)),
        "verdicts": dict(Counter(rec["verdict"] for rec in records)),
        "statuses_after": dict(Counter(item["row"]["status"] for item in patches)),
        "record_gate": "pass",
        "envelope_gate": "pass",
        "duplicate_tp_gate": "pass",
    }
    (LANE / "ledger-landing-plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    print(json.dumps(plan, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
