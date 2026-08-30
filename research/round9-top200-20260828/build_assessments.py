#!/usr/bin/env python3
"""Wrap blind AuditResults as append-only Neon assessment inputs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round9-top200-20260828"


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["primary", "review", "adjudication"], required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    manifest = rows(LANE / "manifest.jsonl")
    envelopes = []
    for item in manifest:
        result_path = ROOT / (
            item[f"{args.role}_out"]
            if args.role in {"primary", "review"}
            else f"research/round9-top200-20260828/adjudication/{item['worker']}.json"
        )
        if not result_path.exists():
            if args.role == "adjudication":
                continue
            raise SystemExit(f"missing {result_path}")
        record = json.loads(result_path.read_text())
        assessment_id = f"round9-{args.role}-{item['worker']}"
        envelopes.append(
            {
                "assessment_id": assessment_id,
                "class_id": item["class_id"],
                "run_id": args.run_id,
                "base_ledger_revision": item["base_ledger_revision"],
                "verdict": record["verdict"],
                "confidence": None,
                "reasoning": record["reasoning"],
                "causal_chain": {
                    key: record[key]
                    for key in (
                        "case_id", "repo", "advisory_ids", "bug_semantics",
                        "flaw_origin", "introducer_sha", "introducer_parent",
                        "introducer_parent_absent", "squash_decomposed",
                        "decomposed_shas", "fix_sha", "direct_fix_sha",
                    )
                },
                "evidence": {
                    "schema_version": "causal-audit/1",
                    "role": args.role,
                    "audit_record": record,
                },
                "raw_output": result_path.read_text(),
                "agent_id": f"{args.role}-{item['worker']}",
                "metadata": {
                    "bundle_path": item["bundle"],
                    "bundle_sha256": item["bundle_sha256"],
                    "clean_context": True,
                    "worker_id": item["worker"],
                    "selection_score": item["score"],
                },
            }
        )
    output = LANE / f"{args.role}-assessments.jsonl"
    output.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in envelopes))
    print(json.dumps({"role": args.role, "assessments": len(envelopes), "out": str(output)}))


if __name__ == "__main__":
    main()
