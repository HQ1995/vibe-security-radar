#!/usr/bin/env python3
"""Validate frozen selection and blind AuditResult coverage."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from audit_record_gates import check_record

LANE = ROOT / "research/round9-top200-20260828"
MANIFEST = LANE / "manifest.jsonl"
KEYS = [
    "class_id", "case_id", "repo", "advisory_ids", "bug_semantics",
    "flaw_origin", "introducer_sha", "introducer_parent",
    "introducer_parent_absent", "squash_decomposed", "decomposed_shas",
    "ai_marker", "verdict", "fix_sha", "direct_fix_sha", "evidence",
    "reasoning", "remaining_gap",
]
VERDICTS = {"NOT_AI", "AI_ROOT_CAUSE", "AI_CODE_FLAWED", "BLOCKED", "EVIDENCE_GAP", "FALSE_POSITIVE"}
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def validate_manifest() -> list[dict]:
    manifest = rows(MANIFEST)
    assert len(manifest) == 200
    assert [item["ordinal"] for item in manifest] == list(range(200))
    assert [item["worker"] for item in manifest] == [f"w{i:03d}" for i in range(200)]
    assert len({item["class_id"] for item in manifest}) == 200
    official_ids = []
    for item in manifest:
        assert item["status_at_selection"] in {"UNANALYZED", "PARTIALLY_ANALYZED"}
        official_ids.extend(value.upper() for value in item["advisory_ids"])
        bundle = ROOT / item["bundle"]
        assert bundle.exists()
        assert hashlib.sha256(bundle.read_bytes()).hexdigest() == item["bundle_sha256"]
        payload = json.loads(bundle.read_text())
        assert payload["class_id"] == item["class_id"]
        assert payload["repo"] == item["repo"]
        assert {value.upper() for value in payload["advisory_ids"]} == {
            value.upper() for value in item["advisory_ids"]
        }
        assert payload["advisory"].get("description")
        assert payload["base_ledger_revision"] == item["base_ledger_revision"]
    assert len(official_ids) == len(set(official_ids))
    return manifest


def validate_result(item: dict, role: str) -> None:
    path = (
        LANE / "adjudication" / f"{item['worker']}.json"
        if role == "adjudication"
        else ROOT / item[f"{role}_out"]
    )
    assert path.exists(), path
    record = json.loads(path.read_text())
    assert list(record) == KEYS, f"{path}: keys/order mismatch"
    assert record["class_id"] == item["class_id"]
    assert record["repo"].lower().removeprefix("github.com/") == item["repo"].lower()
    assert {value.upper() for value in record["advisory_ids"]} == {
        value.upper() for value in item["advisory_ids"]
    }
    assert record["verdict"] in VERDICTS
    assert isinstance(record["introducer_parent_absent"], bool)
    assert isinstance(record["squash_decomposed"], bool)
    assert isinstance(record["decomposed_shas"], list)
    assert all(SHA40.fullmatch(value) for value in record["decomposed_shas"])
    for key in ("introducer_sha", "introducer_parent", "fix_sha", "direct_fix_sha"):
        assert record[key] is None or SHA40.fullmatch(record[key]), f"{path}: {key}"
    assert isinstance(record["bug_semantics"], str) and record["bug_semantics"].strip()
    assert isinstance(record["flaw_origin"], str) and record["flaw_origin"].strip()
    assert isinstance(record["ai_marker"], str) and record["ai_marker"].strip()
    assert str(record["evidence"]).strip()
    assert isinstance(record["reasoning"], str) and record["reasoning"].strip()
    problems = check_record(record)
    assert not problems, f"{path}: {'; '.join(problems)}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["primary", "review", "adjudication"])
    args = parser.parse_args()
    manifest = validate_manifest()
    if args.role:
        selected = manifest
        if args.role == "adjudication":
            comparisons = {
                row["worker"]: row
                for row in rows(LANE / "comparison.jsonl")
            }
            selected = [item for item in manifest if comparisons[item["worker"]]["needs_adjudication"]]
        for item in selected:
            validate_result(item, args.role)
        print(f"campaign: ok ({len(selected)} {args.role} records)")
    else:
        print("campaign manifest: ok (200 unique cases and advisory identities)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
