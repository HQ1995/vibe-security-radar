#!/usr/bin/env python3
"""Fact gates for a causal-research record. These do not judge the AI role.

They refuse to land a closed verdict that is missing identity, BIC, or a
fix. They do not classify AI vs human — that stays a judgment call.

Usage:
  python3 scripts/audit_record_gates.py RECORD.jsonl
  python3 scripts/audit_record_gates.py --stdin  < one.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CLOSED = {"NOT_AI", "AI_ROOT_CAUSE", "AI_CODE_FLAWED", "FALSE_POSITIVE"}
OPEN = {"EVIDENCE_GAP", "BLOCKED"}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
OFFICIAL_ID = re.compile(r"^(GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}|CVE-\d{4}-\d{4,})$", re.I)

UNPATCHED = re.compile(r"\bunpatched\b", re.I)
EXTERNAL_VCS = re.compile(
    r"\b(?:svn|subversion|cvs)\b.{0,400}\b(?:revision|changeset|r\d+)\b",
    re.I | re.S,
)


def official_ids(record: dict) -> list[str]:
    ids = []
    for item in record.get("advisory_ids") or []:
        text = str(item).strip()
        if OFFICIAL_ID.match(text):
            ids.append(text.upper())
    return ids


def check_record(record: dict) -> list[str]:
    """Return human-readable problems. Empty means the record may land."""
    cid = str(record.get("class_id") or "?")
    verdict = record.get("verdict")
    problems: list[str] = []

    if verdict not in CLOSED | OPEN:
        if verdict is not None:
            problems.append(f"{cid}: unknown verdict {verdict!r}")
        return problems

    if verdict in OPEN:
        if verdict == "EVIDENCE_GAP" and not (record.get("remaining_gap") or "").strip():
            problems.append(f"{cid}: EVIDENCE_GAP requires remaining_gap")
        return problems
    if verdict == "FALSE_POSITIVE":
        gap = " ".join(
            str(record.get(k) or "")
            for k in ("evidence", "reasoning", "remaining_gap")
        )
        if not re.search(r"\b(withdrawn|rejected|not a security issue|false positive)\b", gap, re.I):
            problems.append(f"{cid}: FALSE_POSITIVE requires withdrawn/rejected evidence")
        return problems

    if not official_ids(record):
        problems.append(f"{cid}: closed {verdict} requires a real GHSA/CVE in advisory_ids")

    intro = record.get("introducer_sha")
    provenance = " ".join(
        str(record.get(k) or "") for k in ("flaw_origin", "evidence", "reasoning")
    )
    external_vcs_bic = (
        verdict == "NOT_AI"
        and intro is None
        and record.get("introducer_parent") is None
        and record.get("introducer_parent_absent") is True
        and EXTERNAL_VCS.search(provenance)
    )
    if not (isinstance(intro, str) and SHA40.match(intro)) and not external_vcs_bic:
        problems.append(
            f"{cid}: closed {verdict} requires a 40-hex introducer_sha "
            "or a verified non-Git SVN/CVS BIC boundary"
        )

    fix = record.get("fix_sha") or record.get("direct_fix_sha")
    if not (isinstance(fix, str) and SHA40.match(fix)):
        unpatched_record = record.get("unpatched")
        potential_fix = (
            (unpatched_record or {}).get("potential_fix")
            if isinstance(unpatched_record, dict)
            else None
        )
        if not (
            isinstance(unpatched_record, dict)
            and unpatched_record.get("confirmed") is True
            and isinstance(potential_fix, dict)
            and str(potential_fix.get("approach") or "").strip()
            and str(potential_fix.get("rationale") or "").strip()
        ):
            problems.append(
                f"{cid}: closed {verdict} requires fix_sha, or an explicit "
                "unpatched record with potential_fix approach+rationale"
            )
    return problems


def check_jsonl(path: Path) -> list[str]:
    problems: list[str] = []
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        record = json.loads(line)
        for item in check_record(record):
            problems.append(f"{path}:{idx}: {item}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--stdin", action="store_true")
    args = parser.parse_args()
    problems: list[str] = []
    if args.stdin:
        record = json.load(sys.stdin)
        problems.extend(check_record(record))
    for path in args.paths:
        problems.extend(check_jsonl(path))
    for line in problems:
        print(line, file=sys.stderr)
    if problems:
        print(f"{len(problems)} gate failure(s)", file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
