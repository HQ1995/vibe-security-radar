#!/usr/bin/env python3
"""Accept independent-review outputs against the frozen round12 assignment file."""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round12-top50-20260830-e6371483-bb5e-46b4-8dbd-5385b370881a"
ASSIGN = LANE / "independent-review-assignments.jsonl"
OUT = LANE / "independent-review"
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"

EXPECTED_KEYS = [
    "worker", "review_agent_id", "class_id", "case_id", "repo", "primary_verdict",
    "review_verdict", "protocol_checks", "findings", "corrected_fields", "remaining_gap",
]
CHECK_KEYS = {
    "vulnerability_mechanism", "atomic_bic", "immediate_parent_absence",
    "squash_member_decomposition", "affected_release_membership",
    "fixed_release_membership", "direct_fix_or_unpatched", "bic_only_ai_attribution",
}
ALLOWED = {"CONFIRMED", "CORRECTION_REQUIRED", "EVIDENCE_GAP", "BLOCKED"}


def main() -> int:
    assignments = [json.loads(x) for x in ASSIGN.read_text().splitlines() if x.strip()]
    expected = {a["worker"] for a in assignments}
    by_worker = {a["worker"]: a for a in assignments}
    paths = sorted(p for p in OUT.glob("w[0-9][0-9][0-9].json"))
    present = {p.stem for p in paths}
    extra = sorted(present - expected)
    missing = sorted(expected - present)
    problems = []
    hash_ok = True
    reviews = []
    for path in paths:
        if path.stem not in expected:
            continue
        a = by_worker[path.stem]
        bh = hashlib.sha256((ROOT / a["bundle"]).read_bytes()).hexdigest()
        ph = hashlib.sha256((ROOT / a["primary"]).read_bytes()).hexdigest()
        if bh != a["bundle_sha256"] or ph != a["primary_sha256"]:
            hash_ok = False
            problems.append(f"{path.stem}: input hash mismatch")
        rec = json.loads(path.read_text())
        reviews.append(rec)
        if list(rec) != EXPECTED_KEYS:
            problems.append(f"{path.stem}: key order mismatch")
        ident = (rec.get("worker"), rec.get("class_id"), rec.get("case_id"), rec.get("repo"), rec.get("primary_verdict"))
        want = (a["worker"], a["class_id"], a["case_id"], a["repo"], a["primary_verdict"])
        if ident != want:
            problems.append(f"{path.stem}: identity mismatch {ident} != {want}")
        if rec.get("review_verdict") not in ALLOWED:
            problems.append(f"{path.stem}: bad review_verdict")
        if set(rec.get("protocol_checks") or {}) != CHECK_KEYS:
            problems.append(f"{path.stem}: protocol_checks keys")
        if not rec.get("review_agent_id"):
            problems.append(f"{path.stem}: empty review_agent_id")
        if not isinstance(rec.get("findings"), list):
            problems.append(f"{path.stem}: findings not list")
        if not isinstance(rec.get("corrected_fields"), dict):
            problems.append(f"{path.stem}: corrected_fields not dict")
        if rec.get("review_verdict") == "CONFIRMED" and rec.get("corrected_fields"):
            problems.append(f"{path.stem}: CONFIRMED has corrected_fields")
        if rec.get("review_verdict") == "CORRECTION_REQUIRED" and not rec.get("corrected_fields"):
            problems.append(f"{path.stem}: CORRECTION_REQUIRED empty corrected_fields")
        if rec.get("review_verdict") in {"EVIDENCE_GAP", "BLOCKED"} and not str(rec.get("remaining_gap") or "").strip():
            problems.append(f"{path.stem}: missing remaining_gap")
        if rec.get("review_verdict") == "CONFIRMED" and rec.get("remaining_gap") is not None:
            problems.append(f"{path.stem}: CONFIRMED remaining_gap must be null")

    proposed_verdict = {}
    for rec in reviews:
        cf = rec.get("corrected_fields") or {}
        proposed_verdict[rec["worker"]] = cf.get("verdict", rec.get("primary_verdict"))
    flips = []
    for rec in reviews:
        primary = rec.get("primary_verdict")
        proposed = proposed_verdict.get(rec["worker"])
        if rec.get("review_verdict") == "CORRECTION_REQUIRED" and proposed != primary:
            flips.append({
                "worker": rec["worker"],
                "primary": primary,
                "proposed": proposed,
                "repo": rec.get("repo"),
                "case_id": rec.get("case_id"),
            })
        if rec.get("review_verdict") in {"EVIDENCE_GAP", "BLOCKED"} and rec.get("primary_verdict") not in {rec.get("review_verdict"), "EVIDENCE_GAP"}:
            flips.append({
                "worker": rec["worker"],
                "primary": primary,
                "proposed": rec.get("review_verdict"),
                "repo": rec.get("repo"),
                "case_id": rec.get("case_id"),
            })

    hist = Counter(r.get("review_verdict") for r in reviews)
    primary_hist = Counter(r.get("primary_verdict") for r in reviews)
    corr = sorted(r["worker"] for r in reviews if r.get("review_verdict") == "CORRECTION_REQUIRED")
    gap = sorted(r["worker"] for r in reviews if r.get("review_verdict") == "EVIDENCE_GAP")
    blocked = sorted(r["worker"] for r in reviews if r.get("review_verdict") == "BLOCKED")
    confirmed = sorted(r["worker"] for r in reviews if r.get("review_verdict") == "CONFIRMED")
    summary = {
        "assigned": len(assignments),
        "present": len(present & expected),
        "missing": missing,
        "extra": extra,
        "duplicates": 0,
        "problems": problems[:80],
        "problem_count": len(problems),
        "hash_ok": hash_ok,
        "primary_verdict_histogram": dict(primary_hist),
        "review_verdict_histogram": dict(hist),
        "confirmed": confirmed,
        "correction_required": corr,
        "evidence_gap": gap,
        "blocked": blocked,
        "verdict_flips": flips,
        "complete": len(missing) == 0 and not extra and not problems and hash_ok,
        "ledger_sha256": hashlib.sha256(LEDGER.read_bytes()).hexdigest() if LEDGER.is_file() else None,
    }
    print(json.dumps(summary, indent=1))
    return 0 if summary["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
