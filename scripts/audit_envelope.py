#!/usr/bin/env python3
"""Evidence-envelope gate (canon 2026-08-27, see artifacts/ledger-summary.md).

A closed ledger row (terminal status) must carry the full re-derivation
envelope: advisory_ids + single 40-hex introducer_sha (BLOCKED exempt) +
ai_marker + reasoning. Usage:

    python3 scripts/audit_envelope.py                # whole ledger
    python3 scripts/audit_envelope.py FILE.jsonl     # specific rows file
    python3 scripts/audit_envelope.py --class-id alias-xxx [FILE]
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

HEX40 = re.compile(r"^[0-9a-f]{40}$")
EXTERNAL_VCS = re.compile(
    r"\b(?:svn|subversion|cvs)\b.{0,400}\b(?:revision|changeset|r\d+)\b",
    re.I | re.S,
)
TERMINAL = {"NOT_AI", "AI_ROOT_CAUSE", "AI_CODE_FLAWED", "BLOCKED", "FALSE_POSITIVE"}
ITEM_ARRAYS = ("squash_audit", "partial_wave", "blocked535")


def payloads(row: dict) -> list:
    recs = [
        v
        for k, v in row.items()
        if isinstance(v, dict) and (k.endswith("_research") or k == "causal_research")
    ]
    for k in ITEM_ARRAYS:
        val = row.get(k)
        if isinstance(val, dict):
            recs.append(val)
        else:
            for item in val or []:
                if isinstance(item, dict):
                    recs.append(item)
    return recs

def external_vcs_bic(payload: dict) -> bool:
    provenance = " ".join(
        str(payload.get(key) or "")
        for key in ("flaw_origin", "evidence", "reasoning")
    )
    return (
        payload.get("introducer_sha") is None
        and payload.get("introducer_parent") is None
        and payload.get("introducer_parent_absent") is True
        and bool(EXTERNAL_VCS.search(provenance))
    )


def violations(row: dict) -> list:
    if row.get("status") not in TERMINAL:
        return []
    bad = []
    if not row.get("advisory_ids"):
        bad.append("advisory_ids missing")
    ps = payloads(row)
    bics = [p.get("introducer_sha") for p in ps if p.get("introducer_sha")]
    if row["status"] == "FALSE_POSITIVE":
        return bad  # withdrawn/rejected: no BIC, no AI marker required
    if row["status"] == "BLOCKED":
        if not any(p.get("reasoning") for p in ps):
            bad.append("BLOCKED without reasoning stating why no BIC")
    elif any(p.get("no_bic_reason") for p in ps):
        pass  # documented no-BIC-by-nature (supply-chain intrusion / data record / closed boundary)
    elif row["status"] == "NOT_AI" and any(external_vcs_bic(p) for p in ps):
        pass  # smallest public BIC is a verified non-Git SVN/CVS revision
    else:
        if not bics:
            bad.append("no introducer_sha anywhere in payload")
        elif not all(isinstance(b, str) and HEX40.match(b) for b in bics):
            bad.append(f"non-canonical introducer_sha: {[b[:24] for b in bics if not (isinstance(b, str) and HEX40.match(b))]}")
    if not any(p.get("ai_marker") is not None for p in ps):
        bad.append("ai_marker missing")
    if not any(p.get("reasoning") or p.get("bug_semantics") or p.get("evidence") for p in ps):
        bad.append("reasoning/bug_semantics/evidence missing")
    return bad


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    class_id = None
    if "--class-id" in sys.argv:
        class_id = sys.argv[sys.argv.index("--class-id") + 1]
    path = Path(args[0]) if args else ROOT / "artifacts/funnel-account-20260817.jsonl"
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    fails = 0
    for row in rows:
        if class_id and row.get("class_id") != class_id:
            continue
        v = violations(row)
        if v:
            fails += 1
            print(f"FAIL {row['class_id']} [{row.get('status')}]: {'; '.join(v)}")
    closed = sum(1 for r in rows if r.get("status") in TERMINAL)
    if fails:
        print(f"envelope gate: FAIL ({fails} bad rows of {closed} closed)")
        return 1
    print(f"envelope gate: ok ({closed} closed rows checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
