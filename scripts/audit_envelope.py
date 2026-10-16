#!/usr/bin/env python3
import argparse
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
PROSE_KEYS = ("reasoning", "bug_semantics", "evidence", "flaw_origin")


def has_prose(payload: dict) -> bool:
    return any(str(payload.get(key) or "").strip() for key in PROSE_KEYS)


def status_of_verdict(verdict):
    return "BLOCKED" if verdict in ("EVIDENCE_GAP", "BLOCKED") else verdict


def payloads(row: dict) -> list:
    accepted = row.get("causal_research")
    return [accepted] if isinstance(accepted, dict) and accepted else []

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
    if row["status"] == "NOT_AI" and (
        row.get("site_scope") is not None or row.get("site_tier") is not None
    ):
        bad.append("NOT_AI must not carry site_scope/site_tier")
    if "causal_research" in row:
        accepted = row["causal_research"]
        if not isinstance(accepted, dict) or not accepted:
            bad.append("causal_research must be a nonempty object")
        elif status_of_verdict(accepted.get("verdict")) != row["status"]:
            bad.append("causal_research verdict must match status")
    ps = payloads(row)
    bics = [p.get("introducer_sha") for p in ps if p.get("introducer_sha")]
    if row["status"] == "FALSE_POSITIVE":
        return bad
    if row["status"] == "BLOCKED":
        if not any(p.get("reasoning") or p.get("remaining_gap") for p in ps):
            bad.append("BLOCKED without reasoning or remaining_gap stating what is unknown")
    elif any(p.get("no_bic_reason") for p in ps):
        pass
    elif row["status"] == "NOT_AI" and any(external_vcs_bic(p) for p in ps):
        pass
    else:
        if not bics:
            bad.append("no introducer_sha anywhere in payload")
        elif not all(isinstance(b, str) and HEX40.match(b) for b in bics):
            bad.append(f"non-canonical introducer_sha: {[b[:24] for b in bics if not (isinstance(b, str) and HEX40.match(b))]}")
    if not any(p.get("ai_marker") is not None for p in ps):
        bad.append("ai_marker missing")
    if not any(has_prose(p) for p in ps):
        bad.append("/".join(PROSE_KEYS) + " missing")
    return bad


def main() -> int:
    parser = argparse.ArgumentParser(description="Check every closed ledger row carries its evidence envelope")
    parser.add_argument("ledger", nargs="?", type=Path, default=ROOT / "artifacts/ledger.jsonl")
    parser.add_argument("--class-id")
    args = parser.parse_args()
    class_id = args.class_id
    rows = [json.loads(l) for l in args.ledger.read_text().splitlines() if l.strip()]
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
