#!/usr/bin/env python3
"""Bind batch2 terminals to CONTRACT patch-delta revision. Lane-only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

LANE = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-delta-even-batch2")
CONTRACT = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md")
EXPECTED = "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"

REM_EVAL = {
    "GHSA-434R-7C99-HWF3": {
        "ai_security_boundary_rewrite": False,
        "released_residual_in_that_boundary": False,
        "first_party_advisory_covers_residual": False,
        "later_closure_amends_same_boundary": False,
        "sibling_or_unrelated_old_hole": False,
        "result": "FAIL",
        "reason": "Detector hit is product language (LLM-generated tool-call URLs), not an AI-authored security-boundary rewrite. Patch-delta does not apply as a countable rem row.",
    },
    "GHSA-4CWX-7WF7-3272": {
        "ai_security_boundary_rewrite": True,
        "released_residual_in_that_boundary": False,
        "first_party_advisory_covers_residual": False,
        "later_closure_amends_same_boundary": False,
        "sibling_or_unrelated_old_hole": True,
        "result": "FAIL",
        "reason": "Claude commits rewrite cache revalidation / stale-if-error. Official GHSA closer amends empty qualified private/no-cache parsing. That is a sibling cache hole, not a residual in the AI-added boundary.",
    },
    "GHSA-55H5-XMCQ-C37V": {
        "ai_security_boundary_rewrite": True,
        "released_residual_in_that_boundary": False,
        "first_party_advisory_covers_residual": False,
        "later_closure_amends_same_boundary": False,
        "sibling_or_unrelated_old_hole": True,
        "result": "FAIL",
        "reason": "Claude 4d8ebcec rewrites object-stream cache authority. Official GHSA closer speeds broken-xref recovery. Sibling hole in _reader.py, not a residual of the Claude boundary.",
    },
    "GHSA-6VH2-WG4H-4VWJ": {
        "ai_security_boundary_rewrite": True,
        "released_residual_in_that_boundary": False,
        "first_party_advisory_covers_residual": False,
        "later_closure_amends_same_boundary": False,
        "sibling_or_unrelated_old_hole": True,
        "result": "FAIL",
        "reason": "Claude aee37e16 adds webhook trigger surface. Official closer removes a pre-existing human ...overrideConfig spread. Untouched sibling path, not a residual of the Claude webhook boundary.",
    },
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main() -> None:
    got = sha256_file(CONTRACT)
    if got != EXPECTED:
        raise SystemExit(f"CONTRACT hash {got} != {EXPECTED}")

    cases = [json.loads(l) for l in (LANE / "cases.jsonl").read_text().splitlines()]
    if len(cases) != 80:
        raise SystemExit("expected 80 cases")
    out = []
    for c in cases:
        gid = c["case_id"]
        c["contract_hash"] = EXPECTED
        # Origin/contributor but-for stays. Patch-delta is a rem-class screen only.
        c["but_for_rule"] = "origin_contributor_unchanged"
        if gid in REM_EVAL:
            spec = REM_EVAL[gid]
            c["incomplete_remediation_evaluated"] = True
            c["contribution_class"] = "HUMAN_ORIGIN"
            c["rem_patch_delta"] = spec
            c["verdict"] = "REJECT"
            c["proposed_pass"] = False
            bf = c.get("gates", {}).get("but_for_gate", {})
            if str(bf.get("reason", "")).startswith("Patch-delta FAIL"):
                c["gates"]["but_for_gate"] = {
                    "status": "REJECT",
                    "reason": "Removing a human introducing change does not establish an AI-authored mechanism.",
                }
        else:
            c["incomplete_remediation_evaluated"] = False
        out.append(c)
    (LANE / "cases.jsonl").write_text("".join(json.dumps(c, ensure_ascii=True) + "\n" for c in out))

    res = json.loads((LANE / "result.json").read_text())
    res["contract_hash"] = EXPECTED
    res["contract_revision"] = (
        "AI_INCOMPLETE_REMEDIATION uses patch-delta: rollback may reopen a broader old "
        "vulnerability; count only if an AI security attempt adds/rewrites a boundary, a "
        "released residual in that boundary is first-party-advisory covered, and later "
        "same-mechanism closure directly amends it. Sibling holes do not count. "
        "Origin/contributor but-for is unchanged."
    )
    res["incomplete_remediation_rows"] = []
    res["incomplete_remediation_rows_evaluated"] = sorted(REM_EVAL)
    res["incomplete_remediation_pass"] = 0
    res["origin_contributor_but_for"] = "unchanged"
    res["proposed_pass_count"] = 0
    res["input_hashes"]["leader_contract.md"] = EXPECTED
    res["input_hashes"]["cases_jsonl"] = sha256_file(LANE / "cases.jsonl")
    (LANE / "result.json").write_text(json.dumps(res, indent=2) + "\n")
    print(json.dumps({"contract": EXPECTED, "rem_eval": 4, "pass": 0, "rows": 80}, indent=2))


if __name__ == "__main__":
    main()
