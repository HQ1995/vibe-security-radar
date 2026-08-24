#!/usr/bin/env python3
"""Split cross-review routes out of reviewed totals. Lane write-scope only."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
FREEZE = json.loads((HERE / "id_freeze.json").read_text())
GATES = (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
)

# First-wave new IDs minus dropped 239W, plus 9CR9 (only later row with atomic AI rem evidence).
ADJUDICATED_NEW = {
    "GHSA-24C8-4792-22HX",
    "GHSA-2F96-G7MH-G2HX",
    "GHSA-62Q4-447F-WV8H",
    "GHSA-6CQF-375W-639G",
    "GHSA-892R-P3JQ-JP24",
    "GHSA-89CF-6HMV-8RXM",
    "GHSA-956X-8GVW-WG5V",
    "GHSA-9CR9-25Q5-8PRJ",
    "GHSA-9QHQ-V63V-FV3J",
    "GHSA-C875-H985-HVRC",
    "GHSA-JXCW-QP4H-6JFQ",
    "GHSA-JXX9-PX88-PJ69",
    "GHSA-P6Q4-FGR8-VX4P",
    "GHSA-P8RR-9CVG-CX5J",
    "GHSA-Q9P7-WQXG-MRHC",
    "GHSA-RG3H-X3JW-7JM5",
    "GHSA-RWJ8-PGH3-R573",
    "GHSA-WVPP-8HX9-P66J",
    "GHSA-X2QX-6953-8485",
}
assert len(ADJUDICATED_NEW) == 19

SCREENED = {
    "GHSA-2MQJ-M65W-JGHX",
    "GHSA-6G6R-Q6GW-W8FG",
    "GHSA-8HJW-25CG-G52H",
    "GHSA-RG5Q-PP8P-F7JM",
    "GHSA-XCMW-GRXF-WJHJ",
}


def strip_gates(row: dict) -> dict:
    screening = {k: row.pop(k) for k in GATES if k in row}
    if screening:
        row["screening_or_preserved_gates"] = screening
    return row


def main():
    rows = [json.loads(l) for l in (HERE / "cases.jsonl").read_text().splitlines() if l.strip()]
    out = []
    for r in rows:
        cid = r["case_id"]
        r["schema_version"] = 2
        r["worker_pass_is_proposal"] = True
        if r.get("disposition") == "CROSS_REVIEW_ONLY":
            r["row_role"] = "CROSS_REVIEW_ROUTE"
            r["seven_gate_row"] = False
            r["adjudicated_by_this_lane"] = False
            r["verifier_instruction"] = (
                "Do not consume as a seven-gate row. Existing fp211 identity; "
                "this lane did not adjudicate the seven gates."
            )
            strip_gates(r)
        elif cid in SCREENED:
            r["row_role"] = "SCREENED_NOT_ADJUDICATED"
            r["seven_gate_row"] = False
            r["adjudicated_by_this_lane"] = False
            r["disposition"] = "SCREENED_NOT_ADJUDICATED"
            r["verifier_instruction"] = (
                "Do not consume as a seven-gate row. Keyword-dump screen only; "
                "not part of the bounded 19-ID adjudicated set."
            )
            strip_gates(r)
        elif cid in ADJUDICATED_NEW:
            r["row_role"] = "ADJUDICATED_NEW_ID"
            r["seven_gate_row"] = True
            r["adjudicated_by_this_lane"] = True
            r["verifier_instruction"] = (
                "This lane adjudicated all seven gates. Verdict is REJECT, not PASS. "
                "Worker PASS is only a proposal; this row is not an admission."
            )
            missing = [k for k in GATES if r.get(k) in (None, "NOT_EVALUATED")]
            if missing:
                raise SystemExit(f"{cid} still has unevaluated gates: {missing}")
            if r["verdict"] == "PASS":
                raise SystemExit(f"{cid} is PASS; this draft must stay 0 PASS")
        else:
            raise SystemExit(f"unclassified row {cid}")
        out.append(r)

    adj = [r for r in out if r["row_role"] == "ADJUDICATED_NEW_ID"]
    routes = [r for r in out if r["row_role"] == "CROSS_REVIEW_ROUTE"]
    screened = [r for r in out if r["row_role"] == "SCREENED_NOT_ADJUDICATED"]
    if len(adj) != 19 or len(routes) != 15:
        raise SystemExit(f"expected 19/15, got {len(adj)}/{len(routes)}")

    routes.sort(key=lambda r: r.get("fp211_ordinal") or 0)
    adj.sort(key=lambda r: r["case_id"])
    screened.sort(key=lambda r: r["case_id"])
    ordered = routes + adj + screened
    (HERE / "cases.jsonl").write_text("".join(json.dumps(r, ensure_ascii=True) + "\n" for r in ordered))

    kinds = {}
    for r in adj:
        k = (r.get("residual_classification") or {}).get("kind")
        kinds[k] = kinds.get(k, 0) + 1

    result = {
        "schema_version": 2,
        "lane": "herdr-260813-ghsa200-remediation",
        "task": "fresh AI_INCOMPLETE_REMEDIATION and AI_REINTRODUCTION across all repositories",
        "status": "COMPLETE",
        "completeness_scope": "bounded_adjudicated_new_ids",
        "ecosystem_coverage_claimed": False,
        "checkpoint": "leader-2026-08-13-exclude-cross-review-from-reviewed-totals",
        "started_at": "2026-08-13T16:23:00-04:00",
        "ended_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "output_dir": str(HERE),
        "clone_root": "/tmp/ghsa200-worker-clones/remediation",
        "worker_pass_is_proposal": True,
        "proposed_pass_count": 0,
        "input_hashes": FREEZE["input_hashes"],
        "counts": {
            "reviewed_rows": 19,
            "adjudicated_new_ids": 19,
            "seven_gate_consumable_rows": 19,
            "pass_proposals": 0,
            "reject": 19,
            "narrow": 0,
            "unknown": 0,
            "blocked": 0,
            "route_conflict_within_reviewed": 2,
            "cross_review_routes": 15,
            "screened_not_adjudicated": 5,
            "emitted_rows_total": 39,
            "residual_kinds_within_reviewed": kinds,
        },
        "row_roles": {
            "ADJUDICATED_NEW_ID": "seven-gate REJECT rows this lane actually reviewed; verifier may read gates; not an admission",
            "CROSS_REVIEW_ROUTE": "existing fp211 identity; excluded from reviewed totals; seven_gate_row=false",
            "SCREENED_NOT_ADJUDICATED": "dump-keyword screen; excluded from reviewed totals; seven_gate_row=false",
        },
        "adjudicated_new_ids": sorted(ADJUDICATED_NEW),
        "cross_review_route_ids": [r["case_id"] for r in routes],
        "screened_ids": sorted(SCREENED),
        "shared_paths_mutated": 0,
        "derivation_rule": "New IDs come from this lane's frozen first-party repo advisory dumps plus independently fetched first-party GHSA objects. Sibling fresh-am/fresh-nz files are not evidence.",
        "dedupe": {
            "against_fp211": "15 existing IDs are CROSS_REVIEW_ROUTE only; excluded from reviewed/adjudicated totals",
            "against_fresh_lanes": "GHSA-P8RR-9CVG-CX5J and GHSA-WVPP-8HX9-P66J are ROUTE_CONFLICT inside the 19; no PASS",
        },
        "blockers": [
            "Bounded reviewed set is 19 new IDs, all REJECT. 0 PASS proposals.",
            "COMPLETE applies only to that 19-ID set, not to ecosystem coverage.",
            "15 CROSS_REVIEW_ROUTE rows and 5 SCREENED_NOT_ADJUDICATED rows are not seven-gate consumable.",
        ],
    }
    (HERE / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n")
    print(json.dumps(result["counts"], indent=2))


if __name__ == "__main__":
    main()
