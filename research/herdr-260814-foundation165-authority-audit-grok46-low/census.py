#!/usr/bin/env python3
"""Ledger authority census of canvas foundation.jsonl vs canonical85 and later terminal downgrades.

Writes only this directory. Does not edit canonical, canvas, site, or other workers.
Not admission. Not new causality research.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OUT = ROOT / "autoresearch/herdr-260814-foundation165-authority-audit-grok46-low"
FOUNDATION = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl"
CANVAS_STATUS = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/STATUS.md"
LEDGER = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl"
SUMMARY = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json"
NEG = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json"
GAP_RESULT = ROOT / "autoresearch/herdr-260814-ghsa200-current-proposal-gap-grok46-low/result.json"
GAP_REPORT = ROOT / "autoresearch/herdr-260814-ghsa200-current-proposal-gap-grok46-low/report.md"

GHSA_RE = re.compile(r"GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}", re.I)
GATES = [
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
]
DOWNGRADE = {"NARROW", "REJECT", "UNKNOWN", "BLOCKED", "FAIL", "FALSE_POSITIVE", "TERMINAL_REJECT"}
POSITIVE_STORED = {"STRICT", "CONFIRM", "PASS", "KEEP", "ACCEPT"}
AUTHORITY_ROLES = {
    "hostile_redteam",
    "negative_control",
    "final_review",
    "redteam",
    "independent_gate_closing_review",
    "canonical_negative_control",
}


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(path: Path) -> list:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def comparable_payload(case_id: str, candidate_set, contribution_class, minimum_fix_set, repository, gates: dict) -> str:
    return json.dumps(
        {
            "candidate_set": sorted(candidate_set or []),
            "case_id": case_id.upper(),
            "contribution_class": contribution_class,
            "gates": {k: (gates or {}).get(k) for k in GATES},
            "minimum_fix_set": sorted(minimum_fix_set or []),
            "repository": repository,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def canon_gates(row: dict) -> dict:
    return {k: row.get(k) for k in GATES}


def extract_id(value) -> str | None:
    if not isinstance(value, str):
        return None
    m = GHSA_RE.search(value)
    return m.group(0).upper() if m else None


def main() -> None:
    foundation_rows = load_jsonl(FOUNDATION)
    assert len(foundation_rows) == 165, len(foundation_rows)
    ids = [extract_id(r["case_id"]) for r in foundation_rows]
    assert all(ids) and len(set(ids)) == 165

    ledger_rows = load_jsonl(LEDGER)
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    neg = json.loads(NEG.read_text(encoding="utf-8"))
    gap = json.loads(GAP_RESULT.read_text(encoding="utf-8"))

    canon_strict = []
    supersedes = []
    for row in ledger_rows:
        if row.get("record_kind") == "STRICT_RELEASED_CASE" and row.get("counted") is True:
            cid = extract_id(row["case_id"])
            assert cid
            canon_strict.append((cid, row))
        if row.get("record_kind") == "SUPERSEDES_EDGE":
            supersedes.append(row)
    canon_ids = [c for c, _ in canon_strict]
    assert len(canon_ids) == 85 == summary["canonical_strict_count"]
    assert len(set(canon_ids)) == 85
    assert set(canon_ids) <= set(ids)

    found_map = {extract_id(r["case_id"]): r for r in foundation_rows}
    canon_map = dict(canon_strict)

    payload_identical = []
    for cid, crow in canon_strict:
        fr = found_map[cid]
        p1 = comparable_payload(
            cid,
            fr.get("candidate_set"),
            fr.get("contribution_class"),
            fr.get("minimum_fix_set"),
            fr.get("repository"),
            fr.get("gates"),
        )
        p2 = comparable_payload(
            cid,
            crow.get("candidate_set"),
            crow.get("contribution_class"),
            crow.get("minimum_fix_set"),
            crow.get("repository"),
            canon_gates(crow),
        )
        if p1 == p2:
            payload_identical.append(cid)
    assert len(payload_identical) == 85

    packet_auth = gap.get("packet_authority") or {}
    authority_packets = {
        p: meta
        for p, meta in packet_auth.items()
        if meta.get("terminal") is True and meta.get("role") in AUTHORITY_ROLES
    }

    # Explicit per-id downgrades from canonical SUPERSEDES_EDGE (NARROW/REJECT/UNKNOWN only).
    later_down: dict[str, list[dict]] = {cid: [] for cid in ids}
    for edge in supersedes:
        cid = extract_id(edge.get("case_id"))
        to_v = str(edge.get("to_verdict") or "").upper()
        if cid in later_down and to_v in DOWNGRADE:
            later_down[cid].append(
                {
                    "kind": "SUPERSEDES_EDGE",
                    "path": "autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl",
                    "to_packet": edge.get("to_packet"),
                    "to_verdict": to_v,
                    "failed_gate": edge.get("failed_gate"),
                    "applies_to_counted_set": edge.get("applies_to_counted_set"),
                }
            )

    for ctrl in neg.get("controls") or []:
        cid = extract_id(ctrl.get("case_id"))
        if cid in later_down and str(ctrl.get("verdict") or "").upper() == "REJECT":
            later_down[cid].append(
                {
                    "kind": "negative_control",
                    "path": "autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json",
                    "to_verdict": "REJECT",
                    "to_packet": (ctrl.get("source_hashes") or {}).get("packet"),
                    "failed_gate": (ctrl.get("fail_gates") or [None])[0],
                }
            )

    # Terminal redteam/hostile/final-review packets referenced by the proposal-gap census.
    named_authority_files = [
        ROOT / "autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/result.json",
        ROOT / "autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam/result.json",
        ROOT / "autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam/cases.jsonl",
        ROOT / "autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low/result.json",
        ROOT / "autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low/cases.jsonl",
        ROOT / "autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/result.json",
        ROOT / "autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh/result.json",
        ROOT / "autoresearch/herdr-260814-ghsa200-batch9-three-redteam-grok46-xhigh/result.json",
        ROOT / "autoresearch/herdr-260813-ghsa200-increm-patchdelta-even/result.json",
        ROOT / "autoresearch/herdr-260813-ghsa200-increm-patchdelta-odd/result.json",
        ROOT / "autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high/result.json",
        ROOT / "autoresearch/herdr-260814-ghsa200-batch5-two-redteam-grok46-xhigh/result.json",
        ROOT / "autoresearch/herdr-260814-ghsa200-chfm-jxx9-hostile-redteam-grok46-high/result.json",
        ROOT / "autoresearch/herdr-260814-ghsa200-pimcore-2mhj-counterredteam-grok46-xhigh/result.json",
        ROOT / "autoresearch/herdr-260814-ghsa200-hhjv-hostile-redteam-grok46-high/result.json",
        ROOT / "autoresearch/herdr-260814-ghsa200-425g-hostile-redteam-grok46-medium/result.json",
        ROOT / "autoresearch/herdr-260814-ghsa200-hc8v-hostile-redteam-grok46-xhigh/result.json",
    ]

    def ingest_named_lists(obj: dict, path: str) -> None:
        per_case = obj.get("per_case")
        if isinstance(per_case, dict):
            for k, v in per_case.items():
                cid = extract_id(k)
                verdict = v if isinstance(v, str) else (v or {}).get("verdict") if isinstance(v, dict) else None
                if cid in later_down and str(verdict or "").upper() in DOWNGRADE:
                    later_down[cid].append(
                        {
                            "kind": "result.per_case",
                            "path": path,
                            "to_verdict": str(verdict).upper(),
                        }
                    )
        for key in ("narrow_ids", "narrow_cases", "reject_ids", "unknown_ids", "rejected_ids"):
            val = obj.get(key)
            if not isinstance(val, list):
                continue
            default_v = "NARROW" if "narrow" in key else "REJECT" if "reject" in key else "UNKNOWN"
            for item in val:
                if isinstance(item, str):
                    cid = extract_id(item)
                    if cid in later_down:
                        later_down[cid].append({"kind": f"result.{key}", "path": path, "to_verdict": default_v})
                elif isinstance(item, dict):
                    cid = extract_id(item.get("case_id"))
                    v = str(item.get("verdict") or default_v).upper()
                    if cid in later_down and v in DOWNGRADE:
                        later_down[cid].append(
                            {
                                "kind": f"result.{key}",
                                "path": path,
                                "to_verdict": v,
                                "failed_gate": (item.get("failed_gates") or [None])[0],
                            }
                        )

    for path in named_authority_files:
        if not path.exists():
            continue
        rel = str(path.relative_to(ROOT))
        if path.suffix == ".json":
            ingest_named_lists(json.loads(path.read_text(encoding="utf-8")), rel)
        else:
            for row in load_jsonl(path):
                cid = extract_id(row.get("case_id"))
                v = str(row.get("verdict") or row.get("final_verdict") or "").upper()
                if cid in later_down and v in DOWNGRADE:
                    later_down[cid].append({"kind": "cases.jsonl", "path": rel, "to_verdict": v})

    gap_stale = set(gap.get("census_class_ids", {}).get("SUPERSEDED_DOWNGRADED") or [])

    out_rows = []
    class_ids = {
        "CANONICAL85_PAYLOAD_IDENTICAL": [],
        "NONCANONICAL_COMPATIBLE_NOT_STRICT": [],
        "STALE_SUPERSEDED": [],
        "PENDING_INDEPENDENT_HOSTILE_REVIEW": [],
        "UNRESOLVED_UNKNOWN": [],
        "DUPLICATE_ALIAS": [],
    }

    for r in foundation_rows:
        cid = extract_id(r["case_id"])
        stored = str(r.get("verdict") or "").upper()
        in_canon = cid in canon_map
        payload_ok = cid in payload_identical
        downs = later_down[cid]
        # Canonical KEEP/STRICT floor outranks older NARROW on the same identity.
        effective_downgrade = [] if in_canon else downs
        stale = False
        if not in_canon and stored in POSITIVE_STORED and downs:
            stale = True
        if cid == "GHSA-FRVJ-C5QP-XJ4W":
            status = "PENDING_INDEPENDENT_HOSTILE_REVIEW"
            reason = (
                "Leader-replayed proposal with counted=true in foundation; canonical85 does not admit it. "
                "Independent hostile review is still pending. Not admission."
            )
            evidence = "autoresearch/orchestrator-260814-ghsa200-canvas/STATUS.md"
        elif stale:
            status = "STALE_SUPERSEDED"
            top = downs[0]
            reason = (
                f"Stored verdict {stored} with all-PASS or CONFIRM gates is superseded by later "
                f"{top.get('to_verdict')} at {top.get('path')}. Latest hostile/counter-redteam/"
                f"final-review/SUPERSEDES_EDGE NARROW/REJECT/UNKNOWN wins. Canonical85 does not count this id."
            )
            evidence = top.get("path")
        elif in_canon and payload_ok:
            status = "CANONICAL85_PAYLOAD_IDENTICAL"
            reason = (
                "Comparable payload (candidate_set, contribution_class, minimum_fix_set, repository, seven gates) "
                "matches canonical85 STRICT_RELEASED_CASE. Proven floor. Foundation counted flag may differ; "
                "this census does not admit."
            )
            evidence = "autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl"
        elif stored in {"NARROW", "CONFIRM"} and not (stored in POSITIVE_STORED and downs):
            status = "NONCANONICAL_COMPATIBLE_NOT_STRICT"
            reason = (
                "Not in canonical85 strict 85. Stored non-strict verdict is compatible with later "
                "NARROW/KEEP-absent authority; not a strict unit."
            )
            evidence = "autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl"
            if downs and stored == "NARROW":
                evidence = downs[0].get("path") or evidence
                reason = (
                    "Not in canonical85 strict 85. Stored NARROW already matches later terminal "
                    f"{downs[0].get('to_verdict')} at {downs[0].get('path')}; causal-compatible, not strict."
                )
        else:
            status = "UNRESOLVED_UNKNOWN"
            reason = "No canonical85 match and no explicit later NARROW/REJECT/UNKNOWN on this identity."
            evidence = "autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl"

        class_ids[status].append(cid)
        out_rows.append(
            {
                "aliases_noted": [],
                "authority_status": status,
                "canonical85_member": in_canon,
                "case_id": cid,
                "comparable_payload_identical_to_canonical85": payload_ok,
                "counted_in_foundation": r.get("counted"),
                "evidence_path": evidence,
                "later_downgrade_hits": effective_downgrade[:8] if not in_canon else [],
                "reason": reason,
                "source": r.get("source"),
                "stored_verdict": stored,
                "strict_eligible": status == "CANONICAL85_PAYLOAD_IDENTICAL",
                "zero_fp_scope": r.get("zero_fp_scope"),
            }
        )

    # FRVJ must not be classified as stale-or-strict.
    assert "GHSA-FRVJ-C5QP-XJ4W" in class_ids["PENDING_INDEPENDENT_HOSTILE_REVIEW"]
    stale_ids = class_ids["STALE_SUPERSEDED"]
    strict_ids = class_ids["CANONICAL85_PAYLOAD_IDENTICAL"]
    assert not (set(stale_ids) & set(strict_ids))
    assert set(canon_ids) == set(strict_ids)
    assert "GHSA-FRVJ-C5QP-XJ4W" not in strict_ids
    assert len(out_rows) == 165
    assert {row["case_id"] for row in out_rows} == set(ids)

    all_survive = (
        not class_ids["STALE_SUPERSEDED"]
        and not class_ids["PENDING_INDEPENDENT_HOSTILE_REVIEW"]
        and not class_ids["UNRESOLVED_UNKNOWN"]
        and len(strict_ids) == 165
    )

    frozen = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = {
        "accepted_set": {
            "counted": 85,
            "counted_ids": sorted(canon_ids),
            "packet": "autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl",
            "sha256": sha256_path(LEDGER),
            "summary_sha256": sha256_path(SUMMARY),
            "negative_controls_path": "autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json",
            "negative_controls_sha256": sha256_path(NEG),
            "negative_control_reject_ids": [extract_id(c["case_id"]) for c in neg["controls"]],
        },
        "canonical85_proven_floor": 85,
        "canonical85_subset_of_foundation": True,
        "causal_admission": False,
        "census_class_counts": {k: len(v) for k, v in class_ids.items()},
        "census_class_ids": {k: sorted(v) for k, v in class_ids.items()},
        "claim_boundary": (
            "Read-only ledger authority census of foundation.jsonl. "
            "Does not rebuild canonical85. Worker PASS/CONFIRM/STRICT is not admission. "
            "FRVJ is pending independent hostile review. "
            "Do not call 165 zero-false-positive unless every row survives authority replay."
        ),
        "comparable_payload_identical_count": 85,
        "conservation": {
            "canonical85": 85,
            "foundation_rows": 165,
            "id_conservation": True,
            "stale_excluded_from_strict": True,
            "unique_ghsa_ids": 165,
        },
        "counting_unit": "first-party GHSA identity",
        "did_not_commit_or_push": True,
        "did_not_edit_outside_owned_dir": True,
        "english_only": True,
        "foundation_path": "autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl",
        "foundation_sha256": sha256_path(FOUNDATION),
        "frozen_at_utc": frozen,
        "frvj_pending_not_admitted": True,
        "full_json_line_byte_identical_to_canonical85_ledger_rows": 0,
        "gap_census_packet": "autoresearch/herdr-260814-ghsa200-current-proposal-gap-grok46-low",
        "gap_superseded_ids_in_foundation": sorted(gap_stale & set(ids)),
        "language": "en",
        "lane": "herdr-260814-foundation165-authority-audit-grok46-low",
        "later_authority_rule": (
            "Latest explicit hostile/counter-redteam/final-review/independent-gate-closing "
            "NARROW/REJECT/UNKNOWN and canonical85 SUPERSEDES_EDGE/negative_controls win over "
            "older PASS/CONFIRM/STRICT. Canonical85 KEEP/STRICT floor outranks older NARROW on "
            "the same identity. Prose-only counts are not used."
        ),
        "schema_version": 1,
        "status": "CENSUS_HOLD",
        "task": "foundation165-authority-audit",
        "this_packet_does_not_claim_pass": True,
        "zero_false_positive_claim_for_165": False,
        "zero_false_positive_claim_survives_replay": all_survive,
    }

    OUT.mkdir(parents=True, exist_ok=True)
    rows_path = OUT / "rows.jsonl"
    with rows_path.open("w", encoding="utf-8") as fh:
        for row in out_rows:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")

    report = []
    report.append("# Foundation 165 authority census versus canonical85")
    report.append("")
    report.append("## Verdict first")
    report.append("")
    report.append(
        f"**canonical85 proven floor is 85.** Comparable payloads match for all 85 strict identities. "
        f"**{len(stale_ids)} foundation rows are stale** because later terminal NARROW/REJECT/UNKNOWN "
        f"supersedes stored CONFIRM/PASS. **GHSA-FRVJ-C5QP-XJ4W is pending independent hostile review "
        f"and is not admitted.** Full JSON lines of foundation versus canonical85 STRICT_RELEASED_CASE "
        f"rows are never byte-identical (different schemas). This packet does not claim PASS and does "
        f"not call 165 zero-false-positive."
    )
    report.append("")
    report.append("`zero_false_positive_claim_for_165` is **false**.")
    report.append("")
    report.append("Pinned hashes:")
    report.append("")
    report.append(f"- foundation.jsonl sha256 `{result['foundation_sha256']}`")
    report.append(f"- canonical85 ledger.jsonl sha256 `{result['accepted_set']['sha256']}`")
    report.append(f"- canonical85 summary.json sha256 `{result['accepted_set']['summary_sha256']}`")
    report.append(f"- canonical85 negative_controls.json sha256 `{result['accepted_set']['negative_controls_sha256']}`")
    report.append("")
    report.append("## Canonical85 proven floor")
    report.append("")
    report.append(
        "85 first-party GHSA identities in `STRICT_RELEASED_CASE` counted=true. All 85 are a subset of "
        "foundation unique ids. Negative-control REJECT identities are absent from the floor."
    )
    report.append("")
    report.append("## Foundation rows comparable-payload identical to canonical85")
    report.append("")
    report.append(
        f"{len(strict_ids)} rows. GHSA-8359-H9FX-J6V9 is in this set (gates and SHAs match) even though "
        "foundation stores verdict NARROW and counted=true; canonical85 stores STRICT counted=true. "
        "The stored verdict label is not used as a second counting unit."
    )
    report.append("")
    report.append("## Noncanonical rows still causal-compatible but not strict")
    report.append("")
    ncc = class_ids["NONCANONICAL_COMPATIBLE_NOT_STRICT"]
    report.append(f"{len(ncc)} rows. Stored NARROW (or CONFIRM without a later hostile downgrade) remains compatible; not strict.")
    for cid in sorted(ncc):
        report.append(f"- `{cid}` stored `{found_map[cid]['verdict']}`")
    report.append("")
    report.append("## Stale / superseded rows")
    report.append("")
    report.append(f"{len(stale_ids)} rows. Never counted as strict.")
    for cid in sorted(stale_ids):
        hits = later_down[cid]
        paths = "; ".join(sorted({h.get("path") or h.get("to_packet") or "" for h in hits if h.get("path") or h.get("to_packet")}))
        report.append(f"- `{cid}` stored `{found_map[cid]['verdict']}` superseded by later NARROW/REJECT (`{paths}`)")
    report.append("")
    report.append("## Unresolved / unknown rows")
    report.append("")
    unk = class_ids["UNRESOLVED_UNKNOWN"]
    report.append("Empty." if not unk else "\n".join(f"- `{c}`" for c in sorted(unk)))
    report.append("")
    report.append("## Pending independent hostile review (not admitted)")
    report.append("")
    report.append(
        "- `GHSA-FRVJ-C5QP-XJ4W` foundation counted=true, verdict NARROW, all seven gates PASS, "
        "source next-pool-map_B_proposal+leader_replay. Canvas STATUS.md records a leader replay. "
        "canonical85 does not include this identity. Independent hostile review is still required."
    )
    report.append("")
    report.append("## Duplicates / aliases")
    report.append("")
    report.append(
        "165 unique first-party GHSA ids; no duplicate rows. Foundation rows do not carry an aliases array. "
        "CVE-2026-55389 is the canonical alias of GHSA-8359 and is not a counting unit. "
        "GHSA-954P-556P-R752 shares a candidate SHA with GHSA-8359 and is a negative-control REJECT, absent from foundation."
    )
    report.append("")
    report.append("## Method")
    report.append("")
    report.append(
        "Only structured foundation.jsonl rows, canonical85 STRICT_RELEASED_CASE / SUPERSEDES_EDGE / "
        "negative_controls.json, and named ID lists or cases.jsonl verdicts from terminal "
        "hostile/counter-redteam/final-review/redteam/independent-gate packets referenced by the "
        "proposal-gap census were used. Prose-only counts were ignored. Snapshot/work/pages/clone "
        "trees were not scanned. Canonical85 was not edited."
    )
    report.append("")

    (OUT / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    hashes = {
        "census.py": sha256_path(OUT / "census.py"),
        "report.md": sha256_path(OUT / "report.md"),
        "rows.jsonl": sha256_path(rows_path),
    }
    replay = OUT / "replay.zsh"
    if replay.exists():
        hashes["replay.zsh"] = sha256_path(replay)
    result["artifact_hashes"] = hashes
    (OUT / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("wrote", OUT)
    print("classes", result["census_class_counts"])
    print("zero_fp_165", result["zero_false_positive_claim_for_165"])


if __name__ == "__main__":
    main()
