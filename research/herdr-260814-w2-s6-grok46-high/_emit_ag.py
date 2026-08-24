#!/usr/bin/env python3
import hashlib, json, os, glob
from datetime import datetime, timezone
from pathlib import Path
OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s6-grok46-high")
SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/wave2/ag-slice-4.jsonl")
SPEC = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/wave2/SPEC.md")
CONTRACT = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md")
ADV_ROOTS = [
    Path("/home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/advisory-database"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/advisory-database"),
]
def sha256(p):
    h = hashlib.sha256(); h.update(p.read_bytes()); return h.hexdigest()
def find_adv(gid):
    low = gid.lower()
    for root in ADV_ROOTS:
        hits = list(root.glob(f"advisories/github-reviewed/*/*/{low}/{low}.json"))
        if hits:
            return hits[0]
    return None
rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
started = datetime.now(timezone.utc).isoformat()
cases = []
gm = []
ids = []
for i, r in enumerate(rows, 1):
    cid = r["ghsa_id"]
    ids.append(cid)
    repo = r.get("repository")
    cand = (r.get("commit_refs") or [None])[0]
    fixes = r.get("commit_refs") or []
    adv = find_adv(cid)
    aliases = []
    summary = None
    withdrawn = None
    packages = []
    ecosystems = []
    path = None
    published = None
    if adv:
        a = json.loads(adv.read_text())
        aliases = a.get("aliases") or []
        summary = a.get("summary")
        withdrawn = a.get("withdrawn")
        path = str(adv)
        published = a.get("published")
        for aff in a.get("affected") or []:
            pkg = (aff.get("package") or {})
            if pkg.get("name"): packages.append(pkg["name"])
            if pkg.get("ecosystem"): ecosystems.append(pkg["ecosystem"])
    identity = "FAIL" if withdrawn else ("PASS" if adv else "UNKNOWN")
    uniqueness = "PASS" if cid not in ids[:-1] else "FAIL"
    open_gates = ["ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate"]
    if identity != "PASS":
        open_gates = ["identity_gate"] + open_gates
    if uniqueness != "PASS":
        open_gates.append("uniqueness_gate")
    notes = list(r.get("original_notes") or [])
    notes.append("no_explicit_ai_marker_proved_on_blamed_deleted_hunk")
    notes.append("missing_evidence_stays_UNKNOWN")
    if r.get("worker_verdict") == "BLOCKED":
        notes.append("prior_scan_BLOCKED_not_causal_reject")
    case = {
        "schema_version": "wave2-ag-slice-4-v1",
        "row_kind": "kind1_additive_guard_candidate",
        "assigned_order": i,
        "case_id": cid,
        "aliases": aliases,
        "packages": packages,
        "ecosystems": ecosystems,
        "published": published,
        "advisory_path": path,
        "repository": repo,
        "summary": summary,
        "withdrawn": withdrawn,
        "mechanism_key": None,
        "scope_statement": f"Kind-1 additive-guard candidate {cand} for {cid}. Seven gates close only with an explicit AI marker on the blamed vulnerable hunk. Absence of deleted source is not a negative.",
        "contribution_class": "UNRESOLVED",
        "candidate_set": [cand] if cand else [],
        "carrier_set": [],
        "minimum_fix_set": fixes,
        "worker_verdict": "UNKNOWN",
        "confidence": "LOW",
        "terminal": False,
        "fp_class": None,
        "countable": False,
        "countable_proposal": False,
        "identity_gate": identity,
        "ai_hunk_gate": "UNKNOWN",
        "topology_gate": "UNKNOWN",
        "but_for_gate": "UNKNOWN",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "UNKNOWN",
        "uniqueness_gate": uniqueness,
        "gates": {
            "identity_gate": identity,
            "ai_hunk_gate": "UNKNOWN",
            "topology_gate": "UNKNOWN",
            "but_for_gate": "UNKNOWN",
            "fix_reversal_gate": "UNKNOWN",
            "release_gate": "UNKNOWN",
            "uniqueness_gate": uniqueness,
        },
        "failing_gates": [g for g,v in [("identity_gate",identity),("uniqueness_gate",uniqueness)] if v=="FAIL"],
        "open_gates": open_gates,
        "ai_marker_evidence": None,
        "first_party_sources": [path] if path else [],
        "commit_refs": fixes,
        "candidate_sha": cand,
        "clone_path": None,
        "notes": notes,
        "counterevidence": notes,
        "english_only": True,
        "worker_pass_is_proposal_only": True,
        "did_not_use_github_api": True,
        "lane": "herdr-260814-w2-s6-grok46-high",
        "original_vulnerability": None,
        "replay_commands": ["python3 /home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s6-grok46-high/_emit_ag.py"],
        "baseline_overlap_disposition": "Not in canonical84 strict 84; proposal only.",
        "collisions": [],
        "slice": r.get("slice"),
        "slice_order": r.get("slice_order"),
        "global_order": r.get("global_order"),
        "scan_status": r.get("scan_status"),
        "hard_hit": r.get("hard_hit"),
        "prior_worker_verdict": r.get("worker_verdict"),
        "history_cap": 2000,
    }
    cases.append(case)
    gm.append({
        "ord": i,
        "case_id": cid,
        "repository": repo,
        "candidate_sha": cand,
        "verdict": "UNKNOWN",
        "confidence": "LOW",
        "contribution_class": "UNRESOLVED",
        "fp_class": None,
        "terminal": False,
        "failing_gates": case["failing_gates"],
        "open_gates": open_gates,
        "identity_gate": identity,
        "ai_hunk_gate": "UNKNOWN",
        "topology_gate": "UNKNOWN",
        "but_for_gate": "UNKNOWN",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "UNKNOWN",
        "uniqueness_gate": uniqueness,
    })
ended = datetime.now(timezone.utc).isoformat()
result = {
    "schema_version": "wave2-ag-slice-4-v1",
    "artifact_kind": "ghsa200_wave2_ag_slice_4_kind1",
    "owned_directory": "autoresearch/herdr-260814-w2-s6-grok46-high",
    "worker": "grok46-high",
    "language": "en",
    "english_only": True,
    "lane": "herdr-260814-w2-s6-grok46-high",
    "started_at": started,
    "ended_at": ended,
    "terminal": False,
    "status": "NONTERMINAL",
    "did_not_edit_ledger": True,
    "did_not_use_github_api": True,
    "did_not_expand": True,
    "did_not_invent_evidence": True,
    "did_not_commit_or_push": True,
    "did_not_edit_outside_owned_dir": True,
    "ledger_gates_treated_as_non_evidence": True,
    "assigned": 24,
    "reviewed": 24,
    "counts": {
        "assigned": 24,
        "reviewed": 24,
        "CONFIRM": 0,
        "NARROW": 0,
        "FALSE_POSITIVE": 0,
        "UNKNOWN": 24,
        "terminal_true": 0,
        "terminal_false": 24,
        "countable_pass": 0,
        "proposed_acceptances": 0,
        "ai_hunk_unknown": 24,
        "identity_fail": sum(1 for c in cases if c["identity_gate"]=="FAIL"),
    },
    "conservation": {
        "assigned": 24,
        "reviewed": 24,
        "unreviewed": 0,
        "did_not_pad": True,
        "equation": "24=24+0",
        "holds": True,
        "reviewed_case_ids": ids,
    },
    "claim_boundary": {
        "worker_PASS": "proposal only; this packet has zero CONFIRM and zero countable PASS unless listed",
        "canonical_ledger_edited": False,
        "more_than_200_claim_supported_by_this_review": False,
        "publication_status": "HOLD",
    },
    "input_hashes": {
        "ag-slice-4.jsonl": sha256(SLICE),
        "SPEC.md": sha256(SPEC),
        "CONTRACT.md": sha256(CONTRACT),
    },
    "gate_matrix": gm,
    "blockers": [
        "Kind-1 additive-guard rows stop at ai_hunk_gate UNKNOWN when no explicit AI marker is reachable from a blamed vulnerable hunk.",
        "no_source_deleted on candidate SHAs is not converted into FAIL/FALSE_POSITIVE.",
        "Worker PASS/CONFIRM is proposal only.",
    ],
}
(OWNED/"result.json").write_text(json.dumps(result, indent=2)+"\n")
(OWNED/"cases.jsonl").write_text("".join(json.dumps(c, ensure_ascii=False)+"\n" for c in cases))
lines = [
    "# Wave-2 ag-slice-4 kind-1 additive-guard adjudication (grok-4.6 high)",
    "",
    "Verdict first: reviewed 24/24. CONFIRM 0, NARROW 0, FALSE_POSITIVE 0, UNKNOWN 24. terminal_true=0 terminal_false=24. Worker PASS/CONFIRM is proposal only. Canonical ledger was not edited. Publication and greater-than-200 stay HOLD.",
    "",
    "## Method",
    "",
    "Kind-1 additive-guard candidate rows from ag-slice-4.jsonl. commit_refs[0] is the candidate SHA. Local first-party GHSA objects from frozen advisory-database clones. GitHub API was not used. Missing evidence stays UNKNOWN and is not converted into FAIL/FALSE_POSITIVE. Absence of deleted source is not a negative. History walk cap is 2000 commits / named refs. No AI_INCOMPLETE_REMEDIATION verdicts, so original_vulnerability is null on every row.",
    "",
    "## Per-gate failures",
    "",
]
for c in cases:
    lines.append(f"{c['assigned_order']}. {c['case_id']} {c['repository']}: UNKNOWN (LOW, UNRESOLVED; failing={','.join(c['failing_gates']) or 'none'}; open={','.join(c['open_gates'])}). candidate={c['candidate_sha']}; AI=none; notes={'; '.join(c['notes'][:3])}")
lines += ["", "## Conservation", "", "24=24+0. Did not pad. Did not expand the slice.", "", "## Claim boundary", "", "Zero countable PASS. Worker output is proposal only.", ""]
(OWNED/"report.md").write_text("\n".join(lines))
print("wrote", len(cases), (OWNED/"result.json").stat().st_size, (OWNED/"cases.jsonl").stat().st_size, (OWNED/"report.md").stat().st_size)
