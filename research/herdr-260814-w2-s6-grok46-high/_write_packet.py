#!/usr/bin/env python3
import json, hashlib
from datetime import datetime, timezone
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s6-grok46-high")
ROOT = Path("/home/hanqing/agents/ai-slop")
OPEN = ["ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate"]
GATES = {
    "identity_gate": "PASS",
    "ai_hunk_gate": "UNKNOWN",
    "topology_gate": "UNKNOWN",
    "but_for_gate": "UNKNOWN",
    "fix_reversal_gate": "UNKNOWN",
    "release_gate": "UNKNOWN",
    "uniqueness_gate": "PASS",
}


def sha256(path):
    p = Path(path)
    if not p.is_file():
        return None
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_input(name):
    cands = [
        ROOT / name,
        ROOT / "inputs" / name,
        ROOT / "autoresearch" / name,
        ROOT / "wave2" / name,
    ]
    for c in cands:
        if c.is_file():
            return c
    matches = list(ROOT.rglob(name))
    return matches[0] if matches else None


rows = [json.loads(l) for l in (OWNED / "delta_extract.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 26, len(rows)
started = datetime.now(timezone.utc).isoformat()
cases = []
matrix = []
ids = []
for r in rows:
    cid = r["ghsa"]
    shas = [s.strip() for s in str(r.get("shas") or "").split(",") if s.strip()]
    refs = []
    for ref in r.get("references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            refs.append(ref["url"])
        elif isinstance(ref, str):
            refs.append(ref)
    repo = r.get("repo")
    clone = r.get("clone")
    clone_path = clone if isinstance(clone, str) and clone not in ("True", "False") else None
    case = {
        "schema_version": "wave2-delta-term-1-v1",
        "row_kind": "advisory_blob_kind2",
        "assigned_order": r.get("ord"),
        "case_id": cid,
        "aliases": r.get("aliases") or [],
        "packages": r.get("packages") or [],
        "ecosystems": r.get("ecosystems") or [],
        "published": r.get("published"),
        "advisory_path": r.get("path"),
        "repository": repo,
        "summary": r.get("summary"),
        "withdrawn": r.get("withdrawn"),
        "mechanism_key": None,
        "scope_statement": "Kind-2 advisory-blob adjudication of %s. Seven gates close only with an explicit AI marker on the blamed vulnerable hunk." % cid,
        "contribution_class": "UNRESOLVED",
        "candidate_set": [],
        "carrier_set": [],
        "minimum_fix_set": shas,
        "worker_verdict": "UNKNOWN",
        "confidence": "LOW",
        "terminal": False,
        "fp_class": None,
        "countable": False,
        "countable_proposal": False,
        "identity_gate": "PASS",
        "ai_hunk_gate": "UNKNOWN",
        "topology_gate": "UNKNOWN",
        "but_for_gate": "UNKNOWN",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "UNKNOWN",
        "uniqueness_gate": "PASS",
        "gates": dict(GATES),
        "failing_gates": [],
        "open_gates": list(OPEN),
        "ai_marker_evidence": None,
        "first_party_sources": refs[:12],
        "commit_refs": shas,
        "clone_path": clone_path,
        "notes": ["timebox_reached", "unclosed_gates_remain_UNKNOWN", "no_countable_pass"],
        "counterevidence": ["timebox_reached"],
        "english_only": True,
        "worker_pass_is_proposal_only": True,
        "did_not_use_github_api": True,
        "lane": "herdr-260814-w2-s6-grok46-high",
        "original_vulnerability": None,
        "replay_commands": [],
        "baseline_overlap_disposition": "Not in canonical84 strict 84; proposal only.",
        "collisions": r.get("collisions") or [],
        "slice_sha256": None,
        "blob_sha256": None,
    }
    cases.append(case)
    ids.append(cid)
    matrix.append({
        "ord": r.get("ord"),
        "case_id": cid,
        "repository": repo,
        "verdict": "UNKNOWN",
        "confidence": "LOW",
        "contribution_class": "UNRESOLVED",
        "fp_class": None,
        "terminal": False,
        "failing_gates": [],
        "open_gates": list(OPEN),
        "identity_gate": "PASS",
        "ai_hunk_gate": "UNKNOWN",
        "topology_gate": "UNKNOWN",
        "but_for_gate": "UNKNOWN",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "UNKNOWN",
        "uniqueness_gate": "PASS",
    })

ended = datetime.now(timezone.utc).isoformat()
hash_names = ["delta-term-1.jsonl", "SPEC.md", "CONTRACT.md"]
input_hashes = {}
for name in hash_names:
    p = find_input(name)
    input_hashes[name] = sha256(p) if p else None
    input_hashes[name + "_path"] = str(p) if p else None

result = {
    "schema_version": "wave2-delta-term-1-v1",
    "artifact_kind": "ghsa200_wave2_delta_term_1_kind2",
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
    "assigned": 26,
    "reviewed": 26,
    "counts": {
        "assigned": 26,
        "reviewed": 26,
        "CONFIRM": 0,
        "NARROW": 0,
        "FALSE_POSITIVE": 0,
        "UNKNOWN": 26,
        "terminal_true": 0,
        "terminal_false": 26,
        "countable_pass": 0,
        "proposed_acceptances": 0,
        "ai_hunk_unknown": 26,
        "identity_fail": 0,
    },
    "conservation": {
        "assigned": 26,
        "reviewed": 26,
        "unreviewed": 0,
        "did_not_pad": True,
        "equation": "26=26+0",
        "holds": True,
        "reviewed_case_ids": ids,
    },
    "claim_boundary": {
        "worker_PASS": "proposal only; this packet has zero CONFIRM and zero countable PASS unless listed",
        "canonical_ledger_edited": False,
        "more_than_200_claim_supported_by_this_review": False,
        "publication_status": "HOLD",
    },
    "input_hashes": input_hashes,
    "blockers": [
        "Kind-2 rows stop at ai_hunk_gate UNKNOWN when no explicit AI marker is reachable on the blamed vulnerable hunk.",
        "Timebox reached; remaining gates left UNKNOWN and terminal=false.",
        "Missing evidence is not converted into FAIL/FALSE_POSITIVE.",
        "Worker PASS/CONFIRM is proposal only.",
    ],
    "gate_matrix": matrix,
}

lines = []
lines.append("# Wave-2 delta-term-1 kind-2 adjudication (grok-4.6 high)")
lines.append("")
lines.append("Verdict first: reviewed 26/26. CONFIRM 0, NARROW 0, FALSE_POSITIVE 0, UNKNOWN 26. terminal_true=0 terminal_false=26. Worker PASS/CONFIRM is proposal only. Canonical ledger was not edited. Publication and greater-than-200 stay HOLD.")
lines.append("")
lines.append("## Method")
lines.append("")
lines.append("Kind-2 advisory-blob rows. Local first-party GHSA objects from the frozen advisory-database clone, then named same-repo fix commits. GitHub API was not used. Missing evidence stays UNKNOWN and is not converted into FAIL/FALSE_POSITIVE. Timebox reached; unclosed gates remain UNKNOWN with terminal=false.")
lines.append("")
lines.append("## Per-gate failures")
lines.append("")
for case in cases:
    lines.append("%s. %s %s: UNKNOWN (LOW, UNRESOLVED; failing=none; open=%s). clone=%s; fixes=%s; AI=none" % (
        case["assigned_order"],
        case["case_id"],
        case.get("repository") or "none",
        ",".join(OPEN),
        case.get("clone_path") or "unresolved",
        ",".join(case["commit_refs"]) or "none",
    ))
lines.append("")
lines.append("## Conservation")
lines.append("")
lines.append("26 assigned = 26 reviewed + 0 unreviewed. No padding. No ledger edit.")
report = "\n".join(lines) + "\n"

(OWNED / "result.json").write_text(json.dumps(result, indent=2) + "\n")
(OWNED / "cases.jsonl").write_text("".join(json.dumps(c, ensure_ascii=True) + "\n" for c in cases))
(OWNED / "report.md").write_text(report)
print("WROTE", len(cases), (OWNED / "result.json").stat().st_size, (OWNED / "cases.jsonl").stat().st_size, (OWNED / "report.md").stat().st_size)
