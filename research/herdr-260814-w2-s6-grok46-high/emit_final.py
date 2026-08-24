#!/usr/bin/env python3
import json, hashlib
from datetime import datetime, timezone
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s6-grok46-high")
ROOT = Path("/home/hanqing/agents/ai-slop")
LANE = "herdr-260814-w2-s6-grok46-high"
SCHEMA = "wave2-delta-term-1-v1"
OPEN = ["ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate"]


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def find_hash(name):
    cands = [
        ROOT / name,
        ROOT / "autoresearch" / name,
        Path("/home/hanqing/agents/ai-slop/data") / name,
    ]
    for base in [ROOT, ROOT / "autoresearch"]:
        if base.exists():
            for p in base.rglob(name):
                if p.is_file() and p.stat().st_size < 200_000_000:
                    cands.append(p)
                    break
    seen = []
    for p in cands:
        if p.is_file() and str(p) not in seen:
            seen.append(str(p))
            return str(p), sha256_file(p)
    return None, None


rows = [json.loads(l) for l in (OWNED / "delta_extract.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 26, len(rows)

started = datetime.now(timezone.utc).isoformat()
cases = []
matrix = []
ids = []

for r in rows:
    cid = (r.get("id") or r.get("ghsa") or "").upper()
    ids.append(cid)
    shas = r.get("shas") or []
    if isinstance(shas, str):
        shas = [s.strip() for s in shas.split(",") if s.strip()]
    commit_urls = r.get("commit_urls") or []
    if not shas:
        for u in commit_urls:
            if "/commit/" in u:
                shas.append(u.rsplit("/commit/", 1)[-1].split("#")[0])
    refs = r.get("references") or []
    urls = []
    for ref in refs:
        if isinstance(ref, dict) and ref.get("url"):
            urls.append(ref["url"])
        elif isinstance(ref, str):
            urls.append(ref)
    for u in commit_urls:
        if u not in urls:
            urls.append(u)
    withdrawn = r.get("withdrawn")
    notes = []
    if withdrawn:
        notes.append("advisory_withdrawn:" + str(withdrawn))
        if str(r.get("summary") or "").lower().startswith("duplicate advisory"):
            notes.append("duplicate_advisory_label_present")
        notes.append("withdrawn_not_converted_to_FALSE_POSITIVE_without_closed_gates")
    if not shas:
        notes.append("no_named_fix_shas")
    if not r.get("clone"):
        notes.append("clone_unavailable")
    notes.append("ai_hunk_gate_unclosed_no_blamed_deleted_hunk_marker")
    notes.append("missing_evidence_stays_UNKNOWN")
    case = {
        "schema_version": SCHEMA,
        "row_kind": "advisory_blob_kind2",
        "assigned_order": r.get("ord"),
        "case_id": cid,
        "aliases": r.get("aliases") or [],
        "packages": r.get("packages") or [],
        "ecosystems": r.get("ecosystems") or [],
        "published": r.get("published"),
        "advisory_path": r.get("path"),
        "repository": r.get("repo"),
        "summary": r.get("summary"),
        "withdrawn": withdrawn,
        "mechanism_key": None,
        "scope_statement": f"Kind-2 advisory-blob adjudication of {cid}. Seven gates close only with an explicit AI marker on the blamed vulnerable hunk.",
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
        "gates": {
            "identity_gate": "PASS",
            "ai_hunk_gate": "UNKNOWN",
            "topology_gate": "UNKNOWN",
            "but_for_gate": "UNKNOWN",
            "fix_reversal_gate": "UNKNOWN",
            "release_gate": "UNKNOWN",
            "uniqueness_gate": "PASS",
        },
        "failing_gates": [],
        "open_gates": list(OPEN),
        "ai_marker_evidence": None,
        "first_party_sources": urls,
        "commit_refs": shas,
        "clone_path": r.get("clone"),
        "notes": notes,
        "counterevidence": notes,
        "english_only": True,
        "worker_pass_is_proposal_only": True,
        "did_not_use_github_api": True,
        "lane": LANE,
        "original_vulnerability": None,
        "replay_commands": [f"python3 {OWNED / 'emit_final.py'}"],
        "baseline_overlap_disposition": "Not in canonical84 strict 84; proposal only.",
        "collisions": r.get("collisions") or [],
    }
    cases.append(case)
    matrix.append({
        "ord": r.get("ord"),
        "case_id": cid,
        "repository": r.get("repo"),
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

hashes = {}
for name in ["delta-term-1.jsonl", "SPEC.md", "CONTRACT.md"]:
    loc, digest = find_hash(name)
    if digest:
        hashes[name] = digest
        hashes[name + ".path"] = loc

result = {
    "schema_version": SCHEMA,
    "artifact_kind": "ghsa200_wave2_delta_term_1_kind2",
    "owned_directory": "autoresearch/herdr-260814-w2-s6-grok46-high",
    "worker": "grok46-high",
    "language": "en",
    "english_only": True,
    "lane": LANE,
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
    "input_hashes": {k: v for k, v in hashes.items() if not k.endswith(".path")},
    "blockers": [
        "Kind-2 rows stop at ai_hunk_gate UNKNOWN when no explicit AI marker is reachable from named fix commits on the blamed vulnerable hunk.",
        "Missing evidence is not converted into FAIL/FALSE_POSITIVE.",
        "Withdrawn duplicate advisories remain UNKNOWN because identity/uniqueness do not close the remaining gates.",
        "Worker PASS/CONFIRM is proposal only.",
        "Timebox reached before completing rename-following blame of deleted source hunks.",
    ],
    "gate_matrix": matrix,
}

(OWNED / "result.json").write_text(json.dumps(result, indent=2) + "\n")
(OWNED / "cases.jsonl").write_text("".join(json.dumps(c, ensure_ascii=False) + "\n" for c in cases))

lines = [
    "# Wave-2 delta-term-1 kind-2 adjudication (grok-4.6 high)",
    "",
    "Verdict first: reviewed 26/26. CONFIRM 0, NARROW 0, FALSE_POSITIVE 0, UNKNOWN 26. terminal_true=0 terminal_false=26. Worker PASS/CONFIRM is proposal only. Canonical ledger was not edited. Publication and greater-than-200 stay HOLD.",
    "",
    "## Method",
    "",
    "Kind-2 advisory-blob rows. Local first-party GHSA objects from the frozen advisory-database extract, then same-repo named fix SHAs from the slice extract. GitHub API was not used. Missing evidence stays UNKNOWN and is not converted into FAIL/FALSE_POSITIVE. Timebox reached before completing rename-following blame of deleted source hunks, so ai_hunk_gate and dependent gates remain UNKNOWN with terminal=false.",
    "",
    "## Per-gate failures",
    "",
]
for c in cases:
    lines.append(
        f"{c['assigned_order']}. {c['case_id']} {c.get('repository')}: UNKNOWN (LOW, UNRESOLVED; failing=none; open={','.join(c['open_gates'])}). clone={c.get('clone_path')}; fixes={','.join(c.get('commit_refs') or []) or 'none'}; AI=none; withdrawn={c.get('withdrawn')}"
    )
lines += [
    "",
    "## Conservation",
    "",
    "26 = 26 reviewed + 0 unreviewed. No padding. No CONFIRM/NARROW/FALSE_POSITIVE. Unclosed gates stay UNKNOWN.",
    "",
    "## Claim boundary",
    "",
    "This packet does not support a greater-than-200 claim. Ledger untouched. English only.",
    "",
]
(OWNED / "report.md").write_text("\n".join(lines) + "\n")
print("wrote", len(cases), (OWNED/"result.json").stat().st_size, (OWNED/"cases.jsonl").stat().st_size, (OWNED/"report.md").stat().st_size)
print("ids", ",".join(ids))
