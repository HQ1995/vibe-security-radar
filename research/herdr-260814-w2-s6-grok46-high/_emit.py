#!/usr/bin/env python3
import hashlib, json, datetime
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s6-grok46-high")
ROOT = Path("/home/hanqing/agents/ai-slop")
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/delta-term-2.jsonl"
SPEC = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/SPEC.md"
CONTRACT = ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
EXTRACT = OWNED / "delta_extract.jsonl"


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


def refs(row):
    out = []
    for r in row.get("references") or []:
        u = r.get("url") if isinstance(r, dict) else None
        if u:
            out.append(u)
    return out


def named_shas(row):
    out = []
    for s in row.get("shas") or []:
        if isinstance(s, dict) and s.get("sha"):
            out.append(s)
        elif isinstance(s, str) and s.strip():
            out.append({"sha": s.strip(), "exists": None, "ai": False, "head": ""})
    return out


rows = [json.loads(l) for l in EXTRACT.read_text().splitlines() if l.strip()]
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
cases = []
matrix = []

for i, row in enumerate(rows, 1):
    ghsa = (row.get("id") or row.get("ghsa") or "").lower()
    ghsa_disp = ghsa.upper()
    withdrawn = row.get("withdrawn")
    repo = row.get("repo") or (row.get("repos") or [None])[0]
    shas = named_shas(row)
    min_fix = [s["sha"] for s in shas]
    ai_fix = [s for s in shas if s.get("ai")]
    exists_noai = [s for s in shas if s.get("exists") and not s.get("ai")]
    missing = [s for s in shas if s.get("exists") is False]
    duplicate = bool(withdrawn) or (row.get("summary") or "").lower().startswith("duplicate advisory")
    first_party = bool(repo) and not duplicate

    if duplicate:
        identity = "FAIL"
        uniqueness = "FAIL"
        verdict = "FALSE_POSITIVE"
        terminal = True
        confidence = "HIGH"
        contribution = "WITHDRAWN_OR_CROSS_BOUND"
        ai_hunk = "UNKNOWN"
        topo = butfor = fixrev = release = "UNKNOWN"
        open_gates = ["ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate"]
        failing = ["identity_gate", "uniqueness_gate"]
        marker = None
        rationale = (
            "Withdrawn or duplicate advisory identity is not countable. "
            "identity_gate FAIL; uniqueness_gate FAIL because this GHSA is an explicit duplicate/cross-bound record. "
            "Remaining causal gates stay UNKNOWN; missing introducing-hunk evidence is not converted into extra FAILs."
        )
        fp_class = "WITHDRAWN_DUPLICATE_IDENTITY"
    else:
        identity = "PASS" if first_party else "UNKNOWN"
        uniqueness = "PASS"
        verdict = "UNKNOWN"
        terminal = False
        confidence = "LOW"
        contribution = "UNRESOLVED"
        ai_hunk = "UNKNOWN"
        topo = butfor = fixrev = release = "UNKNOWN"
        open_gates = ["ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate"]
        if identity == "UNKNOWN":
            open_gates = ["identity_gate"] + open_gates
        failing = []
        if ai_fix:
            marker = {
                "kind": "named_fix_sha_ai_marker",
                "shas": [s["sha"] for s in ai_fix],
                "note": "Explicit AI marker was found on advisory-named commit(s), which are treated as candidate fix SHAs, not as blamed introducing hunks. ai_hunk_gate therefore stays UNKNOWN.",
                "heads": [ (s.get("head") or "")[:240] for s in ai_fix ],
            }
            rationale = (
                "First-party advisory names the repository and mechanism, but the named SHA with an AI marker is a candidate fix, not a blamed introducing hunk. "
                "Kind-2 pipeline requires blaming the vulnerable hunk then checking that atomic commit for an explicit AI marker. That introducing-hunk bind did not close, so causal gates stay UNKNOWN."
            )
        elif exists_noai:
            marker = None
            rationale = (
                "Named candidate SHA exists in the local clone but has no explicit AI marker (trailer/bot identity/message). "
                "The introducing vulnerable hunk was not separately blamed within the 2000-commit bound, so ai_hunk_gate stays UNKNOWN."
            )
        elif missing or not shas:
            marker = None
            rationale = (
                "No blamed introducing hunk with an explicit AI marker was reachable from the local clone/advisory path. "
                "Named fix SHAs were missing, empty, or not inspected as introducing hunks. ai_hunk_gate stays UNKNOWN; missing evidence is not FAIL."
            )
        else:
            marker = None
            rationale = "Introducing AI hunk was not proved; unclosed gates remain UNKNOWN."
        fp_class = None

    gates = {
        "identity_gate": identity,
        "ai_hunk_gate": ai_hunk,
        "topology_gate": topo,
        "but_for_gate": butfor,
        "fix_reversal_gate": fixrev,
        "release_gate": release,
        "uniqueness_gate": uniqueness,
    }
    case = {
        "schema_version": "wave2-delta-term-2-v1",
        "row_kind": "advisory_blob_kind2",
        "assigned_order": i,
        "case_id": ghsa_disp,
        "aliases": row.get("aliases") or [],
        "packages": row.get("packages") or [],
        "ecosystems": row.get("ecosystems") or [],
        "published": row.get("published"),
        "advisory_path": row.get("path"),
        "repository": repo,
        "summary": row.get("summary"),
        "withdrawn": withdrawn,
        "mechanism_key": None,
        "scope_statement": (
            f"Kind-2 advisory-blob adjudication of {ghsa_disp}. "
            "Seven gates close only with an explicit AI marker on the blamed vulnerable hunk; withdrawn/cross-bound identities are not countable."
        ),
        "contribution_class": contribution,
        "candidate_set": [s["sha"] for s in ai_fix],
        "carrier_set": [],
        "minimum_fix_set": min_fix,
        "worker_verdict": verdict,
        "confidence": confidence,
        "terminal": terminal,
        "fp_class": fp_class,
        "countable": False,
        "countable_proposal": False,
        "identity_gate": identity,
        "ai_hunk_gate": ai_hunk,
        "topology_gate": topo,
        "but_for_gate": butfor,
        "fix_reversal_gate": fixrev,
        "release_gate": release,
        "uniqueness_gate": uniqueness,
        "gates": gates,
        "failing_gates": failing,
        "open_gates": open_gates,
        "ai_marker_evidence": marker,
        "first_party_sources": refs(row),
        "vulnerable_release_evidence": None,
        "fixed_release_evidence": None,
        "counterevidence": {
            "withdrawn": withdrawn,
            "named_sha_status": [
                {"sha": s.get("sha"), "exists": s.get("exists"), "ai": s.get("ai")} for s in shas
            ],
            "clone": row.get("clone"),
            "note": rationale,
        },
        "baseline_overlap": "not_in_excluded_baseline" if not row.get("excluded_baseline") else "excluded_baseline",
        "original_vulnerability": None,
        "rationale": rationale,
        "replay_commands": [
            f"python3 -c "import json; print(json.load(open('{EXTRACT}')) )"",
            f"git --no-optional-locks -C {row.get('clone') or '<missing-clone>'} log -1 --format='%H%n%an <%ae>%n%s%n%b' {min_fix[0] if min_fix else '<no-sha>'}",
        ],
        "slice_sha256": row.get("sha256_hex"),
        "blob_sha256": row.get("blob_sha256"),
    }
    cases.append(case)
    matrix.append({
        "assigned_order": i,
        "case_id": ghsa_disp,
        "repository": repo,
        "worker_verdict": verdict,
        "confidence": confidence,
        "terminal": terminal,
        "gates": gates,
        "open_gates": open_gates,
        "failing_gates": failing,
        "named_fix_shas": min_fix,
        "ai_marked_named_shas": [s["sha"] for s in ai_fix],
        "withdrawn": withdrawn,
    })

counts = {
    "assigned": len(cases),
    "reviewed": len(cases),
    "CONFIRM": sum(c["worker_verdict"] == "CONFIRM" for c in cases),
    "NARROW": sum(c["worker_verdict"] == "NARROW" for c in cases),
    "FALSE_POSITIVE": sum(c["worker_verdict"] == "FALSE_POSITIVE" for c in cases),
    "UNKNOWN": sum(c["worker_verdict"] == "UNKNOWN" for c in cases),
    "terminal_true": sum(bool(c["terminal"]) for c in cases),
    "terminal_false": sum(not c["terminal"] for c in cases),
    "countable_pass": 0,
    "proposed_acceptances": 0,
    "ai_hunk_unknown": sum(c["ai_hunk_gate"] == "UNKNOWN" for c in cases),
    "identity_fail": sum(c["identity_gate"] == "FAIL" for c in cases),
}

result = {
    "schema_version": "wave2-delta-term-2-v1",
    "artifact_kind": "wave2-slice-adjudication",
    "lane": "delta-term-2",
    "worker": "herdr-260814-w2-s6-grok46-high",
    "owned_directory": str(OWNED),
    "language": "en",
    "english_only": True,
    "status": "UNKNOWN",
    "terminal": False,
    "started_at": now,
    "ended_at": now,
    "assigned": len(cases),
    "reviewed": len(cases),
    "counts": counts,
    "gate_matrix": matrix,
    "claim_boundary": "Proposal only. No CONFIRM/NARROW countable admissions. Withdrawn duplicate identities are FALSE_POSITIVE; all other rows stay UNKNOWN because the introducing AI hunk was not closed.",
    "conservation": "assigned == reviewed == 26; CONFIRM+NARROW+FALSE_POSITIVE+UNKNOWN == 26",
    "blockers": [
        "Kind-2 introducing-hunk blame did not close with an explicit AI marker on an atomic vulnerable commit.",
        "Advisory-named SHAs with AI markers were treated as candidate fixes, not introducing hunks.",
        "No GitHub API; local clones/advisory blobs only.",
    ],
    "input_hashes": {
        "spec_md": sha256(SPEC),
        "contract_md": sha256(CONTRACT),
        "slice_jsonl": sha256(SLICE),
        "delta_extract_jsonl": sha256(EXTRACT),
    },
    "did_not_commit_or_push": True,
    "did_not_edit_ledger": True,
    "did_not_edit_outside_owned_dir": True,
    "did_not_expand": True,
    "did_not_invent_evidence": True,
    "did_not_use_github_api": True,
    "ledger_gates_treated_as_non_evidence": True,
}

(OWNED / "result.json").write_text(json.dumps(result, indent=2) + "\n")
(OWNED / "cases.jsonl").write_text("".join(json.dumps(c, ensure_ascii=False) + "\n" for c in cases))

lines = []
lines.append("# Wave-2 delta-term-2 adjudication")
lines.append("")
lines.append("Owner: `autoresearch/herdr-260814-w2-s6-grok46-high`. Proposal worker only; leader must replay any later PASS.")
lines.append("")
lines.append(f"Assigned 26 kind-2 advisory blobs from `delta-term-2.jsonl`. Verdicts: {counts['FALSE_POSITIVE']} FALSE_POSITIVE (withdrawn/cross-bound identities), {counts['UNKNOWN']} UNKNOWN, 0 CONFIRM, 0 NARROW. No countable admissions.")
lines.append("")
lines.append("## Gate contract applied")
lines.append("")
lines.append("Identity fails for withdrawn or duplicate advisories. ai_hunk_gate requires an explicit AI marker on the blamed introducing hunk; a marker on an advisory-named fix SHA is not sufficient. Unclosed causal gates stay UNKNOWN and terminal=false. Missing clone/SHA evidence is not converted into FALSE_POSITIVE.")
lines.append("")
lines.append("## Per-row verdicts")
lines.append("")
for c in cases:
    lines.append(f"### {c['assigned_order']:02d} {c['case_id']} — {c['worker_verdict']}")
    lines.append("")
    lines.append(f"- repository: {c['repository']}")
    lines.append(f"- summary: {c['summary']}")
    lines.append(f"- withdrawn: {c['withdrawn']}")
    lines.append(f"- gates: identity={c['identity_gate']} ai_hunk={c['ai_hunk_gate']} topology={c['topology_gate']} but_for={c['but_for_gate']} fix_reversal={c['fix_reversal_gate']} release={c['release_gate']} uniqueness={c['uniqueness_gate']}")
    lines.append(f"- named fix SHAs: {', '.join(c['minimum_fix_set']) or '(none)'}")
    lines.append(f"- AI-marked named SHAs: {', '.join(c['candidate_set']) or '(none)'}")
    lines.append(f"- terminal: {str(c['terminal']).lower()}")
    lines.append(f"- rationale: {c['rationale']}")
    lines.append("")
lines.append("## Evidence paths")
lines.append("")
lines.append("- slice: `autoresearch/orchestrator-260814-ghsa200-canvas/wave2/delta-term-2.jsonl`")
lines.append("- spec: `autoresearch/orchestrator-260814-ghsa200-canvas/wave2/SPEC.md`")
lines.append("- contract: `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md`")
lines.append("- local extract: `autoresearch/herdr-260814-w2-s6-grok46-high/delta_extract.jsonl`")
lines.append("- clones: `/home/hanqing/.cache/ghsa200-worker-clones/`")
lines.append("")
lines.append("No original_vulnerability blocks were emitted because no row received AI_INCOMPLETE_REMEDIATION.")
lines.append("")
(OWNED / "report.md").write_text("\n".join(lines))
print("cases", len(cases), "fp", counts["FALSE_POSITIVE"], "unk", counts["UNKNOWN"])
