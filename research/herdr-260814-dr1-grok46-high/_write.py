#!/usr/bin/env python3
import json, hashlib, os, subprocess, glob
from pathlib import Path
from collections import Counter

ROOT = Path("/home/hanqing/agents/ai-slop")
OUT = ROOT / "autoresearch/herdr-260814-dr1-grok46-high"
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-1.jsonl"
ADV_ROOTS = [
    Path("/home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/advisory-database"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta/advisory-database"),
]
POOL = Path("/home/hanqing/.cache/ghsa200-sweep-fetch")
OUT.mkdir(parents=True, exist_ok=True)

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def find_adv(case_id):
    low = case_id.lower()
    for root in ADV_ROOTS:
        hits = glob.glob(str(root / "advisories/github-reviewed/*/*" / low / (low + ".json")))
        if hits:
            return hits[0]
    return None

def git_ok(repo, *args):
    env = os.environ.copy()
    env["GIT_NO_LAZY_FETCH"] = "1"
    try:
        p = subprocess.run(["git","--git-dir",repo,*args], capture_output=True, text=True, timeout=4, env=env)
        return p.returncode == 0, (p.stdout or "").strip(), (p.stderr or "").strip()
    except Exception as e:
        return False, "", str(e)

rows_in = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]

# Closed wrong_edge where overlap is CI/dist/docs/tests or a clearly different mechanism.
# Everything else stays UNKNOWN because blobless diffs did not yield the vulnerable hunk.
FP = {
    "GHSA-C2J3-45GR-MQC4": "CI workflows, README, and dist bundles; ancestor is a 3.4.2 dependabot/jsdom sync, not the sanitizer hunk later closed by 3.4.12.",
    "GHSA-FC6G-2GCP-2QRQ": "Ancestor is a GetMetrics panic guard; first-party closer is aws:SourceIp policy evaluation. Overlap is admin/auth files, not the assigned GetMetrics subject.",
    "GHSA-2QVQ-RJWJ-GVW9": "Ancestor only adds CLI unit tests under spec/expected; Handlebars runtime compile/runtime hunks are untouched.",
    "GHSA-2W6W-674Q-4C4Q": "Same Handlebars CLI test ancestor as the other six sibling GHSAs; overlap is spec fixtures, not the runtime sink.",
    "GHSA-3MFM-83XF-C92R": "Same Handlebars CLI test ancestor; overlap is spec fixtures, not the runtime sink.",
    "GHSA-442J-39WM-28R2": "Same Handlebars CLI test ancestor; overlap is spec fixtures, not the runtime sink.",
    "GHSA-9CX6-37PM-9JFF": "Same Handlebars CLI test ancestor; overlap is spec fixtures, not the runtime sink.",
    "GHSA-XHPV-HC6G-R9C6": "Same Handlebars CLI test ancestor; overlap is spec fixtures, not the runtime sink.",
    "GHSA-XJPJ-3MR7-GCPF": "Same Handlebars CLI test ancestor; overlap is spec fixtures, not the runtime sink.",
    "GHSA-XW7X-H9FJ-P2C7": "Ancestor is a 2.26.0 release-prep commit (changelog, version, apidiffs, example gradle); not an instrumentation sink.",
    "GHSA-Q58J-G3F4-H26H": "Overlap is only GitHub Actions YAML; ancestor subject is a pull_request_target workflow fix, not a CoreShop PHP product hunk.",
    "GHSA-2CF7-HPWF-47H9": "Ancestor is a docs/changelog note plus generated dist maps for credentials guidance, not the n8n manager auth sink.",
}

UNK_REASON = {
    "GHSA-JFWG-RXF3-P7R9": "v2 rewrite touches cassandradb files that the CQL/N1QL closer later parameterizes, but blobless fetch could not supply the ancestor hunk.",
    "GHSA-9Q5R-WFVF-RR7F": "JSON serializer/MemorySize refactor overlaps Earley/grammar files named by the closer, but the introducing hunk was not recovered.",
    "GHSA-4GGG-H7PH-26QR": "Ancestor is itself a CodeQL security patch on the HTTP session server; residual vs introducing hunk was not recovered.",
    "GHSA-C29Q-5XM7-5P62": "New Apple/Amazon/Qobuz embed services overlap the embed factory; new-surface vs pre-existing iframe sink was not recovered.",
    "GHSA-X44P-GVRJ-PJ2R": "reEncryptInstructionFile feature overlaps the encryption client pipeline; instruction-file hunk vs advisory mechanism was not recovered.",
    "GHSA-J6V5-G24H-VG4J": "Bytecode serialization feature overlaps engine.go; whether that commit authored the advisory sink was not recovered.",
    "GHSA-X3F4-V83F-7WP2": "Same v2 rewrite as JFWG, overlapping GraphQL/OAuth/url validators; introducing hunk was not recovered.",
    "GHSA-PR33-38XX-6R26": "Ancestor SHA is the cookie-storage commit also used as fix_ref prefix; whether it introduced or closed the cookie sink was not recovered.",
    "GHSA-Q938-GHWV-8GVC": "New Stripe provider could be a new surface, but Stripe callback/webhook hunk vs advisory mechanism was not recovered.",
    "GHSA-G754-HX8W-X2G6": "qpack v0.6.0 bump overlaps http3 header parsing; header hunk vs advisory mechanism was not recovered.",
    "GHSA-56F2-HVWG-5743": "Ancestor is a Slack media URL security fix overlapping media.ts; introducing vs incomplete-guard hunk was not recovered.",
    "GHSA-WFP2-V9C7-FH79": "Same OpenClaw Slack media ancestor/fix pair as 56F2; introducing hunk was not recovered.",
    "GHSA-H395-GR6Q-CPJC": "Crypto-backend split overlaps validation.rs; JWT algorithm/validation hunk was not recovered.",
}

def gates_fp():
    return {
        "identity_gate": "UNKNOWN",
        "ai_hunk_gate": "FAIL",
        "topology_gate": "PASS",
        "but_for_gate": "FAIL",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "UNKNOWN",
        "uniqueness_gate": "UNKNOWN",
    }

def gates_unk():
    return {
        "identity_gate": "UNKNOWN",
        "ai_hunk_gate": "UNKNOWN",
        "topology_gate": "PASS",
        "but_for_gate": "UNKNOWN",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "UNKNOWN",
        "uniqueness_gate": "UNKNOWN",
    }

out_rows = []
for rec in rows_in:
    cid = rec["case_id"]
    repo = rec["repository"]
    owner, name = repo.split("/", 1)
    gitdir = str(POOL / f"{owner}__{name}")
    adv = find_adv(cid)
    aliases = []
    summary = None
    withdrawn = False
    if adv:
        try:
            aj = json.load(open(adv))
            aliases = [x.get("value") for x in aj.get("aliases", []) if isinstance(x, dict)] or aj.get("aliases") or []
            summary = (aj.get("summary") or aj.get("details") or "")[:240]
            withdrawn = bool(aj.get("withdrawn"))
        except Exception:
            adv = None
    ok_a, subj_a, err_a = git_ok(gitdir, "log", "-1", "--format=%H%n%s%n%an <%ae>", rec["ai_ancestor"])
    ok_f, subj_f, err_f = git_ok(gitdir, "log", "-1", "--format=%H%n%s", rec["fix_ref"] if len(rec["fix_ref"])>=7 else rec["ai_ancestor"])
    fp = cid in FP
    g = gates_fp() if fp else gates_unk()
    if adv and not withdrawn:
        g["identity_gate"] = "PASS"
    elif withdrawn:
        g["identity_gate"] = "FAIL"
    if not ok_a:
        g["topology_gate"] = "UNKNOWN"
    row = {
        "schema_version": 1,
        "case_id": cid,
        "aliases": aliases,
        "repository": repo,
        "fix_ref": rec["fix_ref"],
        "ai_ancestor": rec["ai_ancestor"],
        "subject": rec.get("subject"),
        "published": rec.get("published"),
        "overlap_files": rec.get("overlap_files") or [],
        "overlap_n": rec.get("overlap_n"),
        "final_verdict": "FALSE_POSITIVE" if fp else "UNKNOWN",
        "contribution_class": "wrong_edge" if fp else None,
        "countable_proposal": False,
        "terminal": True,
        "worker_pass_is_proposal_only": True,
        "publication_status": "HOLD",
        "causal_admission": False,
        "gates": g,
        "remediation_patch_delta_gate": "NOT_APPLICABLE",
        "mechanism_key": None,
        "scope_statement": (summary or rec.get("subject") or ""),
        "candidate_set": [rec["ai_ancestor"]],
        "carrier_set": [],
        "minimum_fix_set": [rec["fix_ref"]],
        "exact_ai_marker": None,
        "first_party_advisory": adv,
        "commit_pool": gitdir,
        "ancestor_subject_observed": subj_a.split(chr(10))[1] if ok_a and chr(10) in subj_a else rec.get("subject"),
        "fix_subject_observed": subj_f.split(chr(10))[1] if ok_f and chr(10) in subj_f else None,
        "blobless_diff_error": err_a or None,
        "role_reasoning": FP.get(cid) or UNK_REASON.get(cid),
        "counterevidence": [
            "Assigned overlap files: " + ", ".join((rec.get("overlap_files") or [])[:8]),
            "Ancestor subject: " + (rec.get("subject") or ""),
        ],
        "replay_commands": [
            "GIT_NO_LAZY_FETCH=1 git --git-dir " + gitdir + " log -1 --format=%H%n%s " + rec["ai_ancestor"],
            "GIT_NO_LAZY_FETCH=1 git --git-dir " + gitdir + " log -1 --format=%H%n%s " + rec["fix_ref"],
        ],
        "baseline_overlap_disposition": "NOT_CHECKED_AGAINST_CANONICAL84",
        "unclosed_gates": [k for k,v in g.items() if v == "UNKNOWN"],
    }
    out_rows.append(row)

verdict_c = Counter(r["final_verdict"] for r in out_rows)
gate_counts = {}
for k in ["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]:
    gate_counts[k] = dict(Counter(r["gates"][k] for r in out_rows))

result = {
    "schema_version": 1,
    "lane": "dr-slice-1",
    "owned_directory": "autoresearch/herdr-260814-dr1-grok46-high",
    "terminal": True,
    "status": "TERMINAL",
    "language": "en",
    "english_only": True,
    "worker_pass_is_proposal_only": True,
    "canonical_layer": "canonical84",
    "publication_status": "HOLD",
    "causal_admission": False,
    "more_than_200_claim": False,
    "did_not_commit_or_push": True,
    "did_not_edit_tracked_or_canonical": True,
    "github_api_used": False,
    "input": {
        "spec": "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/DR-SPEC.md",
        "spec_sha256": sha256(ROOT/"autoresearch/orchestrator-260814-ghsa200-canvas/sweep/DR-SPEC.md"),
        "slice": "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-1.jsonl",
        "slice_sha256": sha256(SLICE),
        "contract": "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md",
        "contract_sha256": sha256(ROOT/"autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"),
        "truth_layers": "docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md",
        "truth_layers_sha256": sha256(ROOT/"docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md"),
    },
    "counts": {
        "input_rows": len(out_rows),
        "adjudicated_rows": len(out_rows),
        "terminal_rows": len(out_rows),
        "countable_proposals": 0,
        "FALSE_POSITIVE": verdict_c.get("FALSE_POSITIVE", 0),
        "UNKNOWN": verdict_c.get("UNKNOWN", 0),
        "AI_DIRECT_ROOT": 0,
        "AI_NEW_SURFACE_CONTRIBUTOR": 0,
        "wrong_edge": sum(1 for r in out_rows if r["contribution_class"]=="wrong_edge"),
    },
    "gate_counts": gate_counts,
    "rows": [{
        "case_id": r["case_id"],
        "repository": r["repository"],
        "fix_ref": r["fix_ref"],
        "ai_ancestor": r["ai_ancestor"],
        "final_verdict": r["final_verdict"],
        "contribution_class": r["contribution_class"],
        "countable_proposal": False,
        "terminal": True,
        "gates": r["gates"],
        "unclosed_gates": r["unclosed_gates"],
        "first_party_advisory": r["first_party_advisory"],
        "role_reasoning": r["role_reasoning"],
    } for r in out_rows],
    "blockers": ["Blobless pool refused ancestor diffs (GIT_NO_LAZY_FETCH); unclosed hunk/release/uniqueness gates left UNKNOWN rather than FAIL."],
    "claim_boundary": "Zero countable proposals. Worker PASS is proposal-only and this packet emits none. Greater-than-200 remains unsupported.",
}

(OUT/"result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
(OUT/"cases.jsonl").write_text("".join(json.dumps(r, ensure_ascii=True)+"\n" for r in out_rows), encoding="utf-8")

lines = []
w = lines.append
w("# Direct-root slice 1 adjudication")
w("")
w("## Verdict first")
w("")
w("All 25 assigned rows are terminal and non-countable. Twelve rows are `FALSE_POSITIVE` / `wrong_edge` because the AI ancestor only touches CI, dist, docs, tests, or a clearly different mechanism than the first-party closer. Thirteen rows stay `UNKNOWN` because the blobless sweep pool could not yield ancestor hunks, and missing evidence is not converted into FAIL or into `AI_DIRECT_ROOT`. Zero `AI_DIRECT_ROOT` or `AI_NEW_SURFACE_CONTRIBUTOR` proposals. Uniqueness and release were not closed against canonical84 or shipped artifacts.")
w("")
w("Counts: FALSE_POSITIVE=%d UNKNOWN=%d countable=0" % (verdict_c.get("FALSE_POSITIVE",0), verdict_c.get("UNKNOWN",0)))
w("")
w("## Per-row")
w("")
w("| case_id | verdict | class | I/A/T/B/F/R/U | why |")
w("| --- | --- | --- | --- | --- |")
for r in out_rows:
    g=r["gates"]
    seq="/".join(g[k][0] for k in ["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"])
    w("| `%s` | `%s` | `%s` | %s | %s |" % (r["case_id"], r["final_verdict"], r["contribution_class"] or "unclosed", seq, (r["role_reasoning"] or "").replace("|","/")))
w("")
w("## Evidence paths")
w("")
w("- Spec: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/DR-SPEC.md`")
w("- Slice: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-1.jsonl`")
w("- Contract: `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md`")
w("- Advisory clones under `/home/hanqing/.cache/ghsa200-worker-clones/*/advisory-database`")
w("- Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>`")
w("")
w("## Constraints kept")
w("")
w("Owned directory only. No GitHub API, no commits, no ledger/web/scripts edits. English only. Unclosed gates remain UNKNOWN.")
w("")
(OUT/"report.md").write_text("\n".join(lines)+"\n", encoding="utf-8")
print("rows", len(out_rows))
print("verdicts", dict(verdict_c))
print("result", (OUT/"result.json").stat().st_size)
print("cases", (OUT/"cases.jsonl").stat().st_size)
print("report", (OUT/"report.md").stat().st_size)
