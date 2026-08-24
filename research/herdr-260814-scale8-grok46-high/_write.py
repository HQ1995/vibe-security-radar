#!/usr/bin/env python3
import hashlib, json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OWNED = ROOT / "autoresearch/herdr-260814-scale8-grok46-high"
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-8.jsonl"
SPEC = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/DR-SPEC.md"
CONTRACT = ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
TRUTH = ROOT / "docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md"
LEDGER = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl"

def sha256_file(p):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None

rows_in = [json.loads(x) for x in SLICE.read_text().splitlines() if x.strip()]
assert len(rows_in) == 25

DECISIONS = {
    "GHSA-M6XR-FVFG-5G64": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap includes production selector/lexer/tokenize.go plus tests. Ancestor is a fork merge that may be the closer or an earlier landing. Ancestor-vs-fix hunk comparison was not materialized; unclosed gates stay UNKNOWN."),
    "GHSA-PXM6-MHXR-Q4MJ": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap is production classes/Login.php and login.php. Ancestor adds Magic Link passwordless login, a plausible new auth surface, but closer 3d419a0d was not hunk-compared. Missing evidence is not FAIL."),
    "GHSA-RHV4-8758-JX7V": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap includes production lib/decimal.ex. Ancestor adds compare/3 and eq?/3 with a threshold. That API change is not proved as the advisory sink versus closer 6a523f3a."),
    "GHSA-VHJM-W67Q-G75C": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap is production lib/index.js. Ancestor is itself a redirect header-stripping security change; later closer a5b6fac9 may amend it. Incomplete-remediation patch-delta was not proved."),
    "GHSA-X426-X7CC-3FPC": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Same wreck ancestor 04d91c36 against a different closer b93323b6. Production lib/index.js overlap is not hunk authorship. Patch-delta unclosed."),
    "GHSA-36W4-95HV-5VWG": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap includes production src/gun_http2.erl. Ancestor respects remote MAX_CONCURRENT_STREAMS. Whether that rewrite authored the advisory sink versus closer 567863ff is unclosed."),
    "GHSA-9R4W-JG96-92MV": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap is production attest/internal/events.go. Ancestor is an OOM-prevention patch on EFI_SIGNATURE_LIST; later closer b6e905e7 may be residual. Patch-delta not closed."),
    "GHSA-94PJ-82F3-465W": ("FALSE_POSITIVE", "wrong_edge", "FALSE_POSITIVE_WRONG_EDGE",
        "wrong_edge: assigned overlap is CHANGELOG.md and docs/request-options.md only. Ancestor Support QUERY redirects touches documentation/changelog, not a production redirect sink hunk."),
    "GHSA-J93G-RP6M-J32M": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap includes production cmd/arc/main.go plus release notes. Ancestor is an explicit DuckDB sandbox security fix; later closer 32a4091f may amend that boundary. Patch-delta unclosed."),
    "GHSA-P2J4-C4G6-RPF5": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap includes cmd/arc/main.go. Ancestor is host/address bind feature #441 while closer 91bdc29d is the DuckDB sandbox. Same-file overlap is not hunk proof; missing diff stays UNKNOWN."),
    "GHSA-HMQ2-W58F-27JC": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap is production git/objects/submodule/base.py plus tests. Ancestor initializes a submodule repository before handled failures. Hunk versus closer 4299c990 not compared."),
    "GHSA-2P26-P43X-FHP8": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap includes production lib/mint/http2.ex. Ancestor adds a polymorphic request-body streaming helper. Hunk versus closer b662d127 not compared."),
    "GHSA-G586-CCQF-7X4R": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Same mint ancestor 4c4bf913 against a different closer 70b97b6a. Production http2.ex overlap is not a closed hunk comparison."),
    "GHSA-4C8G-83QW-93J6": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap is production index.js plus test/security.test.js. Ancestor is a fork merge, a common GHSA closer shape. Ancestor-vs-fix hunk comparison was not materialized."),
    "GHSA-655F-MP8P-96GV": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap includes production lib/req/steps.ex. Ancestor auto-parses run_plug request bodies. Hunk versus closer 84977e5b not compared."),
    "GHSA-83W8-P2F5-377R": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap is production index.js. Ancestor ignores unsupported deflate for precompressed assets. Hunk versus closer db4276f8 not compared."),
    "GHSA-8PVW-JCV7-9CMJ": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Same fastify-static ancestor 99f0193a against a different closer 878c72e9. Production index.js overlap is not hunk authorship."),
    "GHSA-97JW-64CJ-JC58": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap includes production lib/view_component/base.rb. Ancestor fixes yielded content location with form helpers. Hunk versus closer 48e5fd2d not compared."),
    "GHSA-9H85-G7W3-RH49": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Same view_component ancestor ea4b7671 against a different closer 7b05073b. Production base.rb overlap is not a closed hunk comparison."),
    "GHSA-HRXH-6V49-42GF": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap is production internal/xds/rbac/matchers.go. Ancestor is an RBAC full-string matching security change; later closer 4ea465d4 may amend that boundary. Patch-delta unclosed."),
    "GHSA-VJ5C-M527-MPFF": ("FALSE_POSITIVE", "wrong_edge", "FALSE_POSITIVE_WRONG_EDGE",
        "wrong_edge: assigned overlap is only __tests__/formats/es6Module.test.js and es6ModuleMinify.test.js. Ancestor adds an es6 module format; the ancestry edge is tests, not a production sink hunk."),
    "GHSA-2XV9-GHH9-XC69": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap is src/mod.ts, a production export barrel rather than tests/docs. Ancestor adds pluck. Hunk versus closer 8147abc8 not compared; not converted into wrong_edge."),
    "GHSA-29PJ-957V-52MC": ("FALSE_POSITIVE", "wrong_edge", "FALSE_POSITIVE_WRONG_EDGE",
        "wrong_edge: assigned overlap is CHANGELOG.md only. Ancestor Prepare for 2.8.3 release is release-notes metadata, not a CommonMark parser hunk."),
    "GHSA-44FP-W29J-9VJ5": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Overlap is production lib/make-middleware.js. Ancestor handles missing field names. Hunk versus closer 2c8505f2 not compared."),
    "GHSA-4PG4-QVPC-4Q3H": ("UNKNOWN", None, "UNCLOSED_HUNK_COMPARISON",
        "Same multer ancestor 055767b1 and closer 2c8505f2 as GHSA-44FP-W29J-9VJ5, distinct GHSA identity. Production make-middleware.js overlap remains an unclosed hunk comparison."),
}

missing = [r["case_id"] for r in rows_in if r["case_id"] not in DECISIONS]
assert not missing, missing

def gates_for(verdict):
    if verdict == "FALSE_POSITIVE":
        return {
            "identity_gate": "UNKNOWN",
            "ai_hunk_gate": "FAIL",
            "topology_gate": "PASS",
            "but_for_gate": "FAIL",
            "fix_reversal_gate": "FAIL",
            "release_gate": "UNKNOWN",
            "uniqueness_gate": "UNKNOWN",
        }
    return {
        "identity_gate": "UNKNOWN",
        "ai_hunk_gate": "UNKNOWN",
        "topology_gate": "PASS",
        "but_for_gate": "UNKNOWN",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "UNKNOWN",
        "uniqueness_gate": "UNKNOWN",
    }

cases = []
result_rows = []
for rec in rows_in:
    cid = rec["case_id"]
    verdict, fp_class, contrib, reason = DECISIONS[cid]
    repo = rec["repository"]
    fix = rec["fix_ref"]
    anc = rec["ai_ancestor"]
    gd = "/home/hanqing/.cache/ghsa200-sweep-fetch/" + repo.replace("/", "__")
    g = gates_for(verdict)
    replay = [
        "GIT_NO_LAZY_FETCH=1 git --git-dir %s show -s --format=%%H%%n%%s%%n%%an %%ae%%n%%b %s" % (gd, anc),
        "GIT_NO_LAZY_FETCH=1 git --git-dir %s diff-tree --no-commit-id -r --name-status -c %s" % (gd, anc),
        "GIT_NO_LAZY_FETCH=1 git --git-dir %s diff-tree --no-commit-id -r --name-only -c %s" % (gd, fix),
    ]
    case = {
        "schema_version": 1,
        "case_id": cid,
        "aliases": [],
        "repository": repo,
        "fix_ref": fix,
        "ai_ancestor": anc,
        "subject": rec.get("subject"),
        "published": rec.get("published"),
        "overlap_files": rec.get("overlap_files") or [],
        "overlap_n": rec.get("overlap_n"),
        "final_verdict": verdict,
        "false_positive_class": fp_class,
        "contribution_class": contrib,
        "countable_proposal": False,
        "terminal": True,
        "gates": g,
        "remediation_patch_delta_gate": "NOT_APPLICABLE",
        "original_vulnerability": None,
        "baseline_overlap_disposition": "NO_LEDGER_MEMBERSHIP_CHECK_IN_LANE",
        "first_party_advisory": None,
        "advisory_summary": None,
        "advisory_cwe": [],
        "advisory_withdrawn": False,
        "commit_pool": gd,
        "ancestor_object_present": None,
        "fix_object_present": None,
        "ancestor_subject_excerpt": rec.get("subject"),
        "exact_ai_marker": None,
        "role_reasoning": reason,
        "counterevidence": [
            "Assigned overlap is ancestry file overlap with the closer, not by itself hunk authorship.",
            "Missing blobless parent diffs were left UNKNOWN rather than FAIL.",
            "Worker PASS is proposal-only; this lane proposes no countable admissions.",
        ],
        "replay_commands": replay,
        "worker_pass_is_proposal_only": True,
        "publication_status": "HOLD",
        "causal_admission": False,
    }
    cases.append(case)
    result_rows.append({
        "case_id": cid,
        "repository": repo,
        "fix_ref": fix,
        "ai_ancestor": anc,
        "final_verdict": verdict,
        "false_positive_class": fp_class,
        "contribution_class": contrib,
        "countable_proposal": False,
        "terminal": True,
        "gates": g,
        "remediation_patch_delta_gate": "NOT_APPLICABLE",
        "exact_ai_marker": None,
        "advisory_json": None,
    })

def count_verdict(v):
    return sum(1 for c in cases if c["final_verdict"] == v)

def gate_hist(name):
    h = {}
    for c in cases:
        val = c["gates"][name]
        h[val] = h.get(val, 0) + 1
    return h

fp_classes = {}
for c in cases:
    if c["false_positive_class"]:
        fp_classes[c["false_positive_class"]] = fp_classes.get(c["false_positive_class"], 0) + 1

def gate_abbrev(g):
    order = ["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
    m = {"PASS":"P","FAIL":"F","UNKNOWN":"U"}
    return "/".join(m[g[k]] for k in order)

generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
result = {
    "schema_version": 1,
    "lane": "dr-slice-8",
    "owned_directory": "autoresearch/herdr-260814-scale8-grok46-high",
    "task": "direct-root adjudication of dr-slice-8",
    "terminal": True,
    "status": "TERMINAL",
    "language": "en",
    "english_only": True,
    "generated_at": generated_at,
    "worker_pass_is_proposal_only": True,
    "canonical_layer": "canonical84",
    "publication_status": "HOLD",
    "causal_admission": False,
    "more_than_200_claim": False,
    "did_not_commit_or_push": True,
    "did_not_edit_tracked_or_canonical": True,
    "github_api_used": False,
    "input": {
        "spec": {"path": "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/DR-SPEC.md", "sha256": sha256_file(SPEC)},
        "slice": {"path": "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-8.jsonl", "sha256": sha256_file(SLICE), "rows": 25},
        "contract": {"path": "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md", "sha256": sha256_file(CONTRACT)},
        "truth_layers": {"path": "docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md", "sha256": sha256_file(TRUTH)},
    },
    "source_heads": {
        "canonical84_ledger_path": "autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl",
        "canonical84_ledger_observed_sha256": sha256_file(LEDGER),
        "commit_pool": "/home/hanqing/.cache/ghsa200-sweep-fetch",
    },
    "counts": {
        "input_rows": 25,
        "adjudicated_rows": 25,
        "terminal_rows": 25,
        "countable_proposals": 0,
        "FALSE_POSITIVE": count_verdict("FALSE_POSITIVE"),
        "UNKNOWN": count_verdict("UNKNOWN"),
        "AI_DIRECT_ROOT": 0,
        "AI_NEW_SURFACE_CONTRIBUTOR": 0,
        "AI_INCOMPLETE_REMEDIATION": 0,
        "false_positive_classes": fp_classes,
    },
    "gate_counts": {
        "identity_gate": gate_hist("identity_gate"),
        "ai_hunk_gate": gate_hist("ai_hunk_gate"),
        "topology_gate": gate_hist("topology_gate"),
        "but_for_gate": gate_hist("but_for_gate"),
        "fix_reversal_gate": gate_hist("fix_reversal_gate"),
        "release_gate": gate_hist("release_gate"),
        "uniqueness_gate": gate_hist("uniqueness_gate"),
    },
    "rows": result_rows,
    "blockers": [
        "Blobless ancestor/fix hunk diffs were not closed for production-overlap rows; those gates stay UNKNOWN.",
        "No countable PASS proposals; leader replay not requested in this lane.",
    ],
}

lines = [
    "# Direct-root slice 8 adjudication",
    "",
    "## Verdict first",
    "",
    "All 25 assigned ancestry-overlap rows are terminal and non-countable. Three are `FALSE_POSITIVE` with class `wrong_edge` because the assigned overlap is documentation, changelog, or tests only. Twenty-two stay `UNKNOWN` because a production file sits in the overlap and ancestor-vs-fix hunk comparison was not materialized; missing evidence is not converted into `FAIL`. Countable proposals: 0. `AI_DIRECT_ROOT` / `AI_NEW_SURFACE_CONTRIBUTOR` / `AI_INCOMPLETE_REMEDIATION`: 0.",
    "",
    "## Counts",
    "",
    "- FALSE_POSITIVE: %d" % result["counts"]["FALSE_POSITIVE"],
    "- UNKNOWN (unclosed hunk): %d" % result["counts"]["UNKNOWN"],
    "- countable proposals: 0",
    "",
    "## Gate policy",
    "",
    "Identity stays `UNKNOWN` because first-party advisory JSON was not loaded in this lane. `ai_hunk_gate` is `FAIL` only when assigned overlap files positively show a non-sink (changelog, docs, or tests only). Missing blobs/diffs stay `UNKNOWN` and were not converted into `FAIL`. Topology is `PASS` from the already-fetched ancestry edge without transferring hunk authorship. Uniqueness stays `UNKNOWN` (ledger membership not closed here). Worker PASS would be proposal-only; this lane proposes none.",
    "",
    "Canonical layer remains L0 `canonical84` (HOLD). This directory is L3 worker output.",
    "",
    "## Per-row",
    "",
    "| case_id | verdict | class | I/A/T/B/F/R/U | overlap | reasoning |",
    "| --- | --- | --- | --- | --- | --- |",
]
for c in cases:
    ov = ", ".join("`" + x + "`" for x in (c["overlap_files"] or [])[:4])
    cls = c["false_positive_class"] or c["contribution_class"]
    reason = c["role_reasoning"].replace("|", "/")
    lines.append("| `%s` | `%s` | %s | %s | %s | %s |" % (c["case_id"], c["final_verdict"], cls, gate_abbrev(c["gates"]), ov, reason))
lines.extend([
    "",
    "## Constraints honored",
    "",
    "- Owned directory only; no ledger/web/scripts edits; no commit/push/reset/checkout; no GitHub API; no git blame/SZZ.",
    "- English only. Worker output is a proposal; leader must replay any future PASS.",
    "",
])

OWNED.mkdir(parents=True, exist_ok=True)
(OWNED / "result.json").write_text(json.dumps(result, indent=2) + "\n")
with (OWNED / "cases.jsonl").open("w") as f:
    for c in cases:
        f.write(json.dumps(c, ensure_ascii=True) + "\n")
(OWNED / "report.md").write_text("\n".join(lines))
for junk_name in ("_collect.py", "_write.py"):
    junk = OWNED / junk_name
    if junk.is_file():
        junk.unlink()
print("FP", result["counts"]["FALSE_POSITIVE"], "UNKNOWN", result["counts"]["UNKNOWN"])
print("wrote", OWNED)

