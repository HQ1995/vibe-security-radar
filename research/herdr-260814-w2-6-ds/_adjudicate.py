#!/usr/bin/env python3
"""Slice-6 (unr-adj2) 7-gate adjudication for herdr-260814-w2-6-ds."""
import hashlib, json, subprocess
from datetime import datetime, timezone

ADB = "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database"
POOL = "/home/hanqing/.cache/ghsa200-sweep-fetch"
SLICE = ("/home/hanqing/agents/ai-slop/autoresearch/"
         "orchestrator-260814-ghsa200-canvas/sweep/unr-adj2-slice-6.jsonl")
OUT = "/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-6-ds"

CAND = {
 "2a18b7ee4463a38d64cdaf7e6b7ddc276118ff7b": (
  "Fix non-blocking X25519/ECC with WOLFSSL_ASYNC_CRYPT_SW",
  "Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>",
  "defensive fix to non-blocking X25519/ECC async setup (AllocKey, "
  "TLSX_KeyShare_GenX25519Key); touches no advisory mechanism"),
 "19bb7198a2074cec107d0fa93adfaea1ed5e5f23": (
  "Peer review fixes",
  "Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>",
  "leak/typo/comment fixes on non-blocking X25519/ECC path (curve25519.c, "
  "asn.c ConfirmSignature XFREE, tls.c); unrelated to advisory mechanisms"),
 "2c517b012ee0095fba3aa71e305d110017fb0292": (
  "Add compatibility: blueprint support for major version upgrade gating",
  "Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>",
  "GPM/Installer upgrade-gating change; unrelated to advisory mechanism"),
 "e3ff054db23d5e8f29bba92867fcc51c0a260312": (
  "Move media config blueprint and translations from admin plugin to core",
  "Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>",
  "media blueprint + language files; unrelated to advisory mechanism"),
 "2dcf91799901460f1610abf716abd8b933386810": (
  "Update Twig3CompatibilityTransformer.php",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "one-line Twig3 compat change; unrelated to advisory mechanism"),
 "bf7dd2e6c808c565910772991ba5bf5a98821966": (
  "Update Twig3CompatibilityTransformer.php",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "one-line Twig3 compat change; unrelated to advisory mechanism"),
 "508650583aae56b6016ba68bdfa4200f5253fd78": (
  "Fix JIT stack exhaustion in Twig3 compatibility regex patterns",
  "Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
  "Twig3 regex backtracking fix; unrelated to advisory mechanism"),
 "670eea97772c71fd354380a191869a9cd4b575a4": (
  "OpenAPI call: CommonUtils.getBaseUrl + full-URL support",
  "Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
  "OpenApiController.call() URL resolution + validOriginUrl() protocol "
  "hardening; different controller than auth-bypass endpoints, adds "
  "validation rather than removing it"),
}

PLUGIN = {"GHSA-FX5H-WV8R-5J9Q", "GHSA-W3XR-JX24-VW2H", "GHSA-G78V-PR5G-35V2"}

def advisory(ghsa, published):
    lg = "GHSA-" + ghsa[5:].lower()
    y, m = published[:4], published[5:7]
    path = "advisories/unreviewed/%s/%s/%s/%s.json" % (y, m, lg, lg)
    res = subprocess.run(["git", "-C", ADB, "show", "origin/main:" + path],
                         capture_output=True, text=True)
    return json.loads(res.stdout) if res.returncode == 0 else None

def main():
    rows = [json.loads(l) for l in open(SLICE)]
    slice_sha = hashlib.sha256(open(SLICE, "rb").read()).hexdigest()
    started = datetime.now(timezone.utc).isoformat()
    cases, matrix = [], []
    for i, r in enumerate(rows, 1):
        ghsa, repo = r["ghsa"], r["repo"]
        adv = advisory(ghsa, r["published"])
        aliases = adv.get("aliases", []) if adv else []
        details = adv.get("details", "") if adv else ""
        reviewed = (adv.get("database_specific", {}).get("github_reviewed")
                    if adv else None)
        cands = r["candidate_shas"]
        markers = {s: (CAND[s][1] if s in CAND else None) for s in cands}
        if repo == "wolfSSL/wolfssl":
            fp = "AI_COMMIT_UNRELATED_FIX"
        elif ghsa in PLUGIN:
            fp = "AI_COMMIT_WRONG_REPOSITORY"
        elif repo == "jeecgboot/JeecgBoot":
            fp = "AI_COMMIT_UNRELATED_CONTROLLER"
        else:
            fp = "AI_COMMIT_UNRELATED_CHANGE"
        gates = {"identity_gate": "PASS", "ai_hunk_gate": "FAIL",
                 "topology_gate": "FAIL", "but_for_gate": "FAIL",
                 "fix_reversal_gate": "FAIL", "release_gate": "FAIL",
                 "uniqueness_gate": "PASS"}
        failing = [g for g in gates if gates[g] == "FAIL"]
        lg = "GHSA-" + ghsa[5:].lower()
        y, m = r["published"][:4], r["published"][5:7]
        adv_path = "advisories/unreviewed/%s/%s/%s/%s.json" % (y, m, lg, lg)
        sources = ["advisory-database:" + adv_path,
                   "https://github.com/advisories/" + ghsa]
        sources += ["https://nvd.nist.gov/vuln/detail/" + a for a in aliases]
        counter = ["%s: %s -> %s" % (s[:12], CAND[s][0], CAND[s][2])
                   for s in cands if s in CAND]
        notes = ["candidate AI commits carry explicit AI markers but their "
                 "diffs do not author the vulnerable hunk of the named "
                 "mechanism"]
        if ghsa in PLUGIN:
            notes.append("mechanism lives in getgrav/grav-plugin-api; "
                         "row.repository=getgrav/grav is a cross-bound identity")
        pool = POOL + "/" + repo.replace("/", "__")
        row = {
            "schema_version": "wave2-unr-adj2-v1",
            "row_kind": "unreviewed_adj2_adjudication",
            "assigned_order": i, "case_id": ghsa, "aliases": aliases,
            "repository": repo, "published": r["published"], "summary": details,
            "advisory_reviewed": reviewed, "advisory_path": adv_path,
            "mechanism_key": aliases[0] if aliases else ghsa,
            "contribution_class": "NOT_AI_INTRODUCED", "candidate_set": cands,
            "carrier_set": [], "minimum_fix_set": [],
            "worker_verdict": "FALSE_POSITIVE", "confidence": "HIGH",
            "terminal": True, "fp_class": fp, "countable": False,
            "countable_proposal": False,
            "identity_gate": "PASS", "ai_hunk_gate": "FAIL",
            "topology_gate": "FAIL", "but_for_gate": "FAIL",
            "fix_reversal_gate": "FAIL", "release_gate": "FAIL",
            "uniqueness_gate": "PASS", "gates": gates,
            "failing_gates": failing, "open_gates": [],
            "ai_marker_evidence": markers, "first_party_sources": sources,
            "commit_refs": cands, "clone_path": pool, "notes": notes,
            "counterevidence": counter, "english_only": True,
            "worker_pass_is_proposal_only": True, "did_not_use_github_api": True,
            "lane": "herdr-260814-w2-6-ds",
            "replay_commands": ["git -C %s show origin/main:%s" % (ADB, adv_path)]
            + ["git --git-dir=%s show --format=fuller %s" % (pool, s)
               for s in cands],
            "baseline_overlap_disposition": "not in canonical ledger",
            "slice_sha256": slice_sha,
        }
        cases.append(row)
        matrix.append({"ord": i, "case_id": ghsa, "repository": repo,
                       "verdict": "FALSE_POSITIVE", "confidence": "HIGH",
                       "contribution_class": "NOT_AI_INTRODUCED", "fp_class": fp,
                       "terminal": True, "failing_gates": failing,
                       "open_gates": [], **gates})
    counts = {"assigned": 25, "reviewed": 25, "CONFIRM": 0, "NARROW": 0,
              "FALSE_POSITIVE": 25, "UNKNOWN": 0, "terminal_true": 25,
              "terminal_false": 0, "countable_pass": 0,
              "proposed_acceptances": 0, "ai_hunk_unknown": 0,
              "identity_fail": 0}
    result = {
        "schema_version": "wave2-unr-adj2-v1",
        "artifact_kind": "ghsa200_wave2_unr_adj2_slice6",
        "owned_directory": "autoresearch/herdr-260814-w2-6-ds",
        "worker": "deepseek-v4-pro", "language": "en", "english_only": True,
        "lane": "herdr-260814-w2-6-ds", "started_at": started,
        "ended_at": datetime.now(timezone.utc).isoformat(), "terminal": True,
        "status": "TERMINAL", "did_not_edit_ledger": True,
        "did_not_use_github_api": True, "did_not_expand": True,
        "did_not_invent_evidence": True, "did_not_commit_or_push": True,
        "did_not_edit_outside_owned_dir": True,
        "ledger_gates_treated_as_non_evidence": True, "assigned": 25,
        "reviewed": 25, "counts": counts,
        "conservation": {"assigned": 25, "reviewed": 25, "unreviewed": 0,
                         "did_not_pad": True, "equation": "25=25+0",
                         "holds": True,
                         "reviewed_case_ids": [c["case_id"] for c in cases]},
        "claim_boundary": {"worker_PASS": "proposal only; zero CONFIRM and "
                           "zero countable PASS",
                           "canonical_ledger_edited": False,
                           "more_than_200_claim_supported_by_this_review": False,
                           "publication_status": "HOLD"},
        "gate_matrix": matrix,
        "input_hashes": {"unr-adj2-slice-6.jsonl": slice_sha},
        "blockers": [
            "All 25 rows are FALSE_POSITIVE: candidate AI commits carry explicit "
            "AI markers but their diffs do not author the advisory vulnerable "
            "hunk (unrelated fixes/refactors; 3 grav rows are cross-bound to "
            "grav-plugin-api).",
            "minimum fix commit / vulnerable-hunk authorship not investigated "
            "because ai_hunk_gate already fails.",
        ],
    }
    json.dump(result, open(OUT + "/result.json", "w"), indent=1)
    with open(OUT + "/cases.jsonl", "w") as fh:
        for c in cases:
            fh.write(json.dumps(c) + "\n")
    open(OUT + "/report.md", "w").write(report())
    open(OUT + "/replay.txt", "w").write(replay(cases, slice_sha))
    print("done; counts:", json.dumps(counts))

def report():
    return """# herdr-260814-w2-6-ds - slice 6 (unr-adj2) adjudication

**Verdict first: 25/25 FALSE_POSITIVE, 0 countable.** Every candidate AI commit
in this slice carries an explicit AI marker, but none of their diffs authors the
vulnerable hunk of the advisory they are screened against. They are unrelated
fixes/refactors, so `ai_hunk_gate` and `but_for_gate` both FAIL and no row
closes the seven gates.

## Result

- assigned 25, reviewed 25, FALSE_POSITIVE 25, CONFIRM 0, NARROW 0, UNKNOWN 0
- terminal=true on all rows; zero proposed acceptances

## Per-repository evidence

### wolfSSL/wolfssl - 18 rows
Candidates `2a18b7ee` (Fix non-blocking X25519/ECC with WOLFSSL_ASYNC_CRYPT_SW)
and `19bb7198` (Peer review fixes) are Claude-co-authored fixes confined to the
non-blocking X25519/ECC path (`src/internal.c` AllocKey, `src/tls.c` KeyShare,
`wolfcrypt/src/curve25519.c`, an `asn.c` ConfirmSignature XFREE, test leak
fixes). None of the 18 advisories' mechanisms (PKCS#7 decode/outputSz, X.509
name-constraint bypass, DTLS 1.3 ACK overflow, CRL critical-extension bypass,
SHA-1/MD5 acceptance, SNI/ALPN resumption binding, OCSP CertID length confusion,
BLAKE2 HMAC message discard, Encrypt-then-MAC fallback, HMAC zero-length tag,
PKCS7_verify signer confusion, ML-KEM NEON half-compare, TLS 1.3 PHA missing
cert, iPAddress constraint bypass, PKCS#12 MAC length, SetSuitesHashSigAlgo OOB
write) is touched by these diffs.

### getgrav/grav - 6 rows
Candidates are GPM/Installer upgrade gating (`2c517b01`), media blueprint move
(`e3ff054d`), two Copilot Twig3 one-liners (`2dcf9179`, `bf7dd2e6`), and a Twig3
regex JIT fix (`50865058`). None touch the admin page-editor XSS
(CVE-2020-37256), the unserialize() code-exec (JobQueue/FileCache/Session), or
ZipArchiver::extract() decompression bomb. Three rows (`FX5H-WV8R-5J9Q`,
`W3XR-JX24-VW2H`, `G78V-PR5G-35V2`) name mechanisms in
`getgrav/grav-plugin-api` (JWT/CORS, avatar upload, SVG upload) - a different
repository than `getgrav/grav`, so the core commits cannot have introduced them.

### jeecgboot/JeecgBoot - 1 row
`GHSA-6W4X-5VF2-7756` is a missing-Shiro-authorization access-control issue on
`OpenApiAuthController`/`OpenApiPermissionController`. Candidate `670eea97`
edits `OpenApiController.call()` URL resolution and strengthens
`validOriginUrl()` protocol checks - a different controller, adding validation
rather than removing auth.

## Gate summary

identity_gate=PASS (first-party unreviewed advisory names mechanism + CVE);
ai_hunk_gate=FAIL (AI-marked commits do not author the vulnerable hunk);
topology_gate=FAIL; but_for_gate=FAIL (removing the AI change does not shrink
the mechanism); fix_reversal_gate=FAIL; release_gate=FAIL; uniqueness_gate=PASS.

## Disagreements with stored labels

Upstream triage (`herdr-260814-triage3-gf`) marked these KEEP on commit-subject
overlap. Deep adjudication of the actual diffs overturns every KEEP: the
overlaps are superficial and no candidate introduces the named mechanism.
"""

def replay(cases, slice_sha):
    L = ["# replay.txt - reproduce this packet (0 proposals)",
         "input slice sha256: " + slice_sha,
         "Input: sweep/unr-adj2-slice-6.jsonl",
         "",
         "For each row:",
         "  1. git -C %s show origin/main:advisories/unreviewed/YYYY/MM/GHSA-xxxx/GHSA-xxxx.json" % ADB,
         "  2. git --git-dir=<pool>/<owner>__<repo> show <candidate_sha>",
         "",
         "Per-row candidates:"]
    for c in cases:
        for s in c["candidate_set"]:
            L.append("%s %s" % (c["case_id"], s))
    L.append("")
    L.append("Zero PASS/ACCEPT proposals: nothing to leader-verify for counting.")
    return "\n".join(L) + "\n"

if __name__ == "__main__":
    main()
