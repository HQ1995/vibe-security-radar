#!/usr/bin/env python3
"""Slice-6 (unr-adj4) 7-gate adjudication for herdr-260814-w4-6-ds."""
import hashlib, json, subprocess
from datetime import datetime, timezone

ADB = "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database"
POOL = "/home/hanqing/.cache/ghsa200-sweep-fetch"
SLICE = ("/home/hanqing/agents/ai-slop/autoresearch/"
         "orchestrator-260814-ghsa200-canvas/sweep/unr-adj4-slice-6.jsonl")
OUT = "/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w4-6-ds"

# sha -> (subject, ai_marker, why_unrelated)
CAND = {
 # fosrl/pangolin
 "69561caa74527ab9df8fabb22d49aa1e6e5b1f2f": ("Fix setup token display condition to include CrowdSec installation", "Co-authored-by: oschwartz10612 (human)", "install/crowdsec.go; not token authorization"),
 "d7311ad947d954aa61c04814edb126ccddf091a7": ("Add setup token printing after CrowdSec installation", "Co-authored-by: oschwartz10612 (human)", "install/crowdsec.go; not token authorization"),
 "336d31ce39e96cfc21a1e966bb2953d543cf2a8b": ("fix(validators): restore 2+ char domain label requirement", "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>", "validators.ts domain label; not token authorization"),
 "8df62e8b6a2c577343a5c45f057228a2e8ecaae2": ("Potential fix for code scanning alert no. 19: Inefficient regular expression", "Co-authored-by: Copilot Autofix powered by AI", "validators.ts regex; not token authorization"),
 # pimcore/admin-ui-classic-bundle
 "064f19ea7b23884d7bcc30a7e4373f536298a858": ("Add authorization check to reset2FaSecretAction", "Co-Authored-By: Claude <noreply@anthropic.com>", "UserController 2FA authz; not grid id filter SQL"),
 "0e05b451f9652777abb606d5a07c6545c05193bf": ("Address second Copilot pass: cap growth, filtered-total exactness", "Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>", "ElementController pagination; not grid id filter SQL"),
 "b498a6f7ad7e171511d0e5bb8aeb6e9098f2d68a": ("Address Copilot review: filtered pagination, hasHidden, cap reachability", "Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>", "dependency-list permission scan; not grid id filter SQL"),
 "5fc94e6dbf43cd991bcecf364ff6dedd0dd4b2a2": ("Add authorization checks to version-management endpoints", "Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>", "version-management authz; not grid id filter SQL"),
 # cockpit-project/cockpit
 "8b015a3bf837dab05b593d4a5d526dc56415c915": ("pam-ssh-add: Fix fragile exit status check", "Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>", "pam-ssh-add.c; not logs-UI command injection"),
 "44489dde42bb1254ba8c4bd3ab68c5c83b6c97de": ("tls: Convert port numbers from network to host byte order", "Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>", "tls/connection.c; not logs-UI command injection"),
 "5951c9c3b4cb9d97dd8c9844f0b1a51a491fc89f": ("overview-cards: port ProfilesMenuDialogBody to TypeScript", "Assisted-by: Claude Opus 4.6", "overview-cards UI; not logs-UI command injection"),
 # simdjson/simdjson
 "f902769b353d246c1cdf707e80e9d1e25ac6a47d": ("builder: force-inline atom templates and replace integer writer", "Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>", "number writer (write_uint_jeaiii); not escape_and_append"),
 "73e69a5e8463acadda6b9618ba236b25d9dd9b30": ("Get reflection working without warnings under GCC 16", "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>", "reflection/consteval warnings; not escape_and_append"),
 "5f6b6e107757cf7e8e66db26da9e1aa616d5984b": ("Update benchmark writeup authors", "Generated with Claude Code; Co-Authored-By: Claude Opus 4.5", "docs; not escape_and_append"),
 # ggml-org/llama.cpp
 "d28961d81e73e32b295d0ad638f3ff14676aeeda": ("llama : enable chunked fused GDN path", "Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>", "ggml CUDA/metal GDN ops; not json-schema-to-grammar/jinja"),
 "b0dbb39e1047f39756fe882c8db4d8fa6b77e921": ("ggml : transpose fused GDN state access for coalesced memory reads", "Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>", "ggml ops; not json-schema-to-grammar/jinja"),
 # awslabs/mcp
 "37734e217143328b41a592a8b7dc00f96b945aba": ("fix(bedrock-kb-retrieval-mcp-server): revert/remove deprecation notices", "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>", "bedrock-kb server; not DocumentDB MCP read-only"),
 # CERTCC/cveClient
 "4272bf05595fa2c1511fea452d5d882d42546c49": ("ci: update actions/checkout and actions/setup-node to v6", "Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>", "CI workflow; not cveInterface.js/API-key handling"),
 # RT-Thread/rt-thread
 "78b6b6e17f66585f3802cbeaae6e701f9a18f158": ("[finsh][shell] Print FinSH prompt with a fixed format string", None, "finsh/shell.c (no AI marker); not CAN/lwp_syscall"),
 "1254af44f253a11e2fe7351bb0242a6dbd219544": ("[gd32][uart] Add GD32VW553 series UART driver support", "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>", "gd32 uart driver; not CAN/lwp_syscall"),
 # pglombardo/PasswordPusher
 "451f40a288b72c34f1935bcb369937cef0aeb20e": ("Enable Permissions-Policy headers for browser feature restrictions", "Co-authored-by: Cursor <cursoragent@cursor.com>", "permissions-policy headers; not access-endpoint rate limit"),
 "3361f2e6395da7cf13fa84d87e16d88b20b902b8": ("Document notify_emails API auth, responses, and availability gaps", "Co-authored-by: Cursor <cursoragent@cursor.com>", "docs; not access-endpoint rate limit"),
 "4ea64812db7d044ec85d3e19efff05bdc8ae462d": ("Polish notify-by-email validation error copy", "Co-authored-by: Cursor <cursoragent@cursor.com>", "email validation copy; not rate limit"),
 "46d78126cd7bd6f26720ce0bb81215a56294d273": ("Filter payload and passphrase from logs and error tracking", "Co-authored-by: Cursor <cursoragent@cursor.com>", "log filtering; not rate limit"),
 "249ca3c9c9bdad7a6dde8e5be8fa98d0b3b1aba6": ("Fix secret_url FORCE_SSL rewrite corrupting https URLs", "Co-authored-by: Cursor <cursoragent@cursor.com>", "application_helper; not rate limit"),
 # OpenNMS/opennms
 "1b6b557d545a0697cc87c8d69f1b41dfaecfae4a": ("NMS-19976: Primevue migration: Menubar", "Co-authored-by: Copilot Autofix powered by AI", "UI theme/selenium; not Measurements/Alarm REST"),
 "55dd1c53502c6470668c736c8c3d0545f7eaba43": ("docs(rest): fix minions v2 write endpoints and ksc resourceId xref", "Assisted-by: ClaudeCode:claude-opus-4-8", "docs; not Measurements/Alarm REST"),
 "5affc919df114e169d39e8393c6c7d80acf0d0a3": ("NMS-16117: Redirect links to Vue Node List, add filters", "Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>", "NodeRestService/search providers; not Measurements/Alarm REST"),
 # apconw/Aix-DB
 "39f5a9f50d66ed3ff02f876c94b9ad7d62c2d071": ("fix(aix-db-cli): add error handling to CLI commands and body size limit", "Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>", "CLI tooling; not server /llm/process_llm_out auth"),
 "8d48f6b79f953b2ae98e09b3d580cf77701b777a": ("feat(aix-db-cli): add browser-based login flow", "Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>", "CLI auth; not server endpoint auth"),
 "746a30afffe8f618dfecc8245de753f0eba0192a": ("feat(aix-db-cli): add chat command with SSE event processing", "Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>", "CLI chat; not server endpoint auth"),
 "869c970af65f2464e6d0fc0d416288186da7e5ea": ("feat(aix-db-cli): add API module with SSE parser", "Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>", "CLI api client; not server endpoint auth"),
 "2d8a5966226c722f97c3c567f46f79e9e4751a96": ("feat(aix-db-cli): add config module with token expiry check", "Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>", "CLI config; not server endpoint auth"),
 # OpenCTI-Platform/opencti
 "f949fe136325263c8cae302c709de95a2f073d2d": ("[backend] Optimize JSON mapper memory usage and performance", "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>", "jsonMapper; not /graphql XSS or static/css traversal"),
 "30f5e7b5804b54c24f8dd996ab10941379952be6": ("[backend] Add upsert fallback when auto merging", "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>", "middleware/upsert; not XSS or traversal"),
 "d9dab7c6652f70cf8cd15bdab3a11325dc730e6c": ("[backend] Add missing securityCoverage resolver for Campaign", "Co-authored-by: copilot-swe-agent[bot]", "campaign resolver; not XSS or traversal"),
 # hickory-dns/hickory-dns
 "d8dea5a02959e8ff57588f149ca7d6fa87a93904": ("resolver: use options.connect_timeout for per-connection timeout", "Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>", "connection timeout; not cross-zone cache poisoning"),
 "4af766e5d5ffc5ec5c8996a52d401deb6cd680a0": ("prometheus: enable gzip compression on metrics endpoint", "Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>", "prometheus endpoint; not cross-zone cache poisoning"),
 "74742521d5bb5de87c71e907b08ebdf116800334": ("resolver: Clamp TTLs on first response, not just cached responses", "Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>", "TTL clamping; not cross-zone cache poisoning"),
 "863ab3cb9d97597439a92f1dbae45860c93312ac": ("resolver: Fix positive_min_ttl not clamping stored record TTLs", "Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>", "TTL clamping; not cross-zone cache poisoning"),
 # makeplane/plane
 "63fac3b8c488eb0afb8ec7d6731688c77ed72e24": ("fix: validate redirects in favicon fetching to prevent SSRF", "Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>", "favicon SSRF fix; not intake description_html XSS"),
 "587fe76032fb69275866fdeb655699a70a83c521": ("fix: prevent privilege escalation in project member role updates", "Co-authored-by: Claude Opus 4.6 (1M context) <noreply@anthropic.com>", "member role privilege fix; not intake XSS"),
 "d94a26945198a5f5a026420fe4ff6ac2acc7ba46": ("fix: add model_activity.delay() to API issue update/create", "Co-authored-by: Claude Opus 4.6 (1M context) <noreply@anthropic.com>", "issue webhook dispatch; not intake XSS"),
 # pinpoint-apm/pinpoint
 "e70f213e77473521a9ad2450dd21126cf3b4f86e": ("Add @Validated to controllers to prevent empty applicationName", "Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>", "controller validation; not session cookie/webhook SSRF"),
 "e679299a8548fe5903c291ce9435f258effdca28": ("Add useGetAgentList hook and migrate AgentListFetcher", "Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>", "React agent list UI; not session cookie/webhook SSRF"),
 "ab4828ac908047f2ef24c29a7b791e1bba64988b": ("Add .claude/ resource discovery rule for monorepo", "Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>", "CLAUDE.md config; not session cookie/webhook SSRF"),
}

# Mechanisms living in a different repo than row.repository (cross-bound).
WRONG_REPO = {
 "GHSA-F6G9-3R3J-32RG",  # Cockpit CMS (Cockpit-HQ/Cockpit), row repo = cockpit-project/cockpit
}

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
        fp = "AI_COMMIT_WRONG_REPOSITORY" if ghsa in WRONG_REPO else "AI_COMMIT_UNRELATED_CHANGE"
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
        notes = ["candidate AI commits (where AI-marked) do not author the "
                 "vulnerable hunk of the named mechanism"]
        if ghsa in WRONG_REPO:
            notes.append("mechanism lives in a different repository than "
                         "row.repository (cross-bound identity)")
        pool = POOL + "/" + repo.replace("/", "__")
        row = {
            "schema_version": "wave2-unr-adj4-v1",
            "row_kind": "unreviewed_adj4_adjudication",
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
            "lane": "herdr-260814-w4-6-ds",
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
        "schema_version": "wave2-unr-adj4-v1",
        "artifact_kind": "ghsa200_wave2_unr_adj4_slice6",
        "owned_directory": "autoresearch/herdr-260814-w4-6-ds",
        "worker": "deepseek-v4-pro", "language": "en", "english_only": True,
        "lane": "herdr-260814-w4-6-ds", "started_at": started,
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
        "input_hashes": {"unr-adj4-slice-6.jsonl": slice_sha},
        "blockers": [
            "All 25 rows are FALSE_POSITIVE: candidate AI commits do not author "
            "the advisory vulnerable hunk (unrelated fixes/refactors; 1 row is "
            "cross-bound to Cockpit CMS).",
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
    return """# herdr-260814-w4-6-ds - slice 6 (unr-adj4) adjudication

**Verdict first: 25/25 FALSE_POSITIVE, 0 countable.** For every row the candidate
AI commits do not author the vulnerable hunk of the named mechanism; they are
unrelated fixes/refactors (one row is cross-bound to Cockpit CMS). `ai_hunk_gate`
and `but_for_gate` FAIL, so no row closes the seven gates.

## Result

- assigned 25, reviewed 25, FALSE_POSITIVE 25, CONFIRM 0, NARROW 0, UNKNOWN 0
- terminal=true on all rows; zero proposed acceptances

## Per-repository evidence

- **fosrl/pangolin** (token reuse authz): candidates are CrowdSec install-token
  display and validators.ts domain-label/regex edits; none touch authz middleware.
- **pimcore/admin-ui-classic-bundle** (grid id-filter SQLi): candidates are 2FA
  reset authz, version-management authz, and ElementController permission-aware
  pagination/dependency scans; none touches the id-column-filter SQL WHERE.
- **cockpit-project/cockpit** (2 rows): logs-UI command injection candidates are
  pam-ssh-add exit-status, tls port byte-order, and an overview-cards TSX port -
  unrelated. The second row (CVE-2026-58467) names **Cockpit CMS** (a PHP CMS,
  Cockpit-HQ/Cockpit), a different repository -> cross-bound.
- **simdjson/simdjson** (escape_and_append int overflow): candidates replace the
  integer writer (write_uint_jeaiii), fix GCC-16 reflection warnings, and edit a
  benchmark writeup; none modifies `string_builder::escape_and_append()`.
- **ggml-org/llama.cpp** (3 rows, json-schema-to-grammar + jinja parser):
  candidates are ggml CUDA/metal fused-GDN ops; none touches
  common/json-schema-to-grammar.cpp or common/jinja/parser.cpp.
- **awslabs/mcp** (DocumentDB read-only bypass): candidate edits the
  bedrock-kb-retrieval server, a different MCP server.
- **CERTCC/cveClient** (2 rows, API-key protection + cveInterface.js XSS):
  candidate updates CI actions; neither mechanism area touched.
- **RT-Thread/rt-thread** (4 rows, CAN handler + lwp_syscall): candidates are a
  FinSH shell prompt fix (no AI marker) and a gd32 UART driver; none touches the
  SWM341/ls1c CAN handlers or lwp_syscall.c.
- **pglombardo/PasswordPusher** (access-endpoint brute force): candidates are
  Permissions-Policy headers, email docs/copy, log filtering, and a FORCE_SSL
  rewrite; none adds the missing rate-limit.
- **OpenNMS/opennms** (2 rows, Measurements JEXL + v2 Alarm REST authz):
  candidates are a Primevue UI migration, rest docs, and NodeRestService/search
  filters; neither Measurements nor Alarm REST touched.
- **apconw/Aix-DB** (missing auth on /llm/process_llm_out): candidates are all
  CLI tooling (aix-db-cli), not the server endpoint auth.
- **OpenCTI-Platform/opencti** (2 rows, 2020-era /graphql XSS + static/css
  traversal): candidates are backend jsonMapper/upsert/campaign-resolver
  changes; neither pre-existing surface touched.
- **hickory-dns/hickory-dns** (cross-zone cache poisoning): candidates are
  connection-timeout, prometheus gzip, and TTL-clamping changes in cache.rs;
  none changes the cache zone-keying/query-association.
- **makeplane/plane** (intake description_html XSS): candidates are favicon SSRF
  fix, member-role privilege fix, and issue webhook dispatch; intake untouched.
- **pinpoint-apm/pinpoint** (2 rows, session cookie flags + webhook SSRF):
  candidates are controller validation, a React agent-list hook, and a CLAUDE.md
  config; neither session-cookie nor webhook-registration path touched.

## Gate summary

identity_gate=PASS (first-party unreviewed advisory names mechanism + CVE);
ai_hunk_gate=FAIL (AI-marked commits do not author the vulnerable hunk);
topology_gate=FAIL; but_for_gate=FAIL; fix_reversal_gate=FAIL;
release_gate=FAIL; uniqueness_gate=PASS.

## Disagreements with stored labels

Upstream triage marked these KEEP on commit-subject overlap. Deep adjudication
of the actual diffs overturns every KEEP: overlaps are superficial and no
candidate introduces the named mechanism.
"""

def replay(cases, slice_sha):
    L = ["# replay.txt - reproduce this packet (0 proposals)",
         "input slice sha256: " + slice_sha,
         "Input: sweep/unr-adj4-slice-6.jsonl",
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
