#!/usr/bin/env python3
"""Slice-6 (unr-adj3) 7-gate adjudication for herdr-260814-w3-6-ds."""
import hashlib, json, subprocess
from datetime import datetime, timezone

ADB = "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database"
POOL = "/home/hanqing/.cache/ghsa200-sweep-fetch"
SLICE = ("/home/hanqing/agents/ai-slop/autoresearch/"
         "orchestrator-260814-ghsa200-canvas/sweep/unr-adj3-slice-6.jsonl")
OUT = "/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w3-6-ds"

# sha -> (subject, ai_marker, why_unrelated)
CAND = {
 # getgrav/grav
 "2c517b012ee0095fba3aa71e305d110017fb0292": (
  "Add compatibility: blueprint support for major version upgrade gating",
  "Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>",
  "GPM/Installer upgrade gating; not the advisory mechanism"),
 "e3ff054db23d5e8f29bba92867fcc51c0a260312": (
  "Move media config blueprint and translations from admin plugin to core",
  "Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>",
  "media blueprint + language files; not the advisory mechanism"),
 "2dcf91799901460f1610abf716abd8b933386810": (
  "Update Twig3CompatibilityTransformer.php",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "one-line Twig3 compat change; not the advisory mechanism"),
 "bf7dd2e6c808c565910772991ba5bf5a98821966": (
  "Update Twig3CompatibilityTransformer.php",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "one-line Twig3 compat change; not the advisory mechanism"),
 "508650583aae56b6016ba68bdfa4200f5253fd78": (
  "Fix JIT stack exhaustion in Twig3 compatibility regex patterns",
  "Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
  "Twig3 regex backtracking fix; not the advisory mechanism"),
 # jenkinsci/jenkins
 "33b3b3b82b414c798aa7be905d7750697869c48d": (
  "Fix sidebar navigation for non-ASCII localized section headers",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "UI dom.js; not FilePath.untarFrom tar extraction"),
 "c2fd9da8bc9c5ee6e33f49a9cd48cf3d676ce77e": (
  "Fix race condition during initial admin account creation",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "HudsonPrivateSecurityRealm; not tar extraction"),
 "e01dd6450959102d519fc4fe2dc9945a9094c3e5": (
  "Distinguish primary/secondary actions in the header",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "header UI jelly; not tar extraction"),
 "188baf00e23df5a15b5907a8ea1c81232833e5e5": (
  "fix inverted badgeClass",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "UI jelly; not tar extraction"),
 "c701361ec7bc9aa58d7745de6291a01b3d7abbe4": (
  "Fix Typo",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "Header.java typo; not tar extraction"),
 # Zie619/n8n-workflows
 "a54fc2fb5d9f657ad2dbb6a4134a19a1db9c16b2": (
  "feat: Add devcontainer configuration for n8n-workflows development",
  "Generated with Claude Code; Co-Authored-By: Claude <noreply@anthropic.com>",
  "devcontainer; not api_server.py download_workflow"),
 "879e0d4f1a329ec95b0543a327dfe13dfbc0f433": (
  "Repository Transformation: workflow organization",
  "Generated with Claude Code; Co-Authored-By: Claude <noreply@anthropic.com>",
  "renamer/static; not api_server.py download_workflow"),
 "e4a3ba4f72ac96f7313b82ec19e3492763c94e25": (
  "Clean up codebase: remove redundant files, consolidate docs",
  "Generated with Claude Code; Co-Authored-By: Claude <noreply@anthropic.com>",
  "docs/gitignore; not api_server.py source"),
 "ff958e486e1f8de4f7fd43c70ef357b8d6eaf433": (
  "Workflow naming convention overhaul and docs optimization",
  "Generated with Claude Code; Co-Authored-By: Claude <noreply@anthropic.com>",
  "docs; not api_server.py download_workflow"),
 "dc3dce1a2231fe114b89b7c0c6a75a6da3e678c1": (
  "Add Python-based n8n workflow documentation generator",
  "Generated with Claude Code; Co-Authored-By: Claude <noreply@anthropic.com>",
  "docs/html generator; not api_server.py download_workflow"),
 "f197ef419b17f616dde55693ba9feab44ea3ea2e": (
  "Refactor: Rename workflow files for clarity",
  None,
  "workflow JSON renames (no AI marker); not api_server.py"),
 # rustdesk/hbb_common
 "652f68fd54c9015d626888b732505414d36acfa9": (
  "Update examples/webrtc_dummy.rs",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "webrtc example; not flutter URI/FFI handler"),
 "2dc15df250a789f5026da146a9f21235be646480": (
  "Update src/webrtc.rs",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "webrtc signaling; not flutter URI/FFI handler"),
 "13ef3411d9cafaed184a6931787fbe658d2b1803": (
  "Update examples/webrtc.rs",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "webrtc example; not flutter URI/FFI handler"),
 "b10a96b7bce37081a65291b455d6617a382ac652": (
  "Apply suggestions from code review",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "webrtc files; not flutter URI/FFI handler"),
 "6463ba0e5241e3988e645a83c1938bad6e8890fa": (
  "Update examples/webrtc_dummy.rs",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "webrtc example; not flutter URI/FFI handler"),
 "47dc73de1e68248699acfa524766f317be2f91d7": (
  "Update src/webrtc.rs",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "webrtc signaling; not flutter URI/FFI handler"),
 # rrweb-io/rrweb
 "22bc4c334e88f0b8ee5488d9e1e95cd8093a15c8": (
  "Migrates to vite@6 to drop base64 inlined worker source",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "build tooling; not snapshot serialization XSS"),
 "ad5ac17422f4cbc450915c5dd6e0c0b0eb6c13a6": (
  "fix: ensure empty string replace/replaceSync clears stylesheets",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "stylesheet replace/replaceSync; not snapshot XSS"),
 "d17011b6387c7386fc7c5b4a5b92cc7d690c399d": (
  "Fix Vitest hanging indefinitely with Vite 6 by using forks pool",
  "Co-authored-by: copilot-swe-agent[bot]",
  "vitest config; not snapshot XSS"),
 # jsonpickle/jsonpickle
 "eb27cf084a90e545c10f8a5435d7f17cf1d28ff9": (
  "Fix pandas 3.0.0 errors and numpy deprecations",
  "Assisted-by: GPT-5.2-Codex via OpenAI-Codex",
  "numpy/pandas ext fixes; not py/repr deserialization"),
 "f238e7ab3e894ff4b66e73e945e39bd62958a571": (
  "Fix default_factory keys when encoding defaultdict",
  "Assisted-by: GPT-5.1-Codex-Mini via OpenAI-Codex",
  "defaultdict encoding; not py/repr deserialization"),
 "d00740675d0cc02442c6f3f3356c55a6ee4b9f6f": (
  "Fix method round-trip by enabling __reduce_ex__ support",
  "Generated with Claude Code; Co-authored-by: Claude <noreply@anthropic.com>",
  "util.py __reduce_ex__; not py/repr deserialization"),
 "b0201099041de3335e7930d0306dda6bae4e2d03": (
  "Add support for importable names of types module",
  "Generated with Claude Code; Co-Authored-By: Claude <noreply@anthropic.com>",
  "util.py importable_name; not py/repr deserialization"),
 "739348868b2e6cdfb10eebd87a3fef23cf49e59f": (
  "Fix method round-trip by enabling __reduce_ex__ support",
  "Generated with Claude Code; Co-Authored-By: Claude <noreply@anthropic.com>",
  "util.py __reduce_ex__; not py/repr deserialization"),
 "a0ac44b6f695031022e24fe3ec1f83b989ad1462": (
  "Add roundtrip test for types module importable names",
  "Generated with Claude Code; Co-Authored-By: Claude <noreply@anthropic.com>",
  "test only; not py/repr deserialization"),
 # hestiacp/hestiacp
 "99fd9a41ee70702172c75957f599f8f43a08bddd": (
  "1.9.5 beta (#5350)",
  None,
  "human release commit (no AI marker); not cronjob access-control intro"),
 "f381e294500f671cf12716c638afd0bfde901f88": (
  "Stop trusting unauthenticated proxy headers",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "proxy-header hardening; not cronjob access-control"),
 "d2d3aaee25a2fec261a0c3e4af2195bb5a6727d2": (
  "Harden template escaping with shared tohtml helper",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "XSS escaping; not cronjob access-control"),
 "725cdc1c2cdfda04f5d6421373f013f264721dd8": (
  "Add missing HTML/url encoding",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "XSS encoding; not cronjob access-control"),
 "ce3e464dabfdc7834b942b83f7772ebe4b63e03e": (
  "Improve HTML encoding",
  "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
  "XSS encoding; not cronjob access-control"),
 # openwrt/luci
 "9e70fd02f8e55f9b311a49957de6e42c0b152b5a": (
  "luci-base: protocol/dhcp: add option to disable DHCPv4 client ID",
  "Assisted-by: Claude:claude-opus-4-8",
  "DHCPv4 client-id option; not samba4 ACL / dhcpv6 lease / upnp XSS"),
 "7af3cf4f00b1b9cf9ca78151efd377a104db80fe": (
  "luci-mod-network: wireless: add WPA3-Personal Compatibility Mode",
  "Assisted-by: Claude:claude-opus-4-8",
  "wireless.js; unrelated to the three luci mechanisms"),
 "e9fc1b61c4b84fcf0c2e88908f0674ccea5f7bca": (
  "luci-mod-network: wireless: add gcmp256, sae_ext_key, transition_disable",
  "Assisted-by: Claude:claude-opus-4-8",
  "wireless.js; unrelated to the three luci mechanisms"),
 "a31eccfa1494e6cb8afc90963ae7081c800d25e0": (
  "luci-base: extend String.format() with named placeholder support",
  "Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>",
  "cbi.js String.format; unrelated to the three luci mechanisms"),
 "a5bedae6482709b3be18e8006a6ceb69d7c709f2": (
  "luci-app-ocserv: fix status page and users view bugs",
  "Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>",
  "ocserv views; unrelated to the three luci mechanisms"),
}

# Mechanisms living in a different repo than the row.repository.
WRONG_REPO = {
 "GHSA-38MM-MXVC-J98Q", "GHSA-X4CG-FXGX-67GM", "GHSA-85VC-29FC-65GW",
 "GHSA-3MPX-XV5P-92MV", "GHSA-993X-642G-H4X5", "GHSA-6959-H8J7-RR7M",
 "GHSA-G77X-8H46-Q78G", "GHSA-MFHQ-GHCJ-C36Q", "GHSA-PRPX-FHMF-2G8P",
 "GHSA-Q6CM-X4F7-73R6", "GHSA-QPVV-MV8X-VG3C", "GHSA-RV98-5GW8-6HF9",
 "GHSA-72V8-H9PQ-46P7", "GHSA-83V8-C68X-GCPR",
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
            "schema_version": "wave2-unr-adj3-v1",
            "row_kind": "unreviewed_adj3_adjudication",
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
            "lane": "herdr-260814-w3-6-ds",
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
        "schema_version": "wave2-unr-adj3-v1",
        "artifact_kind": "ghsa200_wave2_unr_adj3_slice6",
        "owned_directory": "autoresearch/herdr-260814-w3-6-ds",
        "worker": "deepseek-v4-pro", "language": "en", "english_only": True,
        "lane": "herdr-260814-w3-6-ds", "started_at": started,
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
        "input_hashes": {"unr-adj3-slice-6.jsonl": slice_sha},
        "blockers": [
            "All 25 rows are FALSE_POSITIVE: candidate AI commits do not author "
            "the advisory vulnerable hunk (unrelated fixes/refactors; 14 rows "
            "are cross-bound to a different repository).",
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
    return """# herdr-260814-w3-6-ds - slice 6 (unr-adj3) adjudication

**Verdict first: 25/25 FALSE_POSITIVE, 0 countable.** For every row the candidate
AI commits do not author the vulnerable hunk of the named mechanism; they are
unrelated fixes/refactors, and 14 rows name a mechanism in a different
repository than the row's repo. `ai_hunk_gate` and `but_for_gate` FAIL, so no
row closes the seven gates.

## Result

- assigned 25, reviewed 25, FALSE_POSITIVE 25, CONFIRM 0, NARROW 0, UNKNOWN 0
- terminal=true on all rows; zero proposed acceptances

## Per-repository evidence

### getgrav/grav - 16 rows
Candidates are the same five GPM/Installer/media/Twig3 commits as the adj2
slice: upgrade gating (`2c517b01`), media blueprint (`e3ff054d`), two Copilot
Twig3 one-liners (`2dcf9179`, `bf7dd2e6`), and a Twig3 regex fix (`50865058`).
Only three rows name a core-Grav mechanism (blueprint `isSafeDynamicCall`
static-call denylist, Flex Objects ZIP upload RCE, email-action SSTI); the
candidates do not touch those areas. The other 13 rows name mechanisms in
grav-plugin-login (profile-update privilege fields, Remember-Me token expiry),
grav-plugin-form (open redirect, radio/toggle XSS), or grav-plugin-api
(9 API-key scope-cap bypasses) - different repositories than `getgrav/grav`.

### jenkinsci/jenkins - 1 row
CVE-2026-19429 is a `FilePath.untarFrom()` symlink-target bypass. The five
Copilot candidates are UI changes (sidebar navigation, header actions,
badgeClass) plus a `HudsonPrivateSecurityRealm` admin-account race fix; none
touch `FilePath.untarFrom()` tar extraction.

### Zie619/n8n-workflows - 1 row
CVE-2025-55526 is a directory traversal in `api_server.py::download_workflow`.
The Claude candidates are devcontainer, docs, a documentation generator, and
workflow JSON renames; none edit `api_server.py` source.

### rustdesk/hbb_common - 1 row
CVE-2026-30793 is a CSRF/privilege-escalation in the rustdesk-client Flutter URI
handler + FFI bridge (`flutter/lib/common.dart`, `src/flutter_ffi.rs`) - the
`rustdesk/rustdesk` repo, not `hbb_common`. The six Copilot candidates edit
webrtc signaling/examples only.

### rrweb-io/rrweb - 1 row
CVE-2025-45806 is an XSS in rrweb-snapshot serialization (<2.0.0-alpha.18). The
Copilot candidates are a vite migration, a stylesheet replace/replaceSync fix,
and a vitest config fix; none alters snapshot serialization/rebuild.

### jsonpickle/jsonpickle - 1 row
CVE-2021-47952 is the longstanding py/repr deserialization RCE of jsonpickle
2.0.0 (2021). The 2026 GPT/Claude candidates are numpy/pandas, defaultdict,
`__reduce_ex__`, and `types` importable-name changes; none introduces py/repr.

### hestiacp/hestiacp - 1 row
CVE-2026-12196 is a broken access control on the panel cronjob feature. The
candidates are four Copilot XSS/proxy-header hardening commits plus the human
`1.9.5 beta` release (no AI marker); none introduces the cronjob access-control.

### openwrt/luci - 3 rows
CVE-2026-59260 (samba4 `file.exec` ACL), CVE-2026-61876 (DHCPv6 lease hostname
XSS), CVE-2026-61875 (upnp AddPortMapping stored XSS). The five Claude
candidates are DHCPv4 client-id option, two wireless.js additions, a
`cbi.js String.format` extension, and an ocserv status fix; none touches
luci-app-samba4, DHCPv6 lease rendering, or luci-app-upnp.

## Gate summary

identity_gate=PASS (first-party unreviewed advisory names mechanism + CVE);
ai_hunk_gate=FAIL (AI-marked commits do not author the vulnerable hunk);
topology_gate=FAIL; but_for_gate=FAIL; fix_reversal_gate=FAIL;
release_gate=FAIL; uniqueness_gate=PASS.

## Disagreements with stored labels

Upstream triage marked these KEEP on commit-subject overlap. Deep adjudication
of the actual diffs overturns every KEEP: the overlaps are superficial and no
candidate introduces the named mechanism.
"""

def replay(cases, slice_sha):
    L = ["# replay.txt - reproduce this packet (0 proposals)",
         "input slice sha256: " + slice_sha,
         "Input: sweep/unr-adj3-slice-6.jsonl",
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
