#!/usr/bin/env python3
"""Apply leader checkpoint to this lane's outputs only."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
FREEZE = json.loads((HERE / "id_freeze.json").read_text())

# Confirmed identity overlap with fresh-am cases.jsonl (ID-only check; no evidence copied).
FRESH_AM_OVERLAP = {"GHSA-P8RR-9CVG-CX5J", "GHSA-WVPP-8HX9-P66J"}

# Not derived from this lane's frozen first-party repo advisory dumps.
DROP_IDS = {"GHSA-239W-M3H6-CH8V"}

RESIDUAL = {
    "GHSA-VH5J-5FHQ-9XWG": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 UNKNOWN rem row. Cross-review only.",
    },
    "GHSA-5WP8-Q9MX-8JX8": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW rem row. Cross-review only.",
    },
    "GHSA-F38V-77QJ-H4JQ": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW JWT default-open residual. Cross-review only.",
    },
    "GHSA-V396-V7Q4-X2QJ": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW joined-short residual. Cross-review only.",
    },
    "GHSA-3WXW-XV34-2FRG": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW positional --file residual. Cross-review only.",
    },
    "GHSA-F2FQ-4RMP-9X8C": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW ChurchCRM residual. Cross-review only.",
    },
    "GHSA-PV2J-RGHR-V5R9": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW sandbox residual. Cross-review only.",
    },
    "GHSA-3FP5-V549-9V66": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW openclaw rem row. Cross-review only.",
    },
    "GHSA-2X93-H3HG-2XFP": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW openclaw rem row. Cross-review only.",
    },
    "GHSA-QJPC-QF9M-XWMR": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW openclaw rem row. Cross-review only.",
    },
    "GHSA-9C3V-684M-579C": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW openclaw rem row. Cross-review only.",
    },
    "GHSA-J4CX-JVQ7-79VM": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW openclaw rem row. Cross-review only.",
    },
    "GHSA-WP73-F3GG-W4VR": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW openclaw rem row. Cross-review only.",
    },
    "GHSA-7JX6-764P-FGG9": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW openclaw rem row. Cross-review only.",
    },
    "GHSA-2HFG-4FH4-QP7F": {
        "kind": "CROSS_REVIEW_PRESERVED",
        "parent_had_same_form": None,
        "ai_attempt_created_named_bypass": None,
        "rationale": "Existing fp211 NARROW openclaw rem row. Cross-review only.",
    },
    "GHSA-89CF-6HMV-8RXM": {
        "kind": "OLD_VULN_LEFT_INCOMPLETE",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "ScriptRange.Multiply was already unbounded in the parent. Copilot 2d01bd15 did not author that residual. Human 205ca6a7 closed ScriptArray only.",
    },
    "GHSA-24C8-4792-22HX": {
        "kind": "OLD_VULN_LEFT_INCOMPLETE",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "InsertAt fill loop is identical in the parent of Copilot dde661d. The AI sweep never edited InsertAt.",
    },
    "GHSA-C875-H985-HVRC": {
        "kind": "NOT_REMEDIATION",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "Original builtin LoopLimit bypass. Copilot dde661d is the closer, not a residual-creating rem.",
    },
    "GHSA-P6Q4-FGR8-VX4P": {
        "kind": "OLD_VULN_LEFT_INCOMPLETE",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "Nested array-initializer recursion is a sibling parser path the prior depth-limit commit did not edit.",
    },
    "GHSA-WVPP-8HX9-P66J": {
        "kind": "AI_CREATED_RESIDUAL",
        "parent_had_same_form": False,
        "ai_attempt_created_named_bypass": True,
        "rationale": "GPT e8d0fbf7 explicitly preserved the non-splitting compatibility path, creating the unsplit joined-token residual. Still not countable here: uniqueness versus already-counted R9MR, and identity overlaps fresh-am.",
    },
    "GHSA-2F96-G7MH-G2HX": {
        "kind": "OLD_VULN_LEFT_INCOMPLETE",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "Prefix-abbreviation leftover of the 3.1.47 exact-match denylist. GPT 181e8ede is the closer and shares first tag 3.1.51 with the patched bound.",
    },
    "GHSA-X2QX-6953-8485": {
        "kind": "NOT_REMEDIATION",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "Original pre-split multi_options bug. c9a26789 is its closer, not a later residual.",
    },
    "GHSA-956X-8GVW-WG5V": {
        "kind": "NOT_REMEDIATION",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "Original unguarded archive/ls_remote/blame. GPT 701ce32f is the closer of the named scope.",
    },
    "GHSA-RWJ8-PGH3-R573": {
        "kind": "NOT_REMEDIATION",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "Original clone_from expandvars. GPT 8ac5a305 is the complete closer of this named scope.",
    },
    "GHSA-9QHQ-V63V-FV3J": {
        "kind": "OLD_VULN_LEFT_INCOMPLETE",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "Human 47bff654 is the named incomplete MCP allowlist. No AI marker. Residual is the old unvalidated parse path.",
    },
    "GHSA-RG3H-X3JW-7JM5": {
        "kind": "OLD_VULN_LEFT_INCOMPLETE",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "Nine sibling backends already interpolated table_prefix. The SQLite-only guard did not create those holes.",
    },
    "GHSA-JXCW-QP4H-6JFQ": {
        "kind": "OLD_VULN_LEFT_INCOMPLETE",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "Dedicated A2U CLI path never received the claimed 4.5.115 auth. Residual is an unattempted sibling, not an AI-created bypass.",
    },
    "GHSA-892R-P3JQ-JP24": {
        "kind": "OLD_VULN_LEFT_INCOMPLETE",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "AgentOS never received the generated-deploy API auth path. Human closer b4270173.",
    },
    "GHSA-JXX9-PX88-PJ69": {
        "kind": "NOT_REMEDIATION",
        "parent_had_same_form": False,
        "ai_attempt_created_named_bypass": False,
        "rationale": "Claude feature commit created a new multi-tenant surface with fail-open fallback. That is origin/new-surface, not rem of a prior vulnerability. This lane does not PASS that class.",
    },
    "GHSA-6CQF-375W-639G": {
        "kind": "OLD_VULN_LEFT_INCOMPLETE",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "Feed handlers already lacked token-scope checks. Human PR #37698 never edited them.",
    },
    "GHSA-Q9P7-WQXG-MRHC": {
        "kind": "OLD_VULN_LEFT_INCOMPLETE",
        "parent_had_same_form": True,
        "ai_attempt_created_named_bypass": False,
        "rationale": "empty-locals eval builtins leak is the pre-existing sanitizer design, not a residual created by the Copilot full_eval hunk counted in X34R.",
    },
    "GHSA-62Q4-447F-WV8H": {
        "kind": "NOT_REMEDIATION",
        "parent_had_same_form": False,
        "ai_attempt_created_named_bypass": False,
        "rationale": "2023-05-15 startswith reintroduction. No AI marker recovered. Outside May 2025 coverage.",
    },
    "GHSA-P8RR-9CVG-CX5J": {
        "kind": "AI_CREATED_RESIDUAL",
        "parent_had_same_form": False,
        "ai_attempt_created_named_bypass": True,
        "rationale": "Claude 61ff20fe re-allows private/loopback after a prior guard. That is a created reintroduction residual. Still not countable: unreviewed identity, incomplete 3.2.8 reversal, and identity overlaps fresh-am.",
    },
}

NEW_ROWS = [
    {
        "schema_version": 1,
        "lane": "herdr-260813-ghsa200-remediation",
        "worker_pass_is_proposal": True,
        "case_id": "GHSA-2MQJ-M65W-JGHX",
        "aliases": ["CVE-2024-22190"],
        "repository": "gitpython-developers/GitPython",
        "mechanism_key": "gitpython-windows-untrusted-search-path",
        "scope_statement": "Incomplete fix of CVE-2023-40590: Windows still searches an untrusted path when shell=True or when launching bash.exe for hooks.",
        "contribution_class": "AI_INCOMPLETE_REMEDIATION",
        "candidate_set": [],
        "carrier_set": [],
        "minimum_fix_set": [],
        "vulnerable_release_evidence": {"advisory_range": "<= 3.1.40"},
        "fixed_release_evidence": {"advisory_patched": ">= 3.1.41"},
        "identity_gate": "PASS",
        "ai_hunk_gate": "REJECT",
        "topology_gate": "UNKNOWN",
        "but_for_gate": "REJECT",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "NARROW",
        "uniqueness_gate": "PASS",
        "first_party_sources": ["https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-2mqj-m65w-jghx"],
        "ai_marker_evidence": [],
        "counterevidence": [
            "First-party GitPython advisory published 2024-01-10, before May 2025 coverage",
            "Named residual is the leftover Windows search-path hole from CVE-2023-40590, not an AI-created bypass",
        ],
        "replay_commands": [
            "python3 -c \"import json;from pathlib import Path;rows=json.loads(Path('autoresearch/herdr-260813-ghsa200-remediation/evidence/gitpython-advisories.json').read_text());print([r['ghsa_id'] for r in rows if r['ghsa_id']=='GHSA-2mqj-m65w-jghx'])\""
        ],
        "baseline_overlap": "absent_from_fp211_declared_and_publication_corpus",
        "disposition": "REJECT",
        "verdict": "REJECT",
        "false_positive_class": "pre_coverage_old_vuln_left_incomplete",
        "residual_classification": {
            "kind": "OLD_VULN_LEFT_INCOMPLETE",
            "parent_had_same_form": True,
            "ai_attempt_created_named_bypass": False,
            "rationale": "2023/2024 leftover of CVE-2023-40590. No AI rem created this residual.",
        },
        "derivation": "first_party_repo_advisory_dump:evidence/gitpython-advisories.json",
        "notes": None,
    },
    {
        "schema_version": 1,
        "lane": "herdr-260813-ghsa200-remediation",
        "worker_pass_is_proposal": True,
        "case_id": "GHSA-9CR9-25Q5-8PRJ",
        "aliases": ["CVE-2026-47394"],
        "repository": "MervinPraison/PraisonAI",
        "mechanism_key": "praisonai-mcp-workflow-show-path-residual",
        "scope_statement": "Cascade-coauthored 68cc9427 hardened rules.create/show/delete paths and left workflow.show, workflow.validate, and deploy.validate unchanged.",
        "contribution_class": "AI_INCOMPLETE_REMEDIATION",
        "candidate_set": ["68cc9427ffca2f5f844051f8b90f94367bcd5689"],
        "carrier_set": [],
        "minimum_fix_set": [],
        "vulnerable_release_evidence": {"advisory_range": "<= 4.6.39"},
        "fixed_release_evidence": {"advisory_patched": ">= 4.6.40"},
        "identity_gate": "PASS",
        "ai_hunk_gate": "PASS",
        "topology_gate": "PASS",
        "but_for_gate": "REJECT",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "NARROW",
        "uniqueness_gate": "PASS",
        "first_party_sources": ["https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-9cr9-25q5-8prj"],
        "ai_marker_evidence": [
            "68cc9427 Co-authored-by: Cascade <cascade@windsurf.dev>; names GHSA-9mqq-jqxf-grvw rules-path harden only"
        ],
        "counterevidence": [
            "workflow.show was already unguarded in the parent of 68cc9427",
            "Deleting the Cascade rem restores the broader rules-path hole and leaves workflow.show identical",
            "This is an old vulnerability merely left incomplete, not an AI-created residual",
        ],
        "replay_commands": [
            "git -C /tmp/ghsa200-worker-clones/remediation/PraisonAI show -s --format='%an %s%n%b' 68cc9427ffca2f5f844051f8b90f94367bcd5689"
        ],
        "baseline_overlap": "absent_from_fp211_declared_and_publication_corpus",
        "disposition": "REJECT",
        "verdict": "REJECT",
        "false_positive_class": "wrong_edge_old_vuln_left_incomplete",
        "residual_classification": {
            "kind": "OLD_VULN_LEFT_INCOMPLETE",
            "parent_had_same_form": True,
            "ai_attempt_created_named_bypass": False,
            "rationale": "AI rem attempted the rules.* handlers. Named residual is the unedited sibling workflow/deploy handlers.",
        },
        "derivation": "first_party_repo_advisory_dump:evidence/praisonai-advisories.json",
        "notes": None,
    },
    {
        "schema_version": 1,
        "lane": "herdr-260813-ghsa200-remediation",
        "worker_pass_is_proposal": True,
        "case_id": "GHSA-8HJW-25CG-G52H",
        "aliases": ["CVE-2026-55523"],
        "repository": "MervinPraison/PraisonAI",
        "mechanism_key": "praisonai-web-crawl-redirect-ssrf",
        "scope_statement": "web_crawl validates the first URL then follows redirects without revalidation.",
        "contribution_class": "AI_INCOMPLETE_REMEDIATION",
        "candidate_set": [],
        "carrier_set": [],
        "minimum_fix_set": [],
        "vulnerable_release_evidence": {"advisory_range": "praisonaiagents >= 1.5.128, <= 1.6.56"},
        "fixed_release_evidence": {"advisory_patched": ">= 1.6.58"},
        "identity_gate": "PASS",
        "ai_hunk_gate": "UNKNOWN",
        "topology_gate": "UNKNOWN",
        "but_for_gate": "REJECT",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "NARROW",
        "uniqueness_gate": "NARROW",
        "first_party_sources": ["https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-8hjw-25cg-g52h"],
        "ai_marker_evidence": [],
        "counterevidence": [
            "Redirect-follow hole is the leftover of an initial-URL SSRF check, not a new residual form created by an AI rem",
            "No atomic AI marker recovered on the incomplete web_crawl guard",
        ],
        "replay_commands": [],
        "baseline_overlap": "absent_from_fp211_declared_and_publication_corpus",
        "disposition": "REJECT",
        "verdict": "REJECT",
        "false_positive_class": "old_vuln_left_incomplete",
        "residual_classification": {
            "kind": "OLD_VULN_LEFT_INCOMPLETE",
            "parent_had_same_form": True,
            "ai_attempt_created_named_bypass": False,
            "rationale": "httpx follow_redirects leftover of a first-URL blocklist. Parent already had the redirect path.",
        },
        "derivation": "first_party_repo_advisory_dump:evidence/praisonai-advisories.json",
        "notes": None,
    },
    {
        "schema_version": 1,
        "lane": "herdr-260813-ghsa200-remediation",
        "worker_pass_is_proposal": True,
        "case_id": "GHSA-RG5Q-PP8P-F7JM",
        "aliases": ["CVE-2026-55537"],
        "repository": "MervinPraison/PraisonAI",
        "mechanism_key": "praisonai-webhook-dns-fail-open",
        "scope_statement": "validate_webhook_url passes on DNS failure and re-resolves later, a leftover of CVE-2026-40114.",
        "contribution_class": "AI_INCOMPLETE_REMEDIATION",
        "candidate_set": [],
        "carrier_set": [],
        "minimum_fix_set": [],
        "vulnerable_release_evidence": {"advisory_range": "<= 4.6.52"},
        "fixed_release_evidence": {"advisory_patched": ">= 4.6.58"},
        "identity_gate": "PASS",
        "ai_hunk_gate": "UNKNOWN",
        "topology_gate": "UNKNOWN",
        "but_for_gate": "REJECT",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "NARROW",
        "uniqueness_gate": "PASS",
        "first_party_sources": ["https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-rg5q-pp8p-f7jm"],
        "ai_marker_evidence": [],
        "counterevidence": [
            "except socket.gaierror: pass is a leftover of the prior webhook SSRF check, not an AI-created residual form",
            "No atomic AI marker recovered on the incomplete validator",
        ],
        "replay_commands": [],
        "baseline_overlap": "absent_from_fp211_declared_and_publication_corpus",
        "disposition": "REJECT",
        "verdict": "REJECT",
        "false_positive_class": "old_vuln_left_incomplete",
        "residual_classification": {
            "kind": "OLD_VULN_LEFT_INCOMPLETE",
            "parent_had_same_form": True,
            "ai_attempt_created_named_bypass": False,
            "rationale": "DNS fail-open and TOCTOU re-resolve preexist as gaps in the prior webhook guard.",
        },
        "derivation": "first_party_repo_advisory_dump:evidence/praisonai-advisories.json",
        "notes": None,
    },
    {
        "schema_version": 1,
        "lane": "herdr-260813-ghsa200-remediation",
        "worker_pass_is_proposal": True,
        "case_id": "GHSA-6G6R-Q6GW-W8FG",
        "aliases": ["CVE-2026-55536"],
        "repository": "MervinPraison/PraisonAI",
        "mechanism_key": "praisonai-browser-origin-unanchored-regex",
        "scope_statement": "Unanchored chrome-extension Origin regex leftover after GHSA-8x8f-54wf-vv92.",
        "contribution_class": "AI_INCOMPLETE_REMEDIATION",
        "candidate_set": [],
        "carrier_set": [],
        "minimum_fix_set": [],
        "vulnerable_release_evidence": {"advisory_range": "<= 4.6.52"},
        "fixed_release_evidence": {"advisory_patched": ">= 4.6.58"},
        "identity_gate": "PASS",
        "ai_hunk_gate": "UNKNOWN",
        "topology_gate": "UNKNOWN",
        "but_for_gate": "REJECT",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "NARROW",
        "uniqueness_gate": "PASS",
        "first_party_sources": ["https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-6g6r-q6gw-w8fg"],
        "ai_marker_evidence": [],
        "counterevidence": [
            "Unanchored re.match is a leftover of the prior origin check, not a new residual created by an AI rem",
        ],
        "replay_commands": [],
        "baseline_overlap": "absent_from_fp211_declared_and_publication_corpus",
        "disposition": "REJECT",
        "verdict": "REJECT",
        "false_positive_class": "old_vuln_left_incomplete",
        "residual_classification": {
            "kind": "OLD_VULN_LEFT_INCOMPLETE",
            "parent_had_same_form": True,
            "ai_attempt_created_named_bypass": False,
            "rationale": "The named bypass is the same origin-check surface with a weaker regex, not a new form created by AI rem.",
        },
        "derivation": "first_party_repo_advisory_dump:evidence/praisonai-advisories.json",
        "notes": None,
    },
    {
        "schema_version": 1,
        "lane": "herdr-260813-ghsa200-remediation",
        "worker_pass_is_proposal": True,
        "case_id": "GHSA-XCMW-GRXF-WJHJ",
        "aliases": ["CVE-2026-44334"],
        "repository": "MervinPraison/PraisonAI",
        "mechanism_key": "praisonai-tool-override-ungated-exec",
        "scope_statement": "CVE-2026-40287 gated two tools.py import sinks and left templates/tool_override.py unguarded.",
        "contribution_class": "AI_INCOMPLETE_REMEDIATION",
        "candidate_set": [],
        "carrier_set": [],
        "minimum_fix_set": [],
        "vulnerable_release_evidence": {"advisory_range": ">= 4.5.139, <= 4.6.31"},
        "fixed_release_evidence": {"advisory_patched": ">= 4.6.32"},
        "identity_gate": "PASS",
        "ai_hunk_gate": "UNKNOWN",
        "topology_gate": "UNKNOWN",
        "but_for_gate": "REJECT",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "NARROW",
        "uniqueness_gate": "PASS",
        "first_party_sources": ["https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-xcmw-grxf-wjhj"],
        "ai_marker_evidence": [],
        "counterevidence": [
            "tool_override.py already executed tools.py in the parent. The two-file gate did not create that sink",
            "Sibling-unattempted leftover, not an AI-created residual",
        ],
        "replay_commands": [],
        "baseline_overlap": "absent_from_fp211_declared_and_publication_corpus",
        "disposition": "REJECT",
        "verdict": "REJECT",
        "false_positive_class": "wrong_edge_old_vuln_left_incomplete",
        "residual_classification": {
            "kind": "OLD_VULN_LEFT_INCOMPLETE",
            "parent_had_same_form": True,
            "ai_attempt_created_named_bypass": False,
            "rationale": "Third import sink was never edited by the claimed fix. Parent already had the unguarded exec.",
        },
        "derivation": "first_party_repo_advisory_dump:evidence/praisonai-advisories.json",
        "notes": None,
    },
]


def main():
    rows = [json.loads(l) for l in (HERE / "cases.jsonl").read_text().splitlines() if l.strip()]
    out = []
    for r in rows:
        cid = r["case_id"]
        if cid in DROP_IDS:
            continue
        r.pop("notes", None)
        if cid in RESIDUAL:
            r["residual_classification"] = RESIDUAL[cid]
        r["derivation"] = r.get("derivation") or (
            "fp211_freeze_cross_review"
            if r.get("disposition") == "CROSS_REVIEW_ONLY"
            else "first_party_repo_advisory_or_global_object"
        )
        if cid in FRESH_AM_OVERLAP:
            r["disposition"] = "ROUTE_CONFLICT"
            r["verdict"] = "REJECT"
            r["fresh_lane_overlap"] = "fresh-am"
            r.setdefault("counterevidence", []).append(
                "Identity overlaps fresh-am cases.jsonl. ROUTE_CONFLICT; this lane does not PASS."
            )
        if r.get("disposition") == "ROUTE_FRESH_AM":
            r["disposition"] = "REJECT"
            r["verdict"] = "REJECT"
            r.setdefault("counterevidence", []).append(
                "Not rem/reintro class. This lane does not PASS origin or new-surface identities and does not copy fresh-lane candidates."
            )
        if "fresh-am" in json.dumps(r.get("counterevidence", [])).lower() and cid == "GHSA-JXX9-PX88-PJ69":
            r["counterevidence"] = [
                c
                for c in r["counterevidence"]
                if "fresh-am" not in c.lower() and "owned by fresh" not in c.lower()
            ] + [
                "Not rem/reintro class. This lane does not PASS origin or new-surface identities and does not copy fresh-lane candidates."
            ]
        r["worker_pass_is_proposal"] = True
        assert r["verdict"] != "PASS"
        out.append(r)

    have = {r["case_id"] for r in out}
    for nr in NEW_ROWS:
        if nr["case_id"] not in have:
            out.append(nr)

    cross = [r for r in out if r.get("disposition") == "CROSS_REVIEW_ONLY"]
    rest = [r for r in out if r.get("disposition") != "CROSS_REVIEW_ONLY"]
    cross.sort(key=lambda r: r.get("fp211_ordinal") or 0)
    rest.sort(key=lambda r: r["case_id"])
    ordered = cross + rest

    for r in ordered:
        assert r["verdict"] != "PASS"
        assert "residual_classification" in r
        if r.get("disposition") == "CROSS_REVIEW_ONLY":
            assert r["case_id"] in {x["case_id"] for x in FREEZE["narrow_unknown_incomplete"]}

    (HERE / "cases.jsonl").write_text("".join(json.dumps(r, ensure_ascii=True) + "\n" for r in ordered))

    counts = {
        "reviewed_rows": len(ordered),
        "pass_proposals": 0,
        "reject": sum(1 for r in ordered if r["verdict"] == "REJECT"),
        "narrow": sum(1 for r in ordered if r["verdict"] == "NARROW"),
        "unknown": sum(1 for r in ordered if r["verdict"] == "UNKNOWN"),
        "blocked": 0,
        "cross_review_only": sum(1 for r in ordered if r["disposition"] == "CROSS_REVIEW_ONLY"),
        "route_conflict": sum(1 for r in ordered if r["disposition"] == "ROUTE_CONFLICT"),
        "new_ids_reviewed": sum(1 for r in ordered if r["disposition"] != "CROSS_REVIEW_ONLY"),
        "ai_created_residual": sum(
            1 for r in ordered if (r.get("residual_classification") or {}).get("kind") == "AI_CREATED_RESIDUAL"
        ),
        "old_vuln_left_incomplete": sum(
            1 for r in ordered if (r.get("residual_classification") or {}).get("kind") == "OLD_VULN_LEFT_INCOMPLETE"
        ),
        "not_remediation": sum(
            1 for r in ordered if (r.get("residual_classification") or {}).get("kind") == "NOT_REMEDIATION"
        ),
    }

    result = {
        "lane": "herdr-260813-ghsa200-remediation",
        "task": "fresh AI_INCOMPLETE_REMEDIATION and AI_REINTRODUCTION across all repositories",
        "status": "COMPLETE",
        "checkpoint": "leader-2026-08-13-route-conflict-and-residual-kind",
        "started_at": "2026-08-13T16:23:00-04:00",
        "ended_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "output_dir": str(HERE),
        "clone_root": "/tmp/ghsa200-worker-clones/remediation",
        "worker_pass_is_proposal": True,
        "proposed_pass_count": 0,
        "input_hashes": FREEZE["input_hashes"],
        "counts": counts,
        "shared_paths_mutated": 0,
        "derivation_rule": "New IDs come from this lane's frozen first-party repo advisory dumps (gitpython, scriban, praisonai) plus independently fetched first-party GHSA objects. Sibling fresh-am/fresh-nz files are not evidence and were not copied.",
        "dedupe": {
            "against_fp211": "existing fp211 IDs are CROSS_REVIEW_ONLY; no PASS",
            "against_fresh_lanes": "ID-only overlap check marked GHSA-P8RR-9CVG-CX5J and GHSA-WVPP-8HX9-P66J as ROUTE_CONFLICT; no PASS",
        },
        "dropped_not_independently_derived": [
            "GHSA-239W-M3H6-CH8V: not present in this lane's first-party repo advisory dumps; removed after checkpoint"
        ],
        "blockers": [
            "No novel first-party GHSA closed all seven gates as an AI-created rem/reintro residual.",
            "The only AI_CREATED_RESIDUAL rows (WVPP, P8RR) are ROUTE_CONFLICT and fail uniqueness or identity/fix_reversal.",
            "Most incomplete-fix GHSAs are OLD_VULN_LEFT_INCOMPLETE: the parent already contained the named hole.",
        ],
    }
    (HERE / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n")
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
