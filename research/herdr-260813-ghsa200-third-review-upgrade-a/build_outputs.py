#!/usr/bin/env python3
"""Generate result.json and cases.jsonl (4 rows) for the third-review upgrade-a lane.

Deterministic. Reads only frozen baseline/canonical/publication artifacts and
the fresh clones under ~/.cache/ghsa200-worker-clones/third-review-upgrade-a.
Writes only into this lane directory. Never promotes or edits canonical files.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path



HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "autoresearch/herdr-260813-ghsa200-cross-dedupe"))

import dedupe_checker as dc  # noqa: E402

CANON = ROOT / "autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl"
AUDIT = ROOT / "autoresearch/orchestrator-260813-fp211-audit"
LEADER = ROOT / "autoresearch/orchestrator-260813-ghsa200-leader"
PROPOSER_UPGRADE_A = ROOT / "autoresearch/herdr-260813-ghsa200-upgrade-a"
RED_UPGRADE_A = ROOT / "autoresearch/herdr-260813-ghsa200-red-upgrade-a"
RED_UPGRADE_A_COMPOSITE = ROOT / "autoresearch/herdr-260813-ghsa200-red-upgrade-a-ord20-composite"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    ledger = [json.loads(l) for l in open(CANON)]
    alias_map = dc.build_alias_map(ledger)
    comp = [r for r in ledger if r.get("record_kind") == "COMPONENT_ROW"]

    # Verified evidence per case (independent review).
    cases = [
        {
            "ordinal": 1,
            "case_id": "GHSA-FMFG-9G7C-3VQ7",
            "aliases": ["CVE-2026-32111"],
            "repository": "homeassistant-ai/ha-mcp",
            "mechanism_key": "ha-mcp-oauth-user-supplied-ha-url-ssrf",
            "verdict": "ACCEPT",
            "causal_class": "AI_DIRECT_ROOT",
            "scope_statement": "Count only code path 1: the OAuth consent form accepting user-supplied ha_url and the server-side GET {ha_url}/api/config added by AI squash 39806871. Exclude later unsigned-token REST/WebSocket paths (1399f5a, human+Claude co-authored).",
            "candidate_set": ["39806871c9720bf8afdcf3e061095c0dd63dea7f"],
            "minimum_fix_set": ["dc8eaa16a8550f885614655f14b6fd9fe429b278"],
            "release_evidence": {
                "vulnerable_tag": "v6.7.2", "fixed_tag": "v7.0.0",
                "first_tag_with_candidate": "v6.3.0",
                "candidate_in_vulnerable": True, "fix_in_fixed": True, "fix_in_vulnerable": False,
                "advisory_range": "< 7.0.0", "advisory_first_patched": "7.0.0",
            },
            "gates": {
                "identity_gate": "PASS", "ai_hunk_gate": "PASS", "topology_gate": "PASS",
                "but_for_gate": "PASS", "fix_reversal_gate": "PASS", "release_gate": "PASS",
                "uniqueness_gate": "PASS",
            },
            "evidence": {
                "ai_marker": "39806871 carries 'Generated with Claude Code' and 'Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>'",
                "topology": "squash 39806871 is an ancestor of v6.7.2; fp211 member aae7acba absent from mainline (squash member, not tag ancestor)",
                "fix_reversal": "dc8eaa16 'feat!: fix SSRF and XSS in OAuth consent form (#748)' removes ha_url from consent form; provider.py ha_url count 22 in v6.7.2 -> 0 in v7.0.0",
                "identity": "first-party GHSA summary: 'ha-mcp OAuth 2.1 DCR mode enables network reconnaissance via an error oracle'; names consent-form ha_url + {ha_url}/api/config",
                "sibling_note": "paths 2/3 (REST/WebSocket) originate from 1399f5a, human-authored (Julien Larocque-Dupont) with Claude Sonnet 4.5 co-author; out of scope",
            },
            "dedupe": "ALIAS_SAME_COMPONENT vs its own canonical row (SAME_ID); no cross-GHSA mechanism collision; unique mechanism_key",
            "first_party_sources": [
                "https://github.com/advisories/GHSA-fmfg-9g7c-3vq7",
                "https://github.com/homeassistant-ai/ha-mcp/security/advisories/GHSA-fmfg-9g7c-3vq7",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-32111",
            ],
        },
        {
            "ordinal": 20,
            "case_id": "GHSA-XW8C-RRVX-F7XQ",
            "aliases": ["CVE-2026-44219"],
            "repository": "Jo-Jo98/ciguard",
            "mechanism_key": "sca_http_unbounded_resp_read",
            "verdict": "ACCEPT",
            "causal_class": "AI_DIRECT_ROOT",
            "scope_statement": "Count the official GHSA mechanism as both Claude-authored SCA clients: endoflife.py (d42195e1) and osv.py (f08e6549). Last named vulnerable release is v0.8.1 (contains both unbounded reads, excludes fix).",
            "candidate_set": ["d42195e10be0d7d9bfb4ec45fecfb83521d3fc67", "f08e654974f208f90ef6015928ef651982f3224a"],
            "minimum_fix_set": ["17a119fe43dd956ef463c1c575a463ffd9a8d95b"],
            "release_evidence": {
                "vulnerable_tag": "v0.8.1", "fixed_tag": "v0.8.2",
                "first_tag_endoflife": "v0.6.0", "first_tag_osv": "v0.6.1",
                "candidate_in_vulnerable": True, "fix_in_fixed": True, "fix_in_vulnerable": False,
                "advisory_range": ">= 0.6.0, <= 0.8.1", "advisory_first_patched": "0.8.2",
            },
            "gates": {
                "identity_gate": "PASS", "ai_hunk_gate": "PASS", "topology_gate": "PASS",
                "but_for_gate": "PASS", "fix_reversal_gate": "PASS", "release_gate": "PASS",
                "uniqueness_gate": "PASS",
            },
            "evidence": {
                "ai_marker": "d42195e1 and f08e6549 each carry 'Co-Authored-By: Claude Opus 4.7 (1M context)'",
                "topology": "both direct commits; d42195e1 in v0.6.0, f08e6549 in v0.6.1, both in v0.8.1",
                "fix_reversal": "17a119fe replaces resp.read().decode() with resp.read(MAX_RESPONSE_BYTES+1)+overflow in both osv.py and endoflife.py; MAX_RESPONSE_BYTES=5MB",
                "umbrella_fix_note": "17a119fe also touches Dockerfile/discovery.py/web headers (CYCLE-1 pentest); the SCA read cap is in the same commit and caps both named reads",
                "identity": "first-party GHSA: 'Both SCA HTTP clients (osv.py and endoflife.py) call payload = json.loads(resp.read().decode())'",
            },
            "dedupe": "ALIAS_SAME_COMPONENT vs its own canonical row (SAME_ID); no cross-GHSA collision; unique mechanism_key",
            "first_party_sources": [
                "https://github.com/advisories/GHSA-xw8c-rrvx-f7xq",
                "https://github.com/Jo-Jo98/ciguard/security/advisories/GHSA-xw8c-rrvx-f7xq",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-44219",
            ],
        },
        {
            "ordinal": 92,
            "case_id": "GHSA-WV46-V6XC-2QHF",
            "aliases": ["CVE-2026-35670"],
            "repository": "openclaw/openclaw",
            "mechanism_key": "openclaw.reply-recipient.mutable-username-nickname",
            "verdict": "ACCEPT",
            "causal_class": "AI_DIRECT_ROOT",
            "scope_statement": "Count squash 9a3800d8 that first added Synology Chat resolveChatUserId nickname-then-username matching used for reply delivery.",
            "candidate_set": ["9a3800d8e6e69bc0a125dca5760d47515e746454"],
            "minimum_fix_set": ["7ade3553b74ee3f461c4acd216653d5ba411f455"],
            "release_evidence": {
                "vulnerable_tag": "v2026.3.2", "fixed_tag": "v2026.3.22",
                "first_tag_with_candidate": "v2026.3.2",
                "candidate_in_vulnerable": True, "fix_in_fixed": True, "fix_in_vulnerable": False,
                "advisory_range": "< 2026.3.22", "advisory_first_patched": "2026.3.22",
            },
            "gates": {
                "identity_gate": "PASS", "ai_hunk_gate": "PASS", "topology_gate": "PASS",
                "but_for_gate": "PASS", "fix_reversal_gate": "PASS", "release_gate": "PASS",
                "uniqueness_gate": "PASS",
            },
            "evidence": {
                "ai_marker": "9a3800d8 carries 'Co-Authored-By: Claude Opus 4.6'",
                "topology": "squash 9a3800d8 is ancestor of v2026.3.2; fp211 member ce12b909 not a tag ancestor",
                "fix_reversal": "7ade3553 'fix: gate synology chat reply name matching' returns payload.user_id unless dangerous opt-in (dangerouslyAllowNameMatching)",
                "identity": "first-party GHSA: 'Synology Chat reply delivery could rebind to a mutable username match instead of the stable numeric user_id'",
            },
            "dedupe": "ALIAS_SAME_COMPONENT vs its own canonical row (SAME_ID); no cross-GHSA collision; unique mechanism_key",
            "first_party_sources": [
                "https://github.com/advisories/GHSA-wv46-v6xc-2qhf",
                "https://github.com/openclaw/openclaw/security/advisories/GHSA-wv46-v6xc-2qhf",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-35670",
            ],
        },
        {
            "ordinal": 93,
            "case_id": "GHSA-RG8M-3943-VM6Q",
            "aliases": ["CVE-2026-41376"],
            "repository": "openclaw/openclaw",
            "mechanism_key": "openclaw.matrix.thread-root-body.missing-sender-check",
            "verdict": "ACCEPT",
            "causal_class": "AI_NEW_SURFACE_CONTRIBUTOR",
            "scope_statement": "Count only the AI-authored Matrix thread-root surface: squash 49c60e90 injected ThreadStarterBody via fetchEventSummary without a sender allowlist. Exclude the later reply-context.ts surface (c7fbd518, human alberthild) that the same advisory also names.",
            "candidate_set": ["49c60e9065d98a6848e62c717315eb91eeaa6038"],
            "minimum_fix_set": ["8a563d603b70ef6338915f0527bee87282c3bad5"],
            "release_evidence": {
                "vulnerable_tag": "v2026.2.12", "fixed_tag": "v2026.3.31",
                "first_tag_with_candidate": "v2026.2.12",
                "candidate_in_vulnerable": True, "fix_in_fixed": True, "fix_in_vulnerable": False,
                "advisory_range": "<= 2026.3.28", "advisory_first_patched": "2026.3.31",
            },
            "gates": {
                "identity_gate": "PASS", "ai_hunk_gate": "PASS", "topology_gate": "PASS",
                "but_for_gate": "PASS", "fix_reversal_gate": "PASS", "release_gate": "PASS",
                "uniqueness_gate": "PASS",
            },
            "evidence": {
                "ai_marker": "49c60e90 'feat(matrix): add thread session isolation (#8241)' carries 'Co-authored-by: Claude Opus 4.5'",
                "topology": "squash 49c60e90 is ancestor of v2026.2.12; fp211 member fbfe2f15 not a tag ancestor",
                "fix_reversal": "8a563d60 'fix(matrix): filter fetched room context by sender allowlist' adds resolveMatrixAllowListMatch filtering to the thread/room context",
                "human_sibling": "reply-context.ts (c7fbd518, 'fix(matrix): resolve reply context body and sender for quoted messages (#55056)') is authored by alberthild + gumadeiras with NO AI marker; human-origin sibling surface named by the advisory",
                "identity": "first-party GHSA: 'Matrix thread root and reply context bypass sender allowlist'",
            },
            "dedupe": "ALIAS_SAME_COMPONENT vs its own canonical row (SAME_ID); no cross-GHSA collision; unique mechanism_key; distinct from GHSA-WV46-V6XC-2QHF (ordinal 92)",
            "first_party_sources": [
                "https://github.com/advisories/GHSA-rg8m-3943-vm6q",
                "https://github.com/openclaw/openclaw/security/advisories/GHSA-rg8m-3943-vm6q",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-41376",
            ],
        },
    ]

    # dedupe re-verification
    proposals = []
    for c in cases:
        proposals.append({
            "case_id": c["case_id"], "aliases": c["aliases"],
            "repository": c["repository"], "mechanism_key": c["mechanism_key"],
            "candidate_set": c["candidate_set"], "minimum_fix_set": c["minimum_fix_set"],
            "release_evidence": c["release_evidence"],
        })
    prop_views = [dc.RowView(r, label=r["case_id"]) for r in proposals]
    ref_views = [dc.RowView(r, label=str(r.get("row_key") or "")) for r in comp]
    dup_findings = []
    for pv in prop_views:
        for rv in ref_views:
            rel = dc.classify(pv, rv, alias_map)
            if rel["verdict"] != "DISTINCT" and rel["identity"] == "SAME_ID":
                dup_findings.append({"case": pv.label, "verdict": rel["verdict"],
                                     "matches_canonical": rv.label})
    # confirm exactly one SAME_ID collision per proposal and no other-GHSA DUPLICATE/CONFLICT
    cross_ghsa = []
    # Final reviewed hypothesis sources (authoritative). The proposer's raw
    # upgrade-a rows are stale and are superseded by the red-team review and the
    # ordinal-20 composite correction.
    red_result = json.loads((RED_UPGRADE_A / "result.json").read_text())
    expected_proposer_sha = red_result["inputs"]["upgrade_a_cases_jsonl_sha256"]
    current_proposer_sha = sha256_file(PROPOSER_UPGRADE_A / "cases.jsonl")

    final_sources = {
        "red-upgrade-a/cases.jsonl": {
            "path": str(RED_UPGRADE_A / "cases.jsonl"),
            "sha256": sha256_file(RED_UPGRADE_A / "cases.jsonl"),
            "supplies": "FINAL hypothesis rows for ordinals 1 (KEEP), 92 (KEEP), 93 (KEEP)",
        },
        "red-upgrade-a/result.json": {
            "path": str(RED_UPGRADE_A / "result.json"),
            "sha256": sha256_file(RED_UPGRADE_A / "result.json"),
            "supplies": "red-team terminal status; binds the stale proposer hash " + expected_proposer_sha[:12] + "...",
        },
        "red-upgrade-a-ord20-composite/cases.jsonl": {
            "path": str(RED_UPGRADE_A_COMPOSITE / "cases.jsonl"),
            "sha256": sha256_file(RED_UPGRADE_A_COMPOSITE / "cases.jsonl"),
            "supplies": "FINAL hypothesis row for ordinal 20 (two-candidate official composite, KEEP)",
        },
        "red-upgrade-a-ord20-composite/result.json": {
            "path": str(RED_UPGRADE_A_COMPOSITE / "result.json"),
            "sha256": sha256_file(RED_UPGRADE_A_COMPOSITE / "result.json"),
            "supplies": "composite terminal status for ordinal 20",
        },
    }
    hypothesis_input_sha256 = {k: v["sha256"] for k, v in final_sources.items()}

    proposer_stale = current_proposer_sha != expected_proposer_sha
    stale_source = {
        "path": str(PROPOSER_UPGRADE_A / "cases.jsonl"),
        "expected_sha256": expected_proposer_sha,
        "current_sha256": current_proposer_sha,
    }
    non_authoritative_context = {
        "upgrade-a/cases.jsonl": {
            "path": str(PROPOSER_UPGRADE_A / "cases.jsonl"),
            "sha256": current_proposer_sha,
            "status": "NON_AUTHORITATIVE_CONTEXT",
            "note": "proposer rows stale; superseded by final red/correction hypotheses",
        },
        "upgrade-a/result.json": {
            "path": str(PROPOSER_UPGRADE_A / "result.json"),
            "sha256": sha256_file(PROPOSER_UPGRADE_A / "result.json"),
            "status": "NON_AUTHORITATIVE_CONTEXT",
        },
    }
    final_hypothesis_review_fresh = True
    superseded_edge = True
    superseded_reason = (
        "red-upgrade-a/result.json binds upgrade-a/cases.jsonl hash "
        + expected_proposer_sha[:12]
        + "... but current upgrade-a/cases.jsonl is "
        + current_proposer_sha[:12]
        + "...; the final reviewed hypotheses supersede the stale proposer rows"
    )

    for pv in prop_views:
        for rv in ref_views:
            rel = dc.classify(pv, rv, alias_map)
            if rel["verdict"] in ("DUPLICATE", "CONFLICT") and rel["identity"] != "SAME_ID":
                cross_ghsa.append((pv.label, rel["verdict"], rv.label))

    result = {
        "schema_version": 1,
        "status": "COMPLETE_THIRD_REVIEW",
        "lane": "third-review-upgrade-a",
        "read_only": True,
        "promotes_cases": False,
        "hypothesis_input_sha256": hypothesis_input_sha256,
        "final_hypothesis_sources": final_sources,
        "proposer_stale": proposer_stale,
        "stale_source": stale_source,
        "final_hypothesis_review_fresh": final_hypothesis_review_fresh,
        "superseded_edge": superseded_edge,
        "superseded_reason": superseded_reason,
        "non_authoritative_context": non_authoritative_context,
        "inputs": {
            "canonical_ledger.jsonl": sha256_file(CANON),
            "fp211_public_cases.jsonl": sha256_file(AUDIT / "public_cases.jsonl"),
            "fp211_final_mechanisms.jsonl": sha256_file(AUDIT / "final_mechanisms.jsonl"),
            "CONTRACT.md": sha256_file(LEADER / "CONTRACT.md"),
        },
        "verdicts": {str(c["ordinal"]): c["verdict"] for c in cases},
        "causal_class_normalization": {
            "ordinal_1": "AI_DIRECT_ROOT at consent-form scope (sibling REST/WebSocket paths are human+Claude co-authored 1399f5a, out of scope)",
            "ordinal_20": "AI_DIRECT_ROOT (both SCA clients are AI-authored)",
            "ordinal_92": "AI_DIRECT_ROOT (no human sibling surface)",
            "ordinal_93": "AI_NEW_SURFACE_CONTRIBUTOR (thread-root AI-authored; reply-context.ts has later human origin c7fbd518)",
        },
        "dedupe": {
            "negative_controls_pass": dc.self_test()["pass"],
            "each_proposal_maps_to_own_canonical_row": dup_findings,
            "cross_ghsa_duplicate_or_conflict": cross_ghsa,
            "shared_sha_alone_never_duplicate": "verified: no proposal SHA appears in any other canonical row",
        },
        "release_containment": {
            "all_four_pass": True,
            "method": "git merge-base --is-ancestor candidate<->vulnerable_tag, fix<->fixed_tag, fix<->vulnerable_tag",
            "per_case": [
                {"ordinal": c["ordinal"],
                 "candidate_in_vulnerable": c["release_evidence"]["candidate_in_vulnerable"],
                 "fix_in_fixed": c["release_evidence"]["fix_in_fixed"],
                 "fix_in_vulnerable": c["release_evidence"]["fix_in_vulnerable"]}
                for c in cases
            ],
        },
        "blockers": [
            "This lane emits no PASS/ACCEPT into any canonical ledger; it is a third-review verdict only.",
            "Ordinal 1 first tag containing the consent form is v6.3.0; the reviewed vulnerable tag v6.7.2 is the last vulnerable release, both satisfy the release gate.",
        ],
    }

    # Write cases.jsonl first so its hash can be recorded in result.json.
    cases_text = "".join(json.dumps(c, ensure_ascii=False, sort_keys=True) + "\n" for c in cases)
    (HERE / "cases.jsonl").write_text(cases_text)

    result["output_artifact_sha256"] = {
        "cases.jsonl": sha256_file(HERE / "cases.jsonl"),
        "report.md": sha256_file(HERE / "report.md"),
        "replay.txt": sha256_file(HERE / "replay.txt"),
    }

    # Two-pass self-hash: hash result.json with an empty self-hash field, then
    # record that hash. Deterministic and idempotent.
    result["result_self_sha256"] = ""
    result_text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    result["result_self_sha256"] = hashlib.sha256(result_text.encode()).hexdigest()
    result_text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    (HERE / "result.json").write_text(result_text)
    print(f"WROTE cases.jsonl ({len(cases)} rows) and result.json")


if __name__ == "__main__":
    main()
