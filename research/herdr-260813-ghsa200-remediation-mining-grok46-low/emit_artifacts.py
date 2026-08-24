#!/usr/bin/env python3
"""Emit owned-dir artifacts only. Do not edit shared files."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-remediation-mining-grok46-low")

FROZEN = {
    "CONTRACT.md": "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3",
    "leader_baseline.json": "d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132",
    "fp211_canonical_ledger.jsonl": "1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6",
    "fp211_final_mechanisms.jsonl": "0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2",
    "fp211_public_cases.jsonl": "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257",
    "final_candidate_review_cases.jsonl": "e275437954890dca07855b5fcfa545f8f1a366fb85a7ee9f067da5b710b2b3da",
    "final_candidate_review_result.json": "4be2620a548370c845e22c0d7cbe3ed10ab156ef39b1a0432ff4220ff406e528",
    "commitfirst_gn_freeze.json": "a1087603574a83472a916adc6d5d7028e86d0ce8e572f13e2a7fd5fbff9ebc4b",
    "commitfirst_gn_assigned.jsonl": "89cf34362e3f1cc36d91595ddab808eeefc477c0756a924b705d581207149a73",
    "commitfirst_gn_ai_ghsa_intersections.jsonl": "c58444221e9cc00555ba251da75f518281bacd660a438f6cc8a5df3ac5cf331e",
    "publication_adjudications_frozen_in_gn": "bfec060f7705014d11e58dc386294264eac47027cd64d3b934a17422bb1be7a6",
}
CURRENT = {
    "publication_adjudications.json": "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f",
    "netnew22_result.json": "c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829",
    "netnew22_cases.jsonl": "d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889",
    "actual_gogs_cases.jsonl": "3a74a0133dbfd3e128834f9bbc641b78c1515e5647fd07085bba30e2984d827f",
}
b3 = Path(
    "/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh/notes/package-to-source.json"
)
CURRENT["b3_package_to_source.json"] = hashlib.sha256(b3.read_bytes()).hexdigest() if b3.exists() else None

NETRED21 = [
    "GHSA-3RP5-JJMW-4WV2",
    "GHSA-3WXW-XV34-2FRG",
    "GHSA-539M-9XH6-Q6RR",
    "GHSA-5C6W-WWFQ-7QQM",
    "GHSA-8JPQ-5H99-FF5R",
    "GHSA-FMFG-9G7C-3VQ7",
    "GHSA-G39V-CVJH-8FPF",
    "GHSA-J4XF-96QF-RX69",
    "GHSA-JV46-XFWM-36J7",
    "GHSA-MF5G-6R6F-GHHM",
    "GHSA-PF93-J98V-25PV",
    "GHSA-PWF7-47C3-MFHX",
    "GHSA-R48C-V28R-PF6V",
    "GHSA-R9MR-M37C-5FR3",
    "GHSA-RG8M-3943-VM6Q",
    "GHSA-RQP8-Q22P-5J9Q",
    "GHSA-W28W-GP39-M4P6",
    "GHSA-WPXJ-VHFP-HHVM",
    "GHSA-WV46-V6XC-2QHF",
    "GHSA-WXHM-2MQ7-7697",
    "GHSA-XW8C-RRVX-F7XQ",
]
ACTUAL_GOGS = ["GHSA-7GH7-258J-4MPQ", "GHSA-6P9M-Q3JP-47H4", "GHSA-XQJM-27PC-RVWM"]
GATES = [
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
]


def gates(**kwargs: str) -> dict[str, str]:
    base = {k: "FAIL" for k in GATES}
    base.update(kwargs)
    return base


def row(**kw):
    g = kw["gates"]
    kw.setdefault("schema_version", 1)
    kw.setdefault("lane", "herdr-260813-ghsa200-remediation-mining-grok46-low")
    kw.setdefault("contribution_class", "AI_INCOMPLETE_REMEDIATION")
    kw.setdefault("worker_pass_is_proposal_only", True)
    kw.setdefault("causal_admission", False)
    kw.setdefault("countable", False)
    kw.setdefault("publication_status", "HOLD")
    kw.setdefault("carrier_set", [])
    kw.setdefault("aliases", [])
    kw.setdefault("authorship_transfer", False)
    kw.setdefault("routing_is_not_causality", True)
    for k in GATES:
        kw[k] = g[k]
    return kw


def main() -> None:
    OWNED.mkdir(parents=True, exist_ok=True)
    cases = []
    cases.append(
        row(
            case_id="GHSA-6CQF-375W-639G",
            aliases=["CVE-2026-50105"],
            repository="go-gitea/gitea",
            mechanism_key="gitea.web.feed.token-scope.sibling-of-37698",
            scope_statement="Claude-marked 33923a4d adds CheckTokenScopes on raw/media/attachment downloads. GHSA-6cqf names RSS/Atom handlers that never call that helper.",
            candidate_set=["33923a4d7c3c0d25d40373447088d234b4a1387b"],
            minimum_fix_set=["9e84deb969aff5c1115c2984e41250f28c78451f"],
            worker_verdict="REJECT",
            reject_class="OLD_BUG_COPIED_TO_NEW_ROUTE",
            gates=gates(identity_gate="PASS", ai_hunk_gate="PASS", topology_gate="PASS", uniqueness_gate="PASS"),
            ai_marker_evidence="33923a4d trailer Co-authored-by: Claude (Opus 4.7) <noreply@anthropic.com>.",
            counterevidence=[
                "First-party advisory text calls the feeds sibling handlers missed by #37698.",
                "9e84deb96 adds checks in routers/web/feed; it does not amend the AI download helper.",
                "Reverting 33923a4d reopens the download hole; it does not create the feed residual.",
            ],
            first_party_sources=["https://github.com/go-gitea/gitea/security/advisories/GHSA-6cqf-375w-639g"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-gitea__gitea",
            baseline_overlap="absent from 48, netred 21 KEEP, Actual/B3/Gogs",
            replay_commands=[
                "git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-gitea__gitea log -1 --format=%B 33923a4d7c3c0d25d40373447088d234b4a1387b"
            ],
        )
    )
    cases.append(
        row(
            case_id="GHSA-3PWW-VCVM-3GMJ",
            repository="go-gitea/gitea",
            mechanism_key="gitea.web.feed.token-scope.rss-atom",
            scope_statement="Same RSS/Atom token-scope residual as GHSA-6CQF. Duplicate mechanism.",
            candidate_set=["33923a4d7c3c0d25d40373447088d234b4a1387b"],
            minimum_fix_set=["9e84deb969aff5c1115c2984e41250f28c78451f"],
            worker_verdict="REJECT",
            reject_class="DUPLICATE_MECHANISM",
            gates=gates(identity_gate="PASS", ai_hunk_gate="PASS", topology_gate="PASS", uniqueness_gate="FAIL"),
            ai_marker_evidence="Same Claude trailer on 33923a4d.",
            counterevidence=["Uniqueness fails versus GHSA-6CQF. Sibling feeds, not patch-delta."],
            first_party_sources=["https://github.com/go-gitea/gitea/security/advisories/GHSA-3pww-vcvm-3gmj"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-gitea__gitea",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-4X48-CGF9-Q33F",
            repository="novuhq/novu",
            mechanism_key="novu.conditions-filter.webhook.ssrf.sibling-of-validateUrlSsrf",
            scope_statement="AI 87d965eb adds validateUrlSsrf on HTTP-step URLs. GHSA residual is conditions-filter axios.post without that call.",
            candidate_set=["87d965eb88340ac7cd262dd52c8015acd092dc68"],
            minimum_fix_set=["87d965eb88340ac7cd262dd52c8015acd092dc68"],
            worker_verdict="REJECT",
            reject_class="OLD_BUG_COPIED_TO_NEW_ROUTE",
            gates=gates(identity_gate="PASS", ai_hunk_gate="PASS"),
            ai_marker_evidence="Cited SHA is Claude-marked per frozen intersection scan.",
            counterevidence=["Advisory contrasts protected HTTP-step with unprotected conditions webhook. Sibling path."],
            first_party_sources=["https://github.com/novuhq/novu/security/advisories/GHSA-4x48-cgf9-q33f"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/novuhq__novu",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-7F8R-222P-6F5G",
            aliases=["CVE-2025-49596"],
            repository="modelcontextprotocol/inspector",
            mechanism_key="mcp-inspector.proxy.auth.header",
            scope_statement="GHSA merge 50df0e1e is the auth introduction. Claude fdae89ec later switches Authorization to X-MCP-Proxy-Auth.",
            candidate_set=["fdae89ecbfec8fda5d166277ab77398e6d3c06c9"],
            minimum_fix_set=["50df0e1ec488f3983740b4d28d2a968f12eb8979"],
            worker_verdict="REJECT",
            reject_class="REMEDIATION_AFTER_ADVISORY",
            gates=gates(identity_gate="PASS", ai_hunk_gate="PASS", topology_gate="PASS"),
            ai_marker_evidence="fdae89ec Co-Authored-By: Claude <noreply@anthropic.com>.",
            counterevidence=["merge-base --is-ancestor 50df0e1e fdae89ec is success: GHSA fix is ancestor of the AI rem."],
            first_party_sources=["https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/modelcontextprotocol__inspector",
            baseline_overlap="absent",
            replay_commands=[
                "git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/modelcontextprotocol__inspector merge-base --is-ancestor 50df0e1ec488f3983740b4d28d2a968f12eb8979 fdae89ecbfec8fda5d166277ab77398e6d3c06c9"
            ],
        )
    )
    cases.append(
        row(
            case_id="GHSA-6X6H-QQR7-855W",
            aliases=["CVE-2026-61736"],
            repository="HKUDS/LightRAG",
            mechanism_key="lightrag.api.cors.wildcard-credentials",
            scope_statement="Three Claude CORS remediations on 2026-06-24. PyPI 1.5.3 still has original wildcard; 1.5.4 contains the completed helper.",
            candidate_set=["09567a4c983f580050db63569dd477122c058c3d"],
            minimum_fix_set=["ebba6548639c0f2e8919100eff76b401f1222252"],
            worker_verdict="REJECT",
            reject_class="NO_RESIDUAL_IN_RELEASE",
            gates=gates(identity_gate="PASS", ai_hunk_gate="PASS", topology_gate="PASS"),
            ai_marker_evidence="09567a4c / df68d75f / ebba6548 author Claude noreply@anthropic.com.",
            counterevidence=[
                "lightrag_hku-1.5.3.tar.gz sha256 0578d6642103a8692d7e91f58213e4350ce3984e182dd78e71ffd92cc3554117 still defaults CORS_ORIGINS=*.",
                "1.5.4 tarball sha256 48737d21ec545e36d1d495a28b067f28f78136fe5f8b0b31d7f12632244b302c contains the completed CORS helper.",
            ],
            first_party_sources=["https://github.com/HKUDS/LightRAG/security/advisories/GHSA-6x6h-qqr7-855w"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/HKUDS__LightRAG",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-F4VV-55C2-5789",
            repository="HKUDS/LightRAG",
            mechanism_key="lightrag.api.guest-jwt.api-key-bypass",
            scope_statement="Cited f7819aa3 is an AI-marked complete fix of the guest-token bypass.",
            candidate_set=["f7819aa3a49a9d8d92eed8251d82d6ebcafa8cba"],
            minimum_fix_set=["f7819aa3a49a9d8d92eed8251d82d6ebcafa8cba"],
            worker_verdict="REJECT",
            reject_class="REMEDIATION_AS_ORIGIN",
            gates=gates(identity_gate="PASS"),
            ai_marker_evidence="Frozen intersection lists f7819aa3 as AI-marked advisory SHA.",
            counterevidence=["Body reports GHSA-f4vv as the issue being fixed. No later same-helper residual closure isolated."],
            first_party_sources=["https://github.com/HKUDS/LightRAG/security/advisories/GHSA-f4vv-55c2-5789"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/HKUDS__LightRAG",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-2R5C-GW76-RH3W",
            repository="go-gitea/gitea",
            mechanism_key="gitea.hostmatcher.IsPrivate.incomplete-ssrf",
            scope_statement="Default MatchBuiltinExternal uses net.IP.IsPrivate only. No commit_refs and no AI rem isolated.",
            candidate_set=[],
            minimum_fix_set=[],
            worker_verdict="REJECT",
            reject_class="NO_AI_REMEDIATION_HUNK",
            gates=gates(identity_gate="PASS"),
            ai_marker_evidence="",
            counterevidence=["assigned.jsonl commit_refs empty."],
            first_party_sources=["https://github.com/go-gitea/gitea/security/advisories/GHSA-2r5c-gw76-rh3w"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-gitea__gitea",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-25GQ-J9JX-43PG",
            aliases=["CVE-2026-58428"],
            repository="go-gitea/gitea",
            mechanism_key="gitea.release.attachment-edit.allowlist-bypass",
            scope_statement="Web EditReleasePost rename skips upload.Verify. Variant of CVE-2025-68939 on a sibling form path.",
            candidate_set=[],
            minimum_fix_set=["de4b8277e9cb576f2315fb03b5ab6478b42a1d31"],
            worker_verdict="REJECT",
            reject_class="OLD_BUG_COPIED_TO_NEW_ROUTE",
            gates=gates(identity_gate="PASS"),
            ai_marker_evidence="",
            counterevidence=["No AI rem of Verify isolated on the edit form."],
            first_party_sources=["https://github.com/go-gitea/gitea/security/advisories/GHSA-25gq-j9jx-43pg"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-gitea__gitea",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    rem_origin = [
        (
            "GHSA-9X9P-QF8F-MVJG",
            "harttle/liquidjs",
            "dbbf6288030591bf6da28d8c1cce5a17bca97bb6",
            "fix: propagate ownPropertyOnly into Context.spawn()",
            "harttle__liquidjs",
        ),
        (
            "GHSA-8XX9-69P8-7JP3",
            "harttle/liquidjs",
            "5b9c3469085e01c79e2d0af28e2a13f730e1793d",
            "fix: enforce renderLimit for empty renderTemplates calls",
            "harttle__liquidjs",
        ),
        (
            "GHSA-2QV6-9WX5-CWV4",
            "harttle/liquidjs",
            "26ea2856c7a90aec892b98d94a9b7a3e18539045",
            "fix: strip html newline tags",
            "harttle__liquidjs",
        ),
        (
            "GHSA-8MC6-XJPR-H98X",
            "lin-snow/Ech0",
            "091d26d2d942df6df9f520328d2f9cf2592bbefc",
            "fix(connect): block SSRF",
            "lin-snow__Ech0",
        ),
        (
            "GHSA-3V85-FQVH-7RXF",
            "lin-snow/Ech0",
            "fd320fe3e9021c8d8d284fb274775c018690520e",
            "fix(rss): block stored XSS",
            "lin-snow__Ech0",
        ),
        (
            "GHSA-89VP-X53W-74FX",
            "modelcontextprotocol/rust-sdk",
            "8e22aa2de28df5a285eed87c11cd89bf15fa90d3",
            "fix(http): add host check",
            "modelcontextprotocol__rust-sdk",
        ),
        (
            "GHSA-8QVF-MR4W-9X2C",
            "mesop-dev/mesop",
            "c6b382f363b73ac32c402a2db3aadc7784f66a5b",
            "Add path traversal protection to FileStateSessionBackend",
            "mesop-dev__mesop",
        ),
        (
            "GHSA-3JR7-6HQP-X679",
            "mesop-dev/mesop",
            "760a2079b5c609038c826d24dfbcf9b0be98d987",
            "fix: bound concurrent WebSocket threads",
            "mesop-dev__mesop",
        ),
        (
            "GHSA-64CJ-QVX5-M4F3",
            "nhost/nhost",
            "e407511627d2c2c1137a70e9ca1ca31095d23479",
            "harden local configserver",
            "nhost__nhost",
        ),
        (
            "GHSA-6G38-8J4P-J3PR",
            "nhost/nhost",
            "ec8dab3f2cf46e1131ddaf893d56c37aa00380b2",
            "fix(auth): strict use of email verified",
            "nhost__nhost",
        ),
        (
            "GHSA-2C6V-8R3V-GH6P",
            "gogs/gogs",
            "7b7e38c88007a7c482dbf31efff896185fd9b79c",
            "security: prevent deletion of protected branches",
            "gogs__gogs",
        ),
        (
            "GHSA-CJ4V-437J-JQ4C",
            "gogs/gogs",
            "81ee8836445ac888d99da8b652be7d5cbc5c4d5c",
            "lfs: verify content hash and prevent object overwrite",
            "gogs__gogs",
        ),
    ]
    for cid, repo, sha, subj, clone in rem_origin:
        uniq = "FAIL" if cid == "GHSA-CJ4V-437J-JQ4C" else "PASS"
        extra = (
            ["Overwrite-without-hash is the sibling of KEEP proposal GHSA-6P9M. Not counted."]
            if cid == "GHSA-CJ4V-437J-JQ4C"
            else []
        )
        cases.append(
            row(
                case_id=cid,
                repository=repo,
                mechanism_key=cid.lower() + ".cited-ai-fix",
                scope_statement="Advisory-cited SHA is an AI-marked security rem treated as the closure, not an earlier incomplete boundary with a later residual fix.",
                candidate_set=[sha],
                minimum_fix_set=[sha],
                worker_verdict="REJECT",
                reject_class="REMEDIATION_AS_ORIGIN",
                gates=gates(identity_gate="PASS", uniqueness_gate=uniq),
                ai_marker_evidence=subj,
                counterevidence=["AI-marked cited fix is rem-as-origin."] + extra,
                first_party_sources=[f"https://github.com/advisories/{cid.lower()}"],
                clone=f"/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/{clone}",
                baseline_overlap="Gogs-adjacent overwrite sibling of GHSA-6P9M"
                if cid == "GHSA-CJ4V-437J-JQ4C"
                else "absent",
                replay_commands=[],
            )
        )
    cases.append(
        row(
            case_id="GHSA-RV5G-F82M-QRVV",
            aliases=["CVE-2026-39412"],
            repository="harttle/liquidjs",
            mechanism_key="liquidjs.sort_natural.ownPropertyOnly",
            scope_statement="Cited e743da00 Made-with Cursor closes sort_natural. Distinct from GHSA-9X9P spawn helper.",
            candidate_set=["e743da0020d34e2ee547e1cc1a86b58377ebe1ce"],
            minimum_fix_set=["e743da0020d34e2ee547e1cc1a86b58377ebe1ce"],
            worker_verdict="REJECT",
            reject_class="REMEDIATION_AS_ORIGIN",
            gates=gates(identity_gate="PASS", uniqueness_gate="PASS"),
            ai_marker_evidence="Made-with: Cursor on e743da00.",
            counterevidence=["sort_natural is a sibling of Context.spawn ownPropertyOnly."],
            first_party_sources=["https://github.com/harttle/liquidjs/security/advisories/GHSA-rv5g-f82m-qrvv"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/harttle__liquidjs",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-CVQ5-HHX3-F99P",
            repository="kyverno/kyverno",
            mechanism_key="kyverno.configmap.cross-namespace.read",
            scope_statement="Cited bbf3e5c0 Copilot trailer is on a unit-test edit.",
            candidate_set=["bbf3e5c01391d612968440659028ae98e565a777"],
            minimum_fix_set=["bbf3e5c01391d612968440659028ae98e565a777"],
            worker_verdict="REJECT",
            reject_class="COPILOT_ON_TEST_ONLY",
            gates=gates(identity_gate="PASS"),
            ai_marker_evidence="Copilot on test-only hunk.",
            counterevidence=["Incomplete-fix language versus CVE-2026-22039 is not an AI-authored residual helper."],
            first_party_sources=["https://github.com/kyverno/kyverno/security/advisories/GHSA-cvq5-hhx3-f99p"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kyverno__kyverno",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-Q9P7-WQXG-MRHC",
            aliases=["CVE-2026-54769"],
            repository="langroid/langroid",
            mechanism_key="langroid.tablechat.eval.incomplete-sanitizer",
            scope_statement="0d9e4a7b is Copilot-marked follow-up of a human sanitizer.",
            candidate_set=["0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6"],
            minimum_fix_set=[],
            worker_verdict="REJECT",
            reject_class="COPILOT_ON_NON_MECHANISM_HUNK",
            gates=gates(identity_gate="PASS"),
            ai_marker_evidence="Copilot on non-sanitizer hunk.",
            counterevidence=["Advisory has empty commit_refs in assigned.jsonl."],
            first_party_sources=["https://github.com/langroid/langroid/security/advisories/GHSA-q9p7-wqxg-mrhc"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/langroid__langroid",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-892R-P3JQ-JP24",
            repository="MervinPraison/PraisonAI",
            mechanism_key="praisonai.agentos.unauthenticated-after-incomplete-fix",
            scope_statement="Advisory asserts incomplete authentication fix. No AI-marked guard plus later same-boundary closure.",
            candidate_set=[],
            minimum_fix_set=[],
            worker_verdict="REJECT",
            reject_class="NO_AI_REMEDIATION_HUNK",
            gates=gates(identity_gate="PASS"),
            ai_marker_evidence="",
            counterevidence=["Incomplete language without AI hunk."],
            first_party_sources=["https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-892r-p3jq-jp24"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/MervinPraison__PraisonAI",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-9QHQ-V63V-FV3J",
            aliases=["CVE-2026-41497", "CVE-2026-34935"],
            repository="MervinPraison/PraisonAI",
            mechanism_key="praisonai.os-command-injection.unmarked-allowlist",
            scope_statement="Cited 47bff654 adds an allowlist with no AI trailer.",
            candidate_set=["47bff65413beaa3c21bf633c1fae4e684348368c"],
            minimum_fix_set=["47bff65413beaa3c21bf633c1fae4e684348368c"],
            worker_verdict="REJECT",
            reject_class="UNMARKED_INCOMPLETE_FIX",
            gates=gates(identity_gate="PASS"),
            ai_marker_evidence="",
            counterevidence=["Incomplete fix of CVE-2026-34935 is unmarked."],
            first_party_sources=["https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-9qhq-v63v-fv3j"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/MervinPraison__PraisonAI",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-6QVR-WJMV-V8MM",
            repository="koel/koel",
            mechanism_key="koel.safehttp.ssrf.remaining-dns-rebind",
            scope_statement="Cited 5f6ce2ce / c264a3d5 close remaining SSRF after v9.7.0. Neither has an AI trailer.",
            candidate_set=[],
            minimum_fix_set=[
                "5f6ce2cefd08f437a269236b677ad971517ccbb6",
                "c264a3d52513a83b21e1cc3a20e895caea97fc4a",
            ],
            worker_verdict="REJECT",
            reject_class="UNMARKED_INCOMPLETE_FIX",
            gates=gates(identity_gate="PASS"),
            ai_marker_evidence="",
            counterevidence=["Cited closures unmarked."],
            first_party_sources=["https://github.com/koel/koel/security/advisories/GHSA-6qvr-wjmv-v8mm"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/koel__koel",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-84R2-JW7C-4R5Q",
            repository="mmaitre314/picklescan",
            mechanism_key="picklescan.disallowed-inputs.incomplete-list",
            scope_statement="Cited 70c1c6c3 batches several GHSA closures. No AI trailer.",
            candidate_set=["70c1c6c31beb6baaf52c8db1b6c3c0e84a6f9dab"],
            minimum_fix_set=["70c1c6c31beb6baaf52c8db1b6c3c0e84a6f9dab"],
            worker_verdict="REJECT",
            reject_class="UNMARKED_INCOMPLETE_FIX",
            gates=gates(identity_gate="PASS"),
            ai_marker_evidence="",
            counterevidence=["Author Matthieu Maitre."],
            first_party_sources=["https://github.com/mmaitre314/picklescan/security/advisories/GHSA-84r2-jw7c-4r5q"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mmaitre314__picklescan",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-8GC5-J5RX-235R",
            repository="NaturalIntelligence/fast-xml-parser",
            mechanism_key="fxp.entity-expansion.incomplete-limits",
            scope_statement="Cited bd26122c extends entity expansion checks. No AI marker on that SHA.",
            candidate_set=["bd26122c838e6a55e7d7ac49b4ccc01a49999a01"],
            minimum_fix_set=["bd26122c838e6a55e7d7ac49b4ccc01a49999a01"],
            worker_verdict="REJECT",
            reject_class="UNMARKED_INCOMPLETE_FIX",
            gates=gates(identity_gate="PASS"),
            ai_marker_evidence="",
            counterevidence=["Incomplete fix of CVE-2026-26278 is unmarked."],
            first_party_sources=["https://github.com/NaturalIntelligence/fast-xml-parser/security/advisories/GHSA-8gc5-j5rx-235r"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/NaturalIntelligence__fast-xml-parser",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-GHCM-XQFW-Q4VR",
            repository="mermaid-js/mermaid",
            mechanism_key="mermaid.statediagram.classDef.html-injection",
            scope_statement="Earlier AI HTML-escape of tooltip titles is a different sanitizer than classDef.",
            candidate_set=[],
            minimum_fix_set=[],
            worker_verdict="REJECT",
            reject_class="OLD_BUG_COPIED_TO_NEW_ROUTE",
            gates=gates(identity_gate="PASS"),
            ai_marker_evidence="Subject-overlap routing hit 6670ad72 tooltip HTML escape.",
            counterevidence=["classDef injection is an untouched sibling of tooltip escaping."],
            first_party_sources=["https://github.com/mermaid-js/mermaid/security/advisories/GHSA-ghcm-xqfw-q4vr"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mermaid-js__mermaid",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    cases.append(
        row(
            case_id="GHSA-XCJ9-5M2H-648R",
            repository="mermaid-js/mermaid",
            mechanism_key="mermaid.classDefs.css-injection",
            scope_statement="Sibling CSS injection versus GHSA-GHCM HTML injection.",
            candidate_set=[],
            minimum_fix_set=[],
            worker_verdict="REJECT",
            reject_class="OLD_BUG_COPIED_TO_NEW_ROUTE",
            gates=gates(identity_gate="PASS", uniqueness_gate="PASS"),
            ai_marker_evidence="",
            counterevidence=["Not a patch-delta of an AI classDef helper."],
            first_party_sources=["https://github.com/mermaid-js/mermaid/security/advisories/GHSA-xcj9-5m2h-648r"],
            clone="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mermaid-js__mermaid",
            baseline_overlap="absent",
            replay_commands=[],
        )
    )
    if len(cases) != 30:
        raise SystemExit(f"expected 30 cases, got {len(cases)}")
    ids = [c["case_id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate ids")
    banned = set(NETRED21) | set(ACTUAL_GOGS)
    if set(ids) & banned:
        raise SystemExit(sorted(set(ids) & banned))

    (OWNED / "cases.jsonl").write_text("".join(json.dumps(c, sort_keys=True) + "\n" for c in cases), encoding="utf-8")
    report = f"""# Remediation-mining GHSA discovery (grok46-low)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `{FROZEN['CONTRACT.md']}`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc` via commitfirst-gn freeze. Shared tracked files were not edited. No commit, push, or credential output.

## Provenance (frozen vs current, separate roles)

Frozen selection and exclusion inputs were not re-derived from live publication files.

- Frozen: contract, 48-case baseline, fp211 ledger/mechanisms/public_cases, final-review packet, commitfirst-gn assignment/intersections. See result.json frozen_input_hashes.
- Current overlap check only: live scripts/publication_adjudications.json, netred 21 KEEP cases, Actual/Gogs cases.jsonl, B3 notes/package-to-source.json. These hashes do not rebuild the frozen denominator.

Excluded identities: frozen 48 baseline; netred 21 KEEP; Actual/Gogs GHSA-7GH7-258J-4MPQ, GHSA-6P9M-Q3JP-47H4, GHSA-XQJM-27PC-RVWM; B3 KEEP set empty on disk.

## Pattern

High-precision incomplete remediation: an AI-marked commit explicitly attempts a security rem; a later first-party GHSA/fix closes a residual bypass in that same helper; a vulnerable release contains the AI candidate and a fixed release contains the closure. Count by GHSA identity once. Routing is not causality.

## Verdict

Thirty identities were deeply reviewed. Zero closed all seven gates.

Closest misses:

- GHSA-6CQF-375W-639G / GHSA-3PWW-VCVM-3GMJ: Claude 33923a4d (#37698) remediates download token scope. The GHSA residual is RSS/Atom sibling handlers. Advisory text says sibling. but_for_gate FAIL.
- GHSA-6X6H-QQR7-855W: Claude CORS rem chain exists, but PyPI 1.5.3 still has the parent wildcard; 1.5.4 ships the completed helper. No released residual of the AI rem.
- GHSA-7F8R-222P-6F5G: Claude header rem is after the GHSA merge.
- Exact SHA intersections in frozen G-N scans are almost all AI-marked closures (remediation-as-origin).

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| REJECT | 30 |

High-confidence incomplete-language plus exact-ref rem queue for this pattern is exhausted at 30. Remaining first-party GHSAs are UNREVIEWED, not REJECT.

## Claim boundary

Countable PASS requires all seven gates and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a >200 claim.
"""
    (OWNED / "report.md").write_text(report, encoding="utf-8")
    replay = """#!/usr/bin/env zsh
set -euo pipefail
cd /home/hanqing/agents/ai-slop

hash_file() {
  sha256sum -- "$1" | awk '{print $1}'
}

[[ "$(hash_file autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md)" == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-ghsa200-leader/baseline.json)" == "d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl)" == "1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl)" == "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-commitfirst-gn/assigned.jsonl)" == "89cf34362e3f1cc36d91595ddab808eeefc477c0756a924b705d581207149a73" ]]

[[ "$(hash_file scripts/publication_adjudications.json)" == "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/cases.jsonl)" == "d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high/cases.jsonl)" == "3a74a0133dbfd3e128834f9bbc641b78c1515e5647fd07085bba30e2984d827f" ]]

INS=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/modelcontextprotocol__inspector
GITEA=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-gitea__gitea

git --no-optional-locks -c gc.auto=0 -C "$INS" merge-base --is-ancestor 50df0e1ec488f3983740b4d28d2a968f12eb8979 fdae89ecbfec8fda5d166277ab77398e6d3c06c9

body="$(git --no-optional-locks -c gc.auto=0 -C "$GITEA" log -1 --format=%B 33923a4d7c3c0d25d40373447088d234b4a1387b)"
[[ "$body" == *"Co-authored-by: Claude (Opus 4.7)"* ]]

python3 - <<'PY'
import json
from pathlib import Path
p=Path("autoresearch/herdr-260813-ghsa200-remediation-mining-grok46-low/cases.jsonl")
rows=[json.loads(l) for l in p.read_text().splitlines() if l.strip()]
assert len(rows)==30
assert all(r.get("worker_verdict")=="REJECT" for r in rows)
assert all(r.get("countable") is False for r in rows)
ids=[r["case_id"] for r in rows]
assert len(ids)==len(set(ids))
banned={"GHSA-7GH7-258J-4MPQ","GHSA-6P9M-Q3JP-47H4","GHSA-XQJM-27PC-RVWM"}
assert not (set(ids)&banned)
r=json.loads(Path("autoresearch/herdr-260813-ghsa200-remediation-mining-grok46-low/result.json").read_text())
assert r["counts"]["PASS"]==0
assert r["publication_status"]=="HOLD"
assert r["more_than_200_claim"] is False
PY
"""
    (OWNED / "replay.sh").write_text(replay, encoding="utf-8")
    (OWNED / "replay.sh").chmod(0o755)

    result = {
        "schema_version": 1,
        "lane": "herdr-260813-ghsa200-remediation-mining-grok46-low",
        "status": "TERMINAL",
        "language": "en",
        "english_only": True,
        "causal_admission": False,
        "publication_status": "HOLD",
        "worker_pass_is_proposal_only": True,
        "more_than_200_claim": False,
        "did_not_commit_or_push": True,
        "did_not_edit_tracked_or_canonical": True,
        "owned_directory": "autoresearch/herdr-260813-ghsa200-remediation-mining-grok46-low",
        "counting_unit": "first-party GHSA identity",
        "pattern": "AI_INCOMPLETE_REMEDIATION_PATCH_DELTA",
        "deep_reviewed": 30,
        "queue_exhausted": True,
        "counts": {
            "PASS": 0,
            "NARROW": 0,
            "UNKNOWN": 0,
            "BLOCKED": 0,
            "REJECT": 30,
            "countable_pass": 0,
            "proposed_acceptances": 0,
        },
        "excluded_sets": {
            "netred_21_KEEP": NETRED21,
            "actual_gogs_proposals": ACTUAL_GOGS,
            "b3_KEEP": [],
        },
        "frozen_input_hashes": FROZEN,
        "current_input_hashes": CURRENT,
        "hash_roles": {
            "frozen": "contract, 48 baseline, fp211, final-review, commitfirst-gn assignment",
            "current": "live publication overlap, netred KEEP, Actual/Gogs cases, B3 notes",
        },
        "advisory_database_head": "a42c436870111aa3f221257c9d56126a93173ccc",
        "clone_root": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones",
        "claim_boundary": {
            "worker_PASS": "proposal only; none proposed",
            "publication": "HOLD",
            "canonical_ledger_edited": False,
        },
        "blockers": [
            "0 PASS after 30 seven-gate reviews of the high-precision incomplete-remediation queue.",
            "Closest Gitea #37698 residual is an explicit sibling-path feed bypass.",
            "LightRAG CORS AI rem never shipped in 1.5.3.",
            "Exact-ref AI SHAs are typically the cited closure (remediation-as-origin).",
        ],
        "reviewed_ids": ids,
    }
    (OWNED / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    result["artifact_hashes"] = {
        "cases.jsonl": digest(OWNED / "cases.jsonl"),
        "report.md": digest(OWNED / "report.md"),
        "replay.sh": digest(OWNED / "replay.sh"),
        "emit_artifacts.py": digest(OWNED / "emit_artifacts.py"),
    }
    (OWNED / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
