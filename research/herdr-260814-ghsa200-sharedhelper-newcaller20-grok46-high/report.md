# Shared-helper new-caller20 terminal report

Verdict first: **0 PASS**. Frozen selected count is **10**. Claim-grade review is **3 REJECT, 6 UNKNOWN, 1 BLOCKED**. Selector routing is not claim-grade. Misses are mining **NOT_SELECTED**, not causal REJECT. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Worker PASS is a proposal only; this packet emits none.

## Selector routing versus claim-grade

Advisory-database rows are **routing only**. A same-repo security-advisory URL in that global object is not a verified first-party closure of title, details, affected range, or fix. Population claim: `advisory_database_routing_with_same_repo_commit_refs`. Source tier: `advisory_database_routing`. Exact-first-party-fix claim: **false**. 4591 is not a count of verified first-party closures.

Claim-grade bind for the frozen 10 is the GitHub **repository security advisory** API object for that same GHSA (`source_tier=github_repo_security_advisory`). Gates and counterevidence are reassessed from that object. If the object is internally inconsistent or does not name a closable same-repo fix SHA, the row is UNKNOWN or BLOCKED, not REJECT.

## Conservation (selector routing)

GitHub-reviewed 2025-2026: **12817**.
Advisory-database routing after exclusion in window: **8659**.
Advisory-database same-repo commit refs scanned: **4591**.
Excluded identities: **97** (canonical84 strict 84 plus contributor-butfor11 and route/dependency surface identities).
Hard hits (routing heuristic): **10**.
Misses: **4581**.
Frozen: **10** (cap 20, no padding, no backfill).
Unreviewed hits: **0**.
Equations: 4591=10+4581; 10=10+0.
Did not pad. Did not backfill after review.

Miss skip_counts: no_exact_helper_symbol 3221, no_ai_caller_or_released_ancestry 341, diff_failed 305, non_atomic_fix 293, missing_sha 207, no_clone 191, diff_too_large 23.

## Freeze order

Stable GHSA ID ascending. Exact frozen IDs unchanged:

1. GHSA-33HM-CQ8R-WC49
2. GHSA-47Q7-97XP-M272
3. GHSA-4HG8-92X6-H2F3
4. GHSA-CHM3-VQCF-52RX
5. GHSA-CPF4-PMR4-W6CX
6. GHSA-F3RG-XQJJ-CJ9W
7. GHSA-FR6G-7CQ8-FG82
8. GHSA-G353-MGV3-8PCJ
9. GHSA-HV93-R4J3-Q65F
10. GHSA-JMM5-FVH5-GF4P

## Claim-grade review

Repo advisory fetched unauthenticated for all ten. Raw pages are not in the packet; compact English extracts with URL/hash/provenance live in `notes/facts/`.

| ID | Status | Why |
| --- | --- | --- |
| GHSA-33HM-CQ8R-WC49 | REJECT | Repo advisory is sandbox tmp-path; named SHA includes d3da67c7; frozen caller is Chrome extension / test helper |
| GHSA-47Q7-97XP-M272 | BLOCKED | Negative control: summary is config secrets; details/fix 113ebfd6 are hook-token timing; patched 2.13 vs 2.12 |
| GHSA-4HG8-92X6-H2F3 | REJECT | Repo advisory is Telnyx webhook; named SHA 29b587e; frozen caller is config.test.ts; parent already had production webhook |
| GHSA-CHM3-VQCF-52RX | UNKNOWN | Repo advisory names credential IDOR and 3.1.3; no fix SHA; do not reuse routing SHA d81483b |
| GHSA-CPF4-PMR4-W6CX | UNKNOWN | Repo advisory names org v2beta IDOR and 4.6.3; no fix SHA |
| GHSA-F3RG-XQJJ-CJ9W | UNKNOWN | Repo advisory names WorkflowSanitizer and 2.51.3; no fix SHA |
| GHSA-FR6G-7CQ8-FG82 | UNKNOWN | Repo advisory names upsert-history and 3.1.3; no fix SHA; do not union with CHM3 |
| GHSA-G353-MGV3-8PCJ | UNKNOWN | Repo advisory names Feishu webhook and 2026.3.12; no fix SHA |
| GHSA-HV93-R4J3-Q65F | UNKNOWN | Repo advisory names 3421b2ec; selector routed 113ebfd6; do not swap closers |
| GHSA-JMM5-FVH5-GF4P | REJECT | Repo advisory is hook-token timing; named SHA 113ebfd6; parent already compared; AI added sibling /v1/responses |

REJECT rows rest on positive first-party counterevidence after a closed repo-advisory pairing. UNKNOWN/BLOCKED rows are not causal REJECT. A missing advisory keyword by itself is not a reject.

GHSA-47Q7 is recorded as a **negative control**: advisory-database and the repo advisory both mix a config-secrets summary with hook-timing details; 113ebfd6 is not treated as a config-secrets closer.

Canonical84 overlap: none.

## Claim boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim. Worker PASS is proposal only. Independent hostile red-team plus leader acceptance would still be required before any count change.
