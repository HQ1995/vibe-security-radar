# CF4 B0 incomplete-remediation predecessor lane

Verdict first: **0 PASS_PROPOSAL**. Frozen **2**. Reviewed **1**. Unreviewed **1**. Equation **2=1+1**. Shortfall **10** versus freeze cap 12. Did not pad. Canonical strict count stays **88 HOLD**. Worker PASS is proposal only; this packet emits none.

## Method

Different from CF4-b0-direct proximity and CF4-b0-history deleted-line overlap. Remaining bucket-0 rows were filtered to published 2025-2026 with a repository advisory URL or exact fix commit, a local clone, and a real fix object, then ranked github-reviewed first, then uppercase GHSA ID. Inspected the full ranked set of **317** (cap 600). Stop rule: inspected_ranked_real_objects_317_shortfall_10. Those inspect anchors and the exclusion ID list are frozen inside this packet; replay hashes that snapshot and does not re-scan other workers.

For each official closer, collect fix-touched production source files and walk up to 250 first-parent commits. Keep only atomic (n_parents=1) production source_matcher v3 commits whose subject, body, or diff explicitly attempts security hardening, authorization, validation, sanitization, escaping, path checks, SSRF restrictions, command safety, or fail-closed behavior in the same function or invariant. Exact fixed-line overlap is not required. AI-on-fix is not origin. Generic refactors, unrelated same-file security work, and safer-but-incomplete reductions of an older broad flaw were not frozen.

## Sources

- github-reviewed: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`
- unreviewed subtree only: `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226`
- Union by uppercase GHSA ID; f2c6 reviewed wins on 135 collisions.
- CONTRACT `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- canonical88 ledger `35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074`
- Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`

## Universe and conservation

Bucket = integer sha256(uppercase GHSA) modulo 6 equals 0. Replay does not scan the live autoresearch tree. Exclusion and inspect anchors are an immutable packet snapshot in result.json frozen_input (manifest cf4-b0-predecessor-frozen-input-v1, sha256 5c44164659b06086e813b7559a24a0c7d4c10d3fceac8f7998dd5fdf11bd96ed): sorted uppercase excluded GHSA IDs plus inspect 317 / GHSA-23W4-RPC6-WPCC / GHSA-XX7C-F2FQ-QMV3 / assigned IDs. Snapshot-derived eligible after exclude is 57202 (4208 reviewed + 52994 unreviewed). Later worker artifacts cannot change that hash.

| layer | n |
| --- | --- |
| reviewed files f2c6 | 34389 |
| unreviewed files 39d888 | 317316 |
| union bucket0 active | 58514 |
| eligible after exclude | 57202 (4208 reviewed + 52994 unreviewed) |
| 2025-2026 adv-or-fix with clone | 433 |
| ranked with real fix object | 317 |
| inspect cap | 600 |
| inspected prefix | 317 (first GHSA-23W4-RPC6-WPCC last GHSA-XX7C-F2FQ-QMV3) |
| skip slow liferay-class clones | 12 |
| no source files | 38 |
| actual AI security predecessors frozen | 2 |
| shortfall versus 12 | 10 |

Assigned 2 = reviewed 1 + unreviewed 1. Never padded.

Not frozen (counterexamples): GHSA-3C9R-7F29-QP32 Claude rctx rename; GHSA-3GRX-CG6P-5WC6 Claude SSRF fetch guard versus requireMention reaction bypass; GHSA-8VGJ-C3FX-PPRX trusted-proxy pairing skip versus silent reconnect scope-upgrade; GHSA-MFXW-Q267-MGP6 Claude showmode patch is not a security attempt.

## Frozen two

1. GHSA-R5M9-WM49-959F REJECT. github-reviewed mlflow. Claude `e151258a` (#19823) adds gateway CRUD permission handlers in `mlflow/server/auth/__init__.py` and imports ListGateway* without BEFORE_REQUEST_HANDLERS entries. That is the GHSA residual. Listed closer `6989066a` (#20964) filters SearchModelVersions. After that closer, ListGatewaySecretInfos, ListGatewayEndpoints, and ListGatewayModelDefinitions are still absent from BEFORE_REQUEST_HANDLERS. AI is in v3.9.0; closer is in v3.11.0rc0 not v3.10.1. Official minimum fix does not close the named residual. identity/ai_hunk/topology/release/uniqueness PASS; but_for and fix_reversal FAIL.

2. GHSA-7F25-VHJ7-MXRC REJECT. unreviewed openclaw. Claude `60661441` (#1624) exposes config.patch to agents as safe partial updates on `src/agents/tools/gateway-tool.ts`. Residual is disabling exec approval through that action. Human closer `76411b2a` (#55682) blocks tools.exec.ask and tools.exec.security. AI is in v2026.3.22; closer is in v2026.3.28 not v2026.3.22. identity FAIL because the advisory is unreviewed with empty affected[]. Other gates hold as local git facts only. Not a countable proposal.

## Claim boundary

Proposal count **0**. Canonical 88 untouched. No commit, push, tracked edits, durable clones, pages, or helper scripts. Caches read-only. Prefer zero PASS over one false positive.
