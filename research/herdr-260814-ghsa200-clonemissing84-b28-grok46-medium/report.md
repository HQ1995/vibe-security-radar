# Clonemissing84 batch 28: 0 PASS proposals

Verdict first: **0 PASS**. Worker PASS is a proposal only and this packet emits none. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. packet_delta=0. Publication and more-than-200 remain **HOLD**.

## Conservation

Frozen source skip `clone_missing`: **85** unique identities in original-hits order.
Preexcluded: **GHSA-Q2M9-6JP9-C6MC** (just reviewed in promisor389-residual11).
Post-uniqueness: **84**. Equation: **85=1+84**.
This slice is post-uniqueness positions **29 through 56** (1-based), exact assigned order, **28** rows.
Leftover outside this slice: **56**. Packet equation: **84=28+56**.
Packet outcomes: **28=18 UNKNOWN + 6 NOT_SELECTED + 2 BLOCKED + 2 REJECT_CANDIDATE_EDGE**.
PASS=0. Whole-case causal REJECT=0. Did not pad, backfill, replace, or silent-drop.
This is recovery of frozen clone_missing rows, not a re-run of already scanned rows.

## Method

Inputs are `original-hits.jsonl` and `candidate-pool.jsonl` from `herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh`. github/advisory-database at `a42c436870111aa3f221257c9d56126a93173ccc` and OSV HTML are routing only. Claim-grade identity is the same-GHSA repository security advisory HTML. Official product git was fetched without credentials into `/home/hanqing/.cache/ai-slop-ghsa200/herdr-260814-ghsa200-clonemissing84-b28-grok46-medium`. No GitHub API. No `/tmp` clones. No clones inside the repository. A squash subject `(#N)` is not atomic hunk authorship. Temporary clones are deleted before handoff. Replay does not re-clone.

## Assignment outcomes

| n | ID | Host | Verdict | Reason |
| --- | --- | --- | --- | --- |
| 1 | GHSA-3R68-X3XC-RXPG | bx33661/Wireshark-MCP | UNKNOWN | missing_claim_grade_fix_sha |
| 2 | GHSA-3R75-XC34-5F44 | apify/crawlee-python | NOT_SELECTED | recovered_fix_deleted_hunks_not_atomic_ai |
| 3 | GHSA-423P-G724-FR39 | cloudnative-pg/cloudnative-pg | NOT_SELECTED | recovered_fix_deleted_hunks_not_atomic_ai |
| 4 | GHSA-4C35-WCG5-MM9H | amannn/next-intl | UNKNOWN | missing_claim_grade_fix_sha |
| 5 | GHSA-64VR-4GR2-M642 | automagik-dev/genie | BLOCKED | repo_advisory_unavailable |
| 6 | GHSA-7XGW-6QF3-7W59 | dbt-labs/dbt-mcp | UNKNOWN | missing_claim_grade_fix_sha |
| 7 | GHSA-88Q9-CMP2-C2VQ | bzsanti/oxidizePdf | REJECT_CANDIDATE_EDGE | ai_blame_is_restructure_copy_or_clippy_not_introducing_hunk |
| 8 | GHSA-CFCJ-HQPF-HCCF | EvoMap/evolver | UNKNOWN | missing_claim_grade_fix_sha |
| 9 | GHSA-F77V-9VPC-6PJM | electerm/electerm | UNKNOWN | missing_claim_grade_fix_sha |
| 10 | GHSA-G6WW-W5J2-R7X3 | boxlite-ai/boxlite | NOT_SELECTED | recovered_fix_deleted_hunks_not_atomic_ai |
| 11 | GHSA-GC8W-X73W-P4RH | ArtMin96/yii2-mcp-server | BLOCKED | repo_advisory_unavailable |
| 12 | GHSA-JJ54-R8GM-2FCF | dbt-labs/dbt-mcp | UNKNOWN | missing_claim_grade_fix_sha |
| 13 | GHSA-JWP7-WG77-3W9V | apify/apify-mcp-server | UNKNOWN | missing_claim_grade_fix_sha |
| 14 | GHSA-JXH8-JH77-XH6G | EvoMap/evolver | UNKNOWN | missing_claim_grade_fix_sha |
| 15 | GHSA-PWQG-Q8PG-PP6R | daptin/daptin | UNKNOWN | missing_claim_grade_fix_sha |
| 16 | GHSA-QHH4-458H-XWH2 | cdxgen/cdxgen | NOT_SELECTED | recovered_fix_deleted_hunks_not_atomic_ai |
| 17 | GHSA-V228-72C7-FX8J | Aas-ee/open-webSearch | UNKNOWN | missing_claim_grade_fix_sha |
| 18 | GHSA-V5MH-H5HX-7V92 | cloudnativelabs/kube-router | UNKNOWN | missing_claim_grade_fix_sha |
| 19 | GHSA-VRXG-GM77-7Q5G | CursorTouch/Windows-MCP | UNKNOWN | missing_claim_grade_fix_sha |
| 20 | GHSA-XPWW-F6PM-CFHQ | dbt-labs/dbt-mcp | UNKNOWN | missing_claim_grade_fix_sha |
| 21 | GHSA-3PVJ-JV98-QHJQ | ChromeDevTools/chrome-devtools-mcp | UNKNOWN | missing_claim_grade_fix_sha |
| 22 | GHSA-6GQW-JQV7-V88M | eidetic-labs/stigmem | NOT_SELECTED | recovered_fix_deleted_hunks_not_atomic_ai |
| 23 | GHSA-7QJX-GP9H-65QJ | dexidp/dex | NOT_SELECTED | recovered_fix_deleted_hunks_not_atomic_ai |
| 24 | GHSA-FQ4X-789W-JG5H | agenticmail/agenticmail | REJECT_CANDIDATE_EDGE | named_sha_is_hooks_upsert_not_inbound_mail_bypasspermissions |
| 25 | GHSA-HJWC-26PJ-V3PM | agenticmail/agenticmail | UNKNOWN | missing_claim_grade_fix_sha |
| 26 | GHSA-JR33-MW75-7J8F | dbt-labs/dbt-mcp | UNKNOWN | missing_claim_grade_fix_sha |
| 27 | GHSA-M6VC-F87M-CC2H | doorkeeper-gem/doorkeeper-openid_connect | UNKNOWN | missing_claim_grade_fix_sha |
| 28 | GHSA-QH5X-RFWF-RVFV | apernet/hysteria | UNKNOWN | missing_claim_grade_fix_sha |

## Case notes

GHSA-3R75-XC34-5F44, GHSA-423P-G724-FR39, GHSA-G6WW-W5J2-R7X3, GHSA-QHH4-458H-XWH2, GHSA-6GQW-JQV7-V88M, and GHSA-7QJX-GP9H-65QJ recovered first-party fix objects. Deleted-hunk blame is not atomic AI. Mining NOT_SELECTED. Seven counting gates besides identity were not opened. Not GHSA-wide NOT-AI.

GHSA-64VR-4GR2-M642 and GHSA-GC8W-X73W-P4RH: repository advisory HTML is 404 on automagik-dev/genie and ArtMin96/yii2-mcp-server. Global advisory HTML is routing only. BLOCKED.

GHSA-88Q9-CMP2-C2VQ: first-party oxidizePdf PRs 225/226 recover `ca19f8b732a0`, an AI-authored sanitizer of non-finite colour floats. A fix authored by AI is routing only. Deleted colour-format hunks blame later AI restructure, clippy rewrite, and ISO copies of an inherited `{:.3} rg` emitter that already existed on the pre-workspace path. REJECT_CANDIDATE_EDGE only.

GHSA-FQ4X-789W-JG5H: first-party HTML names `b95f52ed9773` (hooks upsert). The GHSA is unauthenticated inbound mail triggering bypassPermissions resume. Hook-config overlap is not the mechanism. REJECT_CANDIDATE_EDGE only.

The remaining UNKNOWN rows have first-party repository advisory HTML but no named claim-grade fix SHA on that HTML. Pool AI commits are file-overlap routing. Missing evidence is UNKNOWN, not a GHSA-wide negative.

## Claim boundary

Worker PASS is a proposal only. This packet has zero PASS. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported.
