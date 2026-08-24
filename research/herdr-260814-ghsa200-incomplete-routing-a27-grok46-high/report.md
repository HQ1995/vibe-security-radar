# Incomplete-remediation routing A27: 0 PASS proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Reviewed count is **27**. Assigned 27. Hard hits 0. REJECT 5. UNKNOWN 2. BLOCKED 20. NARROW 0. NOT_SELECTED 0. No padding. No backfill. Worker PASS is a proposal only and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Conservation

Frozen assignment is the exact 27-ID prompt list in this order. Each ID is in the 2530 `no_first_party_fix_sha` identities from the corrected commitfirst packet. Overlap with canonical84 is 0. Overlap with prior incomplete-remediation20* packets is 0. GHSA-4C96-W8V2-P28J is separately owned by nofixref-first30 and is not in this assignment. Selector-regex reproduction of the claimed 82-to-81 split is **leader-pinned / not independently reconstructed**. Did not pad. Did not backfill. Did not replace a failed row.

## Source tier

GitHub advisory-database global JSON is routing only. Every assigned row required the same-GHSA repository security advisory HTML page. Title, repository, identity, affected range, and patched versions were bound from that page. A global JSON commit ref is never a claim-grade first-party fix. GitHub API was not used (unauthenticated rate remaining was 0; no credentials). Named PR/commit HTML and official git objects were used only when the same-GHSA page named them. Unavailable exact prior-plus-final git closure is BLOCKED. Named-commit / mechanism mismatch is UNKNOWN. Heuristic miss is NOT_SELECTED with gates NOT_OPENED, not causal REJECT. A positively disproved incomplete-rem edge is REJECT_INCOMPLETE_REM_EDGE with ghsa_wide_not_ai=false.

## Outcomes

Five REJECT_INCOMPLETE_REM_EDGE rows, all with ghsa_wide_not_ai=false. GHSA-286P, GHSA-53MQ, and GHSA-6JP5 are first-party malware/account-takeover advisories, not residual guard bypasses; contribution_class is NOT_APPLICABLE_ROUTING_FALSE_HIT. GHSA-7526 prior attempt `b6a4fb1` is Henrique Dias with no AI trailer; later PR 5890 / `f13c7c8` is also human. GHSA-489G prior PR 986 and final PR 1005 are human sooperset/Hyeonsoo Lee with no AI trailer. Those two human-prior rows keep contribution_class AI_INCOMPLETE_REMEDIATION with failed gates.

Two UNKNOWN rows: GHSA-2PQ5 names `b9df06f`, which restores GHSA-gjgq tool handoffs rather than the Neo4j Cypher residual. GHSA-47WQ names merge `b649bd4` (`pap-1347-codex-fast-mode`); carrier/coauthor branding does not transfer authorship and the commit is not the assertCompanyAccess closure.

Twenty BLOCKED rows lack a first-party prior security-attempt SHA and/or final bypass-fix SHA. Missing evidence is not a factual FAIL of the mechanism.

| n | ID | Repository | Verdict | Reason |
| --- | --- | --- | --- | --- |
| 1 | GHSA-25RP-H46X-2HJM | siyuan-note/siyuan | BLOCKED | missing_exact_closure |
| 2 | GHSA-26HH-7CQF-HHC6 | vercel/next.js | BLOCKED | missing_exact_closure |
| 3 | GHSA-286P-VC9P-P5QV | Qix-/color-string | REJECT | malware_not_incomplete_rem |
| 4 | GHSA-2M69-JMVH-6CHR | ci4-cms-erp/ci4ms | BLOCKED | missing_exact_closure |
| 5 | GHSA-2PQ5-3Q89-J7CC | langroid/langroid | UNKNOWN | named_commit_mechanism_mismatch |
| 6 | GHSA-2WPX-QPW2-G5H5 | coredns/coredns | BLOCKED | missing_exact_closure |
| 7 | GHSA-3298-56P6-RPW2 | openclaw/openclaw | BLOCKED | missing_exact_closure |
| 8 | GHSA-3J5Q-7Q7H-2HHV | OpenMage/magento-lts | BLOCKED | missing_exact_closure |
| 9 | GHSA-44FC-8FM5-Q62H | mozilla/node-convict | BLOCKED | missing_exact_closure |
| 10 | GHSA-45Q3-82M4-75JR | netty/netty | BLOCKED | missing_exact_closure |
| 11 | GHSA-47WQ-CJ9Q-WPMP | paperclipai/paperclip | UNKNOWN | named_commit_mechanism_mismatch |
| 12 | GHSA-489G-7RXV-6C8Q | sooperset/mcp-atlassian | REJECT | human_prior_fix |
| 13 | GHSA-4C3Q-X735-J3R5 | node-modules/compressing | BLOCKED | missing_exact_closure |
| 14 | GHSA-53MQ-F4W3-F7QV | Qix-/node-backslash | REJECT | malware_not_incomplete_rem |
| 15 | GHSA-56MP-4F3V-FGJ2 | siyuan-note/siyuan | BLOCKED | missing_exact_closure |
| 16 | GHSA-5FC7-F62M-8983 | openclaw/openclaw | BLOCKED | missing_prior_attempt |
| 17 | GHSA-5HC8-QMG8-PW27 | siyuan-note/siyuan | BLOCKED | missing_exact_closure |
| 18 | GHSA-5J59-XGG2-R9C4 | vercel/next.js | BLOCKED | missing_exact_closure |
| 19 | GHSA-5V5V-WW74-355V | twigphp/Twig | BLOCKED | missing_exact_closure |
| 20 | GHSA-654M-C8P4-X5FP | axios/axios | BLOCKED | missing_exact_closure |
| 21 | GHSA-65PC-FJ4G-8RJX | kjd/idna | BLOCKED | missing_exact_closure |
| 22 | GHSA-6C2X-GCP3-GP73 | open-webui/open-webui | BLOCKED | missing_exact_closure |
| 23 | GHSA-6JP5-HH4C-8C5H | Qix-/node-error-ex | REJECT | malware_not_incomplete_rem |
| 24 | GHSA-6M52-M754-PW2G | nuxt/nuxt | BLOCKED | missing_prior_attempt |
| 25 | GHSA-7526-J432-6PPP | filebrowser/filebrowser | REJECT | human_prior_fix |
| 26 | GHSA-78F9-R8MH-4XM2 | bentoml/BentoML | BLOCKED | missing_exact_closure |
| 27 | GHSA-7FXW-R6JV-74C8 | twigphp/Twig | BLOCKED | missing_exact_closure |

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim. Seven gates were not all opened on non-PASS rows. Canonical overlap is 0.
