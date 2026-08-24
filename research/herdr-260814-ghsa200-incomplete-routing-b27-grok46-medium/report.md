# Incomplete-remediation routing batch B (27)

Verdict first: **0 PASS**. Frozen selected count is **0**. Reviewed count is **27**. Assigned **27**. Unreviewed **0**. Equation **27=27+0**. Worker PASS is a proposal only and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Freeze

The exact prompt list of 27 GHSA IDs was frozen in `assignment27.jsonl` before review. Pass proposals were frozen empty. No padding. No backfill. Each ID is in the 2530 `no_first_party_fix_sha` identities from the corrected commit-first packet and is absent from canonical84 and incomplete-remediation20* case identities. GHSA-4C96-W8V2-P28J is separately owned and is not in this assignment.

Selector-regex reproduction for the global 82 unique incomplete/prior-fix-bypass routes, the removal of GHSA-4C96-W8V2-P28J, and the sorted 81 split A=1-27 / B=28-54 / C=55-81 is **leader-pinned / not independently reconstructed**.

## Source tier

GitHub advisory-database global JSON is routing only. Negative control GHSA-47Q7-97XP-M272 shows that object can name a config-write summary while details and fix describe a hook-token bug. Every assigned row required the same-GHSA repository security advisory HTML page plus official same-repo PR, issue, release, or git refs named there. Title, details, range, and fix were checked for consistency. A global JSON commit ref is never a claim-grade first-party fix. Unavailable repo advisory is BLOCKED. Inconsistent title/details/range/fix is UNKNOWN. Missing exact prior-attempt plus final bypass-fix closure is BLOCKED. Heuristic miss is NOT_SELECTED with gates NOT_OPENED, not causal REJECT. Public GitHub REST API rate remaining was 0; credentials were not used; the API was not retried.

## Pattern

A strict AI_INCOMPLETE_REMEDIATION proposal requires an exact atomic AI marker on the prior security-attempt hunk, explicit security intent, a released vulnerable attempt, a first-party named same-boundary residual, and later exact reversal. Carrier/coauthor branding does not transfer authorship. Rollback may reopen the older broader hole; untouched siblings do not count. Prior public GHSA/CVE IDs are context, never a second count.

## Outcomes

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 4 |
| BLOCKED | 18 |
| REJECT | 2 |

REJECT on GHSA-9G9J-RGGX-7FMG and GHSA-FRH7-2F84-V9MW is malware routing-false-hit. `contribution_class` is `NOT_APPLICABLE_ROUTING_FALSE_HIT`, not `AI_INCOMPLETE_REMEDIATION`. `ghsa_wide_not_ai=false` and `whole_case_causal_reject=false`: this rejects the incomplete-remediation routing hypothesis only.
| NOT_SELECTED | 3 |

| n | prompt | ID | Repository | Verdict | Reason |
| --- | --- | --- | --- | --- | --- |
| 1 | 28 | GHSA-7WQV-XJF3-X35V | parse-community/parse-server | NOT_SELECTED | heuristic_miss_gates_not_opened |
| 2 | 29 | GHSA-7XR2-Q9VF-X4R5 | openclaw/openclaw | BLOCKED | missing_exact_closure |
| 3 | 30 | GHSA-8678-W3JW-XFC2 | sparklemotion/nokogiri | BLOCKED | missing_exact_closure |
| 4 | 31 | GHSA-87QC-FJ39-WCCR | nicolargo/glances | UNKNOWN | title_details_fix_inconsistent |
| 5 | 32 | GHSA-8QQM-FP2Q-V734 | zalando/skipper | UNKNOWN | title_details_fix_inconsistent |
| 6 | 33 | GHSA-8X9C-RMQH-456C | twigphp/Twig | BLOCKED | missing_exact_closure |
| 7 | 34 | GHSA-92MV-8F8W-WQ52 | traefik/traefik | UNKNOWN | title_details_fix_inconsistent |
| 8 | 35 | GHSA-985R-Q3QP-299H | thorsten/phpMyFAQ | BLOCKED | missing_exact_closure |
| 9 | 36 | GHSA-9G9J-RGGX-7FMG | Qix-/node-simple-swizzle | REJECT | malware_irrelevant_wording |
| 10 | 37 | GHSA-C3CH-22RQ-XFWR | WWBN/AVideo | BLOCKED | missing_exact_closure |
| 11 | 38 | GHSA-CCXC-X975-4HH9 | pyload/pyload | BLOCKED | missing_exact_closure |
| 12 | 39 | GHSA-CGCG-Q9JH-5PR2 | keystonejs/keystone | BLOCKED | missing_exact_closure |
| 13 | 40 | GHSA-CMCR-Q4JF-P6Q9 | WWBN/AVideo | BLOCKED | missing_exact_closure |
| 14 | 41 | GHSA-CQP8-FCVH-X7R3 | pydantic/pydantic-ai | BLOCKED | missing_exact_closure |
| 15 | 42 | GHSA-F65R-H4G3-3H9H | mcp-tool-shop-org/backpropagate | BLOCKED | missing_exact_closure |
| 16 | 43 | GHSA-FRH7-2F84-V9MW | Qix-/node-is-arrayish | REJECT | malware_irrelevant_wording |
| 17 | 44 | GHSA-G84H-J7JJ-X32P | ondata/ckan-mcp-server | BLOCKED | missing_exact_closure |
| 18 | 45 | GHSA-GCH2-PHQH-FG9Q | orval-labs/orval | BLOCKED | missing_exact_closure |
| 19 | 46 | GHSA-GWXR-7H77-7777 | projectcapsule/capsule | BLOCKED | missing_exact_closure |
| 20 | 47 | GHSA-H8VQ-8GPG-MHCG | twigphp/Twig | BLOCKED | missing_exact_closure |
| 21 | 48 | GHSA-HF2R-9GF9-RWCH | mozilla/node-convict | BLOCKED | missing_exact_closure |
| 22 | 49 | GHSA-J4H9-PM27-4RFW | OctoPrint/OctoPrint | BLOCKED | missing_exact_closure |
| 23 | 50 | GHSA-JPQ4-7FMQ-Q5FJ | parse-community/parse-server | NOT_SELECTED | heuristic_miss_gates_not_opened |
| 24 | 51 | GHSA-JR6P-8PJJ-MFX6 | projectcapsule/capsule | BLOCKED | missing_exact_closure |
| 25 | 52 | GHSA-JV2H-4P9V-WF5W | Q00/ouroboros | BLOCKED | missing_exact_closure |
| 26 | 53 | GHSA-MVF2-F6GM-W987 | nearform/fast-jwt | UNKNOWN | title_details_fix_inconsistent |
| 27 | 54 | GHSA-MVWX-582F-56R7 | pyload/pyload | NOT_SELECTED | heuristic_miss_gates_not_opened |

## Conservation

Assigned **27**. Reviewed **27**. Unreviewed **0**. Source population **2530**. Canonical84 overlap **0**. Incomplete-remediation20* case overlap **0**. Selected **0**. Packet delta **0**. Did not pad. Did not backfill.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim. Seven gates were not opened on non-hits. Worker PASS remains a proposal only and needs hostile red-team plus leader admission.
