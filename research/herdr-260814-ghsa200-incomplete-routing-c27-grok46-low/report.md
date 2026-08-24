# Incomplete-remediation routing batch C (positions 55-81)

Verdict first: **0 PASS**. Frozen selected count is **0**. Reviewed count is **27**. Assigned 27. Unreviewed 0. Conservation 27=27+0. Worker PASS is a proposal only and this packet emits none. packet_delta=0. Canonical strict count remains **84**. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Freeze

Leader pinned this exact 27-ID C slice of the sorted 81-ID remainder from an 82-ID routing pool in the 2530 no_first_party_fix_sha population. Deno GHSA-4C96-W8V2-P28J is separately owned. A owns 1-27. B owns 28-54. This worker did not reconstruct the selector regex and did not pad or backfill. Pass proposals were frozen empty before review.

Each assigned ID is in the 2530 source and absent from canonical84 and prior incomplete packets.

## Source tier

GitHub advisory-database global JSON is routing only. Title, details, range, and final fix were bound only from the same-GHSA repository advisory HTML plus official same-repo PR, issue, release, and git objects. Union-by-repo is forbidden. GitHub unauthenticated API remaining was 0 and was not used. Missing claim-grade first-party content is BLOCKED. Heuristic miss is NOT_SELECTED with gates NOT_OPENED. Malware wording is REJECT, not PASS. Carrier branding does not transfer authorship.

## Pattern

Strict AI_INCOMPLETE_REMEDIATION requires an exact atomic AI marker on a prior security-attempt hunk, explicit security intent, a released vulnerable attempt, a named same-boundary residual, a later exact reversal, and all seven gates identity/ai_hunk/topology/patch-delta-but_for/fix_reversal/release/uniqueness PASS. No row met that bar.

## Outcomes

BLOCKED 22. REJECT 2. NOT_SELECTED 3. UNKNOWN 0. NARROW 0. PASS 0.

REJECT rows GHSA-PXX3-G568-HXR4 and GHSA-QRMH-QG46-72PP are npm malware after account takeover. That is not AI incomplete remediation. ghsa_wide_not_ai is false.

NOT_SELECTED rows bound a named same-repo commit or release object without an AI marker on a prior security-attempt hunk: GHSA-VM69-H85X-8P85 (siyuan 9914fd1d, author Daniel), GHSA-W856-8P3R-P338 (glances 04579778, author nicolargo), GHSA-XF64-8MW2-4GR2 (traefik release tags v2.11.48 and v3.6.19, prepare-release commits). Gates stay NOT_OPENED.

GHSA-V2QM-5WXJ-QHJ7 and GHSA-W727-595X-PC3R use account-takeover impact language but are not npm malware packages. They lack claim-grade fix SHAs and are BLOCKED.

| n | prompt | ID | Repository | Verdict | Reason |
| --- | ---: | --- | --- | --- | --- |
| 1 | 55 | GHSA-P5CP-R7RG-QPXC | open-webui/open-webui | BLOCKED | missing_exact_closure |
| 2 | 56 | GHSA-PG67-9WJV-MR85 | pyload/pyload | BLOCKED | missing_exact_closure |
| 3 | 57 | GHSA-PMC9-F5QR-2PCR | siyuan-note/siyuan | BLOCKED | missing_exact_closure |
| 4 | 58 | GHSA-PMWG-CVHR-8VH7 | axios/axios | BLOCKED | missing_exact_closure |
| 5 | 59 | GHSA-PR59-H9PH-3FR8 | protobufjs/protobuf.js | BLOCKED | missing_exact_closure |
| 6 | 60 | GHSA-PVMV-CWG8-V6C8 | ZcashFoundation/zebra | BLOCKED | missing_exact_closure |
| 7 | 61 | GHSA-PXX3-G568-HXR4 | Qix-/color-convert | REJECT | malware_irrelevant_wording |
| 8 | 62 | GHSA-QRMH-QG46-72PP | Qix-/color | REJECT | malware_irrelevant_wording |
| 9 | 63 | GHSA-R253-R9JW-QG44 | unclecode/crawl4ai | BLOCKED | missing_exact_closure |
| 10 | 64 | GHSA-RG3H-X3JW-7JM5 | MervinPraison/PraisonAI | BLOCKED | missing_exact_closure |
| 11 | 65 | GHSA-RJVW-7VVW-549V | MervinPraison/PraisonAI | BLOCKED | missing_exact_closure |
| 12 | 66 | GHSA-V2QM-5WXJ-QHJ7 | open-webui/open-webui | BLOCKED | missing_exact_closure |
| 13 | 67 | GHSA-V8H7-RR48-VMMV | netty/netty | BLOCKED | missing_exact_closure |
| 14 | 68 | GHSA-VJV9-7M7J-H833 | MervinPraison/PraisonAI | BLOCKED | missing_exact_closure |
| 15 | 69 | GHSA-VM69-H85X-8P85 | siyuan-note/siyuan | NOT_SELECTED | heuristic_miss_gates_not_opened |
| 16 | 70 | GHSA-VPFX-PXQW-2W79 | WWBN/AVideo | BLOCKED | missing_exact_closure |
| 17 | 71 | GHSA-VRQV-52X7-RM4V | kimai/kimai | BLOCKED | missing_exact_closure |
| 18 | 72 | GHSA-W2PM-X38X-JP44 | bentoml/BentoML | BLOCKED | missing_exact_closure |
| 19 | 73 | GHSA-W6M8-CQVJ-PG5V | openclaw/openclaw | BLOCKED | missing_exact_closure |
| 20 | 74 | GHSA-W727-595X-PC3R | pyload/pyload | BLOCKED | missing_exact_closure |
| 21 | 75 | GHSA-W856-8P3R-P338 | nicolargo/glances | NOT_SELECTED | heuristic_miss_gates_not_opened |
| 22 | 76 | GHSA-WRR5-99H5-GQ57 | go-gitea/gitea | BLOCKED | missing_exact_closure |
| 23 | 77 | GHSA-WRWR-H859-XH2R | n8n-io/n8n | BLOCKED | missing_exact_closure |
| 24 | 78 | GHSA-X8JC-JVQM-PM3F | filebrowser/filebrowser | BLOCKED | missing_exact_closure |
| 25 | 79 | GHSA-XF64-8MW2-4GR2 | traefik/traefik | NOT_SELECTED | heuristic_miss_gates_not_opened |
| 26 | 80 | GHSA-XP9R-PRPG-373R | openclaw/openclaw | BLOCKED | missing_exact_closure |
| 27 | 81 | GHSA-XW9Q-2MV6-9FR8 | fedify-dev/fedify | BLOCKED | missing_exact_closure |

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim. Strict remains 84.
