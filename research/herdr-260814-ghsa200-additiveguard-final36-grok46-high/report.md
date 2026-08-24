# Additive-guard final36 mining packet: 0 hard-hit proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Reviewed count is **0**. This is a mining/selection packet. The bounded additive-guard heuristic found **0 hard-hit proposals** among the 36 assigned rows. That is not a finding that those 36 have no AI origin. A hard-prefilter miss is **NOT_SELECTED**, not causal REJECT. Seven gates were **NOT_OPENED** on the 34 heuristic misses. Fetch/history failure is **BLOCKED**, never causal REJECT; this scan had **2 BLOCKED** rows. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false. Eligible leftover is exhausted. No further additive slice.

## Conservation

Raw unique `no_source_deleted` and no `diff_fail` pool: **381**.
Excluded / already-covered: **345** (315 before next30 plus 30 additiveguard-next30 mining IDs; equivalently 285 prior plus 60 first30+next30 assignment IDs).
Eligible: **36**.
Assigned (scan_assigned): **36**.
Eligible leftover: **0** (exhausted).
Raw outside this assignment: **345**.
Accepted prior accounting: 381=315+66 before next30; 66=30+36 next30 leaving final36.
This packet: 381=345+36; 36=36+0; 381=36+345.
Did not pad. Did not backfill. Eligible is exhausted after 36. No further additive slice.

## Method

Assigned all 36 remaining genuinely unassigned rows in original scan-miss order after canonical84, explicit terminal/current selected/cases snapshot, and explicit exclusion of all 60 additiveguard-first30 and additiveguard-next30 mining IDs regardless of NOT_SELECTED or BLOCKED. For each exact first-party fix, the bounded heuristic parsed added source hunks and unchanged parent context, then `git blame` / `git log -L` that window. Absence of deleted lines is not a negative. Old equivalent bug or refactor, unrelated parent context, post-fix or later member, carrier trailer transfer, and shallow-boundary blame fail closed. A freeze required an explicit AI-marked atomic origin or mapped squash member plus the remaining hard-hit bars. Freeze cap is the first 20 hard-hit proposals. Corrected first-party advisory loader ran during `scan_additive.py`. Empty aliases do not fail identity; identity was not opened. Only hard hits freeze and open seven gates.

## Scan assignment

Raw outcomes stay in `work/scan.jsonl`. Cases rows are scan-assignment records, not seven-gate adjudications.

| n | ID | Repository | Heuristic | Verdict |
| --- | --- | --- | --- | --- |
| 1 | GHSA-PWPJ-P52H-Q484 | grokability/snipe-it | heuristic_no_hard_hit | NOT_SELECTED |
| 2 | GHSA-8645-P2V4-73R2 | gleam-wisp/wisp | heuristic_no_hard_hit | NOT_SELECTED |
| 3 | GHSA-2679-6MX9-H9XC | marimo-team/marimo | heuristic_no_hard_hit | NOT_SELECTED |
| 4 | GHSA-HR2V-4R36-88HR | helm/helm | heuristic_no_hard_hit | NOT_SELECTED |
| 5 | GHSA-VMX8-MQV2-9GMG | helm/helm | heuristic_no_hard_hit | NOT_SELECTED |
| 6 | GHSA-WRWH-C28M-9JJH | nocobase/nocobase | heuristic_no_hard_hit | NOT_SELECTED |
| 7 | GHSA-34R5-6J7W-235F | inspektor-gadget/inspektor-gadget | heuristic_no_hard_hit | NOT_SELECTED |
| 8 | GHSA-26PP-8WGV-HJVM | honojs/hono | heuristic_no_hard_hit | NOT_SELECTED |
| 9 | GHSA-H7CJ-J2VV-QW8R | gleam-wisp/wisp | heuristic_no_hard_hit | NOT_SELECTED |
| 10 | GHSA-V33R-R6H2-8WR7 | kimai/kimai | heuristic_no_hard_hit | NOT_SELECTED |
| 11 | GHSA-VQ4Q-79HH-Q767 | go-vikunja/vikunja | heuristic_no_hard_hit | NOT_SELECTED |
| 12 | GHSA-WF6X-7X77-MVGW | immutable-js/immutable-js | UNKNOWN | BLOCKED |
| 13 | GHSA-XMPV-J7P2-J873 | nautobot/nautobot | heuristic_no_hard_hit | NOT_SELECTED |
| 14 | GHSA-M547-HP4W-J6JX | go-vikunja/vikunja | heuristic_no_hard_hit | NOT_SELECTED |
| 15 | GHSA-47CR-F226-R4PQ | go-vikunja/vikunja | heuristic_no_hard_hit | NOT_SELECTED |
| 16 | GHSA-M272-9RP6-32MC | middleapi/orpc | UNKNOWN | BLOCKED |
| 17 | GHSA-MR3J-P26X-72X4 | go-vikunja/vikunja | heuristic_no_hard_hit | NOT_SELECTED |
| 18 | GHSA-P6XX-57QC-3WXR | honojs/hono | heuristic_no_hard_hit | NOT_SELECTED |
| 19 | GHSA-P8MM-23GG-JC9R | lxc/incus | heuristic_no_hard_hit | NOT_SELECTED |
| 20 | GHSA-5PQ2-9X2X-5P6W | honojs/hono | heuristic_no_hard_hit | NOT_SELECTED |
| 21 | GHSA-Q382-VC8Q-7JHJ | modelcontextprotocol/go-sdk | heuristic_no_hard_hit | NOT_SELECTED |
| 22 | GHSA-8HP8-9FHR-PFM9 | go-vikunja/vikunja | heuristic_no_hard_hit | NOT_SELECTED |
| 23 | GHSA-94XM-JJ8X-3CR4 | go-vikunja/vikunja | heuristic_no_hard_hit | NOT_SELECTED |
| 24 | GHSA-V8W9-8MX6-G223 | honojs/hono | heuristic_no_hard_hit | NOT_SELECTED |
| 25 | GHSA-F26G-JM89-4G65 | GitoxideLabs/gitoxide | heuristic_no_hard_hit | NOT_SELECTED |
| 26 | GHSA-FRF7-JHP9-JXM6 | mantisbt/mantisbt | heuristic_no_hard_hit | NOT_SELECTED |
| 27 | GHSA-PQ86-J2C2-47F6 | mantisbt/mantisbt | heuristic_no_hard_hit | NOT_SELECTED |
| 28 | GHSA-GPX9-96J6-PP87 | microsoft/TaskWeaver | heuristic_no_hard_hit | NOT_SELECTED |
| 29 | GHSA-9726-W42J-3QJR | mmaitre314/picklescan | heuristic_no_hard_hit | NOT_SELECTED |
| 30 | GHSA-GCGX-CHCP-HXP9 | HappyHackingSpace/gakido | heuristic_no_hard_hit | NOT_SELECTED |
| 31 | GHSA-4J78-4XRM-CR2F | getkirby/kirby | heuristic_no_hard_hit | NOT_SELECTED |
| 32 | GHSA-52CP-R559-CP3M | nodeca/js-yaml | heuristic_no_hard_hit | NOT_SELECTED |
| 33 | GHSA-32H4-44JJ-C5VX | keycloak/keycloak | heuristic_no_hard_hit | NOT_SELECTED |
| 34 | GHSA-MW6P-33VW-46CC | mantisbt/mantisbt | heuristic_no_hard_hit | NOT_SELECTED |
| 35 | GHSA-9473-5F9J-94WQ | nuxt/nuxt | heuristic_no_hard_hit | NOT_SELECTED |
| 36 | GHSA-79QM-7RJ5-M7R9 | honojs/hono | heuristic_no_hard_hit | NOT_SELECTED |

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim. Eligible leftover is exhausted. No further additive slice.
