# Additive-guard next30 mining packet: 0 hard-hit proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Reviewed count is **0**. This is a mining/selection packet. The bounded additive-guard heuristic found **0 hard-hit proposals** among the 30 assigned rows. That is not a finding that those 30 have no AI origin. A hard-prefilter miss is **NOT_SELECTED**, not causal REJECT. Seven gates were **NOT_OPENED** on the 24 heuristic misses. Fetch/history failure is **BLOCKED**, never causal REJECT; this scan had **6 BLOCKED** rows. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false. Do not start the final36 additive slice until leader accepts this packet.

## Conservation

Raw unique `no_source_deleted` and no `diff_fail` pool: **381**.
Excluded / already-covered: **315** (285 prior plus 30 additiveguard-first30 mining IDs).
Eligible: **66**.
Assigned (scan_assigned): **30**.
Eligible leftover: **36**.
Raw outside this assignment: **351**.
Equations: 381=315+66; 66=30+36; 381=30+351.
Did not pad. Did not backfill. Did not exhaust leftover 36 or the 351 outside assignment.

## Method

Assigned next 30 genuinely unassigned rows in original scan-miss order after canonical84, explicit terminal/current selected/cases snapshot, and explicit exclusion of additiveguard-first30 mining IDs even though those rows are NOT_SELECTED. For each exact first-party fix, the bounded heuristic parsed added source hunks and unchanged parent context, then `git blame` / `git log -L` that window. Absence of deleted lines is not a negative. Old equivalent bug or refactor, unrelated parent context, post-fix or later member, carrier trailer transfer, and shallow-boundary blame fail closed. A freeze required an explicit AI-marked atomic origin or mapped squash member plus the remaining hard-hit bars. Freeze cap is the first 20 hard-hit proposals. Corrected first-party advisory loader ran during `scan_additive.py`. Empty aliases do not fail identity; identity was not opened.

## Scan assignment

Raw outcomes stay in `work/scan.jsonl`. Cases rows are scan-assignment records, not seven-gate adjudications.

| n | ID | Repository | Heuristic | Verdict |
| --- | --- | --- | --- | --- |
| 1 | GHSA-G344-HCPH-8VGG | mmaitre314/picklescan | heuristic_no_hard_hit | NOT_SELECTED |
| 2 | GHSA-9XPH-J2H6-G47V | mmaitre314/picklescan | heuristic_no_hard_hit | NOT_SELECTED |
| 3 | GHSA-CJ3C-V495-4XQH | mmaitre314/picklescan | heuristic_no_hard_hit | NOT_SELECTED |
| 4 | GHSA-X696-VM39-CP64 | mmaitre314/picklescan | heuristic_no_hard_hit | NOT_SELECTED |
| 5 | GHSA-65RG-554R-9J5X | lycheeverse/lychee-action | heuristic_no_hard_hit | NOT_SELECTED |
| 6 | GHSA-8R4J-24QV-FMQ9 | mmaitre314/picklescan | heuristic_no_hard_hit | NOT_SELECTED |
| 7 | GHSA-6W4W-5W54-RJVR | mmaitre314/picklescan | heuristic_no_hard_hit | NOT_SELECTED |
| 8 | GHSA-6VQJ-C2Q5-J97W | mmaitre314/picklescan | heuristic_no_hard_hit | NOT_SELECTED |
| 9 | GHSA-5QWP-399C-MJWF | mmaitre314/picklescan | heuristic_no_hard_hit | NOT_SELECTED |
| 10 | GHSA-7CQ8-MJ8X-J263 | mmaitre314/picklescan | heuristic_no_hard_hit | NOT_SELECTED |
| 11 | GHSA-W7FW-MJWX-W883 | ljharb/qs | heuristic_no_hard_hit | NOT_SELECTED |
| 12 | GHSA-97F8-7CMV-76J2 | mmaitre314/picklescan | UNKNOWN | BLOCKED |
| 13 | GHSA-3MQ9-XHGQ-R7GJ | lf-edge/eve | heuristic_no_hard_hit | NOT_SELECTED |
| 14 | GHSA-7C4H-VH2M-743M | n8n-io/n8n | UNKNOWN | BLOCKED |
| 15 | GHSA-6J5F-24FW-PQP4 | ImageMagick/ImageMagick | UNKNOWN | BLOCKED |
| 16 | GHSA-H395-GR6Q-CPJC | Keats/jsonwebtoken | heuristic_no_hard_hit | NOT_SELECTED |
| 17 | GHSA-8VRH-3PM2-V4V6 | gtsteffaniak/filebrowser | UNKNOWN | BLOCKED |
| 18 | GHSA-4C4V-42HC-72P6 | lf-edge/eve | heuristic_no_hard_hit | NOT_SELECTED |
| 19 | GHSA-5H7V-G49C-H887 | lf-edge/eve | heuristic_no_hard_hit | NOT_SELECTED |
| 20 | GHSA-8398-GMMX-564H | n8n-io/n8n | UNKNOWN | BLOCKED |
| 21 | GHSA-96PC-27RX-PR36 | ImageMagick/ImageMagick | UNKNOWN | BLOCKED |
| 22 | GHSA-C87C-78RC-VMV2 | man-group/dtale | heuristic_no_hard_hit | NOT_SELECTED |
| 23 | GHSA-M7J5-R2P5-C39R | mmaitre314/picklescan | heuristic_no_hard_hit | NOT_SELECTED |
| 24 | GHSA-9M3X-QQW2-H32H | mmaitre314/picklescan | heuristic_no_hard_hit | NOT_SELECTED |
| 25 | GHSA-26GQ-GRMH-6XM6 | gogs/gogs | heuristic_no_hard_hit | NOT_SELECTED |
| 26 | GHSA-JQ8V-RMF6-65JW | gogs/gogs | heuristic_no_hard_hit | NOT_SELECTED |
| 27 | GHSA-F3C5-6CW8-FG57 | grokability/snipe-it | heuristic_no_hard_hit | NOT_SELECTED |
| 28 | GHSA-VCM5-GVMP-78MP | gogs/gogs | heuristic_no_hard_hit | NOT_SELECTED |
| 29 | GHSA-C9CV-MQ2M-PPP3 | nuxt/nuxt | heuristic_no_hard_hit | NOT_SELECTED |
| 30 | GHSA-8G7M-96C8-8WWC | lxc/incus | heuristic_no_hard_hit | NOT_SELECTED |

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim.
