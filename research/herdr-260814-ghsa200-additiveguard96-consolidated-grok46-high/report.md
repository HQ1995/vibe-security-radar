# Additive-guard 96 consolidated: mining exhaustion proof, 0 PASS

Verdict first: **0 PASS**. Frozen selected count is **0**. Reviewed causal cases: **0**. Hits 0. This packet consolidates three terminal additive-guard mining packets that cover the 96 previously unassigned unique origin-scan rows exactly once: first30 + next30 + final36. Coverage is rebuilt from `scan-miss.jsonl` plus each packet assignment, `cases.jsonl`, and `work/scan.jsonl`. Packet reports are not the source of truth.

Conservation: **381=285+96**. Eligible split: **96=30+30+36**. Outcomes: **96=88+8**. Full: **381=285+30+30+36**. Raw unique pool is origin-scan rows with `no_source_deleted` and no `diff_fail` (382 no_source_deleted rows, 1 also `diff_fail`, 0 duplicates, unique 381). Prior accepted coverage inside that pool is 285 from the first30 frozen exclusion snapshot. Eligible leftover after 96 is 0.

Terminal outcomes aggregate **88 NOT_SELECTED + 8 BLOCKED**. Zero hard hits. Zero PASS proposals. Zero causal REJECT. NOT_SELECTED rows have gates NOT_OPENED. BLOCKED rows have gates UNKNOWN. BLOCKED is fetch/history failure, never causal REJECT.

This is selection/mining exhaustion only, not evidence that misses are NOT AI-caused. packet_delta=0. Canonical strict remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Conservation

Raw unique `no_source_deleted` and no `diff_fail` pool: 381.
Prior accepted coverage/exclusions in that pool: 285.
Previously unassigned: 96.
Assigned first30: 30.
Assigned next30: 30.
Assigned final36: 36.
Eligible leftover: 0.
NOT_SELECTED: 88.
BLOCKED: 8.
Selected: 0.
Hits: 0.
Reviewed causal cases: 0.
Equations: 381=285+96; 96=30+30+36; 96=88+8; 381=285+30+30+36.
Did not pad. Did not backfill. No gaps, overlap, or order drift versus original scan-miss order.

## BLOCKED identities (8)

- GHSA-97F8-7CMV-76J2 slice next30 order 12 scan_miss_order 879 repository mmaitre314/picklescan reason=fetch_fail history_blocked=true gates=UNKNOWN
- GHSA-7C4H-VH2M-743M slice next30 order 14 scan_miss_order 989 repository n8n-io/n8n reason=log_l_fail history_blocked=true gates=UNKNOWN
- GHSA-6J5F-24FW-PQP4 slice next30 order 15 scan_miss_order 1036 repository ImageMagick/ImageMagick reason=blame_fail+log_l_fail history_blocked=true gates=UNKNOWN
- GHSA-8VRH-3PM2-V4V6 slice next30 order 17 scan_miss_order 1045 repository gtsteffaniak/filebrowser reason=log_l_fail history_blocked=true gates=UNKNOWN
- GHSA-8398-GMMX-564H slice next30 order 20 scan_miss_order 1142 repository n8n-io/n8n reason=log_l_fail history_blocked=true gates=UNKNOWN
- GHSA-96PC-27RX-PR36 slice next30 order 21 scan_miss_order 1148 repository ImageMagick/ImageMagick reason=blame_fail+log_l_fail history_blocked=true gates=UNKNOWN
- GHSA-WF6X-7X77-MVGW slice final36 order 12 scan_miss_order 2006 repository immutable-js/immutable-js reason=blame_fail history_blocked=true gates=UNKNOWN
- GHSA-M272-9RP6-32MC slice final36 order 16 scan_miss_order 2066 repository middleapi/orpc reason=blame_fail history_blocked=true gates=UNKNOWN

## Method

Consume a packet only after `result.status` is TERMINAL, `replay.zsh` exits 0, sha256 manifest passes with no self hash and no pycache, and assignment plus scan rows exist. Independently reconstruct the 381 unique origin-scan rows. Intersect the first30 frozen exclusion snapshot with that pool to recover the 285 prior coverage rows. Prove the three disjoint assignments equal the remaining 96 in original scan-miss order. Normalize cases and assignments without clone, cache, or credential paths. Do not infer REJECT from a heuristic miss. Do not open seven gates. Do not change the canonical ledger.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim. Selection/mining exhaustion is not evidence that misses are not AI-caused.
