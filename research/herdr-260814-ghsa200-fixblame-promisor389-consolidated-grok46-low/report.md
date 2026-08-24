# Fix-blame promisor 1-389 consolidated: mining exhaustion proof, 0 PASS

Verdict first: **0 PASS**. Frozen selected count is **0**. Hits 0. This packet consolidates thirteen terminal promisor packets that cover unrepaired remainder positions 1 through 389 exactly once, same GHSA and `scan_miss_order`, no gaps, no overlaps, no backfill. Coverage is rebuilt from each packet `work/scan.jsonl`. Scan-summary `blocked_ids` and `scanned_n` are not the source of truth because packet schemas vary.

Resolved equation: **389=304+74+11**. Raw scan statuses: 282 `no_ai_blame_on_deleted_hunks` plus 22 `no_ai_hit` (304 no-AI-blame variants), 74 `no_deleted_hunk`, and 11 BLOCKED variants (5 `UNKNOWN`, 5 `UNKNOWN_BLOCKED`, and GHSA-C27G-Q93R-2CWF `status=blocked_shallow_boundary` with `blocked=true`). Packet sizes: 389=12*30+29.

This is a mining exhaustion proof only. Heuristic misses are not causal REJECT. Worker PASS is a proposal only and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Conservation

Unrepaired remainder rows sorted by `scan_miss_order`: 389.
Thirteen assignments cover positions 1..389 exactly once.
Selected empty across all packets.
Hits empty across all packets.
No-AI-blame (resolved): 304.
No deleted source hunk: 74.
UNKNOWN/BLOCKED: 11. These identities are listed separately and are not called negatives.
Equation: 389=304+74+11.
Raw equation: 389=282+22+74+5+5+1.
Did not pad. Did not backfill.

## UNKNOWN_BLOCKED identities (11)

- GHSA-RMJ7-2VXQ-3G9F position 13 slice 1-30 raw_status=UNKNOWN
- GHSA-833P-95JQ-929Q position 18 slice 1-30 raw_status=UNKNOWN
- GHSA-Q2M9-6JP9-C6MC position 22 slice 1-30 raw_status=UNKNOWN
- GHSA-F2R5-5M7W-P5CX position 25 slice 1-30 raw_status=UNKNOWN
- GHSA-4X76-22X2-RX8V position 27 slice 1-30 raw_status=UNKNOWN
- GHSA-C27G-Q93R-2CWF position 51 slice 31-60 raw_status=blocked_shallow_boundary blocked=true
- GHSA-R854-JRXH-36QX position 78 slice 61-90 raw_status=UNKNOWN_BLOCKED
- GHSA-94G3-G5V7-Q4JG position 165 slice 151-180 raw_status=UNKNOWN_BLOCKED
- GHSA-XJ4F-8JJG-VX4Q position 189 slice 181-210 raw_status=UNKNOWN_BLOCKED
- GHSA-MP2F-45PM-3CG9 position 292 slice 271-300 raw_status=UNKNOWN_BLOCKED
- GHSA-W3CP-G2PF-65WH position 369 slice 361-389 raw_status=UNKNOWN_BLOCKED

## Method

Consume a packet only after `result.status` is TERMINAL, `replay.zsh` exits 0, sha256 manifest passes with no self hash and no pycache, and `work/scan-summary.json` exists. Reconstruct the 389 `repaired=false` remainder rows, then prove each packet assignment and scan row matches that order. Normalize scan-row statuses as above. Do not infer REJECT from no-AI-blame or no-deleted-hunk. Do not open seven gates. Do not change the canonical ledger.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim.
