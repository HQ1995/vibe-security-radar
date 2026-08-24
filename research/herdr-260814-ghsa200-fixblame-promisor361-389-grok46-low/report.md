# Fix-blame promisor361-389: 0 selected, 0 PASS proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Raw unrepaired positions 361 through 389 were assigned from remainder `scan.jsonl` sorted by `scan_miss_order`. Canonical84 and current selected IDs were snapshotted. Overlap in the slice is 0, so nothing was excluded and nothing was replaced from outside the slice. The 29-row slice was materialized with timeout-bounded public clone/fetch of the exact fix, parent, and enough non-shallow target-file history into `/tmp/ghsa200-fixblame-promisor361-389`. Hits 0. Carrier gate was applied before freeze; pre-gate hits 0, so carrier negatives 0. No padding. Deep review and the seven gates plus release were not opened because there is no frozen hit. Uniqueness versus canonical84 is vacuously PASS. Worker PASS is a proposal only and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Conservation

Unrepaired remainder rows: 389.
Positions 1-360 not claimed: 360.
Raw slice 361-389: 29.
Positions after 389 not claimed: 0.
Equation: 389=360+29+0.
Slice overlap with canonical84/current selected: 0.
Assigned from slice: 29=29+0.
Scanned: 29.
Hits: 0.
No AI blame on deleted hunks: 19.
No deleted source hunk: 9 (GHSA-H5G6-XMH4-HC37, GHSA-8XWF-RJM4-XVHV, GHSA-MJ3G-7XCC-X4VH, GHSA-XF85-363P-868W, GHSA-Q939-RPR3-3284, GHSA-J4R3-HG7J-8CHG, GHSA-H4MF-4V27-HGGJ, GHSA-FQJ9-69PF-6PJG, GHSA-8C48-Q9WJ-3W37).
UNKNOWN/BLOCKED: 1 (GHSA-W3CP-G2PF-65WH; blame timeout, not REJECT).
Carrier negatives: 0.
Equation: 29=0+19+9+1.
Frozen selected: 0. Did not pad. Did not backfill outside the slice. Zero is valid and does not exhaust rows outside positions 361-389.

## Method

Timeout-bounded `git fetch --filter=blob:none` of the exact first-party fix and parent, then enough non-shallow target-file history, into disposable `/tmp` clones. Rename-following blame (`git blame -l -w -M`) of pre-fix deleted/replaced source lines. Shallow-boundary blame is not origin. A hit required an atomic blamed commit with a live AI marker on those exact lines, advisory/fix path overlap, later exact fix, and uniqueness. A one-parent PR squash is not an atomic AI hunk merely because the aggregate message has an AI trailer. If the subject ends (#N), the body has multiple member bullets, or carrier/member evidence exists, exact deleted/replaced lines must map to an AI-marked member; otherwise ai_hunk/topology fail closed. Copilot/Claude trailers are not transferred from an unrelated member. That carrier gate ran before freeze. Fetch/history/blame failure stays UNKNOWN/BLOCKED, not REJECT. Seven gates plus released affected/fixed containment and uniqueness were not opened on a frozen hit because freeze selected 0.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim. Zero in this slice is valid and does not claim rows outside positions 361-389.
