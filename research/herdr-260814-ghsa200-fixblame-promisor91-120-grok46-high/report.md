# Fix-blame promisor91-120: 0 selected, 0 PASS proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Raw unrepaired positions 91 through 120 were assigned from remainder `scan.jsonl` sorted by `scan_miss_order`. Canonical84 and current selected IDs were snapshotted. Overlap in the slice is 0, so nothing was excluded and nothing was replaced from outside the slice. The 30-row slice was materialized with timeout-bounded public clone/fetch of the exact fix, parent, and enough non-shallow target-file history into `/tmp/ghsa200-fixblame-promisor91-120`. Hits 0. Carrier gate was applied before freeze; pre-gate hits 0, so carrier negatives 0. No padding. Deep review and the seven gates plus release were not opened because there is no frozen hit. Uniqueness versus canonical84 is vacuously PASS. Worker PASS is a proposal only and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Conservation

Unrepaired remainder rows: 389.
Positions 1-90 not claimed: 90.
Raw slice 91-120: 30.
Positions 121-389 not claimed: 269.
Equation: 389=90+30+269.
Slice overlap with canonical84/current selected: 0.
Assigned from slice: 30=30+0.
Scanned: 30.
Hits: 0.
No AI blame on deleted hunks: 28.
No deleted source hunk: 2 (GHSA-VJGJ-42F6-7997, GHSA-XQ3M-2V4X-88GG).
UNKNOWN/BLOCKED: 0.
Carrier negatives: 0.
Equation: 30=0+28+2+0.
Frozen selected: 0. Did not pad. Did not backfill outside the slice. Zero is valid and does not exhaust rows outside positions 91-120.

## Method

Timeout-bounded `git fetch --filter=blob:none` of the exact first-party fix and parent, then enough non-shallow target-file history, into disposable `/tmp` clones. Rename-following blame (`git blame -l -w -M`) of pre-fix deleted/replaced source lines. Shallow-boundary blame is not origin. A hit required an atomic blamed commit with a live AI marker on those exact lines, advisory/fix path overlap, later exact fix, and uniqueness. A one-parent PR squash is not an atomic AI hunk merely because the aggregate message has an AI trailer. If the subject ends (#N), the body has multiple member bullets, or carrier/member evidence exists, exact deleted/replaced lines must map to an AI-marked member; otherwise ai_hunk/topology fail closed. Copilot/Claude trailers are not transferred from an unrelated member. That carrier gate ran before freeze. Fetch/history/blame failure stays UNKNOWN/BLOCKED, not REJECT.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim. Zero in this slice is valid and does not claim rows outside positions 91-120.
