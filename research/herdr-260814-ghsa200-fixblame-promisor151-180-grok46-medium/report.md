# Fix-blame promisor151-180: 0 selected, 0 PASS proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Raw unrepaired positions 151 through 180 were assigned from remainder `scan.jsonl` sorted by `scan_miss_order`. Canonical84 and current selected IDs were snapshotted. Overlap in the slice is 0, so nothing was excluded and nothing was replaced from outside the slice. The 30-row slice was materialized with timeout-bounded public clone/fetch into `/tmp/ghsa200-fixblame-promisor151-180`. Hits 0. Carrier gate was applied before freeze; pre-gate hits 0, so carrier negatives 0. No padding. Deep review was not opened because there is no frozen hit. Worker PASS is a proposal only and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Conservation

Unrepaired remainder rows: 389.
Positions 1-150 not claimed: 150.
Raw slice 151-180: 30.
Positions 181-389 not claimed: 209.
Equation: 389=150+30+209.
Slice overlap with canonical84/current selected: 0.
Assigned from slice: 30=30+0.
Scanned: 30.
Hits: 0.
No AI blame on deleted hunks: 25.
No deleted source hunk: 4.
UNKNOWN/BLOCKED (blame timeout, not REJECT): 1 (GHSA-94G3-G5V7-Q4JG).
Carrier negatives: 0.
Equation: 30=0+25+4+1.
Frozen selected: 0. Did not pad. Did not backfill outside the slice.

## Method

Timeout-bounded `git fetch --filter=blob:none` of the exact first-party fix, parent, and target-file objects into disposable `/tmp` clones. Rename-following blame (`git blame -l -w -M`) of pre-fix deleted/replaced source lines. Shallow-boundary blame is not origin. A freeze hit required an atomic blamed commit with a live AI marker on those exact lines, advisory/fix path overlap, later exact fix, and uniqueness. A one-parent PR squash is not an atomic AI hunk merely because the aggregate message has an AI trailer. If the subject ends (#N), the body has multiple member bullets, or carrier/member evidence exists, exact deleted/replaced lines must map to an AI-marked member; otherwise ai_hunk/topology fail closed. Copilot/Claude trailers are not transferred from an unrelated member. That carrier gate ran before freeze. Fetch/history/blame failure stays UNKNOWN/BLOCKED, not REJECT. Seven gates plus released affected/fixed containment and uniqueness were not opened on a frozen hit because freeze selected 0.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim. Zero in this slice is valid and does not claim rows outside positions 151-180.
