# Fix-blame promisor31-60: 0 selected, 0 PASS proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Raw unrepaired remainder positions 31-60 were assigned (30 rows). Canonical84 and current selected-ID overlap in the slice is 0 and was not replaced from outside the slice. Hits 0. No padding. Deep review was not opened because there is no frozen hit. Worker PASS is a proposal only and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Conservation

Unrepaired remainder pool: 389.
Positions 1-30 not claimed: 30.
This slice 31-60: 30.
Positions 61-389 not claimed: 329.
Equation: 389=30+30+329.
Overlap excluded: 0.
Eligible scanned: 30.
no_ai_hit: 22.
no_deleted_hunk: 7.
BLOCKED (shallow-boundary blame, not origin): 1 (GHSA-C27G-Q93R-2CWF).
Hits: 0.
Slice equation: 30=0+22+7+1+0.
Zero is valid. This packet does not claim outside the slice.

## Squash-carrier gate

Applied before freeze. A one-parent PR squash is not an atomic AI hunk merely because the aggregate message has a Copilot or Claude trailer. If the subject ends in (#N), the message contains multiple member bullets, or carrier/member evidence exists, exact vulnerable deleted or replaced lines must map to an AI-marked member. Trailers are not transferred from an unrelated member. No blamed live-AI commit reached freeze, so carrier_negatives.jsonl is empty. The gate remains fail-closed.

## Method

Input is remainder `work/scan.jsonl` records with repaired=false, sorted by scan_miss_order. Disposable clones under `/tmp/ghsa200-fixblame-promisor31-60`. Timeout-bounded GitHub fetch of exact fix, parent, and target-file objects. Shared clones were not mutated and were not used as promisor alternates. Rename-following blame of pre-fix deleted/replaced source lines. Shallow-boundary blame (`^` prefix) is not origin. A freeze hit required an atomic blamed commit with a live AI marker, advisory/fix path overlap, and the squash-carrier member map when the commit is a PR squash carrier. Fetch or history failure is UNKNOWN/BLOCKED, not REJECT.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim.
