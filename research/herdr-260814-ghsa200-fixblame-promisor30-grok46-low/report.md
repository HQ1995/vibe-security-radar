# Fix-blame promisor30: 0 selected, 0 PASS proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Assigned 30 unrepaired remainder rows in original scan_miss_order after canonical84 and current/terminal selected-packet exclusions. Public timeout-bounded clone/fetch into `/tmp/ghsa200-fixblame-promisor30` only. Hits 0. No padding. Squash-carrier gate ran before freeze: a one-parent PR squash is not an atomic AI hunk merely because the aggregate message has an AI trailer. Deep review of a frozen hit was not opened. Worker PASS is a proposal only and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false. The remaining 359 unrepaired rows are not claimed exhausted.

## Conservation

Unrepaired remainder pool: 389.
Already assigned in the exclusion snapshot: 0.
Still-unassigned unrepaired: 389.
Assigned30: 30.
Leftover unrepaired: 359.
Equation: 389=30+359.
Assigned30 split: 30=22 no-AI-hit + 3 no-deleted-hunk + 5 UNKNOWN/BLOCKED + 0 hits.
Did not pad. Errors that are fetch/object/history/blame-timeout stay UNKNOWN/BLOCKED, never REJECT.

## Method

Reuse origin20 rename-following blame of pre-fix deleted/replaced source lines. Caret/shallow-boundary blame is not origin. A hit required an atomic blamed commit with a live AI marker on those exact lines, advisory-path match, pre-fix ancestry, and a later exact fix. One-parent squash carriers whose subject ends (#N) or whose message has multiple member bullets fail closed unless the exact vulnerable hunk maps to an AI-marked member. Copilot/Claude trailers are not transferred from an unrelated member.

## Adjudications

No frozen hits, so seven-gate PASS/FAIL was not opened on a candidate. Five rows remain BLOCKED because blame timed out while materializing target-file history: GHSA-RMJ7-2VXQ-3G9F, GHSA-833P-95JQ-929Q, GHSA-Q2M9-6JP9-C6MC, GHSA-F2R5-5M7W-P5CX, GHSA-4X76-22X2-RX8V. Those are UNKNOWN/BLOCKED, not REJECT. Twenty-two rows had deleted source hunks with no live AI marker on those lines. Three rows had no deleted source hunk.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim.
