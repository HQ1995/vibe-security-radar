# Commit-first hard prefilter20: 0 selected, 0 PASS proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Assigned adjudication count is **0**. Reviewed count is **0**. The remainder pool of 5980 unique-first-seen commit-first identities was walked in original shard order AF, GJ, GN, KN, OZ from the frozen candidate pool. Canonical84 plus every terminal or currently assigned selected.jsonl, including cfrem20, were excluded before probe. Hard-prefilter required first-party non-withdrawn GHSA identity, an atomic non-carrier AI marker or an AI-marked member bound to a PR-style squash carrier, exact deleted-hunk overlap at the first-party fix parent, proof the shipped commit precedes that fix, and affected/fixed release containment. A path-only AI commit after the fix is ineligible. A PR-style squash carrier (subject (#N) or multi-member message) is not atomic hunk authorship even when the carrier has an AI trailer.

Hits **0**. No padding. The pool was exhausted without hitting the cap of 20. Hard-prefilter misses are mining **NOT_SELECTED** outcomes, not causal REJECTs. Seven gates identity, ai_hunk, topology, but_for, fix_reversal, release, and uniqueness remain **NOT_OPENED**. Heuristic no-hit is not identity, AI, or but-for FAIL. Worker PASS is a proposal only and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Conservation

Candidate pool: 5980.
Excluded union (canonical84 plus assigned selected, including cfrem20): 2479.
Excluded in this pool: 1064.
Scanned (hard-prefilter probed): 2301.
Unprobed (clone missing or no first-party fix SHA): 2615 (85 clone_missing, 2530 no_first_party_fix_sha).
Equation: 5980=1064+2301+2615.
Scan split: 2301=2247+54+0 (2247 no_hard_prefilter_hit, 54 no_resolvable_first_party_fix, 0 frozen).
Unprobed split: 2615=85+2530.
Frozen hard hits: 0.
Unprobed after cap: 0.
Padding: false.
Exhausted without cap: true.
Assigned for seven-gate adjudication: 0.
Reviewed: 0.
Causal REJECT: 0.
NOT_SELECTED mining outcomes: 5980.

GHSA-F63H-WC26-PMVC is a hard-prefilter miss after the squash-carrier trailer correction. That is mining NOT_SELECTED, not a causal REJECT. GHSA-CVHV-6XM6-C3V4 is the same class of miss (later Cursor squash is not a member of the blamed carrier).

## Method

Inputs are the five 2026-08-13 commit-first shard artifacts and clones, the frozen local advisory database at `a42c436870111aa3f221257c9d56126a93173ccc`, and current repo read-only state. cfrem20 freeze admitted post-fix path-only hits; this lane requires ancestry or blob-equivalent or squash-member-to-carrier proof before freeze. Independent Git replay showed a404436f (#5280) is a multi-member squash whose Copilot Autofix trailer is not filename or save authorship. The selector was changed so any PR-style carrier must map the exact blamed hunk to an AI-marked atomic non-carrier member bound to that carrier. Later descendant squashes and nested (#N) carriers do not count. Direct-marker acceptance is only for genuinely atomic non-carrier commits. Shard labels were not treated as proof. No fetch, clone, commit, or push.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim. Zero frozen hits is valid. The exhausted remainder is conserved as mining NOT_SELECTED, not as seven-gate REJECT.
