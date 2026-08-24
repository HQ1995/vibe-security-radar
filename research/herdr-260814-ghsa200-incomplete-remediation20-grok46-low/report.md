# Incomplete-remediation20 GHSA mining (grok46-low)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Shared tracked files were not edited. No commit, push, or credential output.

## Freeze

Candidate list was frozen in `work/selected-20.jsonl` (SHA-256 `3d0e65cd3866eb4d45d70d9222c364f31e4950b04c0ce7b0bf19c3371c888dba`) before deep review.

Method: github-reviewed 2025-2026 first-party GHSA JSON in the frozen clone; non-withdrawn; first-party `/security/advisories/GHSA-...` URL matching the identity; exclude canonical73, canonical78, directroot selected/cases through batch17, and every prior `herdr-260813-ghsa200-*` / `herdr-260814-ghsa200-*` packet identity; rank by bypass/incomplete/validation/sanitization/allowlist/denylist/blocklist/guard keyword score, then clone presence, published, id; take 20. Overlap with excluded set: empty. Remaining keyword-ranked identities: 229 UNREVIEWED, not REJECT.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Old-bug siblings, later AI review, squash transfer, unreleased attempts, OSV routing, and broad shared fixes without per-mechanism reversal fail.

## Verdict

Twenty frozen identities were deeply reviewed. Zero closed all seven gates plus `remediation_patch_delta`.

Closest miss:

- GHSA-4CM8-XPFV-JV6F: Claude Sonnet 4.6 `51bc07a` adds Email `is_sender_allowed`. The GHSA names header-only From spoofing. `v0.7.6` / `bf004a2` only documents the limitation and warns; it does not add SPF/DKIM. That is new-surface origin plus non-reversal, not countable incomplete rem.

- GHSA-CJ5W-8MJF-R5F8: GHSA names an incomplete prior patch, but PR 1196 / `2e8fd94b` is human.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 4 |
| REJECT | 16 |

BLOCKED rows lack a local clone for git proof. Missing evidence is not a factual FAIL: unproved causal gates and `remediation_patch_delta` are encoded `BLOCKED`, with `identity_gate` PASS from the first-party GHSA object. They are not REJECT of the mechanism and are not unreviewed.

## Claim boundary

Countable PASS requires all seven gates, patch-delta, and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim.
