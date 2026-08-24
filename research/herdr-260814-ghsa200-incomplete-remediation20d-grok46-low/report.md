# Incomplete-remediation20d GHSA mining (grok46-low)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Same keyword ranking as incomplete-remediation20, 20b, and 20c. Shared tracked files were not edited. No commit, push, or credential output.

## Freeze

Candidate list was frozen in `work/selected-20.jsonl` (SHA-256 `6270cc030886583d088f0ab074cfe91f341412a07fa55b9c7896f54eccddb8bd`) before deep review.

Method: same frozen advisory-database and keyword weights as incomplete-remediation20; github-reviewed 2025-2026 first-party GHSA JSON; non-withdrawn; first-party `/security/advisories/GHSA-...` URL matching the identity; exclude incomplete-remediation20/20b/20c selected-20, canonical81, directroot selected/cases through batch21, and every prior `herdr-260813-ghsa200-*` / `herdr-260814-ghsa200-*` packet identity; rank by keyword score, then clone presence, published, id; take the next 20. No rerank or widen. Overlap with excluded set: empty. Overlap with sibling selected-20, 20b, and 20c: empty. Remaining keyword-ranked identities: 168 UNREVIEWED, not REJECT.

Conservation: selected=20, reviewed=20, unreviewed=168. Prior remaining queue was 188; 20d keyword hits=188; 20+168=188. Selected IDs equal the first twenty of 20c `unreviewed_keyword_ids`.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Old-bug siblings, later AI review, squash transfer, unreleased attempts, OSV routing, and broad shared fixes without per-mechanism reversal fail.

## Verdict

Twenty frozen identities were deeply reviewed. Zero closed all seven gates plus `remediation_patch_delta`.

Closest misses were keyword-shaped origin bugs or human incomplete priors, not AI patch-delta:

- GHSA-389X: Netty BoundedInputStream null-byte residual is a human incomplete prior (Norman Maurer / Chris Vest).
- GHSA-943Q: OpenClaw HTTP deny / ACP rem is Peter Steinberger; thanks @aether-ai-agent is not an AI hunk trailer.
- GHSA-WC79: MinIO SFTP LDAP pubkey residual is Sveinn introducer plus Aditya rem, both unmarked.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 8 |
| REJECT | 12 |

BLOCKED rows lack a local clone. Missing evidence is not a factual FAIL: unproved causal gates and `remediation_patch_delta` are encoded `BLOCKED`, with `identity_gate` PASS from the first-party GHSA object. They are not REJECT of the mechanism and are not unreviewed.

## Claim boundary

Countable PASS requires all seven gates, patch-delta, and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim.
