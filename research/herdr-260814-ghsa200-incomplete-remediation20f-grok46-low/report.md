# Incomplete-remediation20f GHSA mining (grok46-low)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Same keyword ranking as incomplete-remediation20 through 20e. Shared tracked files were not edited. No commit, push, or credential output.

## Freeze

Candidate list was frozen in `work/selected-20.jsonl` (SHA-256 `53bf2ff055fa14d381f4dac699a1e1a0d5f09867bda9ae6bac08205914abbd92`) before deep review.

Method: same frozen advisory-database and keyword weights as incomplete-remediation20; github-reviewed 2025-2026 first-party GHSA JSON; non-withdrawn; first-party `/security/advisories/GHSA-...` URL matching the identity; exclude incomplete-remediation20/20b/20c/20d/20e selected-20, canonical81, directroot selected/cases through batch23, and every prior `herdr-260813-ghsa200-*` / `herdr-260814-ghsa200-*` packet identity; rank by keyword score, then clone presence, published, id; take the next 20. No rerank or widen. Overlap with excluded set: empty. Overlap with sibling selected-20 through 20e: empty. Remaining keyword-ranked identities: 128 UNREVIEWED, not REJECT.

Conservation: selected=20, reviewed=20, unreviewed=128. Prior remaining queue was 148; 20f keyword hits=148; 20+128=148. Selected IDs equal the first twenty of 20e `unreviewed_keyword_ids`.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Old-bug siblings, later AI review, squash transfer, unreleased attempts, OSV routing, and broad shared fixes without per-mechanism reversal fail.

## Verdict

Twenty frozen identities were deeply reviewed. Zero closed all seven gates plus `remediation_patch_delta`.

Closest misses were keyword-shaped origin bugs or human incomplete priors, not AI patch-delta:

- GHSA-4R4M / GHSA-XCJ6: Vite `server.fs.deny` residuals tightened by patak after prior human rem, not an AI guard rewrite.
- GHSA-F82V: Next.js middleware header rem is JJ Kasper origin rem.
- GHSA-4VC4 / GHSA-754F: ruby-saml parser-differential rem is Sixto Martin origin rem.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 7 |
| REJECT | 13 |

BLOCKED rows lack a local clone. Missing evidence is not a factual FAIL: unproved causal gates and `remediation_patch_delta` are encoded `BLOCKED`, with `identity_gate` PASS from the first-party GHSA object. They are not REJECT of the mechanism and are not unreviewed.

## Claim boundary

Countable PASS requires all seven gates, patch-delta, and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim.
