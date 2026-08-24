# Incomplete-remediation20h GHSA mining (grok46-low)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Same keyword ranking as incomplete-remediation20 through 20g. Shared tracked files were not edited. No commit, push, or credential output.

## Freeze

Candidate list was frozen in `work/selected-20.jsonl` (SHA-256 `a3fe5f00950225db235d5698c21677da4c83d42b0d117d66eef9fa144a9b933d`) before deep review.

Method: same frozen advisory-database and keyword weights as incomplete-remediation20; github-reviewed 2025-2026 first-party GHSA JSON; non-withdrawn; first-party `/security/advisories/GHSA-...` URL matching the identity; exclude incomplete-remediation20/20b/20c/20d/20e/20f/20g selected-20, canonical81, directroot selected/cases through batch26, and every prior `herdr-260813-ghsa200-*` / `herdr-260814-ghsa200-*` packet identity; rank by keyword score, then clone presence, published, id; take the next 20. No rerank or widen. Overlap with excluded set: empty. Overlap with sibling selected-20 through 20g: empty. Remaining keyword-ranked identities: 88 UNREVIEWED, not REJECT.

Conservation: selected=20, reviewed=20, unreviewed=88. Prior remaining queue was 108; 20h keyword hits=108; 20+88=108. Selected IDs equal the first twenty of 20g `unreviewed_keyword_ids`.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Old-bug siblings, later AI review, squash transfer, unreleased attempts, OSV routing, and broad shared fixes without per-mechanism reversal fail.

## Verdict

Twenty frozen identities were deeply reviewed. Zero closed all seven gates plus `remediation_patch_delta`.

Closest misses were human origin rem or later unrelated AI siblings, not AI patch-delta:

- GHSA-4X6X: TabberNeue rem f229cab0 is alistair3149 origin rem of the named page-name XSS; later Claude-coauthored markup commits are untouched siblings.
- GHSA-79XX: PhpSpreadsheet generateNavigation XSS is a sibling of earlier oleibman HTML-writer rem, not residual of an AI-added escape.
- Remaining scanned rows are unmarked human origin rem (jongleberry, oleibman, Florian Schmitt, aryaantony92).

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 8 |
| REJECT | 12 |

BLOCKED rows lack a local clone or a cited rem SHA that can be replayed. Missing evidence is not a factual FAIL: unproved causal gates and `remediation_patch_delta` are encoded `BLOCKED`, with `identity_gate` PASS from the first-party GHSA object. They are not REJECT of the mechanism and are not unreviewed.

## Claim boundary

Countable PASS requires all seven gates, patch-delta, and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim.
