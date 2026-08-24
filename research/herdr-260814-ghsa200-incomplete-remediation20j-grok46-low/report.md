# Incomplete-remediation20j GHSA mining (grok46-low)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Same keyword ranking as incomplete-remediation20 through 20i. Shared tracked files were not edited. No commit, push, or credential output.

## Freeze

Candidate list was frozen in `work/selected-20.jsonl` (SHA-256 `ccf1d374787a0464016502fb55f706a808172c9fd24e5dd744c02c68f93bab6e`) before deep review.

Method: same frozen advisory-database and keyword weights as incomplete-remediation20; github-reviewed 2025-2026 first-party GHSA JSON; non-withdrawn; first-party `/security/advisories/GHSA-...` URL matching the identity; exclude incomplete-remediation20/20b/20c/20d/20e/20f/20g/20h/20i selected-20, canonical81, directroot selected/cases through batch27, and every prior `herdr-260813-ghsa200-*` / `herdr-260814-ghsa200-*` packet identity; rank by keyword score, then clone presence, published, id; take the next 20. No rerank or widen. Overlap with excluded set: empty. Overlap with sibling selected-20 through 20i: empty. Remaining keyword-ranked identities: 48 UNREVIEWED, not REJECT.

Conservation: selected=20, reviewed=20, unreviewed=48. Prior remaining queue was 68; 20j keyword hits=68; 20+48=68. Selected IDs equal the first twenty of 20i `unreviewed_keyword_ids`.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Old-bug siblings, later AI review, squash transfer, unreleased attempts, OSV routing, and broad shared fixes without per-mechanism reversal fail.

## Verdict

Twenty frozen identities were deeply reviewed. Zero closed all seven gates plus `remediation_patch_delta`.

Closest misses were human origin rem or later unrelated AI siblings, not AI patch-delta:

- GHSA-2R2V: wg-portal rem 62dbdfe0 is Christoph Haas origin rem of OAuth redirect; later Claude-coauthored 62e7f9d8 is OIDC return-URL base_path routing, an untouched sibling.
- GHSA-VW58: Directus rem 2e893f9c is ian origin rem of access_token log redaction.
- Remaining scanned rows are unmarked human origin rem (Rich Harris, Russell Bryant, Florian Schmitt, Zhiwei Liang, Flavio Castelli, Norman Maurer, David Cook, vexofp, Giuseppe Criscione, Pedro Igor).

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 7 |
| REJECT | 13 |

BLOCKED rows lack a local clone or a cited rem SHA that can be replayed. Missing evidence is not a factual FAIL: unproved causal gates and `remediation_patch_delta` are encoded `BLOCKED`, with `identity_gate` PASS from the first-party GHSA object. They are not REJECT of the mechanism and are not unreviewed.

## Claim boundary

Countable PASS requires all seven gates, patch-delta, and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim.
