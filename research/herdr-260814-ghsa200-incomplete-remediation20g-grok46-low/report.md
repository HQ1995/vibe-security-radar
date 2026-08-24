# Incomplete-remediation20g GHSA mining (grok46-low)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Same keyword ranking as incomplete-remediation20 through 20f. Shared tracked files were not edited. No commit, push, or credential output.

## Freeze

Candidate list was frozen in `work/selected-20.jsonl` (SHA-256 `6559d200404a07b32f32f4b60b85ac8abeb8d965e940538f9873bf927fed4a20`) before deep review.

Method: same frozen advisory-database and keyword weights as incomplete-remediation20; github-reviewed 2025-2026 first-party GHSA JSON; non-withdrawn; first-party `/security/advisories/GHSA-...` URL matching the identity; exclude incomplete-remediation20/20b/20c/20d/20e/20f selected-20, canonical81, directroot selected/cases through batch24, and every prior `herdr-260813-ghsa200-*` / `herdr-260814-ghsa200-*` packet identity; rank by keyword score, then clone presence, published, id; take the next 20. No rerank or widen. Overlap with excluded set: empty. Overlap with sibling selected-20 through 20f: empty. Remaining keyword-ranked identities: 108 UNREVIEWED, not REJECT.

Conservation: selected=20, reviewed=20, unreviewed=108. Prior remaining queue was 128; 20g keyword hits=128; 20+108=128. Selected IDs equal the first twenty of 20f `unreviewed_keyword_ids`.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Old-bug siblings, later AI review, squash transfer, unreleased attempts, OSV routing, and broad shared fixes without per-mechanism reversal fail.

## Verdict

Twenty frozen identities were deeply reviewed. Zero closed all seven gates plus `remediation_patch_delta`.

Closest misses were AI origin rem or human incomplete priors, not AI patch-delta:

- GHSA-VRQM: pdfme Claude-coauthored rem 8c3b6a71 is origin rem of the named decompression bomb; follow-up 41dffae8 is an IPv6 SSRF sibling.
- GHSA-96QW: shakapacker Claude-coauthored rem 3e06781b introduces the first allowlist for a 2017 leak.
- GHSA-66M2: Claude-authored rem ff0fdc06 is origin rem of the symlink deny hole.
- GHSA-GGPF: vLLM `weights_only=True` residual of Russell Bryant human rem, not an AI guard.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 2 |
| REJECT | 18 |

BLOCKED rows lack a local clone. Missing evidence is not a factual FAIL: unproved causal gates and `remediation_patch_delta` are encoded `BLOCKED`, with `identity_gate` PASS from the first-party GHSA object. They are not REJECT of the mechanism and are not unreviewed.

## Claim boundary

Countable PASS requires all seven gates, patch-delta, and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim.
