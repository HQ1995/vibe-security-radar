# Incomplete-remediation20l GHSA mining (grok46-high)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Same keyword ranking as incomplete-remediation20 through 20k. Shared tracked files were not edited. No commit, push, or credential output.

## Freeze

Candidate list was frozen in `work/selected-20.jsonl` (SHA-256 `58f0c8b701202ed3a3d9ffb7f4d94b69c94e718b665dae57fe23ba9ea0fa08c8`) before deep review.

Method: freeze exactly the first 20 IDs, in order, from incomplete-remediation20k `work/freeze.json` `unreviewed_keyword_ids`. Reconstruct full selection rows from the same frozen advisory-database and the same keyword ranking fields as 20k. Assert exact ID equality to that prefix. Leader-verified zero overlap with the true final directroot queue. Remaining eight IDs stay UNREVIEWED, not REJECT. No rerank or widen.

Conservation: selected=20, reviewed=20, unreviewed=8. Prior remaining queue was 28; 28 = 20 + 8.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Old-bug siblings, later AI review, squash transfer, unreleased attempts, OSV routing, and broad shared fixes without per-mechanism reversal fail.

## Verdict

Twenty frozen identities were deeply reviewed. Zero closed all seven gates plus `remediation_patch_delta`. No PASS proposal for independent red-team.

Closest miss was human incomplete-remediation shape, not AI patch-delta:

- GHSA-53Q9: `torch.load(weights_only=True)` could still RCE via `legacy_load`. The weights_only boundary and rem 0eda02a9/8d4b8a92 are Mikayla Gawarecki / pytorchbot, not an AI-authored residual.
- GHSA-528Q: go-httpbin rem 0decfd1a is Will McCutchen origin rem adding a Content-Type allowlist, not a later residual of an AI allowlist.
- Remaining scanned rows are unmarked human origin rem (Simon, Ville Vesilehto, Yashodhan Joshi, Akhil Narang, Brainslug, Frost Ming, Sachin D. Shinde, Julian Wiedmann, Mike Dalessio). Later Claude/Cursor hits on flarum, frappe, directus, bentoml, apollo-router, pytorch, and cilium are sibling paths, not residual of the named rem.

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
