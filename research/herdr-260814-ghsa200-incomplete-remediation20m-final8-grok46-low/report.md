# Incomplete-remediation20m-final8 GHSA mining (grok46-low)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200. No PASS row exists for independent red-team.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Same keyword ranking as 20k. Shared tracked files were not edited. No commit, push, or credential output.

## Freeze

Candidate list was frozen in `work/selected-8.jsonl` (SHA-256 `33d8ace133a97deecb052d299a7e6a1d19e4a7d09a073e01f4e816852cdb9206`) before deep review.

Method: reconstruct 20k ranking from frozen 20k `exclusion-ids.txt` and the same advisory-database HEAD; take ranked[40:48], which equals 20k `unreviewed_keyword_ids` positions 21 through 28. Assert exact ID equality to that suffix. Do not inspect or adjudicate the first twenty remaining IDs (reserved for 20l). Replay does not read 20l artifacts. Leader-verified zero overlap with the true final directroot queue. No rerank or widen.

Conservation: after 20k, 28 remaining = 20 reserved for 20l + these final 8. Overall prior 48 = 20k reviewed 20 + 20l assigned 20 + final 8. This shard selected=8, reviewed=8, unreviewed=0. Keyword hits remain 48.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Old-bug siblings, later AI review, squash transfer, unreleased attempts, OSV routing, and broad shared fixes without per-mechanism reversal fail.

## Verdict

Eight frozen identities were deeply reviewed. Zero closed all seven gates plus `remediation_patch_delta`.

Closest misses were human origin rem, not AI patch-delta:

- GHSA-PJ3V: trpc rem 9beb26c6 is Luke Childs origin rem stopping a rethrow of handled connectionParams errors.
- GHSA-8H6M: rancher rem 7f16b596 is Jonathan Crowther origin rem adding BackingNamespace.
- GHSA-PJR6: nextjs-auth0 rem a4f061ae is Frederik Prijck origin rem setting JWE expiration.
- GHSA-6Q9C: vet rem 0ae3560b is Arunanshu Biswas origin rem adding Host/Origin guards.
- GHSA-JR5F: axios rem fb8eec21 / 02c3c69c are human origin rem for allowAbsoluteUrls.
- GHSA-8P83: rancher rem 08f4cff3 is Jonathan Crowther origin rem narrowing Restricted Admin user verbs.
- Later Claude hits on trpc (docs), rancher (EKS import), vet (agentic query / other PRs), and axios (redirect headers) are siblings, not same-boundary residuals.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 2 |
| REJECT | 6 |

BLOCKED rows lack a local clone (strawberry-graphql/strawberry, awslabs/tough). Missing evidence is not a factual FAIL: unproved causal gates and `remediation_patch_delta` are encoded `BLOCKED`, with `identity_gate` PASS from the first-party GHSA object. They are not REJECT of the mechanism and are not unreviewed.

## Claim boundary

Countable PASS requires all seven gates, patch-delta, and leader admission. Proposed PASS: 0. Publication remains HOLD. Greater-than-200 remains HOLD. This packet does not change the canonical count.
