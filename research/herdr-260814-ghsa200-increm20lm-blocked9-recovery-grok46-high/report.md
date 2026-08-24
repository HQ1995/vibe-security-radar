# Incomplete-remediation20l/20m blocked-nine recovery (grok46-high)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Canonical81 summary SHA-256 `dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c`. Source 20l selected-20 SHA-256 `58f0c8b701202ed3a3d9ffb7f4d94b69c94e718b665dae57fe23ba9ea0fa08c8`. Source 20m selected-8 SHA-256 `33d8ace133a97deecb052d299a7e6a1d19e4a7d09a073e01f4e816852cdb9206`. Shared tracked files, canonical81, and prior packets were not edited. No commit, push, or credential output.

## Assignment

Exactly nine identities, taken from `autoresearch/herdr-260814-ghsa200-incomplete-remediation20l-grok46-high/cases.jsonl` and `autoresearch/herdr-260814-ghsa200-incomplete-remediation20m-final8-grok46-low/cases.jsonl` where those source packets encoded `BLOCKED` / `NO_LOCAL_CLONE`. Source rows are routing only.

1. GHSA-44F7-5FJ5-H4PX
2. GHSA-C98H-7HP9-V9HQ
3. GHSA-HXG4-65P5-9W37
4. GHSA-J8X2-777P-23FC
5. GHSA-7RMP-3G9F-CVQ8
6. GHSA-7MPV-9XG6-5R79
7. GHSA-7M6V-Q233-Q9J9
8. GHSA-5XH2-23CC-5JC6
9. GHSA-76G3-38JV-WXH4

Conservation: assigned = 9, reviewed = 9, unreviewed = 0. Prior gates were not trusted except those exact IDs and first-party advisory repository routing. Official repositories were resolved from the frozen github-reviewed GHSA objects and cloned read-only under `/home/hanqing/.cache/ghsa200-worker-clones/recovery20lm-260814/`. All eight unique repositories were obtained. The two `awslabs/tough` identities share one clone and remain distinct.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Human prior patches, old sibling holes, later AI review, carrier transfer, unreleased attempts, and OSV routing fail. PASS requires all seven gates PASS plus `remediation_patch_delta` PASS. Missing evidence stays BLOCKED and is not converted to FAIL. Same-repo identities remain distinct unless first-party alias and mechanism equality prove duplication.

## Verdict

All nine identities are now git-replayable. None close the incomplete-remediation pattern. Causal gates are FAIL, not BLOCKED: absence of an AI-marked security-attempt hunk is proved on the relevant history.

| Identity | Repository | Worker verdict | Reject class |
|---|---|---|---|
| GHSA-44F7-5FJ5-H4PX | ratify-project/ratify | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-C98H-7HP9-V9HQ | metal3-io/baremetal-operator | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-HXG4-65P5-9W37 | Sylius/PayPalPlugin | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-J8X2-777P-23FC | awslabs/tough | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-7RMP-3G9F-CVQ8 | jhipster/generator-jhipster-entity-audit | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-7MPV-9XG6-5R79 | apollographql/apollo-rs | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-7M6V-Q233-Q9J9 | minio/operator | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-5XH2-23CC-5JC6 | strawberry-graphql/strawberry | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-76G3-38JV-WXH4 | awslabs/tough | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |

### GHSA-44F7-5FJ5-H4PX

First-party reviewed GHSA for Go `github.com/ratify-project/ratify`, alias CVE-2025-27403. GHSA `source_code_location` remains `https://github.com/ratify-project/ratify` (live GitHub `full_name` is `notaryproject/ratify`). Cited rem `0ec0c08490e3` is single-parent Binbin Li adding ACR domain suffix checks in `azure/helper.go`. Tag `v1.2.2` `azureidentity.go` blob `9e5ee011` equals the closer parent. Tag `v1.2.3` blob `6f366e40` equals the closer. Sister rem `84c7c48fa76b` is the same human subject on the 1.3 line (`v1.3.1` parent blob, `v1.3.2` closer). Precise trailer scan of `v1.2.3` and `v1.3.2` is empty. Origin rem of the original missing ACR host check.

### GHSA-C98H-7HP9-V9HQ

First-party reviewed GHSA for Go `github.com/metal3-io/baremetal-operator/apis`, alias CVE-2025-29781. Cited rem `19f8443b1fe1` is Tuomo Tanskanen merge of member `84798044692b` Lennart Jern restricting `HTTPHeadersRef` to the same namespace. Tag `v0.8.0` and `v0.9.0` `bmceventsubscription_validation.go` blob `1aefae1b` equals the merge first-parent. Tag `v0.8.1` peels to cherry-pick `ea8528e73bf9`; `v0.9.1` peels to `bcda0f0f25bd`. All closers share blob `e4e8c209`. Precise trailer scan of `v0.8.1` and `v0.9.1` is empty. Origin rem of the original cross-namespace Secret load.

### GHSA-HXG4-65P5-9W37

First-party reviewed GHSA for Packagist `sylius/paypal-plugin`, alias CVE-2025-30152. Cited rem `5613df827a6d` is Grzegorz Sadowski adding `verify()` amount checks in `PayPalOrderCompleteProcessor.php`. Tag `v1.6.1` processor blob `5eaaaf22` equals the closer parent. Tag `v1.6.2` peels to `5613df827a6d`. Precise trailer scan of `v1.6.2`, `v1.7.2`, and `v2.0.2` is empty. Origin rem of the original post-checkout cart mutation.

### GHSA-J8X2-777P-23FC

First-party reviewed GHSA for crates.io `tough` (no CVE). Cited rem `c5ee1718e630` is Martin Harriman detecting cyclic or redundant TUF delegations in `tough/src/lib.rs` only. Tag `tough-v0.19.0` does not contain the rem. Tag `tough-v0.20.0` does. Distinct from GHSA-76G3. Full-clone precise trailer scan is empty. Origin rem of the original cycle hole.

### GHSA-7RMP-3G9F-CVQ8

First-party reviewed GHSA for npm `generator-jhipster-entity-audit`, alias CVE-2025-31119. Advisory blob `e21e83135d10` is dependabot `javers-core` bump, not the rem. Actual rem `eb00a2442d05` is Marcelo Shima replacing `Class.forName` with `AuditedEntity`. Tag `v5.9.0` `JaversEntityAuditResource.java.ejs` blob `c4623708` equals the closer parent. Tag `v5.9.1` blob `f852640c` equals the closer. Full-clone precise trailer scan is empty. Origin rem of the original unsafe reflection hole.

### GHSA-7MPV-9XG6-5R79

First-party reviewed GHSA for crates.io `apollo-compiler`, alias CVE-2025-31496. GHSA cites PR 952. Merge `35f280cb5bdc` is Sachin D. Shinde rewriting named-fragment validation. Tag `apollo-compiler@1.26.0` `fragment.rs` blob `f554a003` equals the closer parent. Tag `apollo-compiler@1.27.0` blob `f6e7117c` equals the closer. Precise trailer scan of `apollo-compiler@1.27.0` is empty. Origin rem of the original once-per-spread validation DoS.

### GHSA-7M6V-Q233-Q9J9

First-party reviewed GHSA for Go `github.com/minio/operator`, alias CVE-2025-32963. Cited rem `d586294d526b` is Pedro Juarez setting TokenReview audience `sts.min.io` in `pkg/controller/sts.go`. Tag `v7.0.1` sts.go blob `9507095b` equals the closer parent. Tag `v7.1.0` blob `9cea54ab` equals the closer. Precise trailer scan of `v7.1.0` is empty. Origin rem of the original apiserver-audience hole.

### GHSA-5XH2-23CC-5JC6

First-party reviewed GHSA for PyPI `strawberry-graphql`, alias CVE-2025-22151. Cited rem `526eb82b7045` is Thiago Bellini Ribeiro closing relay node type confusion in `strawberry/relay/fields.py`. Tag `0.256.1` fields.py blob `347fd221` equals the closer parent. Tag `0.257.0` blob `3e0c77e2` equals the closer. Precise trailer scan of `0.257.0` is empty. Later `anthropics/claude-code-action` dependabot bumps are not ancestors of `0.257.0`. Origin rem of the original type-confusion hole.

### GHSA-76G3-38JV-WXH4

First-party reviewed GHSA for crates.io `tough`, alias CVE-2025-2888. Cited rem `9b400e1c8b7d` is Martin Harriman delaying timestamp cache until after snapshot rollback checks (`tough/src/lib.rs` plus `error.rs`). Distinct from GHSA-J8X2 (different SHA, files, and mechanism). Tag `tough-v0.19.0` does not contain the rem. Tag `tough-v0.20.0` does. Full-clone precise trailer scan is empty. Origin rem of the original cache-before-check hole.

## Uniqueness

None of the nine IDs is in canonical81 `strict_released_case_ids` (81). Canonical81 ledger has no hit. The only prior packet hits are the uncounted source 20l and 20m BLOCKED rows. Same-repo pair GHSA-J8X2 vs GHSA-76G3 remains distinct (cyclic delegation vs timestamp rollback cache). Shared closer author, shared repository, or shared `tough-v0.20.0` tag does not merge identities. No first-party alias plus mechanism equality proves duplication.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| REJECT | 9 |

## Claim boundary

Countable PASS requires all seven gates, patch-delta PASS, and leader admission. Proposed PASS: 0. Publication remains HOLD. Greater-than-200 remains HOLD. This packet does not support a greater-than-200 claim. Canonical81 was not rebuilt.
