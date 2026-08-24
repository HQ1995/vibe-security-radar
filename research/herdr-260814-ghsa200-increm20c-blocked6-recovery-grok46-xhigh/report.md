# Incomplete-remediation20c blocked-six recovery (grok46-xhigh)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Canonical81 summary SHA-256 `dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c`. Source 20c selected-20 SHA-256 `c4f91e54b68b28295d20ff1d468576ea9f2ca4874642b6e1df258cdace3fed6c`. Shared tracked files, canonical81, and prior packets were not edited. No commit, push, or credential output.

## Assignment

Exactly six identities, taken from `autoresearch/herdr-260814-ghsa200-incomplete-remediation20c-grok46-low/cases.jsonl` where the source packet encoded `BLOCKED` / `NO_LOCAL_CLONE`:

1. GHSA-3WGQ-H4FR-CWG5
2. GHSA-9R25-RP3P-H2W4
3. GHSA-XQ7P-G2VC-G82P
4. GHSA-5V93-9MQW-P9MH
5. GHSA-JG6F-48FF-5XRW
6. GHSA-2466-4485-4PXJ

Conservation: assigned = 6, reviewed = 6, unreviewed = 0. Prior gates were not trusted except those exact IDs and first-party advisory repository routing. Official repositories were resolved from the frozen github-reviewed GHSA objects and cloned read-only under `/home/hanqing/.cache/ghsa200-worker-clones/recovery20c-260814/` when obtainable.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Human prior patches, old sibling holes, later AI review, carrier transfer, unreleased attempts, and OSV routing fail. PASS requires all seven gates PASS plus `remediation_patch_delta` PASS. Missing evidence stays BLOCKED and is not converted to FAIL.

## Verdict

Five identities are now git-replayable. One repository remains unavailable. None close the incomplete-remediation pattern. Where a clone exists, causal gates are FAIL, not BLOCKED: absence of an AI-marked security-attempt hunk is proved. Where the clone still cannot be obtained, unproved causal gates stay BLOCKED.

| Identity | Repository | Worker verdict | Reject class |
|---|---|---|---|
| GHSA-3WGQ-H4FR-CWG5 | macropay-solutions/laravel-crud-wizard-free | BLOCKED | REPO_AND_CLONE_UNAVAILABLE |
| GHSA-9R25-RP3P-H2W4 | Guichaguri/crud-query-parser | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-XQ7P-G2VC-G82P | cryptocoinjs/base-x | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-5V93-9MQW-P9MH | open-web3-stack/open-runtime-module-library | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-JG6F-48FF-5XRW | cosmos/ibc-go | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-2466-4485-4PXJ | Robothy/local-s3 | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |

### GHSA-3WGQ-H4FR-CWG5

First-party reviewed GHSA for Packagist `macropay-solutions/laravel-crud-wizard-free`, not withdrawn, names file validation bypass and cites `5c268cc930ec23a2e6761878cc57c6bd1d1889d2`. Independent GitHub API, authenticated clone, org listing, and Packagist p2 all return 404 (`no packages here`). Repo-advisory and commit endpoints 404. Identity PASS from the frozen github-reviewed object and live global GHSA. uniqueness PASS from canonical81 census. Causal gates and patch-delta remain BLOCKED. Missing clone is not inferred FAIL.

### GHSA-9R25-RP3P-H2W4

First-party reviewed GHSA for npm `crud-query-parser`, alias CVE-2025-32020. The advisory names TypeORM `order`/`sort` SQL injection when no property filter is set, fixed by introducing field validation in 0.1.0. The allowlist wording is a consumer workaround (`filterProperties`), not a residual of an AI allowlist. Clone HEAD `aa3ec62c`. All 83 commits are Guilherme Chaguri. Tag `0.1.0` peels to `4dbc1bd6` (version bump). Field validation is `cace8910` `feat(typeorm): added field validation`, ancestor of `0.1.0`, not an ancestor of history bump `a0460104` (0.0.3). No AI trailer. Origin rem.

### GHSA-XQ7P-G2VC-G82P

First-party reviewed GHSA for npm `base-x`, alias CVE-2025-27611. Cited rem is PR 86. Merge `e4cb9b0b` is Kirill Fomichev of member `831716af` Steven Luscher, subject `Prohibit char codes that would overflow the BASE_MAP`. Tag `v5.0.0` = `125c2030` lacks the merge; `v5.0.1` = `b7b0cec5` contains it. `v4.0.1` and `v3.0.11` are Steven Luscher backports with no AI trailer. 159-commit clone has no AI trailer. Original decode-map hole, not AI incomplete rem.

### GHSA-5V93-9MQW-P9MH

First-party reviewed GHSA for crates.io `orml-rewards`. Cited closer `6720fcd9` is single-parent zjb0807, `update saturating calculation (#1016)`, replacing `as_u128()` with `saturated_into::<u128>()` in `rewards/src/lib.rs`. Closer blob `ab33f868` equals tag `v1.2.1`; parent blob `85e127d1` still panics on the cast. `v1.0.1` does not contain the closer. 889-commit clone has no AI trailer. Origin overflow rem.

### GHSA-JG6F-48FF-5XRW

First-party reviewed GHSA for Go `github.com/cosmos/ibc-go`. Cited closers: `59987d52` is tag `v8.6.1` (Gjermund Garaba, remove packet data remarshaling); `9869b3c6` is tag `v7.9.1` backport. `v8.6.0` `ibc_module.go` blob `2f91fb49` equals the closer parent; `v8.6.1` blob `2325bdf7` equals the closer. `git log v8.6.1` has zero Claude/Cursor/Copilot/anthropic trailers. Later Claude Fable 5 on `bf74b47` (2026-07-14 ratelimit) and Made-with Cursor on `8539ae3` (2026-03-19 v11 bump) are not ancestors of `v8.6.1` and do not rewrite the ack JSON boundary named by this GHSA. Origin rem.

### GHSA-2466-4485-4PXJ

First-party reviewed GHSA for Maven `io.github.robothy:local-s3-rest`. Cited closer `d6ed756` is single-parent Luo, `fix XML External Entity (XXE) Injection (#172)`. Tag `1.20` XmlUtils blob `67aab78b` / LocalS3 blob `b1b1c136` equal the closer parent; tag `1.21` blobs `e937b98b` / `f0d2c4e6` equal the closer. XmlUtils was introduced by human Fuxiang Luo `36e2504a`. 259-commit clone has no AI trailer. Distinct from GHSA-47QW, GHSA-V232, and GHSA-G6WM (shared closer SHA does not merge identities). Those siblings are also origin XXE rem of the same parser; an untouched sibling hole is not AI incomplete-remediation causality.

## Uniqueness

None of the six IDs is in canonical81 `strict_released_case_ids` (81). Canonical81 ledger has no hit. The only prior packet hit is the uncounted source 20c BLOCKED rows. GHSA-2466 remains a distinct first-party identity from GHSA-47QW / GHSA-V232 / GHSA-G6WM.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 1 |
| REJECT | 5 |

## Claim boundary

Countable PASS requires all seven gates, patch-delta PASS, and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim. Canonical81 was not rebuilt.
