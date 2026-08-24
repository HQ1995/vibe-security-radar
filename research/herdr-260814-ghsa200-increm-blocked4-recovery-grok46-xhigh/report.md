# Incomplete-remediation blocked-four recovery (grok46-xhigh)

**Status: TERMINAL. Proposed KEEP = 0. Countable PASS = 0. Publication HOLD.**

Worker KEEP is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Canonical81 summary SHA-256 `dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c`. Shared tracked files, canonical81, and prior packets were not edited. No commit, push, or credential output.

## Assignment

Exactly four identities, taken from `autoresearch/herdr-260814-ghsa200-incomplete-remediation20-grok46-low/cases.jsonl` where the source packet encoded `BLOCKED` / `NO_LOCAL_CLONE`:

1. GHSA-36H8-R92J-W9VW
2. GHSA-VQ63-8F72-F486
3. GHSA-R8GC-QC2C-C7VH
4. GHSA-47QW-CCJM-9C2C

Conservation: assigned = 4, reviewed = 4, unreviewed = 0. Prior gates were not trusted except those exact IDs and first-party advisory repository routing. Official repositories were resolved from the frozen github-reviewed GHSA objects and cloned read-only under `/home/hanqing/.cache/ghsa200-worker-clones/recovery-260814/` when absent.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Human prior patches, old sibling holes, later AI review, carrier transfer, unreleased attempts, and OSV routing fail. KEEP requires all seven gates PASS plus `remediation_patch_delta` PASS. Missing evidence stays BLOCKED and is not converted to FAIL.

## Verdict

All four identities are now git-replayable. None close the incomplete-remediation pattern. Causal gates are FAIL, not BLOCKED: the clones exist and the absence of an AI-marked security-attempt hunk is proved.

| Identity | Repository | Worker verdict | Reject class |
|---|---|---|---|
| GHSA-36H8-R92J-W9VW | italia/spid-aspnetcore | REJECT | NO_AI_GUARD_REWRITE |
| GHSA-VQ63-8F72-F486 | italia/cie-aspnetcore | REJECT | NO_AI_GUARD_REWRITE |
| GHSA-R8GC-QC2C-C7VH | DavidOsipov/PostQuantum-Feldman-VSS | REJECT | NO_AI_GUARD_REWRITE |
| GHSA-47QW-CCJM-9C2C | Robothy/local-s3 | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |

### GHSA-36H8-R92J-W9VW

First-party reviewed GHSA for NuGet `SPID.AspNetCore.Authentication`, not withdrawn. The advisory names `VerifySignature` loading only `nodeList[0]`. Cited closer `093efa2273f8a1e0481f678a0bfcd57fbdc7b029` is single-parent Daniele Giallonardo (`Co-authored-by` himself). Tag `3.3.0` XmlHelpers blob `e2de37f6` equals the closer parent; tag `3.4.0` blob `1370c197` equals the closer and adds `VerifyAllSignatures`. The 217-commit clone has no AI trailer. 2022 `dbf4518` is a human KeyDescriptor rem that still used `nodeList[0]`. Origin rem, not AI patch-delta.

### GHSA-VQ63-8F72-F486

First-party reviewed GHSA for NuGet `CIE.AspNetCore.Authentication`, distinct from the SPID package. Cited closer `e66b7f336ff5d4c69f95f197f27f3145f2484994` is single-parent Daniele Giallonardo and is tag `2.1.0`. Tag `2.0.4` blob `de31f043` still uses `nodeList[0]`. The 71-commit clone has no AI trailer. Shared advisory prose with GHSA-36H8 does not merge identities.

### GHSA-R8GC-QC2C-C7VH

First-party reviewed GHSA for PyPI `PostQuantum-Feldman-VSS`. It names inadequate Python `secure_redundant_execution` and lists last_affected `0.8.0b2` with no `first_patched_version`. The 420-commit clone has no AI trailer. Function text at `v0.8.0b2` and `v0.8.0b3` is identical (five executions, shuffle, 0-9ms delay). Later human `12cb6ec1` (2025-03-25, after publication) is not an ancestor of `v0.8.0b2` and still keeps the Python redundant executor. No AI-marked security attempt and no first-party closure.

### GHSA-47QW-CCJM-9C2C

First-party reviewed GHSA for Maven `io.github.robothy:local-s3-rest`. Cited closer `d6ed756ceb30c1eb9d4263321ac683d734f8836f` is single-parent Luo (`fix XML External Entity (XXE) Injection (#172)`). Tag `1.20` XmlUtils blob `67aab78b` equals the closer parent; `d6ed756` is `tags/1.21~3` and tag `1.21` blob `e937b98b` equals the closer. XmlUtils was introduced by human Fuxiang Luo `36e2504a`. The 262-commit clone has no AI trailer. Original human XXE rem, not a residual of an AI sanitizer.

## Uniqueness

None of the four IDs is in canonical81 `strict_released_case_ids` (81). Canonical81 ledger has no hit. The only prior packet hit is the uncounted source BLOCKED rows. GHSA-36H8 and GHSA-VQ63 remain distinct first-party identities.

## Counts

| Worker verdict | Rows |
|---|---:|
| KEEP (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| REJECT | 4 |

## Claim boundary

Countable KEEP requires all seven gates, patch-delta PASS, and leader admission. Proposed KEEP: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim. Canonical81 was not rebuilt.
