# Incomplete-remediation20g blocked-two recovery (grok46-medium)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Canonical81 summary SHA-256 `dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c`. Source 20g selected-20 SHA-256 `6559d200404a07b32f32f4b60b85ac8abeb8d965e940538f9873bf927fed4a20`. Shared tracked files, canonical81, and prior packets were not edited. No commit, push, or credential output.

## Assignment

Exactly two identities, taken from `autoresearch/herdr-260814-ghsa200-incomplete-remediation20g-grok46-low/cases.jsonl` where the source packet encoded `BLOCKED` / `NO_LOCAL_CLONE`:

1. GHSA-HMP7-X699-CVHQ
2. GHSA-3988-Q8Q7-P787

Conservation: assigned = 2, reviewed = 2, unreviewed = 0. Prior gates were not trusted except those exact IDs and first-party advisory repository routing. Official repositories were resolved from the frozen github-reviewed GHSA objects and cloned read-only under `/home/hanqing/.cache/ghsa200-worker-clones/recovery20g-260814/`.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Human prior patches, old sibling holes, later AI review, carrier transfer, unreleased attempts, and OSV routing fail. PASS requires all seven gates PASS plus `remediation_patch_delta` PASS. Missing evidence stays BLOCKED and is not converted to FAIL. AI origin rem without a residual patch-delta fails.

## Verdict

Both identities are now git-replayable. Neither closes the incomplete-remediation pattern. Causal gates are FAIL, not BLOCKED: absence of an AI-marked security-attempt hunk is proved. No object or clone remained unavailable.

| Identity | Repository | Worker verdict | Reject class |
|---|---|---|---|
| GHSA-HMP7-X699-CVHQ | argoproj/argo-events | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-3988-Q8Q7-P787 | team-alembic/ash_authentication | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |

### GHSA-HMP7-X699-CVHQ

First-party reviewed GHSA for Go `github.com/argoproj/argo-events`, alias CVE-2025-32445, not withdrawn. The advisory names unrestricted `mergo.Merge` of `EventSource`/`Sensor` `spec.template.container` (`corev1.Container`) as a host privilege escape, and cites PR 3528 / commit `18412293` with patched release `v1.9.6`.

Clone HEAD `b3af946b`. Cited closer `18412293` is single-parent Derek Wang, subject `fix: disable the capability of attaching any properties to the container (#3528)`. It replaces full-container merge with a restricted `Container` type and `ApplyToContainer`. That SHA is on `master`, not an ancestor of tag `v1.9.6`. Release-1.9 cherry-pick `061b4030` has the same author, subject, and `template.go` / `resource.go` blobs, and is an ancestor of `v1.9.6`. Tag `v1.9.5` = `7fc4271d`: `template.go` blob `b772e611` and `resource.go` blob `decc44eb` equal the closer parent. Tag `v1.9.6` = `80f59511`: blobs `70acab57` / `5e7a487f` equal the closer and the cherry-pick. 4014-commit clone has no AI trailer. Origin rem of the named merge hole, not residual of an earlier AI container allowlist.

### GHSA-3988-Q8Q7-P787

First-party reviewed GHSA for Hex `ash_authentication`, alias CVE-2025-32782, not withdrawn. The advisory names GET confirmation links auto-followed by email clients, and cites commit `99ea3897` with patched release `4.7.0`.

Clone HEAD `9bc11b94`. Cited closer `99ea3897` is single-parent Zach Daniel, subject `improvement: mitigate medium-sev security issue for confirmation emails (#968)`, adding `require_interaction?` and a compile-time warning that cites this GHSA. Tag `v4.6.4` = `f6d4a264`: `plug.ex` blob `7a65b47a` and `transformer.ex` blob `9119e0c6` equal the closer parent. Tag `v4.7.0` = `d9b0ca8f` contains the closer; blobs `141e590e` / `a76d50cc` equal it. `git log v4.7.0` has no AI trailer. Later Cursor co-author `5b729e8d` (2026-06-18 TOTP tenant opts) and a `claude.ai` mention in docs `de4932d3` (2025-05-30) are not ancestors of `v4.7.0` and are not this GET auto-click boundary. Origin rem, not AI incomplete rem.

## Uniqueness

Neither ID is in canonical81 `strict_released_case_ids` (81). Canonical81 ledger has no hit. The only prior packet hits are the uncounted source 20g BLOCKED rows. The two identities are distinct first-party GHSAs.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| REJECT | 2 |

## Claim boundary

Countable PASS requires all seven gates, patch-delta PASS, and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim. Canonical81 was not rebuilt.
