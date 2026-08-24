# GHSA-QF5V-M7P4-95RP red-team -- KEEP proposal

Independent hostile review of exactly one hypothesized `AI_INCOMPLETE_REMEDIATION` admission for `fission/fission`. Prior medium5 NARROW, incomplete-rem NARROW, fp211 CONFIRM/MEDIUM, and confirm11 PASS rows were read only as hypotheses. Verdict is KEEP as a proposal. Countable remains false until leader admission. Publication and more-than-200 remain HOLD. canonical81 is not rebuilt.

Reviewed: 1. Unreviewed: 0. KEEP proposal: 1. NARROW: 0. REJECT: 0. BLOCKED: 0.

## Verdict

**KEEP (proposal).** An atomic Claude-marked GitHub squash authored the released six-capability denylist that omits `SYS_TIME`. The hypothesized member SHA is not that commit.

Counted atomic commit: squash `e484df8460bb4e8026e24210120602aa7f181f64` (PR 3391 merge, parent `8fa799417c77ce8a0189d9858bfe11ece29b84a6`, parent_count=1). Trailer `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`. First parent has no `pkg/apis/core/v1/podspec_safety.go`. The squash first-parent-introduces `dangerousCapabilities` and `dangerousMergeContainerCapabilities` as the six-cap denylist named by first-party GHSA-qf5v.

Hypothesized member `2db76f65dbfe4f657b4a4efb506ed63b24623e92` is a Claude-marked PR 3391 member on the same parent. It is not an ancestor of the squash, `v1.24.0`, or `v1.25.0`. Contract topology forbids transferring that member trailer onto a different blob. The member binding is rejected. The squash carries its own marker and is the landed hunk.

Minimum fix `2569b42bfadbcb7d78b55a00a60f77937e522699` (PR 3465) replaces `dangerousCapabilities` with `allowedCapabilities = {NET_BIND_SERVICE}` and is an ancestor of `v1.25.0`. Fix-parent file blobs equal the `v1.24.0` blobs.

## Hostile attacks

1. **Older hole: SYS_TIME was already addable, so incomplete rem fails.** Does not kill. Parent `8fa79941` and tag `v1.23.0` have no `podspec_safety.go`. The GHSA names the omitted token inside the AI-added six-cap map, not an untouched sibling CRD field. User-approved incomplete-remediation rule: do not reject solely because the residual pre-existed. Closer `2569b42b` amends that same map to an allowlist covering `SYS_TIME`.

2. **Member is not a v1.24.0 ancestor; authorship transfer onto a different carrier blob.** Fatal for the hypothesized member binding. Not fatal for the counted squash. Member `2db76f65` is not a tag ancestor. Squash `e484df84` is a `v1.24.0` and `v1.25.0` ancestor, single-parent, Claude-marked, and first-parent-introduces the file. PR 3391 has four members; all four are Claude-marked. Member-to-squash `podspec_safety.go` delta is `DeprecatedServiceAccount` only. The six-cap map is unchanged.

3. **Three-way blob inequality of podspec_safety.go.** True and not fatal for the map hunk. Blobs: member `af473d26`, squash `330fccee`, `v1.24.0` `1d7219e7`. Intervening rewrites: SPDX header `ae88c0f7` (PR 3400) and `ValidateContainerSafety` extract `695d3e97` (PR 3406 / GHSA-M63V). The `dangerousCapabilities` map block is byte-identical across member, squash, and `v1.24.0` (SHA-256 `9239b6f536c89ee73bd060a22a5e0cead606da23c6820e3ff35960d39038cb09`). Blame of that map at `v1.24.0` is `e484df84`. Merge-layer map and lookup at `v1.24.0` also blame `e484df84`. The AI patch-delta is tied to the released hunk.

4. **Reverting the denylist reopens a broader old vulnerability.** Does not kill this class. Rollback of `e484df84` would restore HostNetwork/privileged/SYS_ADMIN as well as SYS_TIME. Contract: that is not a failure when the AI patch explicitly attempted this capability boundary and the GHSA residual/fix directly amend it.

5. **Cited tags are prerelease, wrong branch, or lack exact containment.** Does not kill. Lightweight tag `v1.24.0` peels to `ce617120c41b9e4a51d577f81b441238264e88fd`. GitHub Release is `draft=false`, `prerelease=true`, published 2026-05-26 with binaries. `proxy.golang.org` module `github.com/fission/fission@v1.24.0` Origin.Hash equals that peel. First-party GHSA range is `<= 1.24.0` patched `1.25.0` and names tag `ce617120`. Tag `v1.25.0` peels to `ae970aaa9bc76ec93d748bdaf03fd7523b6b6a62`, GitHub Release is not a prerelease, Go module hash matches, file blob equals fix `43e361d3`. Fix-parent blobs equal `v1.24.0`. Squash is in `v1.24.0` without the fix; fix is in `v1.25.0`.

6. **Earlier packet already counts this GHSA/mechanism.** Does not kill. Absent from canonical81 `strict_released_case_ids` (81). Publication label is INCONCLUSIVE with fp211 admission HOLD. medium5 and incomplete-rem NARROW are uncounted. GHSA-M63V shares squash ancestry and is a different first-party identity (standalone Container SecurityContext, closer `695d3e97`). Shared SHA does not merge cases. CVE-2026-50570 is not a counting unit.

7. **First-party GHSA identity, package, or repository mapping is wrong.** Does not kill. Global GHSA `type=reviewed`, `withdrawn_at=null`, `source_code_location=https://github.com/fission/fission`, Go package `github.com/fission/fission`, alias CVE-2026-50570. Repo advisory `state=published`, same `ghsa_id`. Independent raw fetch of github/advisory-database returned HTTP 404; identity uses the first-party GitHub advisory APIs.

## Gates

| Gate | Result |
|---|---|
| identity_gate | PASS |
| ai_hunk_gate | PASS |
| topology_gate | PASS |
| but_for_gate | PASS |
| fix_reversal_gate | PASS |
| release_gate | PASS |
| uniqueness_gate | PASS |
| remediation_patch_delta_gate | PASS |

## Ancestry (proved, not admitted)

First public Go module and git tag containing the incomplete six-cap map and excluding the allowlist: `v1.24.0`. First public Go module and git tag containing the allowlist: `v1.25.0`. Member `2db76f65` is not on that line.

## Hold

This packet proposes KEEP. It does not admit the case and does not change the canonical count. canonical81 remains 81. The leader must independently replay before any ledger rebuild. Publication and more-than-200 remain HOLD.
