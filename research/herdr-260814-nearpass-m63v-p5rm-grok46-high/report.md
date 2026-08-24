# Hostile near-pass: GHSA-M63V and GHSA-P5RM

**NARROW both.** Countable PASS remains 0. Packet delta 0. Canonical94 stays **94 HOLD**. Conservation `2=2+0`.

This is an independent hostile seven-gate replay of two near-pass incomplete-remediation hypotheses. `herdr-260814-cf3-confirm5-grok46-high` and `herdr-260814-nearpass-next10-grok46-medium` are routing only and are not evidence. Inherited PASS/NARROW labels are not proof. Worker PASS is proposal only; this packet emits none. A merge SHA is not an atomic origin. A git tag is not a release unless a Go module or NuGet nupkg contains it.

Assigned exactly GHSA-M63V-2G9W-2W6V and GHSA-P5RM-JG5C-8C77. Did not pad.

## GHSA-M63V-2G9W-2W6V

First terminal failure: **topology_gate**.

Identity PASS. GitHub-reviewed first-party GHSA-m63v-2g9w-2w6v on fission/fission is published, not withdrawn, and aliases CVE-2026-50566. Global catalog and advisory-database OSV name Go module `github.com/fission/fission`, last known affected `<= 1.23.0`, fixed `1.24.0`. The mechanism is standalone `Runtime.Container` / `Builder.Container` SecurityContext bypass of the round-4 PodSpec denylist. Advisory-database JSON sha256 `8d44b004900cb4a07a927ff305e871f90b1144e0f686a6045ef97720f220b42a`.

AI hunk PASS at the hypothesized member. `2db76f65` is `n_parents=1`, parent `8fa79941`. MATCHER_CONTRACT `coauthor_trailer` / `claude_code` matches Claude Opus 4.7. Parent has no `podspec_safety.go`. The member adds `ValidatePodSpecSafety` (blob `af473d26`) and calls it from `Environment.Validate` on PodSpec fields only. `ValidateContainerSafety` count is 0. `MergeContainer` does not sanitize.

Topology NARROW. The member is not an ancestor of squash `e484df84`, closer `695d3e97`, `v1.23.0`, or `v1.24.0`. `tag --contains` member is empty. PR 3391 head is `c9ed98a1`, a four-commit branch after `8fa79941`. GitHub squash `e484df84` is `n_parents=1` with committer GitHub and the same parent, but podspec blobs `af473d26` / `330fccee` / `1d7219e7` are three-way unequal. Counting the squash would transfer the member and later PR commits. The advisory names `e484df84` as the round-4 fix this GHSA bypasses and does not name `2db76f65`. Canonical94 already counts `e484df84` for GHSA-QF5V (SYS_TIME omission). Shared SHA is not this Container mechanism and is not used to close topology.

But-for PASS at commit scope under the incomplete-remediation patch-delta rule. The member introduces the PodSpec denylist that omits standalone Container. OSV `introduced=0` is not causal proof. Parent Claude trailers are not this hunk.

Fix-reversal PASS at commit scope. Closer `695d3e97` (`#3406`, GitHub squash, Claude-marked) names GHSA-m63v and adds `ValidateContainerSafety` (count 4) plus `MergeContainer` sanitizer. AI-on-fix is not origin. Fix parent blob `d3c61896` still lacks `ValidateContainerSafety`.

Release NARROW. proxy.golang.org `v1.23.0` Origin.Hash `710d8431` equals git peel; the zip has zero `podspec_safety.go`. `v1.24.0` Origin.Hash `ce617120` equals git peel; zip bytes equal closer blob `1d7219e7` with `ValidateContainerSafety` count 4. `tag --contains` squash `--no-contains` closer is empty. Same-first-tag complete closer. No Go module contains the member or the incomplete squash blob without the closer. A tag without that zip match would not have been enough.

Uniqueness PASS. Absent from canonical94 strict 94. Distinct from counted GHSA-QF5V-M7P4-95RP. CVE alias is not a counting unit.

## GHSA-P5RM-JG5C-8C77

First terminal failure: **topology_gate**.

Identity PASS. GitHub-reviewed first-party GHSA-p5rm-jg5c-8c77 on microsoft/kiota is published, not withdrawn, and has no CVE alias. OSV names NuGet `Microsoft.OpenApi.Kiota`, last known affected `<= 1.33.0`, fixed `1.34.0`. The mechanism is residual bypass of `IsSafeFileReference` after percent-decode (NUL / fail-open / homoglyph). Advisory-database JSON sha256 `1ed6f5bf2ae6f480ba0a11fdbedc31abf6a355895c403a337347e34b11905753`.

AI hunk PASS at the hypothesized member. `f51f4971` is `n_parents=1`, parent `2350f233`. MATCHER_CONTRACT `coauthor_trailer` / `github_copilot` matches Copilot. Parent matcher is empty. Parent/v1.32.5/v1.33.0 blob `1391bf0c` is the raw validator. The member adds bounded percent-decode (blob `782a03f5`).

Topology NARROW. The member equals PR 7910 head and is not an ancestor of squash `de3d18d9`, closer `430008e9`, `v1.33.0`, or `v1.34.0`. `tag --contains` member is empty. GitHub squash `de3d18d9` is `n_parents=1` with committer GitHub, the same parent, and the same blob. Blob-equal squash is not member-to-tag ancestry. The advisory references `de3d18d9` and `430008e9` and does not name `f51f4971`. Transfer is refused.

But-for PASS at commit scope under patch-delta. The member rewrites the validator with decode and still omits NUL fail-closed and NFKC folding. Closer `430008e9` amends that same function.

Fix-reversal PASS at commit scope. Closer is `n_parents=1` GitHub squash of PR 7913, parent `de3d18d9`, Copilot-marked, blob `1b62b653`. AI-on-fix is not origin.

Release NARROW. NuGet 1.33.0 nupkg sha256 `b1e83319c5737de9f8009ca53f9cc81cb2ea3d00c944cfba0861558f41bf6465` repository commit `f4fe1db0` equals tag `v1.33.0`; `Kiota.Builder.dll` has `IsSafeFileReference` and lacks `MaxPercentDecodePasses`. NuGet 1.34.0 nupkg sha256 `2176337844ba0b6328d949a39a7600f211fc591d60671db1e4fcde6aa5398a8e` commit `9d4f80e2` equals `v1.34.0`; the DLL has `MaxPercentDecodePasses` and git blob `1b62b653` equals the closer. `tag --contains` squash `--no-contains` closer is empty. Same-first-tag complete closer. No nupkg contains incomplete blob `782a03f5` without the closer.

Uniqueness PASS. Absent from canonical94 strict 94.

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical94. Publication and more-than-200 stay HOLD.
