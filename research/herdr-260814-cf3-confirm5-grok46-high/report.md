# CF3 confirm5 independent closure

Verdict-first: **0 PASS_PROPOSAL**. All five foundation CONFIRM-but-not-strict rows stay **NARROW**. Conservation **5=5+0**. Canonical86 strict count remains **86**. Publication **HOLD**. Worker PASS is proposal-only; this packet emits none.

Canonical86 is exclusion/authority. Foundation CONFIRM, fp211, and older closure packets are hypotheses, not inherited verdicts. `release_gate=NA` is not PASS (`na_fails`). Commit-only or unresolved released containment is not strict.

Assigned universe (exact five, no padding):

| Order | ID | Repo | Why not strict |
|---|---|---|---|
| 1 | GHSA-G8MR-85JM-7XHM | vitest-dev/vitest | same-first-tag v3.2.5 |
| 2 | GHSA-M63V-2G9W-2W6V | fission/fission | member not a tag ancestor; v1.24.0 already equals closer |
| 3 | GHSA-P5RM-JG5C-8C77 | microsoft/kiota | member not a tag ancestor; v1.34.0 already equals closer |
| 4 | GHSA-X2W7-XR2G-QHJR | ArnasDon/wacrm | unreviewed identity; 0 tags; sibling meta-send not named engine |
| 5 | GHSA-X8QQ-M4QC-RPJ5 | Roskus/prospero-flow-crm | unreviewed identity; same-first-tag v5.5.3 |

## GHSA-G8MR-85JM-7XHM

Identity PASS: github-reviewed first-party GHSA for vitest-dev/vitest / `@vitest/browser`.

AI hunk PASS: atomic Codex `af88b1f5` adds `canWrite()` on `packages/browser/src/node/rpc.ts` (blob `358ac355`). Topology PASS: parent_count=1 and it is the parent of official closer `385a1aef`.

Scoped but-for / fix-reversal PASS at commit scope under patch-delta incomplete rem: GHSA names ungated `cdp()` after `allowWrite`/`allowExec` were added; closer adds `assertCdpAllowed` on `sendCdpEvent`/`trackCdpEvent` (blob `72818584`).

Release NARROW: v3.2.4 blob equals pre-candidate `7619c5f0`. v3.2.5 contains candidate and closer. `tag --contains cand --no-contains fix` is empty. npm `@vitest/browser` 3.2.4 and 3.2.5 both exist. No published residual of allowWrite without the CDP gate.

Uniqueness PASS: not in canonical86 strict 86.

## GHSA-M63V-2G9W-2W6V

Identity PASS: github-reviewed first-party GHSA for fission/fission.

AI hunk PASS: atomic Claude member `2db76f65` adds `ValidatePodSpecSafety` (`podspec_safety.go` blob `af473d26`). Carrier squash `e484df84` shares parent `8fa79941` and is also Claude-marked. Authorship is not transferred from member to carrier.

Topology NARROW: member is not an ancestor of closer `695d3e97`, carrier, or v1.24.0. `tag --contains member` is empty.

But-for / fix-reversal PASS at commit scope: GHSA is standalone `Runtime.Container`/`Builder.Container` SecurityContext bypass of the PodSpec denylist; closer extracts `ValidateContainerSafety` (count 0/0/4 on member/carrier/closer) and calls it from `Environment.Validate`.

Release NARROW: v1.23.0 lacks the file. v1.24.0 peel `ce617120` equals proxy.golang.org Origin.Hash and blob `1d7219e7` equals the complete closer. Same-first-tag complete closer. Commit-only residual is not strict.

Uniqueness PASS: distinct from counted GHSA-QF5V-M7P4-95RP. Shared squash SHA is not duplication. Canonical86 explicitly does not count M63V.

## GHSA-P5RM-JG5C-8C77

Identity PASS: github-reviewed first-party GHSA for microsoft/kiota / Microsoft.OpenApi.Kiota.

AI hunk PASS: atomic Copilot member `f51f4971` adds percent-decode to `IsSafeFileReference` (blob `782a03f5`). Carrier squash `de3d18d9` shares parent `2350f233` and the same blob. Member is not an ancestor of the carrier.

Topology NARROW: member is not an ancestor of v1.33.0, v1.34.0, or closer `430008e9`. `tag --contains member` is empty.

But-for / fix-reversal PASS at commit scope: GHSA names residual NUL/homoglyph/fail-open bypasses of that decoder; closer blob `1b62b653` amends the same function.

Release NARROW: v1.33.0 blob `1391bf0c` is the older raw-string validator (no percent-decode). v1.34.0 equals the closer. NuGet lists 1.33.0 and 1.34.0. No published residual of the incomplete decoder. Commit-only residual is not strict.

Uniqueness PASS: not in canonical86 strict 86.

## GHSA-X2W7-XR2G-QHJR

Identity NARROW: local advisory is unreviewed (`github_reviewed=false`, `affected=[]`). Text names merge `73041bf`, not AI SHA `4afa9bea`.

AI hunk FAIL / but-for FAIL / fix-reversal FAIL for the named engine mechanism: Claude `4afa9bea` only edits `src/lib/automations/meta-send.ts` (user_id filter on WhatsApp send). Closer `b4f18537` (merged by `73041bf`) amends `engine.ts` `account_id` ownership. `engine.ts` blob is unchanged across the AI commit (`1a131fa0`). Patch-delta requires the later fix to amend the AI-added boundary; it does not. Topology PASS: atomic ancestor of the closer.

Release NARROW: local tag count 0; `git ls-remote --tags origin` empty. Commit-only is not strict.

Uniqueness PASS: not in canonical86 strict 86.

## GHSA-X8QQ-M4QC-RPJ5

Identity NARROW: local advisory is unreviewed (`github_reviewed=false`, `affected=[]`).

AI hunk / topology / but-for / fix-reversal PASS at commit scope as direct root: Claude `56ea64c8` adds `Order::find($id)`; Claude `86f40651` adds `Item::find($id)`; closer `9a859c4d` adds `company_id` scope. Both candidates are ancestors of the closer.

Release NARROW: v4.6.0 lacks the files. v5.5.3 OrderReadController blob `d2e097de` equals the closer. First containing tag of candidates and closer is v5.5.3. Same-first-tag. Commit-only residual is not strict.

Uniqueness PASS: distinct from GHSA-4FXP-2M36-QV64 (canonical86 NARROW noncounting, different mechanism). Shared repo is not duplication.

## Hygiene

No durable pages, clones, packages, or caches in this directory. Registry probes used mktemp and were deleted. Existing clones were read-only. Replay is fail-closed: it drops only the known harmless `error: unable to normalize alternate object path:` line from the fission clone's broken alternates and fails on any other git stderr. No credentials. No GitHub REST/GraphQL. No edits outside the owned directory. No commit or push. ASCII English only.
