# fp211 unseen two-gate remainder (exact 5)

Verdict first: **0 PASS**. Five fp211 NARROW mechanism rows have exactly two non-PASS contract gates after canonical84 and every 2026-08-14 selected/cases packet exclusion, and they do not overlap the active unseen-twogate8 lane. This packet freezes exactly those five identities in ordinal order. Independent replay of every inherited PASS gate keeps every identity **NARROW**. Worker PASS is a proposal and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Scope

Deterministic input: fp211 NARROW rows whose non-PASS gate count is exactly two, after removing canonical84 counted identities and every 2026-08-14 selected/cases packet identity, and after leaving the unseen-twogate8 eight to that lane.

Leader mechanical exclusion because unseen-twogate8 already owns them:

- ord80 GHSA-RQPP-RJJ8-7WV8
- ord86 GHSA-7X5Q-8F6H-RJRC
- ord95 GHSA-G5CG-8X5W-7JPM
- ord98 GHSA-5GVR-V6QV-H5MM
- ord100 GHSA-C4M7-2GWP-VW76
- ord108 GHSA-WJHR-76VG-2HVC
- ord115 GHSA-MGXW-V6RH-WCV6
- ord124 GHSA-G353-MGV3-8PCJ

Frozen remainder, no padding or substitution:

1. ord187 GHSA-37MF-VQ43-5QP9 (identity+release)
2. ord189 GHSA-3FP5-V549-9V66 (but_for+release)
3. ord194 GHSA-QJPC-QF9M-XWMR (but_for+release)
4. ord196 GHSA-J4CX-JVQ7-79VM (but_for+release)
5. ord201 GHSA-JX5R-P82P-2P8M (identity+release)

Conservation: assigned mechanism rows = 5. Reviewed identities = 5. Unique countable cases = 0. selected.jsonl has 5 rows. cases.jsonl has 5 rows. Equation: 5=5+0.

Inherited fp211 PASS values are not proof. OSV routing, commit subject, AI-on-fix, CVE alias, shared SHA, and official page existence alone are insufficient. Member authorship is never transferred onto a squash/merge carrier. Incomplete remediation requires an explicit AI security attempt and a same-boundary patch delta.

## Per-case

### GHSA-37MF-VQ43-5QP9 (187, ChurchCRM/CRM) — NARROW

Identity NARROW. Repository advisory is published and names plugin ZIP PHP under the web root, aliased to CVE-2026-58409. Global GHSA 404. Packagist churchcrm/crm 404. Affected `<=7.3.3` includes `7.2.2`, which has no `PluginInstaller.php`.

Atomic Claude commit `095bf81b` (parent_count=1) first-parent-introduces `PluginInstaller.php` with `php` in `ALLOWED_EXTENSIONS`. AI-hunk PASS. But-for PASS for that new installer surface.

Topology NARROW. Member is not an ancestor of human squash `de417ffa` or of tags `7.3.0`/`7.3.3`. Installer blobs are three-way unequal: member `b79ef358`, carrier/`7.3.0` `bd4e0ec0`, `7.3.3` `332bdd42`. A Claude trailer on the squash is not a transfer.

Fix-reversal PASS: closer `1b4e2c70` names GHSA-37mf and equals `7.4.0` installer blob `c6157e53`, adding `.htaccess` deny while keeping `php` installable. Release NARROW because the AI member is not in the vulnerable tag. Uniqueness PASS versus canonical84.

### GHSA-3FP5-V549-9V66 (189, openclaw/openclaw) — NARROW

Identity PASS. Published repository advisory names npm `openclaw` and flock wrapper durable allow-always bypass, patched `2026.6.9`. Global GHSA 404.

AI-hunk NARROW. `8e41c118` is a human-authored GitHub squash whose subject is `fix: block side-effecting command wrappers [AI] (#87292)`. That is PR-title branding, not a Co-Authored-By trailer. The commit edits time/script unwrap on `DISPATCH_WRAPPER_SPECS` and does not add `unwrapFlockInvocation`. Parent has no flock token.

Topology PASS (direct atomic, no carrier). But-for NARROW: removing the time/script change leaves the named flock path. Incomplete-remediation patch-delta NARROW: flock is a sibling wrapper, not an omitted case inside the AI time/script unwrap. Fix-reversal PASS: `55d1324c` adds the named flock unwrap.

Release PASS on git tag plus GitHub Release: `v2026.6.6` contains the candidate and not the fix; `v2026.6.9` contains the fix; both GitHub Release objects exist and are not drafts. npm `gitHead` is null and is not used as binding. Uniqueness PASS.

### GHSA-QJPC-QF9M-XWMR (194, openclaw/openclaw) — NARROW

Identity PASS. Reviewed global GHSA and published repository advisory name trusted-proxy Control UI WebSocket client-declared scopes before pairing, patched `2026.5.18`.

AI-hunk NARROW. `0e702f10` subject is `[AI] (#77413)` with body `addressing claude review`. `connect-policy.ts` blob `27284609` is identical on parent and candidate. Parent `shouldSkipControlUiPairing` already returns true for `trustedProxyAuthOk`.

Topology PASS. But-for NARROW: the pairing residual is not created by this commit. Fix-reversal PASS: `96fba91b` stops skipping pairing on trusted-proxy auth. Release NARROW: independent GitHub Releases fetch for `v2026.5.12` and `v2026.5.18` returned 403; npm `gitHead` is null. Git tags peel and ancestry hold, but this packet fails closed on missing GitHub Release objects. Uniqueness PASS.

### GHSA-J4CX-JVQ7-79VM (196, openclaw/openclaw) — NARROW

Identity PASS. Published repository advisory names trajectory export secret redaction, patched `2026.6.1`. Global GHSA 404.

AI-hunk NARROW. `17ceca86` subject is `[AI] (#79006)`. Candidate never edits `src/trajectory/export.ts`. That blob `fbbd7e1b` is identical on parent and candidate. Parent already imported `sanitizeDiagnosticPayload`.

Topology PASS. But-for NARROW: export walker is a sibling artifact. Fix-reversal PASS: `19fb9f12` touches only `export.ts` and its test. Release NARROW: GitHub Release object for vulnerable `v2026.5.28` was 403; `v2026.6.1` GitHub Release exists and is not a draft. npm `gitHead` is null. Uniqueness PASS.

### GHSA-JX5R-P82P-2P8M (201, ChurchCRM/CRM) — NARROW

Identity NARROW. Repository advisory is published, aliases CVE-2026-44548, and names three GET-delete pages. Global GHSA 404. `PropertyTypeDelete.php` and `NoteDelete.php` already exist on the member parent. Patched tag `7.3.2` does not exist in git.

Atomic Claude member `6ef78813` (parent_count=1, Co-Authored-By Claude Sonnet 4.6) introduces `FundRaiserDelete.php` as GET `FundRaiserID` delete. AI-hunk PASS. But-for PASS for that new page only.

Topology NARROW. Member is not an ancestor of squash `ede1bfb0` or of `7.2.2`/`7.4.3`. `FundRaiserDelete.php` blobs: member/carrier `80acd007` != `7.2.2` `2963cd58`. Blob equality with the carrier is not ancestry.

Fix-reversal PASS: `f1c11f9f` migrates deletion to POST `/fundraiser/{id}/delete`; the legacy file is absent at `7.4.3`. Release NARROW because the AI member is not a tag ancestor and the released blob is not the member blob. Uniqueness PASS.

## Uniqueness

None of the five reviewed identities is in the canonical84 counted set of 84. None appears as a PASS proposal in a 2026-08-14 selected/cases packet. The unseen-twogate8 eight remain excluded and were not reviewed here. Shared repository or shared SHA does not merge identities.

## Claim boundary

This packet does not edit tracked files, canonical ledgers, publication data, or other worker directories. It does not commit or push. Worker PASS remains a proposal; this packet has zero PASS. packet_delta=0. start_count=84. current_leader_accepted_count=84. Publication stays HOLD. Greater-than-200 remains unsupported.

Status is **TERMINAL**. Expansion stopped. No further candidates.
