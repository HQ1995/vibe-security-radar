# Hostile primary-source lane: GHSA-4FXP-2M36-QV64

**NARROW.** Countable PASS remains 0. Packet delta 0. Canonical91 stays **91 HOLD**.

This is an independent hostile rebuild of fp211 ordinal 148. Prior CONFIRM/HIGH and released_publication_admitted are routing only. Worker PASS is proposal only; this packet emits none. Canonical91 already lists GHSA-4FXP as downgraded / narrow_noncounting. This lane does not reverse that downgrade.

Conservation: assigned=1, reviewed=1, unreviewed=0. Equation `1=1+0`.

## Identity (fails)

Live GitHub Advisory Database `GHSA-4fxp-2m36-qv64` aliases CVE-2026-59233, is not withdrawn, and is `type=unreviewed`. `github_reviewed_at` is null. `repository_advisory_url` is null. `source_code_location` is empty. `vulnerabilities` is empty. Frozen cache sha256 `ec7239df80f6c39dcf9fe9e43727749ab15436ca7110a1c87193a87c562e14cd` equals the live body. GET `/repos/Roskus/prospero-flow-crm/security-advisories/GHSA-4fxp-2m36-qv64` is 404. Frozen advisory-database HEAD `a42c436870111aa3f221257c9d56126a93173ccc` stores `advisories/unreviewed/2026/08/GHSA-4fxp-2m36-qv64/GHSA-4fxp-2m36-qv64.json` (sha256 `aa57ef638c0da67d2eea41601b525264022afcd0dd91a44ac29e66dc951f4584`) with `github_reviewed=false` and empty `affected`. The github-reviewed path is absent. Stale HEAD `39d8887723797efc1804585dd06585c9fd751226` lacks the file. Empty `affected` plus unreviewed status is not a first-party GHSA object that names the affected repository. `identity_gate` is NARROW.

## Alias mistake

Squash `52e5e193` and PR member `e2fd5b10` claim to fix `GHSA-rx76-rw4p-84j7`. Live GET `/advisories/GHSA-rx76-rw4p-84j7` is 404. That label is not this case. CVE-2026-59233 is a formal alias of GHSA-4FXP, not a second counting unit.

## Topology and AI hunk

Squash `52e5e193` is a single-parent GitHub squash of PR #247 onto `27d0a272`. Trailer: Co-authored-by Claude Sonnet 4.6. Parent controller blob `a558cb64` extends `Controller`. Squash blob `f0da620c` extends `MainController` and keeps `syncPermissions`. First-parent pickaxe on `v4.6.0` hits only the squash. Member `e2fd5b10` has the same controller blob and the same Claude trailer but is not an ancestor of the squash, of `v4.6.0`, or of closer `86a7d655`. This packet does not transfer that member. Carrier set is empty. Human-origin-inside-squash is not proved: the atomic squash carries its own Claude marker and authors the MainController switch versus parent.

## Old-bug preservation and patch-delta

The unauthenticated `syncPermissions` write already existed on parent `27d0a272`. Direct-root but-for would fail as old-bug preservation. The row is `AI_INCOMPLETE_REMEDIATION`. The squash is an explicit security attempt that adds the auth gate. `v4.6.0` ships that gate without `PermissionSaveRequest`. Closer `86a7d655` amends the same `save()` path with SuperAdmin `authorize()`. Rollback of the squash reopens unauthenticated rewrite; under patch-delta that is not a failure.

## AI-on-fix

Closer `86a7d655` is Co-Authored-By Claude Haiku 4.5. That is AI-on-fix, not origin. `fix_reversal_gate` still PASSes because that commit introduces `PermissionSaveRequest` and switches `save(PermissionSaveRequest $request)`.

## Release mismatch

GitHub Releases `v4.6.0` (peel `4c15d20a`) and `v5.5.3` (peel `584f3158`) are published and not prerelease. Squash is an ancestor of `v4.6.0`; closer is not. Both are ancestors of `v5.5.3`. Only git tags in this clone besides those two later tags are `v1.0.0` and `v2.0.1`. Named advisory version 5.2.1 has no git tag. `version.php` is 4.6.0 at `v4.6.0`, 5.2.1 at the closer commit, and 5.5.3 at `v5.5.3`. `v5.5.3` `PermissionSaveRequest` blob `795a4c17` is not closer blob `3107cf83` (later CompanyAdmin path). Containment of a SuperAdmin authorize check still exists on `v5.5.3`, so `release_gate` PASSes with this mismatch recorded. It does not repair identity.

## Uniqueness

GHSA-4FXP is absent from canonical91 strict 91. It is listed in canonical91 `downgraded` and `narrow_noncounting`. Distinct from GHSA-X8QQ-M4QC-RPJ5. Shared repo is not duplication. Shared closer SHA with no other counted Prospero permission-save row. CVE alias is not counted.

## Gates

1. identity_gate: NARROW
2. ai_hunk_gate: PASS
3. topology_gate: PASS
4. but_for_gate: PASS (patch-delta; not direct-root)
5. fix_reversal_gate: PASS
6. release_gate: PASS (named 5.2.1 tag absent; v4.6.0 / v5.5.3 used)
7. uniqueness_gate: PASS

## Claim boundary

No hostile proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical91. Publication and more-than-200 stay HOLD.
