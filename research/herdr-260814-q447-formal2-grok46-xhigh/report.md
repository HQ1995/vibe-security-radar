# Hostile formal review: GHSA-Q447-RJ3R-2CGH

**NARROW.** `release_gate` FAIL. PASS forbidden. Countable PASS remains 0. Packet delta 0. Canonical91 stays **91 HOLD**.

This is an independent hostile review of the corrected hypothesis that landing squash `5c2cb6c591e4b63c2df0549ad2202403256e2a96` is both candidate and carrier of the GHSA-q447 Feishu `Lark.adaptDefault` unbounded webhook body, with parent `49c60e9065d98a6848e62c717315eb91eeaa6038`, closer `3cbcba10cf30c2ffb898f0d8c7dfb929f15f8930`, hypothesized vulnerable `v2026.2.12`, and fixed `v2026.2.13`. Prior packets are routing only and are not evidence. Worker PASS is proposal only; this packet emits none. This packet does not admit the row, does not rebuild canonical91, and does not support a greater-than-200 claim.

Conservation: assigned=1, reviewed=1, unreviewed=0. Equation `1=1+0`.

## Release contradiction (binding)

Live first-party GitHub repo advisory display and API for GHSA-q447-rj3r-2cgh:

- Package: `openclaw` (npm)
- Affected versions: `<2026.2.12`
- Patched versions: `>=2026.2.13`

The counted squash first appears in tag `v2026.2.12`. No `v2026.2.*` tag before `v2026.2.12` contains `5c2cb6`. Last formally affected openclaw artifact is `v2026.2.9` / npm `2026.2.9` (peel/gitHead `33c75cb6`): `monitor.ts` still logs `webhook mode not implemented in monitor` and lacks `adaptDefault`; npm tarball sha256 `0f7c67bd...` equals git. Formally affected `clawdbot@2026.1.24-3` gitHead `885167dd` also lacks `5c2cb6`.

npm/tag `2026.2.12` contains the squash but is outside the displayed affected range (not `<2026.2.12`) and outside the patched range (not `>=2026.2.13`). It is not a formally affected released artifact.

Do not infer that `2026.2.12` is affected from advisory-database ECOSYSTEM events `introduced 0` / `fixed 2026.2.13`, or from the global advisory API range `< 2026.2.13`. Those normalized forms are not the live GitHub affected display.

`release_gate` requires a vulnerable released artifact that contains the AI contribution. None exists for this squash. PASS is forbidden.

## Mechanism and topology (not enough)

GitHub-reviewed GHSA-q447 on openclaw/openclaw is published, not withdrawn, and aliases CVE-2026-28478. The advisory names unbounded webhook body buffering and names Feishu among stream-guard migrations. Identity remains PASS.

Squash `5c2cb6c5` is a single-parent GitHub squash of PR #12662 onto `49c60e90` with trailer Co-authored-by Claude Opus 4.6. Parent lacks `adaptDefault`. The squash adds unbounded `Lark.adaptDefault`. Member `b0c67ea0` is not an ancestor of the squash or of any counted tag; identical blobs do not transfer it. That is not the HHJV failure. `ai_hunk_gate` and `topology_gate` remain PASS at that object. They do not close `release_gate`.

## But-for, reversal, uniqueness (not enough)

Removing the squash eliminates the scoped Feishu SDK body surface. Closer `3cbcba10` wraps `Lark.adaptDefault` with `installRequestBodyLimitGuard`. GHSA-Q447 is absent from canonical91 strict 91 and is distinct from G353/XH72 (encryptKey/card-token) and from counted Feishu rows 8JPQ/J4XF. Those gates do not place `5c2cb6` inside `<2026.2.12`.

## Gates

1. identity_gate: PASS
2. ai_hunk_gate: PASS
3. topology_gate: PASS
4. but_for_gate: PASS (scoped new surface)
5. fix_reversal_gate: PASS
6. release_gate: FAIL
7. uniqueness_gate: PASS

Seven-gate exact PASS is false.

## Claim boundary

No NARROW row changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical91. Publication and more-than-200 stay HOLD.
