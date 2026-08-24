# Hostile review: GHSA-8JQH-598V-RFXC

**NARROW.** Countable PASS remains 0. Packet delta 0. Canonical94 stays **94 HOLD**.

This is an independent hostile review of hypothesized pairing candidate `b7b362ae427ccf4b33b8e8cd147f16410f3ce800` (empty carrier) with closer `7d1ddbfdb8296058ab787f7c57b8943c0214d14d` for ArnasDon/wacrm webhook SSRF, alias CVE-2026-67530. nearpass-next10 is routing only. unknown4a six-gate PASS labels are not proof. Worker PASS is proposal only; this packet emits none. Exact seven PASS is required for PASS_PROPOSAL. Release pairing does not close.

Conservation: assigned=1, reviewed=1, unreviewed=0. Equation `1=1+0`.

Network evidence used anonymous public git and registry access only. Credential-bearing environment variables are unset before network commands and are never printed. Anonymous failure is BLOCKED; credentials are not used as a fallback.

## Identity (first-party)

Published repository advisory GHSA-8jqh-598v-rfxc names ArnasDon/wacrm, CWE-918 SSRF via automation `send_webhook` in `src/lib/automations/engine.ts`, and formal alias CVE-2026-67530. State published, withdrawn_at null. Package ecosystem `other` / name `wacrm`, range `<= 0.7.0`, patched_versions `23838a9`. Normalized advisory SHA256 `3022771b5afe158962eeaffc23a7bc9526692c50c15cc336fbcd22a0ff1920f1`. github/advisory-database reviewed JSON for this id is HTTP 404 for 2026/01-12. Identity uses the repository advisory, not the global catalog.

identity_gate: PASS.

## Topology and AI marker

`b7b362ae` is single-parent onto `66dd4ef9`. Trailer: Co-Authored-By Claude Opus 4.7 (1M context). It first-parent-creates `engine.ts` blob `af7673d0` with unguarded `fetch(cfg.url)`. Merge `e8c952b1` (PR #31) is the first-parent introduction onto main and is not authorship. Fix merge `23838a99` (PR #352) parents `03e851be` and closer `7d1ddbfd`; legacy carrier_sha `23838a99` is that fix merge and is not an origin carrier. carrier_set stays empty.

topology_gate: PASS. ai_hunk_gate: PASS.

## But-for and fix reversal

Parent has no `engine.ts`, no `send_webhook`, and no `isDeliverableUrl`. The webhook_endpoints SSRF guard `c0f390c4` is later and is not an ancestor of the candidate. Removing the candidate eliminates the advisory-named fetch. Named commit `274db1c` (package.json 0.7.0, Merge PR #334) still has unguarded fetch; engine blob `c21a25cd` equals closer parent `1d7829e6`.

Closer `7d1ddbfd` is atomic, Claude Opus 4.8 marked, and amends only `engine.ts` plus `engine.test.ts`. It imports `isDeliverableUrl`, throws `send_webhook: destination not allowed`, sets `redirect: 'manual'`, and tests `http://169.254.169.254/latest/meta-data/`. That reverses the same fetch invariant. validate.ts blob `6b652ec8` is unchanged. AI-on-fix is not origin.

but_for_gate: PASS. fix_reversal_gate: PASS.

## Release (hostile close)

Git ls-remote: zero tags. GitHub /releases: no releases. npm `wacrm` and `@arnasdon/wacrm` HTTP 404. pypi `wacrm` HTTP 404. docker hub `arnasdon/wacrm` HTTP 404. package.json `private=true` at 0.7.0/0.6.0/0.8.0 commits. Advisory patched_versions is SHA `23838a9`, not a version tag. Named `274db1c` is a main merge, not a GitHub Release. CHANGELOG heading is not an artifact. crates.io returned HTTP 403 and is unused.

A git commit existing on main is not a release. No first-party vulnerable artifact contains the candidate and no first-party fixed artifact contains the closer.

release_gate: NARROW.

## Uniqueness

GHSA-8JQH is absent from canonical94 strict 94. Same-repo GHSA-X2W7 is a different mechanism and is also uncounted. CVE alias is not a second case.

uniqueness_gate: PASS.

## Claim boundary

Six causal gates close on git evidence. Release does not. seven_gates_exact_pass is false. Verdict NARROW, not PASS_PROPOSAL. Canonical94 is untouched. Publication and more-than-200 stay HOLD.
