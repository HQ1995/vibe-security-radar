# Hostile red-team: GHSA-CHFM-XGC4-47RJ and GHSA-JXX9-PX88-PJ69

**REJECT both.** KEEP proposal 0. Packet delta 0. Current leader-accepted count remains 82. Leader logical count 84 is recorded; committed canonical baseline stays 82.

This is an independent hostile review of leftover4 PASS proposals (selected SHA d0451fc097b0da1aae3befba159facdcbbf322ce3610addc6f0649b1bab0610a, cases SHA 0f2f23102e899bf81aa427706895b531e47971f76a7895012bf025bf8d5403bb, result SHA 2ff65355600bee4830f342e73e6be415d1971eef44315143f6cbbf8bb9bd985a). Worker PASS is proposal only. This packet does not admit either row, does not rebuild canonical82, and does not support a greater-than-200 claim.

Conservation: assigned=2, reviewed=2, unreviewed=0. Direct-root remediation_patch_delta_gate is NOT_APPLICABLE, not a failing gate.

## GHSA-CHFM-XGC4-47RJ -- REJECT

Minimal counterexample: GitHub PR #51643 unmarked member `9f40ec891132372673b82cdda039db51a57e20c1` has no AI marker and first-introduces `extensions/msteams/src/graph-thread.ts` plus unfiltered `formatThreadContext(allMessages, activity.id)` in `message-handler.ts`. Squash `8c852d86` is the PR merge commit and carries Claude Opus 4.6 trailers from later members. Claude-marked members `86645bfd` and `0b2ac6eb` edit only `graph-thread.ts` helper/cache/docs. All four members are missing from the first-party clone and are not ancestors of the squash or of tag `v2026.3.28`. An AI-marked squash cannot transfer authorship from an unmarked member (canonical82 negative control GHSA-2MHJ).

Parent `6cbd2d36` already allowlists the current MS Teams sender and has no Graph thread context. The advisory is the new unfiltered history path, authored by the unmarked member. Fix squash `5cca3808` (#57723) still filters that list; that is mechanism reversal, not origin.

npm freeze: registry tarball `openclaw-2026.3.28` shasum matches, gitHead equals peeled `v2026.3.28`, bundled `dist/src-cE0yAYZb.js` calls `formatThreadContext` on Graph replies without `resolveMSTeamsAllowlistMatch`. `openclaw-2026.3.31` gitHead equals peeled `v2026.3.31` and `dist/src-B1VyaE4s.js` filters `allMessages` when `groupPolicy === "allowlist"`. Tags alone were insufficient; this freeze is containment, not a save.

## GHSA-JXX9-PX88-PJ69 -- REJECT

Minimal counterexample: proposed candidate `f237fad1` does not modify `src/mcp/handlers-n8n-manager.ts` (blob `502a664e` equals parent `424f8ae1`). Parent already extracts `x-n8n-url` / `x-n8n-key` and documents env fallback. The factory string `Falling back to environment configuration for n8n API client` predates the candidate at `34c7f756` (ancestor of the parent). `f237fad1` adds `ENABLE_MULTI_TENANT` session strategy and dynamic tool registration, not the tenant-header fail-open.

`f237fad1` is not on the first-parent chain of `v2.51.1`. PR #212 merge `c5aebc14` is the first-parent landing. Proposed closer `853015d0` has subject `Merge commit from fork` and the squash body lists three security members; leftover4 used that merge as the atomic minimum fix.

First-party repo advisory GHSA-jxx9-px88-pj69 is published and not withdrawn. npm freeze: `n8n-mcp-2.51.1` / `2.51.2` tarball shasums match registry; dist JS equals git tag blobs. `2.51.1` has the env fallback and lacks refuse/HTTP 400; `2.51.2` refuses env-credential fallback and returns `Multi-tenant headers required`. Shared SHA `f237fad1` with GHSA-4GGG (instance-URL SSRF) is a distinct mechanism and is not counted; counted GHSA-56C3 is IPv6 SSRF. Uniqueness does not save origin.

## Gates

KEEP requires all seven gates PASS. Both rows fail `ai_hunk_gate`, `topology_gate`, and `but_for_gate`. Identity, uniqueness, fix-reversal (mechanism, not a save), and release (npm freeze, not a save) do not admit the leftover4 KEEP.

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical82. Publication and more-than-200 stay HOLD.
