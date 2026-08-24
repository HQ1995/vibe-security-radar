# Leftover4: 2 PASS proposals; 2 REJECT

Verdict first: 2 PASS proposals (GHSA-CHFM-XGC4-47RJ, GHSA-JXX9-PX88-PJ69), 2 REJECT (GHSA-X9CF-3W63-RPQ9, GHSA-V3QC-WRWX-J3PW). Assigned 4, reviewed 4, unreviewed 0. Conservation 4=4+0. No padding, backfill, or widening. Worker PASS is proposal only. Start count is not rebuilt. Current leader-accepted count 82 (canonical82, commit 6800d212, ledger hash 58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23). Packet delta 0. Publication and greater-than-200 stay HOLD.

Input frozen to residual-security20 conservation.unreviewed_later_fix_ids_outside_freeze in that exact order.

## Method

Reuse the prior lane later-fix scan plus read-only local clones. Deep-review parent/candidate/fix, atomic AI hunk, topology, but-for or incomplete-remediation patch-delta, exact fix reversal, released artifacts, identity, and uniqueness versus canonical82 plus existing worker selected/cases lists. A trailer on a carrier does not transfer human hunk authorship. Shared SHA does not imply duplicate mechanism.

PASS_proposal here is origin but-for (AI_DIRECT_ROOT), not patch-delta incomplete remediation. remediation_patch_delta_gate is FAIL on both PASS rows.

## PASS proposals

Worker PASS is a proposal. Leader plus independent hostile red-team must accept before the count moves.

### GHSA-CHFM-XGC4-47RJ (openclaw/openclaw)

- Identity: github-reviewed GHSA-chfm-xgc4-47rj, CVE-2026-41365, not withdrawn. npm openclaw, last known affected <= 2026.3.28, fixed >= 2026.3.31.
- AI hunk: 8c852d86 single-parent. Co-Authored-By Claude Opus 4.6. First-parent adds graph-thread.ts and unfiltered Graph thread history in message-handler.ts.
- Topology: atomic. Candidate is an ancestor of v2026.3.28 and of closer 5cca3808. Closer is not in v2026.3.28. No authorship transfer.
- But-for: without the Graph fetch, the advisory's thread-history allowlist bypass does not exist. Patch-delta FAIL because this is origin, not an omitted case on a prior AI guard.
- Fix reversal: 5cca3808 filters allMessages with resolveMSTeamsAllowlistMatch when groupPolicy is allowlist.
- Release: peeled v2026.3.28 equals npm gitHead f9b10792 and still calls formatThreadContext(allMessages). Peeled v2026.3.31 equals npm gitHead 213a704b and contains the filter. GitHub release tag v2026.3.31 is first-party.
- Uniqueness: absent from canonical82 strict 82. Prior directroot-batch17 REJECT does not count it. Distinct from other OpenClaw allowlist GHSAs.

### GHSA-JXX9-PX88-PJ69 (czlonkowski/n8n-mcp)

- Identity: github-reviewed GHSA-jxx9-px88-pj69, CVE-2026-45707, not withdrawn. npm n8n-mcp, introduced 0, fixed 2.51.2.
- AI hunk: f237fad1 single-parent. Generated with Claude Code; Co-Authored-By Claude. First-parent adds ENABLE_MULTI_TENANT and getN8nApiClient env fallback.
- Topology: atomic. Candidate is an ancestor of v2.51.1. Closer 853015d0 is a single-parent security merge-from-fork whose first-parent diff fail-closes the factory; no second parent, so no trailer-on-carrier transfer.
- But-for: without the AI multi-tenant fallback, header-less tenants cannot operate on process-level operator credentials. Patch-delta FAIL (new surface, not rem).
- Fix reversal: 853015d0 rejects header-less multi-tenant HTTP requests and refuses env-fallback clients when ENABLE_MULTI_TENANT=true.
- Release: git tag v2.51.1 commit b7ad5284, package.json 2.51.1, contains f237fad1, does not contain the closer. git tag v2.51.2 is the closer, package.json 2.51.2. First-party GHSA names that tag.
- Uniqueness: absent from canonical82. Shared SHA f237fad1 with GHSA-4GGG (instance-URL SSRF) does not merge this env-credential fallback.

## REJECT (2)

| ID | Class | Minimal counterexample |
| --- | --- | --- |
| GHSA-X9CF-3W63-RPQ9 | feature hunk | AI 8d74578c is vision image injection; closer adds inbound-path-policy.ts |
| GHSA-V3QC-WRWX-J3PW | sibling | AI ab4a08a8 defers gateway restart; closer blocks config.patch exec paths |

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 82. This packet does not rebuild canonical82 and does not support a greater-than-200 claim.
