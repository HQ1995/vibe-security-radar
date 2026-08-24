# CF4 b5 incomplete-remediation predecessor lane

Verdict first: **0 PASS_PROPOSAL**. Frozen **2** actual AI security predecessors. Shortfall **10**. Inspected prefix **397**. Stop rule **prefix_exhausted**. Did not pad. packet_delta **0**. Canonical strict count remains **88** HOLD. Worker PASS is proposal only; this packet emits none.

## Universe and bound

Authoritative github-reviewed subtree: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` path `advisories/github-reviewed`.

Unreviewed subtree only: `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226` path `advisories/unreviewed`.

Union by uppercase GHSA ID; reviewed f2c6 wins on collision (135 collisions in 2025-2026). Unreviewed rows were not dropped. Bucket is integer sha256 of uppercase GHSA ID modulo 6 equals 5.

Remaining 2025-2026 after withdrawn and structured exclusions: **13914**. First-party rows with exact repo advisory or same-repo fix commit: **757**. Local clone plus real fix object: **397**. Rank: reviewed first, repo advisory first, then GHSA ID. Inspect at most the top 600. Prefix first ID `GHSA-2464-8J7C-4CJM`, last ID `GHSA-XVV7-73JX-5WCG`. Prefix git objects 397. Stop after 12 actual AI security-predecessor hits or prefix end. Reached 2 hits and exhausted 397. Shortfall 10. Never padded.

Method: for each inspected row with a real first-party fix object, walk fix-touched source files backward 250 first-parent commits. Admit only atomic production source_matcher commits that explicitly attempted the same security invariant (authorization, validation, escaping, path handling, SSRF restriction, command safety, sandboxing, safe config/dependency, or fail-closed logic) without requiring exact line overlap. Generic refactors, unrelated security work, dependency-only routing, new callers, later human reintroduction, AI-on-fix, and safer-but-incomplete reductions of an older broad flaw fail.

Equation **2=2+0**. Prefer 0 PASS.

## Per identity

1. GHSA-CGJG-P2M2-QM4P mattermost. REJECT. Claude rctx rename overlaps channel.go. Parent already has GetDirectOrGroupMessageMembersCommonTeams. Listed closer is a human common-teams filter, not team-settings invite authorization. Listed SHA is absent from v10.11.9 and v10.11.10; cherry-pick a07b1d7a8c0d is in v10.11.10.

2. GHSA-GXX6-2VWG-3GC3 deer-flow unreviewed. REJECT. Copilot 253fe4d87fb8 adds regex bash-path validation on already-present host execute_command. Closer 92c7a20cb74a disables host bash by default and does not close the regex cd/relative residual for allow_host_bash opt-in. Identity fails: empty affected, no matching repository advisory URL. 0 tags.

## Claim boundary

No worker PASS. Leader admission is unchanged. Publication and more-than-200 stay HOLD. This packet does not edit canonical88, web, or scripts. No durable pages, clones, packages, notes, or helper scripts remain in the owned directory. Temporary clones and pages were not retained.
