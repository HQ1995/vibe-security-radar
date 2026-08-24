# O-Z commit-first new-surface freeze

Verdict first: **0 PASS_PROPOSAL**. Frozen inspected count is **12**. All 12 are **REJECT**. Did not pad to 40. packet_delta=0. Canonical strict count remains **85**. Publication and more-than-200 remain **HOLD**. Worker PASS is proposal only; this packet emits none.

## Bound and conservation

Assigned universe: first-party active O-Z (plus digit/other) rows in `herdr-260813-ghsa200-commitfirst-oz`. Source shard recorded 3623 novel IDs with 0 seven-gate closures (2151 UNKNOWN with a resolvable fix SHA, 1472 BLOCKED).

Exclusions applied before freeze: canonical85 strict 85 plus its negative-control/excluded GHSA keys; canvas `foundation.jsonl` identities; source-shard exclusion GHSA IDs; later-worker terminal PASS/REJECT/NARROW/STRICT/CONFIRM identities. CVE aliases were never counting units.

Mining: rows with a first-party fix SHA and repository AI grep hits. File-add origin (`git log --diff-filter=A` of a fix path lands on an AI commit) produced **0** hits. Same-file atomic AI ancestor of the official fix, AI count <= 40, non-test code paths, produced **12** unique GHSAs. Those 12 were frozen and fully adjudicated. Closer/marker-on-fix was never treated as origin. No GitHub REST/GraphQL. No full clones. Shared commit-oz cache was read; no owned leftover clones or raw pages.

Equation: 12 frozen = 12 reviewed + 0 unreviewed. Did not pad.

## Counterevidence (all REJECT)

| ID | Class | Why |
| --- | --- | --- |
| GHSA-XC5W-4V5W-7X65 | closer not origin | Cursor 0e45f3b0 is the fork patch merged as listed closer 995ff797. regex: and the shell blocklist predate it. |
| GHSA-XPXJ-F2FM-RQCH | closer not origin | Cursor 42204431 is merged as listed closer ec114e95. It caps `registeredStates`; it did not introduce the map. |
| GHSA-73CV-556C-W3G6 | adapter not default | Claude 3ee5500f only retargets FastMCP 3.x APIs. `oauth_enabled` / 0.0.0.0 are earlier. Closer 1c7d3f9 is a later loopback refuse. |
| GHSA-J65M-HV65-R264 | sibling hunk | Claude 8ba78240 is health 503 + constant-time compare (4 lines). It does not wire `RateLimitMiddleware`. |
| GHSA-P8MM-644P-PHMH | sibling hunk | Claude d3895105 proxies a screencast WebSocket. GHSA is Windows PowerShell cleanup injection. |
| GHSA-9M84-WC28-W895 | sibling route | Cursor 5295aef2 adds `DELETE /members/:id/suppression`. GHSA is OTC CSRF on `/session/verify`. |
| GHSA-337J-9HXR-RHXG | sibling hunk | Copilot 44c34783 memoizes `useFetchers`. GHSA is `deserializeErrors` constructor injection. |
| GHSA-P523-JQ9W-64X9 | sibling hunk | Claude 5e054ddc is ast.unparse hardening. Closer adds `cProfile` to the blocklist. |
| GHSA-WFQ2-52F7-7QVJ | sibling hunk | Same AI SHA as P523. Closer adds `runpy` bypass coverage. Shared SHA is not origin. |
| GHSA-8MV7-9C27-98VC | carrier | ee079d4c is a 147-file merge-main-into-next with Copilot plus many humans. |
| GHSA-F48W-9M4C-M7F5 | carrier | Same carrier SHA. Shared SHA across Astro IDs is not mechanism equality. |
| GHSA-X27W-589X-FRM2 | carrier | Same carrier SHA. An AI-marked carrier cannot transfer hunk authorship. |

Same-file overlap is routing only. Missing tags in `--no-tags` clones keep `release_gate` UNKNOWN; that does not upgrade any row to PASS.

## Claim boundary

No worker proposal changes the count. Current leader HOLD snapshot is canonical strict **85**. This packet does not edit canonical or site files and does not support a greater-than-200 claim.
