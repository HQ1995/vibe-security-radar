# Fresh-delta20 terminal report

Verdict: 0 truly new reviewed first-party GHSA identities. Freeze size 0. packet_delta 0. PASS_proposal 0.

## Counts

- Start strict count: 82
- Current leader-accepted strict count: 82
- Canonical82 ledger sha256: 58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23 at commit 6800d2127c19532160cc88880115ae28cc446aa5
- Frozen exclusion union: 224 first-party GHSA IDs (212 PRESERVED_PUBLIC_CASE plus 82 strict IDs, including 12 strict_not_in_pub)
- CVE aliases are not counted separately
- Exact frozen IDs: none
- PASS proposals: none; any future PASS would remain pending independent red-team only

## Source compare

Official github/advisory-database was refreshed into a uniquely named disposable cache, not as a claim artifact.

- Frozen reviewed head: a42c436870111aa3f221257c9d56126a93173ccc at 2026-08-13T20:57:17Z
- Current upstream head observed: f2c6ab3202aeafb36fbea6e76d892532acfca1a6 at 2026-08-14T03:33:36Z
- github-reviewed JSON identities: 34389 frozen, 34389 current
- Added reviewed identities: 0
- Removed reviewed identities: 0
- Modified reviewed identities: 0
- Three upstream commits in the window changed unreviewed files only

## First-party GitHub Security Advisory window

GraphQL securityAdvisories with publishedSince and updatedSince equal to the frozen committer timestamp, 100 nodes per page, orderBy ASC, cursor conservation recorded in work/delta-summary.json. Raw pages stayed in disposable cache.

- publishedSince: 0 nodes
- updatedSince: 1 node, GHSA-R277-6W6Q-XMQW, published 2026-07-24T16:52:05Z, updated 2026-08-14T04:21:32Z, already in frozen github-reviewed, not a new identity, not frozen

## Seven-gate review

No identity was frozen, so no candidate, parent, fix, AI-hunk, topology, but-for, reversal, release, or uniqueness audit was opened. Routing, OSV introduced values, commit references, and AI trailers were not used as causality. Padding to 20 was forbidden.

## Claim boundary

This packet does not admit cases. Canonical count is unchanged at 82. Publication and a greater-than-200 claim remain unsupported. Worker PASS is a proposal only; this packet emits none, so nothing is pending red-team admission.
