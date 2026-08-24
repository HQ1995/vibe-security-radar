# CF4 B0 second-pass history lane

Verdict first: **0 PASS_PROPOSAL**. Frozen **0**. Shortfall **12**. Inspected prefix **600**. Stop rule **inspected_prefix_600_shortfall_12**. Did not pad. Canonical strict count stays **88 HOLD**. Worker PASS is proposal only; this packet emits none.

## Method

Different from CF4-b0-direct ancestry/proximity. Remaining bucket-0 rows were ranked deterministically: github-reviewed first, exact repository advisory URL or official fix commit, published 2025-2026 first, local clone present, then uppercase GHSA ID. Inspected at most the top 600. Stop earlier if 12 atomic AI-history hits; none appeared.

For each inspected official fix object, walk fix-touched source files backward up to 200 first-parent commits and resolve local squash/PR members. Keep only atomic (n_parents=1) production source_matcher v3 commits whose added lines overlap the closer deleted lines. AI ancestry or commit-reference proximity alone is not a hit. AI-on-fix is not origin.

## Sources

- github-reviewed: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`
- unreviewed subtree only: `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226`
- Union by uppercase GHSA ID; f2c6 reviewed wins on 135 collisions.
- CONTRACT `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- canonical88 ledger `35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074`

## Universe and conservation

Bucket = integer sha256(uppercase GHSA) modulo 6 equals 0. Excluded canonical88 plus structured case_id/ghsa_id/reviewed_case_ids/assigned_ids/strict_released_case_ids from prior herdr/orchestrator terminals, including CF4-b0-direct.

| layer | n |
| --- | --- |
| reviewed files f2c6 | 34389 |
| unreviewed files 39d888 | 317316 |
| union bucket0 active | 58514 |
| eligible after exclude | 57203 (4209 reviewed + 52994 unreviewed) |
| inspect cap | 600 |
| inspected prefix | 600 (all reviewed; first GHSA-23W4-RPC6-WPCC last GHSA-3V63-F83X-37X4) |
| real fix objects in prefix | 251 |
| skip no clone/commit | 326 |
| skip slow liferay-class clones | 14 |
| no source files | 39 |
| no real object | 9 |
| timeout skip | 3 |
| actual AI-history hits | 0 |
| shortfall versus 12 | 12 |

Assigned 0 = reviewed 0 + unreviewed 0. Equation 0=0+0. Never padded.

Proximity counterexample (not selected): GHSA-3C9R-7F29-QP32 official closer `61651b0d` User id auth control. Claude atomic `d78d59babe` is a first-parent ancestor (rctx rename). login.go deleted-line overlap with that AI commit is 0. Ancestry is not proof.

## Claim boundary

Proposal count **0**. Canonical 88 untouched. No commit, push, tracked edits, durable clones, pages, or helper scripts. Caches read-only. Prefer zero PASS over one false positive.
