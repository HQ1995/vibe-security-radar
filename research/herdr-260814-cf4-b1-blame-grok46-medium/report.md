# CF4 B1 fix-line blame packet (proposal only)

Verdict: **0 PASS_PROPOSAL / 12 REJECT / TERMINAL**. Canonical88 stays 88. Countable pass 0. Greater-than-200 remains unsupported. Worker PASS is proposal only. Publication stays HOLD.

## Sources

github-reviewed subtree: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`.

unreviewed subtree only: `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226`.

Union by uppercase GHSA ID; reviewed f2c6 wins on collision (2 collisions). The older 39d888 clone is not the reviewed universe.

First-party: repository `security/advisories/GHSA-*` URL matching the identity, or GitHub release tag on the same repo as the PACKAGE URL. Active = not withdrawn. Bucket = integer sha256(uppercase GHSA) modulo 6 equals 1.

## Conservation

Exclusion parse of structured `case_id`, `ghsa_id`, `reviewed_case_ids`, `assigned_ids`, `strict_released_case_ids` across prior herdr/orchestrator terminal artifacts plus canonical88: 8068 IDs, 541 files. Free-text mentions were not excluded.

| layer | n |
| --- | --- |
| reviewed files (f2c6) | 34389 |
| unreviewed files (39d888) | 317316 |
| first-party reviewed | 15691 |
| first-party unreviewed | 136 |
| union after reviewed-wins | 15825 |
| active first-party | 15750 |
| bucket 1 active | 2665 |
| unowned after exclusions | 1494 |
| of which unreviewed-only | 14 |
| no official commit ref | 568 |
| missing local clone | 398 |
| clone and commit refs | 528 |
| real git objects | 515 |

515 >= 12, so no git-object shortfall. Freeze 12. Remaining unowned 1482 were not padded into this packet.

Fix-line blame (-M -C on official-fix parent deleted source hunks) plus added-file origin, production `source_matcher` v3: **0 origin hits and 0 AI-on-fix hits** on all 515 git-object rows. Unreviewed-only identities stayed in the universe (14 unowned, 2 with git objects) and did not outrank reviewed tagged recent rows after a zero-hit blame search.

Assigned 12 = reviewed 12 + unreviewed 0. PASS_PROPOSAL 0. Did not pad a false positive.

## REJECT (all 12)

No production AI authorship on the vulnerable parent lines of the official fix, and no AI-created distinct released path. Identity and uniqueness hold. Topology/but-for fail because the candidate set is empty. Official closers exist and are tagged; that is not AI causality.

1. GHSA-Q6CQ-MHR2-JMR5 netty HAProxy signed-byte sentinel. Closers 5b68c61f / bb2ff68a human merges (Chris Vest, Norman Maurer). bb2ff68a touches HAProxyMessageDecoder.java. Blamed parent lines include Andy Hedges dns decoder hunks. Matcher empty. Tag netty-4.2.16.Final contains closer.
2. GHSA-GVWX-54WH-QM9J node-tar PAX NUL DoS. Closer 7a635c29 isaacs. src/pax.ts parent not AI. Tag v7.5.17.
3. GHSA-724G-MXRG-4QVM js-yaml !!omap quadratic DoS. Closer 39f3211a Vitaly Puzrin. omap.ts parent not AI. Tag 5.2.1.
4. GHSA-H2WF-967X-GXVW mantisbt stored XSS print_all_bug_page_word.php. Closer bdd0e364 Damien Regad. Tag release-2.28.4.
5. GHSA-MM7M-92G8-7M47 nuxt routeRules case bypass. Closers 07e39cd6 / 3f3e3fa7 Daniel Roe. nitro-server index.ts parent not AI. Tags v4.4.7+.
6. GHSA-2GCR-MFCQ-WCC3 hono mount undecoded prefix. Closer 6cbb025f Taku Amano. hono-base.ts parent not AI. Tags v4.12.21+.
7. GHSA-JXXR-4GWJ-5JF2 brace-expansion numeric range. Closer c0b095bd Julian Gruber. Tags v5.0.6+.
8. GHSA-J7V9-F46R-2RP4 mantisbt textarea reflected XSS. Closer c885af13 Damien Regad. Tags release-2.28.2+.
9. GHSA-6M6C-36F7-FHXH mermaid gantt infinite loop. Closers a59ea561 / faafb5d4 Alois Klink. ganttDb.js parent not AI. Tags v10.9.6+.
10. GHSA-6JH4-47V2-4G37 mantisbt tag-update referer injection. Closer b1ebc577 Damien Regad. tag_update_page.php parent not AI. Tags release-2.28.2+.
11. GHSA-R7FX-8G49-7HHR grav markdown media attribute XSS. Closer 5a12f9be Andy Miller. Tags 2.0.0+.
12. GHSA-9C4Q-HQ6P-C237 minio unsigned-trailer missing SigV4. Closer 76913a9f Klaus Post. Parent lines not AI. Tags RELEASE.2023-05-18T00-05-36Z+.

OSV introduced values, shared SHA, AI-on-fix, same repository, same file, new caller of an old bug, refactor preservation, and incomplete hardening are routing, never proof. Prefer zero PASS over one false positive.

## Claim boundary

Canonical strict released first-party GHSA floor remains 88 HOLD. This packet emits no admission. No commit, push, or edits outside this directory. Local caches read-only. Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
