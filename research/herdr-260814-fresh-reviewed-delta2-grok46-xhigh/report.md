# Fresh reviewed delta2 (f2c6 versus 39d888)

Verdict first: **0 PASS_PROPOSAL**. Inspected **0**. Bound 12 not reached. Did not pad. Packet delta **0**. Canonical91 stays **91**. Publication and greater-than-200 remain **HOLD**. Worker PASS is proposal only; this packet emits none.

## Freeze

Official github-reviewed tree at `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` was listed with `git ls-tree` from `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` (tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`, committer 2026-08-14T03:33:36+00:00). Older github-reviewed tree from `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226` (tree `3a1267e940595e82f109a750f2779d987ff4d01b`, committer 2026-07-23T12:34:36+00:00). Shared caches were read-only. No network clone.

New reviewed IDs 34389. Old reviewed IDs 33646. Added **743**. Removed **0**. Exact sorted added-ID sha256 `d2e0f08843dedcd6a62e067a4b8ac3530c1998d8ac528d7097a7437d1244a6a8`. Exact sorted removed-ID sha256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (empty).

## Exclusion (frozen; replay does not glob)

Canonical91 strict IDs: **91**. Structured prior terminal `assignment.jsonl` / `cases.jsonl` `case_id` values from herdr-* and orchestrator-* packets, skipping work/notes/pages/snapshot/clones/cache/tmp: union **8201** after adding the 91. Exact sorted-ID sha256 `ea5500ebc1bd96e9d9da765c49afea9e7c403a5b026dd3f0b69cc9a0c9461f22`. Files parsed 316. The ID list is frozen inside result.json. Replay hashes that snapshot and does not walk other workers.

Delta overlap with exclusion: **667**, including 13 already in canonical91. Remaining added identities: **76**. CVE aliases are not counted.

## Rank

Remaining 76 are all github-reviewed. Withdrawn 10. Empty affected 0. GitHub-repo 76. Exact 40-hex GitHub commit refs: 36 including withdrawn duplicates. Active GitHub-repo exact-fix: **31**. First-party repo-advisory URL matching the same GHSA: **19**.

Rank filter required plausible AI-authored origin or incomplete-remediation history, rebuilt from first-party Git with `source_matcher` contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`. Advisory text AI/incomplete-remediation language: 0 in the remaining 76 (29 such added IDs were already excluded). Listed closers: 0 matcher hits. Code-file history of closer paths, excluding README/docs: 0 matcher hits. Blame of deleted lines at closer parent: 0 matcher hits. README-overlap Claude commits on the MCP Ruby HTTP client are not stdio-buffer or Host/Origin origin and are not counted as plausible history.

Inspect cap 12. Strongest plausible-AI set size **0**. Did not pad with human-only closers.

## Seven gates

identity, AI hunk, topology, but-for, fix reversal, release, uniqueness. Exact PASS required. No inspect row was opened. AI-on-fix, remediation-as-origin, marker transfer, missing release containment, and duplicates fail closed. Missing objects never mint PASS. Worker PASS is proposal only.

Human listed closers on the 19 first-party exact-fix remainders include Daniel Roe (Nuxt), Chris Vest / Norman Maurer (Netty merge-from-fork squash), Koichi ITO (MCP Ruby SDK), Yusuke Wada (Hono), Jason Jean (Nx), and Graham Campbell (Guzzle). Those are not AI hunks. Netty #17063 bodies that mention other authors are not authorship transfer onto the squash carrier.

## Conservation

0 assigned = 0 reviewed + 0 unreviewed. Equation `0=0+0`. Eligible after rank filter 0. Inspected 0. Did not pad. cve_aliases_counted=false. canonical91_overlap on the inspect set=0 (packet assigned none). Added canonical91 overlap 13 excluded from ranking. packet_delta=0.

## Claim boundary

This packet does not admit cases. Current leader-accepted strict count remains 91 HOLD. Greater-than-200 remains unsupported. Canonical91 was not rebuilt. No commit, push, website, or edits outside this directory.
