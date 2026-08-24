# Advisory-delta post-a42c routing census

Verdict first: net-new candidate count = 0. Leader replay confirms the entire reviewed-tree delta is one file and only reorders CWE-400/CWE-1333 in GHSA-36JR-MH4H-2G58. Record: nonsemantic metadata reorder. This packet does not claim causality and does not emit PASS. The source repo was not cloned.

## Compare

Official github/advisory-database clone lived only under `/home/hanqing/.cache/ai-slop-ghsa200/advisorydelta-post-a42c` and is removed at handoff. Exact temp files `/tmp/ghsa36jr-old.json`, `/tmp/ghsa36jr-new.json`, and `/tmp/ghsa36jr-new.err` are removed. Replay asserts their absence.

- Frozen: `a42c436870111aa3f221257c9d56126a93173ccc` at 2026-08-13T20:57:17Z
- Current remote: `37f259e500d68dec361b264b9a3027fc0a715088` at 2026-08-14T09:33:06Z
- Range commits: 6
- github-reviewed identities: 34389 frozen, 34389 current
- Added reviewed: 0
- Modified reviewed: 1
- Deleted reviewed: 0
- Unreviewed path churn (out of denominator): 201 added, 193 modified

## In-range reviewed advisory

The only github-reviewed path change is `advisories/github-reviewed/2022/09/GHSA-36jr-mh4h-2g58/GHSA-36jr-mh4h-2g58.json`, touched by `e5cd38e04446540cd1a831d5653237b978843c43`.

- Identity: GHSA-36JR-MH4H-2G58
- Delta kind: nonsemantic metadata reorder
- Semantic fields unchanged: identity, repo, fix, version, reference, published, modified, aliases, summary, ranges
- Blob delta: CWE identifier order only (`CWE-400`,`CWE-1333` to `CWE-1333`,`CWE-400`)
- Frozen blob sha1 `aed54f0f7c43edcfcbc185c0172f63e0a80466c6` sha256 `901eb7a6bd047d507ac1e34eca968e602592188a9dad2fc01fac26c99d37714f`
- Current blob sha1 `483a07a3f0d43db4aba0f8fb4a6c49ea605b9024` sha256 `35ba98fb18293a0d84db2dceefcb5bd4b926d6b78faaa3ee6094bb4d095268fa`
- Fix refs from the advisory (unchanged): pull `https://github.com/d3/d3-color/pull/100`; release `https://github.com/d3/d3-color/releases/tag/v3.1.0`; no commit SHAs
- Overlap: `autoresearch/herdr-260813-ghsa200-current-delta/cases.jsonl` (prior modified-reviewed NOTE; counted_as_new_id false)
- Routing outcome: NONSEMANTIC_METADATA_REORDER. Not retained. Not net-new.

## Totals

- in-range reviewed advisories: 1
- retained after filters: 0
- net-new candidate GHSA IDs: none
- causal admission: false
