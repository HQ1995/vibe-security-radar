# Fresh reviewed delta3 (c2edfe3 versus 39d888)

Verdict first: **1 PASS_PROPOSAL** (`GHSA-76PC-MQXP-3RQ5`). **1 NARROW** (`GHSA-49MQ-FC6Q-3H46`). Inspected **2**. Bound 20 not filled. Did not pad. Packet delta **0**. Canonical91 stays **91**. Publication and greater-than-200 remain **HOLD**. Worker PASS is proposal only.

## Freeze

Current github-reviewed tree at `c2edfe3bafcf48ae374e1c5e15ac98ae98fa68da` (tree `1741a07b16252ffb489c9f037979a9941007b283`, committer 2026-08-15T00:33:25+00:00) was listed from a temporary blob:none fetch with read-only alternates into `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database`. Canonical91 source cutoff is `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226` (tree `3a1267e940595e82f109a750f2779d987ff4d01b`, committer 2026-07-23T12:34:36+00:00). Shared caches were read-only. Temporary clone, npm tarballs, and advisory blobs were deleted after hashing.

New reviewed IDs 34406. Old reviewed IDs 33646. Added **760**. Removed **0**. Exact sorted added-ID sha256 `4849f8318879d992f68c54a58262826624f638b5dc945f25c27ca540b8717c3d`. Versus prior freeze f2c6ab3: added **17** (sha256 `e0a7bf058d950fa2ddf7aacddf9648600787d55319b6a304b5b178b01ff9a019`).

Official GitHub `/advisories` objects were fetched for the three post-f2c6 remainders. GHSA-9Q54-F358-3FQF is first-party reviewed s2n-quic but has no exact 40-hex same-repo commit reference, so it was not selected.

## Exclusion (frozen; replay does not glob)

Canonical91 strict IDs: **91**. Structured prior terminal `assignment.jsonl` / `cases.jsonl` `case_id` values from herdr-* and orchestrator-* packets, skipping work/notes/pages/snapshot/clones/cache/tmp: union **8200** after adding the 91. Exact sorted-ID sha256 `958f96dc44696364a621616ffe4212af46f8acd3578a6d47a4b32152944d631e`. Files parsed 332. The ID list is frozen inside result.json.

Delta overlap with exclusion: **681**, including 14 already in canonical91. Remaining added identities: **79**. CVE aliases are not counted.

## Rank

Remaining 79 are all github-reviewed. Withdrawn 10. Empty affected 0. GitHub-repo 79. Active GitHub-repo exact 40-hex fix: **33**. First-party repo-advisory URL matching the same GHSA: **21**.

Rank required exact same-repo fix plus pre-fix `source_matcher` evidence under contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`. Listed closers on the other exact-fix remainders were human. Code-file history of those closer paths, cap 15, produced **0** additional matcher hits. Inspect cap 20. Strongest plausible-AI set size **2**. Did not pad.

## Inspected set

| n | ID | Origin | Closer | Verdict |
| --- | --- | --- | --- | --- |
| 1 | GHSA-76PC-MQXP-3RQ5 | Claude 051f2747 | b4ee96dac | PASS proposal |
| 2 | GHSA-49MQ-FC6Q-3H46 | fc358254 footer URL miss | b4ee96dac | NARROW |

### GHSA-76PC-MQXP-3RQ5 PASS proposal

All seven gates PASS at dashboard sessionId path-traversal scope. Worker PASS is not admission.

1. identity_gate PASS. github-reviewed GHSA-76pc-mqxp-3rq5 aliases CVE-2026-55156, not withdrawn. Official object type=reviewed, repository_advisory_url on ooples/token-optimizer-mcp.
2. ai_hunk_gate PASS. Atomic 051f2747 n_parents=1. Co-Authored-By: Claude <noreply@anthropic.com>. Parent has no web-server.ts.
3. topology_gate PASS. No member-to-carrier transfer. Closer Claude trailers are not transferred onto 051f2747.
4. but_for_gate PASS. Removing 051f2747 removes the endpoints.
5. fix_reversal_gate PASS. Closer adds isValidSessionId on both named routes.
6. release_gate PASS. npm 5.0.1 tarball sha256 4594c2d6140c20dd64d85fb5ceee660c8f943ff76f779d610d8554eea7267761 has session-log- and zero isValidSessionId. npm 5.1.1 tarball sha256 1828e97d1c7dabfb7d6d27ac786b88e1977c5fa95f3da1f12bb1630533e670da has isValidSessionId. Git tag v5.1.0 contains the closer. npm 5.1.0 is unpublished.
7. uniqueness_gate PASS versus canonical91 strict 91 and versus GHSA-49MQ. Shared SHA b4ee96dac is the closer here.

### GHSA-49MQ-FC6Q-3H46 NARROW

identity_gate PASS (CVE-2026-55157). ai_hunk_gate FAIL: origin fc358254 footer uses claude.com/claude-code, not frozen claude.ai/code. matches_for_commit empty. Closer is AI-on-fix. topology_gate PASS. but_for_gate NARROW. fix_reversal_gate PASS (execFileSafe). release_gate PASS. uniqueness_gate PASS. Prefer no seven-gate PASS over admitting a non-contract footer.

## Conservation

2 assigned = 2 reviewed + 0 unreviewed. Equation `2=2+0`. Eligible after rank filter 2. Inspected 2. Did not pad. cve_aliases_counted=false. canonical91_overlap on the inspect set=0. Added canonical91 overlap 14 excluded from ranking. packet_delta=0.

## Claim boundary

This packet proposes one PASS and does not admit it. Current leader-accepted strict count remains 91 HOLD. Greater-than-200 remains unsupported. Canonical91 was not rebuilt. No commit, push, website, or edits outside this directory.
