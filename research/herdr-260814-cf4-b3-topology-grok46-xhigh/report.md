# CF4 bucket-3 topology freeze

Verdict first: **0 PASS_PROPOSAL**. Frozen inspected count is **12**. **NARROW=2 REJECT=10**. Did not pad. packet_delta=0. Canonical strict count remains **88**. Publication and more-than-200 remain **HOLD**. Worker PASS is proposal only; this packet emits none.

## Universe and conservation

Advisory split: github-reviewed from `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` subtree `advisories/github-reviewed` only (this clone has no unreviewed tree). Unreviewed subtree only from `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226` subtree `advisories/unreviewed`. Union by uppercase GHSA ID; f2c6 reviewed wins on 1 collision. Did not drop unreviewed cases. The older 39d888 reviewed tree did not constrain reviewed selection.

Reviewed files 34389 (910 withdrawn); bucket 3 = 5588; first-party kept 4055. Unreviewed files 317316; bucket 3 = 53152; first-party kept 284 (all `fp_kind=release_tag`). Union 4338. Prior structured `case_id` / `ghsa_id` / `reviewed_case_ids` / `assigned_ids` / `strict_released_case_ids` exclusions 8056 IDs. Eligible after exclude **3132** (2853 reviewed + 279 unreviewed). Eligible with local clone 1812.

Own bucket: `int(sha256(uppercase GHSA ID),16)%6==3`. Freeze 12 identities that have real Git objects and first-party evidence. Equation: 12 frozen = 11 reviewed + 1 unreviewed. Did not pad.

Focus: squash and merge-from-fork topology. Carrier, parent, and member sets are resolved without transferring authorship. Blob equality does not transfer authorship. Routing is not causality. Prefer zero PASS over one false positive.

## Per identity

1. GHSA-MG56-WC4Q-RW4W usememos/memos. NARROW. github-reviewed. Human squash closer `769dcd0c` (#5217) n_parents=1 author Florian Dewald; parent `df93120f`; ancestor of v0.25.3 peel `e17cd163`, not the origin. user_service.go blobs unequal: v0.25.2 `3bead551`, closer `e5de08db`, v0.25.3 `8ca61773`, Claude `b5e452fc`. Claude `1a329855` exists locally, source_matcher author_identity, 0 tags, not an ancestor of v0.25.3. Registration member `75deb94f` is absent from the durable clone. Investigation PR fetch recovered human security members; that tmp clone was deleted and is not replayed. identity PASS, topology PASS, ai_hunk FAIL, but_for FAIL, release FAIL.
2. GHSA-6556-FWC2-FG2P mmaitre314/picklescan. REJECT. Human squash `70c1c6c3` (#53) is tag v0.0.33; parent/v0.0.32 `d3273f42`. source_matcher empty. PR members 0 AI atomic.
3. GHSA-VV6J-3G6G-2PVJ mmaitre314/picklescan. REJECT. Human squash `7f994d62` (#47) is tag v0.0.28; parent/v0.0.27 `58983e1c`. Distinct mechanism from 6556. 0 AI atomic.
4. GHSA-JJJJ-JWHF-8RGR minio/minio. REJECT. Human squash `c1a49490` (#21642) n_parents=1. Ancestor of RELEASE.2025-10-15T17-29-55Z, not of RELEASE.2025-09-07T16-13-09Z peel `07c3a429`. source_matcher empty.
5. GHSA-FGHV-69VJ-QJ49 netty/netty. NARROW. Human "Merge commit from fork" `edb55fd8` (#15611) n_parents=1 Norman Maurer. Ancestor of netty-4.2.5.Final, not 4.2.4.Final. Fork unique commits are not in the local clone. source_matcher empty. topology NARROW.
6. GHSA-4HR2-XF7W-JF76 line/centraldogma. REJECT. Human squash `95e7bbd7` (#1207) n_parents=1. Ancestor of centraldogma-0.78.0 peel `36231f7a`. source_matcher empty.
7. GHSA-FPJQ-C37H-CQCV kyverno/kyverno. REJECT. Official closers are merge-from-fork `80e728c2` (#15887, in v1.16.4) and `76c8fdbe` (#15888, in v1.17.2, not in v1.16.4). Both n_parents=1 with Assisted-by Claude text; source_matcher v3 emits no match. AI-on-fix routing, not origin.
8. GHSA-XJ37-QJG2-XWV2 whyour/qinglong. REJECT. Copilot SWE authored official closer `6bec52dc` (#2941), which is tag v2.20.1 and an ancestor of v2.20.2. source_matcher github_copilot on the fix. AI-on-fix.
9. GHSA-X3HX-CH7P-8XGG mattermost/mattermost. REJECT. Official closer `c8d66301` (#32162) n_parents=1 is the GHSA fixed pseudo-version and an ancestor of v11.0.0-alpha.1. source_matcher claude_code on the closer. GHSA range is introduced 0, fixed at this SHA. AI-on-fix, not origin.
10. GHSA-PW7P-7FQV-HPJ8 osrg/gobgp. REJECT. Human closer `9ce89366` edits BGPUpdate.DecodeFromBytes; in v4.4.0 not v4.3.0. Copilot ancestor `38c64c91` edits LsTLV Serialize in the same file; DecodeFromBytes is absent from that diff. Same-file routing.
11. GHSA-XH5W-G8GQ-R3V9 keylime/keylime. REJECT. Advisory is UUID/TPM recycle. Cited closer `e1ae8de1` is notify_error() only, in v7.13.0 not v7.12.0, source_matcher empty. Claude Assisted-by on shutdown/session commits in the same file is a wrong edge.
12. GHSA-PWFC-QM9R-P6H4 nesquena/hermes-webui. REJECT. 39d888 unreviewed; github_reviewed=false; affected=[]; no repository advisory URL. First-party release-tag admission only. Closer `3cc5839b` (#412) co-authored-by hinotoi-agent is not a recognized AI identity (source_matcher empty). Distinct from counted GHSA-VVFR. Local tags only v0.51.357 / v0.51.358; listed v0.50.32 / v0.50.132 are absent. identity FAIL. Did not drop this unreviewed row.

## Claim boundary

No worker proposal changes the count. Current leader HOLD snapshot is canonical strict **88**. This packet does not edit canonical or site files and does not support a greater-than-200 claim.
