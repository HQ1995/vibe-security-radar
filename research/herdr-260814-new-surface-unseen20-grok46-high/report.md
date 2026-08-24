# Unseen first-party new-surface freeze

Verdict first: **0 PASS_PROPOSAL**. Frozen inspected count is **5**. All 5 are **REJECT**. Did not pad to 20. packet_delta=0. Canonical strict count remains **91**. Publication and more-than-200 remain **HOLD**. Worker PASS is proposal only; this packet emits none. Incomplete-remediation rows were excluded from counting.

## Bound and conservation

Current github-reviewed tree is advisory-database HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` (34389 reviewed objects). Withdrawn 910. Exclusion union of canonical91 strict 91 plus every identity with a terminal verdict in existing 260813-260814 herdr/orchestrator assignment.jsonl, cases.jsonl, and result.json per_case/reviewed sets: **8203** (314 packets, 612 files; skip work/notes/pages/snapshot/clones/cache/tmp). Remaining first-party reviewed identities with a GitHub repository: **22534**. Local clone plus commit SHA: 7700. Non-mega clones scanned for post-2024-06-01 atomic source_matcher file-add or surface hunks: 1316 clones / 6600 GHSAs. Clones with an AI atomic commit: 664. Exact fix-path overlap that is an ancestor of the listed closer: 19. After requiring an added file or an added route/handler/parser/integration hunk, and dropping incomplete-remediation, **5** identities remained. Those 5 were frozen and fully adjudicated. Did not pad.

Equation: 5 frozen = 5 reviewed + 0 unreviewed.

Mining required a pre-fix AI-marked atomic commit that adds the exact advisory-reachable file, route, handler, parser, integration, or copied component. Same-file overlap is routing only until hunk but-for closes. Old-bug preservation, human PR members under AI squash trailers, and sibling files fail.

## Per identity (all REJECT)

1. GHSA-3VCP-CHFH-F6R2 kumahq/kuma. REJECT. Copilot squash a7a023a7 adds kri_endpoint.go. Parent already has CorsAllowedDomains .* and LocalhostIsAdmin true. Closer 8fefa859 hardens that old pair and does not touch the KRI file. Sibling route. 0 local tags. uniqueness PASS versus canonical91.
2. GHSA-F696-867G-2759 jenkinsci/opentelemetry-plugin. REJECT. Copilot trailer is Apply suggestions from code review on human squash #1098. Closer f5a4ec12 adds isAuthorized(). Incomplete rem is out of scope. Tag 3.1520.vd981c197a_43f contains the candidate not the closer; that is not origin.
3. GHSA-FXP5-37MH-VFF5 jenkinsci/blazemeter-plugin. REJECT. Copilot 3f34e690 only reindents ListBoxModel. Closer 9fe5ed70 is a two-parent merge. Tag 4.27 contains both; 4.26 contains neither.
4. GHSA-MJ73-J457-8X9Q oschwald/maxminddb-rust. REJECT. Claude 11fc4300 is a module rename (R100 reader_test.rs, split reader.rs). Parent changelog already has Reader::open_mmap. v0.27.0 contains candidate and closer. Old-bug preservation / move.
5. GHSA-P58C-Q354-6C4F pgadmin-org/pgadmin4. REJECT. Claude trailer on Dave Page squash #9703 adds OpenAI/Anthropic API URL fields. Parent already had unvalidated ollama_api_url, docker_api_url, and ANTHROPIC_API_KEY_FILE. GHSA names api_url and api_key_file generally. Sibling fields plus old LFI. REL-9_14 vs REL-9_15 containment does not override but-for. No member peel; do not transfer the trailer.

## Claim boundary

No worker proposal changes the count. Current leader HOLD snapshot is canonical strict **91**. This packet does not edit canonical or site files and does not support a greater-than-200 claim.
