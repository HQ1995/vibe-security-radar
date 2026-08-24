# Precutoff 2024-09 to 2024-12 routing census (canonical94)

**Status: TERMINAL.** Worker PASS is a proposal only. This packet emits none. Canonical strict count remains **94**. Publication and a more-than-200 claim remain **HOLD**. packet_delta=0. This packet does not call a PASS.

## Freeze

Frozen github/advisory-database HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 github-reviewed tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` (34389 reviewed identities) at read-only `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database`. CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096`, summary SHA256 `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b`, status HOLD, strict 94.

Date window: published 2024-09-01 inclusive to 2025-01-01 exclusive.

## Universe and exclusions

GitHub-reviewed identities in the date window: **1006**. Conservation:

1006 = 41 withdrawn + 454 no exact owner/repo/security/advisories/GHSA + 160 no same-repo 40-hex closer + 0 canonical94 + 0 later terminals + 351 assigned + 0 unknown.

Inventory of 260813-260815 top-level cases/adjudication/result/assignment/selected artifacts, skipping work/pages/snapshot/clones/cache/tmp: files=867 cases.jsonl=323 adjudications=34 result.json=339 selected.jsonl=56 assignment.jsonl=115 rows=16813. Distinct explicit terminal verdict identities=9627. Selected-or-inspected identities=2673. Union=9630.

Eligible first-party identity (exact repo advisory URL and same-repo 40-hex commit) after canonical94 and later-terminal exclusion: **351**. Overlap with canonical94: 0. Overlap with later terminals: 0. Assigned 351=351+0.

## Identity and clones

Every assigned row has a public repository advisory at the exact owner/repo/security/advisories/GHSA URL and at least one same-repo 40-hex commit reference. Read-only local clone map size 6285. has_clone 244. closer object present 239. no_local_clone 107. closer_not_in_local_clone 5.

## Routing

ROUTE 0. Deep inspect 0 of a max 20. Ranked exact-hunk source_matcher candidates: 0. Did not pad. Fix-touched history (git log closer -- closer files, cap 250) plus PR-member log grep on the 239 object-present rows produced 0 atomic source_matcher hits. AI-on-fix, filename overlap, shared SHA, PR branding, squash-carrier trailer, OSV introduced, and community prose were not used as causal evidence. Landed topology and a vulnerable released artifact were required for ROUTE and were not opened without an exact-hunk candidate. source_matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.

All 351 assigned rows are REJECT_ROUTING, proposed_pass=false. Reasons: no_local_clone 107, closer_not_in_local_clone 5, no_atomic_source_matcher_on_fix_touched_history 239.

## Claim boundary

Worker PASS is a proposal only. This packet admits nothing. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported. Canonical94 remains 94 HOLD.

## Replay

`zsh autoresearch/herdr-260815-precutoff-2024sep-dec-route-grok46-low/replay.zsh`

Two consecutive runs must be byte-identical with empty stderr.
