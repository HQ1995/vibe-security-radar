# Precutoff 2021-01 to 2022-12 routing census (canonical94)

**Status: TERMINAL.** Worker PASS is a proposal only. This packet emits none. Canonical strict count remains **94**. Publication and a more-than-200 claim remain **HOLD**. packet_delta=0. This packet does not call a PASS.

## Why this window

The user goal has no date cutoff. Prior nextqueue-v2 classified github-reviewed identities published before 2025-05-01 as outside_coverage_window. This packet enumerates the disjoint GitHub-reviewed historical slice published 2021-01-01 inclusive through 2023-01-01 exclusive.

## Freeze

Frozen github/advisory-database HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 github-reviewed tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` (34389 reviewed identities) at read-only `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database`. CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096`, summary SHA256 `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b`, status HOLD, strict 94.

Date window: published 2021-01-01 inclusive to 2023-01-01 exclusive.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No clone was retained. Anonymous public git only. Copilot earliest-date policy is 2022-06-01; Copilot-era dates in this window are plausible. AI was never inferred from date or name alone.

## Universe and exclusions

GitHub-reviewed identities in the date window: **11366** (min 2021-01-04T18:22:11Z, max 2022-12-31T21:30:20Z). Empty published 0. Conservation:

11366 = 162 withdrawn + 9183 no exact owner/repo/security/advisories/GHSA + 684 no same-repo 40-hex closer + 0 canonical94 + 0 later terminals + 1337 assigned + 0 unknown.

Inventory of 260813-260815 top-level cases/adjudication/result artifacts, skipping work/pages/snapshot/clones/cache/tmp: files=719 cases.jsonl=334 adjudications=34 result.json=351 rows=16477. Distinct explicit terminal verdict identities=11130. Shared SHA is not identity dedupe. Files newer than the pinned inventory cutoff are ignored.

Eligible first-party identity (exact repo advisory URL and same-repo 40-hex commit) after canonical94 and later-terminal exclusion: **1337**. Overlap with canonical94: 0. Overlap with later terminals: 0. Assigned 1337=1337+0.

## Identity and clones

Every assigned row has a public repository advisory at the exact owner/repo/security/advisories/GHSA URL and at least one same-repo 40-hex commit reference. Read-only local clone map size 6285. Unique local repositories grouped for scan: 180. has_clone 831. closer object present 807. no_local_clone 506. closer_not_in_local_clone 24. repo_git_timeout 0.

## Routing

ROUTE 0. Deep inspect 0 of a max 20. Ranked exact-hunk source_matcher candidates: 0. Did not pad. Each unique local repository received at most one bounded batched `git log` of all closer ancestors (hard 20s timeout) plus one `cat-file --batch-check` (hard 8s timeout). Timed-out repositories would be UNKNOWN; none timed out. Matching metadata was fed to production source_matcher in memory. No per-advisory or per-commit `git show` loop ran, so atomic same-mechanism hunk overlap was not opened. Landed topology and a vulnerable released artifact were required for ROUTE and were not opened without an exact-hunk candidate. AI-on-fix, filename overlap, shared SHA, PR branding, squash-carrier trailer, OSV introduced, and community prose were not used as causal evidence.

All 1337 assigned rows are REJECT_ROUTING, proposed_pass=false. Reasons: no_local_clone 506, closer_not_in_local_clone 24, no_atomic_source_matcher_hunk 807. UNKNOWN 0. PASS 0.

## Claim boundary

Worker PASS is a proposal only. This packet admits nothing. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported. Canonical94 remains 94 HOLD.

## Replay

`zsh autoresearch/herdr-260815-precutoff-2021-2022-grok46-low/replay.zsh`

Two consecutive runs must be byte-identical with empty stderr.
