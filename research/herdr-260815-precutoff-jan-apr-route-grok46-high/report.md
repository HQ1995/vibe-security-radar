# Precutoff Jan-Apr route (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none.

## Why this window

The user goal has no date cutoff. Prior nextqueue-v2 classified github-reviewed identities published before 2025-05-01 as outside_coverage_window (9533 after withdrawn / no_repository / no_same_repo_fix). This packet enumerates the GitHub-reviewed Jan-Apr 2025 slice of that excluded period: published 2025-01-01 inclusive to 2025-05-01 exclusive.

## Freeze

Pinned nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` status HOLD, strict 94.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` from read-only cache `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database`. Reviewed JSON identities: 34389.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No clone was retained. Anonymous public git only.

## Inventory (recomputed; not reused from prose)

Terminal herdr/orchestrator 260813-260815 top-level cases/adjudication/result artifacts parsed, skipping work/pages/snapshot/clones/cache/tmp and nested notes/diffs/facts/node_modules: files=694 cases.jsonl=322 adjudications=34 result.json=338 rows=14957. Distinct identities with an explicit terminal verdict field: 9627. Shared SHA is not identity dedupe. Files newer than the pinned inventory cutoff are ignored.

## Universe and identity

github-reviewed identities 34389. Jan-Apr published 1181 (min 2025-01-02T06:30:47Z, max 2025-04-30T17:41:16Z). Empty published 0.
Identity requires an exact `owner/repo/security/advisories/GHSA` reference for the same GHSA plus a same-repo 40-hex closer commit reference. A GitHub repository URL or range.repo field alone fails. CVE aliases are not counted.

Jan-Apr 1181 = withdrawn 34 + no_repository 36 + no_same_repo_fix 528 + no_first_party_repo_advisory 186 + identity-eligible 397.
Identity-eligible 397 minus canonical94 overlap 0 minus later terminal 173 = remaining 224.
Remaining 224 = no_local_clone 90 + fix_object_missing 0 + closer-present 134.

## Routing search

Closer-present 134 mapped to read-only local clones. Closer object required (`git cat-file -t` == commit). Search: fix-touched history (up to 250 no-merge ancestors of the closer parent on closer paths) plus local PR members; atomic source_matcher authorship; exact hunk overlap with closer-deleted lines; or blame of closer-deleted code hunks. Landed topology required (candidate is an ancestor of the closer). Vulnerable released-artifact evidence would be required to ROUTE. AI-on-fix, filename overlap, shared SHA, PR branding, squash-carrier trailer, OSV introduced, and community prose do not route.

Exact hunk candidates: 0. Blame-hunk AI: 0. Deep inspect 0 of max 20. Leftover unreviewed 0. ROUTE 0.

Two non-routing AI markers were observed and were not assigned:
- GHSA-92CP-5422-2MW7 redis/go-redis Copilot `ebe11d06ca95` landed; filename overlap README.md and redis_test.go; overlap_lines 0. Filename overlap does not route.
- GHSA-HX7H-9VF7-5XHG louislam/uptime-kuma Copilot `2a6d9b4acda1` is not an ancestor of closer `7a9191761dbe`. Not-landed does not route.

no_exact_hunk 134. assigned 0.

## Conservation

1181 = withdrawn 34 + no_repository 36 + no_same_repo_fix 528 + no_first_party_repo_advisory 186 + canonical94 0 + terminal_verdict 173 + no_local_clone 90 + fix_object_missing 0 + no_exact_hunk 134 + assigned 0.
Equation 1181=34+36+528+186+0+173+90+0+134+0. Check: 1181 = 1181. Holds.
assigned 0 = reviewed 0 + unreviewed 0. Equation 0=0+0. Holds. Did not pad.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Canonical94 remains 94 HOLD.

## Claim boundary

Worker PASS is a proposal only. This packet admits nothing. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported.

Stop. No ledger, site, or other-directory edits. No retained clone or advisory fetch. No commit or push. No PASS.
