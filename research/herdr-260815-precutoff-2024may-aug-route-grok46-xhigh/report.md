# Precutoff May-Aug 2024 route (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none.

## Why this window

The user goal has no date cutoff. Prior nextqueue-v2 classified github-reviewed identities published before 2025-05-01 as outside_coverage_window (9533 after withdrawn / no_repository / no_same_repo_fix). This packet enumerates the GitHub-reviewed May-Aug 2024 slice of that excluded period: published 2024-05-01 inclusive to 2024-09-01 exclusive.

## Freeze

Pinned nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` status HOLD, strict 94.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` from read-only cache `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database`. Reviewed JSON identities: 34389.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No clone was retained. Anonymous public git only.

## Inventory (recomputed; not reused from prose)

Terminal herdr/orchestrator 260813-260815 top-level cases/adjudication/result artifacts parsed, skipping work/pages/snapshot/clones/cache/tmp and nested notes/diffs/facts/node_modules: files=700 cases.jsonl=325 adjudications=34 result.json=341 rows=15628. Distinct identities with an explicit terminal verdict field: 10295. Shared SHA is not identity dedupe. The inventory source path list is pinned; later packets are ignored.

## Universe and identity

github-reviewed identities 34389. May-Aug 2024 published 1435 (min 2024-05-01T08:29:48Z, max 2024-08-31T00:31:05Z). Empty published 0. Before 2024-05-01: 19131. On or after 2024-09-01: 13823.
Identity requires an exact `owner/repo/security/advisories/GHSA` reference for the same GHSA plus a same-repo 40-hex closer commit reference. A GitHub repository URL or range.repo field alone fails. CVE aliases are not counted.

May-Aug 1435 = withdrawn 33 + no_repository 71 + no_same_repo_fix 534 + no_first_party_repo_advisory 430 + identity-eligible 367.
Identity-eligible 367 minus canonical94 overlap 0 minus later terminal 0 = remaining 367.
Remaining 367 = no_local_clone 155 + fix_object_missing 4 + closer-present 208.

Closer object missing (mapped clone present, `git cat-file -t` is not commit; no fetch): GHSA-GJ7M-853R-289R grafana/grafana, GHSA-JV32-5578-PXJC grafana/grafana, GHSA-MCMC-C59M-PQQ8 GeoNode/geonode, GHSA-X744-MM8V-VPGR grafana/grafana.

## Routing search

Closer-present 208 mapped to read-only local clones. Closer object required (`git cat-file -t` == commit). Search: fix-touched history (up to 250 no-merge ancestors of the closer parent on closer paths) plus local PR members; atomic source_matcher authorship; exact hunk overlap with closer-deleted lines; or blame of closer-deleted code hunks. Landed topology required (candidate is an ancestor of the closer). Vulnerable released-artifact evidence would be required to ROUTE. AI-on-fix, filename overlap, shared SHA, PR branding, squash-carrier trailer, OSV introduced, and community prose do not route.

Exact hunk candidates: 0. Blame-hunk AI: 0. Closer AI (AI-on-fix): 0. Filename-only landed AI: 0. Deep inspect 0 of max 20. Leftover unreviewed 0. ROUTE 0.

no_exact_hunk 208. assigned 0.

## Conservation

1435=33+71+534+430+0+0+155+4+208+0
1435 = withdrawn 33 + no_repository 71 + no_same_repo_fix 534 + no_first_party_repo_advisory 430 + canonical94 0 + terminal_verdict 0 + no_local_clone 155 + fix_object_missing 4 + no_exact_hunk 208 + assigned 0.
Check: 1435 = 1435. Holds.
assigned 0 = reviewed 0 + unreviewed 0. Equation 0=0+0. Holds. Did not pad.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Canonical94 remains 94 HOLD.

## Claim boundary

Worker PASS is a proposal only. This packet admits nothing. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported.

Stop. No ledger, site, or other-directory edits. No retained clone or advisory fetch. No commit or push. No PASS.
