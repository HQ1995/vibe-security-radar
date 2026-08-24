# Reverse incomplete-remediation census (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none.

## Why reverse

Prior incomplete-remediation packets started from advisory keyword language and blamed closer deleted lines. This census starts from exact AI-marked commits that explicitly attempted a security guard or remediation, then requires a later first-party GHSA closer on the same repository. The later advisory must name a residual bypass, and the later minimum fix must amend the same file or function boundary. Generic old bugs, AI-on-fix, unrelated security work, squash attribution transfer, unreleased attempts, and broad file overlap are rejected. ROUTE only; never PASS.

## Freeze

Pinned github/advisory-database HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 github-reviewed tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` (34389 reviewed identities) at read-only `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` status HOLD, strict 94.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No clone was retained. Anonymous public git only.

Incomplete-remediation20 through 20m selected freezes plus fresh remediation packets are exclusion sources. Frozen union 291 identities (IR 249, fresh 42). Overlap with remaining identity-eligible rows: 0. Extra frozen identities outside the eligible slice sit in withdrawn / no-repository / no-same-repo-fix / no-first-party-repo-advisory buckets.

## Inventory (recomputed; not reused from prose)

Terminal herdr/orchestrator 260813-260815 top-level cases/adjudication/result artifacts parsed, skipping work/pages/snapshot/clones/cache/tmp and nested notes/diffs/facts/node_modules: files=716 cases.jsonl=330 adjudications=40 result.json=346 rows=16355. Distinct identities with an explicit terminal verdict field: 10888. Shared SHA is not identity dedupe. The inventory source path list is pinned; later packets are ignored.

## Universe and identity

github-reviewed identities 34389.
Identity requires an exact `owner/repo/security/advisories/GHSA` reference for the same GHSA plus a same-repo 40-hex closer commit reference. A GitHub repository URL or range.repo field alone fails. CVE aliases are not counted.

34389 = withdrawn 910 + no_repository 4068 + no_same_repo_fix 14050 + no_first_party_repo_advisory 6637 + identity-eligible 8724.
Identity-eligible 8724 = canonical94-eligible 62 + later terminal 5992 + frozen-extra 0 + remaining 2670.
Of canonical94 strict 94, 32 fail this identity parser and already sit in the non-eligible buckets; all 94 remain excluded from remaining.
Remaining 2670 = no_local_clone 1104 + closer-present 1566.

## Reverse search

Closer-present 1566 mapped to read-only local clones. Closer object required (`git cat-file -t` == commit). Search: first-parent history of closer-touched code files (up to 250 no-merge ancestors). Atomic source_matcher authorship. Explicit security-attempt subject or trailer body (guard, sanitizer, allowlist, denylist, validation, bypass, CVE/GHSA fix language). Candidate must be an ancestor of the closer and must not be the closer. Same-code-file overlap with the closer is required; same-function overlap ranks higher. Advisory residual-bypass language is required to ROUTE. Vulnerable tags must contain the candidate and not the closer. Megapatch candidates (>40 code files), closers with >80 code files, test/lockfile-only overlap, squash n_parents!=1, and class-token disjoint security work are rejected.

Results on 1566 closer-present rows:
- fix_object_missing 36
- closer_no_code 263
- broad_closer 1 (GHSA-H77F-XXX7-4858)
- no_ai_security_attempt 1266
- high_signal 0
- ROUTE 0

Repos with any AI-marked ancestor on closer code files: 1. Repos with an AI-marked explicit security-attempt ancestor on those files: 0.

HEAD-side AI markers exist in many remaining 2025 repositories, but `git merge-base --is-ancestor` against the GHSA closer fails: those commits are descendants of the closer (later hardening or AI-on-fix), not prior attempts. Path-filtered first-parent history of the closer therefore yields no countable reverse IR edge.

Closest miss, still not ROUTE: GHSA-92CP-5422-2MW7 redis/go-redis. Closer `d236865b0cfa1b752ea4b7da666b1fdcd0acebb6` (`fix: handle network error on SETINFO`, CVE-2025-29923). One atomic Copilot coauthor ancestor `ebe11d06ca95d2692bece729bda565d401cc7e54` (`feat: Enable CI for Redis CE 8.0`) touches closer files including `redis.go` but is CI enablement, not an explicit security guard. Residual-bypass language is absent from the advisory. Parent of closer: `74d4f084764d855c811ebd2c57193f74fe0ec7ad`.

Thirty-five closer-present advisories carry residual-bypass language. None had an AI-marked security-attempt ancestor on the closer code boundary.

Did not pad to 80. Assigned 0.

## Conservation

34389 = 910 + 4068 + 14050 + 6637 + 8724. Holds.
8724 = 62 + 5992 + 0 + 2670. Holds.
2670 = 1104 + 1566. Holds.
1566 = 36 + 263 + 1 + 1266 + 0. Holds.
assigned 0 = reviewed 0 + unreviewed 0. Equation 0=0+0. Holds. Did not pad.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Canonical94 remains 94 HOLD.

Full-row check: 34389 = 910+4068+14050+6637+62+5992+0+1104+36+263+1+1266+0. Holds.

## Claim boundary

Worker PASS is a proposal only. This packet admits nothing. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported.

ROUTE IDs: none.

Stop. No ledger, site, or other-directory edits. No retained clone or advisory fetch. No commit or push. No PASS.
