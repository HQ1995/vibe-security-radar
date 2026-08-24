# CF4 B1 incomplete-remediation predecessor packet (proposal only)

Verdict: **0 PASS_PROPOSAL / 0 REJECT / TERMINAL**. Frozen **0**. Shortfall **12**. Canonical88 stays 88. Countable pass 0. Greater-than-200 remains unsupported. Worker PASS is proposal only. Publication stays HOLD. Prefer zero PASS.

## Bound

Eligible remaining bucket-1 after structured exclusions and canonical88: **56891**.

Rank remaining 2025-2026 first-party rows with exact repo advisory URL or same-repo fix commit, then local clone plus real fix objects, then uppercase GHSA ID. Github-reviewed f2c6 wins on collision.

Inspect cap 600. Qualified ranked pool **430** (419 reviewed, 11 unreviewed). Inspected prefix **430**. Stop reason: **qualified_pool_exhausted_shortfall_12**. Did not pad. Did not scan other years or non-first-party remainder.

Prefix first `GHSA-227X-7MH8-3CF6`. Prefix last `GHSA-XVWH-VH35-WWV2`.

## Method

For each ranked row with a local clone and a real official-fix object, walk fix-touched source files backward **250** first-parent commits. Freeze only atomic (`n_parents=1`) production `source_matcher` v3 commits that explicitly attempt the same security invariant as the GHSA: authorization, validation, escaping, path safety, SSRF restriction, command safety, sandboxing, or fail-closed behavior.

That freeze signal is not seven-gate PASS. Generic refactors, other security work in the same file, new callers of old flaws, later human reintroduction, AI-on-fix, and safer-but-incomplete changes that only shrink an old broad hole without creating the residual GHSA boundary are rejected.

Did not repeat CF4-b1-blame fix-line blame. Did not re-review CF4-b1-history same-file AI ancestors.

## Sources

github-reviewed subtree: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`.

unreviewed subtree only: `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226`.

Union by uppercase GHSA ID; reviewed f2c6 wins on collision (135 collisions). Unreviewed identities stayed eligible; 11 entered the qualified pool; 1 had a local git object; none froze.

## Conservation

Exclusion parse of structured `case_id`, `ghsa_id`, `reviewed_case_ids`, `assigned_ids`, `strict_released_case_ids` across prior herdr/orchestrator terminal artifacts plus canonical88: **8159** IDs. Free-text mentions were not excluded. CF4-b1-blame 12 and CF4-b1-history 12 are inside that set and were not re-reviewed.

| layer | n |
| --- | --- |
| reviewed files f2c6 | 34389 |
| unreviewed files 39d888 | 317316 |
| eligible remaining bucket-1 | 56891 |
| 2025-2026 first-party exact repo advisory/fix | 430 |
| local clone plus real fix objects | 165 |
| skip no clone or no real object | 265 |
| no source files on closer | 19 |
| git-searched 250 first-parent | 146 |
| atomic AI same-invariant predecessors | 0 |
| freeze / assigned | 0 |
| shortfall versus 12 | 12 |

Assigned 0 = reviewed 0 + unreviewed 0. Equation 0=0+0. Never padded.

## Git facts (not selected)

GHSA-227X-7MH8-3CF6 gardener-extension-provider-aws closer `cb5045fc` is human (Konstantinos Angelopoulos), `source_matcher` empty, `n_parents=1`. Tag `v1.64.0` contains the closer. Subject is shoot input validation. No atomic AI same-invariant predecessor in the 250 first-parent window on fix-touched validation sources.

GHSA-22CC-P3C6-WPVM h3 closer `7791538e` is contained in tag `v1.15.8`.

GHSA-23C5-XMQV-RM74 minimatch closer `11d0df61` is contained in tag `v10.2.3`.

## Claim boundary

Canonical strict released first-party GHSA floor remains 88 HOLD. This packet emits no admission. No commit, push, or edits outside this directory. Local caches read-only. Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
