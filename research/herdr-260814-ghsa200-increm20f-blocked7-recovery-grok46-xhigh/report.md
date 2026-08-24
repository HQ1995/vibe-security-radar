# Incomplete-remediation20f blocked-seven recovery (grok46-xhigh)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Canonical81 summary SHA-256 `dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c`. Shared tracked files, canonical81, and prior packets were not edited. No commit, push, or credential output.

## Assignment

Exactly seven identities, taken from `autoresearch/herdr-260814-ghsa200-incomplete-remediation20f-grok46-low/cases.jsonl` where the source packet encoded `BLOCKED` / `NO_LOCAL_CLONE`:

1. GHSA-9P8X-F768-WP2G node-saml/xml-crypto
2. GHSA-X3M8-899R-F7C3 node-saml/xml-crypto
3. GHSA-V432-7F47-9G94 DavidOsipov/PostQuantum-Feldman-VSS
4. GHSA-Q9F5-625G-XM39 corazawaf/coraza
5. GHSA-2J42-H78H-Q4FG beego/beego
6. GHSA-26WH-CC3R-W6PJ canonical/get-workflow-version-action
7. GHSA-CG3C-245W-728M api-platform/core

Conservation: assigned = 7, reviewed = 7, unreviewed = 0. Prior gates were not trusted except those exact IDs and first-party advisory repository routing. Official repositories were resolved from the frozen github-reviewed GHSA objects and cloned read-only under `/home/hanqing/.cache/ghsa200-worker-clones/recovery20f-260814/`. Every clone was obtained. Missing evidence is not converted to FAIL; here the clones exist, so absence of an AI-marked security-attempt hunk is FAIL/REJECT.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Human prior patches, old sibling holes, later AI review, carrier transfer, unreleased attempts, and OSV routing fail. PASS requires all seven gates PASS plus `remediation_patch_delta` PASS. Untouched old sibling holes fail. Same-repo identities remain distinct unless first-party alias and mechanism equality prove duplication.

## Verdict

All seven identities are now git-replayable. None close the incomplete-remediation pattern. Causal gates are FAIL, not BLOCKED.

| Identity | Repository | Worker verdict | Reject class |
|---|---|---|---|
| GHSA-9P8X-F768-WP2G | node-saml/xml-crypto | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-X3M8-899R-F7C3 | node-saml/xml-crypto | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-V432-7F47-9G94 | DavidOsipov/PostQuantum-Feldman-VSS | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-Q9F5-625G-XM39 | corazawaf/coraza | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-2J42-H78H-Q4FG | beego/beego | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-26WH-CC3R-W6PJ | canonical/get-workflow-version-action | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-CG3C-245W-728M | api-platform/core | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |

### GHSA-9P8X-F768-WP2G

First-party reviewed GHSA for npm `xml-crypto`, not withdrawn. The advisory names signature bypass via multiple SignedInfo references. Cited closer `28f92218ecbb8dcbd238afa4efbbd50302aa9aed` is single-parent Matt Dzwonczyk `Merge commit from fork`; parent equals tag `v3.2.0`. Tag `v3.2.1` is a descendant (`v3.2.1~1`). `lib/signed-xml.js` blob `190ddc75` at the closer equals `v3.2.1` and differs from `v3.2.0` blob `ac3dd51f`. v2 backport `886dc63a` is unmarked Matt Dzwonczyk / Blair Weber; v6 closer `8ac6118e` is unmarked ahacker1 (`alex@securesaml.com`). The 486-commit clone has no AI trailer. Origin human SignedInfo rem, not AI patch-delta.

### GHSA-X3M8-899R-F7C3

First-party reviewed GHSA for npm `xml-crypto` DigestValue comments (CVE-2025-29775). Not an alias of GHSA-9p8x. The same three unmarked human rem SHAs add `valid_saml_with_digest_comment.xml` and DigestValue `textContent` handling. Tag `v6.0.0` equals parent of `8ac6118e`; tag `v6.0.1` `src/signed-xml.ts` blob `4f6d11ec` equals `8ac6118e`. Shared SHAs do not merge identities. Origin human DigestValue rem, not AI patch-delta.

### GHSA-V432-7F47-9G94

First-party reviewed GHSA for PyPI `PostQuantum-Feldman-VSS`. No commit URL; last_affected `<= 0.7.6b0`; first_patched `0.7.7b0`. Tag `v0.7.6-beta` (`40ffb4b3`) has no `MemoryMonitor`. Tag `v0.8.0b2` (`36d6fb74`) does. Intro `9d814d0b` is unmarked DavidOsipov `Signed-off-by`. The 404-commit clone has no AI trailer. Keyword `still be` is remaining theoretical GMP abort after advertised mitigations of the original dependency crash.

### GHSA-Q9F5-625G-XM39

First-party reviewed GHSA for Go `github.com/corazawaf/coraza/v3`. Cited closer `4722c9ad` is unmarked blotus `Merge commit from fork` and equals tag `v3.3.3`. Parent `8b612f4e` name-rev is `v3.3.3~1`. `transaction.go` blob `8264c7e6` at `v3.3.2` equals the parent; blob `67ecfab0` at `v3.3.3` equals the closer. 59 Copilot-class trailers start 2026-03-06, after the rem. Origin human `ParseRequestURI` rem.

### GHSA-2J42-H78H-Q4FG

First-party reviewed GHSA for Go `github.com/beego/beego/v2`. Cited closer `939bb18c` is unmarked Ville Vesilehto HTML escaping in `renderFormField`. Tag `v2.3.5` `templatefunc.go` blob `f7cce06a` equals the parent; tag `v2.3.6` blob `ba2cc543` equals the closer; name-rev `v2.3.6~1`. The 4925-commit clone has no AI trailer. Older `adminui.go` XSS rem is an unmarked sibling path.

### GHSA-26WH-CC3R-W6PJ

First-party reviewed GHSA for GitHub Action `canonical/get-workflow-version-action`. Cited closer `88281a62` is unmarked Carl Csaposs and equals tag `v1.0.1`. Parent equals tag `v1.0.0`. `main.py` blob `8d22fd96` at `v1.0.0` equals the parent; blob `07f0eb11` at `v1.0.1` equals the closer. The 11-commit clone has no AI trailer.

### GHSA-CG3C-245W-728M

First-party reviewed GHSA for Packagist `api-platform/core`. Cited rem `55712452` is unmarked Antoine Bluchet / soyuka; name-rev `v3.4.17~3`. Cited rem `60747cc8` is the same author; name-rev `v4.0.22~3` and ancestor of `v4.1.5`. `ResolverFactory.php` blob `1aca8b41` at both closers equals `v3.4.17` / `v4.0.22` / `v4.1.5`; parent blob `c7ba0328` equals `v3.4.16` / `v4.0.21` / `v4.1.4`. 28 Copilot-class trailers start 2026-01-16, after the rem.

## Uniqueness

None of the seven IDs is in canonical81 `strict_released_case_ids` (81). Canonical81 ledger has no hit. Prior packet hits are the uncounted source BLOCKED rows. GHSA-9P8X remains distinct from GHSA-X3M8 despite shared rem SHAs: different first-party GHSA objects, different CVEs, different mechanisms (multiple SignedInfo vs DigestValue comments).

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| REJECT | 7 |

## Claim boundary

Countable PASS requires all seven gates, patch-delta PASS, and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim. Canonical81 was not rebuilt.
