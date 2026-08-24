# Incomplete-remediation20i blocked-eleven recovery (grok46-xhigh)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Canonical81 summary SHA-256 `dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c`. Source 20i selected-20 SHA-256 `e7e23c15eb7d29d77bb1f0d6e0289ddd3a4e293d5fe7dccf5b7b19bf47441002`. Shared tracked files, canonical81, and prior packets were not edited. No commit, push, or credential output.

## Assignment

Exactly eleven identities, taken from `autoresearch/herdr-260814-ghsa200-incomplete-remediation20i-grok46-low/cases.jsonl` where the source packet encoded `BLOCKED` (`NO_LOCAL_CLONE` or `MISSING_CITED_FIX`):

1. GHSA-Q53R-9HH9-W277
2. GHSA-PP9M-QF39-HXJC
3. GHSA-8366-XMGF-334F
4. GHSA-6WXF-7784-62FP
5. GHSA-9M63-33Q3-XQ5X
6. GHSA-33CR-M232-XQCH
7. GHSA-4WF3-5QJ9-368V
8. GHSA-H2RP-8VPX-Q9R4
9. GHSA-VHV4-FH94-JM5X
10. GHSA-MGRM-FGJV-MHV8
11. GHSA-CCJ3-5P93-8P42

Conservation: assigned = 11, reviewed = 11, unreviewed = 0. Prior gates were not trusted except those exact IDs and first-party advisory repository routing. Official repositories were resolved from the frozen github-reviewed GHSA objects and cloned read-only under `/home/hanqing/.cache/ghsa200-worker-clones/recovery20i-260814/`. All required repositories were obtained. GHSA-q53r rem was replayed in `pimcore/customer-data-framework` (the affected bundle), not only in `pimcore/pimcore`. `redaxo/redaxo` now redirects to `redaxo/core`; both clones share HEAD `d3850fef`.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Human prior patches, old sibling holes, later AI review, carrier transfer, unreleased attempts, and OSV routing fail. PASS requires all seven gates PASS plus `remediation_patch_delta` PASS. Missing evidence stays BLOCKED and is not converted to FAIL. Same-repo identities remain distinct unless first-party alias and mechanism equality prove duplication.

## Verdict

All eleven identities are now git-replayable. None close the incomplete-remediation pattern. Causal gates are FAIL, not BLOCKED: absence of an AI-marked security-attempt hunk is proved on the relevant history.

| Identity | Repository | Worker verdict | Reject class |
|---|---|---|---|
| GHSA-Q53R-9HH9-W277 | pimcore/pimcore | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-PP9M-QF39-HXJC | oxyno-zeta/s3-proxy | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-8366-XMGF-334F | redaxo/redaxo | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-6WXF-7784-62FP | strangelove-ventures/horcrux | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-9M63-33Q3-XQ5X | go-vela/server | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-33CR-M232-XQCH | cheqd/cheqd-node | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-4WF3-5QJ9-368V | cosmos/ibc-go | REJECT | HUMAN_INCOMPLETE_PRIOR_NOT_AI |
| GHSA-H2RP-8VPX-Q9R4 | cheqd/cheqd-node | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-VHV4-FH94-JM5X | jitbit/HtmlSanitizer | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-MGRM-FGJV-MHV8 | vllm-project/vllm | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-CCJ3-5P93-8P42 | surrealdb/surrealdb | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |

### GHSA-Q53R-9HH9-W277

First-party reviewed GHSA for Packagist `pimcore/customer-management-framework-bundle`, alias CVE-2024-11956, hosted on pimcore/pimcore. Rem is in pimcore/customer-data-framework. Closer `a49b322b` is Matthias Schuhmayer, PR 549, parameterizing CustomerSegment joins. Tag `v4.2.0` CustomerSegment.php blob `3bf9fcad` equals the closer parent. Tag `v4.2.1` contains the rem. Precise AI-trailer scan of `v4.2.1` is empty. Later Claude commits in pimcore/pimcore are a different repository. Origin rem of the original filter SQLi.

### GHSA-PP9M-QF39-HXJC

First-party reviewed GHSA for Go `github.com/oxyno-zeta/s3-proxy`, alias CVE-2025-27088. Cited rem `c611c741` is Havrileck Alexandre, sanitizing HTTP request fields into `LightSanitizedRequest`. Tag `v4.18.1` peels to that SHA. `templates/folder-list.tpl` is unchanged. Tag `v4.18.0` template.go blob `9a294d66` equals the closer parent. Full clone has no AI trailer. Origin rem of the original template XSS.

### GHSA-8366-XMGF-334F

First-party reviewed GHSA for Packagist `redaxo/source`, alias CVE-2025-27412. Closer `44df786f` is Gregor Harlan, PR 6260, storing API reboot results in session instead of reflecting `rex-api-result` through the URL. Tag `5.18.2` api_function.php blob `98266a3e` equals the closer parent. Tag `5.18.3` blob `01592d5f` equals the closer. Precise trailer scan of `5.18.3` is empty. Later Claude/Copilot commits are not ancestors of `5.18.3`. Origin rem of the original reflected XSS.

### GHSA-6WXF-7784-62FP

First-party reviewed GHSA for Go `github.com/strangelove-ventures/horcrux/v3` (no CVE). Introducer `34c4db1d` Andrew Gouin PR 169 is an ancestor of `v3.1.0`. Cited rem `fb49be9b` is Andrew Gouin, PR 297, a single mutex over HRS read and write. Tag `v3.3.1` peels to the closer parent. Tag `v3.3.2` peels to the rem. Full clone has no AI trailer. Origin rem of the original race.

### GHSA-9M63-33Q3-XQ5X

First-party reviewed GHSA for Go `github.com/go-vela/server`, alias CVE-2025-27616. Advisory-cited `257886e5` is dave vader CORS-origin list #1262, a sibling in `v0.26.3`, not webhook verification. Webhook rem is `20c5a6cb` Easton Crupper `Merge commit from fork`, verifying repository and installation events. Tag `v0.26.2` webhook blob `e5f64488` equals the closer parent. Tag `v0.26.3` blob `2fec135e` equals the closer. Tag `v0.25.3` peels to `67c1892e`, the v25 backport. Precise trailer scan of both fixed tags is empty. A later Copilot Autofix trailer is not an ancestor. Origin rem of the original webhook hole.

### GHSA-33CR-M232-XQCH

First-party reviewed GHSA for Go `github.com/cheqd/cheqd-node` (no CVE). The GHSA names upstream IBC-Go GHSA-jg6f. Cited SHA `59987d52` is not in cheqd-node. Cheqd rem `7a6075b9` is Tasos Derisiotis bumping ibc-go in go.mod. Tag `v3.1.6` is the closer parent. Tag `v3.1.7` contains the bump. Full clone has no AI trailer. Distinct from GHSA-h2rp. Upstream dependency bump, not an AI cheqd guard.

### GHSA-4WF3-5QJ9-368V

First-party reviewed GHSA for Go `github.com/cosmos/ibc-go` (no CVE). The GHSA text states this patch extends a previous transfer-only rem to all applications. Prior rem GHSA-jg6f is human Gjermund Garaba `59987d52` / `9869b3c6` removing transfer packet remarshaling. GHSA-4wf3 closers `17b2240c` (v8, parent `59987d52`) and `a5b5b929` (v7) are Gjermund Garaba `Merge commit from fork`, rewriting `modules/core/04-channel/keeper/packet.go`, Co-authored-by Aditya Sripal. Tag `v8.6.0` packet.go blob `698dc952` equals the v8 closer parent blob because `59987d52` does not touch packet.go; `v8.6.0` lacks both rem commits. Tag `v8.6.1` peels to `59987d52` and lacks `17b2240c`. Tag `v8.7.0` blob `84b50411` equals `17b2240c`. Tag `v7.9.1` peels to `9869b3c6`; `v7.10.0` contains `a5b5b929`. Precise trailer scan of both fixed tags is empty. Human incomplete prior, not AI patch-delta.

### GHSA-H2RP-8VPX-Q9R4

First-party reviewed GHSA for Go `github.com/cheqd/cheqd-node` (no CVE). Cited rem `5a58b08d` is Tasos Derisiotis bumping cosmos-sdk to v0.47.17 and ibc-go to v7.10.0. Tag `v3.1.7` lacks that SHA. Tag `v3.1.8` contains it. Distinct from GHSA-33cr (different upstream advisories, different tags). Upstream dependency bump, not an AI cheqd guard.

### GHSA-VHV4-FH94-JM5X

First-party reviewed GHSA for npm `@jitbit/htmlsanitizer`, alias CVE-2025-29771. Cited rem `af6d2a78` is Alexander Yumashev deleting the post-sanitation `<br>` beautify replace. Tag `2.0.2` HtmlSanitizer.js blob `6ca8ea83` equals the closer parent. Tag `2.0.3` contains the rem. Full clone has no AI trailer. Origin rem of the original beautifier XSS.

### GHSA-MGRM-FGJV-MHV8

First-party reviewed GHSA for PyPI vllm, alias CVE-2025-29770. PR 14837 merge `776dcec8` is Russell Bryant disabling the outlines disk cache by default. Tag `v0.7.3` lacks that SHA. Tag `v0.8.0` outlines blob `8b2a0f4c` equals the closer. Precise trailer scan of `v0.8.0` is empty. Origin rem of the original unbounded cache.

### GHSA-CCJ3-5P93-8P42

First-party reviewed GHSA for crates.io surrealdb (no CVE). Closer `3be0366b` is Mees Delzenne `Fix import injection security bug`, escaping export idents in `core/src/kvs/export.rs`. Tag `v2.0.4` export.rs blob `3a5b1bd1` equals the closer parent. Tag `v2.0.5` blob `317239b2` equals `3be0366b`. Lineage copies `d1d41efc` (v2.1.5) and `b86f6ac5` (v2.2.2) carry the same human subject. Precise trailer scan of `v2.0.5` and `v2.2.2` is empty. Origin rem of the original export-escape hole.

## Uniqueness

None of the eleven IDs is in canonical81 `strict_released_case_ids` (81). Canonical81 ledger has no hit. The only prior packet hit is the uncounted source 20i BLOCKED rows. Same-repo pair GHSA-33CR vs GHSA-H2RP remains distinct: v3.1.7 ibc-go GHSA-jg6f bump versus v3.1.8 cosmos-sdk GHSA-47ww plus ibc-go GHSA-4wf3 bump. GHSA-4WF3 is the ibc-go first-party identity and is not merged with the cheqd downstream advisories. Shared author or shared release line does not merge identities. No first-party alias plus mechanism equality proves duplication.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| REJECT | 11 |

## Claim boundary

Countable PASS requires all seven gates, patch-delta PASS, and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim. Canonical81 was not rebuilt.
