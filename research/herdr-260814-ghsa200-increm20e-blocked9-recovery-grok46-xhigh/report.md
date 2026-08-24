# Incomplete-remediation20e blocked-nine recovery (grok46-xhigh)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Canonical81 summary SHA-256 `dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c`. Source 20e selected-20 SHA-256 `a07fdd1d44c92a2c4b2bffcb66927500319fd99a11dbebedefa342b649b1afc3`. Shared tracked files, canonical81, and prior packets were not edited. No commit, push, or credential output.

## Assignment

Exactly nine identities, taken from `autoresearch/herdr-260814-ghsa200-incomplete-remediation20e-grok46-low/cases.jsonl` where the source packet encoded `BLOCKED` / `NO_LOCAL_CLONE`:

1. GHSA-P9V8-Q5M4-PF46
2. GHSA-V4MQ-X674-FF73
3. GHSA-GMJ9-H825-CHQ2
4. GHSA-VP47-9734-PRJW
5. GHSA-3WWR-3G9F-9GC7
6. GHSA-2237-5R9W-VM8J
7. GHSA-MRQP-Q7VX-V2CX
8. GHSA-4RCC-7PG7-F57F
9. GHSA-H958-FXGG-G7W3

Conservation: assigned = 9, reviewed = 9, unreviewed = 0. Prior gates were not trusted except those exact IDs and first-party advisory repository routing. Official repositories were resolved from the frozen github-reviewed GHSA objects and cloned read-only under `/home/hanqing/.cache/ghsa200-worker-clones/recovery20e-260814/`. All seven repositories were obtained.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Human prior patches, old sibling holes, later AI review, carrier transfer, unreleased attempts, and OSV routing fail. PASS requires all seven gates PASS plus `remediation_patch_delta` PASS. Missing evidence stays BLOCKED and is not converted to FAIL. Same-repo identities remain distinct unless first-party alias and mechanism equality prove duplication.

## Verdict

All nine identities are now git-replayable. None close the incomplete-remediation pattern. Causal gates are FAIL, not BLOCKED: absence of an AI-marked security-attempt hunk is proved on the relevant history.

| Identity | Repository | Worker verdict | Reject class |
|---|---|---|---|
| GHSA-P9V8-Q5M4-PF46 | canonical/snapd | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-V4MQ-X674-FF73 | aws/aws-cdk | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-GMJ9-H825-CHQ2 | zopefoundation/RestrictedPython | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-VP47-9734-PRJW | lmfit/asteval | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-3WWR-3G9F-9GC7 | lmfit/asteval | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-2237-5R9W-VM8J | opensource-workshop/connect-cms | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-MRQP-Q7VX-V2CX | instaclustr/cassandra-lucene-index | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-4RCC-7PG7-F57F | OPCFoundation/UA-.NETStandard | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-H958-FXGG-G7W3 | OPCFoundation/UA-.NETStandard | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |

### GHSA-P9V8-Q5M4-PF46

First-party reviewed GHSA for Go `github.com/snapcore/snapd`, alias CVE-2024-5138. Cited rem `68ee9c6aa916` is single-parent Zygmunt Krynicki, rewriting `isAllowedToRun` so `--` terminates option parsing. Tag `2.63.1` ctlcmd.go blob `b663420a` equals the closer parent and does not contain the rem. Tag `2.64` blob `a4a717fd` equals the closer. Precise AI-trailer scan of `2.64` is empty. Origin rem of the original help-flag confusion.

### GHSA-V4MQ-X674-FF73

First-party reviewed GHSA for npm `aws-cdk-lib`, alias CVE-2025-23206. Cited rem `3e4f3773bfa4` is GZ / yuanhaoz, PR 32921, threading `rejectUnauthorized` behind a feature flag. Tag `v2.176.0` still hardcodes `false`. Tag `v2.177.0` equals the closer. OIDC handler origin is Elad Ben-Israel `20621acf`. Precise trailer scan of `v2.177.0` is empty. A later Claude Opus 4.6 trailer on a jsii upgrade is not an ancestor of `v2.177.0`. Origin rem of the original TLS option.

### GHSA-GMJ9-H825-CHQ2

First-party reviewed GHSA for PyPI RestrictedPython, alias CVE-2025-22153. Tag `6.0` introduced `except*` as a Python 3.11 feature (`visit_TryStar` allowed ExceptionGroup). Tag `7.4` still allows it. Cited rem `48a92c5bb617` is Michael Howitz changing `visit_TryStar` to `not_allowed`. Tag `8.0` transformer blob equals the closer. Full clone has no AI trailer. Feature removal / origin rem of the CPython type-confusion hole.

### GHSA-VP47-9734-PRJW

First-party reviewed GHSA for PyPI asteval (no CVE). Merge `45bb47533f7a` Matt Newville of member `babca619c10d` William Khem Marquez introducing `safe_getattr`. Tag `1.0.5` lacks the merge; `1.0.6` contains it. Distinct from GHSA-3WWR. Shared closer SHA does not merge identities. Origin rem of the Procedure.body / UNSAFE_ATTRS TOCTOU hole.

### GHSA-3WWR-3G9F-9GC7

First-party reviewed GHSA for PyPI asteval, alias CVE-2025-24359. Same merge/member as GHSA-vp47, but the named mechanism is `on_formattedvalue` / `safe_format`. Both original holes closed in one human member commit, so neither is a later residual of the other. Origin rem of the format-string hole.

### GHSA-2237-5R9W-VM8J

First-party reviewed GHSA for Packagist `opensource-workshop/connect-cms`. v1.8.0 introducer `105bf1c63a67` gakigaki added site-search body text as a feature. Closer `cb64bfae4ee5` gakigaki `Fix: GHSA-2237-5r9w-vm8j` adds page/frame visibility filters. Tag `v1.8.3` SearchsPlugin blob equals the closer parent; `v1.8.4` contains the rem. Precise trailer scan of `v1.8.4` is empty. Later CLAUDE.md commits are not ancestors of `v1.8.4`. Origin rem of the original search leak.

### GHSA-MRQP-Q7VX-V2CX

First-party reviewed GHSA for Maven `com.instaclustr:cassandra-lucene-index-plugin`, alias CVE-2025-26511. Closers `44ab4b639c93` and `94380b165bd3` are Jackson Fleming adding `statement.authorize` / `validate` in IndexQueryHandler.scala. Tag `cassandra-4.0.17-1.0.0` peels to `44ab4b639c93`. Tag `cassandra-4.1.8-1.0.0` still lacks authorize; `cassandra-4.1.8-1.0.1` contains `94380b16`. Full clone has no AI trailer. Origin rem of the missing RBAC check.

### GHSA-4RCC-7PG7-F57F

First-party reviewed GHSA for NuGet `OPCFoundation.NetStandard.Opc.Ua.Bindings.Https`, alias CVE-2024-42513. HTTPS rem is `d0e89a3bf140` Suciu Mircea Adrian, PR 2849 mutual TLS on HTTPS endpoints. Tag `1.5.374.158` HttpsTransportListener blob equals that closer; `1.5.374.118` does not contain it. Distinct from GHSA-h958 (different package, TCP files, different SHA). Origin rem of missing HTTPS application authentication. Untouched sibling TCP hole is not this identity.

### GHSA-H958-FXGG-G7W3

First-party reviewed GHSA for NuGet `OPCFoundation.NetStandard.Opc.Ua.Core`, alias CVE-2024-42512. Cited rem `3543d0292556` is Suciu Mircea Adrian, PR 2850 rogue-client detection on Basic128, TCP transport only. Tag `1.5.374.158` TcpTransportListener blob equals the closer. Later Copilot-coauthored commits are not ancestors of `1.5.374.158`. Distinct from GHSA-4rcc. Origin rem of the original Basic128Rsa15 hole.

## Uniqueness

None of the nine IDs is in canonical81 `strict_released_case_ids` (81). Canonical81 ledger has no hit. The only prior packet hit is the uncounted source 20e BLOCKED rows. Same-repo pairs remain distinct: GHSA-VP47 vs GHSA-3WWR (Procedure.body vs FormattedValue); GHSA-4RCC vs GHSA-H958 (HTTPS mTLS vs TCP Basic128 rogue-client). Shared closer SHA or shared release tag does not merge identities. No first-party alias plus mechanism equality proves duplication.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| REJECT | 9 |

## Claim boundary

Countable PASS requires all seven gates, patch-delta PASS, and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim. Canonical81 was not rebuilt.
