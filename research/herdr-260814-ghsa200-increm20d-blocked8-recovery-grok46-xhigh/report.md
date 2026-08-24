# Incomplete-remediation20d blocked-eight recovery (grok46-xhigh)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Canonical81 summary SHA-256 `dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c`. Shared tracked files, canonical81, and prior packets were not edited. No commit, push, or credential output.

## Assignment

Exactly eight identities, taken from `autoresearch/herdr-260814-ghsa200-incomplete-remediation20d-grok46-low/cases.jsonl` where the source packet encoded `BLOCKED` / `NO_LOCAL_CLONE`:

1. GHSA-94VH-GPHV-8PM8 zip-rs/zip2
2. GHSA-6JRF-4JV4-R9MW informalsystems/tendermint-rs
3. GHSA-22FP-MF44-F2MQ dirkf/youtube-dl
4. GHSA-8C3X-HQ82-GJCM HL7/fhir-ig-publisher
5. GHSA-VQF5-2XX6-9WFM github/codeql-action
6. GHSA-G6WM-2V64-WQ36 Robothy/local-s3
7. GHSA-785H-76CM-CPMF OmenApps/django-tomselect
8. GHSA-QP8J-P87F-C8CC lnbits/lnbits

Conservation: assigned = 8, reviewed = 8, unreviewed = 0. Prior gates were not trusted except those exact IDs and first-party advisory repository routing. Official repositories were resolved from the frozen github-reviewed GHSA objects and cloned read-only under `/home/hanqing/.cache/ghsa200-worker-clones/recovery20d-260814/`. Every clone was obtained. Missing evidence is not converted to FAIL; here the clones exist, so absence of an AI-marked security-attempt hunk is FAIL/REJECT.

## Pattern

`AI_INCOMPLETE_REMEDIATION` patch-delta: an atomic AI-marked commit introduces or rewrites an explicit guard; a released artifact contains that attempt without closure; the GHSA names the residual; the later fix amends the same AI boundary. Human prior patches, old sibling holes, later AI review, carrier transfer, unreleased attempts, and OSV routing fail. PASS requires all seven gates PASS plus `remediation_patch_delta` PASS. Untouched old sibling holes fail.

## Verdict

All eight identities are now git-replayable. None close the incomplete-remediation pattern. Causal gates are FAIL, not BLOCKED.

| Identity | Repository | Worker verdict | Reject class |
|---|---|---|---|
| GHSA-94VH-GPHV-8PM8 | zip-rs/zip2 | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-6JRF-4JV4-R9MW | informalsystems/tendermint-rs | REJECT | NO_AI_GUARD_REWRITE |
| GHSA-22FP-MF44-F2MQ | dirkf/youtube-dl | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-8C3X-HQ82-GJCM | HL7/fhir-ig-publisher | REJECT | HUMAN_INCOMPLETE_PRIOR_NOT_AI |
| GHSA-VQF5-2XX6-9WFM | github/codeql-action | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-G6WM-2V64-WQ36 | Robothy/local-s3 | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-785H-76CM-CPMF | OmenApps/django-tomselect | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |
| GHSA-QP8J-P87F-C8CC | lnbits/lnbits | REJECT | ORIGIN_NOT_INCOMPLETE_REMEDIATION |

### GHSA-94VH-GPHV-8PM8

First-party reviewed GHSA for crates.io `zip`, not withdrawn. The advisory names extract following earlier symlinks without canonicalization. Cited closer `a2e062f37066c3b12860a32eb1cb44856cfb7afe` is two-parent Chris Hennick merge-from-fork; incoming `0199ac2cb8e9a5d7e645e53d51838655d8e15148` is eternal-flame-AD `Signed-off-by: eternal-flame-AD <yume@yumechi.jp>`. Tag `v2.2.3` is not a descendant; tag `v2.3.0` is (`v2.3.0~5`). `src/path.rs` is absent at `v2.2.3`. 3175 commits have 127 later gemini-code-assist trailers, all after 2025-09-02, none before the rem. Origin human extract rem, not AI patch-delta.

### GHSA-6JRF-4JV4-R9MW

First-party reviewed GHSA for crates.io `tendermint-light-client-verifier`. Cited closer `1aabcfe6a3c0678db22097543f7f7a662f0db34b` is single-parent Anton Kaliaev merge-from-fork; parent equals tag `v0.40.2`. `voting_power.rs` blob `703b8830` at the closer equals tag `v0.40.3`. The 2413-commit clone has no AI trailer.

### GHSA-22FP-MF44-F2MQ

First-party reviewed GHSA for dirkf/youtube-dl / PyPI `youtube-dl`. Cited ytdl-org `d42a222ed541b96649396ef00e19552aef0f09ec` and dirkf cherry-pick `46521096433aceaa41b4caa845bed22ca6f377ce` share patch-id `355665f1`; both are unmarked dirkf. `46521096` is an ancestor of dirkf HEAD; no git tag contains it. GHSA `first_patched_version` is null; last_affected is 2021.12.17. The 20721-commit clone has no AI trailer. Distinct from yt-dlp GHSA-79w7.

### GHSA-8C3X-HQ82-GJCM

First-party reviewed GHSA for Maven `org.hl7.fhir.publisher`. The advisory names a residual after GHSA-59rq (patched 1.6.22). Prior rem `e5db459f3995bbf9dfd558f9f40020fb4df79d33` is human dotasek `Fix XXE issue`. Cited closer `3560de2f486d688a3ddcf4aa54d8bdacea380c3d` is human dotasek checkstyle for XML factory instantiations, ancestor of `1.7.4` not `1.7.3`. 23 Copilot trailers are 2026 Gino Canessa packaging work. Human incomplete prior, not AI patch-delta. Distinct from GHSA-59rq.

### GHSA-VQF5-2XX6-9WFM

First-party reviewed GHSA for GitHub Action `github/codeql-action`. Cited closer `519de26711ecad48bde264c51e414658a82ef3fa` is Angela P Wen `Temporarily disable uploading debug artifacts`. `src/debug-artifacts.ts` blob `5594b818` at `v3.28.2` equals the closer parent; blob `a15277a7` at `v3.28.3` equals the closer. Two pre-rem Copilot hits touch `autobuild.ts` and `status-report.ts`, not this boundary. Origin human disable of the upload, not AI incomplete rem.

### GHSA-G6WM-2V64-WQ36

First-party reviewed GHSA for Maven `io.github.robothy:local-s3-rest` CreateBucketConfiguration XXE. Cited closer `d6ed756ceb30c1eb9d4263321ac683d734f8836f` is Luo, the same SHA as GHSA-47qw. Tag `1.20` XmlUtils blob `67aab78b` equals the parent; tag `1.21` blob `e937b98b` equals the closer. XmlUtils was introduced by human Fuxiang Luo `36e2504a`. Distinct identity from GHSA-47qw; same human origin rem. The 256-commit clone has no AI trailer.

### GHSA-785H-76CM-CPMF

First-party reviewed GHSA for PyPI `django-tomselect`. Keyword incomplete is the original widget-attribute hole. Cited closer `0990ed36c8874f9d42fa9deff7734bf8dcd46d40` is jacklinke; carrier `b6817c43` is Jack Linke merge-from-fork into `2025.3.3`. `utils.py` is absent at `2025.3.2` and equals the closer at `2025.3.3` (blob `942c7495`). The 458-commit clone has no AI trailer.

### GHSA-QP8J-P87F-C8CC

First-party reviewed GHSA for PyPI `lnbits`. No commit URL; `first_patched_version` is null; last_affected git tag `v0.12.12` = `51c9d294`. Closest later callback validation is unmarked Vlad Stan `bfa23568e3c84e863df14be25eb6f3f1b7cb2fc2`, ancestor of `v1.0.0`, not of `v0.12.12`. Seven Claude trailers start 2025-09 on unrelated files. Origin SSRF hole, not AI patch-delta.

## Uniqueness

None of the eight IDs is in canonical81 `strict_released_case_ids` (81). Canonical81 ledger has no hit. Prior packet hits are the uncounted source BLOCKED rows. GHSA-G6WM remains distinct from GHSA-47QW despite a shared closer SHA. GHSA-8C3X remains distinct from GHSA-59RQ. GHSA-22FP remains distinct from yt-dlp GHSA-79W7.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| REJECT | 8 |

## Claim boundary

Countable PASS requires all seven gates, patch-delta PASS, and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a greater-than-200 claim. Canonical81 was not rebuilt.
