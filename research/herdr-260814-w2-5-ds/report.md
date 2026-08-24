# unr-adj2-slice-5 adjudication — verdict-first evidence summary

## Verdict

Proposed admissions: **0 / 25** (`CONFIRM`/`AI_DIRECT_ROOT`/`AI_NEW_SURFACE_CONTRIBUTOR` = 0).
Every row is **FALSE_POSITIVE (class `no_ai_origin`)**: the candidate AI commit's diff authors an unrelated hunk and does not create the advisory's named mechanism.

- 25/25 unreviewed advisory objects are `github_reviewed=false` with `affected=[]`; the `details` field names the mechanism and the references name the repository, but there is no first-party reviewed identity, so `identity_gate` = UNKNOWN (never PASS).
- 16 unique candidate commits were fetched by git smart-HTTP into `/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>` and their parent→child diffs read. All 16 carry an explicit AI marker (Claude/Copilot/Copilot Autofix co-author trailer).
- 16/16 diffs touch files disjoint from the vulnerable file named in the advisory, so `ai_hunk_gate` and `but_for_gate` are FAIL (affirmative non-authorship, not missing evidence).
- `topology_gate`, `fix_reversal_gate`, `release_gate`, `uniqueness_gate` stay UNKNOWN after causal exclusion; a rejected row is not opened for uniqueness/release containment.

## Frozen evidence and method

- Contract: `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md`, SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
- Spec: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/FWD-SPEC.md`, SHA-256 `672c45d1f98054a597ce12aa0879daa00b884d9207884e9a10e23c0fdc2d5750`.
- Slice: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj2-slice-5.jsonl`, SHA-256 `ccb59a9c4f18f2103b99d88eb7ff1752e81064e322c01c64887f68ff3c74cfeb` (25 rows).
- Advisory database: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database` at `origin/main` = `8b901fa43d0e3d09e9bece095afb760dd9dff6e8` (2026-08-15 `Publish Advisories`). Every advisory blob is read from that exact tree.
- Commit pool: `git --filter=blob:none` blobless bare clones; missing repos (wolfssl, fastnetmon, dask) were initialized and fetched with `--deepen=80` via git smart-HTTP. No GitHub API, no `git blame`, no SZZ.

## Row-by-row finding (grouped by repository)

| GHSA | CVE | Repository | Named mechanism (file) | Candidate diff (files) | Verdict |
|---|---|---|---|---|---|
| GHSA-Q7X2-2W32-GXV3 | CVE-2026-9579 | jeecgboot/JeecgBoot | SysUser userEdit IDOR | OpenApiController.java | FALSE_POSITIVE (no_ai_origin) |
| GHSA-V77Q-XXPR-RX9G | CVE-2026-9580 | jeecgboot/JeecgBoot | selectDepart IDOR | OpenApiController.java | FALSE_POSITIVE (no_ai_origin) |
| GHSA-32F8-XFVP-9M45 | CVE-2026-9604 | jeecgboot/JeecgBoot | AiragModelController IDOR | OpenApiController.java | FALSE_POSITIVE (no_ai_origin) |
| GHSA-3M2M-6PHQ-RXRQ | CVE-2026-10241 | jeecgboot/JeecgBoot | download2DiskFromNet SSRF | OpenApiController.java | FALSE_POSITIVE (no_ai_origin) |
| GHSA-GG5C-V856-2RJP | CVE-2026-10239 | jeecgboot/JeecgBoot | WordUtil.addImage SSRF | OpenApiController.java | FALSE_POSITIVE (no_ai_origin) |
| GHSA-Q4C7-VXGR-R6M2 | CVE-2026-10240 | jeecgboot/JeecgBoot | airagModel/test baseUrl SSRF | OpenApiController.java | FALSE_POSITIVE (no_ai_origin) |
| GHSA-G4G6-G3HX-2F5W | CVE-2026-11464 | jeecgboot/JeecgBoot | SysUserController salt disclosure | OpenApiController.java | FALSE_POSITIVE (no_ai_origin) |
| GHSA-2R69-34R8-6C68 | CVE-2026-11502 | jeecgboot/JeecgBoot | ThirdLogin open redirect | OpenApiController.java | FALSE_POSITIVE (no_ai_origin) |
| GHSA-CJ56-5C53-9QJF | CVE-2026-55961 | wolfSSL/wolfssl | PKCS7_verify no-signer | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-H6GC-RMV2-74G6 | CVE-2026-6094 | wolfSSL/wolfssl | PKCS7 EnvelopedData overread | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-HVWM-W7RW-23CV | CVE-2026-6291 | wolfSSL/wolfssl | PKCS7 KTRI padding oracle | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-MHQ8-94H7-MRGX | CVE-2026-6091 | wolfSSL/wolfssl | partial-chain cert anchor | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-Q4Q5-JX42-4XP9 | CVE-2026-55967 | wolfSSL/wolfssl | AES-GCM counter wrap | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-WRW6-8JH4-QVCX | CVE-2026-11999 | wolfSSL/wolfssl | X.509 path-depth bypass | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-GJM7-VCH5-HCH8 | CVE-2026-10512 | wolfSSL/wolfssl | X25519 x86_64 asm MSB | curve25519.c (nb shared-secret) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-HCGC-HFP6-58V4 | CVE-2026-10097 | wolfSSL/wolfssl | ML-KEM AVX2 IND-CCA2 | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-58FJ-7XWC-45HQ | CVE-2026-55960 | wolfSSL/wolfssl | un-negotiated RPK as X.509 | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-68G3-7FHP-7RG3 | CVE-2026-55964 | wolfSSL/wolfssl | temp-CA keyCertSign | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-8MFX-6CPC-CR47 | CVE-2026-55958 | wolfSSL/wolfssl | Renesas TSIP OOB write | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-H4WH-367G-85GM | CVE-2026-11310 | wolfSSL/wolfssl | X509_verify_cert chain bypass | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-M8R2-QGR6-4GQM | CVE-2026-10592 | wolfSSL/wolfssl | wildcard SAN name-constraint | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-Q349-X427-XG3W | CVE-2026-12340 | wolfSSL/wolfssl | SM2/SM3 OOB read | internal.c/tls.c (async nbCtx) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-P5CP-VQJQ-6CJ7 | CVE-2026-48682 | pavel-odintsov/fastnetmon | simple_packet_parser_ng.cpp IPv4 OOB | afpacket_collector.cpp / tests | FALSE_POSITIVE (no_ai_origin) |
| GHSA-QP9Q-4RH4-M8JC | CVE-2026-10705 | dask/dask | hyperloglog.py nunique_approx | _task_spec.py/base.py/bag | FALSE_POSITIVE (no_ai_origin) |
| GHSA-32FW-H446-J4HH | CVE-2026-56701 | getgrav/grav | SVG upload XXE (simplexml) | GPM/Upgrade/Twig regex | FALSE_POSITIVE (no_ai_origin) |

## Why each candidate is not the origin

- **JeecgBoot** — the single candidate `670eea97772c` rewrites `OpenApiController.validOriginUrl` and its call URL to support microservice gateway base paths and full http(s) `originUrl` (issue 9590). The eight advisories target SysUser, LoginController, AiragModelController, FileDownloadUtils, WordUtil, and ThirdLoginController; the candidate touches none of those components, so it cannot introduce those mechanisms.
- **wolfSSL** — the two candidates `2a18b7ee` and `19bb7198` are in the `WOLFSSL_ASYNC_CRYPT_SW` non-blocking X25519/ECC path (`src/internal.c`, `src/tls.c`, `asn.c` `ConfirmSignature`, `curve25519.c` shared-secret-nb) and are defensive fixes (conditional `nbCtx` setup, `XFREE`, zero-shared-secret check). The 14 advisories are PKCS#7, X.509, AES-GCM, ML-KEM, SM2/SM3, RPK, name-constraint and Renesas-TSIP issues in unrelated paths. The closest-appearing CVE-2026-10512 (X25519 asm MSB) lives in the x86_64 assembly, not the C `curve25519.c` file the candidate edits.
- **FastNetMon** — three candidates are GitHub code-scanning autofixes (integer cast, `O_CREAT` mode, printf format); the advisory names `src/simple_packet_parser_ng.cpp`, which none touches.
- **dask** — candidates are duck-typed-Future scheduling refactors and Python 3.14 pickle/CI changes; the advisory names `dask/dataframe/hyperloglog.py::nunique_approx`, untouched.
- **Grav** — candidates are major-version upgrade gating, a media-config blueprint move, and `Twig3CompatibilityTransformer` regex edits; the advisory names SVG upload via `simplexml_load_string`, untouched.

## Gate matrix

| Gate | PASS | FAIL | UNKNOWN |
|---|---|---|---|
| identity_gate | 0 | 0 | 25 |
| ai_hunk_gate | 0 | 25 | 0 |
| topology_gate | 0 | 0 | 25 |
| but_for_gate | 0 | 25 | 0 |
| fix_reversal_gate | 0 | 0 | 25 |
| release_gate | 0 | 0 | 25 |
| uniqueness_gate | 0 | 0 | 25 |

## Claim boundary

Negative diff reading proves no AI origin for these 25 rows; it is not evidence of global semantic uniqueness. No `PASS` is proposed, so the leader has nothing to replay here beyond confirming the no_ai_origin exclusions.
