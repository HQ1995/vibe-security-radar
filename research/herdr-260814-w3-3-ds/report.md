# unr-adj3-slice-3 unreviewed forward-map adjudication (deepseek-v4-pro)

Verdict first: reviewed 25/25. CONFIRM 0, FALSE_POSITIVE 25, UNKNOWN 0. countable_proposal=0. terminal=true. No AI candidate commit introduces the named mechanism in any row; every row is an unrelated AI fix/docs/test/workflow change or a different surface. The canonical ledger was not edited and greater-than-200 stays HOLD.

## Method

FWD-SPEC forward-map for no-fix-ref unreviewed advisories. First-party (unreviewed) GHSA objects were loaded from the local advisory-database clone (advisories/unreviewed/...). Candidate commit diffs were read from the sweep pool (all five repos already present: jeecgboot, fastnetmon, dask, getgrav, wolfSSL). No GitHub API, no git blame/SZZ. FALSE_POSITIVE is used only where the candidate diff was read and positively shows a fix or a non-matching surface; missing evidence is never converted to FAIL.

## Counts

- assigned 25, reviewed 25, unreviewed 0. Conservation 25=25+0.
- CONFIRM 0, FALSE_POSITIVE 25, UNKNOWN 0, countable_proposal 0.
- identity_gate PASS 25 (unreviewed GHSA objects name mechanism + public identity; none withdrawn).
- ai_hunk/topology/but_for FAIL 25 (candidate diff read; wrong surface / fix-only).
- fix_reversal/release UNKNOWN 25 (unreviewed affected=[] and no structured fix commit).
- uniqueness PASS 25 (absent from foundation.jsonl and canonical84 ledger).

## Per-row

| # | case_id | repo | verdict | mechanism | note |
|---|---|---|---|---|---|
| 0 | GHSA-Q7X2-2W32-GXV3 | jeecgboot/JeecgBoot | FALSE_POSITIVE | sysuser-useredit-improper-access-control | Single candidate 670eea97 (Co-Authored-By Claude Opus 4.7) is an OpenA |
| 1 | GHSA-V77Q-XXPR-RX9G | jeecgboot/JeecgBoot | FALSE_POSITIVE | selectdepart-improper-access-control | Single candidate 670eea97 (Co-Authored-By Claude Opus 4.7) is an OpenA |
| 2 | GHSA-32F8-XFVP-9M45 | jeecgboot/JeecgBoot | FALSE_POSITIVE | airag-model-improper-access-control | Single candidate 670eea97 (Co-Authored-By Claude Opus 4.7) is an OpenA |
| 3 | GHSA-3M2M-6PHQ-RXRQ | jeecgboot/JeecgBoot | FALSE_POSITIVE | file-download-ssrf-metadata-endpoint | Single candidate 670eea97 (Co-Authored-By Claude Opus 4.7) is an OpenA |
| 4 | GHSA-GG5C-V856-2RJP | jeecgboot/JeecgBoot | FALSE_POSITIVE | word-util-addimage-ssrf | Single candidate 670eea97 (Co-Authored-By Claude Opus 4.7) is an OpenA |
| 5 | GHSA-Q4C7-VXGR-R6M2 | jeecgboot/JeecgBoot | FALSE_POSITIVE | airag-model-test-ssrf | Single candidate 670eea97 (Co-Authored-By Claude Opus 4.7) is an OpenA |
| 6 | GHSA-P5CP-VQJQ-6CJ7 | pavel-odintsov/fastnetmon | FALSE_POSITIVE | ipv4-parser-oob-read | Three candidates are Copilot-Autofix (github-advanced-security bot) Co |
| 7 | GHSA-QP9Q-4RH4-M8JC | dask/dask | FALSE_POSITIVE | hll-nunique-approx-resource-consumption | Five candidates (Co-Authored-By Claude) are duck-typed Futures support |
| 8 | GHSA-G4G6-G3HX-2F5W | jeecgboot/JeecgBoot | FALSE_POSITIVE | user-list-querypagelist-info-disclosure | Single candidate 670eea97 (Co-Authored-By Claude Opus 4.7) is an OpenA |
| 9 | GHSA-2R69-34R8-6C68 | jeecgboot/JeecgBoot | FALSE_POSITIVE | third-login-open-redirect | Single candidate 670eea97 (Co-Authored-By Claude Opus 4.7) is an OpenA |
| 10 | GHSA-32FW-H446-J4HH | getgrav/grav | FALSE_POSITIVE | svg-upload-xxe | Five candidates (Claude/Copilot) are: compatibility blueprint gating ( |
| 11 | GHSA-CJ56-5C53-9QJF | wolfSSL/wolfssl | FALSE_POSITIVE | pkcs7-degenerate-verify | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 12 | GHSA-H6GC-RMV2-74G6 | wolfSSL/wolfssl | FALSE_POSITIVE | pkcs7-envelopeddata-overread | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 13 | GHSA-HVWM-W7RW-23CV | wolfSSL/wolfssl | FALSE_POSITIVE | pkcs7-ktri-padding-oracle | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 14 | GHSA-MHQ8-94H7-MRGX | wolfSSL/wolfssl | FALSE_POSITIVE | partial-chain-verify | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 15 | GHSA-Q4Q5-JX42-4XP9 | wolfSSL/wolfssl | FALSE_POSITIVE | aes-gcm-counter-wrap | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 16 | GHSA-WRW6-8JH4-QVCX | wolfSSL/wolfssl | FALSE_POSITIVE | x509-verify-path-depth-bypass | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 17 | GHSA-GJM7-VCH5-HCH8 | wolfSSL/wolfssl | FALSE_POSITIVE | x25519-asm-reduction | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 18 | GHSA-HCGC-HFP6-58V4 | wolfSSL/wolfssl | FALSE_POSITIVE | ml-kem-avx2-implicit-rejection | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 19 | GHSA-58FJ-7XWC-45HQ | wolfSSL/wolfssl | FALSE_POSITIVE | raw-public-key-chain-bypass | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 20 | GHSA-68G3-7FHP-7RG3 | wolfSSL/wolfssl | FALSE_POSITIVE | temp-ca-keycertsign | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 21 | GHSA-8MFX-6CPC-CR47 | wolfSSL/wolfssl | FALSE_POSITIVE | renesas-tsip-transcript-oob-write | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 22 | GHSA-H4WH-367G-85GM | wolfSSL/wolfssl | FALSE_POSITIVE | x509-verify-path-depth-bypass-2 | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 23 | GHSA-M8R2-QGR6-4GQM | wolfSSL/wolfssl | FALSE_POSITIVE | wildcard-san-name-constraint-bypass | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 24 | GHSA-Q349-X427-XG3W | wolfSSL/wolfssl | FALSE_POSITIVE | sm2-sm3-signature-oob-read | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |

## Per-repo candidate disposition

- **jeecgboot/JeecgBoot**: Single candidate 670eea97 (Co-Authored-By Claude Opus 4.7) is an OpenAPI proxy base-path fix for issue #9590 in OpenApiController.call/validOriginUrl. It does not touch any of the named surfaces: SysUser userEdit/queryPageList, LoginController.selectDepart, AiragModelController, FileDownloadUtils, WordUtil, airagModel/test, or ThirdLoginController.
- **pavel-odintsov/fastnetmon**: Three candidates are Copilot-Autofix (github-advanced-security bot) CodeQL fixes: multiplication cast in afpacket_collector.cpp, file-open mode in tests/pcap_writer.cpp, printf format in tests/lpm_performance_tests.cpp. None touches src/simple_packet_parser_ng.cpp (the IPv4 OOB-read sink).
- **dask/dask**: Five candidates (Co-Authored-By Claude) are duck-typed Futures support in dask/_task_spec.py + dask/base.py, and Python 3.14 pickle/CI changes in dask/bag/core.py + workflows. None touches dask/dataframe/hyperloglog.py (nunique_approx).
- **getgrav/grav**: Five candidates (Claude/Copilot) are: compatibility blueprint gating (Package.php, SafeUpgradeService, IndexCommand), media config blueprint + translations, and Twig3CompatibilityTransformer regex fixes. None touches the SVG-upload / simplexml_load_string XXE sink.
- **wolfSSL/wolfssl**: Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) are async-crypto FIXES: a non-blocking X25519/ECC devId guard and peer-review memory-leak fixes. The three other recent commits are CI workflow changes. None introduces the named C mechanism (separate PRs name the actual fixes).

## Evidence paths

- Slice: /home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj3-slice-3.jsonl (sha256 ccb59a9c4f18f2103b99d88eb7ff1752e81064e322c01c64887f68ff3c74cfeb)
- Contract: /home/hanqing/agents/ai-slop/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md (sha256 cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3)
- FWD spec: /home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/FWD-SPEC.md (sha256 672c45d1f98054a597ce12aa0879daa00b884d9207884e9a10e23c0fdc2d5750)
- Advisories: /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database (advisories/unreviewed/...)
- Repo clones: jeecgboot__JeecgBoot, pavel-odintsov__fastnetmon, dask__dask, getgrav__grav, wolfSSL__wolfssl
- Uniqueness: foundation.jsonl (168) and canonical84/ledger.jsonl (read-only).

## Claim boundary

Worker FALSE_POSITIVE is a proposal. Leader replay is required before anything counts. Canonical84 remains the only claim source.
