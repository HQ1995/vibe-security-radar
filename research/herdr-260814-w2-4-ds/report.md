# Unreviewed forward-map adjudication: unr-adj2-slice-4.jsonl

Verdict-first: **0 countable**. All 25 assigned rows are `FALSE_POSITIVE` (24 `wrong_edge`, 1 `wrong_version`): no candidate AI commit authors the advisory's named vulnerable hunk. No PASS proposals for leader replay.

## Method
- Read each unreviewed advisory JSON from the local advisory-database clone (`advisories/unreviewed/`, `github_reviewed=false`).
- Fetched and read the candidate AI commit diffs via git smart-HTTP into the sweep pool (no GitHub API, no blame/SZZ).
- Compared the advisory's named vulnerable function/file against the candidate commit diffs.
- 18/25 rows are wolfSSL: both candidates are Co-Authored-By Claude X25519/ECC non-blocking async changes; each advisory names a memory-safety/crypto bug in a different subsystem.
- 6/25 rows are JeecgBoot: single candidate 670eea97 (Claude Opus 4.7) is an OpenApiController originUrl change; 5 rows name a different component, and the one matching component (FC85, originUrl SSRF) fails on release topology.
- 1/25 is maxi-blocks (Stored XSS): candidates are unused-variable/snapshot/test edits and a carrier merge, not the style-card REST route.

## Result

| ord | case_id | repository | verdict | class | vulnerable surface | AI-commit surface |
|---:|---|---|---|---|---|---|
| 1 | GHSA-2JVP-H4W4-2VXH | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | src/sniffer.c::ssl_DecodePacket | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 2 | GHSA-52WM-3MQV-VMMJ | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | wolfcrypt/src/pkcs7.c::PKCS7_VerifySignedData | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 3 | GHSA-5JQQ-XPCR-Q3R7 | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | wolfcrypt/src/asn.c::wolfSSL_X509_notAfter/notBefore | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 4 | GHSA-65XM-PFX9-G5P3 | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | src/tls.c::TLSX_EchChangeSNI/TLSX_EchRestoreSNI | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 5 | GHSA-6V2V-JGG9-H79W | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | src/internal.c::MatchDomainName | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 6 | GHSA-9XMR-C663-3RPR | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | wolfcrypt/src/asn.c chain verification | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 7 | GHSA-F4W6-5M9P-28HW | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | src/tls.c CertificateVerify | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 8 | GHSA-F5FH-XMXQ-55P9 | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | src/internal.c session restore | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 9 | GHSA-FGX8-Q3CF-P457 | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | wolfcrypt/src/pkcs7.c::wc_PKCS7_DecryptOri | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 10 | GHSA-QVJW-73XM-JW34 | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | wolfcrypt/src/pkcs7.c CBC decrypt | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 11 | GHSA-W5QH-HW7X-9W39 | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | src/dtls.c ACK processing | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 12 | GHSA-W87P-FQGX-CQQ8 | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | src/tls.c::TLSX_KeyShare_ProcessPqcHybridClient | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 13 | GHSA-3XR8-R75G-G9C6 | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | wolfcrypt/src/evp.c::wolfSSL_EVP_CipherFinal | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 14 | GHSA-47QF-HP3H-RWMM | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | wolfcrypt/src/eccsi.c::wc_VerifyEccsiHash | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 15 | GHSA-9QGC-PCPX-G38Q | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | wolfcrypt/src/asn.c SAN parsing | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 16 | GHSA-GRQC-3VMG-P68X | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | wolfcrypt/src/cmac.c::wc_CmacUpdate | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 17 | GHSA-HG75-4CMP-F367 | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | compat layer wolfSSL_X509_verify_cert | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 18 | GHSA-M77R-VQW2-HFFX | wolfSSL/wolfssl | FALSE_POSITIVE | wrong_edge | wolfcrypt/src/pkcs7.c::wc_PKCS7_DecodeAuthEnvelopedData | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 19 | GHSA-596J-X8QJ-W8QX | jeecgboot/JeecgBoot | FALSE_POSITIVE | wrong_edge | /sys/fillRule/edit (ruleClass arg, improper authorization) | OpenApiController.java (originUrl full-URL) |
| 20 | GHSA-8P3W-9597-PWH9 | maxi-blocks/maxi-blocks | FALSE_POSITIVE | wrong_edge | core/class-maxi-api.php::style-card (sc_styles param) | ai-chat-panel JS, snapshots, setSVGColor test, carrier merge |
| 21 | GHSA-FC85-MQVW-FGVH | jeecgboot/JeecgBoot | FALSE_POSITIVE | wrong_version | OpenApiController.java::add/call (originUrl) | OpenApiController.java (originUrl full-URL) |
| 22 | GHSA-VXX8-4P2V-5G5J | jeecgboot/JeecgBoot | FALSE_POSITIVE | wrong_edge | FileDownloadUtils.java::checkPathTraversalBatch (files arg, SSRF) | OpenApiController.java (originUrl full-URL) |
| 23 | GHSA-59HR-3PCC-42PG | jeecgboot/JeecgBoot | FALSE_POSITIVE | wrong_edge | CommonController.java::uploadImgByHttp/HttpFileToMultipartFileUtil (SSRF) | OpenApiController.java (originUrl full-URL) |
| 24 | GHSA-PGHV-W792-QVJG | jeecgboot/JeecgBoot | FALSE_POSITIVE | wrong_edge | /sys/dict/loadTreeData (condition arg, SQL injection) | OpenApiController.java (originUrl full-URL) |
| 25 | GHSA-27F4-GXM8-Q49Q | jeecgboot/JeecgBoot | FALSE_POSITIVE | wrong_edge | /sys/comment/add (improper access control) | OpenApiController.java (originUrl full-URL) |

## Gate summary
Every row: `identity_gate=PASS` (advisory names repo + mechanism + identity, `github_reviewed=false`), `ai_hunk_gate=FAIL` (candidate diffs read; they do not author the vulnerable hunk), `topology_gate=PASS` (no authorship transfer), `but_for_gate=FAIL` (removing the AI commit does not remove the named mechanism), `fix_reversal_gate=UNKNOWN` and `release_gate=UNKNOWN` (no first-party fix/version evidence closes them locally), `uniqueness_gate=PASS`.

FC85 (CVE-2026-7604, originUrl SSRF) is the sole row where the candidate touches the named component. Its `ai_hunk_gate` is FAIL on version topology, not on file mismatch: `670eea97` is not an ancestor of `v3.9.1` (the vulnerable release the advisory names) and IS an ancestor of `v3.9.2` (the fix release). The vulnerable `<=3.9.1` hunk (`url = RestUtil.getBaseUrl() + originUrl` + `restTemplate.exchange`, with no validation) is human-authored and predates the AI commit (2026-04-29). The AI commit references issues/9590 (microservice deployment), distinct from the SSRF report issues/9554.

## Evidence
- Advisory DB: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` @ `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`
- wolfSSL pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/wolfSSL__wolfssl`; candidates 2a18b7ee4463a38d64cdaf7e6b7ddc276118ff7b, 19bb7198a2074cec107d0fa93adfaea1ed5e5f23
- JeecgBoot pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/jeecgboot__JeecgBoot`; candidate 670eea97772c71fd354380a191869a9cd4b575a4; tags v3.9.1=1d4042a0c13ad4a9e6092453063005ca25623fd0, v3.9.2=7df07a823fd558be857d0208ccae96342539fbc1
- maxi-blocks pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/maxi-blocks__maxi-blocks`; 5 candidates (47a90ec3, 935aec85, f6320d64, d41fc473, 37cf81b7)

Candidate wolfSSL diffs (both read in full):
- `2a18b7ee` "Fix non-blocking X25519/ECC with WOLFSSL_ASYNC_CRYPT_SW" - `src/internal.c`, `src/tls.c` (nbCtx setup only when devId!=INVALID_DEVID).
- `19bb7198` "Peer review fixes" - `src/tls.c` (TLSX_KeyShare_ProcessX25519_ex comment), `wolfcrypt/src/asn.c` (ConfirmSignature nbCtx XFREE), `curve25519.c`, `test.c`.
Neither touches the advisory-named functions (sniffer.c, pkcs7.c, ECH, MatchDomainName, nameConstraints, evp.c, cmac.c, dtls.c, eccsi.c, dual-alg, PQC KeyShare, SAN).

Candidate JeecgBoot diff (read in full):
- `670eea97` "[issues/9590] OpenAPI call uses CommonUtils.getBaseUrl and allows full http(s) originUrl" - `OpenApiController.java` only (relaxes `validOriginUrl` to permit full http(s) URLs).

Candidate maxi-blocks diffs (all read in full): unused-variable fixes (flowEngine.js, container.js), playwright snapshots, setSVGColor test, and a merge whose diff does not touch `core/class-maxi-api.php`.
