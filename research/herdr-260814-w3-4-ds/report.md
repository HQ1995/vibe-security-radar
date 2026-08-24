# Unreviewed forward-map adjudication: unr-adj3-slice-4.jsonl

Verdict-first: **0 countable**. All 25 assigned rows are `FALSE_POSITIVE` (class `no_ai_origin`): no candidate AI commit authors the advisory's named vulnerable hunk. No PASS proposals for leader replay.

## Method
- Read each unreviewed advisory JSON from the local advisory-database clone (`advisories/unreviewed/`, `github_reviewed=false`).
- Fetched and read the candidate AI commit diffs via git smart-HTTP into the sweep pool (no GitHub API, no blame/SZZ).
- Compared the advisory's named vulnerable function/file against the candidate commit diffs.
- 18/25 rows are wolfSSL (both candidates Co-Authored-By Claude X25519/ECC non-blocking async changes); 6/25 are getgrav/grav; 1/25 is jeecgboot/JeecgBoot.

## Result

| ord | case_id | repository | verdict | class | vulnerable surface | AI-commit surface |
|---:|---|---|---|---|---|---|
| 1 | GHSA-W9RP-WWM2-FWMR | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | src/tls.c::TLSX_KeyShare PQC error cleanup | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 2 | GHSA-6Q89-VXVR-WGV2 | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | wolfcrypt/src/pkcs7.c decode (outputSz) | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 3 | GHSA-9C3C-227Q-3J67 | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | wolfcrypt/src/asn.c name constraints | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 4 | GHSA-C9Q2-5C67-XG9P | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | src/dtls.c ACK record list | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 5 | GHSA-P894-8WV9-373J | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | wolfcrypt/src/pkcs7.c::wc_PKCS7_DecryptOri | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 6 | GHSA-QPCH-GJF6-C9GF | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | wolfcrypt/src/asn.c::ParseCRL_Extensions | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 7 | GHSA-W3GW-F9WR-G6QX | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | wolfcrypt/src/asn.c certificate processing | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 8 | GHSA-GWRH-R2G6-7WGP | getgrav/grav | FALSE_POSITIVE | no_ai_origin | grav-plugin-admin page editor (before 1.6.30) | upgrade-gating / media-blueprint / Twig3-compat (core grav) |
| 9 | GHSA-Q3PX-VRJJ-4F97 | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | src/tls.c session resumption | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 10 | GHSA-XPV9-P7VG-QHRC | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | wolfcrypt/src/ocsp.c::wolfSSL_OCSP_resp_find_status | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 11 | GHSA-34QM-63X6-FCM3 | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | wolfcrypt/src/blake2b.c/blake2s.c HMAC final | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 12 | GHSA-576M-XH9M-C774 | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | src/tls.c (HAVE_ENCRYPT_THEN_MAC) | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 13 | GHSA-5HPF-PC4X-3JCF | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | wolfcrypt/src/evp.c::EVP_DigestVerifyFinal | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 14 | GHSA-69Q5-VHM6-656F | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | wolfcrypt/src/pkcs7.c::PKCS7_verify | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 15 | GHSA-89V8-3927-WFCG | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | wolfcrypt/src/mlkem.c (ARM64 NEON) | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 16 | GHSA-GQ94-HF88-G4WV | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | src/tls.c post-handshake auth (PHA) | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 17 | GHSA-H4JR-6MF9-63FQ | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | wolfcrypt/src/asn.c name constraints | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 18 | GHSA-R98J-G9P3-FCGM | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | wolfcrypt/src/pkcs12.c MAC verify | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 19 | GHSA-XPF5-WWVX-W945 | wolfSSL/wolfssl | FALSE_POSITIVE | no_ai_origin | src/tls.c::SetSuitesHashSigAlgo | src/internal.c+src/tls.c / src/tls.c+asn.c+curve25519.c (X25519/ECC async) |
| 20 | GHSA-6W4X-5VF2-7756 | jeecgboot/JeecgBoot | FALSE_POSITIVE | no_ai_origin | OpenApiAuthController.java / OpenApiPermissionController.java (missing Shiro authz) | OpenApiController.java (originUrl full-URL) |
| 21 | GHSA-58CG-X8GX-6HG3 | getgrav/grav | FALSE_POSITIVE | no_ai_origin | Scheduler\JobQueue, Framework\Cache\Adapter\FileCache, Session, InstallCommand (before 2.0.0-beta.2) | upgrade-gating / media-blueprint / Twig3-compat (core grav) |
| 22 | GHSA-FX5H-WV8R-5J9Q | getgrav/grav | FALSE_POSITIVE | no_ai_origin | grav-plugin-api (before v1.0.0-rc.16) | upgrade-gating / media-blueprint / Twig3-compat (core grav) |
| 23 | GHSA-W3XR-JX24-VW2H | getgrav/grav | FALSE_POSITIVE | no_ai_origin | grav-plugin-api avatar endpoint (1.0.0, fixed 1.0.1) | upgrade-gating / media-blueprint / Twig3-compat (core grav) |
| 24 | GHSA-G78V-PR5G-35V2 | getgrav/grav | FALSE_POSITIVE | no_ai_origin | grav-plugin-api media endpoint (before 1.0.3) | upgrade-gating / media-blueprint / Twig3-compat (core grav) |
| 25 | GHSA-JXPJ-M582-7727 | getgrav/grav | FALSE_POSITIVE | no_ai_origin | system/src/Grav/Common/Utils/ZipArchiver.php::extract (before 2.0.1) | upgrade-gating / media-blueprint / Twig3-compat (core grav) |

## Gate summary
Every row: `identity_gate=PASS` (advisory names repo + mechanism + identity, `github_reviewed=false`), `ai_hunk_gate=FAIL` (candidate diffs read; they do not author the vulnerable hunk), `topology_gate=PASS` (no authorship transfer), `but_for_gate=FAIL` (removing the AI commit does not remove the named mechanism), `fix_reversal_gate=UNKNOWN` and `release_gate=UNKNOWN` (no first-party fix/version evidence closes them locally), `uniqueness_gate=PASS`.

## Evidence
- Advisory DB: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` @ `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`
- wolfSSL pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/wolfSSL__wolfssl`; candidates 2a18b7ee4463a38d64cdaf7e6b7ddc276118ff7b, 19bb7198a2074cec107d0fa93adfaea1ed5e5f23
- JeecgBoot pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/jeecgboot__JeecgBoot`; candidate 670eea97772c71fd354380a191869a9cd4b575a4
- getgrav pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/getgrav__grav`; candidates 2c517b01, e3ff054d, 2dcf9179, bf7dd2e6, 50865058

Candidate wolfSSL diffs (both read in full):
- `2a18b7ee` "Fix non-blocking X25519/ECC with WOLFSSL_ASYNC_CRYPT_SW" - `src/internal.c`, `src/tls.c` (nbCtx setup only when devId!=INVALID_DEVID).
- `19bb7198` "Peer review fixes" - `src/tls.c`, `wolfcrypt/src/asn.c` (ConfirmSignature nbCtx XFREE), `curve25519.c`, `test.c`.
Neither touches PQC KeyShare, PKCS7, nameConstraints, DTLS ACK, CRL, SHA-1/MD5 policy, SNI/ALPN resumption, OCSP, BLAKE2 HMAC, EtM, EVP HMAC, PKCS7_verify, ML-KEM, PHA, PKCS12 MAC, or SetSuitesHashSigAlgo.

Candidate getgrav diffs (all read in full):
- `2c517b01` "Add compatibility: blueprint major-version upgrade gating" - Install.php, SafeUpgradeService, GPM, console (no shell/exec/unserialize/git-clone).
- `e3ff054d` "Move media config blueprint + translations from admin to core" - media.yaml + 44 language files.
- `2dcf9179`, `bf7dd2e6` - 1-line comments in Twig3CompatibilityTransformer.php (Copilot).
- `50865058` "Fix JIT stack exhaustion in Twig3 compatibility regex" - Twig3CompatibilityTransformer.php regex only.
None touches the admin page editor, Scheduler\JobQueue/FileCache/Session unserialize, InstallCommand git clone, Twig security blocklist, the API plugin endpoints, or ZipArchiver::extract.

Candidate JeecgBoot diff (read in full):
- `670eea97` "[issues/9590] OpenAPI call uses CommonUtils.getBaseUrl and allows full http(s) originUrl" - `OpenApiController.java` only; does not touch `OpenApiAuthController.java` or `OpenApiPermissionController.java`.
