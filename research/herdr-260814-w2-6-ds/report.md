# herdr-260814-w2-6-ds - slice 6 (unr-adj2) adjudication

**Verdict first: 25/25 FALSE_POSITIVE, 0 countable.** Every candidate AI commit
in this slice carries an explicit AI marker, but none of their diffs authors the
vulnerable hunk of the advisory they are screened against. They are unrelated
fixes/refactors, so `ai_hunk_gate` and `but_for_gate` both FAIL and no row
closes the seven gates.

## Result

- assigned 25, reviewed 25, FALSE_POSITIVE 25, CONFIRM 0, NARROW 0, UNKNOWN 0
- terminal=true on all rows; zero proposed acceptances

## Per-repository evidence

### wolfSSL/wolfssl - 18 rows
Candidates `2a18b7ee` (Fix non-blocking X25519/ECC with WOLFSSL_ASYNC_CRYPT_SW)
and `19bb7198` (Peer review fixes) are Claude-co-authored fixes confined to the
non-blocking X25519/ECC path (`src/internal.c` AllocKey, `src/tls.c` KeyShare,
`wolfcrypt/src/curve25519.c`, an `asn.c` ConfirmSignature XFREE, test leak
fixes). None of the 18 advisories' mechanisms (PKCS#7 decode/outputSz, X.509
name-constraint bypass, DTLS 1.3 ACK overflow, CRL critical-extension bypass,
SHA-1/MD5 acceptance, SNI/ALPN resumption binding, OCSP CertID length confusion,
BLAKE2 HMAC message discard, Encrypt-then-MAC fallback, HMAC zero-length tag,
PKCS7_verify signer confusion, ML-KEM NEON half-compare, TLS 1.3 PHA missing
cert, iPAddress constraint bypass, PKCS#12 MAC length, SetSuitesHashSigAlgo OOB
write) is touched by these diffs.

### getgrav/grav - 6 rows
Candidates are GPM/Installer upgrade gating (`2c517b01`), media blueprint move
(`e3ff054d`), two Copilot Twig3 one-liners (`2dcf9179`, `bf7dd2e6`), and a Twig3
regex JIT fix (`50865058`). None touch the admin page-editor XSS
(CVE-2020-37256), the unserialize() code-exec (JobQueue/FileCache/Session), or
ZipArchiver::extract() decompression bomb. Three rows (`FX5H-WV8R-5J9Q`,
`W3XR-JX24-VW2H`, `G78V-PR5G-35V2`) name mechanisms in
`getgrav/grav-plugin-api` (JWT/CORS, avatar upload, SVG upload) - a different
repository than `getgrav/grav`, so the core commits cannot have introduced them.

### jeecgboot/JeecgBoot - 1 row
`GHSA-6W4X-5VF2-7756` is a missing-Shiro-authorization access-control issue on
`OpenApiAuthController`/`OpenApiPermissionController`. Candidate `670eea97`
edits `OpenApiController.call()` URL resolution and strengthens
`validOriginUrl()` protocol checks - a different controller, adding validation
rather than removing auth.

## Gate summary

identity_gate=PASS (first-party unreviewed advisory names mechanism + CVE);
ai_hunk_gate=FAIL (AI-marked commits do not author the vulnerable hunk);
topology_gate=FAIL; but_for_gate=FAIL (removing the AI change does not shrink
the mechanism); fix_reversal_gate=FAIL; release_gate=FAIL; uniqueness_gate=PASS.

## Disagreements with stored labels

Upstream triage (`herdr-260814-triage3-gf`) marked these KEEP on commit-subject
overlap. Deep adjudication of the actual diffs overturns every KEEP: the
overlaps are superficial and no candidate introduces the named mechanism.
