# herdr-260814-w3-1-ds — unreviewed-adj3 adjudication slice-1

**Verdict-first: 25/25 FALSE_POSITIVE. 0 countable, 0 PASS proposals.**

No candidate AI commit introduces the named advisory mechanism. The dominant pattern is fix-only: the flagged commits are Claude/OpenHands-co-authored *fixes* (bludit security hardening, wolfSSL async-ECC/X25519 cleanup, ixray OpenSSL-fork hardening) that remove bugs rather than introduce the vulnerability; the remainder (ocaml determinism tests, wordpress-webmention include updates) touch files fully disjoint from the mechanism file. Packet delta = 0; canonical count unchanged; publication HOLD.

## Method

- Advisory mechanisms read from the local advisory-database clone `advisories/unreviewed/` (origin/main FETCH_HEAD 8b901fa43d0e3d09e9bece095afb760dd9dff6e8).

- Candidate diffs read from the sweep pool `/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>` (all five slice repos already present; no new fetches). No GitHub API, no blame/SZZ.

- `diff_read` rows: full `git show <sha> -- <file>` (bludit fbb08543, wolfSSL 2a18b7ee / 19bb7198). `changed_files` rows: `git diff-tree --name-only -r <sha>` + commit subject.

## Gates

identity=NARROW (unreviewed; all 25 name the correct repository), ai_hunk=FAIL (AI commits author fix/disjoint hunks, never the vulnerable hunk), topology=NARROW, but_for=FAIL, fix_reversal=UNKNOWN (no fix ref in this lane), release=UNKNOWN, uniqueness=PASS (none of the 25 ids/aliases in foundation.jsonl).

## Per-row

| # | GHSA | CVE | repo | mechanism | candidate(s) | class | verdict |
|---|---|---|---|---|---|---|---|
| 1 | GHSA-WG93-HP69-VV5W | CVE-2026-27742 | bludit/bludit | pages.class.php (post content XSS) | fbb08543,f91393d7,6a6cdb02,d09327cb,270d59bb | FIX_ONLY | FALSE_POSITIVE |
| 2 | GHSA-XW6C-FFPM-FGCM | CVE-2026-27741 | bludit/bludit | admin uninstall-plugin/install-theme (CSRF) | fbb08543,f91393d7,6a6cdb02,d09327cb,270d59bb | DISJOINT | FALSE_POSITIVE |
| 3 | GHSA-2Q9G-Q8JJ-FR53 | CVE-2026-1005 | wolfSSL/wolfssl | sniffer.c ssl_DecodePacket | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |
| 4 | GHSA-3CR6-HPF3-2HMG | CVE-2026-0819 | wolfSSL/wolfssl | pkcs7.c BuildSignedAttributes | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |
| 5 | GHSA-24VQ-QFC5-QRMJ | CVE-2026-2646 | wolfSSL/wolfssl | ssl.c d2i_SSL_SESSION | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |
| 6 | GHSA-86FV-Q5VX-MW5M | CVE-2026-3548 | wolfSSL/wolfssl | crl.c CRL number | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |
| 7 | GHSA-CWC7-2FMX-FFFQ | CVE-2026-2645 | wolfSSL/wolfssl | internal.c/tls.c CertificateVerify | 2a18b7ee,19bb7198 | FIX_ONLY | FALSE_POSITIVE |
| 8 | GHSA-F5X4-GF23-WQM9 | CVE-2026-3579 | wolfSSL/wolfssl | sp_*.c __muldi3 | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |
| 9 | GHSA-PGC5-R6CV-2825 | CVE-2026-3503 | wolfSSL/wolfssl | mlkem/mldsa | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |
| 10 | GHSA-WM74-PVWW-Q7H2 | CVE-2026-3580 | wolfSSL/wolfssl | sp_c32.c | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |
| 11 | GHSA-267H-VRW9-53P3 | CVE-2026-3849 | wolfSSL/wolfssl | hpke.c ECH | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |
| 12 | GHSA-6P64-86QJ-33GC | CVE-2026-3229 | wolfSSL/wolfssl | ssl.c add_to_chain | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |
| 13 | GHSA-CQX9-3CPJ-RRQP | CVE-2026-4395 | wolfSSL/wolfssl | ecc.c KCAPI | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |
| 14 | GHSA-F377-557W-VJGV | CVE-2026-3547 | wolfSSL/wolfssl | internal.c/tls.c ALPN | 2a18b7ee,19bb7198 | FIX_ONLY | FALSE_POSITIVE |
| 15 | GHSA-G3XR-5F55-CF5G | CVE-2026-3230 | wolfSSL/wolfssl | tls13.c HRR | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |
| 16 | GHSA-J2G5-52P7-MFPC | CVE-2026-3549 | wolfSSL/wolfssl | internal.c ECH | 2a18b7ee,19bb7198 | FIX_ONLY | FALSE_POSITIVE |
| 17 | GHSA-M9R6-9WMX-24JV | CVE-2026-4159 | wolfSSL/wolfssl | pkcs7.c EnvelopedData | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |
| 18 | GHSA-6C79-F9M3-C7M5 | CVE-2026-4733 | ixray-team/ixray-1.6-stcop | (not named) | 07d0f320,8def7a05,47ab138e,dc27dbaa,4d06ee38 | DISJOINT | FALSE_POSITIVE |
| 19 | GHSA-6P45-JV22-32GP | CVE-2026-34353 | ocaml/ocaml | stdlib/bigarray.ml | 023461ab,a5bf6c8a,37d9d80e,c7455ea1,ebbeb505 | DISJOINT | FALSE_POSITIVE |
| 20 | GHSA-PWM7-WR54-2JXV | CVE-2026-0686 | pfefferle/wordpress-webmention | class-receiver.php | 5be4c572,f355d5bf,0bc8faf7,86c9ad4b,bc1d5678 | DISJOINT | FALSE_POSITIVE |
| 21 | GHSA-WJF6-53J2-2F8C | CVE-2026-0688 | pfefferle/wordpress-webmention | class-tools.php | 5be4c572,f355d5bf,0bc8faf7,86c9ad4b,bc1d5678 | DISJOINT | FALSE_POSITIVE |
| 22 | GHSA-98WW-GW4P-68M3 | CVE-2026-5187 | wolfSSL/wolfssl | asn.c DecodeObjectId | 2a18b7ee,19bb7198 | FIX_ONLY | FALSE_POSITIVE |
| 23 | GHSA-F5H9-5Q52-QRX7 | CVE-2026-5194 | wolfSSL/wolfssl | asn.c ECDSA verify | 2a18b7ee,19bb7198 | FIX_ONLY | FALSE_POSITIVE |
| 24 | GHSA-MX4J-FJQX-F8QJ | CVE-2026-5447 | wolfSSL/wolfssl | asn.c CertFromX509 | 2a18b7ee,19bb7198 | FIX_ONLY | FALSE_POSITIVE |
| 25 | GHSA-VGV9-MV66-MPC7 | CVE-2026-5446 | wolfSSL/wolfssl | aes.c ARIA-GCM | 2a18b7ee,19bb7198 | DISJOINT | FALSE_POSITIVE |

## Detail

- **bludit (#1/#2, fbb08543)** — `fix: #1506 #1582 #1613 #1571 security and bug fixes`, `Co-Authored-By: Claude Sonnet 4.6`. Adds an IDOR authorization check, `SameSite=Lax`/`__Secure-` session cookie, `htmlspecialchars` on navigation labels, and an empty-content guard in `pages.class.php`. It does not introduce the stored-XSS output-encoding gap (#1) or the uninstall-plugin/install-theme CSRF (#2).

- **wolfSSL (#3-17, #22-25, 2a18b7ee + 19bb7198)** — `Fix non-blocking X25519/ECC with WOLFSSL_ASYNC_CRYPT_SW` and `Peer review fixes`, both `Co-Authored-By: Claude` (Sonnet/Opus 4.x), author David Garske. The two diffs only (a) guard `AllocKey`/`TLSX_KeyShare_GenX25519Key` async setup behind `devId != INVALID_DEVID` to avoid `FP_WOULDBLOCK`, and (b) add an `XFREE` memory-leak fix in `asn.c ConfirmSignature`. Every named CVE lives in a different file (sniffer.c, pkcs7.c, ssl.c, crl.c, sp_*.c, mlkem/mldsa, hpke.c, ecc.c, tls13.c, aes.c) or a different hunk of internal.c/tls.c/asn.c (CertificateVerify, ALPN, ECH, DecodeObjectId, CertFromX509).

- **ixray (#18)** — OpenHands/tabudz commits are all OpenSSL-fork fixes (tasn_dec leak, DH small-subgroup, BN_bn2dec overflow, BN_mod_sqrt loop); the advisory names no function/file ("before 1.3").

- **ocaml (#19)** — `.cmo` determinism tests + typing counter resets; disjoint from `stdlib/bigarray.ml Bigarray.reshape`.

- **wordpress-webmention (#20/#21)** — candidates touch `includes/class-comment-walker.php`, `wp-admin/*`, `Entity/class-item.php`, `Handler/class-wp.php`; disjoint from `includes/class-receiver.php` (Receiver::post) and `includes/class-tools.php` (Tools::read).

## Conclusion

This packet admits no countable case. All 25 rows close at ai_hunk/but_for FAIL (fix-only or disjoint edge). Canonical ledger untouched; publication HOLD.
