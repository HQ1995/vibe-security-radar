# unr-adj2-slice-3 unreviewed forward-map adjudication (deepseek-v4-pro)

Verdict first: reviewed 25/25. CONFIRM 0, FALSE_POSITIVE 25, UNKNOWN 0. countable_proposal=0. terminal=true. No AI candidate commit introduces the named mechanism in any row; every row is an unrelated AI fix/test/workflow change or a different surface. The canonical ledger was not edited and greater-than-200 stays HOLD.

## Method

FWD-SPEC forward-map for no-fix-ref unreviewed advisories. Each row names ghsa, repo, recent_ai_commits, candidate_shas. First-party (unreviewed) GHSA objects were loaded from the local advisory-database clone (advisories/unreviewed/...). Candidate commit diffs were read from the sweep pool; missing repos were fetched via git smart-HTTP (--filter=blob:none --shallow-since=2025-08-01). No GitHub API, no git blame/SZZ. FALSE_POSITIVE is used only where the candidate diff was read and positively shows a fix or a non-matching surface; missing evidence is never converted to FAIL.

## Counts

- assigned 25, reviewed 25, unreviewed 0. Conservation 25=25+0.
- CONFIRM 0, FALSE_POSITIVE 25, UNKNOWN 0, countable_proposal 0.
- identity_gate PASS 25 (unreviewed GHSA objects name mechanism + public identity; repository identified from references; none withdrawn).
- ai_hunk/topology/but_for FAIL 25 (candidate diff read; wrong surface / fix-only).
- fix_reversal/release UNKNOWN 25 (unreviewed affected=[] and no structured fix commit).
- uniqueness PASS 25 (absent from foundation.jsonl and canonical84 ledger).

## Per-row

| # | case_id | repo | verdict | mechanism | note |
|---|---|---|---|---|---|
| 0 | GHSA-WG93-HP69-VV5W | bludit/bludit | FALSE_POSITIVE | stored-xss-post-content | Candidate commits carry Co-Authored-By Claude (Sonnet/Opus 4.6) traile |
| 1 | GHSA-XW6C-FFPM-FGCM | bludit/bludit | FALSE_POSITIVE | csrf-plugin-theme-management | Candidate commits carry Co-Authored-By Claude (Sonnet/Opus 4.6) traile |
| 2 | GHSA-2Q9G-Q8JJ-FR53 | wolfSSL/wolfssl | FALSE_POSITIVE | packet-sniffer-aead-underflow | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 3 | GHSA-3CR6-HPF3-2HMG | wolfSSL/wolfssl | FALSE_POSITIVE | pkcs7-signed-attributes-stack-overflow | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 4 | GHSA-24VQ-QFC5-QRMJ | wolfSSL/wolfssl | FALSE_POSITIVE | session-deserialize-heap-overflow | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 5 | GHSA-86FV-Q5VX-MW5M | wolfSSL/wolfssl | FALSE_POSITIVE | crl-number-buffer-overflow | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 6 | GHSA-CWC7-2FMX-FFFQ | wolfSSL/wolfssl | FALSE_POSITIVE | tls12-cert-verify-before-cke | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 7 | GHSA-F5X4-GF23-WQM9 | wolfSSL/wolfssl | FALSE_POSITIVE | riscv-muldi3-timing-sidechannel | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 8 | GHSA-PGC5-R6CV-2825 | wolfSSL/wolfssl | FALSE_POSITIVE | ml-kem-dsa-fault-injection | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 9 | GHSA-WM74-PVWW-Q7H2 | wolfSSL/wolfssl | FALSE_POSITIVE | sp256-get-entry-timing | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 10 | GHSA-267H-VRW9-53P3 | wolfSSL/wolfssl | FALSE_POSITIVE | hpke-labeled-extract-ech-stack-overflow | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 11 | GHSA-6P64-86QJ-33GC | wolfSSL/wolfssl | FALSE_POSITIVE | add-to-chain-heap-corruption | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 12 | GHSA-CQX9-3CPJ-RRQP | wolfSSL/wolfssl | FALSE_POSITIVE | kcapi-ecc-import-heap-overflow | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 13 | GHSA-F377-557W-VJGV | wolfSSL/wolfssl | FALSE_POSITIVE | alpn-oob-read | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 14 | GHSA-G3XR-5F55-CF5G | wolfSSL/wolfssl | FALSE_POSITIVE | tls13-hrr-key-share | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 15 | GHSA-J2G5-52P7-MFPC | wolfSSL/wolfssl | FALSE_POSITIVE | tls13-ech-parsing-underflow | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 16 | GHSA-M9R6-9WMX-24JV | wolfSSL/wolfssl | FALSE_POSITIVE | pkcs7-envelopeddata-oob-read | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 17 | GHSA-6C79-F9M3-C7M5 | ixray-team/ixray-1.6-stcop | FALSE_POSITIVE | sensitive-info-disclosure | Candidates are authored by OpenHands (<openhands@all-hands.dev>) and a |
| 18 | GHSA-6P45-JV22-32GP | ocaml/ocaml | FALSE_POSITIVE | bigarray-reshape-int-overflow | Candidates (Co-Authored-By Claude) touch testsuite/tests/tool-ocamlc-d |
| 19 | GHSA-PWM7-WR54-2JXV | pfefferle/wordpress-webmention | FALSE_POSITIVE | ssrf-mf2-parse-authorpage | Candidates (Co-authored-by Copilot) touch class-comment-walker.php, cl |
| 20 | GHSA-WJF6-53J2-2F8C | pfefferle/wordpress-webmention | FALSE_POSITIVE | ssrf-tools-read | Candidates (Co-authored-by Copilot) touch class-comment-walker.php, cl |
| 21 | GHSA-98WW-GW4P-68M3 | wolfSSL/wolfssl | FALSE_POSITIVE | decodeobjectid-oob-write | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 22 | GHSA-F5H9-5Q52-QRX7 | wolfSSL/wolfssl | FALSE_POSITIVE | ecdsa-digest-size-check | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 23 | GHSA-MX4J-FJQX-F8QJ | wolfSSL/wolfssl | FALSE_POSITIVE | certfromx509-aki-overflow | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |
| 24 | GHSA-VGV9-MV66-MPC7 | wolfSSL/wolfssl | FALSE_POSITIVE | aria-gcm-nonce-reuse | Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) |

## Per-repo candidate disposition

- **bludit/bludit**: Candidate commits carry Co-Authored-By Claude (Sonnet/Opus 4.6) trailers and are security/bug FIXES for other issues: fbb08543 (IDOR auth check, SameSite cookie, page-erasure guard, navigation-label XSS escape), f91393d7 (thumbnail toggle), 6a6cdb02/d09327cb (API pagination), 270d59bb (search cache). None authors the stored-XSS or CSRF hunk.
- **wolfSSL/wolfssl**: Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) are async-crypto FIXES: a non-blocking X25519/ECC devId guard in src/internal.c and src/tls.c, and peer-review memory-leak fixes in tls.c/asn.c/curve25519.c. The three other recent commits are CI workflow changes. None introduces the named C mechanism (separate PRs name the actual fixes).
- **ixray-team/ixray-1.6-stcop**: Candidates are authored by OpenHands (<openhands@all-hands.dev>) and are backports of upstream OpenSSL CVE fixes (CVE-2015-3195, CVE-2016-0701, CVE-2016-2182, CVE-2022-0778) into src/3rd-party/crypto/openssl/. None introduces the info-disclosure mechanism (before 1.3).
- **ocaml/ocaml**: Candidates (Co-Authored-By Claude) touch testsuite/tests/tool-ocamlc-determinism and driver/compmisc.ml (type-ID/level counter reset for .cmo determinism). None touches otherlibs/bigarray (Bigarray.reshape).
- **pfefferle/wordpress-webmention**: Candidates (Co-authored-by Copilot) touch class-comment-walker.php, class-admin.php, class-settings-fields.php, Entity/class-item.php, Handler/class-wp.php. The SSRF sinks are includes/handler/class-mf2.php (MF2::parse_authorpage) and includes/class-tools.php (Tools::read); no candidate file matches.

## Evidence paths

- Slice: /home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj2-slice-3.jsonl (sha256 c9f6ffdb921c4c9fddeb6554e4474dff464e823e6d43b855f5946bc6408ff5b7)
- Contract: /home/hanqing/agents/ai-slop/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md (sha256 cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3)
- FWD spec: /home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/FWD-SPEC.md (sha256 672c45d1f98054a597ce12aa0879daa00b884d9207884e9a10e23c0fdc2d5750)
- Advisories: /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database (advisories/unreviewed/...)
- Repo clones (fetched this run): bludit__bludit, wolfSSL__wolfssl, ixray-team__ixray-1.6-stcop, ocaml__ocaml, pfefferle__wordpress-webmention
- Uniqueness: foundation.jsonl (168) and canonical84/ledger.jsonl (read-only).

## Claim boundary

Worker FALSE_POSITIVE is a proposal. Leader replay is required before anything counts. Canonical84 remains the only claim source.
