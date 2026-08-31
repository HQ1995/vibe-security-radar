# Independent review of round12 top-50 primaries

Second pass over the 50 frozen Round12 primaries in
`research/round12-top50-20260830-e6371483-bb5e-46b4-8dbd-5385b370881a/report.md`.
Protocol: `docs/AUDIT-PROTOCOL.md`. Review findings only; this wave did not
mutate primaries, the ledger, clones, roster, or the website.

## Acceptance

`python3 research/round12-top50-20260830-e6371483-bb5e-46b4-8dbd-5385b370881a/collect_independent_review.py`
exited 0 with `complete: true`.

| Check | Result |
|---|---|
| Assigned workers | 50 unique |
| Physical `wXXX.json` | 50 |
| Missing / extra / duplicate | 0 / 0 / 0 |
| Schema, identity, protocol_checks | all pass |
| Bundle + primary SHA-256 vs assignment freeze | match (`hash_ok`) |
| `BLOCKED` | 0 |
| Ledger sha256 live | `59699d7ab3e102cd08907aee1135bc6f0097cdbbe0db55a685571cce9d28fbc2` |

These results are not canonical corrections until a separate reconciliation
checks each proposed field against the cited objects.

## Review-verdict histogram

| Verdict | Count |
|---|---:|
| `CONFIRMED` | 40 |
| `CORRECTION_REQUIRED` | 8 |
| `EVIDENCE_GAP` | 2 |
| `BLOCKED` | 0 |

Primary snapshot at freeze was `NOT_AI` 39, `EVIDENCE_GAP` 5, `AI_ROOT_CAUSE` 3,
`FALSE_POSITIVE` 2, `AI_CODE_FLAWED` 1.

## Confirmed TPs (4)

Original TPs all held:

| worker | primary | review | repo | case |
|---|---|---|---|---|
| w004 | `AI_ROOT_CAUSE` | `CONFIRMED` | jahlives/openssl_encrypt | GHSA-4hf6-j482-f379 |
| w007 | `AI_ROOT_CAUSE` | `CONFIRMED` | jahlives/openssl_encrypt | GHSA-7qj7-jv8m-rfjw |
| w008 | `AI_ROOT_CAUSE` | `CONFIRMED` | jahlives/openssl_encrypt | GHSA-5cp4-g2w4-gm8p |
| w010 | `AI_CODE_FLAWED` | `CONFIRMED` | gitpython-developers/gitpython | CVE-2026-78678 |

w006 `FALSE_POSITIVE` (GHSA-hmf7-54mh-cvp4) also `CONFIRMED`.

## Verdict flips proposed (4)

| worker | primary | proposed | repo | case |
|---|---|---|---|---|
| w001 | `EVIDENCE_GAP` | `NOT_AI` | n8n-io/n8n | CVE-2026-72764 |
| w009 | `FALSE_POSITIVE` | `AI_ROOT_CAUSE` | jahlives/openssl_encrypt | GHSA-crfx-7r98-6r44 |
| w033 | `EVIDENCE_GAP` | `NOT_AI` | magento/magento2 | GHSA-69x9-xp2j-w8g8 |
| w046 | `EVIDENCE_GAP` | `NOT_AI` | bagisto/bagisto | GHSA-5j4h-4f72-qpm6 |

If those four land, the 50-case class histogram would become
`NOT_AI` 42, `AI_ROOT_CAUSE` 4, `EVIDENCE_GAP` 2, `FALSE_POSITIVE` 1,
`AI_CODE_FLAWED` 1.

### w009 — only proposed new TP

Primary treated the in-memory TOTP limiter as nonexistent because stable
v1.3.6 has no `openssl_encrypt_server`. Reviewer: CVE-2026-74878 is
PUBLISHED; pip 1.4.0b3–1.4.0b8 ship `TOTPRateLimiter`; claimed fix
`2749bc0949b34a5921a35fb4a3f1856fc51916de` still defaults to
`InMemoryBackend`; BIC `1b6f732232018609189c863a165a11aaa89db250` has
Claude Code / Claude Sonnet 4.5 co-author trailers. Proposed unpatched
`AI_ROOT_CAUSE`.

### w001, w033, w046 — gaps closed as human

- **w001**: bounded fetch recovered PR #10698 member
  `feb31f61bbcf80bec25acf82c440cd97ed09aa54` (Valya Bullions). Mainline
  `27d83e0d918f` is the squash aggregate.
- **w033**: Login-as-Customer persist-without-revoke is present;
  BIC `dd15e184efe63d3fa5ebdf6d7906ef5874b5fdf2` (Ihor Vansach, 2015);
  direct fix `485febbd60a1eb28da779024c6c27f856e28ed39`. Packaging
  squash is not the BIC.
- **w046**: Vue client-side template injection of stored address fields,
  not Blade SSTI/RCE. BIC `371012a6beb4594e54c0f97bd0cc483796a8d8e8`
  (prashant-webkul, 2018). Direct fix `ce5b5d66ba163ff6ad652a32313788bfc2eca201`.

## Remaining `EVIDENCE_GAP` (2)

Both Adobe Magento APSB bundles with no CVE-to-hunk map:

- **w034** `magento/magento2` CVE-2025-49550 — CWE-863, PR:N, UI:R is real
  and published, but APSB25-50 contains several authorization hunks and
  no first-party binding names this CVE's sink. LYNX-839 GraphQL
  deletions fail the vendor affected-range / UI:R vector.
- **w035** `magento/magento2` CVE-2025-54266 — stored XSS is real and
  published, but APSB25-94 also ships CVE-2025-54264. Packaging tags are
  squash aggregates. No isolated patch names this CVE's field/sink.

## `CORRECTION_REQUIRED` with class unchanged (4)

BIC / origin replacements; proposed class stays `NOT_AI`.

| worker | repo | case | what changes |
|---|---|---|---|
| w011 | gitpython-developers/gitpython | CVE-2026-73622 | BIC `e6e23ed24b35` → `43564d2e8f3b` (native `os.path.expandvars`, not Cygwin cygpath) |
| w018 | thorsten/phpmyfaq | CVE-2026-76213 | BIC `410208b90f1d` (frontend copy) → `2acabf760cd7` (admin first-write) |
| w030 | concretecms/concretecms | GHSA-jr5g-qv3g-rxxx | BIC `f0d6a2f9cc31` (2012 move) → `6ac5687f09b7` (2009 git-svn first-write) |
| w031 | magento/magento2 | CVE-2025-43585 | BIC `7f25fa6a5ec0` (payment-info wrapper) → `14cdb650cb58` (anonymous guest-carts order route) |

## Confirmed `NOT_AI` (35 of 39 primary NOT_AI)

The remaining 35 `NOT_AI` primaries are `CONFIRMED` as named-human BIC
authorship. Together with the four BIC-only corrections above, that covers
all 39 original `NOT_AI` rows. w000/w002/w003/w005 n8n, w012/w014 ech0,
w013/w015/w016 GitPython, w017/w019–w021 phpMyFAQ, w022/w025 OliveTin,
w023/w024 xserver, w026–w029 ConcreteCMS, w032 Magento, w036/w037 Tor,
w038 Krayin, w039–w042/w044 MessagePack-CSharp, w043/w045 Bagisto, w047 FRR,
w048/w049 Spring Security.
