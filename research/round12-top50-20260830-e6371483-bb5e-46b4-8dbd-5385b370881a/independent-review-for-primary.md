# Round12 independent review — handoff for original auditors

This file is the second-pass result for the original `primary/wNNN.json`
authors. It does **not** mutate primaries, clones, the ledger, or the
campaign `report.md`.

Lane: `research/round12-top50-20260830-e6371483-bb5e-46b4-8dbd-5385b370881a/`
Protocol: `docs/AUDIT-PROTOCOL.md`
Collector: `python3 collect_independent_review.py` → `complete: true`

Machine records: `independent-review/wNNN.json` (one per worker).
Campaign summary: `independent-review/report.md`.

## What original auditors should do

Respond only to the 10 rows below. For each: **agree**, **rebut with
exact objects**, or **keep gap with a tighter remaining_gap**.

Do not reopen the 40 `CONFIRMED` rows unless you have a new object that
breaks a protocol gate.

## Histogram

| | Count |
|---|---:|
| Independent `CONFIRMED` (skip) | 40 |
| Independent `CORRECTION_REQUIRED` (respond) | 8 |
| Independent `EVIDENCE_GAP` (respond) | 2 |
| Independent `BLOCKED` | 0 |

Primary freeze: `NOT_AI` 39, `EVIDENCE_GAP` 5, `AI_ROOT_CAUSE` 3,
`FALSE_POSITIVE` 2, `AI_CODE_FLAWED` 1.

Confirmed TPs (no action): w004, w007, w008 `AI_ROOT_CAUSE`; w010
`AI_CODE_FLAWED`. Confirmed FP: w006.

---

## Priority 1 — class flip

### w009 — `FALSE_POSITIVE` → proposed `AI_ROOT_CAUSE`

- case: `GHSA-crfx-7r98-6r44` / CVE-2026-74878
- repo: `jahlives/openssl_encrypt`
- record: `independent-review/w009.json`

Reviewer claim: the in-memory TOTP limiter bypass is a real source-to-sink.
CVE.org is PUBLISHED. Primary used stable v1.3.6 (no `openssl_encrypt_server`)
to prove no affected release and missed public pip `1.4.0b3`–`1.4.0b8`.
Claimed fix `2749bc0949b34a5921a35fb4a3f1856fc51916de` still defaults to
`InMemoryBackend`. Proposed unpatched.

| field | primary | proposed |
|---|---|---|
| `verdict` | `FALSE_POSITIVE` | `AI_ROOT_CAUSE` |
| `introducer_sha` | null | `1b6f732232018609189c863a165a11aaa89db250` |
| `introducer_parent` | null | `c21f2a81b6bc6999c4067d1b2e4ea6d97448d037` |
| `direct_fix_sha` | null | null (`unpatched.confirmed=true`) |
| `ai_marker` | UNKNOWN (Claude on this SHA called non-causal) | PRESENT — Claude Code / Claude Sonnet 4.5 on this BIC |

Ask: is `FALSE_POSITIVE` still right, or was v1.3.6 the wrong affected
bound? If the limiter is real on public 1.4.0b wheels and the default
backend is still in-memory, this is a TP.

### w001 — `EVIDENCE_GAP` → proposed `NOT_AI`

- case: `CVE-2026-72764`
- repo: `n8n-io/n8n`
- record: `independent-review/w001.json`

Reviewer claim: bounded fetch recovered PR #10698 member
`feb31f61bbcf80bec25acf82c440cd97ed09aa54`; parent
`d0ec54c9bff74d908d36b02c2c08a06ba1762eda` lacks the runner package.
Mainline `27d83e0d918f5009101bb27bb09ea8c6374a11d9` is the squash.
Author/committer Valya Bullions, no AI marker. Direct fix unchanged
(`1cd2c5fb22a906058cc083c3af2d561ce7f4332d`).

Ask: is that member the atomic first-write, or is there a finer
pre-move public object?

### w033 — `EVIDENCE_GAP` → proposed `NOT_AI`

- case: `GHSA-69x9-xp2j-w8g8` / CVE-2025-54263
- repo: `magento/magento2`
- record: `independent-review/w033.json`

Reviewer claim: Login-as-Customer persist-without-revoke is complete in
the clone. BIC `dd15e184efe63d3fa5ebdf6d7906ef5874b5fdf2` (Ihor Vansach,
2015-12-12). Direct fix `485febbd60a1eb28da779024c6c27f856e28ed39`
(AC-15021). Packaging p-tags are APSB25-94 squashes, not the BIC.

Ask: is APSB25-94/CVE-2025-54263 actually this LAC path, or a different
hunk in the same bulletin?

### w046 — `EVIDENCE_GAP` → proposed `NOT_AI`

- case: `GHSA-5j4h-4f72-qpm6` / CVE-2026-21448
- repo: `bagisto/bagisto`
- record: `independent-review/w046.json`

Reviewer claim: blob:none gaps were fetchable. Real bug is Vue
client-side template injection of stored address fields (CWE-1336), not
Blade SSTI/RCE. BIC `371012a6beb4594e54c0f97bd0cc483796a8d8e8`
(prashant-webkul, 2018-08-24). Direct fix
`ce5b5d66ba163ff6ad652a32313788bfc2eca201` (PR #11063), not tag
`813e28551dd1d3207b9e275e6c2bd63f68f0f8b0`.

Ask: accept Vue CWE-1336 + this BIC/fix, or keep gap?

---

## Priority 2 — class stays `NOT_AI`, BIC is wrong

### w011 GitPython `CVE-2026-73622`

| field | primary | proposed |
|---|---|---|
| `introducer_sha` | `e6e23ed24b35c6154b4ee0da5ae51cd5688e5e67` | `43564d2e8f3b95f33e10a5c8cc2d75c0252d659a` |
| `introducer_parent` | `ba7c2a0f81f83c358ae256963da86f907ca7f13c` | `2ba39bd0f0b27152de78394d2a37f3f81016d848` |

Reviewer: `e6e23ed24b35` is Cygwin cygpath; HTTP URLs with a scheme are
not expanded on that path. Native `os.path.expandvars` first-write is
`43564d2e8f3b`. Direct fix unchanged `863417457a06`. Record:
`independent-review/w011.json`.

### w018 phpMyFAQ `CVE-2026-76213`

| field | primary | proposed |
|---|---|---|
| `introducer_sha` | `410208b90f1d01534812ac5203d3e8d9c7bd591f` | `2acabf760cd7e44ec589a3e207381e9a480dd64f` |
| `introducer_parent` | `06d644e5871f132ff50020490eb817be52076429` | `4e31e12a9c54afbfee03bc67c5300624c61013e7` |

Reviewer: `410208b90f1d` is the 2026-06-19 frontend copy into
`phpmyfaq/index.php`. Admin session-reset throttle was first written
2026-04-24 in Administration `AuthenticationController.php`. Direct fix
unchanged `59593a013862`. Record: `independent-review/w018.json`.

### w030 ConcreteCMS `GHSA-jr5g-qv3g-rxxx`

| field | primary | proposed |
|---|---|---|
| `introducer_sha` | `f0d6a2f9cc31c5bf8e544ca0bfec7866ce981f5d` | `6ac5687f09b766158e43932ebbf5367d5e787792` |
| `introducer_parent` | `151f8448a9ac03e4b3a5dcaeef919f974c646f3e` | `f955acab4deaa9d088ddeafe4076a2a8b08d0e93` |

Reviewer: `f0d6a2f9cc31` is a 2012 class-override **move**. Parent already
has CSRF-less `do_update`. First-write is 2009 git-svn
`6ac5687f09b7` (`update($pkgHandle)` in `dashboard/install.php`). Direct
fix unchanged `f22b9dff5945`. Record: `independent-review/w030.json`.

### w031 Magento `CVE-2025-43585`

| field | primary | proposed |
|---|---|---|
| `introducer_sha` | `7f25fa6a5ec0639cbb2ac63d82fc73f4cd397b59` | `14cdb650cb58ba620baeb3443331194c39b9a845` |
| `introducer_parent` | `1d941ba7a09a964569f5a14c4590c219b16b7f3c` | `9a0fbce28ec1c4baccb52623d47b992d48ee88ee` |

Reviewer: parent of `7f25fa6a5ec0` already had anonymous
`PUT /V1/guest-carts/:cartId/order`. That SHA is a later payment-information
wrapper. First anonymous guest-carts order route is `14cdb650cb58`
(Anup Dugar, 2015). Direct fix packaging SHA unchanged
`9bf2c06ea8c9`. Record: `independent-review/w031.json`.

---

## Priority 3 — both sides still `EVIDENCE_GAP`

Keep unless you have a first-party CVE-to-hunk map.

### w034 Magento `CVE-2025-49550`

Record: `independent-review/w034.json`. Independent agrees with primary
gap. Remaining gap: Adobe/Magento isolated patch, VULN/LYNX id, or
advisory note that names **this** CVE's sink. Do not promote LYNX-839
GraphQL deletions (2.4.8-only, no UI:R) or other APSB25-50 hunks.

### w035 Magento `CVE-2025-54266`

Record: `independent-review/w035.json`. Independent agrees with primary
gap. Remaining gap: map CVE-2025-54266 as distinct from CVE-2025-54264
to one stored field + fix hunk. Packaging p-tags are squash aggregates.

---

## Skip list (40 `CONFIRMED`)

w000, w002, w003, w004, w005, w006, w007, w008, w010, w012, w013, w014,
w015, w016, w017, w019, w020, w021, w022, w023, w024, w025, w026, w027,
w028, w029, w032, w036, w037, w038, w039, w040, w041, w042, w043, w044,
w045, w047, w048, w049.

Full 40-hex SHAs and protocol checks are in
`independent-review/wNNN.json`. Do not copy conclusions from
`independent-review/report.md` back into a primary without checking
the cited objects.
