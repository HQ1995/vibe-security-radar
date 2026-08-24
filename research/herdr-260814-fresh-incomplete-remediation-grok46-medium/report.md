# Fresh incomplete-remediation screen (2025-2026 GHSA)

Verdict first: **0 PASS**. Screened **27** (cap 30, not padded). Fully closed **10** (cap 10). AI prior-attempt hits **0**. Packet delta **0**. Canonical84 stays **84**. Publication and more-than-200 remain **HOLD**. Worker PASS is a proposal only and is not issued.

This lane requires an AI-authored commit that explicitly attempted a security guard, a vulnerable release that contained that attempt, and a later exact closer of the same residual bypass. Ordinary vulnerable feature origins are out of lane.

## Sources (read-only)

- Canonical84 ledger sha256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`
- Canonical84 summary sha256 `6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a`
- Canonical84 manifest sha256 `a4b930757e97a3ecaa76fde28a0ee37ebd851717bc0eb214d42fb6292fc00bec`
- Advisory cache `/home/hanqing/.cache/cve-analyzer/advisory-database` git HEAD `39d8887723797efc1804585dd06585c9fd751226` (2026-07-23). Used read-only.
- Repo clones under `/home/hanqing/.cache/cve-analyzer/repos` used read-only. No clone was fetched into owned `work/`.
- Freeze sha256 `f56081cfae7152530536ebe8e9ddd3a310a591e4fae8da348ca4058e1b8a30be`

## Screen

Local github-reviewed 2025-2026 JSON: 12074 files. Strong incomplete-remediation language: 386. Not in canonical84: 377. Freeze: unique-repo rows whose summary matches incomplete fix for/of a CVE or GHSA, excluding canonical84 identities, canonical84 incomplete-remediation repositories, and previously assigned incomplete-remediation packet identities. Resulting freeze: 27. Did not pad to 30.

Deleted-line blame of named closers found no AI-marked security-attempt commit. Official prior-advisory fix SHAs were then loaded from the same cache. None of those resolved prior SHAs carry an explicit AI trailer.

## Fully closed 10 (REJECT)

All ten have identity PASS, uniqueness PASS (absent from canonical84), topology PASS (prior is an ancestor of closer), ai_hunk FAIL, but_for FAIL, and remediation_patch_delta FAIL. The required original_vulnerability block records the prior public ID and human prior-attempt SHA. Introducing origin SHAs are null, not invented.

| ID | Repository | Prior (human) | Closer | Release gate |
|---|---|---|---|---|
| GHSA-8GC5-J5RX-235R | naturalintelligence/fast-xml-parser | `910dae5be2de` | `bd26122c838e` | PASS |
| GHSA-4MX9-3C2H-HWHG | siyuan-note/siyuan | `d68bd5a79391` | `d01d561875d4` | PASS |
| GHSA-72H5-39R7-R26J | wwbn/avideo | `ade348ed6d28` | `3ae02fa24093` | PASS |
| GHSA-7GVF-3W72-P2PG | pyload/pyload | `b76b6d4ee5e3` | `33c55da08432` | UNKNOWN |
| GHSA-R7WM-3CXJ-WFF9 | fasterxml/jackson-core | `b0c428e6f993` | `4cdd529749da` | PASS |
| GHSA-2W79-R9G8-WMCR | openclaw/openclaw | `1d8968c8a821` | `9abcfdadf591` | PASS |
| GHSA-3VGW-585J-4M45 | blacklanternsecurity/bbot | `6325f2f4f8f6` | `4fb38fd6e77c` | UNKNOWN |
| GHSA-PH8X-4JFV-V9V8 | dagu-org/dagu | `e2ed589105d7` | `7d07fda8f9de` | PASS |
| GHSA-XJVC-PW2R-6878 | flarum/framework | `1761660c98ea` | `2d90a1f19f0e` | UNKNOWN |
| GHSA-C36X-H252-G9X2 | openbao/openbao | `c0495646b41c` | `b20b999dd404` | UNKNOWN |

### GHSA-8GC5-J5RX-235R REJECT

Numeric/HTML entity expansion residual after human entity-limit security patch 910dae5be2de.

Original vulnerability: `CVE-2026-26278` / `GHSA-JMR7-XGP7-CMFJ`. Prior attempt `910dae5be2de2955e968558fadf6e8f74f117a77` by amit kumar gupta <amitgupta.gwl@gmail.com>. AI marker: none. Advisory sha256 `d101b809a991942eb5ffd173d7c8a8198235403780de00cc355932c28db71b94`.

Git tags v5.3.6-v5.4.1 contain the prior attempt and not closer bd26122c838e. Closer first appears in tags starting v5.5.6.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release PASS; uniqueness PASS; patch-delta FAIL.

Counterevidence: Prior attempt 910dae5be2de author amit kumar gupta <amitgupta.gwl@gmail.com> has no AI trailer. Deleted-line blame of the closer did not hit an AI-marked security-attempt commit. Closer extends entity-expansion checks to lastEntities and HTML entities on the same parser boundary.

### GHSA-4MX9-3C2H-HWHG REJECT

SanitizeSVG data:text/xml bypass after human GHSA-6865 lock commit d68bd5a79391.

Original vulnerability: `CVE-2026-29183` / `GHSA-6865-QJCF-286F`. Prior attempt `d68bd5a79391742b3cb2e14d892bdd9997064927` by Daniel <845765@qq.com>. AI marker: none. Advisory sha256 `399f4cbc0b1e31b7eb408e02aa25378ed81080bb313a93007b55f61daabd0f34`.

Git tags v3.5.9, v3.5.10, v3.6.0 contain the prior attempt and not closer d01d561875d4. Closer is in v3.6.1+.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release PASS; uniqueness PASS; patch-delta FAIL.

Counterevidence: Prior attempt d68bd5a79391 author Daniel <845765@qq.com> has no AI trailer. Deleted-line blame of the closer did not hit an AI-marked security-attempt commit. Closer is a first-party lock commit naming this GHSA on the same SVG sanitizer surface.

### GHSA-72H5-39R7-R26J REJECT

Markdown javascript: URI residual after human ParsedownSafeWithLinks/safe-mode attempt ade348ed6d28.

Original vulnerability: `CVE-2026-27568` / `GHSA-RCQW-6466-3MV7`. Prior attempt `ade348ed6d28b3797162c3d9e98054fb09ec51d7` by Daniel Neto <me@danielneto.com>. AI marker: none. Advisory sha256 `37c2623232389118d9aaf345236cc2a99bd9caf04dbf6a74f5cdaa30a3f6f851`.

Git tags 21.0-26.0 contain the prior attempt and not closer 3ae02fa24093. Closer is in tag 29.0.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release PASS; uniqueness PASS; patch-delta FAIL.

Counterevidence: Prior attempt ade348ed6d28 author Daniel Neto <me@danielneto.com> has no AI trailer. Deleted-line blame of the closer did not hit an AI-marked security-attempt commit. Closer sanitizes inline link hrefs on the same markdown-to-HTML path.

### GHSA-7GVF-3W72-P2PG REJECT

SSRF redirect residual after human GHSA-m74m fix b76b6d4ee5e3.

Original vulnerability: `CVE-2026-33992` / `GHSA-M74M-F7CR-432X`. Prior attempt `b76b6d4ee5e32d2118d26afdee1d0a9e57d4bfe8` by GammaC0de <gammac0de@users.noreply.github.com>. AI marker: none. Advisory sha256 `fbed4ff06c45bae17307e101f3a811a5e4f4611c19805b5f44dc8b24527cc210`.

Local clone has no git tags containing prior or closer. GitHub Releases were not queried.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release UNKNOWN; uniqueness PASS; patch-delta FAIL.

Counterevidence: Prior attempt b76b6d4ee5e3 author GammaC0de <gammac0de@users.noreply.github.com> has no AI trailer. Deleted-line blame of the closer did not hit an AI-marked security-attempt commit. Closer commit subject names this GHSA; prior subject names GHSA-m74m on the same downloader SSRF filter.

### GHSA-R7WM-3CXJ-WFF9 REJECT

Async parser integer-path maxNumberLength residual after human #1555 commit b0c428e6f993.

Original vulnerability: `GHSA-72HV-8253-57QQ` / `GHSA-72HV-8253-57QQ`. Prior attempt `b0c428e6f993e1b5ece5c1c3cb2523e887cd52cf` by PJ Fanning <pjfanning@users.noreply.github.com>. AI marker: none. Advisory sha256 `3aca35a2d399f6d3d3844a84de9cdd2e87c2c88ff0f1e3cca595eb7bf310763e`.

Tags jackson-core-2.18.6 and 2.18.7 contain the prior attempt and not closer 4cdd529749da. Closer is in jackson-core-2.18.8+.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release PASS; uniqueness PASS; patch-delta FAIL.

Counterevidence: Prior attempt b0c428e6f993 author PJ Fanning <pjfanning@users.noreply.github.com> has no AI trailer. Deleted-line blame of the closer did not hit an AI-marked security-attempt commit. Closer applies the number-length validator on the streaming integer path of the same async parser.

### GHSA-2W79-R9G8-WMCR REJECT

Oversized pre-start WebSocket frame residual after human voice-call harden 1d8968c8a821.

Original vulnerability: `CVE-2026-32062` / `GHSA-MFG5-7Q5G-F37J`. Prior attempt `1d8968c8a821ff1a05c294a1846b3bcb6f343794` by Peter Steinberger <steipete@gmail.com>. AI marker: none. Advisory sha256 `f4bb4846ded8d8cfaab170410b0b24d28ba1df1505df36d5bba5f49e6824c488`.

Git tags including v2026.2.22-v2026.2.25 contain the prior attempt and not closer 9abcfdadf591.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release PASS; uniqueness PASS; patch-delta FAIL.

Counterevidence: Prior attempt 1d8968c8a821 author Peter Steinberger <steipete@gmail.com> has no AI trailer. Deleted-line blame of the closer did not hit an AI-marked security-attempt commit. Closer rejects oversized pre-start media frames on the same voice-call WebSocket path.

### GHSA-3VGW-585J-4M45 REJECT

Zip-slip residual after human unarchive dest-dir abort 6325f2f4f8f6.

Original vulnerability: `CVE-2025-10284` / `GHSA-FHW8-8V9P-7JP7`. Prior attempt `6325f2f4f8f6f4545703e4c9b8004e69f71bec82` by TheTechromancer <thetechromancer@protonmail.com>. AI marker: none. Advisory sha256 `754e0931eb2dce08c9062e5233c743b5b23f2819599eb7d6c7d374e430f05f4c`.

Multiple v3.0.0.*rc tags contain the prior attempt and not closer 4fb38fd6e77c. Closer is in v3.0.0.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal UNKNOWN; release UNKNOWN; uniqueness PASS; patch-delta FAIL.

Counterevidence: Prior attempt 6325f2f4f8f6 author TheTechromancer <thetechromancer@protonmail.com> has no AI trailer. Deleted-line blame of the closer did not hit an AI-marked security-attempt commit. Closer hardens unarchive extraction; rc-only residual tags are not treated as a countable public artifact.

### GHSA-PH8X-4JFV-V9V8 REJECT

Encoded-slash DAG path traversal residual after human create-API traversal fix e2ed589105d7.

Original vulnerability: `CVE-2026-27598` / `GHSA-6V48-FCQ6-FF23`. Prior attempt `e2ed589105d79273e4e6ac8eb31525f765bb3ce4` by Yota Hamada <yohamta@gmail.com>. AI marker: none. Advisory sha256 `8914bc5f8f275b4cbddb40f2d788851249851c8ce9dfd78e958294ac7880290e`.

Tags v2.0.0 and v2.0.1 contain the prior attempt and not closer 7d07fda8f9de. Closer is in v2.10.0+.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release PASS; uniqueness PASS; patch-delta FAIL.

Counterevidence: Prior attempt e2ed589105d7 author Yota Hamada <yohamta@gmail.com> has no AI trailer. Deleted-line blame of the closer did not hit an AI-marked security-attempt commit. Closer rejects DAG file traversal via encoded slashes on the same API path boundary.

### GHSA-XJVC-PW2R-6878 REJECT

LESS feature residual after human dangerous-LESS disallow 1761660c98ea.

Original vulnerability: `CVE-2023-27577` / `GHSA-VHM8-WWRF-3GCW`. Prior attempt `1761660c98ea5a3e9665fb8e6041d1f2ee62a444` by Sami Mazouz <sychocouldy@gmail.com>. AI marker: none. Advisory sha256 `5ecf69360c42b1df1ecb9cedef0a77349dbf0541ac146b4f0a354724ed268fb3`.

Tags v1.7.0+ contain the prior attempt. Closer 2d90a1f19f0e is a merge-from-fork with no containing tags in the local clone.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal UNKNOWN; release UNKNOWN; uniqueness PASS; patch-delta FAIL.

Counterevidence: Prior attempt 1761660c98ea author Sami Mazouz <sychocouldy@gmail.com> has no AI trailer. Deleted-line blame of the closer did not hit an AI-marked security-attempt commit. Closer is a merge commit from a fork; hunk identity was not guessed.

### GHSA-C36X-H252-G9X2 REJECT

Cross-namespace lease lookup residual after human endpoint removal c0495646b41c.

Original vulnerability: `CVE-2026-45808` / `GHSA-V8V8-CM84-M686`. Prior attempt `c0495646b41cea0e3f5a1030132e9cf5c2375b5c` by Alexander Scheel <alex.scheel@control-plane.io>. AI marker: none. Advisory sha256 `d8e7944f1a50255d50d77d52eb142b374e14fc628ee281c8842e7d6df5545322`.

Tags containing the prior attempt also contain the closer in this clone; no residual tag interval was proved.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release UNKNOWN; uniqueness PASS; patch-delta FAIL.

Counterevidence: Prior attempt c0495646b41c author Alexander Scheel <alex.scheel@control-plane.io> has no AI trailer. Deleted-line blame of the closer did not hit an AI-marked security-attempt commit. Closer fixes cross-namespace lease lookup routing after the prior endpoint-removal attempt.

## Screened remainder (not fully closed)

UNKNOWN is preserved where prior commit refs, clones, residual releases, or a distinct prior-versus-closer SHA are missing. BLOCKED is used only for missing local clones that this packet did not fetch. Human prior attempts beyond the 10-row full-close cap are NOT_SELECTED; they are not converted into extra causal REJECT rows.

| n | ID | Repository | Verdict | Reason |
|---|---|---|---|---|
| 1 | GHSA-JR45-52CW-69H5 | nl-portal/nl-portal-backend-libraries | BLOCKED | missing_local_clone_no_fetch_in_this_packet |
| 2 | GHSA-F48W-9M4C-M7F5 | withastro/astro | UNKNOWN | prior_advisory_has_no_commit_ref |
| 3 | GHSA-QCM7-3VPR-HJ5H | adonisjs/bodyparser | UNKNOWN | prior_sha_equals_closer_sha |
| 4 | GHSA-3775-99MW-8RP4 | argoproj/argo-workflows/v3 | UNKNOWN | prior_advisory_has_no_commit_ref |
| 6 | GHSA-CG7W-RG45-PC59 | pydantic/pydantic-ai | UNKNOWN | prior_advisory_has_no_commit_ref |
| 10 | GHSA-8Q5W-MMXF-48JG | siyuan-note/siyuan/kernel | UNKNOWN | prior_sha_equals_closer_sha |
| 11 | GHSA-J3FJ-QPPJ-FMMC | axllent/mailpit | UNKNOWN | missing_prior_or_closer_sha |
| 12 | GHSA-J6FM-9RFM-J5HX | froxlor/froxlor | UNKNOWN | prior_sha_equals_closer_sha |
| 13 | GHSA-PJWM-PJ3P-43MV | axios/axios | NOT_SELECTED | human_prior_observed_over_full_close_cap |
| 15 | GHSA-X6QJ-4H56-5RJ5 | nuxt/nuxt | UNKNOWN | prior_advisory_has_no_commit_ref |
| 18 | GHSA-45H5-66JX-R2WF | mjmlio/mjml | NOT_SELECTED | human_prior_observed_over_full_close_cap |
| 19 | GHSA-6QVR-WJMV-V8MM | koel/koel | BLOCKED | missing_local_clone_no_fetch_in_this_packet |
| 20 | GHSA-7V6W-C3F4-9WPQ | openremote/openremote | BLOCKED | missing_local_clone_no_fetch_in_this_packet |
| 21 | GHSA-FXJ4-P9XP-37V5 | hapifhir/org.hl7.fhir.core | BLOCKED | missing_local_clone_no_fetch_in_this_packet |
| 22 | GHSA-HCJJ-CHVW-FMW9 | admidio/admidio | UNKNOWN | prior_sha_equals_closer_sha |
| 23 | GHSA-JG2M-9X48-3GVJ | apache/camel | NOT_SELECTED | human_prior_observed_over_full_close_cap |
| 27 | GHSA-VG6X-6PG9-6QWG | arcadedata/arcadedb | BLOCKED | missing_local_clone_no_fetch_in_this_packet |

## Count boundary

Screened 27 = fully closed 10 + not fully closed 17. No PASS proposals. Canonical ledger was not edited. Fetched clones under owned work/: none.

