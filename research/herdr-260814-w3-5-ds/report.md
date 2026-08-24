# unr-adj3-slice-5 adjudication — verdict-first evidence summary

## Verdict

Proposed admissions: **0 / 25** (`CONFIRM`/`AI_DIRECT_ROOT`/`AI_NEW_SURFACE_CONTRIBUTOR` = 0).
Every row is **FALSE_POSITIVE (class `no_ai_origin`)**: each candidate AI commit's diff authors an unrelated hunk and does not create the advisory's named mechanism.

- 25/25 unreviewed advisory objects are `github_reviewed=false` with `affected=[]`; the `details` field names the mechanism and the references name the repository, but there is no first-party reviewed identity, so `identity_gate` = UNKNOWN (never PASS).
- 13 unique candidate commits fetched by git smart-HTTP into `/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>`; parent→child diffs read. All 13 carry an explicit AI marker (Claude/Copilot/Copilot Autofix co-author trailer).
- 13/13 diffs touch files disjoint from the vulnerable file named in each advisory, so `ai_hunk_gate` and `but_for_gate` are FAIL (affirmative non-authorship, not missing evidence).
- `topology_gate`, `fix_reversal_gate`, `release_gate`, `uniqueness_gate` stay UNKNOWN after causal exclusion.

## Frozen evidence and method

- Contract: `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md`, SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
- Spec: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/FWD-SPEC.md`, SHA-256 `672c45d1f98054a597ce12aa0879daa00b884d9207884e9a10e23c0fdc2d5750`.
- Slice: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj3-slice-5.jsonl`, SHA-256 `0e4dbf6c22923e6f4d8814a7c9336d0fe6a4ed9b89556cc1b729f16184c0bc58` (25 rows).
- Advisory database: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database` at `origin/main` = `8b901fa43d0e3d09e9bece095afb760dd9dff6e8` (2026-08-15 `Publish Advisories`); every advisory blob read from that exact tree.
- Commit pool: `git --filter=blob:none` blobless bare clones; new repos (maccms10, amule) initialized and fetched with `--deepen=80` via git smart-HTTP. No GitHub API, no `git blame`, no SZZ.

## Row-by-row finding

| GHSA | CVE | Repository | Named mechanism | Verdict |
|---|---|---|---|---|
| GHSA-XG8J-6M35-M6WR | CVE-2026-61450 | getgrav/grav | Twig sandbox bypass lets a page author exfiltrate configuration secrets | FALSE_POSITIVE (no_ai_origin) |
| GHSA-Q4J8-3JF6-PJVP | CVE-2026-61454 | getgrav/grav | Admin2 SPA embeds window.__GRAV_CONFIG__ global exposing secrets | FALSE_POSITIVE (no_ai_origin) |
| GHSA-R7C2-XCMM-M4PR | CVE-2026-15516 | magicblack/maccms10 | MacCMS install module step5 (application/install/controller/Index.php) authorization bypass | FALSE_POSITIVE (no_ai_origin) |
| GHSA-7R93-5V7X-H4C9 | CVE-2026-51105 | amule-project/amule | Buffer overflow in the OP_SERVERMESSAGE handler (DoS) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-MPQ7-Q5X9-RF83 | CVE-2026-58655 | getgrav/grav | Flex Objects stored server-side template injection in dynamic titles | FALSE_POSITIVE (no_ai_origin) |
| GHSA-373M-P57P-8665 | CVE-2026-61453 | getgrav/grav | XSS blueprint validator runs before Twig processing (twig_content bypass) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-7WCR-M737-MCHR | CVE-2026-61457 | getgrav/grav | API media upload extension bypass (validateFileExtension only final extension) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-R9R9-WG76-6QMQ | CVE-2026-61451 | getgrav/grav | API forgot-password admin_base_url origin not validated | FALSE_POSITIVE (no_ai_origin) |
| GHSA-RRR3-RPGW-867X | CVE-2026-61452 | getgrav/grav | API JWT access tokens lack jti so cannot be revoked | FALSE_POSITIVE (no_ai_origin) |
| GHSA-V626-428R-43P8 | CVE-2026-61449 | getgrav/grav | ZipArchiver/GPM decompression-bomb size-cap bypass | FALSE_POSITIVE (no_ai_origin) |
| GHSA-M8GP-46R6-RC3F | CVE-2026-61873 | getgrav/grav | Form process.save.filename arbitrary file write after Twig processing | FALSE_POSITIVE (no_ai_origin) |
| GHSA-4M9M-RMH9-2PGF | CVE-2026-62232 | getgrav/grav | login regenerate2FASecret checks existence not authorization (2FA bypass) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-5MV9-76R9-RPRQ | CVE-2026-62230 | getgrav/grav | Default .htaccess sensitive-file rules lack [NC] flag (case-sensitive bypass) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-Q7W3-H9X7-95X7 | CVE-2026-62231 | getgrav/grav | API key scopes created but never enforced by ApiKeyAuthenticator | FALSE_POSITIVE (no_ai_origin) |
| GHSA-6GQG-9QJP-56JM | CVE-2026-62237 | getgrav/grav | ReDoS in regex_replace filter/function allowlisted in Twig sandbox | FALSE_POSITIVE (no_ai_origin) |
| GHSA-CX27-6J8X-H4H6 | CVE-2026-62386 | getgrav/grav | API accepts JWT via ?token= query parameter on every route | FALSE_POSITIVE (no_ai_origin) |
| GHSA-F4C6-8FCQ-J58X | CVE-2026-62236 | getgrav/grav | login.regenerate2FASecret CSRF on frontend task | FALSE_POSITIVE (no_ai_origin) |
| GHSA-GV8P-326F-P8GJ | CVE-2026-62235 | getgrav/grav | Flex-Objects admin-next REST broken access control (api.access CRUD) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-H4X5-FMW9-97F9 | CVE-2026-62387 | getgrav/grav | API default CORS Access-Control-Allow-Origin: * on authenticated endpoints | FALSE_POSITIVE (no_ai_origin) |
| GHSA-QRM9-PPGH-QWM9 | CVE-2026-62233 | getgrav/grav | API createApiKey/generate2fa/disable2fa missing super-admin check | FALSE_POSITIVE (no_ai_origin) |
| GHSA-RV94-VQVR-WJJH | CVE-2026-62234 | getgrav/grav | Webhook dispatch allows file://, dict://, gopher:// cURL protocols (SSRF) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-4P4X-7XPG-55GW | CVE-2026-57852 | getgrav/grav | scheduler-webhook short-circuit auth bypass triggers scheduled jobs | FALSE_POSITIVE (no_ai_origin) |
| GHSA-3Q93-H5P2-5MX8 | CVE-2026-65008 | getgrav/grav | Blueprint::dynamicData call_user_func on Class::method string (RCE) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-6M96-62FV-F2WH | CVE-2026-65007 | getgrav/grav | API key generation/revocation bypasses account-management ACL | FALSE_POSITIVE (no_ai_origin) |
| GHSA-R7WW-MW2X-MJ59 | CVE-2026-64628 | getgrav/grav | shortcode-core stored XSS (XSS scan only matches literal angle brackets) | FALSE_POSITIVE (no_ai_origin) |

## Why each candidate set is not the origin

- **getgrav/grav (23 rows)** — the single shared candidate set is: major-version upgrade gating (`2c517b01`, GPM/Upgrade/Installer), a media-config blueprint move (`e3ff054d`), and `Twig3CompatibilityTransformer` regex edits (`2dcf9179`, `bf7dd2e6`, `50865058`; Twig 2/3 template-syntax compatibility, including the JIT-stack-exhaustion fix). The 23 advisories target the Twig *content* sandbox, Admin2/API/Form/Login/Flex-Objects plugins, ZipArchiver, webhook dispatch, scheduler-webhook, `Blueprint::dynamicData`, and shortcode-core — none of which lives in the files the candidates edit. The two Twig-adjacent CVEs (CVE-2026-61450 sandbox bypass, CVE-2026-62237 `regex_replace` ReDoS) are in the Twig content-sandbox allowlist/filter code, not the `Twig3CompatibilityTransformer`.
- **magicblack/maccms10 (1 row, CVE-2026-15516)** — install-module `step5` authorization bypass in `application/install/controller/Index.php`. The five candidates are an AI-SEO batch feature (admin views), AI-SEO i18n keys, plugin-icon swaps, and a new AI Content Assistant addon; none touches the install controller.
- **amule-project/amule (1 row, CVE-2026-51105)** — buffer overflow in the `OP_SERVERMESSAGE` (eDonkey server-message) handler. The three candidates are Copilot Autofix integer/unsigned-expression fixes in `src/kademlia/net/PacketTracking.cpp` (Kademlia flood tracking) and `src/EncryptedStreamSocket.cpp` (encryption negotiation), not the server-message handler.

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

Negative diff reading proves no AI origin for these 25 rows; it is not evidence of global semantic uniqueness. No `PASS` is proposed, so the leader has nothing to replay beyond confirming the no_ai_origin exclusions.
