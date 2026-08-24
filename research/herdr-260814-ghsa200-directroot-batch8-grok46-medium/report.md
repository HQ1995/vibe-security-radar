# Direct-root mining batch 8 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical73 and directroot batches 1-7. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 590
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 210+30+590+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical73 strict identities plus batch1-7 `selected-30.jsonl`/`cases.jsonl`, including in-progress batch3/4/7. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS would still be a proposal.

## Cases

### 01 GHSA-JF73-858C-54PG — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `OliveTin/OliveTin`
- Rank: 211
- Summary: OliveTin doesn't check view permission when returning dashboards
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked commit aa2bd95c is feat(policy) show/hide version number. Trailer is Made-with: Cursor rather than an explicit Co-authored-by marker. Fix d7962710 adds IsAllowedView on dashboard bindings. Deeper blame of deleted source hunks attributed zero AI-marked lines. Version-redaction overlap on api.go is routing, not origin of missing view checks.

### 02 GHSA-2MC2-G238-722J — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 212
- Summary: OpenClaw affected by iMessage remote attachment SCP hardening (strict host-key checks and remoteHost validation)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Claude commit 3b0c80ce is a composite PR for per-sender group tool policies. Fix 49d0def6 hardens iMessage remote SCP/SSH StrictHostKeyChecking. Deeper blame attributed zero ranked-AI lines on the SCP path. Config-schema overlap is routing.

### 03 GHSA-CJV3-M589-V3RX — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 213
- Summary: OpenClaw has Canvas route hardening for mixed-trust deployments
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f4b03599 adds OpenResponses /v1/responses. Fix 08a79679 fails closed on gateway bind fallback and tightens canvas IP fallback. Deeper blame attributed zero ranked-AI lines. New-endpoint overlap is routing, not canvas bind origin.

### 04 GHSA-R54R-WMMQ-MH84 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 214
- Summary: OpenClaw: ZIP extraction race could write outside destination via parent symlink rebind
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f5c2be19 distinguishes outside-workspace errors in fs-safe. Fix 7dac9b05 hardens ZIP write-race handling. Deeper blame attributed zero ranked-AI lines. Same-file fs-safe history without deleted-hunk identity is routing, not TOCTOU origin.

### 05 GHSA-2RGF-HM63-5QPH — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 215
- Summary: OpenClaw improperly parses X-Forwarded-For behind trusted proxies allows client IP spoofing in security decisions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b8c8130e uses LAN IP for WebSocket/probe URLs when bind=lan. Fix 07039dc0 hardens trusted-proxy X-Forwarded-For parsing. Deeper blame attributed zero ranked-AI lines. Same SHA is also ranked for GHSA-4RQQ; shared net.ts chore is not two origins and is not XFF spoofing.

### 06 GHSA-8G7G-HMWM-6RV2 — REJECT `COMPOSITE_ADVISORY_SIBLING`

- Repository: `czlonkowski/n8n-mcp`
- Rank: 216
- Summary: n8n-mcp affected by path traversal, redirect-following SSRF, and telemetry payload exposure
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: First-party GHSA bundles path traversal, redirect-following SSRF, and telemetry payload exposure. Ranked Claude 597bd290 is a telemetry sanitizer security attempt. Fix 1cfe9c6b is a fork merge covering the bundle. Deeper blame of deleted hunks did not attribute the residual surfaces to 597bd290. A telemetry-only security rewrite is not but-for of the composite identity, and incomplete rem of an untouched sibling path is rejected.

### 07 GHSA-V8VW-GW5J-W7M6 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `modelcontextprotocol/registry`
- Rank: 217
- Summary: MCP Registry has open redirect via protocol-relative path in trailing-slash middleware
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c5f50e81 improves DNS verification error text. Fix 1201cbd8 closes protocol-relative open redirect in trailing-slash middleware. Deeper blame attributed 5 AI lines on other files, none to the ranked SHA. Wrong-selector hint overlap is routing.

### 08 GHSA-4PCG-253R-RF9W — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 218
- Summary: Open WebUI's chat completion API allows tool restrictions to be bypassed
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 2e7c7d63 prevents ExternalReranker from blocking the event loop. Fix 4737e1f1 is open terminal integration. Deeper blame attributed zero AI lines. Perf/config overlap is not origin of chat-completion tool-restriction bypass.

### 09 GHSA-R7G9-XPMJ-5FCQ — REJECT `OLD_BUG_SIBLING_REGEX`

- Repository: `harttle/liquidjs`
- Rank: 219
- Summary: LiquidJS Vulnerable to ReDoS via Quadratic Backtracking in `strip_html` Filter Regex
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Cursor commit 26ea2856 is an explicit XSS attempt: it widens strip_html from <.*?> to <[\s\S]*?> so tags may span newlines. Parent already used [\s\S]*? on unclosed <script>/<style>, which is the ReDoS the later linear-scan fix 3616a744 documents and tests. Deeper blame attributed 1 ranked-AI line (the catch-all alternative). Residual quadratic backtracking is the pre-AI script/style alternatives, not but-for origin, and is incomplete rem of an untouched sibling alternative.

### 10 GHSA-C3PX-H233-H6FQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `getarcaneapp/arcane`
- Rank: 220
- Summary: Arcane Has an Authenticated Arbitrary Host File Read via Docker Compose Include Directives
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 1174e527 adds depth limit and skip list to project directory scanning. Fix b6cbffab blocks unsafe compose include file reads. Deeper blame attributed zero ranked-AI lines. Scan-perf overlap is routing, not compose-include origin.

### 11 GHSA-F3RG-XQJJ-CJ9W — REJECT `AI_INCOMPLETE_REMEDIATION_WRONG_HUNK`

- Repository: `czlonkowski/n8n-mcp`
- Rank: 221
- Summary: n8n-MCP: Workflow telemetry sanitizer could retain partial values from URL-shaped node parameters
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Claude e14c647b refactors telemetry and adds event-validator URL/[KEY]/email sanitization. Advisory residual is URL-shaped fragments in workflow-sanitizer node parameters. Deeper blame attributed 1 ranked-AI line in event-validator.ts and 29 lines of workflow-sanitizer.ts to other AI 597bd290 (also ranked for GHSA-8G7G). The later fix 6cf6fef6 amends the sanitizer/validator, but ranked SHA is not the blamed author of the residual URL-path boundary. Incomplete rem without ranked hunk identity is rejected. SHA sharing with the 8G7G telemetry attempt is not mechanism equality.

### 12 GHSA-CMRH-WVQ6-WM9R — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `czlonkowski/n8n-mcp`
- Rank: 222
- Summary: n8n-mcp webhook and API client paths has an authenticated SSRF
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Claude squash d9d847f2 is Merge commit from fork closing GHSA-4GGG-H7PH-26QR (already assigned in directroot batch3). This GHSA is residual authenticated SSRF in webhook/API client paths. Fix bcaba839 is another fork merge amending ssrf-protection.ts. Deeper blame attributed 28 AI lines, none to d9d847f2 (later rewrite 06cbb402 owns deleted ssrf-protection hunks). Patch-delta on the ranked squash is not proved. Prior-advisory squash is not a new direct-root identity.

### 13 GHSA-JCC8-G2Q4-9FXQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `argoproj/argo-workflows`
- Rank: 223
- Summary: Argo Vulnerable to Unauthenticated Memory Exhaustion (DoS) in Webhook Interceptor
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 97635e65 is chore: improve linting. Fix 7abb4de6 is a fork merge bounding webhook body reads. Deeper blame attributed zero ranked-AI lines. Lint overlap on interceptor.go is routing, not unauthenticated memory-exhaustion origin.

### 14 GHSA-PJ6Q-4VQ4-R8CG — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `lin-snow/Ech0`
- Rank: 224
- Summary: Ech0 allows PUT /api/echo/like/:id unauthenticated: anonymous callers to modify any echo's fav_count
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 2a5b03a7 only prepends SPDX/Copyright headers. Fix cecc2c19 rate-limits public likes. Deeper blame attributed zero ranked-AI lines. Header chore sharing SHA with GHSA-RGJ7 is not like-endpoint origin and is not two mechanisms.

### 15 GHSA-4RQQ-W8V4-7P47 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 225
- Summary: OpenClaw has incomplete IPv4 special-use SSRF blocking in web fetch guard
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI is the same b8c8130e LAN-IP probe commit as GHSA-2RGF. Advisory is incomplete IPv4 special-use SSRF blocking in web_fetch. Fix 333fbb86 consolidates IP checks with ipaddr.js. Deeper blame attributed zero ranked-AI lines. Shared SHA without mechanism equality is rejected; LAN bind helper is not the SSRF denylist origin.

### 16 GHSA-RGJ7-VG8V-J4WR — REJECT `SIBLING_FIX`

- Repository: `lin-snow/Ech0`
- Rank: 226
- Summary: Ech0's Unauthenticated Like Endpoint Enables Arbitrary Engagement Metric Inflation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Advisory text is unauthenticated like-metric inflation (same surface as GHSA-PJ6Q). Ranked SHA is the SPDX header chore 2a5b03a7. Minimum fix a7e8b8e8 is exact OAuth redirect URI matching, a sibling auth change. Deeper blame attributed zero ranked-AI lines. Weak fix pairing plus shared SHA with PJ6Q is not a distinct countable origin.

### 17 GHSA-XR5H-PHRJ-8VXV — REJECT `SQUASH_CARRIER_TRANSFER`

- Repository: `withastro/astro`
- Rank: 227
- Summary: Astro: Server island encrypted parameters vulnerable to cross-component replay
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked 336b0033 is Merge main into next (#15348): 48 files, many human co-authors, plus Claude Opus 4.5 as one trailer among dozens. Deeper blame attributed 8 server-island encryption lines to that merge. Authorship of AES-GCM without AAD is transferred across the branch merge/carrier, not an atomic first-parent invention of the ranked commit. Later AI co-author on a merge of main is insufficient. Fix 3d82220a adds AEAD context binding.

### 18 GHSA-4Q5V-7G7X-J79W — REJECT `REFACTOR_OLD_BUG`

- Repository: `oscal-compass/compliance-trestle`
- Rank: 228
- Summary: compliance-trestle - jinja has an Arbitrary File Write via Path Traversal
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Claude f85944cf is feat: migrate to hatch for build process (198 files). Deeper blame attributed 2 ranked-AI lines in jinja.py that are trailing-comma / import formatting. Fix 247fcce2 adds PathSecurityValidator on -o output. Hatch migration is not but-for of the pre-existing arbitrary file write. Same SHA is ranked for GHSA-W76H.

### 19 GHSA-FQVV-JVHR-G5JC — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `ManoManoTech/firefighter-incident`
- Rank: 229
- Summary: FireFighter has unauthenticated SSRF in its Raid jira_bot endpoint that allows IAM credential theft
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 84ccb563 finalizes RaidArea to IncidentCategory migration. Fix 2586679e is a fork merge adding URL validation on the unauthenticated jira_bot attachments fetch. Deeper blame attributed zero ranked-AI lines. Category-migration overlap is routing, not SSRF origin.

### 20 GHSA-Q8MJ-M7CP-5Q26 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `ljharb/qs`
- Rank: 230
- Summary: qs has a remotely triggerable DoS: qs.stringify crashes with TypeError on null/undefined entries in comma-format arrays when encodeValuesOnly is set
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a0a81ea2 uses configured delimiter after charsetSentinel in stringify. Fix 21f80b33 skips null/undefined entries in comma format with encodeValuesOnly. Deeper blame attributed zero ranked-AI lines. Adjacent stringify edits are not origin of the TypeError crash.

### 21 GHSA-H3WW-Q6XX-W7X3 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 231
- Summary: Open WebUI: LDAP and OAuth First-User Race Condition Allows Multiple Admin Accounts
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 823b9a6d removes old SRC-level log env vars. Fix 96a0b323 prevents first-user admin race in LDAP/OAuth. Deeper blame attributed zero ranked-AI lines. Same SHA is ranked for GHSA-26G9. Log-env chore is not TOCTOU origin of first-user admin assignment.

### 22 GHSA-FJ2M-QVH9-JQ4Q — REJECT `SIBLING_FIX`

- Repository: `LearningCircuit/local-deep-research`
- Rank: 232
- Summary: local-deep-research is Vulnerable to HTML Injection via Unescaped User Input in PDF Export (`pdf_service.py:_markdown_to_html`)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Advisory is HTML injection via unescaped title/metadata in PDFService._markdown_to_html (html.escape already imported on the parent). Ranked Copilot commit ccb352ed is WeasyPrint graceful-degradation / MissingPDFDependencyError. Deeper blame attributed 1 ranked-AI line (optional WeasyPrint import). Minimum fix 15f13d5c gates WeasyPrint url_fetcher with an SSRF validator, a sibling PDF surface, not reversal of the HTML interpolation invariant.

### 23 GHSA-W76H-Q7C6-JPJP — REJECT `REFACTOR_OLD_BUG`

- Repository: `oscal-compass/compliance-trestle`
- Rank: 233
- Summary: compliance-trestle Vulnerable to SSRF in Remote Fetching Subsystem
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked SHA is the same hatch migration f85944cf as GHSA-4Q5V. Advisory is SSRF in trestle/core/remote/cache.py HTTPSFetcher. Fix 53de5e75 is a fork merge. Deeper blame attributed zero ranked-AI lines on cache.py. Build-tool migration is not origin of unsanitized requests.get, and shared SHA is not two mechanisms.

### 24 GHSA-7J2F-6H2R-6CQC — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `koel/koel`
- Rank: 234
- Summary: Koel Vulnerable to SSRF via Podcast Episode Enclosure URLs
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c5214b7b switches to mago as PHP CS fixer. Fix be1e8679 validates redirect targets when downloading podcast episodes. Deeper blame attributed zero ranked-AI lines. Linter chore overlap on EpisodePlayable.php is routing, not enclosure-URL SSRF origin.

### 25 GHSA-M6XR-FVFG-5G64 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `TomWright/dasel`
- Rank: 235
- Summary: Dasel: Denial of service in dasel selector lexer due to infinite loop on unterminated regex literal
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked 5fc11722 and fix 95f8dd3a are both Merge commit from fork on the selector lexer. Deeper blame attributed zero ranked-AI lines on tokenize.go. A later security fork merge without blamed deleted hunks of the ranked squash is not proved as AI_DIRECT_ROOT or as patch-delta incomplete rem.

### 26 GHSA-P6V2-XCPG-H6XW — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `better-auth/better-auth`
- Rank: 236
- Summary: Better Auth: Rate limiter keys IPv6 addresses individually and is bypassable via prefix rotation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6ba15d56 refactors origin-check middleware. Fix 57af0f7b normalizes IPv6 rate-limit keys onto subnets. Deeper blame attributed zero ranked-AI lines. Origin-middleware overlap is routing, not IPv6 prefix-rotation origin.

### 27 GHSA-26G9-27VM-X3Q8 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 237
- Summary: Open WebUI: shared-chat branch ignores access_type, allowing unauthorized file deletion
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked SHA is the same log-env chore 823b9a6d as GHSA-H3WW. Advisory is shared-chat file-deletion authz. Fix 2e52ad8f refactors shared chat. Deeper blame attributed zero ranked-AI lines. Shared SHA without mechanism equality is rejected.

### 28 GHSA-FC86-6RV6-2JPM — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `webonyx/graphql-php`
- Rank: 238
- Summary: webonyx/graphql-php has quadratic validation cost in OverlappingFieldsCanBeMerged via inline fragments
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b5e7c995 deduplicates named fields in OverlappingFieldsCanBeMerged to prevent DoS (security attempt on the CVE-2023-26144 named-fragment cache). Advisory residual is quadratic cost via inline fragments. Fix 996adcfc adds a comparison budget. Deeper blame attributed zero ranked-AI deleted lines. Incomplete rem of an untouched inline-fragment sibling path is out of this direct-root lane without patch-delta on the ranked hunk.

### 29 GHSA-95C3-6VVW-4MRQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `modelcontextprotocol/registry`
- Rank: 239
- Summary: MCP Registry's GitHub OIDC tokens are replayable across registry deployments due to shared audience
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c733ceda is auth: New auth flow (#273). Fix 3f89fc2b binds GitHub OIDC token exchange to a per-deployment audience. Deeper blame attributed zero ranked-AI lines. Introducing a shared-audience OIDC flow is not proved by deleted-hunk identity on the later audience-bind; file-history without hunk identity remains routing.

### 30 GHSA-QQ3R-W4HJ-GJP6 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `chainguard-dev/apko`
- Rank: 240
- Summary: apko dirFS has a symlink-following path traversal that allows multiple entry points to escape the build root
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 8dd55f2c fixes a dirFS ReadFile zeros caching bug. Fix f5a96e12 scopes DirFS operations through os.Root. Deeper blame attributed zero ranked-AI lines. Cache-correctness overlap on rwosfs.go is routing, not symlink-escape origin of sanitizePath.

## Conservation

830 unique rank hits. Batches 1-7 reviewed 210. This batch reviewed 30. Unreviewed hits 590. Rank misses 2643. 210+30+590+2643=3473.

## Claim boundary

Publication HOLD. More-than-200 unsupported. Canonical ledger not edited. No commit or push.
