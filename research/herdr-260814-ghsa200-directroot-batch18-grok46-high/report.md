# Direct-root mining batch 18 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical78 and directroot batches 1-17, including frozen in-progress batch16 and batch17 selections. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 290
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 510+30+290+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical78 strict identities plus batch1-17 `selected-30.jsonl`/`cases.jsonl`, including frozen in-progress batch16 and batch17. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Incomplete remediation of untouched siblings is rejected. Worker PASS is a proposal.

## Cases

### 01 GHSA-353C-V8X9-V7C3 — REJECT `SIBLING_FIX`

- Repository: `QuantGeekDev/mcp-framework`
- Rank: 511
- Summary: MCP-Framework: Unbounded memory allocation in readRequestBody allows denial of service via HTTP transport
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f165b99b adds a configurable /health endpoint on SSE and HTTP Stream transports. Fix f97d2bb7 caps readRequestBody with maxMessageSize. Deeper blame attributed zero AI lines. A health-endpoint feature is not origin of unbounded HTTP body concatenation.

### 02 GHSA-CWCX-382V-8M9G — REJECT `SIBLING_FIX`

- Repository: `WeblateOrg/weblate`
- Rank: 512
- Summary: Weblate Vulnerable to Authenticated SSRF via Project Backup Import bypassing validate_repo_url
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4c2b90c5 formalizes the addons cache as AddonCache. Fix e1eff1f5 annotates remote VCS operations for validation. Deeper blame attributed zero AI lines across 80 spans. Addons-cache refactor is not origin of bulk_create bypassing validate_repo_url on backup import.

### 03 GHSA-8FFJ-4HX4-9PGF — REJECT `SIBLING_FIX`

- Repository: `HKUDS/LightRAG`
- Rank: 513
- Summary: lightrag-hku: JWT Algorithm Confusion Vulnerability
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 22f590db adds bcrypt password hashing and a default TOKEN_SECRET warning. Fix 728f2e54 rejects JWT algorithm none. Deeper blame attributed zero AI lines. Password hashing is not origin of JWT algorithm confusion.

### 04 GHSA-89R3-6X4J-V7WF — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 514
- Summary: OpenClaw: Voice-call Plivo replay mutates in-process callback origin before replay rejection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 48aea870 adds prek pre-commit hooks and dependabot. Fix efe9183f pins Plivo callback origins. Deeper blame attributed zero AI lines. Hook scaffolding is not origin of Plivo replay mutating callback origin.

### 05 GHSA-G9C2-GF25-3X67 — REJECT `SIBLING_FIX`

- Repository: `tinacms/tinacms`
- Rank: 515
- Summary: @tinacms/graphql's FilesystemBridge Path Validation Can Be Bypassed via Symlinks or Junctions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bde4e4f6 improves the CLI error when the content dir is missing tina/. Fix f124eaba hardens FilesystemBridge and media endpoints against symlink traversal. Deeper blame attributed zero AI lines. A missing-folder error message is not origin of symlink path-validation bypass.

### 06 GHSA-82QX-6VJ7-P8M2 — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 516
- Summary: OpenClaw: Channel setup catalog lookups could include untrusted workspace plugin shadows
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4cb8dde8 adds video-generation infrastructure. Marker regex did not hit. Fix 1fede43b excludes workspace shadows from channel-setup catalog lookups. Deeper blame attributed zero AI lines. Video generation is not origin of untrusted workspace plugin shadows.

### 07 GHSA-736R-JWJ6-4W23 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 517
- Summary: OpenClaw: Sandboxed agents could escape exec routing via host=node override
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI f3459d71 treats shell exit codes 126/127 as failures. Fix dffad085 blocks sandboxed host=node exec override. Deeper blame attributed zero AI lines. Shared SHA with GHSA-VFP4 without mechanism equality. Exit-code handling is not origin of host=node sandbox escape.

### 08 GHSA-VFP4-8X56-J7C5 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 518
- Summary: OpenClaw: Exec environment denylist missed high-risk interpreter startup variables
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA f3459d71 as GHSA-736R. Fix 2d126fc6 expands the host env denylist. Deeper blame attributed zero AI lines. Shared exec-runtime file without mechanism equality is not interpreter-startup denylist origin.

### 09 GHSA-6W67-HWM5-92MQ — REJECT `OLD_BUG_REFACTOR`

- Repository: `InternLM/lmdeploy`
- Rank: 519
- Summary: LMDeploy has Server-Side Request Forgery (SSRF) via Vision-Language Image Loading
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c677cdd5 is a 327-file pyupgrade/ruff modernization. Fix 71d64a33 hardens VL image URL loading. Deeper blame attributed zero AI lines. A style modernization preserving load_image HTTP fetch is not SSRF origin.

### 10 GHSA-RMX9-2PP3-XHCR — REJECT `INCOMPLETE_FIX_REVERSAL`

- Repository: `tektoncd/pipeline`
- Rank: 520
- Summary: Tekton Pipelines has VerificationPolicy regex pattern bypass via substring matching
- Failing gates: ai_hunk_gate, but_for_gate, fix_reversal_gate
- Counterevidence: Ranked AI 84d32b50 prevents excessive reconciliation when timeout is disabled. Ranked closer 2c398711 only hoists VerificationPolicy listing out of a per-task loop. The advisory names regexp.MatchString substring matching, and a different commit 0133513d. Deeper blame attributed zero AI lines. A timeout-reconciliation change plus a perf hoist does not reverse unanchored pattern matching.

### 11 GHSA-R297-P3V4-WP8M — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `nicolargo/glances`
- Rank: 521
- Summary: Glances's Browser API Exposes Reusable Downstream Credentials via /api/4/serverslist
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 7b200f00 adds MCP server support to the web server. Shared SHA with GHSA-QHJ7 and GHSA-GH4X and with already-reviewed GHSA-GFC2 CORS. Fix 879ef868 redacts browser /serverslist credentials. Deeper blame attributed zero AI lines. MCP listener support without mechanism equality is not serverslist credential-exposure origin.

### 12 GHSA-PFJF-5GXR-995X — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `gradio-app/gradio`
- Rank: 522
- Summary: Gradio has an Open Redirect in its OAuth Flow
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 029034f7 is the 1264-file Gradio 6.0 bundle. Same SHA and same closer dfee0da0 as GHSA-H3H8. Fix is a bundled OAuth patch. Deeper blame attributed zero AI lines. A mega-merge without mechanism equality is not OAuth open-redirect origin.

### 13 GHSA-H5HG-H7RR-GPF3 — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 523
- Summary: OpenClaw: Node browser proxy allowProfiles bypass through persistent profile mutation and runtime profile selection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6b4c24c2 adds Telegram custom apiRoot. Fix eac93507 enforces node browser proxy allowProfiles. Deeper blame attributed zero AI lines. Telegram apiRoot is not origin of browser-proxy profile mutation.

### 14 GHSA-GC9R-867R-J85F — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 524
- Summary: OpenClaw: Microsoft Teams SSO invoke handler missed sender authorization checks
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 355794c2 adds Teams reaction support with delegated auth. Fix 80b1fa17 enforces sender allowlist on SSO signin invokes. Deeper blame attributed zero AI lines. Reaction support is a sibling Teams path, not SSO invoke authorization origin.

### 15 GHSA-Q5PR-72PQ-83V3 — REJECT `SIBLING_FIX`

- Repository: `h3js/h3`
- Rank: 525
- Summary: H3: Unbounded Chunked Cookie Count in Session Cleanup Loop may Lead to Denial of Service
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4dea405a adds getValidatedCookies. Fix 399257cb caps chunked cookie count at 100. Deeper blame attributed zero AI lines. A new validation helper is not origin of unbounded CHUNKED_COOKIE parseInt in the pre-existing cleanup loop.

### 16 GHSA-H3H8-3V2V-RG7M — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `gradio-app/gradio`
- Rank: 526
- Summary: Gradio: Mocked OAuth Login Exposes Server Credentials and Uses Hardcoded Session Secret
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 029034f7 and same closer dfee0da0 as GHSA-PFJF. The advisory is mocked OAuth login credentials, not open redirect. Deeper blame attributed zero AI lines. Shared Gradio 6.0 SHA without mechanism equality is not mocked-login origin.

### 17 GHSA-R48F-3986-4F9C — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `trailofbits/fickling`
- Rank: 527
- Summary: fickling modules linecache, difflib and gc are missing from the unsafe modules blocklist
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 351ed4d4 adds platform to UNSAFE_IMPORTS for a different advisory GHSA-5CXW. Fix 7f39d972 then adds linecache, difflib, and gc. Deeper blame attributed zero AI lines because the fix only appends sibling module names. A later denylist entry for pre-existing omitted modules is not a patch-delta of the platform addition.

### 18 GHSA-H45M-MGCP-Q388 — REJECT `AI_INCOMPLETE_REMEDIATION_NO_RELEASE`

- Repository: `jahlives/openssl_encrypt`
- Rank: 528
- Summary: openssl-encrypt: TOTP rate limiter is in-memory only — not shared across workers, lost on restart
- Failing gates: release_gate
- Counterevidence: Ranked AI 90fc5d2c only rewrites TOTP lockout error text. Deeper blame attributed 43 deleted lines to 1b6f7322, an explicit Claude-marked security attempt that introduced in-memory TOTPRateLimiter. Fix 2749bc09 adds a pluggable DatabaseBackend for that same limiter. Patch-delta of the AI-added rate-limit boundary holds, but the clone has zero release tags so release containment cannot close. Worker PASS stays uncounted.

### 19 GHSA-RVQR-HRCC-J9VV — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 529
- Summary: OpenClaw: Bonjour/DNS-SD TXT metadata steers CLI routing after failed service resolution
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 01bd83d6 releases the gateway lock before process.exit in run-loop. Fix deecf68b fails closed on unresolved discovery endpoints. Deeper blame attributed zero AI lines. Lock-release-before-exit is not origin of Bonjour TXT steering after failed resolution.

### 20 GHSA-56PC-6HVP-4GV4 — REJECT `COMMIT_ONLY_CHANGE`

- Repository: `openclaw/openclaw`
- Rank: 530
- Summary: OpenClaw vulnerable to arbitrary file read via $include directive
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c89eb351 is oxfmt formatting of doctor-config-flow.ts. Fix d1c00dbb hardens include confinement. Deeper blame attributed zero AI lines. A formatter-only edit is not origin of $include arbitrary file read.

### 21 GHSA-JHPV-5J76-M56H — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 531
- Summary: OpenClaw: Sender policy bypass in host media attachment reads allows unauthorized local file disclosure
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f7de41ca falls back to the dispatcher when same-channel origin routing fails. Fix c949af9f honors sender policy for host media reads. Deeper blame attributed zero AI lines. Follow-up dispatcher fallback is not origin of host media attachment disclosure.

### 22 GHSA-QHJ7-V7H7-Q4C7 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `nicolargo/glances`
- Rank: 532
- Summary: Glances Vulnerable to Command Injection via Dynamic Configuration Values
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 7b200f00 MCP web-server support as GHSA-R297 and GHSA-GH4X. Fix 358d76a2 is a merge of the command-injection advisory branch. Deeper blame attributed zero AI lines. Shared MCP SHA without mechanism equality is not dynamic-config command-injection origin.

### 23 GHSA-9HJH-FR4F-GXC4 — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 533
- Summary: OpenClaw: Gateway Backend Reconnect lets Non-Admin Operator Scopes Self-Claim operator.admin
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 20523b91 allows trusted-proxy Control UI auth to skip device pairing. Fix d3d8e316 requires pairing for backend scope upgrades. Deeper blame attributed zero AI lines. Trusted-proxy pairing skip is a sibling gateway auth path, not operator.admin self-claim origin.

### 24 GHSA-GH4X-F7CQ-WWX6 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `nicolargo/glances`
- Rank: 534
- Summary: Glances Exposes Unauthenticated Configuration Secrets
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 7b200f00 MCP web-server support as GHSA-R297 and GHSA-QHJ7. Fix 306a7136 is a merge-from-fork of config-secret exposure. Deeper blame attributed zero AI lines. Shared MCP SHA without mechanism equality is not unauthenticated config-secret origin.

### 25 GHSA-RM2P-J3R7-4X4J — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 535
- Summary: OpenClaw's Slack reaction/pin sender-policy consistency issue in non-message ingress
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d3c71875 caps Discord gateway reconnect at 50 attempts. Fix aedf62ac hardens Discord and Slack reaction ingress authorization. Deeper blame attributed zero AI lines. Reconnect capping is not origin of Slack reaction/pin sender-policy inconsistency.

### 26 GHSA-53P3-C7VP-4MCC — REJECT `SIBLING_FIX`

- Repository: `basecamp/trix`
- Rank: 536
- Summary: Trix is vulnerable to XSS through JSON deserialization bypass in drag-and-drop (Level0InputController)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bf389080 replaces Karma with @web/test-runner. Fix 9c0a993d blocks javascript: URIs in JSON drag-drop deserialization. Deeper blame attributed zero AI lines. A test-runner swap is not origin of Level0InputController XSS.

### 27 GHSA-8RGJ-VRFR-6HQR — REJECT `SIBLING_FIX`

- Repository: `withstudiocms/studiocms`
- Rank: 537
- Summary: StudioCMS: IDOR — Arbitrary API Token Revocation Leading to Denial of Service
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 341b59e3 adds the auth-kit package. Deeper blame attributed one line in types.ts: the availablePermissionRanks array order. Fix 9eec9c3b adds an admin API token revocation endpoint and reorders those ranks. The first-party IDOR is missing ownership checks on DELETE api-tokens, not the rank-array order. One blamed type-line is not token-revocation origin.

### 28 GHSA-GCHP-Q4R4-X4FF — REJECT `COMMIT_ONLY_CHANGE`

- Repository: `alexcrichton/tar-rs`
- Rank: 538
- Summary: tar-rs incorrectly ignores PAX size headers if header size is nonzero
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 32a9bbb2 adds RandomReader to exercise partial-read resilience in tests. Marker regex did not hit. Fix de1a5870 unconditionally honors PAX size. Deeper blame attributed zero AI lines. A test helper is not origin of ignoring nonzero PAX size headers.

### 29 GHSA-Q4R8-XM5F-56GW — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `smallstep/certificates`
- Rank: 539
- Summary: step-ca has Unauthenticated Certificate Issuance via SCEP UpdateReq (MessageType=18)
- Failing gates: ai_hunk_gate, but_for_gate, fix_reversal_gate
- Counterevidence: Ranked AI 01c87964 resolves golangci-lint gosec errors. Ranked closer e6da031d is titled Add scep integration tests. Deeper blame attributed zero AI lines. Linting plus a test commit is not origin of SCEP UpdateReq skipping authorization.

### 30 GHSA-GV8F-WPM2-M5WR — REJECT `SIBLING_FIX`

- Repository: `siteboon/claudecodeui`
- Rank: 540
- Summary: @siteboon/claude-code-ui Vulnerable to Unauthenticated RCE via WebSocket Shell Injection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7a087039 makes the authentication database path configurable via DATABASE_PATH. Fix 12e7f074 is a merge-from-fork of WebSocket shell injection. Deeper blame attributed zero AI lines. A DB path config change is not origin of unauthenticated WebSocket RCE.

## Conservation

- rank_pool 3473 = 510 prior directroot reviews + 30 this slice + 290 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch17: 510; this slice 511-540
- Incoming unreviewed hits before this slice: 320; after: 290
- Stale 260813 batch3 equals formal 260814 batch3 (30 IDs) and is not 30 extra reviewed rows
- Canonical78 counted IDs are excluded; six of those IDs already sit inside the prior 510 ranked-hit reviews
- Unreviewed remaining IDs are UNREVIEWED, not REJECT

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. GHSA-H45M-MGCP-Q388 is an AI incomplete-remediation patch-delta of TOTPRateLimiter that still fails release_gate because the openssl_encrypt clone has no git tags. Publication and more-than-200 remain HOLD.
