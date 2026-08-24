# Direct-root mining batch 14 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical73 and directroot batches 1-13, including frozen in-progress batch12 and batch13 selections. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 410
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 390+30+410+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical73 strict identities plus batch1-13 `selected-30.jsonl`/`cases.jsonl`, including frozen in-progress batch12 and batch13. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-VJF3-2GPJ-233V — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `n8n-io/n8n`
- Rank: 391
- Summary: n8n has an SSO Enforcement Bypass in its Self-Service Settings API
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6b474e41 adds data-table resources to the public API. Fix a70b2ea3 prevents SSO enforcement bypass via self-service settings. Deeper blame attributed zero AI lines. dto/index.ts overlap is routing, not SSO self-settings origin.

### 02 GHSA-6HF3-MHGC-CM65 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 392
- Summary: OpenClaw session tool visibility hardening and Telegram webhook secret fallback
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 03bec492 sanitizes tool-call text in sessions-helpers extractAssistantText. Fix c6c53437 scopes session tools and webhook secret fallback. Deeper blame attributed zero AI lines. sessions-helpers.ts overlap is a sibling sanitizer, not session-visibility or webhook-secret origin.

### 03 GHSA-782P-5FR5-7FJ8 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 393
- Summary: OpenClaw Affected by Remote Code Execution via System Prompt Injection in Slack Channel Descriptions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 3b0c80ce adds per-sender group tool policies. Fix 35eb40a7 separates untrusted channel metadata from the system prompt. Deeper blame attributed zero AI lines. get-reply-run.ts overlap is routing, not Slack channel-description prompt-injection origin.

### 04 GHSA-WRRR-8JCV-WJF5 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `lobehub/lobehub`
- Rank: 394
- Summary: LobeHub Vulnerable to Improper Authorization in Presigned Upload
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a91f9034 adds unit tests for the S3 module. Fix 2c1762b8 adds userId authorization on knowledge-base file removal. Deeper blame attributed zero AI lines. S3 test overlap is routing, not presigned-upload authorization origin.

### 05 GHSA-33FM-6GP7-4P47 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `WeblateOrg/weblate`
- Rank: 395
- Summary: Weblate has an argument injection in management console
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9e7010cb fixes pending-units handling on components. Fix 78773cc1 improves SSH-key adding in the management console. Deeper blame attributed zero AI lines. component.py overlap is a sibling path, not argument-injection origin.

### 06 GHSA-HV93-R4J3-Q65F — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 396
- Summary: OpenClaw Hook Session Key Override Enables Targeted Cross-Session Routing
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 961b4adc deprecates query-param hook token auth. Same SHA is also ranked for GHSA-MV9J (Nostr profile API). Fix 113ebfd6 hardens hook and device-token auth. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not hook session-key override origin.

### 07 GHSA-RVHR-26G4-P2R8 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Budibase/budibase`
- Rank: 397
- Summary: Budibase: Remote Code Execution via Unsafe eval() in View Filter Map Function (Budibase Cloud)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 46db3c1d is linting after middleware import changes. Fix 34865981 is a merge PR for views-security. Deeper blame attributed zero AI lines. view.ts overlap is routing, not eval-in-view-filter origin.

### 08 GHSA-V82V-C5X8-W282 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `zauberzeug/nicegui`
- Rank: 398
- Summary: NiceGUI's XSS vulnerability in ui.markdown() allows arbitrary JavaScript execution through unsanitized HTML content
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ffac9971 segregates Quasar important CSS rules. Fix f1f75335 is a merge-from-fork sanitizing markdown/HTML. Deeper blame attributed zero AI lines. extract_core_libraries.py overlap is routing, not markdown XSS origin.

### 09 GHSA-RWJ8-P9VQ-25GV — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 399
- Summary: OpenClaw has a LFI in BlueBubbles media path handling
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5af322f7 adds Discord set-presence. Fix 71f357d9 hardens BlueBubbles local media paths against LFI. Deeper blame attributed zero AI lines. zod-schema.providers-core.ts overlap is routing, not BlueBubbles LFI origin.

### 10 GHSA-MHC9-48GJ-9GP3 — REJECT `SIBLING_FIX`

- Repository: `trailofbits/fickling`
- Rank: 400
- Summary: Fickling has safety check bypass via REDUCE+BUILD opcode sequence
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ff423dad fixes a different advisory (GHSA-mxhj OBJ opcode persistence). Fix 0c4558d9 expands UNSAFE_IMPORTS for this REDUCE+BUILD report. Deeper blame attributed zero AI lines. Same-file fickle.py overlap is a sibling opcode/blocklist fix, not REDUCE+BUILD origin.

### 11 GHSA-MV9J-6XHH-G383 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 401
- Summary: OpenClaw's unauthenticated Nostr profile HTTP endpoints allow remote profile/config tampering
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 961b4adc as GHSA-HV93. Fix 647d929c authenticates Nostr profile HTTP endpoints. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not two origins.

### 12 GHSA-VJQX-CFC4-9H6V — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `modelcontextprotocol/servers`
- Rank: 402
- Summary: mcp-server-git : Path traversal in git_add allows staging files outside repository boundaries
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 88320daf imports BadName directly for pyright. Fix 862e717f validates git_add paths. Deeper blame attributed zero AI lines. server.py overlap is routing, not git_add path-traversal origin.

### 13 GHSA-QRQ5-WJGG-RVQW — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 403
- Summary: OpenClaw has a Path Traversal in Plugin Installation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9ceac415 auto-compacts on context overflow. Fix d03eca84 hardens plugin and hook install paths. Deeper blame attributed zero AI lines. compact.ts overlap is routing, not plugin-install traversal origin.

### 14 GHSA-V773-R54F-Q32W — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 404
- Summary: OpenClaw Slack: dmPolicy=open allowed any DM sender to run privileged slash commands
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 481bd333 handles AbortError and transient network errors. Fix f19eabee gates DM slash-command authorization. Deeper blame attributed zero AI lines. slash.ts overlap is routing, not dmPolicy slash-auth origin.

### 15 GHSA-C37P-4QQG-3P76 — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `openclaw/openclaw`
- Rank: 405
- Summary: OpenClaw Twilio voice-call webhook auth bypass when ngrok loopback compatibility is enabled
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 8b4696c0 validates voice-call provider credentials from env vars. Fix ff11d879 requires Twilio signatures in ngrok loopback mode. Deeper blame attributed zero AI lines. Credential validation is a sibling boundary; residual loopback signature skip is an untouched sibling, not patch-delta of the AI-added credential gate.

### 16 GHSA-MRPH-W4HH-GX3G — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `gogs/gogs`
- Rank: 406
- Summary: Gogs has arbitrary file read/write via Path Traversal in Git hook editing
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4ee706b2 replaces pkg/errors with cockroachdb/errors. Fix 48946299 validates Git server hook names for editing. Deeper blame attributed zero AI lines. setting.go overlap is an old-bug refactor, not hook-name traversal origin.

### 17 GHSA-QXX2-7H4C-83F4 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `chainguard-dev/melange`
- Rank: 407
- Summary: melange QEMU runner could write files outside workspace directory
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e51ca30c is a merge-from-fork. Fix 6e243d0d is a later merge-from-fork adding QEMU workspace path validation. Deeper blame attributed zero AI lines (no deleted source spans). Prior fork merge is not QEMU workspace-write origin.

### 18 GHSA-VP6Q-7M36-PQ3W — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `bugsink/bugsink`
- Rank: 408
- Summary: Bugsink is vulnerable to Stored XSS via Pygments fallback in stacktrace rendering
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 77da3835 adds an OpenAPI link to the navigation bar. Fix e784d6ae escapes Pygments fallback output. Deeper blame attributed zero AI lines. theme/tests.py overlap is routing, not stacktrace XSS origin.

### 19 GHSA-X2MW-7J39-93XQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `n8n-io/n8n`
- Rank: 409
- Summary: n8n has Arbitrary Command Execution via File Write and Git Operations
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 2cb8e843 adds dynamic editor banners. Fix 97365caf limits file access by regex. Deeper blame attributed zero AI lines. config.test.ts overlap is routing, not file-write/git RCE origin.

### 20 GHSA-RXRV-835Q-V5MH — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `locutusjs/locutus`
- Rank: 410
- Summary: locutus is vulnerable to Prototype Pollution
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Advisory names a residual includes() bypass after an earlier parse_str forbidden-key check. Ranked AI 0b10e65a is a large maintenance bundle. Fix 042af9ca hardens the parse_str guard. Deeper blame attributed zero AI lines on deleted parse_str hunks. File-history without hunk identity is not proved AI authorship of the incomplete guard.

### 21 GHSA-PHWV-C562-GVMH — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `sveltejs/svelte`
- Rank: 411
- Summary: Svelte vulnerable to XSS during SSR with contenteditable bind:innerText and bind:textContent
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e3d7f398 updates ESLint to v10. Fix 0df5abca is a merge-from-fork escaping contenteditable SSR bindings. Deeper blame attributed zero AI lines. element.js overlap is routing, not contenteditable XSS origin.

### 22 GHSA-W45G-5746-X9FP — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 412
- Summary: OpenClaw hardened cron webhook delivery against SSRF
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 04e3a66f passes agentId to runHeartbeatOnce. Fix 99db4d13 guards cron webhook delivery against SSRF. Deeper blame attributed zero AI lines. server-cron.ts overlap is routing, not webhook SSRF origin.

### 23 GHSA-2QJ5-GWG2-XWC4 — REJECT `ROUTING_DEFENSE_IN_DEPTH`

- Repository: `openclaw/openclaw`
- Rank: 413
- Summary: OpenClaw: Unsanitized CWD path injection into LLM prompts
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 42164494 guards resolveUserPath against undefined and introduces workspace-run.ts. Fix 6254e96a sanitizes paths before prompt embedding in system-prompt.ts and as defense-in-depth in workspace-run.ts. Deeper blame attributed two AI lines only on workspaceDir resolveUserPath calls, not the system-prompt embedding hunks. Advisory introduced:0; unsanitized CWD-in-prompt is an old hole. Resolver sanitization is not but-for origin of prompt injection.

### 24 GHSA-PRJ9-97MP-MWH2 — REJECT `SIBLING_FIX`

- Repository: `OliveTin/OliveTin`
- Rank: 414
- Summary: OliveTin has Unvalidated ot_-prefixed Arguments that Bypass Input Filtering
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f33d764a fixes argument-form submit and ascii_sentence mapping. Fix ebffd9f0 treats all ot_ system arguments as reserved in the executor. Deeper blame attributed one AI line in ArgumentForm.vue (ascii_sentence type mapping also extended by the fix). Frontend type mapping is not keepArgument ot_ filter-bypass origin in executor.go.

### 25 GHSA-63GR-G7JC-V8RG — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `agenticmail/agenticmail`
- Rank: 415
- Summary: @agenticmail/mcp Missing Authentication for Critical Function
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 900e6b95 adds operator-query MCP/OpenClaw tools. Fix 7d1791da adds HTTP MCP authentication. Deeper blame attributed zero AI lines. packages/mcp/src/index.ts overlap is routing, not missing-auth origin.

### 26 GHSA-744X-3838-5R56 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `gogs/gogs`
- Rank: 416
- Summary: Gogs Vulnerable to Unauthenticated Organization Teams Information Disclosure via API
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a1fa62b2 decouples API types from go-gogs-client. Fix 2ebc0e27 requires token auth for org metadata and team list. Deeper blame attributed zero AI lines. api.go overlap is an old-bug refactor, not unauthenticated team-list origin.

### 27 GHSA-GX55-F84R-V3R7 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `fission/fission`
- Rank: 417
- Summary: Fission Environment CRD podspec passthrough enables hostPID/hostNetwork/privileged pods, node escape
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9225ce56 adds CORS deny and security headers. Fix e484df84 rejects dangerous PodSpec fields. Deeper blame attributed zero AI lines. validation.go overlap is a sibling security change, not podspec passthrough origin.

### 28 GHSA-MQXH-6GQ7-558M — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `earendil-works/pi`
- Rank: 418
- Summary: Pi Agent: Pi loads project-local extensions without approval
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ff5148e7 forwards message and tool-execution events to extensions. Fix 718215bd adds extension project-trust decisions. Deeper blame attributed zero AI lines. extensions/index.ts overlap is a sibling event-forwarding feature, not load-without-approval origin.

### 29 GHSA-35P6-XMWP-9G52 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `nodejs/undici`
- Rank: 419
- Summary: undici vulnerable to HTTP response queue poisoning via keep-alive socket reuse
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f0b40bd6 eliminates eager llhttp promise creation. Fix 6ea54ef8 guards idle socket validation to skip fresh sockets. Deeper blame attributed zero AI lines. client-h1.js overlap is an old-bug refactor, not keep-alive queue-poisoning origin.

### 30 GHSA-QW99-GRCX-4PVM — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 420
- Summary: OpenClaw's Chrome extension relay binds publicly due to wildcard treated as loopback
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 8befe7f8 cleans up suspended Clawdbot CLI processes. Fix 8d75a496 centralizes isPlainObject/isLoopbackHost utilities. Deeper blame attributed zero AI lines. helpers.ts overlap is routing; wildcard-as-loopback is not AI origin.

## Conservation

- rank_pool 3473 = 390 prior directroot reviews + 30 this slice + 410 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch13: 390; this slice 391-420
- Incoming unreviewed hits before this slice: 440; after: 410
- Unreviewed remaining IDs are UNREVIEWED, not REJECT

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD.
