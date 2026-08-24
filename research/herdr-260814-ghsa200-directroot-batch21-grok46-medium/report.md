# Direct-root mining batch 21 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical81 and directroot batches 1-20, including the frozen batch20 selected-30. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 200
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 600+30+200+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical81 strict identities plus batch1-20 `selected-30.jsonl`/`cases.jsonl`, including frozen in-progress batch20 selected-30. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-77W2-CRQV-CMV3 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 601
- Summary: OpenClaw: Feishu Raw Card Send Surface Can Mint Legacy Card Callbacks That Bypass DM Pairing
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ca578a91 marks a Feishu card field optional in the message tool schema. Fix rejects legacy raw card command payloads. Deeper blame attributed zero AI lines. channel.test.ts overlap is routing, not raw-card callback pairing-bypass origin.

### 02 GHSA-R7VR-GR74-94P8 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 602
- Summary: OpenClaw: Command-authorized non-owners could reach owner-only `/config` and `/debug` surfaces
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 481bd333 handles AbortError and transient network errors on the gateway, the same SHA already reviewed for GHSA-PJVX. Fix requires owner for /config and /debug. Deeper blame attributed zero AI lines. commands.test.ts overlap is routing, not owner-only command origin.

### 03 GHSA-VVXM-VXMR-624H — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 603
- Summary: Open WebUI vulnerable to Path Traversal in `POST /api/v1/audio/transcriptions`
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 823b9a6d removes unused SRC-level log environment variables. Fix suppresses internal path leakage in audio transcription errors. Deeper blame attributed zero AI lines. audio.py overlap is routing, not transcription path-traversal origin.

### 04 GHSA-JMM5-FVH5-GF4P — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `openclaw/openclaw`
- Rank: 604
- Summary: OpenClaw has non-constant-time token comparison in hooks authentication
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 961b4adc deprecates query-param hook token auth and keeps `token !== hooksConfig.token`. Fix adds safeEqualSecret plus hook auth throttling. Deeper blame attributed zero AI lines. Query-token deprecation is a sibling hook-auth change, not constant-time compare origin. Shared SHA with GHSA-5847 and GHSA-47Q7 does not imply mechanism equality.

### 05 GHSA-JWF4-8WF4-JF2M — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 605
- Summary: OpenClaw: BlueBubbles (optional plugin) pairing/allowlist mismatch when allowFrom is empty
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b91e4371 adds an interactive LINQ onboarding adapter. Fix shares BlueBubbles dm/group access policy checks. Deeper blame attributed zero AI lines. plugin-sdk/index.ts overlap is routing, not empty-allowFrom pairing origin.

### 06 GHSA-5847-RM3G-23MW — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `openclaw/openclaw`
- Rank: 606
- Summary: OpenClaw has hook auth rate limiter bypass via IPv4-mapped IPv6 client key variants
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 961b4adc is the same query-param deprecation commit as GHSA-JMM5 and does not author the later remoteAddress throttle key. Fix normalizes IPv4-mapped IPv6 client keys. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not rate-limit bucket origin.

### 07 GHSA-2HM8-RQRM-XFJQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 607
- Summary: OpenClaw's owner-only gateway tool access checks were incomplete in specific authenticated DM flows
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5c2cb6c5 syncs Feishu community contributions. Fix centralizes owner-only tool gating. Deeper blame attributed zero AI lines. bot.ts overlap is a sibling Feishu feature, not owner-only DM tool-gating origin.

### 08 GHSA-3X4C-7XQ6-9PQ8 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vercel/next.js`
- Rank: 608
- Summary: Next.js: Unbounded next/image disk cache growth can exhaust storage
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f1a047fd removes IsolatedDevBuild. Fix adds an LRU next/image disk cache cap. Deeper blame attributed zero AI lines. config-schema.ts overlap is routing, not unbounded image-cache origin.

### 09 GHSA-68F8-9MHJ-H2MP — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 609
- Summary: OpenClaw has a Gateway HTTP /v1/models Route Bypasses Operator Read Scope
- Failing gates: ai_hunk_gate, but_for_gate, fix_reversal_gate
- Counterevidence: Ranked AI f404ff32 adds one useNoBundledPlugins() line to a bundle MCP loader test. Ranked fix only skips plugin allowlist warnings for explicit config paths. Deeper blame attributed zero AI lines. Neither SHA reverses /v1/models operator-read scope.

### 10 GHSA-XQ8G-HGH6-87HV — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 610
- Summary: OpenClaw: BlueBubbles Webhook Missing Rate Limiting Enables Brute-Force Password Guessing
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f92c9251 routes fetch calls through fetchWithSsrFGuard, the same SHA already reviewed for GHSA-MW7W. Fix throttles BlueBubbles webhook auth guesses. Deeper blame attributed zero AI lines. monitor.ts overlap is routing, not webhook brute-force origin.

### 11 GHSA-J5Q5-J9GM-2W5C — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `tektoncd/pipeline`
- Rank: 611
- Summary: Path traversal in Tekton Pipelines git resolver allows reading arbitrary files from the resolver pod
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 791c3a69 categorizes tests as parallel versus serial. Fix prevents path traversal in git resolver pathInRepo. Deeper blame attributed zero AI lines. resolvers_test.go overlap is routing, not pathInRepo origin.

### 12 GHSA-5H2W-QMFP-GGP6 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 612
- Summary: OpenClaw: Gateway `operator.write` can reach admin-only persisted `verboseLevel` via `chat.send` `/verbose`
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0743463b suppresses NO_REPLY tokens in webchat transcripts. Fix requires admin for persisted verbose defaults. Deeper blame attributed zero AI lines. gateway-server-chat.test.ts overlap is routing, not /verbose privilege origin.

### 13 GHSA-2WW6-868G-2C56 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `openclaw/openclaw`
- Rank: 613
- Summary: OpenClaw Vulnerable to HTML injection via unvalidated image MIME type in data-URL interpolation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6ac1c1d6 picks file extensions from output_format. Fix HTML-escapes gallery user input. Deeper blame attributed zero AI lines. Extension mapping is a sibling gen.py change, not unvalidated data-URL MIME origin.

### 14 GHSA-RCHV-X836-W7XP — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 614
- Summary: OpenClaw's dashboard leaked gateway auth material via browser URL/query and localStorage
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 62986980 reverts mixed UI portions from main. Fix scrubs gateway tokens from URL and localStorage persistence. Deeper blame attributed zero AI lines. storage.ts overlap is routing from a revert, not URL/query token-leak origin.

### 15 GHSA-JM6W-M3J8-898G — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `nltk/nltk`
- Rank: 615
- Summary: Unauthenticated remote shutdown in nltk.app.wordnet_app
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 1c3f7996 HTML-escapes a lookup_ not-found XSS message. Fix binds the WordNet HTTP server to 127.0.0.1 against /SHUTDOWN. Deeper blame attributed zero AI lines. XSS escaping is a sibling wordnet_app path, not unauthenticated shutdown origin. Clone has no tags containing either SHA.

### 16 GHSA-F44P-C7W9-7XR7 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 616
- Summary: OpenClaw: Gateway WebSocket Denial of Service via unbounded pre-auth upgrades
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f4b03599 adds the OpenResponses /v1/responses endpoint. Fix caps concurrent pre-auth WebSocket upgrades. Deeper blame attributed zero AI lines. server-runtime-state.ts overlap is a sibling gateway feature, not pre-auth upgrade-cap origin.

### 17 GHSA-X6P3-76F2-XXVH — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `BKDDFS/shamefile`
- Rank: 617
- Summary: Shamefile has an arbitrary file read via shamefile.yaml in shame next
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 47cf4487 collects Python integration-test coverage and refactors registry path normalization. Fix renders shame next snippets from the registry instead of disk. Deeper blame attributed seven AI lines only in e2e_tests/test_shame_next.py, not the yaml path-read origin.

### 18 GHSA-JMMG-JQC7-5QF4 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 618
- Summary: OpenClaw's browser-origin WebSocket auth hardening gap could enable loopback password brute-force chains
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ab4a08a8 defers gateway restart until replies are sent. Fix hardens browser WebSocket auth. Deeper blame attributed zero AI lines. server.impl.ts overlap is routing, not browser-origin brute-force origin.

### 19 GHSA-98H9-4798-4Q5V — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `huggingface/diffusers`
- Rank: 619
- Summary: Diffusers has a `trust_remote_code` bypass via `custom_pipeline` and local custom components
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d7fa4454 removes an 8-bit device restriction. Fix tightens trust_remote_code. Deeper blame attributed zero AI lines. pipeline_utils.py overlap is routing, not custom_pipeline bypass origin.

### 20 GHSA-9WQX-G2CW-VC7R — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 620
- Summary: OpenClaw: Matrix Verification Notices Bypass Matrix DM Policy and Reply to Unpaired DM Peers
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI caf5d2dd adds Matrix multi-account support, the same SHA already reviewed for GHSA-WM8R. Fix gates verification notices on DM access. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not verification-notice pairing origin.

### 21 GHSA-8JJP-R2W2-4V22 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 621
- Summary: Open WebUI: Low-privilege authenticated users can enumerate and stop global background tasks, causing system-wide chat disruption
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 8cf32ae2 uses run_coroutine_threadsafe to avoid worker death during document upload. Fix adds ownership checks to global task endpoints. Deeper blame attributed zero AI lines. main.py overlap is routing, not global-task ownership origin.

### 22 GHSA-3234-GXC3-PQ6F — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `pimcore/pimcore`
- Rank: 622
- Summary: Pimcore Vulnerable to SQL Injection in Custom Reports Column Configuration
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 1baf7690 quoteIdentifier-wraps selected column names. Fix strips SQL comments before the pre-existing DDL/DML keyword denylist. Deeper blame attributed zero AI lines. Identifier quoting is not the columnConfig concatenated-SQL residual; the later denylist amendment is not a patch-delta of the quote change.

### 23 GHSA-43X4-G22P-3HRQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 623
- Summary: OpenClaw: Chrome --no-sandbox disabled OS-level browser sandbox in sandbox browser container
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI cc3c25e4 applies oxfmt 0.32.0 whitespace. Fix forces sandbox browser hash migration. Deeper blame attributed zero AI lines. Two-line formatter overlap in browser.ts is not --no-sandbox origin.

### 24 GHSA-P3HX-PWF3-J8WR — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `nautobot/nautobot`
- Rank: 624
- Summary: Nautobot: GitRepository.current_head field should not be writable through REST API
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ac10784e adds wireless models. Fix is a merge-from-fork making current_head read-only. Deeper blame attributed zero AI lines. test_api.py overlap is routing. Shared SHA with GHSA-C35Q does not imply current_head writability origin.

### 25 GHSA-Q8QP-CVCW-X6JJ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `axios/axios`
- Rank: 625
- Summary: Axios has prototype pollution read-side gadgets in HTTP adapter that allow credential injection and request hijacking
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6ef867e6 clarifies empty proxy-authorization error messages. Fix hardens header-pollution gadgets. Deeper blame attributed zero AI lines. http.js overlap is routing, not prototype-pollution gadget origin.

### 26 GHSA-2PR2-HCV6-7GWV — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 626
- Summary: OpenClaw's device removal and token revocation do not terminate active WebSocket sessions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0f1388fa hot-reloads channelHealthCheckMinutes without a full restart. Fix disconnects revoked device sessions. Deeper blame attributed zero AI lines. server.impl.ts overlap is routing, not session-revocation origin.

### 27 GHSA-RF6H-5GPW-QRGQ — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 627
- Summary: OpenClaw: MS Teams Feedback Invocation Bypasses Sender Allowlists and Records Unauthorized Session Feedback
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 8c852d86 fetches Teams thread history via Graph API. Fix aligns feedback invoke authorization. Deeper blame attributed eight lines to a different SHA 897cda7d in message-handler.ts, not the ranked Graph-history commit. Shared file without mechanism equality is not feedback-allowlist origin.

### 28 GHSA-FXC7-FM93-6Q77 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `ArcadeData/arcadedb`
- Rank: 628
- Summary: ArcadeDB vulnerable to cross-database authorization bypass and unsecured newly-created databases
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 1a2273b3 refactors index replication. Fix enforces per-database access in the HTTP command handler. Deeper blame attributed zero AI lines. LocalDocumentType.java overlap is routing, not HTTP cross-database auth origin.

### 29 GHSA-C35Q-VXRP-PH26 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `nautobot/nautobot`
- Rank: 629
- Summary: Nautobot: Webhook definitions could be used for server-side request forgery (SSRF)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ac10784e is the same wireless-models commit as GHSA-P3HX. Fix is a merge-from-fork against webhook SSRF. Deeper blame attributed zero AI lines. settings.py overlap is routing. Shared SHA without mechanism equality is not webhook SSRF origin.

### 30 GHSA-QRCH-52M5-VV85 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `flightphp/core`
- Rank: 630
- Summary: Flight vulnerable to sensitive information disclosure via default error handler
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 82daf71d applies code-review suggestions in Request.php. Fix hardens the default Engine error handler. Deeper blame attributed zero AI lines. Request.php overlap is routing, not default error-handler disclosure origin.

## Conservation

- rank_pool 3473 = 600 prior directroot reviews + 30 this slice + 200 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch20: 600; this slice 601-630
- Incoming unreviewed hits before this slice: 230; after: 200
- Stale 260813 batch3 equals formal 260814 batch3 (30 IDs) and is not 30 extra reviewed rows
- Unreviewed remaining IDs are UNREVIEWED, not REJECT
- Checkpoint at 75 percent recorded before the final seven rows, then the assigned slice was exhausted

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD. Two deeper-blame hits (GHSA-X6P3 test coverage lines; GHSA-RF6H a different SHA in message-handler.ts) still fail ai_hunk and but-for. GHSA-68F8 also fails fix_reversal because the ranked pair never touches /v1/models operator-read scope.
