# Direct-root mining batch 16 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical73 and directroot batches 1-15, including frozen in-progress batch15 selection. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 350
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 450+30+350+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical73 strict identities plus batch1-15 `selected-30.jsonl`/`cases.jsonl`, including frozen in-progress batch15. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-J9WQ-VXXC-94WF — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `benoitc/hackney`
- Rank: 451
- Summary: Hackney has CR/LF injection in query parameter
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 422f4363 uses ssl_opts/2 for cacertfile handling in hackney_conn. Fix ca73dd0a rejects CR/LF/NUL in the request target. Deeper blame attributed zero AI lines. hackney_conn.erl overlap is routing, not query CR/LF injection origin.

### 02 GHSA-CH57-39Q2-4CRM — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `zenitraM/malla`
- Rank: 452
- Summary: malla: Stored XSS via Meshtastic node names in multiple frontend pages
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a086530f adds a chat feature. The first-party advisory names stored XSS of MQTT node names across pre-existing templates (traceroute_graph.html, map.html, and others) with introduced:0. Fix 4086e2b5 rewrites many templates plus chat.js. Deeper blame attributed 80 AI lines only in chat.js. Chat is an additional sibling renderer, not but-for origin of the multi-page node-name XSS.

### 03 GHSA-HVQH-JW65-WCPQ — REJECT `OLD_BUG_REFACTOR`

- Repository: `devbridge/jQuery-Autocomplete`
- Rank: 453
- Summary: devbridge-autocomplete has XSS in its default formatters: formatGroup and formatResult fail to escape HTML in untrusted inputs
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e1e8a444 rewrites ES5 autocomplete into TypeScript and states the 31-spec suite is an unmodified behavior contract. Parent src/jquery.autocomplete.js already had unescaped formatGroup/formatResult. Fix 63ff096f escapes category and value. Deeper blame attributed two AI lines in the moved format.ts. Preserving the old unescaped formatters is not XSS origin.

### 04 GHSA-533Q-W4G6-5586 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `psi-4ward/psitransfer`
- Rank: 454
- Summary: PsiTransfer: Upload PATCH path traversal can create config.<NODE_ENV>.js and lead to code execution on restart
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d1ffc377 disables HTTP compression on the file download route. Fix 8b547bf3 hardens file uploads. Deeper blame attributed zero AI lines. endpoints.js overlap is routing, not PATCH upload traversal origin.

### 05 GHSA-3WW4-5JV9-J5GM — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vllm-project/vllm`
- Rank: 455
- Summary: vLLM's Artifact Pin Decay allows pinned deployments to load unpinned code, weights, and processors
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a2812bec adds Cohere Eagle/MoE model support. Fix d26a28ab propagates revision/code_revision pins. Deeper blame attributed zero AI lines. registry.py overlap is routing, not artifact-pin decay origin.

### 06 GHSA-Q8GQ-377P-JQ3R — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vllm-project/vllm`
- Rank: 456
- Summary: vLLM: Security Check Bypass via assert Statement in Activation Function Loading Allows Arbitrary Code Execution
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 1a7894db replaces Optional[X] with X | None. Fix b3c7ffca replaces assert with exceptions in pooling. Deeper blame attributed zero AI lines. pooling_params.py overlap is a sibling path, not activation-function loading assert bypass origin.

### 07 GHSA-JQ2F-59PJ-P3M3 — REJECT `COMMIT_ONLY_CHANGE`

- Repository: `craftcms/cms`
- Rank: 457
- Summary: Craft CMS has a Missing Authorization Check on User Group Removal via save-permissions Action
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5aa4db3c deletes an unused @throws BadRequestHttpException annotation. Fix b1353848 addresses missing authorization on user-group removal. Deeper blame attributed zero AI lines. A docstring annotation deletion is not missing-auth origin.

### 08 GHSA-FJRM-76X2-C4Q4 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `latchset/jwcrypto`
- Rank: 458
- Summary: JWCrypto: JWE ZIP decompression bomb
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9de81ec3 makes HMAC key-length enforcement optional. Fix 25db861d limits JWE decompression plaintext size. Deeper blame attributed zero AI lines. tests.py overlap is routing, not ZIP bomb origin.

### 09 GHSA-PF3H-QJGV-VCPR — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vllm-project/vllm`
- Rank: 459
- Summary: vLLM: Server-Side Request Forgery (SSRF) in download_bytes_from_url
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI cf88b237 checks HTTP status in batch read_file. Fix 57861ae4 hardens SSRF in download_bytes_from_url. Deeper blame attributed zero AI lines. Status-code checking is not SSRF origin; residual URL fetch is an untouched sibling.

### 10 GHSA-F37V-82C4-4X64 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `electron/electron`
- Rank: 460
- Summary: Electron: Crash in clipboard.readImage() on malformed clipboard image data
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 227cc02a bumps Chromium. Fix a48f03fb guards clipboard.readImage on malformed image data. Deeper blame attributed zero AI lines. electron_api_clipboard.cc overlap is routing, not clipboard crash origin.

### 11 GHSA-926X-3R5X-GFHW — REJECT `SIBLING_FIX`

- Repository: `langchain-ai/langchain`
- Rank: 461
- Summary: LangChain has incomplete f-string validation in prompt templates
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 46971447 filters empty content blocks from formatted prompts. Fix af2ed47c adds more template sanitization. Deeper blame attributed zero AI lines. Empty-block filtering is a sibling prompt change, not incomplete f-string validation origin.

### 12 GHSA-3MWP-WVH9-7528 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vllm-project/vllm`
- Rank: 462
- Summary: vLLM: Unauthenticated OOM Denial of Service via Unbounded n Parameter in OpenAI API Server
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7acaea63 adds an in-tree AMD Zen CPU backend. Fix b111f8a6 caps n via VLLM_MAX_N_SEQUENCES. Deeper blame attributed zero AI lines. envs.py overlap is routing, not unbounded-n OOM origin.

### 13 GHSA-XJ9W-5R6Q-X6V4 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 463
- Summary: OpenClaw: Device-Paired Node Skips Node Scope Gate to Host RCE
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 20523b91 allows trusted-proxy Control UI auth to skip device pairing. Fix 3886b65e requires node pairing before node commands. Deeper blame attributed zero AI lines. message-handler.ts overlap is a sibling auth path, not node-scope-gate skip origin.

### 14 GHSA-92JP-89MQ-4374 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 464
- Summary: OpenClaw: Sandbox noVNC helper route exposed interactive browser session credentials
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 83825933 adds Discord media dedup in the messaging tool pipeline. Fix 8dfbf326 gates sandbox noVNC helper auth. Deeper blame attributed zero AI lines. types.ts overlap is routing, not noVNC credential exposure origin.

### 15 GHSA-G2HM-779G-VM32 — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `openclaw/openclaw`
- Rank: 465
- Summary: OpenClaw: Heartbeat owner downgrade missed untrusted webhook wake events
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 2806f2b8 adds isolatedSession for heartbeat runs. Fix 31281bc9 forces owner downgrade for untrusted hook:wake events. Deeper blame attributed zero AI lines. Isolated-session reuse is not a proved patch-delta of the missed webhook-wake downgrade; residual wake handling is an untouched sibling.

### 16 GHSA-GFC2-9QMW-W7VH — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `nicolargo/glances`
- Rank: 466
- Summary: Glances: Cross-Origin Information Disclosure via Unauthenticated REST API (/api/4) due to Permissive CORS
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7b200f00 adds MCP server support to the web server. Fix fdfb977b tightens CORS on the unauthenticated REST API. Deeper blame attributed zero AI lines. glances_restful_api.py overlap is a sibling feature, not permissive-CORS origin.

### 17 GHSA-V3QC-WRWX-J3PW — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 467
- Summary: OpenClaw: Agentic Consent Bypass — LLM Agent Can Silently Disable Exec Approval via config.patch
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ab4a08a8 defers gateway restart until replies are sent and refactors gateway-tool delivery extraction. Fix 76411b2a blocks protected tools.exec.ask/security writes. Deeper blame attributed one AI line in gateway-tool.ts. Restart deferral is not config.patch consent-bypass origin; config.patch existed before.

### 18 GHSA-2VHW-Q7VH-7XV2 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `jahlives/openssl_encrypt`
- Rank: 468
- Summary: openssl-encrypt's readiness endpoint leaks database error details to unauthenticated callers
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI b835baad adds database query timeouts. Fix 7aa8787f replaces str(e) on /ready. Deeper blame attributed one line to a different SHA 8170b3e0 (unified FastAPI server), not the ranked timeout commit. Shared file without mechanism equality is not readiness-leak origin.

### 19 GHSA-4W7W-66W2-5VF9 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vitejs/vite`
- Rank: 469
- Summary: Vite Vulnerable to Path Traversal in Optimized Deps .map Handling
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d65a9831 improves malformed URL handling in middlewares. Fix 79f002f2 avoids path traversal in the optimize-deps sourcemap handler. Deeper blame attributed zero AI lines. transform.ts overlap is a sibling middleware, not optimized-deps .map traversal origin.

### 20 GHSA-3XXC-PWJ6-JGRJ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `trailofbits/rfc3161-client`
- Rank: 470
- Summary: rfc3161-client Has Improper Certificate Validation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ab45f1d2 migrates type checking to ty. Fix 4f7d3722 is a merge-from-fork of certificate validation. Deeper blame attributed zero AI lines. test_verify.py overlap is routing, not improper certificate-validation origin.

### 21 GHSA-MVVV-V22X-XQWP — REJECT `SIBLING_FIX`

- Repository: `nocobase/nocobase`
- Rank: 471
- Summary: NocoBase has SSRF in Workflow HTTP Request and Custom Request Plugins
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 821b0f5c fixes a formula.js engine security issue. Fix 28533682 adds server-request security to the workflow-request plugin. Deeper blame attributed zero AI lines. utils index.ts overlap is a sibling evaluator fix, not workflow HTTP SSRF origin.

### 22 GHSA-WG4G-395P-MQV3 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `czlonkowski/n8n-mcp`
- Rank: 472
- Summary: n8n-MCP: Sensitive MCP tool-call arguments logged on authenticated requests in HTTP mode
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 7b3ccb10 is a staging QA bundle (get_node version modes, rewireConnection, search_templates). Fix 59b665bd is a merge-from-fork of log redaction. Deeper blame attributed 22 lines to other SHAs 3fec6813 and 87f26eef in server.ts, not the ranked QA commit. Shared file without mechanism equality is not tool-argument logging origin.

### 23 GHSA-GJ9Q-8W99-MP8J — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 473
- Summary: OpenClaw: TOCTOU read in exec script preflight
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 3b3191ab skips gateway cwd injection for remote node host. Fix b024fae9 replaces TOCTOU check-then-read with a pinned-fd open. Deeper blame attributed zero AI lines. cwd-injection skip is routing, not exec-script TOCTOU origin.

### 24 GHSA-GFG9-5357-HV4C — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 474
- Summary: OpenClaw: Webchat audio embedding could read local files without local-root containment
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c9449d77 persists webchat inbound images to disk. Fix 6e58f1f9 enforces localRoots on the webchat audio embedding path. Deeper blame attributed zero AI lines. Image persistence is a sibling path, not audio-embedding LFI origin.

### 25 GHSA-PQF5-4PQQ-29F5 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `rust-openssl/rust-openssl`
- Rank: 475
- Summary: rust-openssl: Deriver::derive and PkeyCtxRef::derive can overflow short buffers on OpenSSL 1.1.1
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6c9a993c updates OpenSSL documentation URLs. Fix 09b425e5 checks derive output buffer length on OpenSSL 1.1.x. Deeper blame attributed zero AI lines. derive.rs overlap is routing, not short-buffer overflow origin.

### 26 GHSA-XMGF-HQ76-4VX2 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `rust-openssl/rust-openssl`
- Rank: 476
- Summary: rust-openssl has an Out-of-bounds read in PEM password callback when returning an oversized length
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 327f8b4e bumps the minimum OpenSSL version to 1.0.2. Fix 5af6895c rejects oversized password-callback lengths. Deeper blame attributed zero AI lines. ec.rs overlap is routing, not PEM password-callback OOB origin.

### 27 GHSA-J88V-2CHJ-QFWX — REJECT `COMMIT_ONLY_CHANGE`

- Repository: `jackc/pgx`
- Rank: 477
- Summary: pgx: SQL Injection via placeholder confusion with dollar quoted string literals
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e196a39a adds a fuzz test for the SQL lexer. Fix 60644f84 fixes dollar-quoted strings and placeholder overflow in the sanitizer. Deeper blame attributed zero AI lines. sanitize_fuzz_test.go overlap is a test-only change, not dollar-quote SQLi origin.

### 28 GHSA-4RH7-JWG9-M28M — REJECT `INCOMPLETE_FIX_REVERSAL`

- Repository: `jahlives/openssl_encrypt`
- Rank: 478
- Summary: openssl-encrypt accepts refresh tokens as URL query parameters causing token leakage
- Failing gates: fix_reversal_gate, release_gate
- Counterevidence: Ranked AI cdc9c7d8 added /refresh endpoints that take refresh_token via FastAPI Query in both keyserver and telemetry routes, with an explicit AI marker. The first-party advisory names both files. Cited fix 4b2adb0 only moves telemetry to POST Body and leaves keyserver Query intact. Clone has no release tags; openssl_encrypt_server was later removed. Incomplete reversal of the advisory invariant plus unproved release containment cannot close all seven gates.

### 29 GHSA-XW45-CC32-442F — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `ellanetworks/core`
- Rank: 479
- Summary: Ella Core Has Audit Log Falsification via Path/Body IMSI Mismatch in UpdateSubscriber
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6fc24601 adds pprof endpoints. Fix 7f64b7a7 addresses path/body resource-name mismatch on API PUT. Deeper blame attributed zero AI lines. api_data_networks_test.go overlap is routing, not UpdateSubscriber IMSI mismatch origin.

### 30 GHSA-R4FG-73RC-HHH7 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `go-vikunja/vikunja`
- Rank: 480
- Summary: Vikunja has Algorithmic Complexity DoS in Repeating Task Handler
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9712dbe2 maps MySQL task-bucket duplicates from HTTP 500 to 400. Fix 6df0d6c8 caps repeat_after at 10 years. Deeper blame attributed zero AI lines. error.go overlap is routing, not repeating-task DoS origin.

## Conservation

- rank_pool 3473 = 450 prior directroot reviews + 30 this slice + 350 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch15: 450; this slice 451-480
- Incoming unreviewed hits before this slice: 380; after: 350
- Stale 260813 batch3 equals formal 260814 batch3 (30 IDs) and is not 30 extra reviewed rows
- Unreviewed remaining IDs are UNREVIEWED, not REJECT

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD.
