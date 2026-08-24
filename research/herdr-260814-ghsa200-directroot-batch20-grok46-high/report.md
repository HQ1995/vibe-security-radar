# Direct-root mining batch 20 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical81 and directroot batches 1-19. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. Canonical81's three append identities already sit in batch9 and batch11, so they do not add extra ranked-hit skips. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 230
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 570+30+230+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical81 strict identities plus batch1-19 `selected-30.jsonl`/`cases.jsonl`. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-469J-VMHF-R6V7 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `nltk/nltk`
- Rank: 571
- Summary: NLTK has a Downloader Path Traversal Vulnerability (AFO) - Arbitrary File Overwrite
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 3bc1214f is a one-line Copilot stacklevel change in downloader.py. Fix is a merge adding subdir/id path validation. Deeper blame attributed zero AI lines. Advisory introduced:0. File overlap is routing, not XML index path-traversal origin.

### 02 GHSA-GQ2M-77HF-VWGH — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `OliveTin/OliveTin`
- Rank: 572
- Summary: OliveTin Session Fixation: Logout Fails to Invalidate Server-Side Session
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI aa2bd95c adds a show/hide version-number policy and uses Made-with Cursor rather than a Co-authored-by marker. Fix invalidates server-side sessions on logout. Deeper blame attributed zero AI lines. api.go overlap is routing, not session-revocation origin.

### 03 GHSA-2J3P-GQW5-G59J — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `AsfhtgkDavid/theshit`
- Rank: 573
- Summary: theshit's Improper Privilege Dropping Allows Local Privilege Escalation via Command Re-execution
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0fc1b4f7 is copilot-swe-agent timeout wrapping of get_command_output. Fix is a merge that moves that timeout scaffolding into output.rs while adding privilege-drop on re-exec. Deeper blame attributed 98 AI lines only in the timeout rewrite. Advisory introduced:0. Timeout wrapping is not privilege-drop origin. Clone git tag --contains is empty.

### 04 GHSA-F7WW-2725-QVW2 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 574
- Summary: OpenClaw: Node system.run approval bypass via parent-symlink cwd rebind
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 483fba41 adds Discord exec-approval forwarding, the same SHA as GHSA-HFPR and batch19 GHSA-98HH/GHSA-FF98. Fix centralizes system.run approval context. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not parent-symlink cwd origin.

### 05 GHSA-25PW-4H6W-QWVM — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 575
- Summary: OpenClaw has a BlueBubbles group allowlist mismatch via DM pairing-store fallback
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 48aea870 adds prek pre-commit hooks and dependabot, the same SHA as batch19 GHSA-GCJ7. Fix binds voice-call webhook dedupe. Deeper blame attributed zero AI lines. plivo.test.ts/twilio webhook overlap is routing, not BlueBubbles pairing-store origin.

### 06 GHSA-FQW4-MPH7-2VR8 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 576
- Summary: OpenClaw: Silent privilege escalation via gateway shared-auth reconnect
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 20523b91 allows trusted-proxy Control UI to skip device pairing, shared with GHSA-553V and GHSA-48VW. Fix blocks silent reconnect scope-upgrade. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not silent reconnect origin.

### 07 GHSA-QH6H-P6C9-FF54 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `langchain-ai/langchain`
- Rank: 577
- Summary: LangChain Core has Path Traversal vulnerabilites in legacy `load_prompt` functions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 46971447 filters empty content blocks from formatted prompts. Fix validates paths in prompt.save and load_prompt. Deeper blame attributed zero AI lines. chat.py overlap is routing; the advisory names loading.py path injection.

### 08 GHSA-87J9-M7X6-HVW2 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `ellanetworks/core`
- Rank: 578
- Summary: Ella Core has Privilege Escalation via Database Restore by NetworkManager role
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6fc24601 adds pprof profiling endpoints. Fix removes backup/restore permissions from NetworkManager. Deeper blame attributed zero AI lines. authorization_middleware.go overlap is routing, not restore-permission origin.

### 09 GHSA-3JX4-Q2M7-R496 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `openclaw/openclaw`
- Rank: 579
- Summary: OpenClaw: Hardlink alias checks could bypass workspace-only file boundaries in specific configurations
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5e3502df prefixes sandbox fs-bridge paths so leading hyphens are not shell options, the same SHA as batch19 GHSA-3PXQ. Fix blocks workspace hardlink alias escapes. Deeper blame attributed zero AI lines. Hyphen-option hardening is a sibling path-safety change, not hardlink-alias origin.

### 10 GHSA-P443-P7W5-2F7F — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `OliveTin/OliveTin`
- Rank: 580
- Summary: OliveTin's RestartAction always runs actions as guest
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI aa2bd95c is the same version-number policy commit as GHSA-GQ2M. Fix makes RestartAction preserve caller identity. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not RestartAction-as-guest origin.

### 11 GHSA-W5G8-5849-VJ76 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `zauberzeug/nicegui`
- Rank: 581
- Summary: NiceGUI's unvalidated chunk size parameter in media routes can cause memory exhaustion
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 2941a963 fixes .mjs MIME types on Windows. Fix validates the media-route chunk-size parameter. Deeper blame attributed zero AI lines. test_serving_files.py overlap is routing, not range-response chunk-size origin.

### 12 GHSA-H4JX-HJR3-FHGC — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 582
- Summary: OpenClaw: Gateway Plugin Subagent Fallback `deleteSession` Uses Synthetic `operator.admin`
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4cb8dde8 adds video-generation infrastructure and uses no Co-authored-by marker. Fix requires caller scope for subagent session deletion. Deeper blame attributed zero AI lines. server-plugins.test.ts overlap is routing, not synthetic operator.admin origin.

### 13 GHSA-39MP-8HJ3-5C49 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `gradio-app/gradio`
- Rank: 583
- Summary: Gradio is Vulnerable to Absolute Path Traversal on Windows with Python 3.13+
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 029034f7 is a 1264-file Gradio 6.0 mega-commit. Fix adjusts Windows absolute-path checks. Deeper blame attributed zero AI lines and blamed zero deleted spans. File-history without hunk identity is not isabs origin.

### 14 GHSA-9JFM-9RC6-2HFQ — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `nicolargo/glances`
- Rank: 584
- Summary: Glances's Default CORS Configuration Allows Cross-Origin Credential Theft
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7b200f00 adds MCP server support to the web server, the same SHA as GHSA-HHCG and batch19 GHSA-CVWP/GHSA-WVXV. Fix merges CORS credential restrictions. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not default-CORS origin.

### 15 GHSA-QMPG-8XG6-PH5Q — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `basecamp/trix`
- Rank: 585
- Summary: Trix has a Stored XSS vulnerability through serialized attributes
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bf389080 replaces Karma with @web/test-runner. Fix sanitizes serialized attributes. Deeper blame attributed zero AI lines and blamed zero deleted spans. Bundled trix.js overlap is routing, not stored-XSS origin.

### 16 GHSA-553V-F69R-656J — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 586
- Summary: OpenClaw unpaired device identity can bypass operator pairing and self-assign operator scopes with shared auth
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 20523b91 added trusted-proxy Control UI pairing skip and kept pre-existing skipPairingForOperatorSharedAuth. Fix deletes that shared-auth operator skip and keeps trustedProxyAuthOk. Deeper blame attributed one AI line in the skipPairing assignment, not shared-auth operator origin. Shared SHA with GHSA-FQW4/GHSA-48VW does not imply mechanism equality. Clone git tag --contains is empty.

### 17 GHSA-C7HF-C5P5-5G6H — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `louislam/uptime-kuma`
- Rank: 587
- Summary: Uptime Kuma is Missing Authorization Checks on Ping Badge Endpoint, Leaks Ping times of monitors without needing to be on a status page
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI cde96900 widens ping duration columns to BIGINT. Fix adds authorization on the ping badge endpoint. Deeper blame attributed zero AI lines. api-router.js overlap is routing, not missing badge-auth origin.

### 18 GHSA-VWMF-PQ79-VJVX — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `langflow-ai/langflow`
- Rank: 588
- Summary: Unauthenticated Remote Code Execution in Langflow via Public Flow Build Endpoint
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b5a6f397 adds Component Inputs telemetry. Fix blocks RCE via the data parameter on build_public_tmp. Deeper blame attributed zero AI lines. chat.py overlap is routing, not unauthenticated public-build origin.

### 19 GHSA-VR7J-G7JV-H5MP — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 589
- Summary: OpenClaw session transcript files were created without forced user-only permissions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c4e76eb6 enables image attachments in chat messages for the Claude API. Fix creates transcript files with 0o600 permissions. Deeper blame attributed zero AI lines. chat.ts overlap is routing, not transcript mode origin.

### 20 GHSA-WCCX-J62J-R448 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `trailofbits/fickling`
- Rank: 590
- Summary: Fickling has `always_check_safety()` bypass: pickle.loads and _pickle.loads remain unhooked
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 87146271 is an explicit Claude security attempt that hooks pickle.Unpickler for PyTorch v1.3+. Fix adds pickle.loads, _pickle.load, and _pickle.loads to the same run_hook(). Those function entry points were already unhooked before the Unpickler addition, so the residual is an untouched sibling hole rather than a patch-delta of the AI boundary. Deeper blame attributed one AI line. Clone git tag --contains is empty.

### 21 GHSA-G9F6-9775-HFFM — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `nhost/nhost`
- Rank: 591
- Summary: Nhost Storage Affected by MIME Type Spoofing via Trusted Client Content-Type Header in Storage Upload
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 80664ef8 improves image processing and resource management. Fix always detects MIME type instead of trusting the client Content-Type. Deeper blame attributed zero AI lines. upload_files.go overlap is a sibling upload-path change, not MIME-spoof origin.

### 22 GHSA-V2X6-WWFW-R2RQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `agentgateway/agentgateway`
- Rank: 592
- Summary: Agentgateway is missing parameter sanitization in MCP to OpenAPI conversion
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c4902ec6 adds listener-level config tuning. Fix sanitizes MCP-to-OpenAPI path, query, and header handling. Deeper blame attributed zero AI lines. openapi/mod.rs overlap is routing, not parameter-sanitization origin.

### 23 GHSA-48VW-M3QC-WR99 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `openclaw/openclaw`
- Rank: 593
- Summary: OpenClaw's Trusted-proxy Control UI sessions retain privileged scopes without device identity on device-less allow paths
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 20523b91 added trusted-proxy pairing skip onto a pre-existing Control UI device-less allow exception that skipped clearUnboundScopes. Fix amends that exception with trustedProxyAuthOk rather than reversing skip-pairing. Deeper blame attributed zero AI lines. New-surface routing onto an old hole is not seven-gate direct-root. Shared SHA with GHSA-553V/GHSA-FQW4. Clone git tag --contains is empty.

### 24 GHSA-WJ55-88GF-X564 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 594
- Summary: OpenClaw may have stale policy enforcement for queued node actions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d00d814a includes platform and reason in node command rejection errors. Fix rechecks queued actions before delivery. Deeper blame attributed zero AI lines. nodes.ts overlap is routing, not stale queued-policy origin.

### 25 GHSA-354R-7MFH-7RH2 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 595
- Summary: OpenClaw: Discord DM reaction ingress missed dmPolicy/allowFrom checks in restricted setups
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d3c71875 caps Discord gateway reconnect at 50 attempts. Fix hardens Discord and Slack reaction ingress authorization. Deeper blame attributed zero AI lines. provider.ts overlap is routing, not DM reaction dmPolicy origin.

### 26 GHSA-X2CM-HG9C-MF5W — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 596
- Summary: OpenClaw leaf subagents can bypass controlScope restrictions to send messages to child sessions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 481bd333 handles AbortError and transient network errors, the same SHA as batch19 GHSA-PJVX. Fix restricts subagent follow-up messaging scope. Deeper blame attributed zero AI lines. commands.test.ts overlap is routing, not controlScope origin.

### 27 GHSA-HFPR-JHPQ-X4RM — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 597
- Summary: OpenClaw: `operator.write` chat.send could reach admin-only config writes
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 483fba41 is the same Discord exec-approval commit as GHSA-F7WW. Fix requires admin for chat config writes. Deeper blame attributed zero AI lines. commands-approve.ts overlap is routing, not operator.write config-write origin.

### 28 GHSA-HHCG-R27J-FHV9 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `nicolargo/glances`
- Rank: 598
- Summary: Glances's REST/WebUI Lacks Host Validation and Remains Exposed to DNS Rebinding
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7b200f00 is the same MCP web-server commit as GHSA-9JFM. Fix merges host validation against DNS rebinding. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not missing Host-header origin.

### 29 GHSA-Q2QC-744P-66R2 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 599
- Summary: OpenClaw: `session_status` sessionId resolution bypasses sandboxed session-tree visibility
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0f342553 ignores local identity files. Fix enforces the session_status guard after sessionId resolution. Deeper blame attributed zero AI lines. session-status-tool.ts overlap is routing, not session-tree visibility origin.

### 30 GHSA-QJ22-XQJR-V83V — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 600
- Summary: OpenClaw's Telegram message_reaction authorization bypass allows unauthorized system-event injection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 506bed5a adds Telegram sticker support with vision caching. Fix enforces Telegram reaction authorization. Deeper blame attributed zero AI lines. bot-handlers.ts overlap is a sibling Telegram path, not message_reaction auth origin.

## Conservation

- rank_pool 3473 = 570 prior directroot reviews + 30 this slice + 230 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch19: 570; this slice 571-600
- Incoming unreviewed hits before this slice: 260; after: 230
- Canonical81 append identities GHSA-X4HG-HFWF-P9MW, GHSA-322X-V876-G883, and GHSA-PMCH-G965-GRMR were already in batch9 and batch11
- Stale 260813 batch3 equals formal 260814 batch3 (30 IDs) and is not 30 extra reviewed rows
- Unreviewed remaining IDs are UNREVIEWED, not REJECT
- Checkpoint at 75 percent recorded before the final seven rows, then the assigned slice was exhausted

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD. GHSA-WCCX-J62J-R448 is an explicit AI security-hook attempt, but the GHSA residual is pre-existing unhooked pickle.loads family entry points, so incomplete-remediation patch-delta fails. Empty git tags also leave release_gate unproved.
