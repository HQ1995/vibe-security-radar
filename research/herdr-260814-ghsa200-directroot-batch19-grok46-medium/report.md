# Direct-root mining batch 19 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical78 and directroot batches 1-18, including frozen in-progress batch17 and batch18 selections. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 260
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 540+30+260+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical78 strict identities plus batch1-18 `selected-30.jsonl`/`cases.jsonl`, including frozen in-progress batch17 and batch18. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-WM8R-W8PF-2V6W — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 541
- Summary: OpenClaw has Signal group allowlist authorization bypass via DM pairing-store leakage
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI caf5d2dd adds Matrix multi-account support. Fix enforces explicit group auth boundaries across channels. Deeper blame attributed zero AI lines. handler.ts overlap is routing, not Signal DM pairing-store leakage origin.

### 02 GHSA-4HMJ-39M8-JWC7 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 542
- Summary: OpenClaw has ACP CLI approval prompt ANSI escape sequence injection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 63c6080d cleans stale gateway PIDs before launchctl/systemctl restart and uses Made-with Cursor rather than a Co-authored-by marker. Fix sanitizes ACP terminal tool titles. Deeper blame attributed zero AI lines. restart.test.ts overlap is routing, not ACP ANSI injection origin.

### 03 GHSA-3PXQ-F3CP-JMXP — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `openclaw/openclaw`
- Rank: 543
- Summary: OpenClaw: Unified root-bound write hardening for browser output and related path-boundary flows
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5e3502df prefixes sandbox fs-bridge paths so leading hyphens are not shell options. Fix replaces check-then-rename browser output commits with root-bound fd-verified writes. Deeper blame attributed zero AI lines. Hyphen-option hardening is a sibling path-safety change, not root-bound write origin.

### 04 GHSA-PJVX-RX66-R3FG — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 544
- Summary: OpenClaw: Cross-account sender authorization expansion in `/allowlist ... --store` account scoping
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 481bd333 handles AbortError and transient network errors on the gateway. Fix scopes allowlist store writes by account. Deeper blame attributed zero AI lines. commands.test.ts overlap is routing, not allowlist --store account-scoping origin.

### 05 GHSA-G86V-F9QV-RH6M — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `openclaw/openclaw`
- Rank: 545
- Summary: OpenClaw SSRF guard misses four IPv6 special-use ranges
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI dd9ba974 sorts IPv4 before IPv6 in SSRF pinned DNS for Telegram media fetch. Fix blocks missing IPv6 special-use ranges in ip.ts. Deeper blame attributed four AI lines only in ssrf.pinning.test.ts fixture addresses. IPv4 preference sorting is not the IPv6 special-use classifier origin.

### 06 GHSA-474H-PRJG-MMW3 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 546
- Summary: OpenClaw: Sandboxed sessions_spawn(runtime="acp") bypassed sandbox inheritance and allowed host ACP initialization
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5710d725 adds configurable default runTimeoutSeconds for subagent spawns. Fix enforces ACP sandbox inheritance for sessions_spawn. Deeper blame attributed zero AI lines. subagent-spawn.ts overlap is routing, not ACP sandbox-inheritance origin.

### 07 GHSA-47Q7-97XP-M272 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 547
- Summary: OpenClaw: Config writes could persist resolved ${VAR} secrets to disk
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 961b4adc deprecates query-param hook token auth. Fix hardens hook and device token auth. Deeper blame attributed zero AI lines. server-http.ts overlap is a sibling token-auth path, not resolved-secret persistence origin.

### 08 GHSA-J48Q-4C78-RHF9 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `jahlives/openssl_encrypt`
- Rank: 548
- Summary: openssl-encrypt: Dynamic .so loading for Whirlpool uses broad glob pattern without integrity verification
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 69885685 adds Flatpak packaging and extra site-package paths. Fix validates .so realpaths inside site-packages. Deeper blame attributed three lines to a different SHA cb07e5f8 in setup_whirlpool.py, not the ranked Flatpak commit. Shared file without mechanism equality is not glob-load origin. Advisory also names hash_registry.py.

### 09 GHSA-CVWP-R2G2-J824 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `nicolargo/glances`
- Rank: 549
- Summary: Glances has Incomplete Secrets Redaction: /api/v4/args Endpoint Leaks Password Hash and SNMP Credentials
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7b200f00 adds MCP server support to the web server. Fix merges args-endpoint secret redaction. Deeper blame attributed zero AI lines. glances_restful_api.py overlap is a sibling feature, not /api/v4/args redaction origin.

### 10 GHSA-MW7W-G3MG-XQM7 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 550
- Summary: OpenClaw: BlueBubbles Group Reactions Bypass requireMention and Still Enqueue Agent-Visible System Events
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f92c9251 routes fetch calls through fetchWithSsrFGuard. Fix honors BlueBubbles reaction mention gating. Deeper blame attributed zero AI lines. monitor-processing.ts overlap is routing, not reaction requireMention origin.

### 11 GHSA-VP96-HXJ8-P424 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `pyca/pyopenssl`
- Rank: 551
- Summary: pyOpenSSL allows TLS connection bypass via unhandled callback exception in set_tlsext_servername_callback
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 35b55a3b fixes test_wantWriteError on macOS. Fix handles exceptions in set_tlsext_servername_callback. Deeper blame attributed zero AI lines. test_ssl.py overlap is routing, not SNI callback exception-bypass origin.

### 12 GHSA-J4C9-W69R-CW33 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 552
- Summary: OpenClaw: Telegram DM-Scoped Inline Button Callbacks Bypass DM Pairing and Mutate Session State
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d264c761 adds allow_sending_without_reply to prevent lost Telegram messages. Fix enforces DM auth for callbacks. Deeper blame attributed zero AI lines. bot-handlers.runtime.ts overlap is a sibling Telegram path, not callback pairing-bypass origin.

### 13 GHSA-8MF7-VV8W-HJR2 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 553
- Summary: OpenClaw's tools.exec.safeBins generic fallback allowed interpreter-style inline payload execution in allowlist mode
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 06b961b0 flattens remaining anyOf/oneOf in Gemini schema cleaning. Fix requires explicit safe-bin profiles. Deeper blame attributed zero AI lines. pi-tools.ts overlap is routing, not interpreter-style safeBins origin.

### 14 GHSA-FF98-W8HJ-QRXF — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 554
- Summary: OpenClaw plugin runtime command execution is part of trusted plugin boundary
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 483fba41 adds Discord exec-approval forwarding and the text /approve command. Fix restores trusted plugin runtime exec default. Deeper blame attributed zero AI lines. zod-schema.ts overlap is a two-line import, not plugin runtime exec origin. Shared SHA with GHSA-98HH does not imply mechanism equality.

### 15 GHSA-5CXW-W2XG-2M8H — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `trailofbits/fickling`
- Rank: 555
- Summary: fickling's `platform` module subprocess invocation evades `check_safety()` with `LIKELY_SAFE`
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9a6d03fb adds inspect to UNSAFE_IMPORTS. Fix adds platform to the same pre-existing denylist. Deeper blame attributed zero AI lines. Inspect vs platform are sibling denylist entries; the GHSA residual is the untouched platform hole (introduced:0), not a patch-delta of the inspect addition. Clone has no release tags.

### 16 GHSA-425G-FJHQ-5H92 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `jahlives/openssl_encrypt`
- Rank: 556
- Summary: openssl-encrypt silently skips schema validation when jsonschema library is not installed
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 2a8f4d45 registers metadata v10/v11 schemas. Fix raises when jsonschema is missing. Deeper blame attributed four lines to a different SHA a3d7f417 in json_validator.py, not the ranked schema-version commit. Silent skip existed before the v10/v11 mapping. Shared file without mechanism equality is not fail-closed validation origin.

### 17 GHSA-98HH-7GHG-X6RQ — REJECT `UNRELEASED_CONTAINMENT`

- Repository: `openclaw/openclaw`
- Rank: 557
- Summary: OpenClaw: Discord text `/approve` bypasses `channels.discord.execApprovals.approvers` and allows non-approvers to resolve pending exec approvals
- Failing gates: release_gate
- Counterevidence: Ranked AI 483fba41 newly authors commands-approve.ts /approve without Discord approver checks, with an explicit Claude marker, and the later fix adds isDiscordExecApprovalApprover on that same handler. Scoped but-for and fix-reversal hold for the text-approve surface. Clone git tag --contains is empty for both SHAs, so release containment is unproved. Seven exact PASS gates are required; this is not countable.

### 18 GHSA-V9VM-R24H-6RQM — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `gogs/gogs`
- Rank: 558
- Summary: Gogs: Release tag option injection in release deletion
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI a1fa62b2 decouples API types from go-gogs-client. Fix uses a safe git-module API for tag deletion. Deeper blame attributed one line to a different SHA 4ee706b2 in release.go, not the ranked SDK decoupling commit. Shared file without mechanism equality is not tag-option injection origin.

### 19 GHSA-89XV-2J6F-QHC8 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `modelcontextprotocol/go-sdk`
- Rank: 559
- Summary: Cross-Site Tool Execution for HTTP Servers without Authorizatrion in github.com/modelcontextprotocol/go-sdk
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4e8b6ca1 returns 400 instead of 500 when body read fails in stateless mode. Fix verifies Origin and Content-Type headers. Deeper blame attributed zero AI lines. streamable.go overlap is routing, not missing Origin/Content-Type CSRF origin.

### 20 GHSA-QHRR-GRQP-6X2G — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 560
- Summary: OpenClaw's tools.exec.safeBins trusted PATH directories allowed binary shadowing in allowlist mode
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 06b961b0 is the same Gemini schema-flattening commit as GHSA-8MF7. Fix hardens safe-bin trusted directories. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not PATH-shadowing origin.

### 21 GHSA-MQ59-M269-XVCX — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vercel/next.js`
- Rank: 561
- Summary: Next.js: null origin can bypass Server Actions CSRF checks
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fa56f2c1 stops revalidateTag with profile from triggering client cache invalidation. Fix disallows Server Action submissions from privacy-sensitive contexts. Deeper blame attributed zero AI lines. action-handler.ts overlap is routing, not null-origin CSRF origin.

### 22 GHSA-792Q-QW95-F446 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `openclaw/openclaw`
- Rank: 562
- Summary: OpenClaw's Signal reaction-only status events could, in limited cases, be enqueued before access checks
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 1d46ca3a adds mention gating for Signal group messages. Fix enforces DM/group allowlist access before reaction-notification enqueue. Deeper blame attributed zero AI lines. Mention gating is a sibling Signal control, not reaction-before-access origin.

### 23 GHSA-3H52-CX59-C456 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 563
- Summary: OpenClaw: Feishu webhook reads and parses unauthenticated request bodies before signature validation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bd4237c1 closes Feishu WebSocket connections on monitor stop. Fix validates webhook signatures before parsing. Deeper blame attributed zero AI lines. monitor.transport.ts overlap is a sibling Feishu path, not parse-before-signature origin.

### 24 GHSA-667W-MMH7-MRR4 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `withstudiocms/studiocms`
- Rank: 564
- Summary: StudioCMS has Privilege Escalation via Insecure API Token Generation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 341b59e3 adds the auth-kit package. Fix adds admin token revocation and reverses availablePermissionRanks used by the new revoke comparator. Deeper blame attributed one AI line in types.ts. The first-party advisory is missing authorization on token generation for a target user ID; rank-order reversal on a new revoke path is not generation origin. Clone has no tags containing either SHA.

### 25 GHSA-WVXV-4J8Q-4WJQ — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `nicolargo/glances`
- Rank: 565
- Summary: Glances exposes the REST API without authentication
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7b200f00 is the same MCP web-server commit as GHSA-CVWP. Fix merges unauthenticated REST-API authentication. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not missing REST auth origin.

### 26 GHSA-QF48-QFV4-JJM9 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 566
- Summary: OpenClaw: Feishu extension resolveUploadInput bypasses file-system sandbox and allows arbitrary file reads via upload_image
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5f6e1c19 syncs Feishu multi-account support. Fix enforces localRoots on Feishu docx upload file reads. Deeper blame attributed zero AI lines. docx.ts overlap is a sibling Feishu feature, not upload_image sandbox-bypass origin.

### 27 GHSA-7P48-42J8-8846 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `streamlit/streamlit`
- Rank: 567
- Summary: Unauthenticated SSRF Vulnerability in Streamlit on Windows (NTLM Credential Exposure)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a2d93ce8 enforces type annotations for untyped Python functions. Fix prevents SSRF via path traversal in component file handling. Deeper blame attributed zero AI lines. app_static_file_handler.py overlap is routing, not Windows NTLM SSRF origin.

### 28 GHSA-X9P5-W45C-7FFC — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `gogs/gogs`
- Rank: 568
- Summary: Gogs: Access tokens get exposed through URL params in API requests
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4ee706b2 replaces pkg/errors with cockroachdb/errors. Fix rejects access tokens passed via URL query parameters. Deeper blame attributed zero AI lines. auth.go overlap is routing, not query-token exposure origin.

### 29 GHSA-GCJ7-R3HG-M7W6 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 569
- Summary: OpenClaw's voice-call Twilio replay dedupe now bound to authenticated webhook identity
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 48aea870 adds prek pre-commit hooks and dependabot. Fix binds webhook dedupe to verified request identity. Deeper blame attributed zero AI lines. plivo.test.ts/twilio webhook overlap is routing, not Twilio replay-dedupe origin.

### 30 GHSA-2858-XG23-26FP — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 570
- Summary: OpenClaw: Node camera URL payload host-binding bypass allowed gateway fetch pivots
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 47bb568c resolves the default node when multiple canvas-capable nodes are connected. Fix fail-closes node camera URL downloads. Deeper blame attributed zero AI lines. nodes-utils.ts overlap is routing, not camera URL host-binding origin.

## Conservation

- rank_pool 3473 = 540 prior directroot reviews + 30 this slice + 260 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch18: 540; this slice 541-570
- Incoming unreviewed hits before this slice: 290; after: 260
- Stale 260813 batch3 equals formal 260814 batch3 (30 IDs) and is not 30 extra reviewed rows
- Unreviewed remaining IDs are UNREVIEWED, not REJECT
- Checkpoint at 75 percent recorded before the final seven rows, then the assigned slice was exhausted

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD. GHSA-98HH-7GHG-X6RQ has five other exact PASS gates plus uniqueness/identity, but empty git tags fail release_gate, so it is not a countable proposal.
