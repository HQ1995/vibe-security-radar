# Direct-root mining batch 7 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly the next 30 highest-score unassigned rank hits after canonical73 plus directroot batches 1-6. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 620
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 180+30+620+2643=3473 rank_pool

## Selection

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending (equals original ranks 1-830). Excluded every GHSA in canonical73 strict IDs and in batch1-batch6 selected-30/cases artifacts. Overlap with each excluded set is zero. Assigned original ranks 181-210. Selection recorded in `work/selected-30.jsonl` before review.

## Method

Each row used the frozen github-reviewed advisory JSON, the ranked AI SHA and fix SHA, first-parent `git log`/`diff`, and deeper `git blame -l -w` of source deleted hunks on the fix parent against the AI-commit index. File-history overlap without blamed deleted lines remains routing. Incomplete-remediation security attempts stay out of this direct-root lane unless all patch-delta clauses pass. Shared SHAs without mechanism equality are rejected.

## Cases

### 01 GHSA-767M-XRHC-FXM7 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 181
- Summary: OpenClaw: Gateway operator.write can reach admin-class Telegram config and cron persistence
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6b4c24c2 adds Telegram custom apiRoot. Fix b7d70ade gates Telegram writeback admin scope. Deeper blame of deleted source hunks attributed zero AI-marked lines. File overlap on telegram send/channel is routing, not origin of operator.write privilege.

### 02 GHSA-RM5C-4RMF-VVHW — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 182
- Summary: OpenClaw: Sandbox file operations use check-then-act, bypassing fd-based TOCTOU defenses
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f5c2be19 distinguishes outside-workspace errors from not-found in fs-safe. Fix 32a4a47d pins apply-patch workspace mutations. Deeper blame attributed zero AI lines. Error-message hygiene is not but-for origin of TOCTOU apply-patch.

### 03 GHSA-2W79-R9G8-WMCR — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `openclaw/openclaw`
- Rank: 183
- Summary: OpenClaw: Voice-call still parses large WebSocket frames before start validation (incomplete remediation)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: First-party summary labels incomplete remediation. Ranked AI 101d0f45 queues TTS to prevent audio overlap. Fix 9abcfdad rejects oversized pre-start media frames. Deeper blame attributed zero AI lines. Residual frame-size guard is an untouched sibling path, not AI_DIRECT_ROOT hunk identity.

### 04 GHSA-57R2-H2WJ-G887 — REJECT `NO_AI_MARKER`

- Repository: `openclaw/openclaw`
- Rank: 184
- Summary: OpenClaw: Isolated cron awareness events were recorded as trusted system events
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked commit 905e56d1 treats zero nextRunAtMs as invalid and does not match the AI-marker regex. Fix f61896b0 preserves untrusted awareness event labels. Deeper blame attributed zero AI lines. Missing atomic AI marker fails ai_hunk_gate.

### 05 GHSA-VJ45-X3PJ-F4W4 — REJECT `SIBLING_FIX`

- Repository: `WeblateOrg/weblate`
- Rank: 185
- Summary: Weblate: Improper access control for pending tasks in API
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a229da5b lets users modify own notification settings. Fix 4e06b12c tightens pending-task API access. Deeper blame attributed zero AI lines. Notification ACL is a sibling surface, not origin of pending-task authorization.

### 06 GHSA-RCMW-7MC7-3RJ7 — REJECT `SIBLING_SECURITY_ATTEMPT`

- Repository: `getsentry/sentry`
- Rank: 186
- Summary: Sentry improper authentication on SAML SSO allows user identity linking
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 02cc5f9e hardens SSO login for inactive user identities. Fix 0c67558a pins SSO setup identity link to the authenticated session. Deeper blame attributed one deleted span with zero AI lines. Incomplete/sibling SSO rewrite is not hunk identity for the GHSA linking bug.

### 07 GHSA-V8QF-FR4G-28P2 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 187
- Summary: OpenClaw: Assistant media route missed scope enforcement for trusted-proxy authorization
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 3e9c8721 lets non-GET requests fall through controlUi routing when basePath is set. Fix 99ef3a63 requires read scope for assistant media. Deeper blame attributed zero AI lines. Control-UI routing is not origin of assistant-media scope.

### 08 GHSA-VFW7-6RHC-6XXG — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `openclaw/openclaw`
- Rank: 188
- Summary: OpenClaw incomplete fix for CVE-2026-4039: CLI backend environment variable injection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Advisory names an incomplete prior CLI env fix. Ranked AI 42164494 guards resolveUserPath against undefined input. Fix c2fb7f19 adjusts CLI backend environment handling before spawn. Deeper blame attributed zero AI lines. Path-guard sibling is not proved patch-delta incomplete remediation.

### 09 GHSA-MR34-9552-QR95 — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 189
- Summary: OpenClaw: Webchat media embedding lacked remote-host file:// rejection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0362f217 makes sendPolicy deny suppress delivery rather than inbound processing. Fix 1470de5d rejects remote-host file:// URLs in media embedding. Deeper blame attributed zero AI lines. Delivery-policy change is not origin of file:// embedding.

### 10 GHSA-7RP8-R62P-Q6WC — REJECT `WRONG_EDGE`

- Repository: `chainguard-dev/melange`
- Rank: 190
- Summary: melange update-cache has unbounded HTTP download that can exhaust disk in CI
- Failing gates: ai_hunk_gate, but_for_gate, fix_reversal_gate
- Counterevidence: Ranked AI 5c26d4dc points UV_CACHE_DIR and PIP_CACHE_DIR at /var/cache/melange. Fix 652ca5af corrects parsing error line numbers. Deeper blame attributed zero AI lines. Cache-dir default is not the unbounded HTTP download hunk; the ranked fix SHA is not even the advisory mechanism.

### 11 GHSA-FWJQ-XWFJ-GV75 — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `openclaw/openclaw`
- Rank: 191
- Summary: OpenClaw: session_status still bypasses tools.sessions.visibility for unsandboxed invocations
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d9810811 is an explicit security attempt that reruns the visibility guard after sessionId resolution for sandboxed callers (Claude-marked, 1-line). Advisory residual is unsandboxed invocations skipping the same guard. Fix 4d369a34 always runs visibilityGuard.check. Deeper blame of deleted hunks attributed zero AI lines: the later fix amends a sibling unsandboxed branch rather than deleting the AI-added sandboxed check. Patch-delta incomplete-remediation is not proved; out of this direct-root lane.

### 12 GHSA-5PWR-322W-8JR4 — REJECT `SIBLING_FIX`

- Repository: `pyca/pyopenssl`
- Rank: 192
- Summary: pyOpenSSL DTLS cookie callback buffer overflow
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d41a8147 handles exceptions in set_tlsext_servername_callback. Fix 57f09bb4 bounds DTLS cookie generation. Deeper blame attributed zero deleted source spans. SNI callback exception handling is not origin of the DTLS cookie overflow.

### 13 GHSA-RM59-992W-X2MV — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 193
- Summary: OpenClaw unauthenticated resource exhaustion through the voice-call webhook
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e707c97c guards webhook server lifecycle against EADDRINUSE. Fix 651dc745 hardens webhook pre-auth guards. Deeper blame attributed zero AI lines. Lifecycle locking is not origin of unauthenticated exhaustion.

### 14 GHSA-7R34-79R5-RCC9 — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `sooperset/mcp-atlassian`
- Rank: 194
- Summary: MCP Atlassian SSRF via unvalidated X-Atlassian-Jira-Url / X-Atlassian-Confluence-Url headers
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ffa6b395 adds US Government Cloud URL detection. Fix 5cd697df adds SSRF protection for header-based URL validation. Deeper blame attributed zero AI lines. Cloud-URL allowlist expansion is a sibling/incomplete boundary, not but-for origin of header SSRF.

### 15 GHSA-6XG4-82HV-CP6F — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 195
- Summary: OpenClaw: Gateway chat.send ACP-only provenance guard could be bypassed by client identity
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c9449d77 persists webchat inbound images to disk. Fix 4b954271 requires verified scope for chat provenance. Deeper blame attributed zero AI lines. Image persistence is not origin of provenance-guard bypass.

### 16 GHSA-27VG-33GH-4HWG — REJECT `SIBLING_SECURITY_ATTEMPT`

- Repository: `actualbudget/actual`
- Rank: 196
- Summary: Actual Sync Server authenticated path traversal
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Cursor commit a68b2aca enforces file-access authorization on sync API endpoints. Advisory and fix 18072e1d validate x-actual-file-id against path traversal. Deeper blame attributed zero deleted source spans (fix is additive). Authorization rewrite is a sibling surface to CWE-22 file-id traversal, not but-for origin.

### 17 GHSA-5HWF-RC88-82XM — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `trailofbits/fickling`
- Rank: 197
- Summary: Fickling missing RCE-capable modules in UNSAFE_IMPORTS
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ff423dad fixes an OBJ opcode safety-check bypass (different GHSA). Fix ffac3479 expands UNSAFE_IMPORTS. Deeper blame attributed zero deleted spans. Later blocklist growth is incomplete remediation of an untouched sibling import set, not AI_DIRECT_ROOT.

### 18 GHSA-H6C8-CWW8-35HF — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openfga/openfga`
- Rank: 198
- Summary: OpenFGA authorization bypass through cached keys
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6b6b2c56 fixes cache_item_count metric overcounting. Fix 049b50cc is a merge-from-fork of cache-key authorization. Deeper blame attributed zero AI lines. Metric counting is not origin of cached-key authz bypass.

### 19 GHSA-844J-XRRQ-WGH4 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 199
- Summary: OpenClaw: Forwarding header spoofing bypasses gateway.trustedProxies origin detection
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI b8c8130e uses LAN IP for WebSocket/probe URLs when bind=lan. Same SHA is also ranked for GHSA-VVJH and GHSA-HF68. Fix fc2d29ea (shared with HF68) tightens forwarded-client and pairing guards. Deeper blame attributed zero AI lines. Shared SHA without equal mechanism is routing, not three origins.

### 20 GHSA-M69H-JM2F-2PV8 — REJECT `SQUASH_CARRIER_OR_IMPORT`

- Repository: `openclaw/openclaw`
- Rank: 200
- Summary: OpenClaw: Feishu reaction events could bypass group authorization and mention gating
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 5c2cb6c5 syncs community Feishu contributions (Claude-marked). Deeper blame of deleted send.ts hunks hit 2267d58a, a Claude-marked plugin replacement that relocated FeishuMessageInfo rather than introducing omitted chat_type on reaction events. Fix 3e730c03 preserves reaction chat type. Type relocation and carrier import are not but-for origin of p2p misclassification.

### 21 GHSA-X9CF-3W63-RPQ9 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 201
- Summary: OpenClaw vulnerable to sensitive file disclosure via stageSandboxMedia
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 3b0c80ce adds per-sender group tool policies. Fix 1316e574 enforces inbound attachment root policy. Deeper blame attributed zero AI lines. Group-policy feature is not origin of sandbox media disclosure.

### 22 GHSA-CFP9-W5V9-3Q4H — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 202
- Summary: OpenClaw: Image tool tools.fs.workspaceOnly bypass via sandbox bridge mounts
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 8d74578c adds native image injection for vision models (also ranked for GHSA-H3X4). Fix 14baadda honors fsPolicy.workspaceOnly in image/pdf localRoots. Deeper blame attributed zero AI lines on this fix. Shared SHA without mechanism equality plus later policy honor is not proved AI_DIRECT_ROOT.

### 23 GHSA-VVJH-F6P9-5VCF — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 203
- Summary: OpenClaw Canvas authentication bypass
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked LAN-bind SHA b8c8130e as GHSA-844J and GHSA-HF68. Fix c45f3c5b hardens canvas auth with session capabilities. Deeper blame attributed zero AI lines. Shared SHA is not canvas-auth origin.

### 24 GHSA-FP4X-GGRF-WMC6 — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `h3js/h3`
- Rank: 204
- Summary: H3 open redirect via protocol-relative path in redirectBack() Referer validation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 60a2e915 escapes HTML in redirect() body. Fix 459a1c65 rejects protocol-relative paths in redirectBack(). Deeper blame attributed zero AI lines. HTML-escape of a sibling redirect helper is not patch-delta proof for Referer open redirect.

### 25 GHSA-H3M5-P59H-X88P — REJECT `REFACTOR_OLD_BUG`

- Repository: `jahlives/openssl_encrypt`
- Rank: 205
- Summary: openssl-encrypt visible password in process list via --password CLI argument
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9424c8f5 adds a missing --parallel-kdf flag. Deeper blame of two deleted subparser lines hit Claude-marked bb727ce9, which implemented segregated CLI help and re-wired an already-existing --password option. Fix e78a3666 deprecates --password for --password-file/--password-fd. Help-system refactor of an old flag is not origin of process-list exposure.

### 26 GHSA-FWHJ-785H-43HH — REJECT `NO_AI_MARKER`

- Repository: `OliveTin/OliveTin`
- Rank: 206
- Summary: OliveTin crash on NPE by calling APIs with invalid bindings or log references
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked commit aa2bd95c adds a policy to show/hide version number and does not match the AI-marker regex. Fix bb14c5da null-guards API bindings. Deeper blame attributed zero AI lines.

### 27 GHSA-H3X4-HC5V-V2GM — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 207
- Summary: OpenClaw: Windows media loaders accepted remote-host file URLs before local path validation
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked image-injection SHA 8d74578c as GHSA-CFP9. Deeper blame attributed one AI line in images.test.ts only. Fix 93880717 hardens secondary local path seams. Test-only blame is not a vulnerable production hunk; shared SHA is not two origins.

### 28 GHSA-V6X2-2QVM-6GV8 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 208
- Summary: OpenClaw reuses the gateway auth token in the owner ID prompt hashing fallback
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ab71fdf8 adds plugin compaction/reset hooks and bootstrap globs. Fix c99e7696 decouples owner display secret from gateway auth token. Deeper blame attributed zero AI lines. Plugin-API feature is not origin of owner-display secret reuse.

### 29 GHSA-VPHC-468G-8RFP — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `pab1it0/adx-mcp-server`
- Rank: 209
- Summary: Azure Data Explorer MCP Server KQL injection in multiple tools
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 48b29339 is Model Context Protocol expert setup. Fix 0abe0ee5 is a merge-from-fork. Deeper blame attributed one AI line in tests/test_all_tools.py only. Test-only blame is not origin of KQL injection in server.py.

### 30 GHSA-HF68-49FM-59CQ — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 210
- Summary: OpenClaw Gateway RCE and privilege escalation from operator.pairing to operator.admin
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA b8c8130e and same fix fc2d29ea as GHSA-844J. Deeper blame attributed zero AI lines. Shared SHA/fix without mechanism equality is not a second countable origin.

## Conservation

- rank_pool 3473 = 180 prior directroot reviews + 30 this slice + 620 unreviewed hits + 2643 rank misses
- hits 830; excluded-in-hits 180 (batches 1-6); canonical73 IDs were already outside this hit slice
- Incoming unreviewed hits before this slice: 650; after: 620
- Unreviewed remaining IDs are UNREVIEWED, not REJECT

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD.
