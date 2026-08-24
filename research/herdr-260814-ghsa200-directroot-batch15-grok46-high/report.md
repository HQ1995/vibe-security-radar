# Direct-root mining batch 15 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly the next 30 highest-score unassigned rank hits after canonical73 plus directroot batches 1-14, including frozen in-progress batch14 selection. The stale 260813 batch3 selection-only draft is byte-identical to formal 260814 batch3 and is one exclusion, not 30 extra reviewed rows. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 380
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 420+30+380+2643=3473 rank_pool

## Selection

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending (equals original ranks 1-830). Excluded every GHSA in canonical73 strict IDs and in batch1-batch14 selected-30/cases artifacts, including frozen in-progress batch14 selection. Stale 260813 batch3 equals formal 260814 batch3 and is counted once. Overlap with each excluded set is zero. Assigned original ranks 421-450. Selection recorded in `work/selected-30.jsonl` before review.

## Method

Each row used the frozen github-reviewed advisory JSON, the ranked AI SHA and fix SHA, first-parent `git log`/`diff`, release-tag containment where present, and deeper `git blame -l -w` of source deleted hunks on the fix parent against the AI-commit index. File-history overlap without blamed deleted lines remains routing. Incomplete-remediation security attempts stay out of this direct-root lane unless all patch-delta clauses pass. Shared SHAs without mechanism equality are rejected.

## Cases

### 01 GHSA-7CFQ-5MHV-JRP9 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `inspektor-gadget/inspektor-gadget`
- Rank: 421
- Summary: Inspektor Gadget: Unprivileged container can crash USDT note parser via crafted ELF (no shipped gadget affected)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f20c4ad9 is a golangci-lint chore. Fix ec69da2e is a release merge that hardens the USDT/ELF parser. Deeper blame attributed zero AI lines. Linting is not origin of the crafted-ELF crash.

### 02 GHSA-MJ5R-HH7J-4GXF — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 422
- Summary: OpenClaw Telegram allowlist authorization accepted mutable usernames
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 506bed5a adds Telegram sticker support with vision caching. Fix 9e147f00 resolves allowFrom usernames in doctor. Deeper blame attributed zero AI lines. Sticker vision caching is not origin of mutable-username allowlist authorization.

### 03 GHSA-7H4P-RFFG-7823 — REJECT `SIBLING_FIX`

- Repository: `vllm-project/vllm`
- Rank: 423
- Summary: vLLM: temperature=NaN and temperature=Infinity bypass validation and propagate to GPU kernels
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c7560af4 replaces shared-memory routed experts with ModelRunnerOutput transfer. Fix d598d239 rejects non-finite temperature and repetition_penalty. Deeper blame attributed zero AI lines. Expert-routing transfer is not origin of NaN temperature bypass.

### 04 GHSA-3R8V-2XMJ-5C39 — REJECT `SIBLING_FIX`

- Repository: `fission/fission`
- Rank: 424
- Summary: Fission: Cross-namespace Package read via unvalidated PackageRef in Function admission webhook
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 3e3830bc adds CRD conditions and SSA list markers. Fix 80e7ba55 rejects cross-namespace Environment and Package references. Deeper blame attributed zero AI lines. Shared with GHSA-CVW6/GHSA-8WCJ/GHSA-WMGG without mechanism equality. CRD conditions are not origin of missing PackageRef namespace validation.

### 05 GHSA-2R2C-CX56-8933 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `jline/jline3`
- Rank: 425
- Summary: JLine3 Telnet server: Unauthenticated Remote DoS via Unbounded Telnet NAWS Terminal Geometry
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 934f09e6 is a merge-from-fork that caps NEW-ENVIRON variable count. The first-party advisory is unbounded NAWS terminal geometry. Fix 733eb353 is a later merge-from-fork on the same TelnetIO.java file. Deeper blame attributed zero AI lines. Shared file without mechanism equality is not NAWS origin.

### 06 GHSA-VJHC-CF4P-72Q4 — REJECT `SIBLING_FIX`

- Repository: `fission/fission`
- Rank: 426
- Summary: Fission: Cross-namespace Environment reference in Package allows build-time command execution and SA token exfiltration
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 814d232c extends HMAC application-layer auth to fetcher, builder, executor, and router-internal. Fix e2b92663 rejects cross-namespace Package and KubernetesWatchTrigger references. Deeper blame attributed zero AI lines. Shared SHA with GHSA-GC3J and GHSA-7M8X. HMAC listeners are not origin of Package EnvironmentRef namespace confusion.

### 07 GHSA-J5F8-GRM9-P9FC — REJECT `SIBLING_FIX`

- Repository: `axios/axios`
- Rank: 427
- Summary: Axios: Proxy-Authorization header leaks to redirect target when proxy is re-evaluated to direct connection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6ef867e6 changes the empty-proxy-authorization error to AxiosError. Fix afca61a0 clears the stale Proxy-Authorization header when a redirect becomes a direct connection. Deeper blame attributed zero AI lines. Empty-auth error typing is not origin of redirect header leakage.

### 08 GHSA-7RCP-MXPQ-72PJ — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 428
- Summary: OpenClaw Chutes manual OAuth state validation bypass can cause credential substitution
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 08b7932d adds Hugging Face Inference provider support and auth refactors. Fix a99ad11a validates state for manual Chutes OAuth. Deeper blame attributed zero AI lines. Hugging Face provider support is not origin of Chutes OAuth state bypass.

### 09 GHSA-GC3J-79F2-7VVW — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `fission/fission`
- Rank: 429
- Summary: Fission: Cross-namespace event leakage via KubernetesWatchTrigger allows persistent tenant surveillance
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 814d232c as GHSA-VJHC. Fix e2b92663 is the shared Package plus KubernetesWatchTrigger closer. Deeper blame attributed zero AI lines. HMAC auth without mechanism equality is not KubernetesWatchTrigger event-leakage origin.

### 10 GHSA-8WCJ-MFRC-JX5Q — REJECT `SIBLING_FIX`

- Repository: `fission/fission`
- Rank: 430
- Summary: Fission builder pods auto-mount the fission-builder ServiceAccount token in the user-supplied builder container
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 3e3830bc adds CRD conditions and SSA list markers. Fix 8fa79941 drops the fission-builder ServiceAccount token from the user builder container. Deeper blame attributed zero AI lines. CRD conditions are not origin of auto-mounted builder SA tokens.

### 11 GHSA-V455-MV2V-5G92 — REJECT `SIBLING_FIX`

- Repository: `fission/fission`
- Rank: 431
- Summary: Fission Container Executor Function PodSpec Injection Leading to Node Escape
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9225ce56 adds CORS deny and security headers across HTTP listeners. Fix e484df84 rejects dangerous PodSpec fields in Environment and Function. Deeper blame attributed zero AI lines. CORS headers are not origin of Function PodSpec injection.

### 12 GHSA-WMFG-5P4H-5FW3 — REJECT `OLD_BUG_REFACTOR`

- Repository: `gogs/gogs`
- Rank: 432
- Summary: Gogs allows users to write to readonly repositories using receive-pack plus service=git-upload-pack confusion
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 36d56d55 renames packages ending with util to end with x. Fix 7c9cf53a hardens Git HTTP access checks. Deeper blame attributed zero AI lines. Shared rename SHA with GHSA-C4V7 and GHSA-XP79. A package rename is not origin of receive-pack service confusion.

### 13 GHSA-3QQ3-668M-V9MJ — REJECT `SIBLING_FIX`

- Repository: `gogs/gogs`
- Rank: 433
- Summary: Gogs has a Denial of Service in repository/wiki file listing web pages
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4ee706b2 replaces pkg/errors with cockroachdb/errors. Fix ae41bab5 always lists tree entries with verbatim. Deeper blame attributed zero AI lines. Error-library replacement is not origin of listing DoS.

### 14 GHSA-C4V7-XG93-QF8G — REJECT `OLD_BUG_REFACTOR`

- Repository: `gogs/gogs`
- Rank: 434
- Summary: Gogs has SSRF in webhook deliveries
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 36d56d55 package rename as GHSA-WMFG. Fix 199cf4fd stops following redirects on webhook delivery. Deeper blame attributed zero AI lines. Rename without mechanism equality is not webhook SSRF origin.

### 15 GHSA-X975-RGX4-5FH4 — REJECT `SIBLING_FIX`

- Repository: `appium/appium-mcp`
- Rank: 435
- Summary: appium-mcp: Unescaped Locator Data XSS in MCP-UI Resource (createLocatorGeneratorUI)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4068a7a4 is a minor-issues fix. Fix e222bbbd adds escaping in mcp-ui-utils. Deeper blame attributed zero AI lines. Unrelated minor fixes are not origin of unescaped locator XSS.

### 16 GHSA-XQXV-4JC2-X56X — REJECT `SIBLING_FIX`

- Repository: `zitadel/zitadel`
- Rank: 436
- Summary: ZITADEL: Missing client_id binding in OIDC authorization code exchange and refresh token flows
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 01fe34a5 uses authenticated encryption for opaque tokens. Fix 0973b074 is a merge-from-fork of client_id binding. Deeper blame attributed zero AI lines. Opaque-token encryption is not origin of missing client_id binding.

### 17 GHSA-HGG8-FQQC-VFMW — REJECT `SIBLING_FIX`

- Repository: `vllm-project/vllm`
- Rank: 437
- Summary: vLLM: incomplete CVE-2026-22778 fix leaks PIL repr addresses via Anthropic router
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 8477fe42 moves adjust_request onto the reasoning parser and fixes Gemma4. It only skips appending empty user Anthropic messages. Fix 94923629 applies sanitize_message to Anthropic and STT error paths. Deeper blame attributed zero AI lines. The incomplete CVE-2026-22778 residual is not this Gemma parser change, and the omitted sanitize path is an untouched sibling rather than a patch-delta of the ranked AI hunk.

### 18 GHSA-6F75-X745-XCPR — REJECT `SIBLING_FIX`

- Repository: `grokability/snipe-it`
- Rank: 438
- Summary: Snipe-IT: Bulk editing users allowed ldap_import and activated fields
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d363793c only edits resources/lang/en-US/general.php. Fix 403f9c84 disallows ldap_import and activated in bulk user edits without permission. Deeper blame attributed zero AI lines. A language-string edit is not origin of the bulk-edit authorization hole.

### 19 GHSA-4J89-2C4F-44C6 — REJECT `SIBLING_FIX`

- Repository: `gogs/gogs`
- Rank: 439
- Summary: Gogs has DoS in rendering issue index pattern
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bf17cc6c replaces github.com/unknwon/com with stdlib helpers. Fix 0529d95f avoids panic on malformed external issue tracker URL format. Deeper blame attributed zero AI lines. Stdlib helper replacement is not origin of issue-index DoS.

### 20 GHSA-37GC-85XM-2WW6 — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 440
- Summary: OpenClaw affected by Stored XSS in Control UI via unsanitized assistant name/avatar in inline script injection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fabdf2f6 adds webchat image paste support. Fix 3b4096e0 loads Control UI bootstrap config via a JSON endpoint. Deeper blame attributed zero AI lines. Image paste is not origin of unsanitized assistant-name script injection.

### 21 GHSA-4936-9HRH-QQPW — REJECT `SIBLING_FIX`

- Repository: `tinacms/tinacms`
- Rank: 441
- Summary: @tinacms/cli: Remote Code Execution in @tinacms/cli via Forestry migration unsanitised markers
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b260b5ed migrates docs links in packages to aliased URLs. Fix 77665ae7 hardens Forestry migration code generation against untrusted input. Deeper blame attributed zero AI lines. Docs URL aliasing is not origin of Forestry marker RCE.

### 22 GHSA-7M8X-QG2J-4M3V — REJECT `SIBLING_FIX`

- Repository: `fission/fission`
- Rank: 442
- Summary: Fission: MessageQueueTrigger scaler manager materializes Secret values into Deployment envvars and accepts arbitrary user PodSpec
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 814d232c extends HMAC auth. Fix 94bf5792 drops secret materialization and allowlists PodSpec fields in MessageQueueTrigger. Deeper blame attributed three lines on test/integration/framework/router.go from a different AI SHA 4982e27d, not the ranked candidate. HMAC listeners and a test helper are not origin of MQT secret materialization.

### 23 GHSA-WMGG-3P4H-48X7 — REJECT `SIBLING_FIX`

- Repository: `fission/fission`
- Rank: 443
- Summary: Fission Environment CRD PodSpec Injection Leading to Node Escape and Cluster Takeover
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate, fix_reversal_gate
- Counterevidence: Ranked AI 3e3830bc adds CRD conditions. Ranked fix 8fa79941 is the GHSA-8WCJ builder-SA-token drop, not an Environment PodSpec allowlist. Deeper blame attributed zero AI lines. Shared SHA and shared closer without mechanism equality is not Environment PodSpec injection origin.

### 24 GHSA-239W-M3H6-CH8V — REJECT `UNIQUENESS_SAME_MECHANISM`

- Repository: `filebrowser/filebrowser`
- Rank: 444
- Summary: File Browser: Symlink following lets scoped users read, overwrite, and share files outside their filebrowser scope
- Failing gates: but_for_gate, fix_reversal_gate, uniqueness_gate
- Counterevidence: Ranked AI 847d08bd is Co-Authored-By Claude Opus 4.8 and adds files.WithinScope as an explicit security attempt named in the commit as GHSA-239w. That same SHA is already counted in canonical73 as GHSA-8WC8 AI_INCOMPLETE_REMEDIATION of the WithinScope/ScopedFs.within parent-fallback and as GHSA-83XP zip-slip. Human 7c2c0a11 moves WithinScope into ScopedFs.within() and keeps the dangling parent-fallback comment; v2.63.6 contains 847d08bd without 7c2c0a11, and v2.63.14 contains 7c2c0a11. The first-party GHSA is the original pre-AI BasePathFs symlink-follow umbrella, not a distinct omitted residual from counted GHSA-8WC8. Shared SHA without a distinct mechanism is not a second countable case.

### 25 GHSA-F637-W7P2-M7FX — REJECT `SIBLING_FIX`

- Repository: `OliveTin/OliveTin`
- Rank: 445
- Summary: OliveTin: ValidateArgumentType API Endpoint's Missing Authentication Allows Action and Argument Enumeration
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI aa2bd95c is marked Made-with: Cursor and adds a policy to show or hide the version number. The dump marker regex missed that trailer. Fix a3865704 authenticates the validation endpoints. Deeper blame attributed zero AI lines. Version-redaction policy is not origin of missing ValidateArgumentType authentication.

### 26 GHSA-CMWH-PVXP-8882 — REJECT `SIBLING_FIX`

- Repository: `cure53/DOMPurify`
- Rank: 446
- Summary: DOMPurify: Permanent ALLOWED_ATTR pollution via setConfig() bypassing the hook clone-guard
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d291155e applies SAFE_FOR_TEMPLATES scrub in the RETURN_DOM path. The advisory is an incomplete 3.4.7 hook-pollution residual on setConfig(). Fix 011bc3b2 extends the hook allowlist clone-guard to setConfig(). Deeper blame attributed zero AI lines. RETURN_DOM template scrub is not origin of setConfig ALLOWED_ATTR pollution, and the omitted setConfig path is an untouched sibling of a different security attempt.

### 27 GHSA-98XF-R82G-9MHX — REJECT `SIBLING_FIX`

- Repository: `langchain-ai/langgraphjs`
- Rank: 447
- Summary: LangGraph has NoSQL parameter injection in MongoDBSaver, allowing cross-tenant state access
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 38db67f3 adds opt-in enableTimestamps for upserted_at. Fix 284226c7 validates configurable checkpoint IDs. Deeper blame attributed zero AI lines. Timestamp opt-in is not origin of MongoDBSaver NoSQL injection.

### 28 GHSA-VXGM-5RMG-5W8G — REJECT `SIBLING_FIX`

- Repository: `gohugoio/hugo`
- Rank: 448
- Summary: Hugo: security.http.urls allow-list bypass via HTTP redirects
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 842d8f10 fixes context canceled on GetRemote with a per-request timeout. Fix 86fbb0f7 validates redirects against security.http.urls. Deeper blame attributed zero AI lines. Timeout handling is not origin of redirect allow-list bypass.

### 29 GHSA-CVW6-GFVV-953Q — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `fission/fission`
- Rank: 449
- Summary: Fission: Cross-namespace Environment reference via unvalidated EnvironmentRef in Function admission webhook
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 3e3830bc and same fix 80e7ba55 as GHSA-3R8V. The advisory is Function EnvironmentRef rather than PackageRef. Deeper blame attributed zero AI lines. Shared CRD-conditions SHA without mechanism equality is not EnvironmentRef origin.

### 30 GHSA-XP79-5MX3-JX52 — REJECT `OLD_BUG_REFACTOR`

- Repository: `gogs/gogs`
- Rank: 450
- Summary: Gogs has Unauthenticated Asymmetric Denial of Service via SSH Handshake Stall
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 36d56d55 package rename as GHSA-WMFG. Fix 7da9cda3 times out stalled SSH handshakes after 15s. Deeper blame attributed zero AI lines. Rename without mechanism equality is not SSH handshake-stall origin.

## Conservation

- rank_pool 3473 = 420 prior directroot reviews + 30 this slice + 380 unreviewed hits + 2643 rank misses
- hits 830; excluded-in-hits 420 (batches 1-14, with stale 260813 batch3 counted once); canonical73 IDs were already outside this hit slice
- Incoming unreviewed hits before this slice: 410; after: 380
- Unreviewed remaining IDs are UNREVIEWED, not REJECT

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD.
