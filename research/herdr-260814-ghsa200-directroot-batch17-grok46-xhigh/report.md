# Direct-root mining batch 17 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical73 and directroot batches 1-16, including frozen in-progress batch15 and batch16 selections. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 320
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 480+30+320+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical73 strict identities plus batch1-16 `selected-30.jsonl`/`cases.jsonl`, including frozen in-progress batch15 and batch16. Stale 260813 batch3 is the same IDs as formal 260814 batch3, not an extra reviewed slice. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-JJ6Q-RRRF-H66H — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 481
- Summary: OpenClaw: Shared-secret comparison call sites leaked length information through timing
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f92c9251 routes extension fetch through fetchWithSsrFGuard. Fix be10ecef reuses a shared secret comparison helper. Deeper blame attributed zero AI lines. BlueBubbles monitor.ts overlap is SSRF-fetch routing, not timing-safe compare origin.

### 02 GHSA-XH72-V6V9-MWHC — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 482
- Summary: OpenClaw: Feishu webhook and card-action validation now fail closed
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bd4237c1 closes Feishu WebSocket connections on monitor stop. Fix c8003f1b hardens Feishu webhook replay guards. Deeper blame attributed zero AI lines. monitor.transport.ts overlap is lifecycle cleanup, not fail-closed webhook validation origin.

### 03 GHSA-9CP7-J3F8-P5JX — REJECT `SIBLING_FIX`

- Repository: `daptin/daptin`
- Rank: 483
- Summary: Daptin has Unauthenticated Path Traversal and Zip Slip
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9173037e adds a nil credential check in cloud storage actions. Fix 8d626bbb blocks upward directory traversal in file upload. Deeper blame attributed zero AI lines. action_cloudstore_file_upload.go overlap is a sibling nil-guard, not path-traversal or zip-slip origin.

### 04 GHSA-GJM7-HW8F-73RQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 484
- Summary: OpenClaw: Paired node escalates to gateway RCE via unrestricted node.event agent dispatch
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0954b6bf has no explicit AI marker (human author plus SidQin co-author). It propagates ephemeral sessionId through tool contexts. Fix a77928b1 hardens node.event trust boundaries. Deeper blame attributed zero AI lines. pi-tools.ts overlap is routing, not node-event RCE origin.

### 05 GHSA-QRP5-GFW2-GXV4 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 485
- Summary: OpenClaw: Bundled MCP/LSP tools could bypass configured tool policy
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 3b0c80ce adds per-sender group tool policies. The same SHA was already ranked for GHSA-782P (Slack channel-description prompt injection) in directroot batch14. Fix 0e7a992d filters bundled MCP/LSP tools through final policy. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not bundled-tool policy origin.

### 06 GHSA-8M29-FPQ5-89JJ — REJECT `SIBLING_FIX`

- Repository: `ZcashFoundation/zebra`
- Rank: 486
- Summary: Zebra Vulnerable to Consensus Divergence in Transparent Sighash Hash-Type Handling
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 09be46ab adds non-standard mempool transaction filters. Fix 1f605eca applies combined consensus/sighash security fixes. Deeper blame attributed zero AI lines. zebra-consensus transaction.rs overlap is a sibling mempool-policy change, not sighash hash-type origin.

### 07 GHSA-3F6H-2HRP-W5WX — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `sveltejs/kit`
- Rank: 487
- Summary: @sveltejs/kit: Unvalidated redirect in handle hook causes Denial-of-Service
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b2c5d029 is Copilot cookie-key handling across paths and domains. Fix 10d7b444 is a merge-from-fork adding safer redirects. Deeper blame attributed zero AI lines. respond.js overlap is routing, not unvalidated-redirect DoS origin.

### 08 GHSA-FVCV-3M26-PCQX — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `axios/axios`
- Rank: 488
- Summary: Axios has Unrestricted Cloud Metadata Exfiltration via Header Injection Chain
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 16ae9508 is a v0.x CI refactor. The same SHA and fix 03cdfc99 are also ranked for GHSA-3P68 (NO_PROXY bypass) in this slice. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not cloud-metadata header-injection origin.

### 09 GHSA-GHM9-CR32-G9QJ — REJECT `OLD_BUG_REFACTOR`

- Repository: `rust-openssl/rust-openssl`
- Rank: 489
- Summary: rust-openssl: rustMdCtxRef::digest_final() writes past caller buffer with no length check
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5507b22d enables sign/verify/reset on BoringSSL, LibreSSL, and AWS-LC. Fix 826c3888 errors when digest_final() is given a short out buffer. Advisory introduced 0.10.39, predating this commit. Deeper blame attributed zero AI lines. md_ctx.rs overlap is a sibling backend-enablement, not digest_final overflow origin.

### 10 GHSA-4X48-CGF9-Q33F — REJECT `SIBLING_FIX`

- Repository: `novuhq/novu`
- Rank: 490
- Summary: Novu has SSRF via conditions filter webhook bypasses validateUrlSsrf() protection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6092f074 adds environment-variable compilation in the worker HTTP step. Fix 87d965eb validates condition webhook URLs against SSRF. Deeper blame attributed zero AI lines. execute-http-request-step overlap is a sibling compiler path, not conditions-filter webhook SSRF origin.

### 11 GHSA-V2WJ-Q39Q-566R — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vitejs/vite`
- Rank: 491
- Summary: Vite: `server.fs.deny` bypassed with queries
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d65a9831 only expands a malformed-URI log line in transform middleware. Fix a9a3df29 checks server.fs after stripping the query via cleanUrl(). First-parent diff of the overlapping file is logging, not fs.deny. Deeper blame attributed zero AI lines.

### 12 GHSA-WWFP-W96M-C6X8 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 492
- Summary: OpenClaw: Pairing pending-request caps were enforced per channel instead of per account
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0743463b suppresses NO_REPLY in webchat transcripts and patches TypeScript in pairing-store. Fix 9bc1f896 scopes pending pairing caps per account. Deeper blame attributed zero AI lines. pairing-store.ts overlap is a sibling type/stat guard, not per-account cap origin.

### 13 GHSA-3JR7-6HQP-X679 — REJECT `SIBLING_FIX`

- Repository: `mesop-dev/mesop`
- Rank: 493
- Summary: Mesop: Unbounded Thread Creation in WebSocket Handler Leads to Denial of Service
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7763fdf2 adds an Origin check to prevent CSWSH. Fix 760a2079 bounds concurrent WebSocket threads per connection. Deeper blame attributed zero AI lines. Same-file server.py overlap is a sibling WebSocket security change, not thread-DoS origin.

### 14 GHSA-525J-HQQ2-66R4 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 494
- Summary: OpenClaw: Sandbox browser CDP relay could expose DevTools protocol on 0.0.0.0
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI cc3c25e4 applies oxfmt 0.32.0 formatting. Fix fbf11ebd enforces CDP source-range restriction by default. Deeper blame attributed zero AI lines. browser.ts overlap is formatting, not CDP bind-address origin.

### 15 GHSA-CHFM-XGC4-47RJ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 495
- Summary: OpenClaw: MSTeams thread history bypasses sender allowlist via Graph API
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 8c852d86 adds graph-thread.ts and wires Graph thread history into message-handler.ts. Fix 5cca3808 filters that history by sender allowlist and does not touch graph-thread.ts. Deeper blame attributed zero AI lines; local clone blobs for the added file are missing, so hunk identity is unproved. New-file history without hunk identity remains routing, not Graph-allowlist origin.

### 16 GHSA-3G92-F9CH-QJCM — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Plonky3/Plonky3`
- Rank: 496
- Summary: Plonky3: The sponge construction used to get a hash function from a cryptographic permutation is not collision resistant for inputs of different lengths
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c01e9b88 adds compile-time assertions across crypto crates. Fix 5c1dc1d6 is a merge-from-fork adding sponge 10-padding. Deeper blame attributed zero AI lines. sponge.rs overlap is an old-bug assertion refactor, not padding origin.

### 17 GHSA-5GFJ-64GH-MGMW — REJECT `SIBLING_FIX`

- Repository: `Josh-XT/AGiXT`
- Rank: 497
- Summary: AGiXT Vulnerable to Path Traversal in safe_join()
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9501a0f7 adds check_domain_availability (WHOIS) to essential_abilities.py. Fix 2079ea5a hardens safe_join() with realpath workspace checks. First-parent diffs confirm disjoint functions in the same file. Deeper blame attributed zero AI lines. Sibling feature, not safe_join path-traversal origin.

### 18 GHSA-3P68-RC4W-QGX5 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `axios/axios`
- Rank: 498
- Summary: Axios has a NO_PROXY Hostname Normalization Bypass that Leads to SSRF
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 16ae9508 and fix 03cdfc99 as GHSA-FVCV. AI is a CI refactor; history overlap is a test file. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not two origins.

### 19 GHSA-HVC7-763R-4F3H — REJECT `SIBLING_FIX`

- Repository: `jahlives/openssl_encrypt`
- Rank: 499
- Summary: openssl-encrypt has no owner verification on key revocation — any client can revoke any key
- Failing gates: ai_hunk_gate, but_for_gate, fix_reversal_gate
- Counterevidence: Ranked AI 1d519a1e implements HMAC token validation and cites a different advisory (GHSA-4g2c). Fix 05e45f39 only documents that revocation signatures already prove ownership. Advisory names service.py; ranked overlap is keys.py. Deeper blame attributed zero AI lines. Sibling token-auth work plus a documentation-only reversal is not owner-check origin.

### 20 GHSA-38C5-483C-4QQP — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `becheran/grid`
- Rank: 500
- Summary: Grid: Integer Overflow in Grid::expand_rows Leads to Safe-API Undefined Behavior
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 781d36c5 is copilot-swe-agent tests for delete methods. Fix be213bd3 adds overflow checks on expand/prepend. Deeper blame attributed zero AI lines. src/lib.rs overlap is test-only, not expand_rows overflow origin.

### 21 GHSA-CMXV-58FP-FM3G — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `AsyncHttpClient/async-http-client`
- Rank: 501
- Summary: AsyncHttpClient leaks authorization credentials to untrusted domains on cross-origin redirects
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fb50dc26 adds an opt-in stripAuthorizationOnRedirect flag. Advisory introduced 2.0.0/3.0.0.Beta1, predating that flag, and covers default credential forwarding plus a residual Realm leak. Fix 6b2fbb7f strips credentials on cross-domain redirects by default. Deeper blame attributed zero AI lines; interceptor blobs are missing. An optional incomplete guard over an old default hole is not proved patch-delta incomplete-remediation.

### 22 GHSA-FVX6-PJ3R-5Q4Q — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 502
- Summary: OpenClaw's complex interpreter pipelines could skip exec script preflight validation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 22c75a55 returns plain-text exec tool errors instead of raw JSON. Fix 8aceaf5d closes a fail-open bypass in exec script preflight. Deeper blame attributed zero AI lines. bash-tools.exec.ts overlap is a sibling error-format change, not preflight origin.

### 23 GHSA-49CG-279W-M73X — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 503
- Summary: OpenClaw: Empty approver lists could grant explicit approval authorization
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 483fba41 adds Discord exec-approval forwarding to DMs and adds commands-approve.test.ts. Fix 0a105c09 prevents empty approver lists from granting authorization in channel-approval-auth.ts. Deeper blame attributed zero AI lines. Overlap is a newly added test file, not empty-approver origin.

### 24 GHSA-8H88-GXP3-J7PG — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `jahlives/openssl_encrypt`
- Rank: 504
- Summary: openssl-encrypt's unverified key bundle from_dict() + to_identity() path allows encryption to attacker keys
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fafdfeed adds openssl_encrypt/modules/key_bundle.py as a new file in a keyserver feature. Fix f4a1ba66 verifies signatures on from_dict(). Deeper blame attributed zero AI lines; local clone blobs and git tags are missing, so hunk identity and release containment are unproved. New-file history without hunk identity remains routing.

### 25 GHSA-28XX-PPPM-VQFF — REJECT `OLD_BUG_REFACTOR`

- Repository: `ydb-platform/ydb-go-sdk`
- Rank: 505
- Summary: ydb-go-sdk's transactions are not committed using the `options.WithCommit()` option on last call `table.Transaction.Execute` in transaction
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f3aeeb14 modernizes Go idioms and CI across 140 files. Fix 25dcff4c honors options.WithCommit() in table.Session.Execute. Deeper blame attributed zero AI lines. session.go overlap is a large-refactor touch, not WithCommit origin.

### 26 GHSA-7R9J-R86Q-7G45 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Budibase/budibase`
- Rank: 506
- Summary: Budibase: Server-Side Request Forgery via REST Connector with Empty Default Blacklist
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 1e6bf7f4 implements OAuth2 tokens for automation steps. Fix 5b0fe83d is a merge that blocks internal REST targets by default. Deeper blame attributed zero AI lines. oauth2.spec.ts overlap is a test file, not empty-blacklist SSRF origin.

### 27 GHSA-XW59-HVM2-8PJ6 — REJECT `SIBLING_FIX`

- Repository: `modelcontextprotocol/go-sdk`
- Rank: 507
- Summary: DNS Rebinding Protection Disabled by Default in Model Context Protocol Go SDK for Servers Running on Localhost
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI cf88bda0 enforces an SSE retry limit when streams make no progress. Fix 67bd3f2e adds automatic DNS rebinding protection for localhost servers. First-parent diffs of streamable.go confirm disjoint hunks. Deeper blame attributed zero AI lines. Sibling transport change, not DNS-rebinding origin.

### 28 GHSA-88GM-J2WX-58H6 — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `withastro/astro`
- Rank: 508
- Summary: Cloudflare has SSRF via redirect following through its image-binding-transform endpoint (incomplete fix for GHSA-qpr4)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Advisory is an incomplete remediation of prior GHSA-qpr4. Ranked AI 141c4a26 is the Environment API mega-merge that adds image-binding-transform.ts among many human and Copilot co-authors. Fix a43eb4b4 uses redirect:manual. Deeper blame attributed zero AI lines; AI-side blobs are missing. Mega-merge file add without hunk identity is not proved patch-delta of the remaining redirect-follow hole.

### 29 GHSA-G87C-R2JP-293W — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `tinacms/tinacms`
- Rank: 509
- Summary: @tinacms/graphql's Media Endpoints Can Escape the Media Root via Symlinks or Junctions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bde4e4f6 improves the missing tina/ folder error via an isContentRoot flag. Fix f124eaba closes symlink traversal in media endpoints and FilesystemBridge. First-parent diff of the overlapping dev-command file is an error-message path, while the fix only adds a host-exposure warning there. Deeper blame attributed zero AI lines.

### 30 GHSA-89GG-P5R5-Q6R4 — REJECT `OLD_BUG_REFACTOR`

- Repository: `Project-MONAI/MONAI`
- Rank: 510
- Summary: MONAI: Unsafe functions lead to pickle deserialization rce
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 57fdd594 replaces pyupgrade with Ruff UP across many files. Fix 9078a72f replaces pickle with JSON in Auto3DSeg serialization. Deeper blame attributed zero AI lines. bundle_gen.py overlap is a lint refactor, not pickle-RCE origin.

## Conservation

- rank_pool 3473 = 480 prior directroot reviews + 30 this slice + 320 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch16: 480; this slice 481-510
- Incoming unreviewed hits before this slice: 350; after: 320
- Stale 260813 batch3 counted once (byte-identical to formal 260814 batch3)
- Unreviewed remaining IDs are UNREVIEWED, not REJECT

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD.
