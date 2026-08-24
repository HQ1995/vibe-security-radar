# Direct-root mining batch 10 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly the next 30 highest-score unassigned rank hits after canonical73 plus directroot batches 1-9, including frozen in-progress batch8 and batch9 selections. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 530
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 270+30+530+2643=3473 rank_pool

## Selection

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending (equals original ranks 1-830). Excluded every GHSA in canonical73 strict IDs and in batch1-batch9 selected-30/cases artifacts, including frozen in-progress batch8 and batch9 selections. Overlap with each excluded set is zero. Assigned original ranks 271-300. Selection recorded in `work/selected-30.jsonl` before review.

## Method

Each row used the frozen github-reviewed advisory JSON, the ranked AI SHA and fix SHA, first-parent `git log`/`diff`, release-tag containment where present, and deeper `git blame -l -w` of source deleted hunks on the fix parent against the AI-commit index. File-history overlap without blamed deleted lines remains routing. Incomplete-remediation security attempts stay out of this direct-root lane unless all patch-delta clauses pass. Shared SHAs without mechanism equality are rejected.

## Cases

### 01 GHSA-386Q-5HP3-95M9 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `koxudaxi/datamodel-code-generator`
- Rank: 271
- Summary: datamodel-code-generator: code injection via attacker-controlled default_factory schema field
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 160e507e fixes required-field default rendering. Fix 17fc235e is a merge-from-fork that stops interpolating schema default_factory as a Python expression. Deeper blame of deleted source hunks attributed zero AI-marked lines. Default-rendering hygiene is not origin of default_factory injection.

### 02 GHSA-R5VV-FF45-PRP2 — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `koxudaxi/datamodel-code-generator`
- Rank: 272
- Summary: datamodel-code-generator: Authorization / request headers leaked to cross-origin redirect target when fetching remote schemas
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f6d4cbd3 adds --allow-remote-refs and HTTP status/content-type checks while keeping follow_redirects=True with original headers. Fix a585c037 strips Authorization on cross-origin redirects. Deeper blame attributed zero deleted AI lines (fix is additive). Redirect credential stripping is an untouched sibling of the AI-added fetch gate, not proved patch-delta incomplete remediation.

### 03 GHSA-97JW-64CJ-JC58 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `ViewComponent/view_component`
- Rank: 273
- Summary: ViewComponent: around_render HTML-Safety Bypass
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ea4b7671 syncs capture output buffer so form-helper yields land inside tags. Fix 48e5fd2d hardens around_render HTML safety. Deeper blame attributed zero AI lines. Capture-buffer location is not origin of around_render unsafe strings.

### 04 GHSA-FWJX-9P69-H25H — REJECT `NO_AI_MARKER`

- Repository: `JanDeDobbeleer/oh-my-posh`
- Rank: 274
- Summary: Oh My Posh: Terminal escape sequence injection via unsanitized prompt segment data
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked commit 63e12433 makes progress-sequence terminals configurable. Author is copilot-swe-agent bot without a Co-authored-by line that matches the AI-marker regex. Fix edcf3c88 strips control runes from rendered segments. Deeper blame attributed zero AI lines. Missing atomic AI marker fails ai_hunk_gate.

### 05 GHSA-26V7-H57M-GH9M — REJECT `SIBLING_FIX`

- Repository: `QuantumNous/new-api`
- Rank: 275
- Summary: New API is vulnerable to CSRF through user email binding
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d7c55b92 adds a disk request-body cache. Deeper blame attributed one deleted line: a GetStatus _qn fingerprint. Fix e099117c switches email/WeChat bind from GET to POST. Cache middleware and status fingerprint are not origin of CSRF bind.

### 06 GHSA-WQXV-W64V-5WH6 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `coder/coder`
- Rank: 276
- Summary: Suspended Coder users retain access to AI Bridge LLM proxy endpoints
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI eddd4a8c accepts delegated API-key IDs for in-process aibridge callers. Fix 0d2c9f90 adds StatusActive to IsAuthorized. Deeper blame attributed three AI lines in aibridgedserver_test.go only. Test-only blame is not a vulnerable production hunk; the additive status check is not but-for origin of the omitted suspension guard.

### 07 GHSA-RJG6-39JM-RGG4 — REJECT `SIBLING_SECURITY_ATTEMPT`

- Repository: `better-auth/better-auth`
- Rank: 277
- Summary: @better-auth/scim: account takeover and stale access via SCIM provider-id collision
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a26333b5 deletes sessions when SCIM deletes a user (explicit attempt for a different GHSA). Fix 7c126dcd scopes write-path operations and honors active. Deeper blame attributed 17 AI lines in scim-users.test.ts only. Session-cleanup sibling is not origin of provider-id collision.

### 08 GHSA-956X-8GVW-WG5V — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `gitpython-developers/GitPython`
- Rank: 278
- Summary: GitPython: command injection via unguarded Git options in Repo.archive(), git.ls_remote(), and arbitrary file overwrite via Repo.iter_commits() / Repo.blame()
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 56806080 hardens check_unsafe_options for joined short options and states it completes GHSA-2F96-G7MH-G2HX (already reviewed in batch4). Fix 701ce32f wires the checker into archive, ls_remote, blame, and related sibling APIs. Deeper blame attributed zero AI lines. Residual unguarded APIs are untouched siblings, not patch-delta of the joined-short-option boundary.

### 09 GHSA-25GQ-J9JX-43PG — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `go-gitea/gitea`
- Rank: 279
- Summary: Gitea: Release attachment extension allowlist bypass via web release edit form (variant of CVE-2025-68939)
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 18762c77 batch-loads actions run/job/task API data. Same SHA and bundle fix de4b8277 as GHSA-66M4 in this slice. Deeper blame attributed six lines on oauth.go, api.go, and permission.go from other AI SHAs, not the ranked commit. File overlap on actions list helpers is routing. Shared SHA without mechanism equality is not attachment-allowlist origin.

### 10 GHSA-WM3W-8RRP-J577 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `guzzle/guzzle`
- Rank: 280
- Summary: Guzzle: Host-only cookie scope is not preserved
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fb92d95f updates CI workflows and PHPStan. Fix 7b68220d is Security fixes 7.15 for cookie scope. Deeper blame attributed zero AI lines. CI/tooling is not origin of host-only cookie handling.

### 11 GHSA-JQ8W-8Q2F-FFM9 — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `zitadel/zitadel`
- Rank: 281
- Summary: ZITADEL Users Can Self-Verify Email/Phone via API
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: First-party advisory names a residual after GHSA-282G (batch2). Ranked AI 282b2486 adds metadata on UpdateUser. Fix ed09b3df is a merge-from-fork of remaining self-verify paths. Deeper blame attributed zero AI lines. Metadata feature and residual sibling path are not proved patch-delta incomplete remediation of this GHSA.

### 12 GHSA-XWX6-JJHV-84P8 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `n8n-io/n8n`
- Rank: 282
- Summary: n8n: Prototype Pollution via Dot-Notation Field Names Leads To Instance-Wide Denial of Service
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 9410e961 preserves Date values in the expression isolate. Same SHA and bundle-backport fix f69dfc6d as five other n8n GHSAs in this slice. Deeper blame attributed 48 lines on computer-use, token-exchange, and MCP files, not Set-node prototype pollution. Shared SHA without mechanism equality is not six origins.

### 13 GHSA-649P-MMHF-85C7 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `go-gitea/gitea`
- Rank: 283
- Summary: Gitea: Cached Per-Branch Permission Check in Pre-Receive Hook Allows Full Repository Write
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI db7eb4d5 fixes issue-label deletion with Actions tokens. Same SHA and bundle fix 99f8b3d9 as GHSA-GX3V. Deeper blame attributed zero AI lines. Label-deletion ACL is not cached per-branch permission origin.

### 14 GHSA-855V-HQ7W-JMJW — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `open-webui/open-webui`
- Rank: 284
- Summary: Open WebUI: Realtime endpoints accept Redis-revoked JWTs after signout/backchannel logout
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 823b9a6d removes unused SRC log env vars (also ranked for GHSA-QG3F). Fix 33b91bd8 adds realtime JWT revocation checks. Deeper blame attributed zero AI lines. Log-env chore is not origin of Socket.IO JWT revocation.

### 15 GHSA-GX3V-Q759-G323 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `go-gitea/gitea`
- Rank: 285
- Summary: Gitea: TOTP TOCTOU race on web 2FA paths + missing replay check on Basic-Auth X-Gitea-OTP surface
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA db7eb4d5 and same bundle fix 99f8b3d9 as GHSA-649P. Deeper blame attributed zero AI lines. Shared SHA without equal mechanism is not TOTP TOCTOU origin.

### 16 GHSA-QG3F-8X3J-GGF2 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `open-webui/open-webui`
- Rank: 286
- Summary: Open WebUI: WEB_FETCH_FILTER_LIST host allow/block filter bypassable via URL path and non-label-boundary matching
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 823b9a6d as GHSA-855V. Fix 087878ce tightens WEB_FETCH_FILTER_LIST hostname matching. Deeper blame attributed zero AI lines. Shared log-env SHA is not hostname-filter origin.

### 17 GHSA-W4Q6-QW23-4RG7 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `github/github-mcp-server`
- Rank: 287
- Summary: GitHub MCP Server has Nil Pointer Dereference DoS in completion/complete Handler
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 61a34c14 documents SERVER_NAME/TITLE and tweaks NewServer comments plus test cleanup. Fix c88d2ecd nil-guards CompletionsHandler params.Ref. Deeper blame attributed zero deleted spans. Comment/docs on NewServer is not origin of the nil-deref.

### 18 GHSA-W5PG-649R-P6GG — REJECT `SIBLING_FIX`

- Repository: `go-gitea/gitea`
- Rank: 288
- Summary: Gitea: Branch Protection Bypass via PR Retargeting Preserves Stale official Approval Flag
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bc9d53a5 clears leftover ReviewTypeRequest when submitting a pending review. Fix 74ad781d re-evaluates the official flag on PR retarget. Deeper blame attributed zero AI lines. Re-request-icon hygiene is not origin of stale official approvals.

### 19 GHSA-CJ9H-QX8G-PQ2G — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `n8n-io/n8n`
- Rank: 289
- Summary: n8n: Shared-Workflow Editor Can Exfiltrate Credentials via Inline Sub-Workflow JSON
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked Date-isolate SHA 9410e961 and same bundle-backport fix f69dfc6d as the other n8n rows in this slice. Deeper blame hits unrelated computer-use and token-exchange files. Shared SHA is not inline sub-workflow credential origin.

### 20 GHSA-3HRF-2GC2-MX32 — REJECT `SIBLING_FIX`

- Repository: `microsoft/kiota`
- Rank: 290
- Summary: Microsoft Kiota: XML Doc-Comment Newline Breakout Code Injection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d032b08a keeps required query params from affecting sibling operations on the same path. Fix ebb632db strips newlines from C# XML doc comments. Deeper blame attributed zero AI lines. Query-param isolation is not origin of doc-comment injection.

### 21 GHSA-HR66-5MQR-8MPX — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Budibase/budibase`
- Rank: 291
- Summary: Budibase: Unauthenticated user information disclosure via public tenant user lookup endpoint
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9eb0917d removes an unused global user onboarding endpoint. Fix e6bf245f is vuln-76 user lookup. Deeper blame attributed zero AI lines. Onboarding-endpoint removal is not origin of public tenant user lookup.

### 22 GHSA-66M4-5JJR-2RG5 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `go-gitea/gitea`
- Rank: 292
- Summary: Gitea: Webhooks created by a collaborator keep firing after their repo access is revoked
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 18762c77 and same bundle fix de4b8277 as GHSA-25GQ. Deeper blame attributed oauth/permission lines from other AI SHAs, not the ranked actions batch-load. Shared SHA without mechanism equality is not webhook-after-revoke origin.

### 23 GHSA-H3RM-78G3-J7CP — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `better-auth/better-auth`
- Rank: 293
- Summary: @better-auth/stripe: cross-organization billing tampering in organization subscription actions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bb89498d handles customer.subscription.created webhooks. Fix 29fbcb57 is a merge-from-fork of organization subscription authorization. Deeper blame attributed zero AI lines. Webhook-created handler is not origin of cross-org billing tampering.

### 24 GHSA-64XH-79J6-R5V8 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `n8n-io/n8n`
- Rank: 294
- Summary: n8n: Bypass Allowed HTTP Request Domains Credential Restriction in Multiple AI and LLM Nodes
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked Date-isolate SHA 9410e961 and same bundle-backport fix f69dfc6d as the other n8n rows. Deeper blame hits unrelated files. Shared SHA is not HTTP-domain restriction origin.

### 25 GHSA-HMJ8-5XMH-5573 — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `libp2p/py-libp2p`
- Rank: 295
- Summary: libp2p: yamux connection DoS via oversized data frame
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Cursor commit bee45b46 rewrites yamux with outgoing MAX_MESSAGE_SIZE and receive-window auto-tuning. Advisory is unbounded incoming DATA length. Fix 146ea87d rejects incoming frames above MAX_WINDOW_SIZE and times out body reads. Deeper blame attributed two AI lines in the rewritten read path. Outgoing size cap is a sibling boundary; residual incoming length check is an untouched sibling, not patch-delta of the AI-added outgoing MaxMessageSize.

### 26 GHSA-RCV6-PVRJ-4XCG — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `n8n-io/n8n`
- Rank: 296
- Summary: n8n: Authenticated code execution in the n8n Git node
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked Date-isolate SHA 9410e961 and same bundle-backport fix f69dfc6d as the other n8n rows. Shared SHA is not Git-node RCE origin.

### 27 GHSA-XMC9-4F2H-JF9C — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `n8n-io/n8n`
- Rank: 297
- Summary: n8n: Edit Image Node Format Injection Allows Arbitrary File Write
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked Date-isolate SHA 9410e961 and same bundle-backport fix f69dfc6d as the other n8n rows. Shared SHA is not Edit Image format-injection origin.

### 28 GHSA-PM5P-7W5H-JM5Q — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `alextselegidis/easyappointments`
- Rank: 298
- Summary: Easy!Appointments has server-side request forgery in CalDAV connection test that exposes the deployment's internal network
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a1b00516 parses CalDAV calendar-data by namespace URI and isolates per-event import errors. Fix 2da2baed wires an enable_ssrf_check flag (subject: always allow http://baikal). Deeper blame attributed zero AI lines. XML namespace robustness is not origin of CalDAV SSRF.

### 29 GHSA-GV7G-JM28-CR3M — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `n8n-io/n8n`
- Rank: 299
- Summary: n8n: Expression sandbox escape via arrow-function bodies enabling command execution
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked Date-isolate SHA 9410e961 and same bundle-backport fix f69dfc6d as the other n8n rows. Expression Date preservation is not arrow-function sandbox-escape origin.

### 30 GHSA-5QJQ-93H5-HRGP — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `py-pdf/pypdf`
- Rank: 300
- Summary: pypdf: Possible large memory usage for wrong image dimensions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0276a6fa avoids a per-pixel getpixel loop for 1-bit indexed images. Fix c64583be applies a general requested-image-size limit. Deeper blame attributed zero AI lines. Pixel-loop performance is not origin of declared-dimension memory exhaustion.

## Conservation

- rank_pool 3473 = 270 prior directroot reviews + 30 this slice + 530 unreviewed hits + 2643 rank misses
- hits 830; excluded-in-hits 270 (batches 1-9); canonical73 IDs were already outside this hit slice
- Incoming unreviewed hits before this slice: 560; after: 530
- Unreviewed remaining IDs are UNREVIEWED, not REJECT

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD.
