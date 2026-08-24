# Direct-root mining batch 24 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical81 and directroot batches 1-23, including frozen batch23 selected-30 and terminal batch21/batch22 selected/cases. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 110
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 690+30+110+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical81 strict identities plus batch1-23 `selected-30.jsonl`/`cases.jsonl`, including frozen batch23 selected-30 and terminal batch21/batch22. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-JPCW-4WR7-C3VQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `getkin/kin-openapi`
- Rank: 691
- Summary: kin-openapi openapi3filter: unauthenticated nil-pointer panic when validating a request against a content parameter whose media type has no schema
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b292ee06 honors comma-separated and wildcard encoding.contentType. Fix is a merge-from-fork against a nil schema on content parameters. Deeper blame attributed zero AI lines. req_resp_decoder.go overlap is routing, not nil-schema panic origin.

### 02 GHSA-PGWH-4JJ4-QM8V — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `flytohub/flyto-core`
- Rank: 692
- Summary: Flyto2 Core: Multiple HTTP-family modules fetch client-controlled URLs without the SSRF guard their siblings apply
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 082b7a37 only adds agent.* to browser can_connect_to, including a one-line proxy_rotate.py wiring change. Fix adds missing per-module SSRF guards. Deeper blame attributed three import lines to a different SHA b7e7710c on http.get/request/batch, not the ranked commit. Shared file without mechanism equality is not missing-sibling-guard origin.

### 03 GHSA-73X5-H92W-XC2J — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 693
- Summary: Open WebUI: Private channel messages can be disclosed through cross-channel thread parent_id binding
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b3ca943d batches user lookup in model_response_handler thread history. Fix binds thread parent/reply to the URL channel. Deeper blame attributed zero AI lines. channels.py overlap is routing, not cross-channel parent_id origin.

### 04 GHSA-G2R8-WVMJ-JF5W — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `nrwl/nx`
- Rank: 694
- Summary: nx graph dev server permissive CORS policy
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c1a93cb0 sets windowsHide on child process spawns across 109 files. Fix removes the graph-app Access-Control-Allow-Origin header. Deeper blame attributed zero AI lines. graph.ts overlap is routing, not permissive CORS origin.

### 05 GHSA-JR5X-6H83-WRXF — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `go-gitea/gitea`
- Rank: 695
- Summary: Gitea: REST API exposes organization membership of private organizations to public
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0724344a is a 70-file CodeQL alert sweep. Fix stops exposing private org membership via public_members. Deeper blame attributed zero AI lines. member.go overlap is routing, not public_members origin.

### 06 GHSA-RWXX-MRJM-WC2M — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vllm-project/vllm`
- Rank: 696
- Summary: vLLM: ReDoS via structured_outputs.regex compiled without timeout in xgrammar and outlines backends
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e2f993dc integrates DeepEP v2. Fix adds a timeout guard for regex compilation. Deeper blame attributed zero AI lines. envs.py overlap is routing, not regex-timeout origin.

### 07 GHSA-WJJJ-24CX-F28G — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `surrealdb/surrealdb`
- Rank: 697
- Summary: SurrealDB has unauthenticated remote DoS via malformed RPC use call
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0bf1a519 improves error communication and serialisation across 102 files. Fix stops panicking on use { db: x } without namespace. Deeper blame attributed zero AI lines. protocol.rs overlap is routing, not malformed-use panic origin.

### 08 GHSA-HR7P-WG7R-HG9M — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `flytohub/flyto-core`
- Rank: 698
- Summary: Flyto2 Core: ${env.VAR} interpolation reads any env secret despite env.get being denylisted
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d5fda807 renames _get_nested_value to get_nested_value. Parent already called os.getenv for ${env.*}. Fix newly gates interpolation through is_env_var_allowed. Deeper blame attributed zero AI lines. Preserving the old getenv path is not env-interpolation origin.

### 09 GHSA-PVCR-8MVP-W8QR — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Budibase/budibase`
- Rank: 699
- Summary: Budibase: Chat-Link Handoff Identity Confusion (Same-Tenant Account-Link CSRF)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 77ecbd3a is prettier formatting on the chat link confirmation page. Fix is a merge for chat-link identity confusion. Deeper blame attributed zero AI lines. chatIdentityLinks.ts overlap is routing, not account-link CSRF origin.

### 10 GHSA-8MPJ-M6QM-5QR8 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `lepture/mistune`
- Rank: 700
- Summary: Mistune directives/include: mutual include recursion crashes the renderer with RecursionError
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5afeaf6b filters image-directive src through safe_url. Fix constrains include targets and recursion. Deeper blame attributed zero AI lines. Image-src sanitization is a sibling directive path, not include-recursion origin, and is not a patch-delta of the same omitted-include boundary.

### 11 GHSA-GCFJ-64VW-6MP9 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `axios/axios`
- Rank: 701
- Summary: Axios Node HTTP adapter can use an inherited proxy after interceptor config cloning
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6bb12c19 strips custom auth headers on cross-origin redirects, the same SHA as GHSA-42H9 and GHSA-MMX7. Fix is the same malformed-URL commit. Deeper blame attributed one redirect-test line in http.test.js, not inherited-proxy origin. Shared SHA without mechanism equality is not interceptor-proxy origin.

### 12 GHSA-FRVJ-C5QP-XJ4W — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 702
- Summary: open-webui terminal proxy path traversal guard bypass via 9x encoded traversal
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f5f4b589 hardens model profile images against SVG stored XSS. Fix fails closed when the proxy/redirect path decode cap is exceeded. Deeper blame attributed zero AI lines. models.py overlap is routing, not 9x-encoded traversal origin.

### 13 GHSA-42H9-826W-CGV3 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `axios/axios`
- Rank: 703
- Summary: Axios: Excessive recursion in formDataToJSON can cause denial of service
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6bb12c19 is the same redirect header-strip commit as GHSA-GCFJ. Fix is the same malformed-URL commit. Deeper blame attributed one redirect-test line, not formDataToJSON recursion. Shared SHA without mechanism equality is not formData DoS origin.

### 14 GHSA-2M9V-5Q2G-58VQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `go-gitea/gitea`
- Rank: 704
- Summary: Gitea: Git LFS object reuse allows non-Code access to authorize private source objects
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d69b7860 fixes LFS GC. Fix requires Code-unit access for cross-repo LFS object reuse. Deeper blame attributed zero AI lines. lfs.go overlap is routing, not LFS reuse-authorization origin.

### 15 GHSA-6V4M-FW66-8R4X — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `ericcornelissen/shescape`
- Rank: 705
- Summary: Shescape: Path disclosure on Unix with Zsh
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 90563030 adds an ESLint missing-rule detector with Assisted-by Claude. Fix is the same overall-escaping commit as GHSA-GM3R and GHSA-W4HW. Deeper blame attributed zero AI lines. eslint.js overlap is tooling routing, not Zsh path-disclosure origin.

### 16 GHSA-GM3R-Q2WP-HW87 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `ericcornelissen/shescape`
- Rank: 706
- Summary: Shescape: Quadratic-time denial of service in the flag-protection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 90563030 is the same ESLint detector as GHSA-6V4M. Fix is the same overall-escaping commit. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not flag-protection DoS origin.

### 17 GHSA-29W2-FQ35-V728 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `awslabs/mcp`
- Rank: 707
- Summary: AWS API MCP Server Security Policy Bypass via Startup Initialization Failure
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 04e24706 removes duplicate assignments in tests. Fix closes a security-policy bypass when startup initialization fails. Deeper blame attributed zero AI lines. test_server.py overlap is routing, not init-failure policy origin.

### 18 GHSA-W284-33MX-6G9V — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `acacode/swagger-typescript-api`
- Rank: 708
- Summary: swagger-typescript-api vulnerable to code injection via unescaped OpenAPI path strings in generated method bodies
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 691d07d8 adds a changeset for preferExistingSchemaNamesForExternalRefs. Fix is a bundled security commit. Deeper blame attributed zero AI lines. code-gen-process.ts overlap is routing, not unescaped path-string origin.

### 19 GHSA-3WHF-VGF2-9W6G — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `zingolabs/zaino`
- Rank: 709
- Summary: zaino-state has a Non-Finalized State Reorg — No Cycle Detection or Depth Limit
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 75d00747 bounds NFS sync apply at the iter's committed chain_height. Fix adds a recursion bound to handle_reorg. Deeper blame attributed zero AI lines. Sync-height bounding is a sibling NFS loop, not reorg cycle/depth origin, and is not a patch-delta of the same omitted-reorg boundary.

### 20 GHSA-2XWM-4H2Q-GGFX — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `open-webui/open-webui`
- Rank: 710
- Summary: Open WebUI: Model meta.knowledge read-only file access can be upgraded to file write/delete
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d169f086 gates the shared-chat branch on access_type == read. Fix requires object-owner equality on knowledge-base and workspace-model branches. Deeper blame attributed zero AI lines. The later fix does not amend the AI-added shared-chat gate. Shared-chat write narrowing is a sibling authorization branch, not meta.knowledge write-upgrade origin.

### 21 GHSA-G357-X5C3-C72P — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `harttle/liquidjs`
- Rank: 711
- Summary: LiquidJS: pop filter bypasses memoryLimit accounting that its array-filter siblings enforce
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 3616a744 rewrites strip_html as a linear scan to avoid ReDoS. Fix charges pop-filter allocation to memoryLimit. Deeper blame attributed zero AI lines. strip_html ReDoS hardening is a sibling filter, not pop-memoryLimit origin, and is not a patch-delta of the same omitted-pop boundary.

### 22 GHSA-F4VV-55C2-5789 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `HKUDS/LightRAG`
- Rank: 712
- Summary: LightRAG is Vulnerable to Authentication Bypass: hardcoded DEFAULT_TOKEN_SECRET and public /auth-status defeat LIGHTRAG_API_KEY protection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 909e5fae refactors tests into mirrored feature folders across 140 files. Fix stops guest tokens from bypassing X-API-Key auth. Deeper blame attributed zero AI lines. test_auth.py overlap is routing, not DEFAULT_TOKEN_SECRET origin.

### 23 GHSA-CHX6-HX7R-MCP5 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `remix-run/react-router`
- Rank: 713
- Summary: React Router: Unauthenticated Denial of Service via Inefficient Route Matching
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7e6725a4 is a 49-file lint cleanup. Fix optimizes route matching internals. Deeper blame attributed zero AI lines. utils.ts/server.ts overlap is routing, not inefficient route-match origin.

### 24 GHSA-MMX7-HFXF-JPPX — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `axios/axios`
- Rank: 714
- Summary: Axios: Prototype pollution gadgets can alter axios request construction
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6bb12c19 is the same redirect header-strip commit as GHSA-GCFJ. Fix is the same malformed-URL commit. Deeper blame attributed one redirect-test line, not prototype-pollution gadgets. Shared SHA without mechanism equality is not prototype-gadget origin.

### 25 GHSA-RG4H-FPCP-2QM8 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `microsoft/kiota`
- Rank: 715
- Summary: Microsoft Kiota: Generation-time SSRF + remote/local file inclusion via unrestricted $ref
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI dc812dbb sanitizes client class and namespace names against code injection. Fix adds an allow list for external $ref resolution. Deeper blame attributed zero AI lines. Name sanitization is a sibling generation hardening, not unrestricted-$ref SSRF origin, and is not a patch-delta of the same omitted-ref boundary.

### 26 GHSA-7R7X-GJVR-448G — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 716
- Summary: Open WebUI: Upload metadata.knowledge_id bypasses the knowledge-base write-access check
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 804f9f31 offloads sync VECTOR_DB_CLIENT calls via AsyncVectorDBClient. Fix authorizes KB write before auto-linking an uploaded file. Deeper blame attributed zero AI lines. files.py overlap is routing, not knowledge_id write-bypass origin.

### 27 GHSA-GV74-J8M3-FG5F — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `better-auth/better-auth`
- Rank: 717
- Summary: @better-auth/sso: SSO provider may allow registration for any org member without checking their role
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e32bad12 prefers UserInfo over ID token and maps the sub claim. Fix requires org admin role to register SSO providers. Deeper blame attributed zero AI lines. sso.ts overlap is routing, not missing-admin-role origin.

### 28 GHSA-V422-HMWV-36X6 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `expressjs/body-parser`
- Rank: 718
- Summary: body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ea1f25e5 switches docs to standard jsdoc tags. Fix improves limit option validation. Deeper blame attributed zero AI lines. utils.js overlap is routing, not invalid-limit DoS origin.

### 29 GHSA-J657-M4C4-24JQ — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `open-webui/open-webui`
- Rank: 719
- Summary: Open WebUI: Terminal proxy forwards a spoofable, integrity-unbound user identity to the upstream
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 05098d25 is the GHSA-FRVJ path-decode fail-closed commit. Fix encodes terminal ws session_id against user_id query injection. Deeper blame attributed zero AI lines. terminals.py overlap is a sibling proxy change, not spoofable X-User-Id origin.

### 30 GHSA-W4HW-QCX7-56PR — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `ericcornelissen/shescape`
- Rank: 720
- Summary: Shescape: Shell injection via unescaped parentheses on Windows with CMD
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 90563030 is the same ESLint detector as GHSA-6V4M. Fix is the same overall-escaping commit. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not CMD parenthesis-injection origin.

## Conservation

- rank_pool 3473 = 690 prior directroot reviews + 30 this slice + 110 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch23: 690; this slice 691-720
- Incoming unreviewed hits before this slice: 140; after: 110
- Stale 260813 batch3 equals formal 260814 batch3 (30 IDs) and is not 30 extra reviewed rows
- Unreviewed remaining IDs are UNREVIEWED, not REJECT
- Checkpoint at 75 percent recorded before the final seven rows, then the assigned slice was exhausted

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD. Four deeper-blame hits remain non-origin: GHSA-PGWH blamed a different SSRF SHA than the ranked browser wiring commit; GHSA-GCFJ/42H9/MMX7 blamed one axios redirect-test line shared across three identities.
