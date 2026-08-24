# Direct-root mining batch 13 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly the next 30 highest-score unassigned rank hits after canonical73 plus directroot batches 1-12, including frozen in-progress batch11 and batch12 selections. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 440
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 360+30+440+2643=3473 rank_pool

## Selection

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending (equals original ranks 1-830). Excluded every GHSA in canonical73 strict IDs and in batch1-batch12 selected-30/cases artifacts, including frozen in-progress batch11 and batch12 selections. Overlap with each excluded set is zero. Assigned original ranks 361-390. Selection recorded in `work/selected-30.jsonl` before review.

## Method

Each row used the frozen github-reviewed advisory JSON, the ranked AI SHA and fix SHA, first-parent `git log`/`diff`, release-tag containment where present, and deeper `git blame -l -w` of source deleted hunks on the fix parent against the AI-commit index. File-history overlap without blamed deleted lines remains routing. Incomplete-remediation security attempts stay out of this direct-root lane unless all patch-delta clauses pass. Shared SHAs without mechanism equality are rejected.

## Cases

### 01 GHSA-9C54-GXH7-PPJC — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `LearningCircuit/local-deep-research`
- Rank: 361
- Summary: Local Deep Research is Vulnerable to Server-Side Request Forgery (SSRF) in Download Service
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 56eda07d changes a client.py docstring example from llama:8b to llama2:7b. Fix b79089ff migrates requests usage to SafeSession across download_service and other HTTP call sites. Deeper blame attributed two lines on settings_routes.py from a different AI SHA. A docstring edit is not origin of download-service SSRF.

### 02 GHSA-MV7P-34FV-4874 — REJECT `SIBLING_FIX`

- Repository: `nocobase/nocobase`
- Rank: 362
- Summary: Authentication Bypass via Default JWT Secret in NocoBase docker-compose Deployments
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e0c3878e adds multipart/form-data to the workflow-request plugin. Fix de4292ea hardens JWT secret handling. Deeper blame attributed zero AI lines. Workflow upload encoding is not origin of default JWT secret bypass.

### 03 GHSA-565G-HWWR-4PP3 — REJECT `SIBLING_FIX`

- Repository: `trailofbits/fickling`
- Rank: 363
- Summary: Fickling has missing detection for marshal.loads and types.FunctionType in unsafe modules list
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5e054ddc fixes ast.unparse crashes on malformed pickle identifiers. The first-party advisory states that crash is unrelated. Fix 4e345613 adds marshal and types to the unsafe-module denylist. Deeper blame attributed zero AI lines. Identifier extraction is not origin of the omitted denylist entries.

### 04 GHSA-F4CF-9RVR-2RCX — REJECT `SIBLING_FIX`

- Repository: `zitadel/zitadel`
- Rank: 364
- Summary: Zitadel Discloses the Total Number of Instance Users
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 8fc11a73 ports user API requests to the resource API. Fix 826039c6 is a merge-from-fork that stops leaking total user counts. Deeper blame attributed zero AI lines. Resource-API porting is not origin of count disclosure.

### 05 GHSA-2267-XQCF-GW2M — REJECT `SIBLING_FIX`

- Repository: `NeoRazorX/facturascripts`
- Rank: 365
- Summary: FacturaScripts is Vulnerable to Stored Cross-Site Scripting (XSS) via XML File Upload
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 928ff763 adds cache headers to static/MyFiles controllers. Fix e908ade2 forces download of xml/svg/html. Deeper blame attributed zero AI lines. Cache-Control is not origin of stored XSS via XML upload.

### 06 GHSA-C6XV-RCVW-V685 — REJECT `SIBLING_FIX`

- Repository: `open-webui/open-webui`
- Rank: 366
- Summary: Open WebUI vulnerable to Server-Side Request Forgery (SSRF) via Arbitrary URL Processing in /api/v1/retrieval/process/web
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b4bc71d1 adds granular workspace import/export permissions. Fix 02238d31 adds SSRF blocklist on retrieval web fetch. Deeper blame attributed zero AI lines. Import/export ACL is not origin of retrieval URL SSRF.

### 07 GHSA-XRQC-7XGX-C9VH — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `argoproj/argo-workflows`
- Rank: 367
- Summary: RCE via ZipSlip and symbolic links in argoproj/argo-workflows
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 97635e65 is a linting chore. Fix 6b92af23 hardens executor archive extraction. Deeper blame attributed zero AI lines. Linting is not ZipSlip origin.

### 08 GHSA-WPQC-H9WP-CHMQ — REJECT `SIBLING_FIX`

- Repository: `n8n-io/n8n`
- Rank: 368
- Summary: n8n vulnerable to Remote Code Execution via Git Node Custom Pre-Commit Hook
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 2cb8e843 adds dynamic editor banners. Fix d5a1171f disables Git hooks by default. Deeper blame attributed zero AI lines. Banner config is not origin of Git-node pre-commit RCE.

### 09 GHSA-8FR4-5Q9J-M8GM — REJECT `SIBLING_FIX`

- Repository: `vllm-project/vllm`
- Rank: 369
- Summary: vLLM vulnerable to remote code execution via transformers_utils/get_config
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c438b295 enables engine-level arguments with speculators models. Fix ffb08379 removes a Nemotron-Nano-VL config copy. Deeper blame attributed zero AI lines. Speculators engine args are not origin of get_config RCE.

### 10 GHSA-W832-GG5G-X44M — REJECT `SIBLING_FIX`

- Repository: `simonw/datasette`
- Rank: 370
- Summary: Open redirect endpoint in Datasette
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 400fa08e adds keyset pagination to allowed_resources(). Fix f257ca6e closes the open redirect. Deeper blame attributed zero AI lines. Pagination is not origin of the redirect endpoint.

### 11 GHSA-J4G7-V4M4-77PX — REJECT `SIBLING_FIX`

- Repository: `zitadel/zitadel`
- Rank: 371
- Summary: ZITADEL is vulnerable to Account Takeover with deactivated Instance IdP
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5403be7c ports user profile requests in resource APIs. Fix 33c51deb is a merge-from-fork of deactivated-IdP takeover. Deeper blame attributed zero AI lines. Profile resource APIs are not origin of deactivated-IdP ATO.

### 12 GHSA-H238-5MWF-8XW8 — REJECT `SIBLING_FIX`

- Repository: `treeverse/lakeFS`
- Rank: 372
- Summary: lakeFS affected by unauthenticated access to API usage metrics
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c5680959 adds IAM policy statement conditions. Fix 1c8adab8 is a merge-from-fork of metrics auth. Deeper blame attributed zero AI lines. IAM conditions are not origin of unauthenticated usage metrics.

### 13 GHSA-6QV9-48XG-FC7F — REJECT `SIBLING_FIX`

- Repository: `langchain-ai/langchain`
- Rank: 373
- Summary: LangChain Vulnerable to Template Injection via Attribute Access in Prompt Templates
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 46971447 filters empty content blocks from formatted prompts. Fix c4b6ba25 restricts f-string/jinja2/mustache template features. Deeper blame attributed zero AI lines. Empty-block filtering is not origin of attribute-access template injection.

### 14 GHSA-Q66Q-FX2P-7W4M — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `modelcontextprotocol/servers`
- Rank: 374
- Summary: @modelcontextprotocol/server-filesystem allows for path validation bypass via prefix matching and symlink handling
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 4e31b9d6 only changes a fatal-error log string in src/filesystem/index.ts. Same SHA as GHSA-HC55. Fix d00c60df addresses symlink and path-prefix allowed-directory checks. Deeper blame attributed zero AI lines. Shared log-string SHA without mechanism equality is not symlink/prefix origin.

### 15 GHSA-HC55-P739-J48W — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `modelcontextprotocol/servers`
- Rank: 375
- Summary: @modelcontextprotocol/server-filesystem vulnerability allows for path validation bypass via colliding path prefix
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 4e31b9d6 as GHSA-Q66Q. Fix cc99bdab merges the path-prefix/symlink security branch. Deeper blame attributed zero AI lines. Shared log-string SHA is not colliding-prefix origin.

### 16 GHSA-526J-MV3P-F4VV — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `lf-edge/ekuiper`
- Rank: 376
- Summary: eKuiper API endpoints handling SQL queries with user-controlled table names
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Copilot Autofix f47289ab adds isValidTableName on createSqlTs. Advisory and fix 72c49187 target getLast SQL interpolation plus Prepare/Exec misuse. Deeper blame attributed zero deleted AI lines. Residual getLast is an untouched sibling path of the createSqlTs guard, not proved patch-delta incomplete remediation.

### 17 GHSA-QP7J-X725-G67F — REJECT `SIBLING_FIX`

- Repository: `hydraide/hydraide`
- Rank: 377
- Summary: HydrAIDE Authentication Bypass Vulnerability
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7413ae77 fixes a non-Docker port configuration prompt. Fix b252554a is a merge-from-fork of authentication bypass. Deeper blame attributed zero AI lines. CLI port prompt is not origin of auth bypass.

### 18 GHSA-GM8Q-M8MV-JJ5M — REJECT `SIBLING_SECURITY_ATTEMPT`

- Repository: `Unstructured-IO/unstructured`
- Rank: 378
- Summary: Unstructured has Path Traversal via Malicious MSG Attachment that Allows Arbitrary File Write
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 1c519efe remediates unrelated dependency CVEs and bumps __version__.py. Fix b01d35b2 sanitizes MSG attachment filenames. Deeper blame attributed the version-string line only. Dependency CVE maintenance is not origin of MSG path traversal.

### 19 GHSA-2W46-VQ8H-98VH — REJECT `SIBLING_FIX`

- Repository: `shopware/shopware`
- Rank: 379
- Summary: Shopware 6's password recovery link does not expire after email change
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 140ee5cd updates Symfony validator named arguments. Fix 2fb94855 expires recovery on email change. Deeper blame attributed zero AI lines. Constraint-argument syntax is not origin of stale recovery links.

### 20 GHSA-43FC-JF86-J433 — REJECT `OLD_BUG_REFACTOR`

- Repository: `axios/axios`
- Rank: 380
- Summary: Axios is Vulnerable to Denial of Service via __proto__ Key in mergeConfig
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 860e0339 switches extend/inherits to Object.defineProperty for HardenedJS frozen prototypes. Advisory is mergeConfig TypeError on JSON __proto__ keys, ecosystem-introduced at 1.0.0. Fix 28c72158 rewrites mergeConfig and reformats lib/utils.js; deeper blame of 14 AI lines is rewrite attribution, not mergeConfig origin. Frozen-prototype compatibility is not but-for of the old mergeConfig crash.

### 21 GHSA-RF4G-89H5-CRCR — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `chainguard-dev/melange`
- Rank: 381
- Summary: melange affected by potential host command execution via license-check YAML mode patch pipeline
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 6e243d0d is a merge-from-fork that validates tar paths for GHSA-qxx2. Fix bd132535 is another merge-from-fork for patch.yaml shell injection. Deeper blame attributed one test line. Shared SHA without mechanism equality is not patch-pipeline command-injection origin.

### 22 GHSA-6V48-FCQ6-FF23 — REJECT `SIBLING_FIX`

- Repository: `dagu-org/dagu`
- Rank: 382
- Summary: Dagu: Path traversal in DAG creation allows arbitrary YAML file write outside DAGs directory
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c861c6be aligns canonical status strings. Fix e2ed5891 closes create-API path traversal. Deeper blame attributed zero AI lines. Status-string alignment is not origin of DAG path traversal.

### 23 GHSA-G34W-4XQQ-H79M — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 383
- Summary: OpenClaw iMessage group allowlist authorization inherited DM pairing-store identities
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ab4a08a8 defers gateway restart until replies are sent. Fix 872079d4 keeps DM pairing-store identities out of group allowlist auth. Deeper blame attributed zero AI lines. Restart deferral is not origin of iMessage group allowlist inheritance.

### 24 GHSA-V6C6-VQQG-W888 — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 384
- Summary: OpenClaw affected by potential code execution via unsafe hook module path handling in Gateway
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 079af0d0 lets token auth bypass device identity. Fix 35c0e66e hardens hooks module loading. Deeper blame attributed zero AI lines. Token-vs-device auth order is not origin of unsafe hook module paths.

### 25 GHSA-W5CR-2QHR-JQC5 — REJECT `SIBLING_FIX`

- Repository: `cloudflare/agents`
- Rank: 385
- Summary: Cloudflare Agents has a Reflected Cross-Site Scripting (XSS) vulnerability in AI Playground site
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 026696f0 adds createMcpHandler for a stateless MCP worker. Fix 3f490d04 escapes HTML in an external OAuth error message. Deeper blame attributed zero AI lines. MCP worker helper is not origin of playground reflected XSS.

### 26 GHSA-PGVM-WXW2-HRV9 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `labstack/echo`
- Rank: 386
- Summary: Echo has a Windows path traversal via backslash in middleware.Static default filesystem
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b4ea9248 fixes a comment typo in SetParamValues. Fix b1d44308 hardens Static middleware path handling. Deeper blame attributed zero AI lines. A comment typo is not origin of Windows backslash traversal.

### 27 GHSA-WH94-P5M6-MR7J — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 387
- Summary: OpenClaw Discord moderation authorization used untrusted sender identity in tool-driven flows
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 06b961b0 flattens remaining anyOf/oneOf in Gemini schema cleaning. Fix 77581603 enforces trusted sender auth for Discord moderation. Deeper blame attributed zero AI lines. Gemini schema flattening is not origin of Discord moderation authz.

### 28 GHSA-5XFQ-5MR7-426Q — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 388
- Summary: OpenClaw's unsanitized session ID enables path traversal in transcript file operations
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c4e76eb6 enables image attachments in Claude chat messages. Fix cab0abf5 resolves transcript paths with explicit agent context. Deeper blame attributed zero AI lines. Image attachments are not origin of session-ID path traversal.

### 29 GHSA-H9G4-589H-68XV — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 389
- Summary: OpenClaw has an authentication bypass in sandbox browser bridge server
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 3b0c80ce adds per-sender group tool policies. Fix 6dd6bce9 enforces sandbox bridge auth. Deeper blame attributed zero AI lines. Group tool-policy precedence is not origin of sandbox bridge auth bypass.

### 30 GHSA-M82Q-59GV-MCR9 — REJECT `SIBLING_FIX`

- Repository: `n8n-io/n8n`
- Rank: 390
- Summary: n8n Vulnerable to Arbitrary File Write on Remote Systems via SSH Node
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9319139a switches to structured destination nodes. Fix 528ad6b9 sanitizes filenames for file operations including the SSH node. Deeper blame attributed zero AI lines. Destination-node structure is not origin of SSH arbitrary file write.

## Conservation

- rank_pool 3473 = 360 prior directroot reviews + 30 this slice + 440 unreviewed hits + 2643 rank misses
- hits 830; excluded-in-hits 360 (batches 1-12); canonical73 IDs were already outside this hit slice
- Incoming unreviewed hits before this slice: 470; after: 440
- Unreviewed remaining IDs are UNREVIEWED, not REJECT

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD.
