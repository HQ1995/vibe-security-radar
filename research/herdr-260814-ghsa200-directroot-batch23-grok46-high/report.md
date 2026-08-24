# Direct-root mining batch 23 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical81 and directroot batches 1-22, including the frozen batch22 selected-30. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. Canonical81's three append identities already sit in batch9 and batch11, so they do not add extra ranked-hit skips. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 140
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 660+30+140+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical81 strict identities plus batch1-22 `selected-30.jsonl`/`cases.jsonl`, including terminal batch21 selected/cases and frozen in-progress batch22 selected-30. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-2CWQ-PWFR-WCW3 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `AArnott/Nerdbank.MessagePack`
- Rank: 661
- Summary: Nerdbank.MessagePack: Attacker-controlled stackalloc in DateTime decoding causes process-terminating StackOverflowException
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4751a197 is Copilot exception wrapping in array/map converters and uses no Co-authored-by marker. Fix merges DateTime timestamp stackalloc bounds. Deeper blame attributed zero AI lines. Converter overlap is routing, not DateTime stackalloc origin.

### 02 GHSA-62HF-57XW-28J9 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `axios/axios`
- Rank: 662
- Summary: Axios: unbounded recursion in toFormData causes DoS via deeply nested request data
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d8233d9e restores AxiosError.cause typing. Fix bounds toFormData recursion. Deeper blame attributed zero AI lines. index.d.ts overlap is routing, not nested-form-data origin.

### 03 GHSA-PQ29-69JG-9MXC — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `rustfs/rustfs`
- Rank: 663
- Summary: RustFS Path Traversal Vulnerability
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 277d80de implements a priority heal queue. Deeper blame attributed one AI line in local.rs from a different Copilot heal SHA a8b7b28, not the advisory read_file_stream path. Parent blame of the open_file call is 9384b831. Fix adds check_valid_path. Shared SHA without mechanism equality is not path-traversal origin.

### 04 GHSA-C5CP-VX83-JHQX — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `langflow-ai/langflow`
- Rank: 664
- Summary: Langflow Missing Authentication on Critical API Endpoints
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b5a6f397 adds Component Inputs telemetry, the same SHA already reviewed for batch20 GHSA-VWMF. Fix authenticates various endpoints. Deeper blame attributed zero AI lines. chat.py overlap is routing, not missing-auth origin.

### 05 GHSA-5HVC-6WX8-MVV4 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `trailofbits/fickling`
- Rank: 665
- Summary: Fickling vulnerable to use of ctypes and pydoc gadget chain to bypass detection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5e054ddc is an explicit Claude ast.unparse crash fix for malformed pickle identifiers. Fix adds ctypes and pydoc to the unsafe-import list. Deeper blame attributed zero AI lines. Identifier extraction is a sibling fickle.py change, not ctypes/pydoc blocklist origin. Shared SHA with GHSA-Q5QQ does not imply mechanism equality.

### 06 GHSA-232V-J27C-5PP6 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `MCPJam/inspector`
- Rank: 666
- Summary: REC in MCPJam inspector due to HTTP Endpoint exposes
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d10e689e integrates WorkOS auth. Fix closes an exposed HTTP port. Deeper blame attributed zero AI lines. server/index.ts overlap is routing, not port-exposure origin.

### 07 GHSA-36P8-MVP6-CV38 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `cloudflare/workers-sdk`
- Rank: 667
- Summary: Wrangler affected by OS Command Injection in `wrangler pages deploy`
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 1655bec5 reports workerd startup errors before profiling. Fix executes git commands in pages deploy safely. Deeper blame attributed zero AI lines. deploy.ts overlap is routing, not --commit-hash shell origin.

### 08 GHSA-3G2F-4RJG-9385 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `WeblateOrg/weblate`
- Rank: 668
- Summary: Weblate leaks information via screenshots
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 89664a49 fixes an unused local variable. Fix proxies the screenshot view. Deeper blame attributed zero AI lines. middleware.py overlap is routing, not screenshot-leak origin.

### 09 GHSA-VQXF-V2GG-X3HC — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `docling-project/docling-core`
- Rank: 669
- Summary: docling-core vulnerable to Remote Code Execution via unsafe PyYAML usage
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0f7ca77c adds a key-value visualizer. Fix switches to a safe YAML loader. Deeper blame attributed zero AI lines. document.py overlap is routing, not yaml.load origin.

### 10 GHSA-96XM-FV9W-PF3F — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `stellar/rs-soroban-sdk`
- Rank: 670
- Summary: soroban-sdk has overflow in Bytes::slice, Vec::slice, GenRange::gen_range for u64
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ecad5add adds bn254 and poseidon host functions. Fix bounds slice/gen_range overflows. Deeper blame attributed zero AI lines. tests.rs overlap is routing, not u64 range-overflow origin.

### 11 GHSA-GJQQ-6R35-W3R8 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `getarcaneapp/arcane`
- Rank: 671
- Summary: Arcane Has a Command Injection in Arcane Updater Lifecycle Labels That Enables RCE
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 75fc5f06 adds container/image update notifications onto updater_service.go. Fix removes lifecycle pre/post-update shell labels. Deeper blame attributed zero AI lines. Notification wiring is a sibling updater change, not unsanitized lifecycle-label origin.

### 12 GHSA-J7XP-4MG9-X28R — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `lobehub/lobe-chat`
- Rank: 672
- Summary: Lobe Chat has IDOR in Knowledge Base File Removal that Allows Cross User File Deletion
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a91f9034 adds S3 module unit tests. Fix adds userId authorization on removeFilesFromKnowledgeBase. Deeper blame attributed zero AI lines. S3 index.test.ts overlap is routing, not knowledge-base IDOR origin.

### 13 GHSA-J62C-4X62-9R35 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `sveltejs/kit`
- Rank: 673
- Summary: SvelteKit is vulnerable to denial of service and possible SSRF when using prerendering
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b2c5d029 supports multiple cookies with the same name. Fix is a merge from the prerendering fork. Deeper blame attributed zero AI lines. respond.js overlap is routing, not prerender fetch origin.

### 14 GHSA-Q5QQ-MVFM-J35X — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `trailofbits/fickling`
- Rank: 674
- Summary: Fickling has Static Analysis Bypass via Incomplete Dangerous Module Blocklist
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5e054ddc is the same ast.unparse crash fix as GHSA-5HVC. Fix adds importlib, code, and multiprocessing to unsafe modules. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not the incomplete-blocklist origin.

### 15 GHSA-9RP8-H4G8-8766 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `WeblateOrg/wlc`
- Rank: 675
- Summary: Weblate wlc has insecure API key configuration
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f30eea7d improves error reporting. Fix avoids loading the API key from system-wide settings. Deeper blame attributed zero AI lines. test_base.py overlap is routing, not system-wide key origin.

### 16 GHSA-4H3H-63V6-88QX — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `esphome/esphome`
- Rank: 676
- Summary: ESPHome vulnerable to denial-of-service via out-of-bounds check bypass in the API component
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 487e1f87 switches call sites to encode_uintXX and only adds an include in proto.cpp. Fix uses subtraction for protobuf bounds checks. Deeper blame attributed zero AI lines. Include-only overlap is routing, not ptr+field_length overflow origin.

### 17 GHSA-Q3JJ-46PQ-826R — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `openclaw/openclaw`
- Rank: 677
- Summary: OpenClaw's ACP child sessions inherit subagent security envelope constraints
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 3b0c80ce adds per-sender group tool policies. Fix enforces subagent envelope inheritance on ACP child sessions. Deeper blame attributed zero AI lines. pi-tools overlap is a sibling policy change, not ACP child-envelope origin.

### 18 GHSA-2CP6-34R9-54XX — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `microsoft/maker.js`
- Rank: 678
- Summary: Maker.js has Unsafe Property Copying in makerjs.extendObject
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4a4a24d4 replaces eval-based environment detection with typeof checks. Fix filters dangerous keys in extendObject. Deeper blame attributed zero AI lines. Eval removal is a sibling maker.ts hardening, not prototype-pollution origin.

### 19 GHSA-95CV-R8X4-VH75 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `OpenListTeam/OpenList`
- Rank: 679
- Summary: OpenList: Authenticated users can rename files outside their base path via batch rename `src_name` traversal
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d85f084a adds fine-grained meta permissions and notes that FsBatchRename checks parent permissions only. Fix validates src_name. Deeper blame attributed zero AI lines. Permission rewrite is a sibling fsbatch.go change, not src_name traversal origin. Advisory introduced:0.

### 20 GHSA-6QCR-QXGR-M7FV — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `QuantumNous/new-api`
- Rank: 680
- Summary: New API: SSRF Protection Bypass via Unresolved Hostname in Notification URLs
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 202a433f adds a Waffo payment gateway. Fix hardens SSRF checks on notification URLs. Deeper blame attributed zero AI lines. api-router.go overlap is routing, not unresolved-hostname SSRF origin.

### 21 GHSA-F456-RF33-4626 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `orval-labs/orval`
- Rank: 681
- Summary: Orval Mock Generation Code Injection via const
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d50ce612 adds Faker v9 multipleOf onto an already-interpolated faker.number.float template. Fix escapes mocked values. Deeper blame attributed zero AI lines. multipleOf interpolation was pre-existing; the residual const injection is an untouched sibling faker path.

### 22 GHSA-JQWH-526H-C92J — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `microsoft/kiota`
- Rank: 682
- Summary: Microsoft Kiota: Code Generation Literal Injection in Kiota PHP Generator
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6ce5e7d3 fixes a C# union NullReferenceException. Fix escapes $ in PHP double-quoted literals. Deeper blame attributed zero AI lines. CodeMethodWriter.cs overlap is routing, not PHP literal-injection origin.

### 23 GHSA-HQ9Q-27G5-QWPJ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `microsoft/kiota`
- Rank: 683
- Summary: Microsoft Kiota: Command injection via x-ms-kiota-info dependencyInstallCommand surfaced by `kiota info`
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI aef1960f fixes empty allOf composed-type models. Fix stops using the OpenAPI extension install command. Deeper blame attributed zero AI lines. KiotaBuilderTests.cs overlap is routing, not dependencyInstallCommand origin.

### 24 GHSA-X36R-4347-PM5X — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `acacode/swagger-typescript-api`
- Rank: 684
- Summary: swagger-typescript-api vulnerable to Server-Side Request Forgery via spec `$ref`
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 691d07d8 adds a changeset for preferExistingSchemaNamesForExternalRefs. Fix is a security bundle for $ref SSRF. Deeper blame attributed zero AI lines. code-gen-process.ts overlap is routing, not $ref fetch origin.

### 25 GHSA-WQJV-9729-C5Q2 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `sveltejs/kit`
- Rank: 685
- Summary: SvelteKit: Big remote form function payloads can cause Node process to crash
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 95ca921c removes Content-Length overflow checks in deserialize_binary_form. Fix adds .catch(noop) to prevent unhandled rejection crashing the process. Deeper blame attributed zero AI lines. Overflow-check removal is a sibling form-utils.js change, not the unhandled-rejection crash origin. Clone git tag --contains is empty.

### 26 GHSA-8M8R-38JM-F355 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `koxudaxi/datamodel-code-generator`
- Rank: 686
- Summary: `datamodel-code-generator` vulnerable to code execution on import via unescaped `validators` entries in --extra-template-data
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI df834dcf sets validate_default=True for structured union defaults. Fix is a merge from the extra-template-data fork. Deeper blame attributed zero AI lines. pydantic_v2/base_model.py overlap is routing, not unescaped validators origin.

### 27 GHSA-FH2F-XFXC-Q9CC — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `bablilayoub/openhole`
- Rank: 687
- Summary: openhole-server vulnerable to path traversal via URL-decoded request path
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 82cd3565 only bumps Version from 0.1.0 to 0.1.1. Fix preserves escaped paths in ForwardToLocal. Deeper blame attributed one AI line in version.go. Version-string overlap is routing, not URL-decoded path-traversal origin. Clone git tag --contains is empty.

### 28 GHSA-G5R6-GV6M-F5JV — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `sooperset/mcp-atlassian`
- Rank: 688
- Summary: mcp-atlassian: Arbitrary file read via missing path validation in confluence_upload_attachment
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ad6af511 adds a filesystem-free content_base64 upload path and keeps the pre-existing file_path open(). Fix confines file_path with validate_safe_path. Deeper blame attributed zero AI lines. Base64 upload is a new sibling path; the GHSA residual is the old unvalidated file_path hole. Advisory introduced:0.

### 29 GHSA-G38M-R43W-P2Q7 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `better-auth/better-auth`
- Rank: 689
- Summary: Better Auth has an account takeover issue via OAuth auto-link to unverified pre-registered email
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6ba15d56 refactors origin-check middleware and only changes isDevelopment() in link-account.ts. Fix blocks OAuth linking to unverified local accounts. Deeper blame attributed ten AI lines in admin.test.ts from a different Copilot SHA 50990564 (has-permission). Shared SHA without mechanism equality is not unverified auto-link origin.

### 30 GHSA-74H3-CXQ7-VC5Q — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `open-webui/open-webui`
- Rank: 690
- Summary: Open WebUI: Cross-user code-interpreter and tool execution via unvalidated Socket.IO event-caller session_id
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 22f2fe1f is an explicit Claude security attempt that authenticates ydoc awareness/leave handlers. Fix scopes get_event_call to the requester's session_id. Deeper blame attributed zero AI lines. ydoc handler auth is a sibling Socket.IO path, not execute:python/tool event-caller origin. Advisory introduced:0.

## Conservation

- rank_pool 3473 = 660 prior directroot reviews + 30 this slice + 140 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch22: 660; this slice 661-690
- Incoming unreviewed hits before this slice: 170; after: 140
- Canonical81 append identities GHSA-X4HG-HFWF-P9MW, GHSA-322X-V876-G883, and GHSA-PMCH-G965-GRMR were already in batch9 and batch11
- Stale 260813 batch3 equals formal 260814 batch3 (30 IDs) and is not 30 extra reviewed rows
- Unreviewed remaining IDs are UNREVIEWED, not REJECT
- Checkpoint at 75 percent recorded before the final seven rows, then the assigned slice was exhausted

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD. Three deeper-blame hits (GHSA-PQ29 one heal-queue line in local.rs from a different SHA; GHSA-FH2F a version.go bump; GHSA-G38M ten admin.test.ts lines from a different SHA) still fail ai_hunk and but-for. GHSA-WQJV, GHSA-G5R6, and GHSA-74H3 are sibling-path security-adjacent AI edits, not seven-gate direct-root.
