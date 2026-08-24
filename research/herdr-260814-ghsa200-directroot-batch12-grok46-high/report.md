# Direct-root mining batch 12 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly the next 30 highest-score unassigned rank hits after canonical73 plus directroot batches 1-11, including frozen in-progress batch9 and batch11 selections. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 470
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 330+30+470+2643=3473 rank_pool

## Selection

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending (equals original ranks 1-830). Excluded every GHSA in canonical73 strict IDs and in batch1-batch11 selected-30/cases artifacts, including frozen in-progress batch9 and batch11 selections. Overlap with each excluded set is zero. Assigned original ranks 331-360. Selection recorded in `work/selected-30.jsonl` before review.

## Method

Each row used the frozen github-reviewed advisory JSON, the ranked AI SHA and fix SHA, first-parent `git log`/`diff`, release-tag containment where present, and deeper `git blame -l -w` of source deleted hunks on the fix parent against the AI-commit index. File-history overlap without blamed deleted lines remains routing. Incomplete-remediation security attempts stay out of this direct-root lane unless all patch-delta clauses pass. Shared SHAs without mechanism equality are rejected. GHSA-WVPP shares the already-counted GHSA-R9MR check_unsafe_options mechanism.

## Cases

### 01 GHSA-55Q2-FJHQ-7XH7 — REJECT `SQUASH_CARRIER_TRANSFER`

- Repository: `cure53/DOMPurify`
- Rank: 331
- Summary: DOMPurify: IN_PLACE hook removal leaves a detached subtree executable, causing XSS
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 6f67fd39 is Sync/3.4.2, a multi-PR squash including dependabot. Fix 3067f77 is release 3.4.13 for IN_PLACE detached-subtree XSS. Deeper blame attributed zero AI lines. Squash-carrier file overlap on purify.ts is not origin of hook-removal XSS.

### 02 GHSA-JWJP-4649-V8JP — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `sipsorcery-org/sipsorcery`
- Rank: 332
- Summary: SIPSorcery vulnerable to Denial of Service via out-of-bounds read in SCTP SACK chunk parsing
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI aebe49c5 consolidates projects into a single repo. Fix a2466550 validates SCTP SACK gap-ack and duplicate-TSN counts. Deeper blame attributed zero AI lines (fix is additive). Repo consolidation is not origin of SACK out-of-bounds reads.

### 03 GHSA-F23P-VX2J-J53R — REJECT `SIBLING_FIX`

- Repository: `honojs/hono`
- Rank: 333
- Summary: Hono: memo() retains SSR output across requests, leading to cross-user data disclosure
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bfba97ca normalizes SVG attributes on the svg root (same SHA as batch9 GHSA-HVRM). Fix 0c45036d is a merge-from-fork of memo() request isolation. Deeper blame attributed zero AI lines. SVG attribute normalization is not origin of memo() cross-request reuse.

### 04 GHSA-29PJ-957V-52MC — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `thephpleague/commonmark`
- Rank: 334
- Summary: league/commonmark: AttributesExtension href/src unsafe-link filter bypass via embedded control bytes
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 8d3b5da3 adds PHPUnit 12/13 support. Fix 493a5aa7 hardens the unsafe-link filter against obfuscated schemes. Deeper blame attributed zero AI lines. Test-runner support is not origin of control-byte scheme bypass.

### 05 GHSA-QGQ7-7HM3-Q39J — REJECT `NO_AI_MARKER`

- Repository: `go-git/go-git`
- Rank: 335
- Summary: go-git: Malicious reference names may modify files outside the reference storage
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked commit 1ce83365 adds CloseIdleDescriptors. Body has Assisted-by Claude without a Co-authored-by line that matches the AI-marker regex. Fix da9f7d8a is a merge of reference-name containment. Deeper blame attributed zero AI lines. Missing atomic AI marker fails ai_hunk_gate; FD idle-close is not origin of ref-name path traversal.

### 06 GHSA-G6CJ-PR64-35W5 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `pyca/cryptography`
- Rank: 336
- Summary: cryptography: PKCS#7 EnvelopedData decryption exposes a Bleichenbacher oracle through distinguishable errors and timing
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 59500867 replaces pretend.stub() with DummyEd25519PublicKey in tests. Fix 53fccd93 stops leaking PKCS#7 encryptedKey decryption failure. Deeper blame attributed three test-only lines in tests/doubles.py and tests/test_doubles.py. Test doubles are not a vulnerable production hunk; they are not origin of the Bleichenbacher oracle.

### 07 GHSA-WP74-F5HH-5F3R — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `FlowiseAI/Flowise`
- Rank: 337
- Summary: Flowise: Missing authorization on /api/v1/files allows low-privileged API keys to list and delete files across workspaces within the same organization
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI aee37e16 adds ambient-agent webhooks. Fix bc22bf8b is FLOWISE-596 files ACL. Deeper blame attributed zero AI lines. Webhook feature is not origin of missing checkPermission on /api/v1/files.

### 08 GHSA-47PJ-3JCM-6WHG — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `langchain-ai/langgraph`
- Rank: 338
- Summary: LangGraph: Namespace prefix matching crosses segment boundaries in Postgres and SQLite stores
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9f969f5f handles TTL refresh in AsyncSqliteStore.asearch. Fix 66ebe1a0 scopes namespace matching to segment boundaries. Deeper blame attributed zero AI lines. TTL refresh is not origin of LIKE prefix crossing dot-segment boundaries.

### 09 GHSA-8342-988Q-86CR — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `n8n-io/n8n`
- Rank: 339
- Summary: n8n: Account Takeover via Unverified Email Claim in Token Exchange Embed Login
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 9410e961 preserves Date values in the expression isolate. Same SHA and bundle-backport fix f69dfc6d as GHSA-HX4H and GHSA-VHF8 in this slice and as batch10 n8n rows. Deeper blame of identity-resolution.service.ts hits squash-carrier Bundle/2.x a4bc50f9, not the ranked Date-isolate commit. Shared SHA without mechanism equality is not unverified-email origin.

### 10 GHSA-HX4H-VR3M-45VH — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `n8n-io/n8n`
- Rank: 340
- Summary: n8n: Prototype Pollution via VM Expression Engine Sandbox Escape Leads to Denial of Service
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked Date-isolate SHA 9410e961 and same bundle-backport fix f69dfc6d. The AI inserted Date pass-through beside pre-existing arr[index] without an integer-index guard. That is old-bug preservation, not a security-boundary rewrite. Shared SHA without mechanism equality is not sandbox-escape origin.

### 11 GHSA-88PR-878C-24WF — REJECT `SIBLING_SECURITY_ATTEMPT`

- Repository: `FlowiseAI/Flowise`
- Rank: 341
- Summary: Flowise: Authenticated arbitrary file write in the S3 Directory document loader via unsanitized S3 object keys
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e47d9466 adds MIME type and extension validation for file uploads. Fix 571b5d62 sanitizes S3 object keys in the S3 Directory loader. Deeper blame attributed zero AI lines. MIME spoofing guard is an untouched sibling of S3 key path traversal, not patch-delta incomplete remediation.

### 12 GHSA-WVPP-8HX9-P66J — REJECT `UNIQUENESS_SAME_MECHANISM`

- Repository: `gitpython-developers/GitPython`
- Rank: 342
- Summary: GitPython: Unsafe git option guard bypass via split_single_char_options=False short-option token smuggling enables command execution
- Failing gates: ai_hunk_gate, but_for_gate, uniqueness_gate
- Counterevidence: Ranked AI e8d0fbf7 is the already-counted GHSA-R9MR closer (canonical73 AI_INCOMPLETE_REMEDIATION of check_unsafe_options). Fix 96a888f4 extends that same candidate-list guard to the joined/non-split path. First-party GHSA-WVPP is a residual of the counted kwarg-option mechanism, not a second countable case. Clone has no 3.1.57/3.1.58 tags containing these SHAs.

### 13 GHSA-29G2-3RMR-QM68 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `sveltejs/kit`
- Rank: 343
- Summary: SvelteKit: ReDoS (O(n^2)) in content negotiation — unauthenticated DoS via the Accept header
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a2dc8cd6 preserves multiple Set-Cookie headers on 304 responses. Fix 82712fc0 hardens Accept content negotiation. Deeper blame attributed zero AI lines. Cookie-header preservation is not origin of Accept ReDoS.

### 14 GHSA-HMQ2-W58F-27JC — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `gitpython-developers/GitPython`
- Rank: 344
- Summary: GitPython: Arbitrary Git Repository Creation Outside the Working Tree via Unvalidated .gitmodules Submodule Name in GitPython
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b324c831 is the immediate parent of fix 4299c990 and only initializes mrepo before keep_going failure. Deeper blame attributed one line from e4b8e7d0, which added _validated_name only on the gitfile branch. The residual legacy-path hole is an untouched sibling of that incomplete guard, and the ranked SHA is not the blamed origin. Clone has no 3.1.57/3.1.58 tags containing either SHA.

### 15 GHSA-VHF8-CG2H-CG3P — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `n8n-io/n8n`
- Rank: 345
- Summary: n8n: SSRF Protection Bypass via MCP Client Node
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked Date-isolate SHA 9410e961 and same bundle-backport fix f69dfc6d as GHSA-8342 and GHSA-HX4H. Deeper blame of MCP utils hits squash-carrier Bundle/2.x d4f92238. Shared SHA without mechanism equality is not MCP SSRF origin.

### 16 GHSA-3RRR-JR9J-H3Q3 — REJECT `SIBLING_SECURITY_ATTEMPT`

- Repository: `mermaid-js/mermaid`
- Rank: 346
- Summary: Mermaid Architecture diagrams are vulnerable to prototype pollution
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f1e3b121 scopes cytoscape label mapping to edges with labels. Fix 99af3fc3 is a merge-from-fork replacing Record with Map. Deeper blame attributed four lines from a different SHA c337f10d (addJunction crash validation), not __proto__ Record assignment. Label-warning and junction-parent checks are not origin of architecture prototype pollution.

### 17 GHSA-RH67-4C8J-HJJH — REJECT `SIBLING_FIX`

- Repository: `nautobot/nautobot`
- Rank: 347
- Summary: Nautobot may allows uploaded media files to be accessible without authentication
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ac10784e adds wireless models (same SHA as batch9 GHSA-WPXJ). Fix 9c892dc3 requires authentication for media files. Deeper blame attributed zero AI lines. Wireless-model feature is not origin of unauthenticated MEDIA_ROOT serving.

### 18 GHSA-7F8R-222P-6F5G — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `modelcontextprotocol/inspector`
- Rank: 348
- Summary: MCP Inspector proxy server lacks authentication between the Inspector client and proxy
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI de84c472 adds structured output support to the browser UI. Fix 50df0e1e is a merge-from-fork of proxy authentication. Deeper blame attributed zero AI lines. Structured-output UI is not origin of missing client-proxy auth.

### 19 GHSA-W64R-2G3W-W8W4 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `coder/agentapi`
- Rank: 349
- Summary: Coder AgentAPI exposed user chat history via a DNS rebinding attack
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 33124c23 updates Codex support. Fix 5c425c62 implements HTTP allowed hosts/origins checking. Deeper blame attributed zero AI lines. Codex support is not origin of DNS-rebinding /messages exposure.

### 20 GHSA-XRW9-R35X-X878 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `zitadel/zitadel`
- Rank: 350
- Summary: Zitadel allows brute-forcing authentication factors
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5403be7c adds user profile requests in resource APIs. Fix b8db8cdf is a merge-from-fork of OTP tarpit/brute-force controls. Deeper blame attributed zero AI lines. Profile-request feature is not origin of authentication-factor brute force.

### 21 GHSA-XJV7-6W92-42R7 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `marimo-team/marimo`
- Rank: 351
- Summary: marimo vulnerable to proxy abuse of /mpl/{port}/
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a5e0296c allows different backends. Fix 0312706d refactors the MPL proxy endpoint. Deeper blame attributed zero AI lines. Backend selection is not origin of /mpl/{port}/ proxy abuse.

### 22 GHSA-93M4-6634-74Q7 — REJECT `SIBLING_FIX`

- Repository: `vitejs/vite`
- Rank: 352
- Summary: vite allows server.fs.deny bypass via backslash on Windows
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d65a9831 improves malformed URL handling via decodeURIIfPossible. Fix f479cc57 trims a trailing slash before the server.fs.deny check. Deeper blame attributed zero AI lines. Malformed-URL decode is a sibling of the Windows backslash deny bypass.

### 23 GHSA-CQ46-M9X9-J8W2 — REJECT `OLD_BUG_REFACTOR`

- Repository: `secdev/scapy`
- Rank: 353
- Summary: Scapy Session Loading Vulnerable to Arbitrary Code Execution via Untrusted Pickle Deserialization
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 57390355 reworks AutoArgparse and extensions, reordering imports in scapy/main.py. Fix 13621d11 removes session pickle load/save. Deeper blame attributed one line (pickle import). Import reorder of a pre-existing pickle session loader is not but-for origin of untrusted deserialization.

### 24 GHSA-MXH2-CCGJ-8635 — REJECT `COMMIT_ONLY_CHANGE`

- Repository: `esphome/esphome`
- Rank: 354
- Summary: ESP-IDF web_server basic auth bypass using empty or incomplete Authorization header
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 3fbbdb45 replaces std::find_if with a simple loop to reduce binary size. Fix 2aceb566 is a merge-from-fork of basic-auth comparison. Deeper blame attributed zero AI lines. Binary-size loop rewrite is not origin of empty/substring Authorization bypass.

### 25 GHSA-WR9H-G72X-MWHM — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vllm-project/vllm`
- Rank: 355
- Summary: vLLM is vulnerable to timing attack at bearer auth
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 67244c86 returns 503 on /health when the engine is dead. Fix ee10d7e6 validates API tokens in constant time. Deeper blame attributed zero AI lines. Health-endpoint 503 is not origin of bearer timing.

### 26 GHSA-6FVQ-23CW-5628 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `vllm-project/vllm`
- Rank: 356
- Summary: vLLM: Resource-Exhaustion (DoS) through Malicious Jinja Template in OpenAI-Compatible Server
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked 503-health SHA 67244c86 as GHSA-WR9H. Fix 7977e502 filters chat-template kwargs. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not Jinja template DoS origin.

### 27 GHSA-M98W-CQP3-QCQR — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `gofiber/utils`
- Rank: 357
- Summary: Fiber Utils UUIDv4 and UUID Silent Fallback to Predictable Values
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9fc4fde7 refactors TrimSpace comment and benchmark loops. Fix 6c6cf047 is a merge-from-fork of UUID fallback. Deeper blame attributed zero AI lines. TrimSpace cleanup is not origin of crypto/rand silent zero-UUID fallback.

### 28 GHSA-9RWJ-6RC7-P77C — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `langchain-ai/langgraph`
- Rank: 358
- Summary: LangGraph's SQLite is vulnerable to SQL injection via metadata filter key in SQLite checkpointer list method
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked TTL-refresh SHA 9f969f5f as GHSA-47PJ. Fix 29724291 hardens the SQLite checkpointer. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not metadata-filter SQL injection origin.

### 29 GHSA-G239-Q96Q-X4QM — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vitejs/vite-plugin-react`
- Rank: 359
- Summary: @vitejs/plugin-rsc has an Arbitrary File Read via /__vite_rsc_findSourceMapURL Endpoint
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 486ebb03 fixes deserializing client references with React 19.2.1+. Fix 582fba0b validates findSourceMapURL requests. Deeper blame attributed zero AI lines. Client-reference deserialize is not origin of source-map URL file read.

### 30 GHSA-J76J-5P5G-9WFR — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vitejs/vite-plugin-react`
- Rank: 360
- Summary: @vitejs/plugin-rsc Remote Code Execution through unsafe dynamic imports in RSC server function APIs on development server
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 170f74e2 shows logs for RSC build steps. Fix fe634b58 validates reference id on dev. Deeper blame attributed zero AI lines. Build-step logging is not origin of unsafe dynamic imports.

## Conservation

- rank_pool 3473 = 330 prior directroot reviews (batches 1-11) + 30 this slice + 470 unreviewed hits + 2643 rank misses
- hits 830; incoming unreviewed hits before this slice: 500; after: 470
- Unreviewed remaining IDs are UNREVIEWED, not REJECT

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD.
