# Direct-root mining batch 26 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical81 and directroot batches 1-25, including frozen batch25 selected-30 and terminal batch23/batch24 selected/cases. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 50
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 750+30+50+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical81 strict identities plus batch1-25 `selected-30.jsonl`/`cases.jsonl`, including frozen batch25 selected-30 and terminal batch23/batch24. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-GH7P-78X6-JW6M — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 751
- Summary: Open WebUI: /api/v1/channels/{id}/members exposes full user model including sensitive credentials
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b3ca943d batches user lookup in model_response_handler thread history. Fix is a members-payload refactor. Deeper blame attributed zero AI lines. channels.py overlap is routing, not credential-leaking members origin.

### 02 GHSA-6GPP-XCG3-4W24 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vercel/next.js`
- Rank: 752
- Summary: Next.js: Middleware / Proxy bypass in App Router applications using Turbopack and single locale
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4588a735 converts tests from createNext to nextTestSetup across 135 files. Fix corrects the Turbopack i18n single-locale middleware matcher. Deeper blame attributed zero AI lines. Test-file overlap is routing, not matcher origin.

### 03 GHSA-M99W-X7HQ-7VFJ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vercel/next.js`
- Rank: 753
- Summary: Next.js: Denial of Service in App Router using Server Actions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fa56f2c1 stops revalidateTag profile from client cache invalidation. Fix speeds MPA form-submission validation. Deeper blame attributed zero AI lines. action-handler.ts overlap is routing, not Server Action DoS origin.

### 04 GHSA-X2FF-V5V8-M75M — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 754
- Summary: Open WebUI: Cross-channel message overwrite via chat completion API (single-model and multimodel message_ids)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI cc15a017 avoids crashing when stdout cannot encode the startup banner. Fix gates the chat_completion channel: branch on access and message scoping. Deeper blame attributed zero AI lines. main.py overlap is routing, not cross-channel overwrite origin.

### 05 GHSA-Q53C-4PRM-W95Q — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `ericcornelissen/shescape`
- Rank: 755
- Summary: Shescape: Home-directory disclosure in assignment context on Unix with Dash
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 90563030 adds an ESLint missing-rule detector with Assisted-by Claude. Fix is the same overall-escaping commit as prior Shescape identities. Deeper blame attributed zero AI lines. eslint.js overlap is tooling routing, not Dash assignment-context origin.

### 06 GHSA-4VV7-JJ25-4GH6 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `microsoft/kiota`
- Rank: 756
- Summary: Microsoft Kiota: Arbitrary file write + code-injection via x-ms-kiota-info clientClassName and clientNamespaceName
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI aef1960f fixes empty models when allOf inheritance is reached via a composed type. Fix sanitizes client class and namespace names. Deeper blame attributed zero AI lines. allOf model reconstruction is a sibling generator path, not clientClassName injection origin, and is not a patch-delta of the same omitted-name boundary.

### 07 GHSA-955P-X3MX-JCVP — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `vercel/next.js`
- Rank: 757
- Summary: Next.js: Unauthenticated disclosure of internal Server Function endpoints
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fa56f2c1 is the same revalidateTag cache commit as GHSA-M99W. Fix validates server reference IDs during manifest lookup. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not Server Function disclosure origin.

### 08 GHSA-C9HR-64H3-GXPC — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `flytohub/flyto-core`
- Rank: 758
- Summary: Flyto2 Core: Guarded HTTP modules follow redirects into internal space without per-hop SSRF revalidation
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 082b7a37 only adds agent.* to browser can_connect_to, including a one-line proxy_rotate.py wiring change. Fix adds missing per-module SSRF guards and redirect revalidation. Deeper blame attributed three import lines to a different SHA b7e7710c on http.get/request/batch, not the ranked commit. Shared file without mechanism equality is not redirect-revalidation origin.

### 09 GHSA-FPXG-5XMV-922M — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `surrealdb/surrealdb`
- Rank: 759
- Summary: SurrealDB has bypass of field-level SELECT permissions through JSON Patch copy and move with empty from
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 452c21ef adds mutex_atomic and needless_pass_by_value clippy lints. Fix rejects root from for JSON Patch copy/move. Deeper blame attributed zero AI lines. operation.rs overlap is routing, not empty-from permission origin.

### 10 GHSA-5RR4-8452-HF4V — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `better-auth/better-auth`
- Rank: 760
- Summary: @better-auth/sso provider registration has server-side request forgery via unvalidated OIDC endpoints
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e32bad12 prefers UserInfo over ID token and maps the sub claim. Fix validates user-supplied OIDC endpoint URLs at registration. Deeper blame attributed zero AI lines. sso.ts overlap is routing, not unvalidated-OIDC-URL origin.

### 11 GHSA-F7WF-V2VW-MPCX — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `mkreyman/mcp-memory-keeper`
- Rank: 761
- Summary: mcp-memory-keeper: Arbitrary local file read in context_import via unvalidated filePath
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 4dd0a651 hardens object schemas for strict validators. Fix confines context_import to the exports directory. Deeper blame attributed 16 src/index.ts lines to six other AI SHAs, not 4dd0a651. Schema-item properties are not unvalidated-filePath origin.

### 12 GHSA-72M8-9M7M-H278 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `BerriAI/litellm`
- Rank: 762
- Summary: LiteLLM: Custom Code Guardrails production endpoints bypass code safety checks
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e00c181f adds MCP end-user object permissions. Fix sandboxes custom-code guardrail create/update and demotes missing-master-key callers from PROXY_ADMIN. Deeper blame attributed four end_user_object_permission lines that the fix only reformatted, not the sandbox or role-default origin.

### 13 GHSA-F4GW-2P7V-4548 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `axios/axios`
- Rank: 763
- Summary: Axios: NO_PROXY bypass for 0.0.0.0 local addresses in axios
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6bb12c19 strips custom auth headers on cross-origin redirects. Fix is the same malformed-URL commit as other axios identities. Deeper blame attributed one redirect-test line in http.test.js, not NO_PROXY 0.0.0.0 origin. Shared SHA without mechanism equality is not that bypass.

### 14 GHSA-89XV-2M56-2M9X — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `vercel/next.js`
- Rank: 764
- Summary: Next.js: Server-Side Request Forgery in Server Actions on custom servers
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fa56f2c1 is the same revalidateTag cache commit as GHSA-M99W. Fix sets the correct origin for internal redirects in a custom server. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not custom-server SSRF origin.

### 15 GHSA-QQ9H-G4JM-XGF3 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `better-auth/better-auth`
- Rank: 765
- Summary: Better Auth: Account takeover via pre-account hijacking on magic-link and email-OTP sign-in
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6c83eca2 moves adapter-factory to core. Fix revokes unproven credentials on magic-link/email-OTP sign-in. Deeper blame attributed zero AI lines. db/index.ts overlap is routing, not unproven-credential origin.

### 16 GHSA-HCPX-6FM6-WX23 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `axios/axios`
- Rank: 766
- Summary: Axios form serializer maxDepth bypass via {} metatoken
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6bb12c19 is the same redirect header-strip commit as GHSA-F4GW. Fix is the same malformed-URL commit. Deeper blame attributed one redirect-test line, not form-serializer maxDepth origin. Shared SHA without mechanism equality is not that bypass.

### 17 GHSA-F5PF-Q7C7-M3VV — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Cyberdrop-DL/cyberdrop-dl`
- Rank: 767
- Summary: Pixeldrain API key shared with unverified thirdparty sites
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 81729489 updates crawlers to a new request method across 107 files. Fix rejects unknown PixelDrain domains. Deeper blame attributed zero AI lines. pixeldrain.py overlap is routing, not unknown-domain origin.

### 18 GHSA-6VG3-HGRW-P5GF — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `surrealdb/surrealdb`
- Rank: 768
- Summary: SurrealDB has an Authorization Bypass via Composite Record-id Paths
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 24f15e56 adds a predicate prefilter for KV scans. Fix resolves id.<field> to the record-id key component. Deeper blame attributed zero AI lines. field.rs overlap is routing, not composite record-id origin.

### 19 GHSA-5F94-X226-CCPM — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `acacode/swagger-typescript-api`
- Rank: 769
- Summary: swagger-typescript-api vulnerable to code injection via unescaped enum string values
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 691d07d8 adds a changeset for preferExistingSchemaNamesForExternalRefs. Fix is a bundled security commit. Deeper blame attributed zero AI lines. code-gen-process.ts overlap is routing, not unescaped-enum origin.

### 20 GHSA-6QVR-WJMV-V8MM — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `koel/koel`
- Rank: 770
- Summary: Koel: Incomplete fix for CVE-2026-47260 — systemic SSRF in podcast and radio fetch paths
- Failing gates: but_for_gate
- Counterevidence: Ranked AI 8a4b9347 adds radio now-playing and introduces Network::isPublicHost. The first-party GHSA enumerates residual podcast and radio fetchers that still lack per-hop redirect checks after CVE-2026-47260, plus DNS rebinding. Deeper blame attributed 45 Network.php lines because the later commit relocated that helper, but the omitted redirect defenses are sibling call sites, not a patch-delta of an omitted case inside the AI-added radio helper. The clone has no release tags, so released containment is unproved.

### 21 GHSA-97VG-427P-8HX5 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `surrealdb/surrealdb`
- Rank: 771
- Summary: SurrealDB: Port-specific --deny-net rules silently bypassed on HTTP redirect
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7d9c6242 fixes CI checks on main. Fix hardens HTTP redirect handling and DNS resolution filtering. Deeper blame attributed zero AI lines. statements.rs overlap is routing, not deny-net redirect origin.

### 22 GHSA-4W3Q-QPFQ-V992 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `apolloconfig/apollo`
- Rank: 772
- Summary: Apollo ConfigService access key authentication bypass via appId parsing and non-canonical matching
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b183c443 adds incremental configuration synchronization. Fix validates configservice app ids for access-key auth. Deeper blame attributed zero AI lines. ConfigServiceAutoConfiguration.java overlap is routing, not appId-matching origin.

### 23 GHSA-VJ7Q-GJH5-988W — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `modelcontextprotocol/python-sdk`
- Rank: 773
- Summary: MCP Python SDK: WebSocket server transport does not support Host/Origin validation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9d0f2dad reorganizes message handling for type safety. Fix adds TransportSecuritySettings to the WebSocket server transport. Deeper blame attributed zero AI lines. websocket.py overlap is routing, not missing Host/Origin origin.

### 24 GHSA-6C4R-FMH3-7RH8 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vllm-project/vllm`
- Rank: 774
- Summary: vLLM: Processing differential in multi-channel audio downmixing enables hidden-input/moderation bypass for audio models
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7acaea63 adds an in-tree AMD Zen CPU backend. Fix removes librosa from the audio dependency. Deeper blame attributed zero AI lines. setup.py overlap is routing, not downmix-differential origin.

### 25 GHSA-H4PC-58CC-HC95 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `apolloconfig/apollo`
- Rank: 775
- Summary: Apollo ConfigService access key authentication bypass via raw config file appId parsing
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b183c443 is the same incremental-sync commit as GHSA-4W3Q. Fix is the same app-id validation commit. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not raw-config appId origin.

### 26 GHSA-WJV6-JCFJ-MF9R — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `koxudaxi/datamodel-code-generator`
- Rank: 776
- Summary: datamodel-code-generator vulnerable to code injection via unescaped carriage return in --extra-template-data comment field
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 160e507e fixes required-field default rendering. Fix escapes carriage returns in template comment data. Deeper blame attributed zero AI lines. base.py overlap is routing, not comment-CR origin.

### 27 GHSA-2956-977X-2W3R — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `flytohub/flyto-core`
- Rank: 777
- Summary: Flyto2 Core: Arbitrary file write via image.download (and other file-writing modules)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d5fda807 renames _get_nested_value to get_nested_value. Fix confines writes and gates env interpolation. Deeper blame attributed zero AI lines. variable_resolver.py overlap is routing, not image.download write origin.

### 28 GHSA-XJ6Q-8X83-JV6G — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `axios/axios`
- Rank: 778
- Summary: Axios: Prototype pollution auth subfields can inject Basic auth
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6bb12c19 is the same redirect header-strip commit as GHSA-F4GW. Fix is the same malformed-URL commit. Deeper blame attributed one redirect-test line, not prototype-pollution auth gadgets. Shared SHA without mechanism equality is not that origin.

### 29 GHSA-8J5Q-MFJ2-5Q9Q — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `withastro/astro`
- Rank: 779
- Summary: @astrojs/rss: XML Injection via Unescaped RSS Feed Fields
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 336b0033 merges main into next across 48 files. Fix escapes source and enclosure RSS fields. Deeper blame attributed zero AI lines. astro-rss index.ts overlap is routing, not unescaped RSS-field origin.

### 30 GHSA-MWF2-3PR3-8698 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `axios/axios`
- Rank: 780
- Summary: Axios: HTTP/2 streamed uploads bypass maxBodyLength
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6bb12c19 is the same redirect header-strip commit as GHSA-F4GW. Fix is the same malformed-URL commit. Deeper blame attributed one redirect-test line, not HTTP/2 maxBodyLength origin. Shared SHA without mechanism equality is not that bypass.

## Conservation

- rank_pool 3473 = 750 prior directroot reviews + 30 this slice + 50 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch25: 750; this slice 751-780
- Incoming unreviewed hits before this slice: 80; after: 50
- Stale 260813 batch3 equals formal 260814 batch3 (30 IDs) and is not 30 extra reviewed rows
- Unreviewed remaining IDs are UNREVIEWED, not REJECT
- Checkpoint at 75 percent recorded before the final seven rows, then the assigned slice was exhausted

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD. Deeper-blame hits remain non-origin: GHSA-C9HR blamed a different SSRF SHA than the ranked browser wiring commit; GHSA-F7WF blamed other schema/index SHAs than the ranked validator commit; GHSA-72M8 blamed MCP permission lines the fix only reformatted; GHSA-6QVR authored Network::isPublicHost but the advisory residual is sibling fetchers, not a patch-delta of that radio helper; GHSA-F4GW/HCPX/XJ6Q/MWF2 blamed one axios redirect-test line shared across identities.
