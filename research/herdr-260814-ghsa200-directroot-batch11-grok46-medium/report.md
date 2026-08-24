# Direct-root mining batch 11 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical73 and directroot batches 1-10, including frozen in-progress batch9 and batch10 selections. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 500
- PASS proposals: 1 (`GHSA-PMCH-G965-GRMR`, uncounted)
- REJECT: 29
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 300+30+500+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical73 strict identities plus batch1-10 `selected-30.jsonl`/`cases.jsonl`, including frozen in-progress batch9 and batch10. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-F75J-4CW6-RMX4 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `go-gitea/gitea`
- Rank: 301
- Summary: Gitea Docker image: REVERSE_PROXY_TRUSTED_PROXIES = * default lets any source IP impersonate any user via X-WEBAUTH-USER
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI db7eb4d5 is issue-label deletion with Actions tokens. Fix 99f8b3d9 is a composite security backport including org-label visibility and other surfaces. Deeper blame attributed zero AI lines. File overlap on api.go/hook_pre_receive is routing. Same SHA is also ranked for GHSA-V73X; shared SHA without mechanism equality is not two origins.

### 02 GHSA-4M82-P8CX-F94J — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `surrealdb/surrealdb`
- Rank: 302
- Summary: SurrealDB: LIVE query subscriptions survive session state changes, bypassing access controls
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Cursor commit 0bf1a519 improves RPC error serialisation. Fix 6cc48412 cleans LIVE queries on auth principal change. Deeper blame attributed zero AI lines (no deleted source spans on the LIVE-cleanup hunks). protocol.rs overlap is routing, not LIVE-subscription origin.

### 03 GHSA-HP74-GM6M-2QM5 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `pocket-id/pocket-id`
- Rank: 303
- Summary: Pocket ID has a reauthentication bypass via one-time access token login — passkey step-up requirement defeated by JWT freshness check that accepts any login method
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Copilot/Claude commit 59fe481a adds OIDC prompt-parameter handling. Fix 978ac87d is the immediate child and tightens refresh-token / authorized-client checks. Deeper blame attributed zero deleted AI hunks. Prompt handling is not the JWT-freshness reauth bypass; same-file oidc_service.go overlap is routing. Advisory introduced:0 is an old hole, not AI origin.

### 04 GHSA-Q8WF-6R8G-63CH — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vercel/next.js`
- Rank: 304
- Summary: Next.js: Denial of Service in the Image Optimization API using SVGs
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e2fca6c6 adds experimental graph CSS chunking. Fix 93cb9089 speeds detectContentType in next/image. Deeper blame attributed zero AI lines. config-schema overlap is routing, not SVG image-optimizer origin.

### 05 GHSA-55H5-XMCQ-C37V — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `py-pdf/pypdf`
- Rank: 305
- Summary: pypdf: Possible long runtimes for repeated malformed cross-reference entries
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4d8ebcec fixes stale object-stream cache. Fix b5fc5aa7 replaces regex xref recovery. Deeper blame attributed zero AI lines. _reader.py history without deleted-hunk identity is an old-bug refactor, not AI origin of malformed-xref DoS.

### 06 GHSA-9H85-G7W3-RH49 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `ViewComponent/view_component`
- Rank: 306
- Summary: ViewComponent: Reused Component Instances Retain Stale Render Context
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ea4b7671 fixes yielded content location with form helpers. Fix 7b05073b clears stale render context on reused instances. Deeper blame attributed zero AI lines. Same-file base.rb overlap is a sibling fix, not stale-context origin. Advisory introduced 4.0.0 predates the ranked commit.

### 07 GHSA-866W-XMHQ-WJ7X — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `sveltejs/kit`
- Rank: 307
- Summary: SvelteKit: Prototype pollution in file input deletion path in remote-function forms
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 95ca921c removes Content-Length dependency in binary form deserialization. Fix df32f6fe adds DELETE_KEY handling to avoid prototype pollution on file-input deletion. Deeper blame attributed zero AI lines. form-utils.js overlap is a sibling path, not origin of deep_set deletion pollution. Advisory introduced:0.

### 08 GHSA-H95V-H523-3MW8 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `guzzle/guzzle`
- Rank: 308
- Summary: Guzzle: URI fragments disclosed in redirect Referer headers
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Claude commit fb92d95f updates CI, PHPStan, and removes Psalm. Fix 7b68220d excludes fragments from Referer and preserves host-only cookies. Deeper blame attributed zero AI lines. CookieJar/RedirectMiddleware file-history without hunk identity is routing.

### 09 GHSA-FMH4-WCC4-5JM3 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `better-auth/better-auth`
- Rank: 309
- Summary: Better Auth vulnerable to unauthorized invitation acceptance via unverified email match in organization plugin
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Copilot Autofix 6559c1e8 handles multi-role users in invite/member-removal checks. Fix 23094a62 defaults requireEmailVerificationOnInvitation. Deeper blame attributed zero AI lines. Incomplete remediation of an untouched email-verification sibling is rejected; the AI change did not author the residual gate.

### 10 GHSA-392P-2Q2V-4372 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `better-auth/better-auth`
- Rank: 310
- Summary: Better Auth: OAuth refresh-token rotation forks the token family on concurrent redemption
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Copilot commit 1e30369b adds legacy OAuth clients without PKCE. Fix c6918ecc hardens refresh-token rotation. Deeper blame attributed zero AI lines. PKCE-legacy feature is not concurrent-redemption origin. token.ts overlap is routing.

### 11 GHSA-5578-W22F-PFX9 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `koxudaxi/datamodel-code-generator`
- Rank: 311
- Summary: datamodel-code-generator vulnerable to code injection via x-python-import / customTypePath in generated import statements
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 160e507e fixes required-field default rendering. Fix 577d4956 validates x-python-import. Deeper blame attributed zero AI lines. jsonschema.py overlap is a sibling parser change, not import-injection origin.

### 12 GHSA-2XGG-R2WC-C5R2 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Budibase/budibase`
- Rank: 312
- Summary: Budibase: MySQL DESCRIBE Backtick Injection via multipleStatements in Database Connector
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI dcef40e1 maps citext to string on Postgres. Fix 2c61f389 is a composite SQL-connector merge. Deeper blame attributed zero AI lines. Postgres citext mapping is not MySQL DESCRIBE backtick injection. Weak connector-file overlap is routing.

### 13 GHSA-6QC9-MQVW-JG7X — REJECT `COMPOSITE_BUNDLE_SIBLING`

- Repository: `n8n-io/n8n`
- Rank: 313
- Summary: n8n: Credential Authorization Bypass via Expression in HTTP Request Node genericAuthType
- Failing gates: ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate
- Counterevidence: Ranked Claude commit 9410e961 preserves Date values in the expression isolate (2 files). Fix f69dfc6d is a release-candidate bundle backport touching 73 source files. Deeper blame attributed 48 AI lines to other SHAs (computer-use search-files, token-exchange, MCP utils), not 9410e961 and not genericAuthType. Shared SHA with GHSA-2X35 and GHSA-GF29 without mechanism equality is rejected. Bundle closer is not a minimum same-invariant reversal.

### 14 GHSA-HG5R-VQ93-9FV6 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `go-gitea/gitea`
- Rank: 314
- Summary: Gitea Actions Artifacts V4 signed URL HMAC ambiguity allows cross-repository artifact read and cross-task upload-state write
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0ab612f5 refactors storage ServeDirectURL content-type handling. Fix 1c2d5e9b makes artifact signature payloads unambiguous. Deeper blame attributed zero AI lines. Storage-options overlap is routing, not HMAC-payload origin.

### 15 GHSA-7488-6R32-C95Q — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `BerriAI/litellm`
- Rank: 315
- Summary: LiteLLM: MCP Authentication Bypass via OAuth2 Passthrough Fallback
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 12c48768 is Agents assign-tools / max_iterations. Fix 73869f0f tightens MCP public-route detection and OAuth2 fallback. Deeper blame attributed zero AI lines. Auth-file overlap is routing, not OAuth2-passthrough origin.

### 16 GHSA-JM28-2WCR-QF3H — REJECT `UNTOUCHED_SIBLING_INCOMPLETE_REMEDIATION`

- Repository: `OliveTin/OliveTin`
- Rank: 316
- Summary: OliveTin: StartActionAndWait Endpoints Bypass logs Permission and Return Action Output
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI afd9f903 expands entity list/detail APIs. Fix e421780c adds logs ACL on StartActionAndWait. Deeper blame attributed 1 line to a different Cursor commit a530dca5 (justification template), not the ranked SHA and not the missing logs check. Advisory documents the hole as pre-existing on ...AndWait while GetLogs already enforced logs. Untouched sibling / old missing check is rejected.

### 17 GHSA-2CF7-HPWF-47H9 — REJECT `LATER_AI_SECURITY_FIX_ROUTING`

- Repository: `czlonkowski/n8n-mcp`
- Rank: 317
- Summary: n8n-MCP: Incorrect authorization can expose default-scope workflow version backups in multi-tenant HTTP mode
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked commit d9d847f2 is itself a fork-merge closing a different advisory GHSA-4ggg. Fix c1ca1e73 closes this workflow-version backup authorization hole. Deeper blame attributed zero ranked-AI lines. A later AI-marked security fix on a sibling advisory is not origin of this mechanism.

### 18 GHSA-824W-X939-6CMC — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `tensorzero/tensorzero`
- Rank: 318
- Summary: TensorZero Gateway: Arbitrary file read and SSRF in internal object storage endpoint
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Cursor commit 36253de2 supports evaluations with new gateway config. Fix 0abbc838 hardens object storage. Deeper blame attributed 2 ranked-AI lines only in evaluations e2e tests, plus other AI SHAs in ClickHouse query builders. Test-file overlap is not object_storage.rs origin. Sibling AI lines in a composite closer are not this mechanism.

### 19 GHSA-V73X-HX65-6PF4 — REJECT `SHA_SHARING_WITHOUT_MECHANISM_EQUALITY`

- Repository: `go-gitea/gitea`
- Rank: 319
- Summary: Gitea: Unauthorized Access to Labels of Private Organizations
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Same ranked SHA and composite closer as GHSA-F75J. Ranked AI is Actions token label-deletion. Fix 99f8b3d9 enforces org visibility on label read among other security items. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not private-org label origin.

### 20 GHSA-683J-3FF6-HH2X — REJECT `COMPOSITE_BUNDLE_SIBLING`

- Repository: `go-gitea/gitea`
- Rank: 320
- Summary: Gitea: Privilege Escalation via Access Token Scope Escalation in API
- Failing gates: ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate
- Counterevidence: Ranked AI 18762c77 batch-loads Actions run/job/task API data. Fix de4b8277 is a 92-file composite security backport. Deeper blame attributed 6 lines to other AI SHAs (oauth.go, permission.go, api.go, issue_test.go), not 18762c77 and not access-token scope. Shared SHA with GHSA-9MQ6, GHSA-X77V, GHSA-6C6R without mechanism equality is rejected.

### 21 GHSA-9MQ6-MQJJ-C2C5 — REJECT `COMPOSITE_BUNDLE_SIBLING`

- Repository: `go-gitea/gitea`
- Rank: 321
- Summary: Gitea: Unbounded Arch package file metadata can cause resource amplification in Gitea package uploads
- Failing gates: ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate
- Counterevidence: Same ranked SHA and composite closer as GHSA-683J. Arch metadata limits live in modules/packages/arch, not the Actions batch-load commit. Deeper blame did not attribute arch metadata to 18762c77. SHA sharing without mechanism equality is rejected.

### 22 GHSA-X77V-Q46J-393G — REJECT `COMPOSITE_BUNDLE_SIBLING`

- Repository: `go-gitea/gitea`
- Rank: 322
- Summary: Gitea: Blind SSRF in OAuth2 avatar synchronization via unvalidated OIDC picture claim
- Failing gates: ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate
- Counterevidence: Same ranked SHA and composite closer as GHSA-683J. OIDC picture SSRF is not Actions batch-load. Deeper blame hit other AI lines in oauth.go, not this ranked SHA as origin of the picture-claim fetch. SHA sharing without mechanism equality is rejected.

### 23 GHSA-PMCH-G965-GRMR — PASS `AI_INCOMPLETE_REMEDIATION`

- Repository: `langroid/langroid`
- Rank: 323
- Summary: Langroid: SQLChatAgent _validate_query blocklist misses pg_read_file family enabling arbitrary file read
- Gates: all seven PASS (proposal only)
- Counterevidence: OSV introduced:0 is routing and is not used as origin. The original CVE-2026-25879 COPY PROGRAM hole predates the denylist; incomplete-remediation does not require AI origin of the parent vulnerability. Rollback of 60933b48 would reopen the broader parent; that is not a failure for this class. Clone has no git tags; release_gate uses first-party advisory versions plus pyproject version-bump commits fee670d5 (0.63.0) and 84d2aff0 (0.64.0).

### 24 GHSA-RJWR-M7QX-3FJR — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `oapi-codegen/oapi-codegen`
- Rank: 324
- Summary: oapi-codegen: OpenAPI Server Description Escapes Generated Go Comment and Injects Executable Code
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 08b30183 routes server enums through general enums codegen. Fix 19c6282e tightens string escaping in server-URL templates. Deeper blame attributed zero AI lines. Sibling codegen in the same feature is not comment-escape origin.

### 25 GHSA-2X35-3FW4-9JR4 — REJECT `COMPOSITE_BUNDLE_SIBLING`

- Repository: `n8n-io/n8n`
- Rank: 325
- Summary: n8n: Send Email Node Arbitrary File Read and SSRF via Nodemailer Content-Object Type Confusion
- Failing gates: ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate
- Counterevidence: Same ranked Date-isolate SHA and bundle closer as GHSA-6QC9. Nodemailer content-object confusion is not expression-isolate Date preservation. Deeper blame did not attribute the email node to 9410e961. SHA sharing without mechanism equality is rejected.

### 26 GHSA-3WP3-XXJ9-5JQQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 326
- Summary: Open WebUI: Cross-user model-list exposure via static cache key in get_all_models (aiocache key= vs key_builder= misuse)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 47198811 moves bypass_system_prompt off a query parameter onto request.state. Fix 0fc630b3 replaces static aiocache key= on get_all_models. Deeper blame attributed zero AI lines. Same-file ollama.py/openai.py overlap is routing, not cache-key origin.

### 27 GHSA-G9G6-QHRC-P3QC — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `go-gitea/gitea`
- Rank: 327
- Summary: Gitea: Improper authorization on OAuth sign-in callback silently re-enables administrator-disabled accounts
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4e5f4389 ignores stale OIDC links to organizations. Fix c43eb7c3 stops auto-reactivating disabled users on OAuth2 callback. Deeper blame attributed zero AI lines. Same-file oauth.go overlap is a sibling auth fix, not IsActive=true origin.

### 28 GHSA-6WCC-39RP-HH9P — REJECT `OLD_BUG_REFACTOR`

- Repository: `hypequery/hypequery`
- Rank: 328
- Summary: @hypequery/clickhouse has SQL Injection in parameter escaping that allows arbitrary SQL execution
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b0a5a5a8 migrates a dataset adapter and only adds an empty-params early return in escapeValue/substituteParameters. The weak JSON.stringify and backslash-escape branches already existed on the parent. Fix 2879161a parenthesizes WHERE AND/OR and later commits in the same advisory close escaping. Deeper blame of 5 AI lines is adapter/sql-tag comments and splitSqlPlaceholders wiring, not origin of escapeValue. Advisory introduced:0. Old-bug refactor / sibling precedence fix is rejected.

### 29 GHSA-6C6R-5XR4-CR5M — REJECT `COMPOSITE_BUNDLE_SIBLING`

- Repository: `go-gitea/gitea`
- Rank: 329
- Summary: Gitea: Cross-repository issue/comment attachment re-linking can expose private attachment content
- Failing gates: ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate
- Counterevidence: Same ranked SHA and composite closer as GHSA-683J. Attachment re-linking is not Actions batch-load. SHA sharing without mechanism equality is rejected.

### 30 GHSA-GF29-4F56-R2JF — REJECT `COMPOSITE_BUNDLE_SIBLING`

- Repository: `n8n-io/n8n`
- Rank: 330
- Summary: n8n: Git Node fetch/pull/pushTags Operations Bypass Sandbox Path Restriction
- Failing gates: ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate
- Counterevidence: Same ranked Date-isolate SHA and bundle closer as GHSA-6QC9. Git-node sandbox bypass is not expression-isolate Date preservation. SHA sharing without mechanism equality is rejected.

## Conservation

- hits: 830
- prior directroot reviewed: 300
- this slice: 30
- unreviewed hits after: 500
- rank misses: 2643
- rank pool: 3473
- 300+30+500+2643=3473
- Unreviewed hits are UNREVIEWED, not REJECT.

## Hold

Publication stays HOLD. Greater-than-200 stays HOLD. The one PASS is a worker proposal; the leader must independently verify identity, topology, patch-delta, release containment, and uniqueness before any ledger admission.
