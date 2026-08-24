# Direct-root mining batch 25 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical81 and directroot batches 1-24, including the frozen batch24 selected-30. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. Canonical81's three append identities already sit in batch9 and batch11, so they do not add extra ranked-hit skips. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 80
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 720+30+80+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical81 strict identities plus batch1-24 `selected-30.jsonl`/`cases.jsonl`, including terminal batch22 and batch23 selected/cases and frozen in-progress batch24 selected-30. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-53G2-MVCC-Q9X3 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `basecamp/trix`
- Rank: 721
- Summary: Trix: Stored XSS via HTMLParser attribute injection on paste
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bf389080 replaces Karma with @web/test-runner. Fix blocks javascript: URIs in JSON drag-drop deserialization. Deeper blame attributed zero AI lines. trix.js overlap is routing, not HTMLParser attribute-injection origin.

### 02 GHSA-PMV8-RQ9R-6J72 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `axios/axios`
- Rank: 722
- Summary: Axios: Deep formToJSON Key Recursion Can Cause Denial of Service
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6bb12c19 strips custom auth headers on cross-origin redirects, the same SHA already ranked for GHSA-7Q8Q and GHSA-JQH4. Fix is a later malformed-URL / security merge. Deeper blame attributed one AI line in tests/unit/adapters/http.test.js, not formDataToJSON. http.js overlap is routing, not formToJSON recursion origin.

### 03 GHSA-V96J-25GV-G2W9 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `go-gitea/gitea`
- Rank: 723
- Summary: Gitea: Unauthenticated ReDoS via CODEOWNERS pattern matching allows denial of service
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f810e882 is a chroma/regexp2 v2 dependency bump whose pull.go hunk only retargets the regexp2 import path. Fix bounds CODEOWNERS match time. Deeper blame attributed zero AI lines. Import retarget is routing, not unbounded CODEOWNERS origin.

### 04 GHSA-GCFQ-8GQF-4876 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `gofiber/fiber`
- Rank: 724
- Summary: GoFiber Vulnerable to X-Real-IP Spoofing via Header.Add() in BalancerForward
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fe1bf4a0 adds conditional copy helpers. Fix switches BalancerForward from Header.Add to Header.Set. Deeper blame attributed zero AI lines. proxy.go overlap is routing, not X-Real-IP append origin.

### 05 GHSA-4QCJ-M5WP-JMF4 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Budibase/budibase`
- Rank: 725
- Summary:  Budibase: Missing RBAC on GET /api/global/groups allows BASIC users to enumerate all tenant groups and role mappings
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 24b6e70e adds bulk CSV group-user upload. Fix requires builder access on group listing. Deeper blame attributed zero AI lines. groups.spec.ts overlap is routing, not missing-RBAC origin.

### 06 GHSA-FRVP-7C67-39W9 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `honojs/node-server`
- Rank: 726
- Summary: Node.js Adapter for Hono: Path traversal in `serve-static` on Windows via encoded backslash (`%5C`)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7503265e optimizes request header construction. Fix hardens serve-static against encoded backslash. Deeper blame attributed zero AI lines. serve-static.test.ts overlap is a test-file routing hit, not %5C traversal origin.

### 07 GHSA-6G9V-7GQ3-P2C6 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `surrealdb/surrealdb`
- Rank: 727
- Summary: SurrealDB: Authenticated callers can read fields hidden by field-level SELECT permissions via error messages
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 24f15e56 adds predicate prefilter for KV scans. Fix replaces raw operands with type names in arithmetic/extend errors. Deeper blame attributed zero AI lines. val/mod.rs overlap is routing, not error-message leak origin.

### 08 GHSA-GMFW-G93R-VG53 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 728
- Summary: Open WebUI: Unauthenticated WebSocket Access to Collaborative Document Handlers (ydoc:awareness:update, ydoc:document:leave)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 823b9a6d removes unused SRC log env vars. Fix requires auth on ydoc awareness/leave handlers. Deeper blame attributed zero AI lines. socket/main.py overlap is routing, not unauthenticated ydoc origin.

### 09 GHSA-4C39-4CCG-62R3 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `vercel/next.js`
- Rank: 729
- Summary: Next.js: Unbounded Server Action payload in Edge runtime
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fa56f2c1 stops revalidateTag(profile) from forcing client cache invalidation. Fix enforces serverActions.bodySizeLimit on Edge. Deeper blame attributed zero AI lines. action-handler.ts overlap is a sibling Server Action change, not unbounded Edge payload origin.

### 10 GHSA-M3QF-58WF-W979 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `open-webui/open-webui`
- Rank: 730
- Summary: Open WebUI: Arena task endpoints can bypass underlying model access controls
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 47198811 moves bypass_system_prompt onto request.state. Fix enforces per-model access on arena fallback before bypass_filter. Deeper blame attributed zero AI lines. chat.py overlap is a sibling prompt-bypass move, not arena model-ACL origin.

### 11 GHSA-JX74-CQJV-2C67 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `flytohub/flyto-core`
- Rank: 731
- Summary: Flyto2 Core: Unauthenticated flyto-verification /run: callback_url SSRF and internal runner-secret exfiltration
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 082b7a37 widens browser can_connect_to to agent.* modules. Fix authenticates verification /run and adds per-module SSRF guards. Deeper blame attributed three lines from a different SHA b7e7710c in http/batch.py, get.py, and request.py, not verification_service.py. proxy_rotate.py overlap is routing, not unauthenticated /run origin.

### 12 GHSA-45GF-FJXP-CJPQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `pipeboard-co/meta-ads-mcp`
- Rank: 732
- Summary: meta-ads-mcp: Server-Side Request Forgery (SSRF) in `upload_ad_image` via Unrestricted `image_url` Fetch
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ae007582 corrects create_ad_creative docs. Fix validates upload_ad_image image_url. Deeper blame attributed zero AI lines. __init__.py overlap is routing, not image_url SSRF origin.

### 13 GHSA-V5FF-XMFP-P245 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `electerm/electerm`
- Rank: 733
- Summary: electerm has Command Injection in File System Operations (rmrf, mv, cp)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 24ce7103 rewrites openFile to spawn argument arrays. Fix replaces rmrf/mv/cp shell strings with fs.promises. Deeper blame attributed zero AI lines. openFile is a sibling fs.js change, not rm/cp/mv injection origin.

### 14 GHSA-VXV2-8J6R-PCPG — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `go-gitea/gitea`
- Rank: 734
- Summary: Gitea: OAuth token introspection returns metadata of tokens issued to other clients (RFC 7662 section 4 violation)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f3bdcc58 sets OAuth2 authorization-code expiry and reuse checks. Fix restricts introspection to the token's client. Deeper blame attributed zero AI lines. oauth2_provider.go overlap is a sibling OAuth hardening, not introspection-client origin.

### 15 GHSA-VJG6-GM8M-V5G6 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `openbabel/openbabel`
- Rank: 735
- Summary: Open Babel has out-of-bounds write in MOL2 attribute/value parser
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e23a224b adds a GetAtom NULL check on MOL2 charge parsing (CVE-2026-2705). Fix width-limits sscanf on the attribute/value header (CVE-2022-43607). Deeper blame attributed zero AI lines. Charge-parser hardening is a sibling mol2format.cpp path, not attribute/value OOB origin.

### 16 GHSA-33CG-GXV8-3P8G — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vllm-project/vllm`
- Rank: 736
- Summary: vLLM denial of service via prompt embeds on M-RoPE models
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c7560af4 replaces shared-memory routed experts with ModelRunnerOutput transfer. Fix guards prompt_embeds on M-RoPE models. Deeper blame attributed zero AI lines. gpu_model_runner.py overlap is routing, not M-RoPE prompt-embed origin.

### 17 GHSA-P893-RVQ9-2XF9 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `onnx/onnx`
- Rank: 737
- Summary: ONNX: Heap-Buffer-Overflow READ in Gemm Version Converter Adapter via Undersized Input Shape
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 455256a7 adds scatter version-converter adapters for opsets 15-18. Fix adds Gemm input-rank checks. Deeper blame attributed zero AI lines. version_converter_test.py overlap is routing, not Gemm_7_6 undersized-shape origin.

### 18 GHSA-7Q8Q-RJ6J-MHJQ — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `axios/axios`
- Rank: 738
- Summary: Axios: Nested axios option objects can consume polluted prototype values
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6bb12c19 strips custom auth headers on cross-origin redirects, the same SHA already ranked for GHSA-PMV8 and GHSA-JQH4. Fix is the later malformed-URL / security merge. Deeper blame attributed one AI line in tests/unit/adapters/http.test.js. Shared SHA without nested-options mechanism equality is not prototype-pollution origin.

### 19 GHSA-7RC3-G7H6-22M7 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `filebrowser/filebrowser`
- Rank: 739
- Summary: File Browser: Colliding username normalization gives two users the same home directory
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 847d08bd addresses archive traversal, login DoS, and symlink escape, including a MaxBytesReader cap in auth.go. Fix rejects signup when a normalized home directory collides. Deeper blame attributed zero AI lines. Body-size capping is a sibling auth.go change, not username-normalization origin.

### 20 GHSA-JQH4-M9W3-8HP9 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `axios/axios`
- Rank: 740
- Summary: Axios: Fetch adapter `ReadableStream` uploads bypass `maxBodyLength`
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6bb12c19 strips custom auth headers on cross-origin redirects, the same SHA already ranked for GHSA-PMV8 and GHSA-7Q8Q. Fix is the later malformed-URL / security merge touching fetch.js. Deeper blame attributed one AI line in tests/unit/adapters/http.test.js, not the fetch adapter. Shared SHA without ReadableStream maxBodyLength equality is not origin.

### 21 GHSA-RJG7-R26H-CFP2 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `koel/koel`
- Rank: 741
- Summary: Koel: Full-read SSRF via podcast enclosure URL: isPublicHost() filter_var guard does not reject NAT64 (64:ff9b::/96) or 6to4 (2002::/16) IPv6-transition wrappers of internal IPv4
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 8a4b9347 adds radio now-playing and introduces Helpers\Network::isPublicHost for ValidRadioStationUrl only. Podcast enclosure validation is wired later by 8708f077 (GHSA-7j2f). Fix 5f6ce2ce closes remaining SSRF including IPv6 transition. Deeper blame attributed 45 helper lines in Network.php. Radio-helper origin without podcast-enclosure equality is not this advisory's direct root. Shared SHA with GHSA-JR4P does not imply mechanism equality.

### 22 GHSA-664H-WQGQ-64GW — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Automattic/mongoose`
- Rank: 742
- Summary: Mongoose: Prototype pollution in mongoose update casting via __proto__-prefixed dotted path (Schema._getSchema/path getter)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 24ff1d1e is a Copilot Autofix comment-only change around completeManyOptions.defaults. Fix delays cloning Query._update so __proto__ paths survive. Deeper blame attributed zero AI lines. query.js overlap is routing, not __proto__ update-cast origin.

### 23 GHSA-CQJC-RMPQ-XPRQ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Eugeny/russh`
- Rank: 743
- Summary: Russh: Post-auth remote panic via pty-req with more than 130 terminal-mode records
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 32fd46f1 reduces write-path copies with direct Bytes sends. Fix validates pty terminal-mode records. Deeper blame attributed zero AI lines. encrypted.rs overlap is routing, not pty-req panic origin.

### 24 GHSA-FCRW-F7GG-6G9F — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `Budibase/budibase`
- Rank: 744
- Summary:  Budibase: SSO OAuth2 Token Leakage via User Metadata Endpoints to Power-Role Users
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 700ff33d exposes CurrentUser.oauth2 on automation UserBindings. Fix strips oauth2 and other sensitive fields from /api/users/metadata merges. Deeper blame attributed zero AI lines. Automation bindings in utils.ts are a sibling oauth exposure, not metadata-endpoint leak origin.

### 25 GHSA-XG2H-5XR2-29JW — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `microsoft/kiota`
- Rank: 745
- Summary: Microsoft Kiota: Code Generation Literal Injection in Kiota Ruby Generator
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 50d819d6 fixes isStream always evaluating false in Ruby CodeMethodWriter. Fix escapes interpolation markers in generated string literals. Deeper blame attributed zero AI lines. isStream comparison is a sibling CodeMethodWriter change, not literal-injection origin.

### 26 GHSA-JR4P-4XJH-FWVW — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `koel/koel`
- Rank: 746
- Summary: Koel: Server-Side Request Forgery (SSRF) in radio station creation due to missing validation bail
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 8a4b9347 adds isPublicHost inside ValidRadioStationUrl. RadioStationStoreRequest already lacked bail before that commit. Fix adds bail and relocates the network helper. Deeper blame attributed 45 helper lines in Network.php, not the request-class rule list. Missing bail is an untouched sibling validation-pipeline hole, not radio now-playing origin. Shared SHA with GHSA-RJG7 does not imply mechanism equality.

### 27 GHSA-C8JX-96C9-8XRP — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `surrealdb/surrealdb`
- Rank: 747
- Summary: SurrealDB: Field-level SELECT permissions bypassed via indexed COUNT fast paths
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 15579bd2 refactors planner code to reduce duplication. Fix plugs field-permission leaks in indexed COUNT fast paths. Deeper blame attributed zero AI lines. planner/select/mod.rs overlap is routing, not COUNT fast-path origin.

### 28 GHSA-38C3-WV3C-V3XJ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `acacode/swagger-typescript-api`
- Rank: 748
- Summary: swagger-typescript-api vulnerable to code injection via unescaped `servers[0].url` in axios http-client template
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 691d07d8 adds a changeset for preferExistingSchemaNamesForExternalRefs. Fix escapes servers[0].url in the axios http-client template. Deeper blame attributed zero AI lines. code-gen-process.ts overlap is routing, not base-url injection origin.

### 29 GHSA-RQJ7-6WRP-6G2G — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `open-webui/open-webui`
- Rank: 749
- Summary: Open WebUI: POST /api/v1/images/edit bypasses the global image-edit switch and the per-user image-generation permission
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI de8ea08f routes image-URL fetches through an SSRF-safe session. Fix authorizes POST /api/v1/images/edit. Deeper blame attributed zero AI lines. SSRF fetch hardening in images.py is a sibling change, not missing ENABLE_IMAGE_EDIT origin.

### 30 GHSA-38HQ-7X33-PHP4 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `backstage/backstage`
- Rank: 750
- Summary: @backstage/plugin-auth-backend: Unauthenticated OAuth account takeover via `redirect_uri` allowlist bypass
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ed4ffaa3 defaults catalog presence checks on and renames config. Fix hardens the redirect_uri allowlist. Deeper blame attributed zero AI lines. OidcRouter.test.ts overlap is routing, not allowlist-bypass origin.

## Conservation

- rank_pool 3473 = 720 prior directroot reviews + 30 this slice + 80 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch24: 720; this slice 721-750
- Incoming unreviewed hits before this slice: 110; after: 80
- Canonical81 append identities GHSA-X4HG-HFWF-P9MW, GHSA-322X-V876-G883, and GHSA-PMCH-G965-GRMR were already in batch9 and batch11
- Stale 260813 batch3 equals formal 260814 batch3 (30 IDs) and is not 30 extra reviewed rows
- Unreviewed remaining IDs are UNREVIEWED, not REJECT
- Checkpoint at 75 percent recorded before the final seven rows, then the assigned slice was exhausted

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD. Six deeper-blame hits still fail ai_hunk and but-for: axios GHSA-PMV8/7Q8Q/JQH4 share one redirect-header SHA with a single test-file line; flyto GHSA-JX74 blames a different HTTP SHA; koel GHSA-RJG7/JR4P share a radio isPublicHost helper later reused for podcasts and a missing-bail sibling. Sibling-path security-adjacent AI edits are not seven-gate direct-root.
