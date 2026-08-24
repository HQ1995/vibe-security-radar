# Direct-root mining batch 27 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical81 and directroot batches 1-26, including frozen batch26 selected-30 and terminal batch24/batch25 selected/cases. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 20
- PASS proposals: 0
- REJECT: 29
- BLOCKED: 1
- NARROW / UNKNOWN: 0
- Conservation: assigned=reviewed=30; 780+30+20+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical81 strict identities plus batch1-26 `selected-30.jsonl`/`cases.jsonl`, including frozen batch26 selected-30 and terminal batch24/batch25. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-H754-FXP7-88WX — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `acacode/swagger-typescript-api`
- Rank: 781
- Summary: swagger-typescript-api vulnerable to authorization-token exfiltration via spec $ref
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 691d07d8 adds a changeset and reparses external $ref type names when preferExistingSchemaNamesForExternalRefs is false. Fix is a bundled security commit. Deeper blame attributed zero AI lines. code-gen-process.ts overlap is routing, not Authorization-token exfiltration origin.

### 02 GHSA-R4RV-85JG-W4MF — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `lepture/mistune`
- Rank: 782
- Summary: Mistune: Arbitrary File Read via Include directive path traversal
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5afeaf6b filters image-directive src through safe_url. Fix constrains Include directive targets. Deeper blame attributed zero AI lines. Image-scheme filtering is a sibling directive path, not include path-traversal origin, and is not a patch-delta of an omitted include-boundary case.

### 03 GHSA-QQ9Q-XGM3-XV9G — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `flytohub/flyto-core`
- Rank: 783
- Summary: Flyto2 Core: LLM/API keys leak to an attacker-controlled base_url
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d5fda807 is the same get_nested_value rename as prior Flyto identities. Fix confines writes and gates env credentials. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not attacker-controlled base_url origin.

### 04 GHSA-94PJ-82F3-465W — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `guzzle/guzzle`
- Rank: 784
- Summary: Guzzle: Proxy-Authorization headers can be sent to origin servers
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fb92d95f updates CI workflows, PHPStan, and removes Psalm. Fix stops first-class Proxy-Authorization from reaching origins. Deeper blame attributed zero AI lines. StreamHandlerTest.php overlap is routing, not proxy-header origin.

### 05 GHSA-HQJ5-CW9F-RX67 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `acacode/swagger-typescript-api`
- Rank: 785
- Summary: swagger-typescript-api vulnerable to code injection via unescaped servers[0].url in fetch http-client template
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 691d07d8 is the same preferExistingSchemaNamesForExternalRefs changeset as GHSA-H754. Fix is the same bundled security commit. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not unescaped servers[0].url origin.

### 06 GHSA-CR7P-CR3Q-H5CM — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Budibase/budibase`
- Rank: 786
- Summary: Budibase: Account Enumeration via Login Lockout Response Differential
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 43b56471 adds HTML mode for the Embed binding panel. Fix aligns login lockout for unknown users. Deeper blame attributed zero AI lines. auth.spec.ts overlap is routing, not lockout-response origin.

### 07 GHSA-PC2W-4MQ8-32QW — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `dynatrace-oss/dynatrace-mcp`
- Rank: 787
- Summary: @dynatrace-oss/dynatrace-mcp-server's create_dynatrace_notebook missing the human-approval gate
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI af161e02 handles CLI metadata flags before env validation. Fix adds a human-approval gate to create_dynatrace_notebook. Deeper blame attributed zero AI lines and zero deleted source spans. index.ts overlap is routing, not missing-approval origin.

### 08 GHSA-3769-JGQC-CXM7 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `FlowiseAI/Flowise`
- Rank: 788
- Summary: Flowise: RCE via NodeVM Sandbox Escape in executeJavaScriptCode() nodeVMOptions Override
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e47d9466 adds MIME type and extension validation for file uploads. Fix hardens executeJavaScriptCode nodeVMOptions. Deeper blame attributed zero AI lines. utils.ts overlap is routing, not nodeVMOptions-override origin.

### 09 GHSA-FQ2P-5P22-8G6J — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `go-gitea/gitea`
- Rank: 789
- Summary: Gitea: Public-Only Personal access tokens scope bypass in Organization and Permission Endpoints
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 45809c8f adds configurable permissions for Actions automatic tokens. Fix unifies public-only token filtering. Deeper blame attributed zero AI lines. repo_list.go overlap is routing, not PAT public-only origin.

### 10 GHSA-4CWX-7WF7-3272 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `nodejs/undici`
- Rank: 790
- Summary: undici vulnerable to cross-user information disclosure and parse-time crash via degenerate private cache directives
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI de01babc stores revalidation-only no-cache/etag responses. Fix handles empty qualified private cache directives. Deeper blame attributed zero AI lines. cache.js overlap is routing, not private="" shared-cache origin.

### 11 GHSA-6VH2-WG4H-4VWJ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `FlowiseAI/Flowise`
- Rank: 791
- Summary: Flowise: Unauthenticated Property Injection into Flow Execution Context via Ungated overrideConfig Spread in Prediction API
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI aee37e16 adds ambient-agent webhooks. Fix removes the ungated overrideConfig spread. Deeper blame attributed zero AI lines. buildAgentflow.ts overlap is routing, not Prediction overrideConfig origin.

### 12 GHSA-W2RX-84HP-GG95 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `open-webui/open-webui`
- Rank: 792
- Summary: Open WebUI: SSRF into internal services via unvalidated sub-resource requests in the Playwright web loader
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 087878ce switches WEB_FETCH_FILTER_LIST matching onto hostname label boundaries. Fix validates Playwright sub-resources and redirect hops. Deeper blame attributed 34 utils.py lines to a different AI SHA f02aeea0 that intercepted document navigations and explicitly left sub-resources through. Authorship cannot transfer across commits. Ranked hostname matching is not unvalidated-sub-resource origin.

### 13 GHSA-VMV7-4M6C-3CG5 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `FlowiseAI/Flowise`
- Rank: 793
- Summary: Flowise: CSV Agent Remote Code Execution via Pyodide Code Injection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 42d593f8 hardens pythonCodeValidator Unicode/backslash cases. Fix deletes CSVAgent, AirtableAgent, and the validator. Deeper blame attributed zero AI lines on source deleted hunks under the 200-line skip. Shared SHA without mechanism equality is not CSVAgent interpolation origin, and deleting the agents is not a patch-delta of an omitted validator case.

### 14 GHSA-2MHJ-FHVG-V428 — BLOCKED `AI_INCOMPLETE_REMEDIATION`

- Repository: `pimcore/pimcore`
- Rank: 794
- Summary: Pimcore: ClassDefinition UID regex missing end anchor allows SQL injection via Block.php unquoted table name
- Failing gates: release_gate
- Counterevidence: Ranked AI dbe1d131 is an explicit ClassDefinition security rewrite that added leading ^ anchors but omitted trailing $. The first-party GHSA names that omitted $ as the residual bypass, and fix 33a0e188 amends the same regex. Deeper blame attributed those two ClassDefinition.php lines to dbe1d131. The local clone has zero tags, so a released artifact containing the incomplete AI guard is unproved. Worker PASS is withheld.

### 15 GHSA-P2RR-RVMM-C5FP — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `electron/electron`
- Rank: 795
- Summary: Electron: Sandboxed iframes can launch external protocol handlers
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0ef05613 reads nodeIntegrationInWorker from per-frame WebPreferences. Fix respects iframe sandbox flags for external protocol navigation. Deeper blame attributed zero AI lines. chromium-spec.ts overlap is routing, not sandbox-protocol origin.

### 16 GHSA-6X64-9X62-F2GX — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `mermaid-js/mermaid`
- Rank: 796
- Summary: Mermaid allows CSS injection applying to sibling elements of the diagram
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI dea05724 enforces a -beta suffix policy in tests. Fix is a merge-from-fork security commit. Deeper blame attributed zero AI lines. mermaidAPI.spec.ts overlap is routing, not sibling-CSS origin.

### 17 GHSA-4J8X-X6V7-W9RQ — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `FlowiseAI/Flowise`
- Rank: 797
- Summary: Flowise: RCE via CSVAgent csvFile data URI base64 segment is interpolated into Python source without validation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 42d593f8 is the same pythonCodeValidator homoglyph commit as GHSA-VMV7. Fix is the same agent-removal commit. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not csvFile data-URI interpolation origin.

### 18 GHSA-F6WF-28G6-769X — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `smarty-php/smarty`
- Rank: 798
- Summary: Smarty: Symlink path traversal out of trusted directories
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ff2ef3b0 redirects test temp dirs to the system temp directory. Fix prevents symlink traversal out of secure_dir. Deeper blame attributed zero AI lines. SecurityTest.php overlap is routing, not symlink-escape origin.

### 19 GHSA-3CG5-48J3-V4GV — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 799
- Summary: Open WebUI: A folder write-collaborator can permanently delete the owner's chats by deleting a shared subfolder
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 823b9a6d removes unused SRC-level log env vars. Fix restricts folder deletion to the owner or an admin. Deeper blame attributed zero AI lines. folders.py overlap is routing, not collaborator-delete origin.

### 20 GHSA-C6XH-WV4J-PPV5 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `FlowiseAI/Flowise`
- Rank: 800
- Summary: Flowise: SSRF Protection Bypass via IPv4-Mapped IPv6 Addresses
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 8c2b2ffe always unions DEFAULT_DENY_LIST into custom deny-list values. Fix normalizes IPv4-mapped IPv6 before CIDR matching. Deeper blame attributed two httpSecurity.ts lines to a different AI SHA 643ebf53 from a DNS-rebinding advisory, not 8c2b2ffe. Authorship cannot transfer. Deny-list merge is not IPv4-mapped comparison origin.

### 21 GHSA-WG23-69C2-GJC8 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `craftcms/cms`
- Rank: 801
- Summary: Craft CMS: Passkey login accepts replayed WebAuthn assertions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5aa4db3c removes unused BadRequestHttpException throws from userActionChecks. Fix reads WebAuthn request options from session. Deeper blame attributed zero AI lines. UsersController.php overlap is routing, not assertion-replay origin.

### 22 GHSA-RFFM-9Q57-Q649 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 802
- Summary: Open WebUI: Client-side SSRF via unrestricted external resource loading in Vega/Vega-Lite chart rendering
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bf6325ff sanitizes mermaid SVG output. Fix blocks external resource loading in Vega chart rendering. Deeper blame attributed zero AI lines. utils/index.ts overlap is routing, not Vega loader origin.

### 23 GHSA-73CQ-MCGH-379C — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `open-webui/open-webui`
- Rank: 803
- Summary: Open WebUI: Instance-wide stall via automation recurrence rules that force multi-second parsing
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 920b655f re-gates scheduled automation owners and fails closed on per-model access. Fix changes RRULE DTSTART anchoring so minutely/hourly rules do not walk from year 2000. Deeper blame attributed zero AI lines. Owner-permission gating is a sibling automations.py path, not recurrence-parse DoS origin, and is not a patch-delta of an omitted RRULE bound.

### 24 GHSA-JXC9-XMC4-GR23 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 804
- Summary: Open WebUI: Deletion of directories and file embeddings in other knowledge bases via sync cleanup
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f0e0cfcf avoids a redundant knowledge re-fetch. Fix scopes sync cleanup deletions to the target knowledge base. Deeper blame attributed zero AI lines and zero deleted source spans. knowledge.py overlap is routing, not cross-base cleanup origin.

### 25 GHSA-3VF6-64VR-3G56 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 805
- Summary: Open WebUI: Any authenticated user can cancel another user's chat generation via the chat delete endpoint
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a0898423 stops reverting replace/outlet content on chat save. Fix authorizes before cancelling tasks in chat delete. Deeper blame attributed zero AI lines. chats.py overlap is routing, not cross-user cancel origin.

### 26 GHSA-M65R-RPRJ-R5RG — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Eugeny/russh`
- Rank: 806
- Summary: Russh: Channel-scoped server callbacks can be reached without an open channel
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 32fd46f1 reduces write-path copies with direct Bytes sends. Fix guards channel messages against not-yet-established channel IDs. Deeper blame attributed zero AI lines. encrypted.rs overlap is routing, not unopened-channel origin.

### 27 GHSA-52FH-8V99-63C2 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `FlowiseAI/Flowise`
- Rank: 807
- Summary: Flowise: Pyodide validator Unicode homoglyph bypass leads to RCE
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 42d593f8 is the same Flowise 591 validator commit as GHSA-VMV7. The GHSA describes a residual homoglyph bypass, but fix f4e2794f deletes CSVAgent/AirtableAgent and the validator instead of amending an omitted case inside that AI-added boundary. Deeper blame skipped the 390-line file delete. Shared SHA plus product removal is not countable incomplete-remediation patch-delta.

### 28 GHSA-M8RV-5G2X-5CG5 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `nodejs/undici`
- Rank: 808
- Summary: undici vulnerable to CRLF Injection via blob-like body type property
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f0b40bd6 eliminates eager llhttp promise creation. Fix validates blob body content type. Deeper blame attributed zero AI lines. client-h1.js overlap is routing, not blob-type CRLF origin.

### 29 GHSA-2V8P-3F2J-5MP7 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `mermaid-js/mermaid`
- Rank: 809
- Summary: Mermaid XY Charts are vulnerable to an infinite loop DoS
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 29bd1f55 organises Cypress spec files into diagram subfolders. Fix is a merge-from-fork security commit. Deeper blame attributed zero AI lines. xyChart.spec.js overlap is routing, not infinite-loop origin.

### 30 GHSA-G423-GRF7-98RV — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 810
- Summary: Open WebUI: Users denied the image-generation permission can still generate images via chat completions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e64acf1c batches and deduplicates per-request DB reads in chat middleware. Fix enforces feature permissions on the legacy chat-features block. Deeper blame attributed zero AI lines. middleware.py overlap is routing, not image_generation permission origin.

## Conservation

- rank_pool 3473 = 780 prior directroot reviews + 30 this slice + 20 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch26: 780; this slice 781-810
- Incoming unreviewed hits before this slice: 50; after: 20
- Stale 260813 batch3 equals formal 260814 batch3 (30 IDs) and is not 30 extra reviewed rows
- Unreviewed remaining IDs are UNREVIEWED, not REJECT
- Checkpoint at 75 percent recorded before the final seven rows, then the assigned slice was exhausted

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD. Deeper-blame hits remain non-origin or unreleased: GHSA-W2RX blamed a different Playwright intercept SHA than the ranked hostname-filter commit; GHSA-C6XH blamed a different DNS-rebinding SHA than the ranked deny-list merge; GHSA-2MHJ has patch-delta incomplete-remediation evidence on the omitted `$` regex but the local clone has zero tags so released containment is BLOCKED; GHSA-VMV7/4J8X/52FH share the Flowise 591 validator SHA whose later fix deletes agents rather than amending an omitted case.
