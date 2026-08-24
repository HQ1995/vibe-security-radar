# Direct-root mining batch 28 (frozen assigned 20)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 20 assigned first-party GHSA identities: the next 20 unique rank-hits after canonical81 and directroot batches 1-27. Authoritative ID order is batch27 `work/unreviewed-hit-ids.txt`. Leader correction: original ranks are the score-sorted unique remaining queue, not raw file-line numbers. Discarded-slice results are not promoted. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 20
- Reviewed: 20
- Remaining unreviewed rank hits: 0
- PASS proposals: 0
- REJECT: 20
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=20; 810+20+0+2643=3473 rank_pool; 810+20=830 unique rank hits

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical81 strict identities plus batch1-27 `selected-30.jsonl`/`cases.jsonl`, including terminal batch27 selected-30. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. Zero overlap with incomplete-remediation20k asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-FM2F-4339-4P2F — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `FlowiseAI/Flowise`
- Rank: 811
- Summary: Flowise: Missing Authorization on Execution Update Endpoint
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI e135b294 adds apikey permission columns and rewrites Permissions.ts constructors. Fix adds executions:update and applies it to PUT /api/v1/executions. Deeper blame attributed zero AI lines. Apikey RBAC rewrite is a sibling access-control path, not execution-update origin, and is not a patch-delta of that omitted executions boundary.

### 02 GHSA-JFM3-95JQ-Q3RF — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `thephpleague/commonmark`
- Rank: 812
- Summary: league/commonmark:  Denial of service via duplicate footnote definitions
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI 84870f31 adds enable_inline_footnotes config and documentation. Fix de-duplicates footnote definitions in GatherFootnotesListener and NumberFootnotesListener. Deeper blame attributed zero AI lines. Test-file overlap is routing, not duplicate-definition DoS origin.

### 03 GHSA-RM43-82J9-R4MJ — REJECT `OLD_BUG_PRESERVATION`

- Repository: `dep0we/atomic-agents-stack`
- Rank: 813
- Summary: atomic-agents-stack: Dashboard HTTP server path traversal allows arbitrary file read
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI 08c5f6ab adds allowlisted dashboard tab routes that join constant filenames under _dashboard. The advisory mechanism is request-path traversal on /agents/<name> through pre-existing _serve_file. Deeper blame hit the tab-map lines the later security commit also rewrote, but removing the tab routes does not eliminate the /agents traversal. Tab routing is a sibling path, not origin, and is not a patch-delta of an omitted tab-boundary case.

### 04 GHSA-4F78-QHMW-8J8M — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `electron/electron`
- Rank: 814
- Summary: Electron: DevTools JavaScript Injection via Unsanitized Dock State Parameter
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI fe477ce3 is a Chromium roller bump with Claude patch-conflict helpers. Fix allowlists dock_state before DevTools JS execution. Deeper blame attributed zero AI lines. inspectable_web_contents.cc overlap is routing, not unsanitized dock-state origin.

### 05 GHSA-C4C3-PG64-4M4V — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `mermaid-js/mermaid`
- Rank: 815
- Summary: Mermaid configuration APIs allow prototype pollution
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI dea05724 enforces -beta suffix policy in tests and fixtures. Fix refactors assignWithDepth against prototype pollution. Deeper blame attributed zero AI lines. mermaidAPI.spec.ts overlap is routing, not configuration-merge pollution origin.

### 06 GHSA-MJ63-M3RC-8PPR — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `thephpleague/commonmark`
- Rank: 816
- Summary: league/commonmark: Denial of service via deeply nested XML output
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI ba637f65 is a PHPStan 2 annotation cleanup. Fix caps XmlRenderer indentation depth. Deeper blame attributed zero AI lines. XmlRenderer.php overlap is routing, not quadratic XML indentation origin.

### 07 GHSA-8X5V-CPV7-8JJP — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `open-webui/open-webui`
- Rank: 817
- Summary: Open WebUI: Any authenticated user can reach internal services and cloud metadata via NAT64-encoded URLs
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI 087878ce retargets WEB_FETCH_FILTER_LIST matching onto hostname label boundaries. Fix replaces literal ipaddress.is_global with NAT64-aware _is_global_addr. Deeper blame attributed two lines to a different AI SHA (854440f7 DNS-rebinding connect-time check), not the ranked candidate. Hostname filter-list matching is a sibling SSRF control, not NAT64-embedded IPv4 origin, and is not a patch-delta of that omitted is_global case.

### 08 GHSA-87X5-VMC3-756J — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `vllm-project/vllm`
- Rank: 818
- Summary: vLLM: Completion prompt lists fan out into unbounded engine requests
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI ebf862c3 adds system_fingerprint on OpenAI-compatible responses. Fix bounds completion prompt-list fan-out. Deeper blame attributed zero AI lines. protocol.py overlap is routing, not unbounded prompt-list origin.

### 09 GHSA-WG86-R78F-74MP — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `FlowiseAI/Flowise`
- Rank: 819
- Summary: Flowise Sandbox Escape to RCE
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI e47d9466 adds MIME type and extension validation for uploads. Fix hardens JavaScript sandbox escape paths. Deeper blame attributed zero AI lines. validator.ts / utils.ts overlap is routing. Shared SHA without mechanism equality is not sandbox-escape origin.

### 10 GHSA-MJ5R-JF49-M3W7 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `open-webui/open-webui`
- Rank: 820
- Summary: Open WebUI: Any member with write access to a standard channel can edit or delete other members' messages
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI a66477b7 binds thread parent/reply IDs to the URL channel. Fix requires authorship on standard-channel edit and delete. Deeper blame attributed zero AI lines. Cross-channel thread binding is a sibling channels.py path, not missing authorship origin, and is not a patch-delta of that omitted authorship boundary.

### 11 GHSA-9F4C-93C8-JC8G — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `electron/electron`
- Rank: 821
- Summary: Electron: Sandboxed iframe can bypass the allow-popups restriction via the OpenURL navigation path
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI 0ef05613 reads nodeIntegrationInWorker from per-frame WebPreferences. Fix applies iframe sandbox allow-popups on the OpenURL path. Deeper blame attributed zero AI lines. chromium-spec.ts overlap is routing, not OpenURL popup-restriction origin.

### 12 GHSA-5XVG-PMGG-3MXR — REJECT `INCOMPLETE_REMEDIATION_WITHOUT_PATCH_DELTA`

- Repository: `FlowiseAI/Flowise`
- Rank: 822
- Summary: Flowise: CSV Agent Prompt Injection Remote Code Execution Vulnerability
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI 42d593f8 hardens pythonCodeValidator against Unicode homoglyph and backslash-eval bypasses (FLOWISE-591). Advisory GHSA-5XVG is CSV Agent prompt-injection RCE (FLOWISE-606). Fix touches CSVAgent cores and the validator. Deeper blame attributed zero AI lines, so the later patch does not reverse or amend the AI-added NFKC/backslash boundary as the omitted CSV-agent case. Prior validator hardening is not CSV-agent origin and fails the incomplete-remediation patch-delta rule.

### 13 GHSA-CHM3-VQCF-52RX — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `FlowiseAI/Flowise`
- Rank: 823
- Summary: Flowise: Cross-workspace credential IDOR in openai-assistants-vector-store
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI 840d2ae1 prevents DocumentStore IDOR takeover. Fix is a bundled tenant-guard commit covering openai-assistants-vector-store credentials. Deeper blame attributed zero AI lines. DocumentStore allowlisting is a sibling IDOR surface, not vector-store credential origin, and is not a patch-delta of that omitted credential-ownership boundary.

### 14 GHSA-XC48-889X-5QMW — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `FlowiseAI/Flowise`
- Rank: 824
- Summary: Flowise: CVE-2025-8943 Patch Bypass: npm_config_yes bypasses MCP environment variable blocklist (Unauthenticated RCE)
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI b5f7fac0 threads workspaceId into CustomMCP getVars. Fix expands the MCP environment-variable blocklist against npm_config_yes. Deeper blame attributed zero AI lines. workspaceId plumbing is routing, not CVE-2025-8943 env-blocklist residual origin.

### 15 GHSA-FR6G-7CQ8-FG82 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `FlowiseAI/Flowise`
- Rank: 825
- Summary: Flowise: Information Disclosure in GET /api/v1/upsert-history returns the entire server-wide upsert history
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI 840d2ae1 is the same DocumentStore IDOR commit as GHSA-CHM3. Advisory is server-wide upsert-history disclosure. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not upsert-history origin.

### 16 GHSA-JR45-8VMC-QM54 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `nodejs/undici`
- Rank: 826
- Summary: undici vulnerable to cross-user information disclosure via whitespace around equals in Cache-Control directives
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI 90775009 limits 1-year deleteAt to immutable cache responses. Fix trims qualified Cache-Control field names around equals. Deeper blame attributed zero AI lines. cache.js test overlap is routing, not OWS-around-equals disclosure origin.

### 17 GHSA-W62W-66V9-VVGV — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `seaweedfs/seaweedfs`
- Rank: 827
- Summary: SeaweedFS: Path traversal in the S3 and Iceberg REST gateways allows cross-bucket access
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI 10a30a83 adds GetObjectAttributes API constants and handlers. Fix rejects .. in S3 and Iceberg URL path vars. Deeper blame attributed zero AI lines. header.go overlap is routing, not SkipClean path-traversal origin.

### 18 GHSA-RQ84-P6RR-VF89 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 828
- Summary: Open WebUI: Account takeover via OAuth token exchange accepting tokens issued to any client
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI 823b9a6d is a 100-file log-env cleanup. Fix tightens OAuth token-exchange audience checks in auths.py. Deeper blame attributed zero AI lines. auths.py overlap is routing, not any-client token-exchange origin.

### 19 GHSA-F2R8-JV7C-XQMP — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `electron/electron`
- Rank: 829
- Summary: Electron: DevTools embedder handler executes arbitrary files via shell open
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI fe477ce3 is the same Chromium roller bump as GHSA-4F78. Fix uses ShowItemInFolder for the DevTools embedder message. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not shell-open file-execution origin.

### 20 GHSA-8XCM-R25X-G524 — REJECT `CARRIER_OR_MERGE`

- Repository: `nodejs/undici`
- Rank: 830
- Summary: undici vulnerable to downstream response desynchronization via retry interceptor
- Failing gates: ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate
- Counterevidence: Ranked AI f601c1a1 is a two-parent merge of main into next. Ranked n_parents=2. Overlap is retry-handler test timing. Ranked fix 2b3f7493 only corrects test fixtures; advisory first-party fix SHAs are other retry interceptor commits. Merge/carrier authorship transfer is insufficient, and the assigned fix does not reverse the desynchronization mechanism.

## Conservation

810 prior reviewed + these 20 = 830 unique rank hits. Rank pool 3473 = 810 + 20 + 0 unreviewed hits + 2643 misses.

## Publication

HOLD. No PASS proposals. Canonical count is unmodified.
