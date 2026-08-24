# Direct-root mining batch 22 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities: the next 30 unique rank-hits after canonical81 and directroot batches 1-21, including frozen batch20 selected-30 and terminal batch21 selected/cases. The stale 260813 batch3 selection is byte-identical to formal 260814 batch3 and is counted once. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 170
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 630+30+170+2643=3473 rank_pool

## Method

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending. Exclude canonical81 strict identities plus batch1-21 `selected-30.jsonl`/`cases.jsonl`, including frozen batch20 selected-30 and terminal batch21. Zero overlap asserted before review. Each row used the frozen github-reviewed advisory JSON, parent/candidate/fix first-parent git, and deeper blame of source deleted hunks. File-history without hunk identity remains routing. Worker PASS is a proposal.

## Cases

### 01 GHSA-VCGP-9326-PQCP — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `ruby/net-imap`
- Rank: 631
- Summary: net-imap vulnerable to STARTTLS stripping via invalid response timing
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6229814f is a one-line JRuby SSLContext#setup change, the same SHA as GHSA-HM49. Fix is a merge for STARTTLS stripping. Deeper blame attributed zero AI lines. imap.rb overlap is routing, not STARTTLS-timing origin.

### 02 GHSA-7RX4-C5VX-G8W3 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `karakeep-app/karakeep`
- Rank: 632
- Summary: Karakeep SDK has SSRF via metascraper-logo-favicon that bypasses validateUrl protections
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7a100672 extracts HTML parsing into a subprocess. Parent crawlerWorker.ts already imported and invoked metascraper-logo-favicon. Fix replaces that plugin with metascraper-safe-favicon. Deeper blame attributed 13 moved AI lines in parseHtmlSubprocess.ts. Moving a pre-existing plugin is not favicon-SSRF origin.

### 03 GHSA-VVVV-983W-R7PV — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `workos/authkit-session`
- Rank: 633
- Summary: @workos/authkit-session has an Open Redirect via state-derived redirect target
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 9be02e9a extracts authentication business logic and removes deprecated code. Fix is a merge-from-fork against state-derived redirects. Deeper blame attributed zero AI lines. AuthService.ts overlap is routing, not open-redirect origin.

### 04 GHSA-3PV8-6F4R-FFG2 — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `composefs/tar-rs`
- Rank: 634
- Summary: tar has a PAX header desynchronization issue
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 17b1fd84 prevents a symlink-directory chmod collision. Fix corrects PAX header desynchronization. Deeper blame attributed zero AI lines. archive.rs overlap is a sibling unpack hardening, not PAX-desync origin.

### 05 GHSA-XWQR-RCQG-22MR — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `flightphp/core`
- Rank: 635
- Summary: Flight vulnerable to SQL Injection via unvalidated identifiers in SimplePdo::insert / update / delete
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 82daf71d applies Request.php code-review suggestions, the same SHA already reviewed for GHSA-QRCH. Fix is the same security-fixes merge as GHSA-VXRR. Deeper blame attributed zero AI lines. Request.php overlap is routing, not SimplePdo identifier-SQLi origin.

### 06 GHSA-7WX4-6VFF-V64P — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `huggingface/diffusers`
- Rank: 636
- Summary: Diffusers: TOCTOU Trust Remote Code Bypass
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d7fa4454 removes an 8-bit device restriction, the same SHA already reviewed for GHSA-98H9. Fix tightens trust_remote_code. Deeper blame attributed zero AI lines. pipeline_utils.py overlap is routing, not TOCTOU trust_remote_code origin.

### 07 GHSA-76W7-J9CQ-RX2J — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `patriksimek/vm2`
- Rank: 637
- Summary: vm2 is Vulnerable to Sandbox Breakout Through Promise Species
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 093494c0 closes GHSA-248r async-generator thenable capture, the same SHA shared with GHSA-6J2X, GHSA-M5Q2, and GHSA-Q3FM. Fix closes Promise species hijack. Deeper blame attributed zero AI lines. setup-sandbox.js overlap is a sibling sandbox patch, not Promise-species origin.

### 08 GHSA-P7C4-8X34-8J8F — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `DatanoiseTV/tinyice`
- Rank: 638
- Summary: TinyIce: Missing authentication on WebRTC ingest endpoint allows unauthorized stream injection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 56365f0e is a v2 admin UI, API token, and Swagger overhaul. Fix requires source password on /webrtc/source-offer. Deeper blame attributed zero AI lines. handlers_api.go overlap is routing, not WebRTC ingest-auth origin.

### 09 GHSA-WC7J-G8WX-M2QX — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `pimcore/pimcore`
- Rank: 639
- Summary: Pimcore: Missing Authorization in WebDAV MOVE via unchecked asset move handling
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4788bf3a hardens the unserializer and allowed classes. Fix adds WebDAV MOVE authorization. Deeper blame attributed zero AI lines. Tree.php overlap is a sibling serializer change, not MOVE-authorization origin.

### 10 GHSA-V865-P3GQ-HW6M — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 640
- Summary: OpenClaw has encoded-path auth bypass in plugin `/api/channels` route classification
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f5cab29e deregisters a stale Synology Chat webhook route. Fix hardens plugin HTTP route contracts. Deeper blame attributed zero AI lines. channel.ts overlap is a sibling plugin restart, not encoded-path /api/channels origin.

### 11 GHSA-GQ5C-RW37-G46C — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `NeoRazorX/facturascripts`
- Rank: 641
- Summary: FacturaScripts vulnerable to Reflected Cross-Site Scripting (XSS) via Cookie Manipulation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 73dd9f06 adds a disabled-user logout in auth(). Fix htmlspecialchars cookie nicks in log interpolations. Deeper blame attributed one AI comment line. The login-user-not-found sink is a 2023 non-AI line. Disabled-user logging is a sibling auth change, not fsNick HTML-XSS origin.

### 12 GHSA-3G8V-8R37-CGJM — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `php/frankenphp`
- Rank: 642
- Summary: FrankenPHP: Unsafe Unicode Handling in CGI Path Splitting Allows Execution of Non-PHP Files
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 2da08d63 sets SCRIPT_NAME, PHP_SELF, and PATH_INFO. Fix is a merge-from-fork against CGI Unicode path splitting. Deeper blame attributed zero AI lines. cgi.go overlap is routing, not Unicode path-split origin.

### 13 GHSA-5QRQ-9645-G5G2 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `ethyca/fides`
- Rank: 643
- Summary: ethyca-fides has a DOM-based XSS vulnerability in fides.js via fides_description override
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 3e0b8046 upgrades Prettier to 3.8.3. Fix is a merge-from-fork against fides_description DOM XSS. Deeper blame attributed zero AI lines. i18n test and consent-utils overlap is formatter routing, not fides_description origin.

### 14 GHSA-WJJV-3MJ2-39HF — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `agenticmail/agenticmail`
- Rank: 644
- Summary: AgenticMail API/storage and outbound relay hardening fixes
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 60354e34 is the 0.9.20 host-ownership release. Fix is a merge for API/storage/relay hardening. Deeper blame attributed zero AI lines. accounts.ts overlap is routing, not the advisory's API/storage/relay origin.

### 15 GHSA-6J2X-VHQR-QR7Q — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `patriksimek/vm2`
- Rank: 645
- Summary: vm2 sandbox escape via JSPI-backed Promise `.finally()` species bypass
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 093494c0 is the same GHSA-248r sandbox patch as GHSA-76W7. Fix removes WebAssembly JSPI from the sandbox. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not JSPI-Promise origin.

### 16 GHSA-FMXF-PM6P-7XGM — REJECT `UNTOUCHED_SIBLING_PATH`

- Repository: `AsyncHttpClient/async-http-client`
- Rank: 646
- Summary: async-http-client: Cookie header not stripped on cross-origin redirect
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fb50dc26 adds an optional Authorization-strip-on-redirect flag. Fix strips Cookie on cross-origin redirects. Deeper blame attributed zero AI lines. Authorization stripping is a sibling redirect-header path, not Cookie-leak origin, and is not a patch-delta of the same omitted-cookie boundary.

### 17 GHSA-MQ53-PC65-WJC4 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `FlowiseAI/Flowise`
- Rank: 647
- Summary: FlowiseAI: Evaluation create+update mass-assignment allows cross-workspace evaluation takeover
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6a63dbbf adds loop-bound injection protections, the same SHA as GHSA-WXRR. Fix is the same evaluator/evaluation IDOR commit. Deeper blame attributed zero AI lines. evaluations/index.ts overlap is routing, not evaluation mass-assignment origin.

### 18 GHSA-92VJ-HP7M-GWCJ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `AArnott/Nerdbank.MessagePack`
- Rank: 648
- Summary: Nerdbank.MessagePack has Inefficient CPU Computation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI c6a017c3 adds PreserveIntegerTypes on WithObjectConverter. Fix is a merge for ExpandoObjectLimits. Deeper blame attributed zero AI lines. OptionalConverters.cs overlap is routing, not ExpandoObject CPU-limit origin.

### 19 GHSA-25GX-X37C-7PPH — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `openclaw/openclaw`
- Rank: 649
- Summary: OpenClaw's andbox browser noVNC observer lacked VNC authentication
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI cc3c25e4 applies oxfmt 0.32.0 whitespace, the same SHA already reviewed for GHSA-43X4. Fix requires noVNC observer password auth. Deeper blame attributed zero AI lines. Two-line formatter overlap in browser.ts is not noVNC-auth origin.

### 20 GHSA-MQ5J-PW29-JCV3 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `microsoft/apm`
- Rank: 650
- Summary: Microsoft APM: Windows absolute-path tar member overwrite during legacy-bundle probing in `apm install`
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI 491c9da0 is a target-agnostic local-bundle install. Fix validates Windows absolute tar members before extractall. Deeper blame attributed three lines to different SHAs 1162240a and 6250f1cf, not the ranked commit. Shared file without mechanism equality is not legacy-bundle tar-overwrite origin.

### 21 GHSA-M5Q2-4FM3-VFQP — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `patriksimek/vm2`
- Rank: 651
- Summary: vm2 has a sandbox escape via unblocked cross-realm Symbol.for keys + missing bridge write-trap symbol checks
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 093494c0 is the same GHSA-248r sandbox patch as GHSA-76W7. Fix closes cross-realm Symbol.for plus bridge write-trap leak. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not Symbol.for origin.

### 22 GHSA-HGV7-V322-MMGR — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `sveltejs/kit`
- Rank: 652
- Summary: @sveltejs/kit: `query.batch` cross-talk
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b2c5d029 supports multiple cookies with the same name across paths and domains. Fix is a merge-from-fork against query.batch cross-talk. Deeper blame attributed zero AI lines. respond.js overlap is routing, not query.batch origin.

### 23 GHSA-8MC6-XJPR-H98X — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `lin-snow/Ech0`
- Rank: 653
- Summary: Ech0 has Server-Side Request Forgery (SSRF) via Connect Handler fetchPeerConnectInfo
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 0beda9be extracts an internal/version package and injects build metadata. Fix blocks SSRF in peer info fetch. Deeper blame attributed zero AI lines. connect.go overlap is routing, not fetchPeerConnectInfo origin.

### 24 GHSA-VXRR-W42W-W76G — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `flightphp/core`
- Rank: 654
- Summary: Flight: HTTP method override enabled by default, facilitating CSRF escalation and middleware bypass
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 82daf71d is the same Request.php review commit as GHSA-XWQR and GHSA-QRCH. Fix is the same security-fixes merge. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not default method-override origin.

### 25 GHSA-WXRR-JP8M-QQ7F — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `FlowiseAI/Flowise`
- Rank: 655
- Summary: FlowiseAI: Evaluator create+update mass-assignment allows cross-workspace evaluator takeover
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6a63dbbf is the same loop-bound protection commit as GHSA-MQ53. Fix is the same evaluator/evaluation IDOR commit. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not evaluator mass-assignment origin.

### 26 GHSA-FP53-QCF8-2XX2 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `bugsink/bugsink`
- Rank: 656
- Summary: Bunsink has an SSRF bypass in `validate_webhook_url`
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b564774f adds Slack alert failure-tracking fields. Author is copilot-swe-agent. Fix is a merge-from-fork against webhook URL parser mismatch. Deeper blame attributed zero AI lines. alerts/tests.py overlap is routing, not validate_webhook_url origin.

### 27 GHSA-HM49-WCQC-G2XG — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `ruby/net-imap`
- Rank: 657
- Summary: net-imap vulnerable to command Injection via "raw" arguments to multiple commands
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 6229814f is the same one-line JRuby SSLContext change as GHSA-VCGP. Fix validates setquota storage limits. Deeper blame attributed zero AI lines. imap.rb overlap is routing, not raw-argument command-injection origin.

### 28 GHSA-GHCM-XQFW-Q4VR — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `mermaid-js/mermaid`
- Rank: 658
- Summary: Mermaid: Improper sanitization of `classDef` in state diagrams leads to HTML injection
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 2773d93c reverts a diagramId centralization refactor. Fix creates CSS styles using the CSSOM. Deeper blame attributed zero AI lines. types.ts overlap is routing, not state-diagram classDef origin.

### 29 GHSA-JH37-X3FV-4X72 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `subzeroid/aiograpi`
- Rank: 659
- Summary: aiograpi: Unsafe signup challenge path handling
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 65097735 ports signup mixins from instagrapi. Parent already concatenated unsanitized data['api_path'] into i.instagram.com URLs. Fix adds _safe_challenge_api_path. Deeper blame attributed one unrelated sn_result line. Preserving the old challenge-path concatenation is not origin.

### 30 GHSA-Q3FM-4WCW-G57X — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `patriksimek/vm2`
- Rank: 660
- Summary: vm2 setup-sandbox.js violates Defense Invariant #11 in stack-trace formatter
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 093494c0 is the same GHSA-248r sandbox patch as GHSA-76W7. Fix closes Defense Invariant #11 in the stack-trace formatter. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not stack-trace-formatter origin.

## Conservation

- rank_pool 3473 = 630 prior directroot reviews + 30 this slice + 170 unreviewed hits + 2643 rank misses
- hits 830; unique ranked identities assigned through batch21: 630; this slice 631-660
- Incoming unreviewed hits before this slice: 200; after: 170
- Stale 260813 batch3 equals formal 260814 batch3 (30 IDs) and is not 30 extra reviewed rows
- Unreviewed remaining IDs are UNREVIEWED, not REJECT
- Checkpoint at 75 percent recorded before the final seven rows, then the assigned slice was exhausted

## Hold

Worker PASS is proposal only. This slice proposes zero acceptances. Publication and more-than-200 remain HOLD. Four deeper-blame hits remain non-origin: GHSA-7RX4 moved a pre-existing metascraper plugin; GHSA-GQ5C blamed a comment beside a 2023 XSS sink; GHSA-MQ5J blamed different SHAs than the ranked candidate; GHSA-JH37 preserved parent challenge-path concatenation.
