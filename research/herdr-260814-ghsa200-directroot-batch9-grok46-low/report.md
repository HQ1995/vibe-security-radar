# Direct-root mining batch 9 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly the next 30 highest-score unassigned rank hits after canonical73 plus directroot batches 1-8, including the frozen in-progress batch8 selection. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed rank hits: 560
- PASS proposals: 3 (uncounted)
- REJECT: 27
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 240+30+560+2643=3473 rank_pool

## Selection

Frozen `rank-hits.jsonl` file order, stable sort by numeric score tuple descending (equals original ranks 1-830 unique). Excluded every GHSA in canonical73 strict IDs and in batch1 through batch8 selected-30/cases artifacts, including frozen batch8 `work/selected-30.jsonl`. Overlap with each excluded set is zero. Assigned original ranks 241-270. Selection recorded in `work/selected-30.jsonl` before review.

## Method

Each row used the frozen github-reviewed advisory JSON, the ranked AI SHA and fix SHA, first-parent `git log`/`diff`, and deeper `git blame -l -w` of source deleted hunks on the fix parent against the AI-commit index. Remaining vulnerable lines on the fix parent were blamed when deleted-hunk blame was zero. File-history overlap without hunk identity remains routing. Incomplete-remediation security attempts stay out of this lane unless all patch-delta clauses pass. Shared SHAs without mechanism equality are rejected.

## Proposed PASS (uncounted)

### GHSA-X4HG-HFWF-P9MW — PASS `AI_DIRECT_ROOT`

Claude-marked single-parent `f8ee181b` introduces `HTMLInputElement.checkValidity` constructing `new RegExp` from the user-controlled `pattern` property. Closer `25a3cbac` adds nested-quantifier and length guards on the same hunk. Vulnerable package.json 0.0.21 (`7cd2413`) contains the AI commit and not the closer; 0.0.22 (`00dc8ad`) contains the closer.

### GHSA-322X-V876-G883 — PASS `AI_DIRECT_ROOT`

Claude-marked single-parent `ed0124d3` introduces `matchFileSnapshot` writing caller-controlled paths with no root prefix check. Closer `785e6ac6` adds the prefix check on the same function. Same 0.0.21/0.0.22 containment as X4HG. Distinct SHA and mechanism from X4HG.

### GHSA-6R28-9PPF-4HJ5 — PASS `AI_DIRECT_ROOT`

Copilot-marked single-parent `fe11a243` creates `layers/diameter_avp_decoders.go`. Blame of `dataLength := avp.Length - uint32(headerSize)` on the fix parent is that SHA. Closer `145859d0` inserts a `Length < headerSize` guard. Tag `v1.6.0` contains the AI commit and not the closer; `v1.6.1` contains the closer.

## Rejected cases

### 01 GHSA-GCG5-86JR-F7JG — REJECT `SIBLING_FIX`

- Repository: `WeblateOrg/weblate`
- Rank: 241
- Summary: Weblate Vulnerable to Private Translation Enumeration via Screenshot API
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a229da5b lets users modify own notifications (same SHA as batch7 GHSA-VJ45). Fix 6cf892c7 uses user-accessible filters on screenshot params. Deeper blame attributed zero AI lines. Notification ACL is a sibling surface, not origin of screenshot enumeration.

### 02 GHSA-GG2G-P7XC-QQMM — REJECT `OLD_BUG_REFACTOR`

- Repository: `oscal-compass/compliance-trestle`
- Rank: 242
- Summary: compliance-trestle Vulnerable to Remote Code Execution via Recursive Server-Side Template Injection (SSTI)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f85944cf migrates the hatch build. Deeper blame attributed two lines in trestle/core/commands/author/jinja.py. Fix 247fcce2 is a merge-from-fork of the SSTI closer. Hatch migration is not but-for origin of recursive jinja evaluation.

### 03 GHSA-482J-2PQ6-Q5W4 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `open-webui/open-webui`
- Rank: 243
- Summary: Open WebUI: Jupyter code execution works despite ENABLE_CODE_EXECUTION=false
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 823b9a6d removes old SRC log env vars. Fix 6d736d3c is labeled refac. Deeper blame attributed zero AI lines. Log-env chore is routing, not origin of the Jupyter feature gate.

### 04 GHSA-GFM2-XM6C-37QC — REJECT `SIBLING_FIX`

- Repository: `open-webui/open-webui`
- Rank: 244
- Summary: Open WebUI has Broken Access Control for Completions API
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e7ff4768 adds ownership checks to global task endpoints. Fix cf4218e6 is labeled refac. Deeper blame attributed zero AI lines. Task-endpoint ACL is a sibling surface, not origin of Completions API authorization.

### 05 GHSA-P64J-F4X9-WQ66 — REJECT `COMMIT_ONLY_CHANGE`

- Repository: `lin-snow/Ech0`
- Rank: 245
- Summary: Ech0's OAuth redirect URI validation ignores path component, enables exchange-code theft
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 2a5b03a7 prepends SPDX/Copyright headers. Fix a7e8b8e8 requires exact OAuth redirect URI matching. Deeper blame attributed zero AI lines. Header-only change is not origin of RFC 6749 path-component bypass.

### 06 GHSA-M77W-P5JJ-XMHG — REJECT `SIBLING_FIX`

- Repository: `Gitlawb/openclaude`
- Rank: 246
- Summary: OpenClaude Sandbox Bypass via Model-Controlled dangerouslyDisableSandbox Input
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f3a984dd handles null shell output. Fix aab48905 requires trusted approval for sandbox override. Deeper blame attributed zero AI lines. Null-output handling is not origin of model-controlled sandbox disable.

### 07 GHSA-MJ4X-VF5C-5XG8 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `oscal-compass/compliance-trestle`
- Rank: 247
- Summary: compliance-trestle Profile Import has an Arbitrary File Read via trestle:// URI and Relative Path Traversal
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked hatch-migration SHA f85944cf as GHSA-GG2G. Fix 5c65c592 adds path-traversal and SSRF controls on remote cache. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not a second origin.

### 08 GHSA-RQV2-M695-F8J4 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `modelcontextprotocol/registry`
- Rank: 248
- Summary: MCP Registry vulnerable to stored XSS in catalogue UI via websiteUrl
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b58836c4 adds LocalTransport/RemoteTransport URL templates. Fix 78b7bbde rejects HTML metacharacters in websiteUrl. Deeper blame attributed zero AI lines. Transport templates are not origin of catalogue XSS.

### 09 GHSA-2RC4-7JC6-QFFH — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `fleetdm/fleet`
- Rank: 249
- Summary: Fleet has a Windows MDM management endpoint authentication bypass
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5bf82e29 adds device_status fields to /hosts API. Fix 3ff8119a is Windows MDM app-level impl. Deeper blame attributed zero AI lines. Hosts API fields are not origin of MDM auth bypass.

### 10 GHSA-3775-99MW-8RP4 — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `argoproj/argo-workflows`
- Rank: 250
- Summary: Argo incomplete fix for CVE-2026-31892: hostNetwork, securityContext, serviceAccountName bypass
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: First-party summary labels incomplete remediation. Ranked AI 97635e65 improves linting. Fix 2727f3f7 is a merge-from-fork. Deeper blame attributed zero AI lines. Linting is not a proved patch-delta rewrite of the templateReferencing boundary.

### 11 GHSA-WPXJ-44W3-2J6X — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `nautobot/nautobot`
- Rank: 251
- Summary: Nautobot: REST API permits creation of GenericForeignKey references the user should not reference
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI ac10784e adds wireless models. Fix 36cde714 is a merge-from-fork. Deeper blame attributed zero AI lines. Wireless-model feature is not origin of GenericForeignKey authorization.

### 12 GHSA-93RG-2XM5-2P9V — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 252
- Summary: OpenClaw's Gateway Control UI bootstrap config required Gateway auth
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 3e9c8721 lets non-GET requests fall through controlUi routing when basePath is set (same SHA as batch7 GHSA-V8QF). Fix 2321d672 requires auth for bootstrap config. Deeper blame attributed zero AI lines. Control-UI routing is not origin of bootstrap-config auth.

### 13 GHSA-GW2X-Q739-QHCR — REJECT `ROUTING_ONLY`

- Repository: `rustfs/rustfs`
- Rank: 253
- Summary: RustFS gRPC GetMetrics deserialization panic enables remote DoS
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 29c004d9 separates the console service. Advisory names rustfs/src/storage/tonic_service.rs unwrap on GetMetrics. Deeper blame attributed 61 AI-index lines in console/config/auth helpers, not the gRPC handler. Console separation is not but-for origin of GetMetrics panic.

### 14 GHSA-333V-68XH-8MMQ — REJECT `SIBLING_FIX`

- Repository: `rustfs/rustfs`
- Rank: 254
- Summary: RustFS's RPC signature verification logs shared secret
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Ranked AI eb33e82b is the GetMetrics panic closer from GHSA-GW2X. Fix 6b2eebee removes secret and signature from logs. Deeper blame attributed four lines in rustfs/src/config/mod.rs. A later sibling security commit is not origin of secret logging.

### 15 GHSA-2MMV-7RRP-G8XH — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `WeblateOrg/wlc`
- Rank: 255
- Summary: Weblate command-line client susceptible to SSL verification skip
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI f30eea7d improves error reporting for Weblate 5.10. Fix a513864e avoids startswith for SSL configuration. Deeper blame attributed zero AI lines. Error-reporting feature is not origin of SSL skip.

### 16 GHSA-CV78-6M8Q-PH82 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `argoproj/argo-workflows`
- Rank: 256
- Summary: Argo Workflows affected by stored XSS in the artifact directory listing
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked linting SHA 97635e65 as GHSA-3775. Fix 159a5c56 hardens artifact directory listings. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not a second origin.

### 17 GHSA-H4RM-MM56-XF63 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `trailofbits/fickling`
- Rank: 257
- Summary: Fickling vulnerable to detection bypass due to builtins blindness
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4b09a898 modernizes the uv/ruff build. Fix 9f309ab8 emits AST nodes for builtins imports. Deeper blame attributed one line from a different SHA 5e054ddc, not the ranked commit. Build-tooling is not origin of builtins blindness.

### 18 GHSA-F283-GHQC-FG79 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `guzzle/guzzle`
- Rank: 258
- Summary: Guzzle: Unbounded response cookies risk denial of service
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fb92d95f updates CI, PHPStan, and removes Psalm. Fix 7b68220d is Security fixes 7.15. Deeper blame attributed zero AI lines. CI/tooling is not origin of unbounded cookies.

### 19 GHSA-CWJ3-VQPP-PMXR — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `openclaw/openclaw`
- Rank: 259
- Summary: OpenClaw's gateway config mutation guard allowed unsafe model-driven config writes
- Failing gates: ai_hunk_gate, but_for_gate, release_gate
- Counterevidence: Ranked AI 29f20624 adds a dangerous-flag set-diff beside a pre-existing protected-path denylist. Advisory residual is schema growth past that denylist. Fix bceda608 replaces the denylist with an allowlist. Patch-delta fails: the omitted paths are the untouched pre-AI denylist sibling, not an omitted case in the AI-added flag enumerator. No git tags contain the AI or fix SHAs.

### 22 GHSA-RJVX-X5H2-6PX5 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `go-gitea/gitea`
- Rank: 262
- Summary: Gitea: API Fork Endpoint Authorization Bypass Allows Organization Members to Bypass Repository Creation Restrictions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI db7eb4d5 fixes issue label deletion with Actions tokens. Fix 686d10b7 fixes forking in an organization. Deeper blame attributed zero AI lines. Label-deletion is a sibling API, not origin of fork authorization.

### 23 GHSA-5QJJ-4XWW-7PHC — REJECT `SIBLING_FIX`

- Repository: `open-circle/valibot`
- Rank: 263
- Summary: Valibot: record() issue paths can make flatten() throw for inherited Object property names
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI b16fdf9b fixes intersect with frozen objects. Fix 1bd01c30 handles Object.prototype key collisions in flatten and merge. Deeper blame attributed zero AI lines. Frozen-object intersect is not origin of flatten prototype collisions.

### 24 GHSA-RGV6-XP99-6MGJ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `go-gitea/gitea`
- Rank: 264
- Summary: Gitea Remember-Me Token Theft Not Invalidating Attacker Session
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 18762c77 batch-loads related data in actions run/job/task APIs. Fix de4b8277 is various security fixes. Deeper blame attributed six lines in permission/oauth/api context files, not remember-me invalidation. Actions batch-load is not origin of remember-me session theft.

### 25 GHSA-W6P7-2FXX-4F44 — REJECT `SIBLING_FIX`

- Repository: `pocket-id/pocket-id`
- Rank: 265
- Summary: Pocket ID: OIDC refresh token flow bypasses authorization revocation, account disabling, and group restrictions
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 59fe481a adds OIDC prompt parameter handling and is the immediate parent of fix 978ac87d. Deeper blame of deleted source hunks attributed zero AI lines. Prompt handling rewrites Authorize(), not createTokenFromRefreshToken re-validation. Immediate parent without blamed hunk identity is routing.

### 26 GHSA-H8FP-F39C-Q6MH — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `remix-run/react-router`
- Rank: 266
- Summary: React Router: RSCErrorHandler Missing Protocol Validation (XSS)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 7e6725a4 cleans up lint issues. Fix ce596e82 validates RSC redirect protocols. Deeper blame attributed zero AI lines. Lint cleanup is not origin of RSC protocol XSS.

### 27 GHSA-6HM7-3PWJ-22RM — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `go-gitea/gitea`
- Rank: 267
- Summary: Gitea: Denial of Service via O(N^2) String Concatenation in Debian Package Upload
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked SHA 18762c77 and same fix de4b8277 as GHSA-RGV6. Deeper blame attributed the same six unrelated context/oauth lines. Shared SHA/fix without mechanism equality is not a second origin.

### 28 GHSA-7RW5-9F7Q-XJ36 — REJECT `SHA_SHARE_WITHOUT_MECHANISM_EQUALITY`

- Repository: `open-webui/open-webui`
- Rank: 268
- Summary: Open WebUI: Account enumeration via observable login timing discrepancy
- Failing gates: ai_hunk_gate, but_for_gate, topology_gate
- Counterevidence: Same ranked log-env SHA 823b9a6d as GHSA-482J. Fix 993e7491 is labeled refac. Deeper blame attributed zero AI lines. Shared SHA without mechanism equality is not a second origin.

### 29 GHSA-HVRM-45R6-MJFJ — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `honojs/hono`
- Rank: 269
- Summary: hono/jsx does not isolate context per request, leading to cross-request data disclosure
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI bfba97ca normalizes SVG attributes on the svg root. Fix fab3b136 is a merge-from-fork. Deeper blame attributed zero AI lines. SVG attribute normalization is not origin of request-context isolation.

## Conservation

- rank_pool 3473 = 240 prior directroot reviews (batches 1-8) + 30 this slice + 560 unreviewed hits + 2643 rank misses
- hits 830; incoming unreviewed hits before this slice: 590; after: 560
- Unreviewed remaining IDs are UNREVIEWED, not REJECT

## Hold

Worker PASS is proposal only. This slice proposes three uncounted acceptances. Publication and more-than-200 remain HOLD. Canonical ledgers were not edited.
