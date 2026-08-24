# Direct-root mining batch 6 (frozen assigned 30)

**Status: `TERMINAL`.** Worker PASS is a proposal only. Publication and a more-than-200 claim remain **HOLD**. This packet reviews exactly 30 assigned first-party GHSA identities from the frozen 770 unreviewed rank hits after canonical exclusion and the first 60 deep reviews. It does not rerank and does not verdict any other hit.

## Verdict

- Assigned: 30
- Reviewed: 30
- Remaining unreviewed of the incoming 770: 740
- PASS proposals: 0
- REJECT: 30
- NARROW / UNKNOWN / BLOCKED: 0
- Conservation: assigned=reviewed=30; 60+30+740+2643=3473 rank_pool

## Method

Each row used the frozen github-reviewed advisory JSON, the ranked AI SHA and fix SHA from `rank-hits.jsonl`, first-parent `git log`/`diff`, and deeper `git blame -l -w` of source deleted hunks on the fix parent against the AI-commit index. File-history overlap without blamed deleted lines remains routing. Incomplete-remediation security attempts stay out of this direct-root lane.

## Cases

### 01 GHSA-G5H5-M4HM-XJRR — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `zitadel/zitadel`
- Rank: 137
- Summary: ZITADEL: Missing Token Audience Validation (aud) in JWT IdP Provider
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked Claude commit 7a41fe96 is PostgreSQL 18 setup compatibility. Fix d184e976 is a merge-from-fork of JWT audience validation. Deeper blame of deleted source hunks attributed zero AI-marked lines. Setup overlap is routing, not origin of missing aud checks.

### 02 GHSA-6PR9-RP53-2PMC — REJECT `REFACTOR_OLD_BUG`

- Repository: `vllm-project/vllm`
- Rank: 141
- Summary: vLLM: OOM Denial of Service via Audio Decompression Bomb
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 153ba7f0 is a librosa dependency drop. Fix 1b1359c3 adds decompression-bomb limits on the speech-to-text path. Deeper blame of deleted hunks attributed zero AI lines. Refactor of an old audio decoder is not but-for origin of unbounded decode.

### 03 GHSA-C54G-XJWJ-8G82 — REJECT `SIBLING_SECURITY_ATTEMPT`

- Repository: `gohugoio/hugo`
- Rank: 146
- Summary: Hugo: XSS via text/html content files
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 454450a6 restricts default http.urls '@' deny to userinfo (security attempt on a sibling URL allowlist). Fix e41a0644 disallows HTML content by default. Deeper blame of deleted hunks attributed zero AI lines. Incomplete/sibling security rewrite is out of this direct-root lane and is not hunk identity for HTML XSS.

### 04 GHSA-CG7W-RG45-PC59 — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `pydantic/pydantic-ai`
- Rank: 150
- Summary: pydantic-ai: SSRF blocklist bypass via IPv6 transition forms (incomplete fix of CVE-2026-46678)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: First-party advisory labels an incomplete prior SSRF fix. Ranked AI 06c1ea4a replaces an HTTP client cache. Fix 1add0617 expands IPv6 transition-form handling in _ssrf.py. Deeper blame attributed zero AI lines. AI_INCOMPLETE_REMEDIATION is out of this direct-root lane and is not proved by hunk identity here.

### 05 GHSA-248M-82V9-Q6G6 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `py-pdf/pypdf`
- Rank: 151
- Summary: pypdf: long runtimes for zero-only width values in cross-reference streams
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 4d8ebcec fixes a stale object-stream cache. Fix 507d7c9a disallows zero-only xref widths. Deeper blame attributed zero AI lines. Same-file history without deleted-hunk identity is routing. Same ranked SHA as GHSA-JJ6C is not two origins.

### 06 GHSA-9GGV-8W38-R7PM — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `typeorm/typeorm`
- Rank: 152
- Summary: TypeORM: SQL Injection in UpdateQueryBuilder/SoftDeleteQueryBuilder orderBy
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 46d5b843 scopes invalidWhereValuesBehavior to high-level abstractions (security attempt). Fix 93eec630 validates orderBy at runtime. Deeper blame attributed zero AI lines. Residual orderBy injection is incomplete-remediation / sibling path, not AI_DIRECT_ROOT hunk proof.

### 07 GHSA-W6J9-VW59-27WV — REJECT `SIBLING_FIX`

- Repository: `gogs/gogs`
- Rank: 155
- Summary: Gogs Authentication Bypass via Unvalidated Reverse Proxy Headers
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 81ee8836 verifies LFS content hashes. Fix 0089c4c8 trusts reverse-proxy auth headers only from configured proxies. File overlap on internal/conf is routing. Deeper blame attributed zero AI lines. Sibling LFS hardening is not origin of proxy-header auth.

### 08 GHSA-4565-R4X7-HG8J — REJECT `REFACTOR_OLD_BUG`

- Repository: `gogs/gogs`
- Rank: 160
- Summary: Gogs Privilege Escalation via Collaboration Access Mode Validation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI a1fa62b2 decouples API types from go-gogs-client. Fix 1fdc9cc2 bounds collaboration access by min(actor, admin). Deeper blame attributed zero AI lines. SDK refactor is not the introducing hunk.

### 09 GHSA-XXHQ-69MF-W8CR — REJECT `REFACTOR_OLD_BUG`

- Repository: `gogs/gogs`
- Rank: 162
- Summary: Gogs Open Redirect via redirect_to
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 36d56d55 renames *util packages to *x. Fix c5da9631 hardens same-site URL checks. Deeper blame attributed zero AI lines. Package rename is not origin of the redirect bypass.

### 10 GHSA-J93G-RP6M-J32M — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `Basekick-Labs/arc`
- Rank: 165
- Summary: Arc: Unauthenticated Go pprof endpoints
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 82fc0806 adds host/address bind support. Fix 32a4091f gates pprof behind ARC_DEBUG_PPROF on localhost. Deeper blame attributed zero AI lines. Bind-address feature overlap is not but-for authorship of the unauthenticated pprof listener.

### 11 GHSA-QRPV-Q767-XQQ2 — REJECT `WRONG_EDGE`

- Repository: `langflow-ai/langflow`
- Rank: 171
- Summary: Langflow IDOR in /api/v1/responses get_flow_by_id_or_endpoint_name
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 8d01ba42 adds a flag to block custom component execution. Fix 2c9f498d closes IDOR on get_flow_by_id_or_endpoint_name. Deeper blame attributed zero AI lines. Unrelated execution flag is not the IDOR hunk.

### 12 GHSA-2P9H-RQJW-GM92 — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `n8n-io/n8n`
- Rank: 180
- Summary: n8n Stored XSS via Various Nodes
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI d4ef191b is itself an XSS-prevention attempt on Chat Trigger templates. Fix 062644ef is a weekly bundle. Deeper blame attributed zero AI lines. Security-attempt plus later residual XSS is incomplete-remediation / sibling, not AI_DIRECT_ROOT hunk identity.

### 13 GHSA-246W-JGMQ-88FG — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `jkroepke/openvpn-auth-oauth2`
- Rank: 184
- Summary: openvpn-auth-oauth2 returns FUNC_SUCCESS on client-deny
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI e9d1f6af is chore plugin fixes. Fix 36f69a6c changes client-deny to not return FUNC_SUCCESS. Deeper blame attributed zero AI lines. Subject/file-history routing is not origin of the deny-success invariant.

### 14 GHSA-GX2M-MCC2-R4P3 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `WeblateOrg/wlc`
- Rank: 185
- Summary: wlc: print_html outputs API data without HTML escaping
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 5795beae adds unit-level CLI commands. Fix 0f3e58f6 escapes generated HTML. Deeper blame attributed zero AI lines. New CLI surface without blamed deleted hunks is not proved as but-for origin of unescaped print_html.

### 15 GHSA-C65F-X25W-62JV — REJECT `WEAK_PACKAGE_MAPPING`

- Repository: `jahlives/openssl_encrypt`
- Rank: 191
- Summary: openssl-encrypt CORS wildcard with allow_credentials=True in standalone servers
- Failing gates: release_gate
- Counterevidence: Ranked AI 57e618d3 removes hardcoded database credentials (different GHSA). Deeper blame of the CORS default lines hits Claude-marked first-add commits fafdfeed (key-server) and 4c7ae852 (telemetry-server): parent trees lack those config files, and fix 809416b7 flips cors_origins from ['*'] to []. That hunk identity is real in git. First-party affected package is PyPI openssl-encrypt; sdists 1.4.0b8 and 1.4.0 ship openssl_encrypt_server with an already-empty CORS default and do not ship server/key-server or server/telemetry-server. Advisory introduced:0 / fixed:1.4.0 therefore does not contain the named standalone servers. Weak package mapping fails release_gate. Not countable AI_DIRECT_ROOT.

### 16 GHSA-PJJW-68HJ-V9MW — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `astral-sh/uv`
- Rank: 196
- Summary: uv arbitrary file deletion through RECORD entries
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI uses #[expect(clippy::...)] throughout. Fix refuses to delete files outside the venv on uninstall. Deeper blame of deleted hunks attributed zero AI lines. Lint-only commit is not origin of RECORD path deletion.

### 17 GHSA-5GJC-GRVM-M88J — REJECT `WRONG_EDGE`

- Repository: `openclaw/openclaw`
- Rank: 197
- Summary: OpenClaw: Memory dreaming config persistence reachable from operator.write
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI persists webchat inbound images. Fix requires admin for persistent gateway dreaming toggle. Deeper blame attributed zero AI lines. Image-persist feature is not the dreaming-config authorization hunk.

### 18 GHSA-FH32-73R9-RGH5 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 207
- Summary: OpenClaw: Trailing-dot localhost CDP hosts could bypass remote loopback protections
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI uses LAN IP for WebSocket/probe URLs when bind=lan. Fix normalizes localhost absolute-form CDP hosts. Deeper blame attributed zero AI lines. LAN bind helper is not origin of trailing-dot localhost classification.

### 19 GHSA-5R8F-96GM-5J6G — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 208
- Summary: OpenClaw Gateway operator.write can reach admin-only session reset via chat.send /reset
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI prevents stale threadId leaking into non-thread sessions. Fix aligns chat.send reset scope checks. Deeper blame attributed zero AI lines. Thread-id hygiene is not origin of operator.write /reset privilege.

### 20 GHSA-JJ6C-8H6C-HPPX — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `py-pdf/pypdf`
- Rank: 210
- Summary: pypdf long runtimes for wrong size values in xref and object streams
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Same ranked AI 4d8ebcec (stale object-stream cache) as GHSA-248M. Fix 3733-range limits xref/object stream sizes. Deeper blame attributed zero AI lines. Shared SHA is not two origins; neither has deleted-hunk identity.

### 21 GHSA-HPPC-G8H3-XHP3 — REJECT `SIBLING_FIX`

- Repository: `rust-openssl/rust-openssl`
- Rank: 212
- Summary: rust-openssl unchecked callback length in PSK/cookie trampolines
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI fixes a dangling stack pointer in a custom extension add callback. Fix validates callback-returned lengths in PSK/cookie trampolines. Deeper blame attributed zero AI lines. Sibling callback memory bug, not the named PSK/cookie length leak.

### 22 GHSA-HV99-MXM5-Q397 — REJECT `REFACTOR_OLD_BUG`

- Repository: `WeblateOrg/weblate`
- Rank: 214
- Summary: Weblate: Arbitrary File Read via Symlink
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI formalizes addons cache as AddonCache. Fix tightens symlink validation on components. Deeper blame attributed zero AI lines. Addon-cache refactor is not origin of symlink file read.

### 23 GHSA-HR8G-2Q7X-3F4W — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 216
- Summary: OpenClaw Gateway Control Interface Information Disclosure
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI lets non-GET requests fall through controlUi routing when basePath is set. Fix trims control UI bootstrap payload. Deeper blame attributed zero AI lines. Routing fall-through is not proved as origin of the bootstrap disclosure.

### 24 GHSA-3J8V-CGW4-2G6Q — REJECT `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE`

- Repository: `nearform/fast-jwt`
- Rank: 217
- Summary: fast-jwt: Stateful RegExp (/g or /y) causes non-deterministic allowed-claim validation
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI 587-range is a cache-confusion composite-key security attempt. Fix 593-range addresses regex non-deterministic validation. Deeper blame attributed zero AI lines. Same ranked SHA as GHSA-CJW9. Incomplete/sibling JWT validator work, not deleted-hunk origin of stateful /g validation.

### 25 GHSA-JF25-7968-H2H5 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 231
- Summary: OpenClaw: screen_record outPath bypassed workspace-only filesystem guard
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked commit 0954b6bf says Made-with: Cursor but the worker marker regex did not match, and the subject is ephemeral sessionId propagation through hooks. Fix 635bb35b guards nodes tool outPath. Deeper blame attributed zero AI lines. Hook sessionId plumbing is not the screen_record outPath origin. Marker-on-counted-commit still fails hunk identity.

### 26 GHSA-XRWR-FCW6-FMQ8 — REJECT `WRONG_EDGE`

- Repository: `WeblateOrg/weblate`
- Rank: 235
- Summary: Weblate: SSRF via Project-Level Machinery Configuration
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI allows users to modify own notifications. Fix limits allowed machinery URLs. Deeper blame attributed zero AI lines. Notifications API is not the machinery SSRF hunk.

### 27 GHSA-CJW9-GHJ4-FWXF — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `nearform/fast-jwt`
- Rank: 236
- Summary: fast-jwt ReDoS when using RegExp in allowed* during token verification
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Same ranked AI cache-confusion commit as GHSA-3J8V. Fix is the named ReDoS patch. Deeper blame attributed zero AI lines. Shared SHA is not two origins; neither has deleted-hunk identity for ReDoS.

### 28 GHSA-2XCP-X87W-Q377 — REJECT `SIBLING_FIX`

- Repository: `openclaw/openclaw`
- Rank: 237
- Summary: OpenClaw: Hook mapping templates could bypass hook session-key opt-in
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI deprecates query-param hook token auth. Fix enforces allowRequestSessionKey on template-rendered mapping sessionKeys. Deeper blame attributed zero AI lines. Token-auth deprecation is a sibling hook-auth change, not the template sessionKey bypass origin.

### 29 GHSA-CWQ8-6F96-G3Q4 — REJECT `NO_BLAME_HUNK_PROOF`

- Repository: `openclaw/openclaw`
- Rank: 243
- Summary: OpenClaw: Security Scan Failure Does Not Block Plugin Installation (Fail-Open)
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI supports legacy install entry fallback. Fix blocks install when source scan fails. Deeper blame attributed zero AI lines. Legacy-entry fallback is not proved as origin of fail-open scan skip; incomplete-remediation is out of this lane without hunk identity.

### 30 GHSA-P9FF-H696-F583 — REJECT `WRONG_EDGE`

- Repository: `vitejs/vite`
- Rank: 245
- Summary: Vite Arbitrary File Read via Vite Dev Server WebSocket
- Failing gates: ai_hunk_gate, but_for_gate
- Counterevidence: Ranked AI forwards browser console logs to the dev-server terminal. Fix applies server.fs checks to the env transport. Deeper blame attributed zero AI lines. Console-log forwarding is not origin of WebSocket fs bypass.

## C65F note

GHSA-C65F-X25W-62JV is the only row whose deeper blame attributed AI-marked lines (the CORS `['*']` defaults). Those lines are first-adds of standalone FastAPI servers. The named PyPI package does not ship those servers, so `release_gate` fails on weak package mapping. The row stays REJECT.

## Claim boundary

No countable proposal. Leader must independently verify any future PASS. This worker did not edit tracked files, canonical ledgers, or other worker directories, and did not commit or push.
