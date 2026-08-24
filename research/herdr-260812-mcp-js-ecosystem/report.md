# JavaScript/TypeScript MCP, agent, assistant, and automation-tool adjudication

Research window: 2026-08-12 12:18–12:43 America/New_York

Owned output: `/home/hanqing/agents/ai-slop/autoresearch/herdr-260812-mcp-js-ecosystem/`

Checkout snapshot: branch `dev`, commit `6c0d2084fd1240341d6d1b9f9096252490168f0b`
Status: **PARTIAL** because one read-only history query unexpectedly triggered Git auto-packing in an excluded cache clone. The research result itself reached the requested ten-row bound.

## Result first

Ten previously unadjudicated published GitHub advisory identities were examined as twelve mechanism assessments. Two GHSA-only alias classes in `czlonkowski/n8n-mcp` close at publication-grade within the stated causal roles:

- **3 `STRICT_CAUSAL` components**: one session-control/health-disclosure component under GHSA-75HX-XJ24-MQRW, plus API-path and redirect-SSRF components under GHSA-8G7G-HMWM-6RV2.
- **1 released `AI_INCOMPLETE_REMEDIATION` component**: residual mutation-telemetry exposure under GHSA-8G7G-HMWM-6RV2.
- **2 accepted public-ID rows**, not four: GHSA-8G7G's three mechanisms remain one first-party advisory identity.
- **7 `FAIL` controls** and **1 `UNKNOWN` aggregate** remain non-admitted. They are retained because they prevent same-file routing, project names containing “AI,” guarded sibling code, or human remediation from being rewritten as AI causality.

No OpenClaw or Coolify component was adjudicated. One AgenticMail advisory also lists an `@agenticmail/openclaw` package; that package slice was explicitly excluded. No existing accepted or rejected ledger mechanism was redone.

## Counts

| Measure | Count |
|---|---:|
| Published advisory identities reviewed | 10 |
| CVE↔GHSA alias classes | 8 |
| GHSA-only alias classes | 2 |
| Mechanism assessments | 12 |
| `STRICT_CAUSAL` components admitted | 3 |
| `AI_INCOMPLETE_REMEDIATION` components admitted | 1 |
| Public-ID rows admitted after alias dedup | 2 |
| `FAIL` public-ID controls | 7 |
| `UNKNOWN` public-ID controls | 1 |
| OpenClaw/Coolify component rows | 0 |

## Gate used

`STRICT_CAUSAL` requires all of the following: a published, non-withdrawn first-party advisory identity; an exact atomic candidate or recovered PR member with direct AI attribution; a security-relevant direct-parent delta; the same input/sink/invariant reversed by an exact first-party fix; candidate ancestry into a vulnerable release; and fix ancestry into a later released version.

`AI_INCOMPLETE_REMEDIATION` permits a human root cause only when an explicitly AI-attributed security or privacy remediation shipped, left a concrete residual in the same mechanism, and a later first-party fix closed that residual. It is never restated as strict origin.

Routing, same-file overlap, source recovery, advisory census, tests, and release metadata are diagnostic until candidate delta, mechanism reversal, and release containment close. No build or test result was treated as causal evidence.

## Snapshot boundary and input hashes

The shared checkout was intentionally dirty and other agents were live. Local files were frozen by content hash when read; repository evidence was addressed by immutable commit ID. Changes after the listed observation times are outside this shard.

### Prior-adjudication inputs

| Input | SHA-256 / identity |
|---|---|
| Newest consolidated report, `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| Frozen strict summary | `69dd6c35de1455bf9cee88420aed570c576a190a4d143202d01a26cc3d37b81e` |
| Frozen strict ledger | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| Frozen rejected controls | `6264f79e1c74ed8b0511c772ded43fdf9b377b9591bdc3d065011a0e631aa4be` |
| Frozen rejected edges | `139eaa96fc6be47bdb57b6c9d43660580ef4b883709a6dbafb28ba8324af47e6` |
| GitHub Advisory Database clone | git `39d8887723797efc1804585dd06585c9fd751226` |
| Background evidence artifact | `60fd0782205ba6bfaba0b4f216f00780ebc5b745472ef3bb827dcf9dce02c65a` |

The strict baseline describes 200 public IDs / 110 components; the newest report summarizes 125 strict and 48 released incomplete-remediation components after later work. Those sets, their rejected controls, and their exact candidate/fix fingerprints were exclusions, not a candidate pool.

### Advisory records

All ten records came from the local GitHub Advisory Database clone, then their live repository-advisory state was refreshed with `gh api`. Every selected identity was `published` and non-withdrawn at the live check.

| Identity | Alias | Local reviewed-record SHA-256 |
|---|---|---|
| GHSA-75HX-XJ24-MQRW | none | `3e3654a8e685288bcbf83f29e8ed5ecaa8649700a64d34a5472fad6002bb924c` |
| GHSA-8G7G-HMWM-6RV2 | none | `b5206bcac226dae8dbffbd4b3c3f1ee1fcc392c9dcc8f6fcb2f5e6cf99a2edc8` |
| GHSA-63GR-G7JC-V8RG | CVE-2026-50287 | `c8762b87a4d979f45382e66f59ee93c76ff1d33c6bf9b4a735605f07b12b2cb1` |
| GHSA-FQ4X-789W-JG5H | CVE-2026-57495 | `d8907d65d051feca1f40501283f7cbf64c89d6957f59e98533c8aa9729d77aa3` |
| GHSA-HJWC-26PJ-V3PM | CVE-2026-57494 | `12c2933386c3ed03a3cc092af61fea69e1151d368e1dd6edeb9f840e787fcf22` |
| GHSA-WJJV-3MJ2-39HF | CVE-2026-47255 | `18696a9f374446748af6fcc81a4a1c673ec96b383ac7f5eb497de673d476b5bf` |
| GHSA-FJ4G-2P96-Q6M3 | CVE-2026-42856 | `a5a0c46e99acd2017f1077a8076801e42efa16e8d8fee7a84c4ce14955a1f176` |
| GHSA-J3VX-CX2R-PVG8 | CVE-2026-46701 | `06ad2029a7fadeeea6b60a8b2878d5e9e16c79bdfd98135978279779ce7b4dba` |
| GHSA-QWC3-H9MG-4582 | CVE-2026-27595 | `59c9d974d804c80618ce0e412a103b4ca1c7c09ba95c0d1d86f94bddd08f76ec` |
| GHSA-CVWJ-6C9H-JG6V | CVE-2026-27608 | `f5d3ef13687e711f286eefbe2e280987d3231e93f016ad1567805c9195366030` |

### Source repositories and diagnostic routes

| Repository/input | Frozen identity |
|---|---|
| `czlonkowski/n8n-mcp` read-only clone | HEAD `f1e6e5be393f390b0223057906c675d81f938f63` |
| `agenticmail/agenticmail` read-only clone | HEAD `4a0e0f6f590aed435c0f8bc962bbdd488aec4016` |
| `Jovancoding/Network-AI` read-only clone | HEAD `e4fe33569c70dc4a6d3bcac38809ffabe05c52b3` |
| `parse-community/parse-dashboard` read-only clone | HEAD `f0ea977998c8dfd8e1c89b9344eeb9c10c1f9662` |
| AgenticMail same-file routing artifact | SHA-256 `76d8047756da5ac9204415bdab5c30d859535a1f4cfe6a33363f78108f1c0cfe` |
| Network-AI same-file routing artifact | SHA-256 `4b7ebe59ed4f9786c39c8525da85697e8a841d968ec570ae7eb1e220bbb00af3` |

## Novelty and exclusions

Before candidate replay, the ten GHSA IDs and the recovered candidate/fix fingerprints were searched in the newest reports, strict ledger, rejected controls, and rejected edges. The ID scan returned `NEW_BY_ID` for all ten; the fingerprint scan returned no match. “Novel” here means a new exact `(repository, advisory identity, input, sink, invariant, candidate/fix)` adjudication. A generic CWE or vulnerability class is not claimed as novel.

Already adjudicated examples excluded before work include n8n-mcp GHSA-56C3-VFP2-5QQJ, code-index-mcp GHSA-647R-72HF-4VMH, NetLicensing-MCP GHSA-X9VC-9FFQ-P3GJ, magento2-dev-mcp GHSA-XQV9-QR76-HFQ2, mail-mcp-bridge GHSA-2GFJ-FR43-4735, Ruflo GHSA-C4HM-4H84-2CF3, agentic-flow GHSA-VCV2-R9JH-99M5, Dynatrace MCP GHSA-P7W7-4929-VPJ5, and modelcontextprotocol/registry GHSA-R48C-V28R-PF6V. All OpenClaw and Coolify rows and same-mechanism aliases were excluded.

The AgenticMail identities existed in routing artifacts only. Those routes were not completed causal adjudications and are retained below as new FAIL/UNKNOWN controls, not admitted components.

## Row index

| Row | First-party identity / component | Verdict | Released boundary | Public-ID increment |
|---:|---|---|---|---:|
| 1 | GHSA-75HX-XJ24-MQRW — n8n-mcp session/health surface | `STRICT_CAUSAL` | vulnerable through 2.47.5; fixed 2.47.6 | 1 |
| 2 | GHSA-8G7G-HMWM-6RV2 — n8n API paths, redirect SSRF, telemetry residual | 2× `STRICT_CAUSAL`; 1× `AI_INCOMPLETE_REMEDIATION` | vulnerable <2.50.1; fixed 2.50.1 | 1 |
| 3 | GHSA-63GR-G7JC-V8RG — AgenticMail MCP missing authentication | `FAIL human_origin` | `<0.9.27`; fixed 0.9.27 | 0 |
| 4 | GHSA-FQ4X-789W-JG5H — AgenticMail bridge-wake sender authentication | `FAIL wrong_edge/guarded_sibling` | core `<0.9.43`; fixed 0.9.43 | 0 |
| 5 | GHSA-HJWC-26PJ-V3PM — AgenticMail task authorization | `FAIL human_origin` | API `<0.9.64`; fixed 0.9.64 | 0 |
| 6 | GHSA-WJJV-3MJ2-39HF — AgenticMail aggregate storage/relay advisory | `UNKNOWN aggregate_unsplit` | API 0.9.32 / core 0.9.10 | 0 |
| 7 | GHSA-FJ4G-2P96-Q6M3 — Network-AI MCP missing authentication | `FAIL human_origin` | `<=5.1.2`; fixed 5.1.3 | 0 |
| 8 | GHSA-J3VX-CX2R-PVG8 — Network-AI empty secret/CORS residual | `FAIL no_AI_attribution` | `<=5.4.4`; fixed 5.4.5 | 0 |
| 9 | GHSA-QWC3-H9MG-4582 — Parse Dashboard unauthenticated agent endpoint | `FAIL human_origin` | alpha.42–alpha.7; fixed 9.0.0-alpha.8 | 0 |
| 10 | GHSA-CVWJ-6C9H-JG6V — Parse Dashboard cross-app/read-only authorization | `FAIL human_origin` | alpha.42–alpha.7; fixed 9.0.0-alpha.8 | 0 |

## Row-level evidence

### Row 1 — GHSA-75HX-XJ24-MQRW, `n8n-mcp`

**Verdict: publication-grade `STRICT_CAUSAL`, narrowly as a new-surface contributor. Count the GHSA once.**

The live [repository advisory](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-75hx-xj24-mqrw) reported GHSA-only identity, package `n8n-mcp`, vulnerable `<=2.47.5`, patched `2.47.6`, state `published`, and no withdrawal.

- Candidate [`a597ef5a924ebe17a6a202bbb841965f52328032`](https://github.com/czlonkowski/n8n-mcp/commit/a597ef5a924ebe17a6a202bbb841965f52328032), parent `a4053de998595b4321576ad6a908e65590816ee0`, has its own `Generated with Claude Code` marker and Claude co-author trailer.
- Its parent delta turns unauthenticated `GET /mcp` from static discovery into live session dispatch, adds unauthenticated `DELETE /mcp` session termination, and exposes active session IDs/counts on `/health`.
- Exact first-party fix [`ca9d4b3df6419b8338983be98f7940400f78bde3`](https://github.com/czlonkowski/n8n-mcp/commit/ca9d4b3df6419b8338983be98f7940400f78bde3), parent `ff486ea04f0b20460141e5ef2be3d518e1772b80`, applies authentication/rate limiting to GET/DELETE and removes sensitive health metadata. The candidate is its ancestor.
- npm `2.9.1` contains the candidate; npm `2.47.5` has gitHead equal to the fix parent; npm `2.47.6` has gitHead `4b161b6acbf96120492dea2a6af0f9c72a4a633e`, containing the fix.

The claim is not that this candidate created every pre-existing HTTP route. It created the live-session/termination edges and higher-sensitivity health disclosure that the cited fix reversed.

### Row 2 — GHSA-8G7G-HMWM-6RV2, `n8n-mcp`

The live [repository advisory](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-8g7g-hmwm-6rv2) was GHSA-only, published, non-withdrawn, vulnerable `<2.50.1`, and patched in `2.50.1`. Exact first-party fix [`1cfe9c6bddb4b1634e6e23323c18ea35fd196999`](https://github.com/czlonkowski/n8n-mcp/commit/1cfe9c6bddb4b1634e6e23323c18ea35fd196999), parent `fefa2d9b3908f88ebb060cac28af453c612a7668`, is the npm `2.50.1` gitHead. npm `2.50.0` has pre-fix gitHead `1ca40ce2bdf18b8c88cd571074cec3f61471c7eb`.

#### 2A — caller-controlled API path segments

**Verdict: `STRICT_CAUSAL`, direct target-repository integration origin.**

Candidate [`74f05e937fa7d94babe3507510caa17ce17a698c`](https://github.com/czlonkowski/n8n-mcp/commit/74f05e937fa7d94babe3507510caa17ce17a698c), parent `150de3d1c249e518b73d91b8621db2f6a628b1b5`, has direct Claude markers. It adds the n8n management client and caller-controlled `id` interpolation into workflow/execution/credential/tag/data-table URL paths while carrying the n8n API key. The fix creates a bounded `encodeApiPathSegment` and applies it at the affected path parameters. Candidate-bearing releases begin no later than `v2.7.9`; `2.50.1` is the exact fix release.

The commit says it integrated code from another project. The accepted claim is target-repository integration/new-surface origin, not authorship of upstream source.

#### 2B — redirect-following SSRF in form/chat trigger execution

**Verdict: `STRICT_CAUSAL` as a new form/chat surface contributor. Count the mechanism once.**

[PR #460](https://github.com/czlonkowski/n8n-mcp/pull/460) has squash carrier [`33690c5650e680b2c9cfbae75cac81a761742389`](https://github.com/czlonkowski/n8n-mcp/commit/33690c5650e680b2c9cfbae75cac81a761742389), parent `ddf95567591a5b0a56e9df393e368969536fce3e`. Recovered atomic origin member [`3f698cc62d2f820f83713a51fce23f71e9cc4654`](https://github.com/czlonkowski/n8n-mcp/commit/3f698cc62d2f820f83713a51fce23f71e9cc4654) has its own Claude marker and adds form/chat handlers that validate only the initial URL before redirect-following Axios calls. Atomic member [`7d81204aecb58ba09c70497ae643b886f0d9edc4`](https://github.com/czlonkowski/n8n-mcp/commit/7d81204aecb58ba09c70497ae643b886f0d9edc4) also has direct Claude attribution and applies the same incomplete initial-URL guard to the webhook sibling. Fix `1cfe9c6...` adds `maxRedirects: 0` to all three sinks.

npm `2.28.0` has gitHead equal to carrier `33690c5`; carrier-bearing releases continue through `2.50.0`; npm `2.50.1` is the exact fix. The legacy webhook sibling supports the same-mechanism history but is not a second component.

#### 2C — mutation-operation telemetry residual

**Verdict: released `AI_INCOMPLETE_REMEDIATION`; explicitly not strict origin.**

Human member [`61fdd6433a4ae0a404772a0f6a53f928e4606c5e`](https://github.com/czlonkowski/n8n-mcp/commit/61fdd6433a4ae0a404772a0f6a53f928e4606c5e) creates raw mutation telemetry and has no AI marker. Recovered atomic member [`7ac748e73f69bcd3b43d0a321b38d79078013b91`](https://github.com/czlonkowski/n8n-mcp/commit/7ac748e73f69bcd3b43d0a321b38d79078013b91), parent `6719628350972ebdbc347ef4406b029a712c3f24`, has direct Claude markers and explicitly sanitizes before/after workflow copies, but leaves operation diffs, validation objects, and error strings raw in the same record. [PR #419](https://github.com/czlonkowski/n8n-mcp/pull/419) carries the member chain as squash [`99c5907b71a6c3228d345a2f0879cd893f30cd7e`](https://github.com/czlonkowski/n8n-mcp/commit/99c5907b71a6c3228d345a2f0879cd893f30cd7e). Fix `1cfe9c6...` applies a telemetry sanitizer to each residual field.

npm `2.22.16` has gitHead equal to carrier `99c5907`; that partial state shipped and remained through `2.50.0`; `2.50.1` is the exact closure. This supports incomplete remediation only. The human root is preserved.

### Row 3 — GHSA-63GR-G7JC-V8RG / CVE-2026-50287, AgenticMail MCP

**Verdict: `FAIL human_origin / adjacent_ai_only`. Preserve as a negative control.**

The live [repository advisory](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-63gr-g7jc-v8rg) reported `@agenticmail/mcp <0.9.27`, fixed `0.9.27`. Human commit [`bd15a2a26f24624de491d50a6d24a61e160943e3`](https://github.com/agenticmail/agenticmail/commit/bd15a2a26f24624de491d50a6d24a61e160943e3), parent `bf59f4c...`, first adds the Streamable HTTP server without request authentication and has no AI marker. Exact fix [`7d1791da7c8c8bd4e70d7081db48e18ab55f6736`](https://github.com/agenticmail/agenticmail/commit/7d1791da7c8c8bd4e70d7081db48e18ab55f6736) binds loopback by default and requires a bearer token.

npm `@agenticmail/mcp@0.9.26` has gitHead `900e6b9516459c4e0f9bd0ce61751dda847851c3`, containing the origin; `0.9.27` has gitHead equal to the fix. Routed Claude commits overlap later features or shared package/changelog files, not the origin edge.

### Row 4 — GHSA-FQ4X-789W-JG5H / CVE-2026-57495, AgenticMail bridge wake

**Verdict: `FAIL wrong_edge / guarded_sibling`. Preserve as a negative control.**

Human commit [`bb7566013328b4a8a7d946957f925ebedc57b31f`](https://github.com/agenticmail/agenticmail/commit/bb7566013328b4a8a7d946957f925ebedc57b31f), parent `01579df...`, creates privileged bridge-wake session resume without sender authentication and has no AI marker. Claude-coauthored [`05d8598e4583bab88f436e954b470f82ae49bbd5`](https://github.com/agenticmail/agenticmail/commit/05d8598e4583bab88f436e954b470f82ae49bbd5) later adds a distinct operator-query reply hook and correctly verifies its sender. It does not modify bridge wake or the gateway approval-reply sink. Exact fix [`620678c53a179c17272aa442729c3c38e3865345`](https://github.com/agenticmail/agenticmail/commit/620678c53a179c17272aa442729c3c38e3865345) adds sender gates to those vulnerable edges.

The live advisory lists several AgenticMail packages. This row uses only `@agenticmail/core`: npm `0.9.42` gitHead `51aa43e0e8e80fcb5c8c0ae30824c1ef1c9acd80` contains the human origin, and `0.9.43` gitHead equals the fix. The `@agenticmail/openclaw` package slice was excluded and is not counted.

### Row 5 — GHSA-HJWC-26PJ-V3PM / CVE-2026-57494, AgenticMail task authorization

**Verdict: `FAIL human_origin`. Preserve as a negative control.**

Human commits `cf35e22fbfaa99725245505008e9de7a7c71ed02` and `1b1d9ee28754547ec357464b368651baf1402050` create the task route family and capability-style completion endpoint. Later route rewrites `4054b8e...` and `98aef53...` retain missing cross-agent ownership checks; none has a direct AI marker. Exact fix [`d00728567576411ee8ad6e85f32d6472536ec44b`](https://github.com/agenticmail/agenticmail/commit/d00728567576411ee8ad6e85f32d6472536ec44b) adds the ownership check.

The live [advisory](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-hjwc-26pj-v3pm) reported `@agenticmail/api <0.9.64`, fixed `0.9.64`. npm `0.9.63` has gitHead `620678c53a179c17272aa442729c3c38e3865345`, containing both human origins; npm `0.9.64` has gitHead equal to the fix. Same-file Claude routes through package/changelog files are non-causal.

### Row 6 — GHSA-WJJV-3MJ2-39HF / CVE-2026-47255, AgenticMail aggregate

**Verdict: `UNKNOWN aggregate_unsplit`; neither positive nor negative.**

The live [advisory](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-wjjv-3mj2-39hf) aggregates identifier validation, raw-SQL ownership, metadata access, worker secret, SMTP control characters, and TLS verification. It says the security patch branch was private and cites a multi-commit chain (`1408de5`, merge `234b811`, later `6c70c82`, release `8cb053f`). Exact atomic origins for every independent mechanism could not be recovered safely within the bound, so no aggregate-level attribution is made.

Release containment is real: npm `@agenticmail/api@0.9.31` and `@agenticmail/core@0.9.9` share gitHead `c7f82ecbc7981d0f8a7ee6245d5757c064a8daf1`; fixed `api@0.9.32` and `core@0.9.10` share gitHead `8cb053f2307dd77b7736ffa0d7df04b0ccc3272d`. A future pass must split the advisory by mechanism before replaying origins.

### Row 7 — GHSA-FJ4G-2P96-Q6M3 / CVE-2026-42856, Network-AI

**Verdict: `FAIL human_origin / unrelated_ai_route`. Preserve as a negative control.**

The live [repository advisory](https://github.com/Jovancoding/Network-AI/security/advisories/GHSA-fj4g-2p96-q6m3) reported package `network-ai`, vulnerable `<=5.1.2`, fixed `>=5.1.3`, published and non-withdrawn.

- Human candidate `8469edbe2ae204b90fcd964b541706421f186efe`, parent `516c94ad66a37182001a3ddc487bda8805149272`, creates the HTTP/SSE MCP server, defaults CLI and server binding to `0.0.0.0`, and adds no request authentication. Its message has no AI marker.
- Human fix `b23aedbe5383334076abf9aa4f203b2e86d9e680`, parent `7d52091fff3080f9f74ca801e77db64a4b5944df`, adds a bearer secret and changes the default host to loopback. It still explicitly returns authorized when the configured secret is empty.
- npm `4.0.0` gitHead equals the origin; `5.1.2` gitHead equals the fix parent; `5.1.3` gitHead equals the fix.

Same-file/cross-file routing proposed Claude-coauthored `27b549f4d3a16c2a54a382d58b8ad01530f20b5d`, but its delta is only a MiniMax LLM adapter, README, and adapter test. It does not touch the MCP transport, CLI server, authentication, binding, or CORS. This is an explicit non-causal control.

### Row 8 — GHSA-J3VX-CX2R-PVG8 / CVE-2026-46701, Network-AI

**Verdict: `FAIL no_AI_attribution`, while preserving a real human incomplete-remediation chain.**

The live [repository advisory](https://github.com/Jovancoding/Network-AI/security/advisories/GHSA-j3vx-cx2r-pvg8) reported `network-ai <=5.4.4`, fixed `5.4.5`, published and non-withdrawn. The residual is in row 7's same transport family: fix `b23aedbe...` warns but permits non-loopback operation with an empty secret (`if (!secret) return true`) and leaves `Access-Control-Allow-Origin: *`.

Human exact fix `dc5048112283f3f4eb6c06dd2bf5aa93ef9339be`, parent `c12686e181f231cf8d7bcf836a96d78f0f0877ac`, makes SSE mode fail closed when no secret is set and restricts browser CORS to localhost origins. Neither the partial nor complete remediation has a direct AI marker.

npm `5.1.3` gitHead equals the partial fix; `5.4.4` gitHead equals the complete-fix parent; `5.4.5` gitHead equals the complete fix. This is strong released incomplete-remediation evidence, but it is **human**, so it does not qualify as `AI_INCOMPLETE_REMEDIATION`.

### Row 9 — GHSA-QWC3-H9MG-4582 / CVE-2026-27595, Parse Dashboard

**Verdict: `FAIL human_origin_and_fix`. Preserve as a negative control.**

The live [repository advisory](https://github.com/parse-community/parse-dashboard/security/advisories/GHSA-qwc3-h9mg-4582) reported `parse-dashboard >=7.3.0-alpha.42 <=9.0.0-alpha.7`, fixed `9.0.0-alpha.8`, published and non-withdrawn.

Human candidate `32bd6e855c67e3d4aa2fa4d8e8c3e076969486d0`, parent `4717ae67a89dede13002ec36438220dcc5edc8d0`, adds `POST /apps/:appId/agent` and executes database operations using the selected app's master key without an authentication/CSRF middleware chain. Its subject names an “AI agent,” but neither message nor trailer attributes code generation to AI. Project semantics are not authorship evidence.

Human fix `f92a9ef5246d57e51696bd881a15f3b133b2bb50`, parent `8a34c2f0d6af5ad11793f49b9427dad4b26f1b81`, adds authentication and CSRF checks. npm `7.3.0-alpha.42` gitHead `e5cb66ccfcb4f192a18ca23d21f541bad2379aae` contains the origin; `9.0.0-alpha.7` gitHead equals the fix parent; `9.0.0-alpha.8` gitHead `9866a1b2392bfd3c37ee5b196327b45a1773bbee` contains the fix.

### Row 10 — GHSA-CVWJ-6C9H-JG6V / CVE-2026-27608, Parse Dashboard

**Verdict: `FAIL human_origin_and_fix`. Distinct mechanism, shared candidate/fix.**

The live [repository advisory](https://github.com/parse-community/parse-dashboard/security/advisories/GHSA-cvwj-6c9h-jg6v) has the same released interval as row 9 but a distinct authorization invariant. Candidate `32bd6e...` trusts the route's `appId`, supplies the selected app's master key, and accepts caller-supplied write-operation permissions without checking the authenticated user's app membership or read-only role. Human fix `f92a9ef...` restricts access to `appsUserHasAccessTo`, selects `readOnlyMasterKey`, and overrides write permissions for read-only users.

The exact npm containment is the same as row 9. The two rows are not aliases: GHSA-QWC3 is unauthenticated endpoint access; GHSA-CVWJ is authenticated cross-app/read-only privilege escalation. Shared origin and fix do not collapse distinct first-party identities or invariants. Neither qualifies causally because the candidate and fix are human-authored on recovered evidence.

## Alias and component deduplication

1. CVE aliases were normalized into their GHSA identity. The eight CVE-bearing rows remain eight alias classes, not sixteen IDs.
2. GHSA-75HX is one GHSA-only class. Session termination and sensitive health metadata share one candidate/fix and are reported as one bounded component.
3. GHSA-8G7G is one GHSA-only class with three distinct mechanisms. It contributes three component assessments but exactly one public-ID row.
4. Network-AI's two advisories are distinct official identities at two releases, but they form one staged MCP-authentication family. Both are retained as controls; neither increments the accepted component ledger.
5. Parse Dashboard's two CVE/GHSA classes share an origin and a fix but enforce different invariants, so they are separate negative rows rather than aliases.
6. AgenticMail GHSA-WJJV remains aggregate and unsplit. Counting each sentence as a component without atomic lineage would inflate UNKNOWN evidence.
7. Squash carriers `33690c5` and `99c5907` are release/topology witnesses only. Attribution rests on atomic members `3f698cc`, `7d81204`, and `7ac748e`.
8. The `@agenticmail/openclaw` slice of GHSA-FQ4X was excluded. No OpenClaw or Coolify evidence contributes to counts.

## Exact commands and primary sources

Commands were read-only except for writing this owned directory. Pipelines used at most two subprocesses; no repository build, test suite, broad 51,218-unit rerun, clone, or cache write was requested. After the auto-packing incident described below, every local Git command used `-c gc.auto=0`.

```zsh
cd /home/hanqing/agents/ai-slop

# Checkout and frozen prior evidence.
git rev-parse HEAD
git branch --show-current
sha256sum \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/summary.json \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
  autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/rejected.jsonl \
  autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/rejected_edges.jsonl

# Novelty by normalized IDs; exact candidate/fix fingerprints were searched the same way.
ids=(GHSA-75HX-XJ24-MQRW GHSA-8G7G-HMWM-6RV2 \
  GHSA-63GR-G7JC-V8RG GHSA-FQ4X-789W-JG5H \
  GHSA-HJWC-26PJ-V3PM GHSA-WJJV-3MJ2-39HF \
  GHSA-FJ4G-2P96-Q6M3 GHSA-J3VX-CX2R-PVG8 \
  GHSA-QWC3-H9MG-4582 GHSA-CVWJ-6C9H-JG6V)
for id in $ids; do
  rg -l -i "$id" docs \
    autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
    autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/rejected.jsonl \
    autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/rejected_edges.jsonl \
    >/dev/null && print "$id SEEN" || print "$id NEW_BY_ID"
done

# Immutable commit identity, parents, attribution trailers, and exact deltas.
n8n_repo=.ai-slop/cache/cve-analyzer/repos/v2_github.com_n8n-mcp_7f3ec1dcf0d7cdaa7f65f6c0aed32341a5c14c9c95b456fff2c6e355a78931a1
agent_repo=.ai-slop/cache/cve-analyzer/repos/v2_github.com_agenticmail_6f99dfe6a0084582112588e82224a010cafaa5f1b8095765e41aad971196cf49
network_repo=.ai-slop/cache/cve-analyzer/repos/v2_github.com_network-ai_c283df95e8ff6f315dd00b6b1c65ea84071bed5a6c49575c6555d83dc230e850
parse_repo=/home/hanqing/.cache/cve-analyzer/repos/parse-community_parse-dashboard

git -c gc.auto=0 -C "$n8n_repo" show -s \
  --format='%H%n%P%n%an <%ae>%n%aI%n%B' \
  a597ef5a924ebe17a6a202bbb841965f52328032 \
  ca9d4b3df6419b8338983be98f7940400f78bde3 \
  74f05e937fa7d94babe3507510caa17ce17a698c \
  33690c5650e680b2c9cfbae75cac81a761742389 \
  99c5907b71a6c3228d345a2f0879cd893f30cd7e \
  1cfe9c6bddb4b1634e6e23323c18ea35fd196999
git -c gc.auto=0 -C "$n8n_repo" diff a597ef5a^ a597ef5a -- \
  src/http-server-single-session.ts
git -c gc.auto=0 -C "$n8n_repo" diff 74f05e93^ 74f05e93 -- \
  src/services/n8n-api-client.ts
git -c gc.auto=0 -C "$n8n_repo" diff 1cfe9c6b^ 1cfe9c6b -- \
  src/services/n8n-api-client.ts src/triggers/handlers \
  src/telemetry/mutation-tracker.ts src/telemetry/workflow-sanitizer.ts

git -c gc.auto=0 -C "$agent_repo" show -s \
  --format='%H%n%P%n%an <%ae>%n%aI%n%B' \
  bd15a2a26f24624de491d50a6d24a61e160943e3 \
  7d1791da7c8c8bd4e70d7081db48e18ab55f6736 \
  bb7566013328b4a8a7d946957f925ebedc57b31f \
  05d8598e4583bab88f436e954b470f82ae49bbd5 \
  620678c53a179c17272aa442729c3c38e3865345 \
  cf35e22fbfaa99725245505008e9de7a7c71ed02 \
  1b1d9ee28754547ec357464b368651baf1402050 \
  d00728567576411ee8ad6e85f32d6472536ec44b
git -c gc.auto=0 -C "$agent_repo" diff bd15a2a2^ bd15a2a2 -- packages/mcp/src/index.ts
git -c gc.auto=0 -C "$agent_repo" diff bb756601^ bb756601 -- \
  packages/core/src/host-sessions.ts packages/claudecode/src/bridge-wake.ts \
  packages/codex/src/bridge-wake.ts
git -c gc.auto=0 -C "$agent_repo" diff d0072856^ d0072856 -- packages/api/src/routes/tasks.ts

git -c gc.auto=0 -C "$network_repo" show -s \
  --format='%H%n%P%n%an <%ae>%n%aI%n%B' \
  8469edbe2ae204b90fcd964b541706421f186efe \
  b23aedbe5383334076abf9aa4f203b2e86d9e680 \
  dc5048112283f3f4eb6c06dd2bf5aa93ef9339be \
  27b549f4d3a16c2a54a382d58b8ad01530f20b5d
git -c gc.auto=0 -C "$network_repo" diff 8469edbe^ 8469edbe -- \
  bin/mcp-server.ts lib/mcp-transport-sse.ts
git -c gc.auto=0 -C "$network_repo" diff b23aedbe^ b23aedbe -- \
  bin/mcp-server.ts lib/mcp-transport-sse.ts
git -c gc.auto=0 -C "$network_repo" diff dc504811^ dc504811 -- \
  bin/mcp-server.ts lib/mcp-transport-sse.ts

git -c gc.auto=0 -C "$parse_repo" show -s \
  --format='%H%n%P%n%an <%ae>%n%aI%n%B' \
  32bd6e855c67e3d4aa2fa4d8e8c3e076969486d0 \
  f92a9ef5246d57e51696bd881a15f3b133b2bb50
git -c gc.auto=0 -C "$parse_repo" diff 32bd6e85^ 32bd6e85 -- \
  Parse-Dashboard/app.js src/lib/AgentService.js
git -c gc.auto=0 -C "$parse_repo" diff f92a9ef5^ f92a9ef5 -- \
  Parse-Dashboard/app.js src/lib/tests/AgentAuth.test.js

# Representative ancestry checks; exit 0 was required and observed.
git -c gc.auto=0 -C "$n8n_repo" merge-base --is-ancestor a597ef5a ca9d4b3d
git -c gc.auto=0 -C "$n8n_repo" merge-base --is-ancestor 74f05e93 1cfe9c6b
git -c gc.auto=0 -C "$agent_repo" merge-base --is-ancestor bd15a2a2 900e6b95
git -c gc.auto=0 -C "$network_repo" merge-base --is-ancestor 8469edbe 7d52091f
git -c gc.auto=0 -C "$parse_repo" merge-base --is-ancestor 32bd6e85 8a34c2f0

# Recovered n8n PR/member topology.
gh api repos/czlonkowski/n8n-mcp/pulls/419
gh api repos/czlonkowski/n8n-mcp/pulls/419/commits --paginate
gh api repos/czlonkowski/n8n-mcp/commits/7ac748e73f69bcd3b43d0a321b38d79078013b91
gh api repos/czlonkowski/n8n-mcp/pulls/460
gh api repos/czlonkowski/n8n-mcp/pulls/460/commits --paginate
gh api repos/czlonkowski/n8n-mcp/commits/3f698cc62d2f820f83713a51fce23f71e9cc4654
gh api repos/czlonkowski/n8n-mcp/commits/7d81204aecb58ba09c70497ae643b886f0d9edc4

# Live first-party repository-advisory identity/state. Equivalent calls were made for all ten IDs.
gh api repos/czlonkowski/n8n-mcp/security-advisories/GHSA-75hx-xj24-mqrw
gh api repos/czlonkowski/n8n-mcp/security-advisories/GHSA-8g7g-hmwm-6rv2
gh api repos/agenticmail/agenticmail/security-advisories/GHSA-63gr-g7jc-v8rg
gh api repos/agenticmail/agenticmail/security-advisories/GHSA-fq4x-789w-jg5h
gh api repos/agenticmail/agenticmail/security-advisories/GHSA-hjwc-26pj-v3pm
gh api repos/agenticmail/agenticmail/security-advisories/GHSA-wjjv-3mj2-39hf
gh api repos/Jovancoding/Network-AI/security-advisories/GHSA-fj4g-2p96-q6m3
gh api repos/Jovancoding/Network-AI/security-advisories/GHSA-j3vx-cx2r-pvg8
gh api repos/parse-community/parse-dashboard/security-advisories/GHSA-qwc3-h9mg-4582
gh api repos/parse-community/parse-dashboard/security-advisories/GHSA-cvwj-6c9h-jg6v

# npm provenance without npm cache mutation; repeated for the exact versions in each row.
curl -fsSL -H 'User-Agent: ai-slop-research' \
  'https://registry.npmjs.org/n8n-mcp/2.50.1' \
  | jq -r '[.name,.version,.gitHead,.repository.url,.dist.tarball] | @tsv'
curl -fsSL -H 'User-Agent: ai-slop-research' \
  'https://registry.npmjs.org/%40agenticmail%2Fmcp/0.9.27' \
  | jq -r '[.name,.version,.gitHead,.repository.url,.dist.tarball] | @tsv'
curl -fsSL -H 'User-Agent: ai-slop-research' \
  'https://registry.npmjs.org/network-ai/5.4.5' \
  | jq -r '[.name,.version,.gitHead,.repository.url,.dist.tarball] | @tsv'
curl -fsSL -H 'User-Agent: ai-slop-research' \
  'https://registry.npmjs.org/parse-dashboard/9.0.0-alpha.8' \
  | jq -r '[.name,.version,.gitHead,.repository.url,.dist.tarball] | @tsv'
```

Unauthenticated direct calls to `api.github.com` encountered HTTP 403 rate limiting during the background pass. The same exact endpoints were then read with `gh api`; no token, credential, or authorization header was displayed or stored. Two initial Network-AI calls used the wrong owner and returned HTTP 404; the local advisory's first-party URL identified `Jovancoding/Network-AI`, and the corrected endpoints returned the published records shown above.

## Negative, unknown, and operational controls

- Seven published/released advisories are real vulnerabilities but fail the AI-causality gate. They are not discarded merely because they are negative.
- GHSA-WJJV is `UNKNOWN`, not FAIL: the private patch branch and multi-mechanism aggregate prevent safe atomic lineage recovery.
- Network-AI commit `27b549f4...` is an explicit same-file/cross-file routing false positive: real Claude attribution, wrong files and wrong edge.
- AgenticMail commit `05d8598e...` is an explicit guarded-sibling false positive: it demonstrates the correct sender check on a different path but does not remediate the vulnerable bridge path.
- Parse's “AI agent” feature name is not an AI-authorship marker.
- Human partial remediation in Network-AI is preserved as evidence about the mechanism but not relabeled as AI incomplete remediation.

### Scope incident

During discarded Better Auth triage, an early read-only `git log --all -S...` against `/home/hanqing/.cache/cve-analyzer/repos/better-auth_better-auth` emitted `Auto packing the repository in background for optimum performance`. Git may therefore have repacked object-store metadata in that pre-existing cache, despite no requested write. No worktree or ref mutation command was run, no rollback was attempted, and a later guarded check showed HEAD `f48c66efa322223728f550e4d8b84ec8e9195ff5` with a clean worktree. Better Auth was excluded from the ten selected rows and none of its data supports this report. Subsequent Git reads used `-c gc.auto=0`.

This potential cache-internal mutation violates the shard's strict read-only cache boundary, so the terminal status is `PARTIAL` even though the bounded ten-row research deliverable is complete.

## Claim boundary

- The admitted claims are exactly three strict direct/new-surface components and one released incomplete-remediation component under two GHSA identities. They do not establish that every issue in either advisory was authored by AI.
- GHSA-8G7G contributes three mechanism rows but one public-ID row. GHSA-75HX contributes one component and one public-ID row.
- CVE/GHSA aliases are counted once. Shared commits do not merge distinct invariants; multiple mechanisms in one advisory do not multiply the public-ID census.
- Every admitted component has exact candidate/member lineage, direct attribution, direct-parent mechanism evidence, first-party advisory identity, same-mechanism fix reversal, and vulnerable/fixed npm containment.
- FAIL controls have equally concrete source and release histories; they fail because attribution or edge identity does not close, not because the vulnerability is unreal.
- GHSA-WJJV remains `UNKNOWN` until mechanisms are split and atomic origins recovered. No aggregate inference is permitted.
- The local advisory database and routing artifacts are source-recovery aids. Live first-party GitHub advisory state, exact Git history, and npm gitHeads provide the release and identity closure used here.

The bounded background evidence, including fuller n8n PR-member diffs and AgenticMail control commands, is preserved at `autoresearch/herdr-260812-mcp-js-ecosystem/background_findings.md` with SHA-256 `60fd0782205ba6bfaba0b4f216f00780ebc5b745472ef3bb827dcf9dce02c65a`.
