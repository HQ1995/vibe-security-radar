# Background findings: JavaScript/TypeScript MCP and agent ecosystem

Research window: 2026-08-12 12:19–12:31 America/New_York. This is the bounded background shard, not the campaign's terminal report.

## Result first

I found **two novel published GHSA alias classes** for `n8n-mcp`, comprising **four defensible semantic components**:

| Classification | Semantic components | Public IDs |
|---|---:|---:|
| `STRICT_CAUSAL` | 3 | 2 GHSA-only IDs after alias dedup |
| `AI_INCOMPLETE_REMEDIATION` | 1 | 0 additional IDs (shares GHSA-8G7G-HMWM-6RV2) |
| `FAIL` controls | 3 AgenticMail cases | not admitted |
| `UNKNOWN` control | 1 aggregate AgenticMail advisory | not admitted |

Conservative publication accounting is therefore **2 new public-ID rows**, not 4. A component/mechanism ledger may retain the four subrows below, but must keep the three GHSA-8G7G mechanisms under one official identity and must not increment the public-ID count three times.

The strongest closure is in `czlonkowski/n8n-mcp`. Each positive below has first-party advisory identity, exact candidate/member-to-carrier history, direct-parent mechanism evidence, exact first-party fix reversal, and a released vulnerable state followed by a released fix. OpenClaw, Coolify, and all already adjudicated rows were excluded before candidate work.

## Snapshot boundary and input hashes

The checkout is shared and volatile. I read only the following frozen values at `2026-08-12T12:27:47-04:00`; later edits by other agents are outside this shard's boundary.

| Input | Frozen identity / SHA-256 |
|---|---|
| GitHub Advisory Database clone | git `39d8887723797efc1804585dd06585c9fd751226` (2026-07-23 sync) |
| frozen strict ledger | `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl` = `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| newest consolidated report read | `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` = `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| GHSA-75HX local reviewed record | `3e3654a8e685288bcbf83f29e8ed5ecaa8649700a64d34a5472fad6002bb924c` |
| GHSA-8G7G local reviewed record | `b5206bcac226dae8dbffbd4b3c3f1ee1fcc392c9dcc8f6fcb2f5e6cf99a2edc8` |
| n8n-mcp read-only clone | HEAD `f1e6e5be393f390b0223057906c675d81f938f63` |
| AgenticMail read-only clone | HEAD `4a0e0f6f590aed435c0f8bc962bbdd488aec4016` |
| AgenticMail same-file routing artifact | `autoresearch/orchestrator-260811-atomic150/global-same-file-v6/agenticmail/same-file-candidates.jsonl` = `76d8047756da5ac9204415bdab5c30d859535a1f4cfe6a33363f78108f1c0cfe` |

AgenticMail advisory-record hashes used only for negative/unknown controls:

- GHSA-63GR-G7JC-V8RG: `c8762b87a4d979f45382e66f59ee93c76ff1d33c6bf9b4a735605f07b12b2cb1`
- GHSA-FQ4X-789W-JG5H: `d8907d65d051feca1f40501283f7cbf64c89d6957f59e98533c8aa9729d77aa3`
- GHSA-HJWC-26PJ-V3PM: `12c2933386c3ed03a3cc092af61fea69e1151d368e1dd6edeb9f840e787fcf22`
- GHSA-WJJV-3MJ2-39HF: `18696a9f374446748af6fcc81a4a1c673ec96b383ac7f5eb497de673d476b5bf`

Live GitHub repository-advisory and PR APIs, plus the npm registry, were queried between 12:24 and 12:27 ET. Exact endpoints and returned identities are recorded below; those live responses were not written to a shared cache.

## Prior rows explicitly excluded

I normalized public IDs and searched the frozen strict ledger, its rejected controls, and the newest reports before adjudication. Neither GHSA-75HX-XJ24-MQRW nor GHSA-8G7G-HMWM-6RV2, nor any candidate/fix fingerprint below, appeared there.

Rows deliberately not redone include:

- all 110 components / 200 public IDs in `strict-200-v3`;
- all 125 strict and 48 released incomplete-remediation components summarized by the newest main report;
- n8n-mcp CVE-2026-42449 / GHSA-56C3-VFP2-5QQJ (already adjudicated incomplete remediation);
- code-index-mcp CVE-2026-10692 / GHSA-647R-72HF-4VMH;
- NetLicensing-MCP CVE-2026-54446 / GHSA-X9VC-9FFQ-P3GJ;
- magento2-dev-mcp CVE-2026-5603 / GHSA-XQV9-QR76-HFQ2;
- mail-mcp-bridge CVE-2026-7386 / GHSA-2GFJ-FR43-4735;
- Ruflo CVE-2026-59726 / GHSA-C4HM-4H84-2CF3;
- agentic-flow CVE-2026-58195 / GHSA-VCV2-R9JH-99M5;
- Dynatrace MCP GHSA-P7W7-4929-VPJ5;
- modelcontextprotocol/registry CVE-2026-44430 / GHSA-R48C-V28R-PF6V;
- all OpenClaw and Coolify rows, including same-mechanism aliases.

The AgenticMail cases below were present only as routing artifacts, not as completed causal adjudications. They are retained as new negative/unknown controls, not counted as positive rows.

## Positive row A — GHSA-75HX-XJ24-MQRW (`n8n-mcp`)

**Verdict: publication-grade `STRICT_CAUSAL`, narrowly as a new-surface contributor. Count once.**

### Official identity and release boundary

The first-party [repository advisory](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-75hx-xj24-mqrw) returned:

```text
GHSA-75hx-xj24-mqrw  cve_id=null  state=published  withdrawn_at=null
ecosystem=npm  package=n8n-mcp  vulnerable=<= 2.47.5  patched=2.47.6
```

There is no CVE alias; the alias class is the GHSA alone. The reviewed local record says unauthenticated callers could terminate MCP sessions and obtain operational/session metadata.

### Exact candidate and fix lineage

- Candidate: [`a597ef5a924ebe17a6a202bbb841965f52328032`](https://github.com/czlonkowski/n8n-mcp/commit/a597ef5a924ebe17a6a202bbb841965f52328032), parent `a4053de998595b4321576ad6a908e65590816ee0`.
- Candidate attribution is direct: its own message contains both `Generated with Claude Code` and `Co-Authored-By: Claude <noreply@anthropic.com>`.
- Fix: [`ca9d4b3df6419b8338983be98f7940400f78bde3`](https://github.com/czlonkowski/n8n-mcp/commit/ca9d4b3df6419b8338983be98f7940400f78bde3), parent `ff486ea04f0b20460141e5ef2be3d518e1772b80`; the first-party advisory cites this exact commit. It is a one-parent mainline commit despite the subject `Merge commit from fork`, and it also has a Claude Opus 4.6 co-author trailer.
- `git merge-base --is-ancestor a597ef5... ca9d4b3...` returned 0.

The candidate direct-parent delta did not merely touch the server. It:

1. changed unauthenticated `GET /mcp` from static discovery into a handler that accepts `Mcp-Session-Id` and dispatches into an existing live transport;
2. added unauthenticated `DELETE /mcp`, allowing session termination by supplied session ID;
3. added `sessionIds: activeTransports` and active transport/server counts to unauthenticated `/health`.

The fix directly reverses all three candidate-added edges: `authLimiter + authenticateRequest` on GET and DELETE, removal of the unauthenticated test route, and reduction of `/health` to four liveness fields without session IDs, token metadata, memory, mode, or environment.

This claim is intentionally narrower than “Claude created the whole advisory.” Earlier code already had an unauthenticated static discovery endpoint and basic health response. The accepted role is **new live-session/termination surface plus higher-sensitivity health disclosure**, exactly the portion created by `a597ef5` and reversed by `ca9d4b3`.

### Released containment

- Earliest locally observed tag containing the candidate: `v2.9.1`.
- npm `n8n-mcp@2.9.1` reports gitHead `35b4e77bcd0141cd1f49130f2b9f9f9b083a8b02`; the candidate is its ancestor and the fix is not.
- npm `2.47.5` reports gitHead `ff486ea04f0b20460141e5ef2be3d518e1772b80`, exactly the fix parent.
- npm `2.47.6` reports gitHead `4b161b6acbf96120492dea2a6af0f9c72a4a633e`; `ca9d4b3` is its ancestor.
- The [v2.47.6 release](https://github.com/czlonkowski/n8n-mcp/releases/tag/v2.47.6) is also cited by the advisory.

Thus a released candidate-bearing vulnerable interval and a later released reversal both exist.

## Positive alias class B — GHSA-8G7G-HMWM-6RV2 (`n8n-mcp`)

The first-party [repository advisory](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-8g7g-hmwm-6rv2) returned:

```text
GHSA-8g7g-hmwm-6rv2  cve_id=null  state=published  withdrawn_at=null
ecosystem=npm  package=n8n-mcp  vulnerable=< 2.50.1  patched=2.50.1
```

It is GHSA-only and explicitly describes three independent mechanisms. The first-party fix is [`1cfe9c6bddb4b1634e6e23323c18ea35fd196999`](https://github.com/czlonkowski/n8n-mcp/commit/1cfe9c6bddb4b1634e6e23323c18ea35fd196999), parent `fefa2d9b3908f88ebb060cac28af453c612a7668`. npm `2.50.0` has gitHead `1ca40ce2bdf18b8c88cd571074cec3f61471c7eb`; npm `2.50.1` has gitHead equal to the fix itself. Each candidate/carrier below is an ancestor of the fix and appears in releases before 2.50.1.

### B1 — caller-controlled API path segments

**Verdict: publication-grade `STRICT_CAUSAL`, direct origin.**

- Candidate: [`74f05e937fa7d94babe3507510caa17ce17a698c`](https://github.com/czlonkowski/n8n-mcp/commit/74f05e937fa7d94babe3507510caa17ce17a698c), parent `150de3d1c249e518b73d91b8621db2f6a628b1b5`.
- Direct attribution: `Generated with Claude Code` plus Claude co-author trailer.
- Direct-parent delta adds the n8n management integration and `N8nApiClient`, including caller-controlled `id` interpolation such as ``/workflows/${id}`` and sibling execution/credential/tag/data-table paths. The parent has no such client surface.
- Fix `1cfe9c6...` creates `encodeApiPathSegment` with a bounded allowlist and routes each affected path parameter through it, directly closing same-origin path traversal/endpoint confusion while carrying the configured n8n API key.
- Earliest locally observed containing tag is `v2.7.9`; candidate-bearing tags continue through `v2.50.0`; fixed npm version `2.50.1` is the exact fix gitHead.

The commit subject says the implementation was integrated from another project. The claim is therefore target-repository **integration origin/new surface**, not authorship of the upstream project's original code.

### B2 — redirect-following SSRF in webhook/form/chat trigger execution

**Verdict: publication-grade `STRICT_CAUSAL` as a new form/chat surface contributor; the webhook sibling is supporting incomplete-remediation evidence, not a second count.**

First-party PR topology was recovered rather than attributing the squash carrier:

- [PR #460](https://github.com/czlonkowski/n8n-mcp/pull/460), merged 2025-12-01, squash carrier [`33690c5650e680b2c9cfbae75cac81a761742389`](https://github.com/czlonkowski/n8n-mcp/commit/33690c5650e680b2c9cfbae75cac81a761742389), parent `ddf95567591a5b0a56e9df393e368969536fce3e`.
- Atomic origin member [`3f698cc62d2f820f83713a51fce23f71e9cc4654`](https://github.com/czlonkowski/n8n-mcp/commit/3f698cc62d2f820f83713a51fce23f71e9cc4654), parent `ddf955...`, has its own Claude marker and adds `ChatHandler` and `FormHandler`. Both validate the initial URL with `SSRFProtection.validateWebhookUrl`, then call Axios without `maxRedirects: 0`; their parent has neither handler.
- Atomic remediation member [`7d81204aecb58ba09c70497ae643b886f0d9edc4`](https://github.com/czlonkowski/n8n-mcp/commit/7d81204aecb58ba09c70497ae643b886f0d9edc4), parent `3f698...`, also has its own Claude marker and explicitly adds “SSRF protection” to the webhook sibling, but still validates only the initial URL and leaves redirect following enabled.
- Fix `1cfe9c6...` adds `maxRedirects: 0` to all three request sites (API-client webhook, form, and chat), exactly closing the advisory's validate-then-redirect bypass.
- npm `2.28.0` has gitHead exactly equal to squash carrier `33690c5`; vulnerable carrier-bearing releases continue through `2.50.0`; npm `2.50.1` is the fix.

Count this mechanism once. `3f698` supports a strict new-surface claim for form/chat. `7d812` proves an incomplete SSRF guard on the legacy webhook path, but it is the same advisory mechanism and must not create another component or public ID.

### B3 — unredacted mutation-operation telemetry

**Verdict: publication-grade `AI_INCOMPLETE_REMEDIATION`; explicitly not strict origin.**

First-party PR/member topology:

- Human-origin member [`61fdd6433a4ae0a404772a0f6a53f928e4606c5e`](https://github.com/czlonkowski/n8n-mcp/commit/61fdd6433a4ae0a404772a0f6a53f928e4606c5e) creates mutation telemetry and stores `operations: data.operations`, `validationBefore/After`, and `mutationError` raw. It has no direct AI marker, so it is a negative control for strict origin.
- Atomic AI partial-remediation member [`7ac748e73f69bcd3b43d0a321b38d79078013b91`](https://github.com/czlonkowski/n8n-mcp/commit/7ac748e73f69bcd3b43d0a321b38d79078013b91), parent `6719628350972ebdbc347ef4406b029a712c3f24`, carries `Generated with Claude Code` and a Claude co-author trailer. It explicitly replaces raw before/after workflow copies with multi-layer credential/sensitive-value sanitization, but leaves the operation diff, validation objects, and error strings raw in the same telemetry record.
- [PR #419](https://github.com/czlonkowski/n8n-mcp/pull/419) merged that member chain into squash carrier [`99c5907b71a6c3228d345a2f0879cd893f30cd7e`](https://github.com/czlonkowski/n8n-mcp/commit/99c5907b71a6c3228d345a2f0879cd893f30cd7e), parent `77151e013ee3fea15be34f009594bcde81edf8e2`.
- Fix `1cfe9c6...` adds `sanitizeTelemetryObject` and applies it to `operations`, both validation objects, and `mutationError`, precisely closing the residual named by the advisory.
- npm `2.22.16` has gitHead exactly equal to carrier `99c5907`; the partial remediation therefore shipped. Carrier-bearing releases continue through `2.50.0`; npm `2.50.1` is the exact complete fix.

This row satisfies the broader incomplete-remediation contract: explicit AI-attributed security/privacy sanitization, a concrete same-record residual, a release containing the partial state, a first-party advisory naming that residual, and a later exact closure. It must not be rewritten as “AI introduced telemetry exposure,” because `61fdd6` is the non-AI root.

## Duplicate and non-causal controls

### FAIL control 1 — AgenticMail MCP missing authentication

[CVE-2026-50287 / GHSA-63GR-G7JC-V8RG](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-63gr-g7jc-v8rg) is a real released MCP authorization defect, but it is **not an AI-causal row** on recovered history.

- Human commit [`bd15a2a26f24624de491d50a6d24a61e160943e3`](https://github.com/agenticmail/agenticmail/commit/bd15a2a26f24624de491d50a6d24a61e160943e3), parent `bf59f4c...`, first adds the Streamable HTTP server without request authentication; its full message has no AI author/trailer marker.
- Exact fix [`7d1791da7c8c8bd4e70d7081db48e18ab55f6736`](https://github.com/agenticmail/agenticmail/commit/7d1791da7c8c8bd4e70d7081db48e18ab55f6736) binds loopback by default and requires a bearer token.
- The many routed Claude commits overlap changelog/package files or later features. They do not replace the human origin.

Verdict: **FAIL `human_origin / adjacent_ai_only`**. Preserve as a negative control.

### FAIL control 2 — AgenticMail bridge-wake sender authentication

[CVE-2026-57495 / GHSA-FQ4X-789W-JG5H](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-fq4x-789w-jg5h) is also non-causal for AI under the required gate.

- Human commit [`bb7566013328b4a8a7d946957f925ebedc57b31f`](https://github.com/agenticmail/agenticmail/commit/bb7566013328b4a8a7d946957f925ebedc57b31f), parent `01579df...`, directly creates `handleBridgeMail` and privileged host-session resume without sender authentication. It has no AI marker.
- Claude-coauthored [`05d8598e4583bab88f436e954b470f82ae49bbd5`](https://github.com/agenticmail/agenticmail/commit/05d8598e4583bab88f436e954b470f82ae49bbd5) later adds a **guarded, distinct operator-query email-reply hook** and explicitly verifies its sender. It does not modify `handleBridgeMail`, bridge-wake resume, or the gateway approval-reply sink. It is the advisory's safe sibling/control, not a partial remediation of the vulnerable path.
- Exact fix [`620678c53a179c17272aa442729c3c38e3865345`](https://github.com/agenticmail/agenticmail/commit/620678c53a179c17272aa442729c3c38e3865345) adds sender gates to bridge wake and approval replies.

Verdict: **FAIL `wrong_edge / guarded_sibling`**. Do not turn knowledge of the correct guard elsewhere into causal attribution.

### FAIL control 3 — AgenticMail cross-agent task authorization

[CVE-2026-57494 / GHSA-HJWC-26PJ-V3PM](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-hjwc-26pj-v3pm) has exact fix [`d00728567576411ee8ad6e85f32d6472536ec44b`](https://github.com/agenticmail/agenticmail/commit/d00728567576411ee8ad6e85f32d6472536ec44b), but the recovered route history is human-authored:

- `cf35e22fbfaa99725245505008e9de7a7c71ed02` creates the task route family;
- `1b1d9ee28754547ec357464b368651baf1402050` adds the capability-style complete endpoint;
- later route rewrites `4054b8e...` and `98aef53...` retain missing cross-agent ownership checks but also have no AI marker.

Verdict: **FAIL `human_origin`**. Same-file Claude routing via changelog/package files is non-causal.

### UNKNOWN control — aggregate AgenticMail storage/relay advisory

[CVE-2026-47255 / GHSA-WJJV-3MJ2-39HF](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-wjjv-3mj2-39hf) aggregates identifier validation, raw-SQL ownership, metadata access, worker secret, SMTP control characters, and TLS verification. The advisory says the security patch branch was private and cites a multi-commit fix chain (`1408de5`, merge `234b811`, later `6c70c82`, release `8cb053f`). Within this shard I did not recover exact atomic origins for every independent mechanism or a safe component split.

Verdict: **UNKNOWN**, not negative and not a positive row. A later pass must split mechanisms first, then bind each to its own origin and release interval.

## Exact primary-source commands

All commands were read-only. No credentials were printed, no clone/cache was mutated, and no build/test suite ran.

```zsh
cd /home/hanqing/agents/ai-slop

# Freeze local official and prior-adjudication inputs.
git -C /home/hanqing/.cache/cve-analyzer/advisory-database rev-parse HEAD
sha256sum \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
  /home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/04/GHSA-75hx-xj24-mqrw/GHSA-75hx-xj24-mqrw.json \
  /home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/05/GHSA-8g7g-hmwm-6rv2/GHSA-8g7g-hmwm-6rv2.json

# Verify novelty against accepted/rejected local material.
rg -n -i 'GHSA-75HX-XJ24-MQRW|GHSA-8G7G-HMWM-6RV2|a597ef5a|ca9d4b3d|74f05e93|33690c56|99c5907b|1cfe9c6b' \
  docs \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
  autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/rejected.jsonl \
  autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/rejected_edges.jsonl

n8n_repo=.ai-slop/cache/cve-analyzer/repos/v2_github.com_n8n-mcp_7f3ec1dcf0d7cdaa7f65f6c0aed32341a5c14c9c95b456fff2c6e355a78931a1

# Commit identities, parents, trailers, candidate/fix deltas, and ancestry.
git -C "$n8n_repo" show -s --format='%H%n%P%n%an <%ae>%n%aI%n%B' \
  a597ef5a924ebe17a6a202bbb841965f52328032 \
  ca9d4b3df6419b8338983be98f7940400f78bde3 \
  74f05e937fa7d94babe3507510caa17ce17a698c \
  33690c5650e680b2c9cfbae75cac81a761742389 \
  99c5907b71a6c3228d345a2f0879cd893f30cd7e \
  1cfe9c6bddb4b1634e6e23323c18ea35fd196999
git -C "$n8n_repo" diff a597ef5a^ a597ef5a -- src/http-server-single-session.ts
git -C "$n8n_repo" diff 74f05e93^ 74f05e93 -- src/services/n8n-api-client.ts
git -C "$n8n_repo" diff 99c5907b^ 99c5907b -- src/telemetry/mutation-tracker.ts
git -C "$n8n_repo" diff 1cfe9c6b^ 1cfe9c6b -- \
  src/services/n8n-api-client.ts src/triggers/handlers \
  src/telemetry/mutation-tracker.ts src/telemetry/workflow-sanitizer.ts
git -C "$n8n_repo" merge-base --is-ancestor a597ef5a ca9d4b3d
git -C "$n8n_repo" merge-base --is-ancestor 74f05e93 1cfe9c6b
git -C "$n8n_repo" merge-base --is-ancestor 33690c56 1cfe9c6b
git -C "$n8n_repo" merge-base --is-ancestor 99c5907b 1cfe9c6b

# First-party PR topology and atomic member patches.
gh api repos/czlonkowski/n8n-mcp/pulls/419
gh api repos/czlonkowski/n8n-mcp/pulls/419/commits --paginate
gh api repos/czlonkowski/n8n-mcp/commits/7ac748e73f69bcd3b43d0a321b38d79078013b91
gh api repos/czlonkowski/n8n-mcp/pulls/460
gh api repos/czlonkowski/n8n-mcp/pulls/460/commits --paginate
gh api repos/czlonkowski/n8n-mcp/commits/3f698cc62d2f820f83713a51fce23f71e9cc4654
gh api repos/czlonkowski/n8n-mcp/commits/7d81204aecb58ba09c70497ae643b886f0d9edc4

# Live first-party advisory identity.
gh api repos/czlonkowski/n8n-mcp/security-advisories/GHSA-75hx-xj24-mqrw
gh api repos/czlonkowski/n8n-mcp/security-advisories/GHSA-8g7g-hmwm-6rv2

# npm release provenance without npm cache mutation.
for ver in 2.9.1 2.47.5 2.47.6 2.22.16 2.28.0 2.50.0 2.50.1; do
  curl -fsSL -H 'User-Agent: ai-slop-research' \
    "https://registry.npmjs.org/n8n-mcp/$ver" \
    | jq -r '[.version,.gitHead,.repository.url,.dist.tarball] | @tsv'
done
```

Unauthenticated `curl` calls to `api.github.com` returned HTTP 403 (rate limiting). The same exact first-party endpoints were then read through authenticated `gh api`; no token or header value was displayed or stored.

## Claim boundary

- The four component conclusions above are claim-grade only within their stated roles: three strict direct/new-surface components and one incomplete remediation. They do not establish that every issue in either advisory was authored by AI.
- GHSA-75HX is counted once even though the candidate added both session-control and health-disclosure effects. Splitting it would inflate one first-party identity with one candidate/fix pair.
- GHSA-8G7G has three genuinely distinct input/sink/invariant mechanisms, but one GHSA alias class. Component analysis may retain three rows; public-ID accounting must retain one.
- PR squash carriers `33690c5` and `99c5907` are release/topology witnesses. AI attribution for the critical portions rests on recovered atomic members `3f698cc`, `7d81204`, and `7ac748e`, not on projecting a carrier trailer backward.
- `61fdd6` is preserved as the human telemetry origin; `7ac748e` is only an incomplete remediation. AgenticMail human origins and the guarded sibling are preserved as FAIL controls. The aggregate storage/relay advisory remains UNKNOWN.
- Local candidate routing, same-file overlap, source recovery, API status, and npm metadata were diagnostic until candidate parent/delta, same-mechanism fix reversal, and release containment all closed. No model output, build, or test result was used as causal proof.
