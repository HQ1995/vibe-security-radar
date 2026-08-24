# Batch 2 positive red-team: independent primary-source replay

Status: **COMPLETE for the five Batch 1 mechanism rows**  
Fresh-object observation cutoff: `2026-08-12T17:01:47Z`  
Scope: AutoGPT `CVE-2026-72922` / `GHSA-349P-3C3R-8MJR`, plus every strict or incomplete-remediation mechanism admitted under n8n-mcp `GHSA-75HX-XJ24-MQRW` and `GHSA-8G7G-HMWM-6RV2`.

## Result first

The Batch 1 reports were used only to locate the five rows. Fresh first-party repository advisories, commit objects, parent objects, pull-request members, annotated tags, releases, GitHub comparisons, and npm version objects were then fetched independently.

| Row | Role under review | Red-team disposition | Reason |
|---|---|---|---|
| AutoGPT provider-path webhook bypass | strict candidate | **NARROW** | Keep the causal contributor, but do not say it originated URL-provider selection. Parent `e877391...` already selected the manager from the path. Marked carrier `7f08a16...` added the provider-overridable verification call, default no-op, and protected generic-webhook secret without binding the loaded webhook to its stored provider. |
| n8n-mcp session control / health disclosure | strict candidate | **KEEP** | Marked candidate `a597ef5...` directly added live unauthenticated GET/DELETE session surfaces and session IDs/counts on health; exact fix `ca9d4b3...` authenticated the session routes and minimized health; vulnerable and fixed releases close. |
| n8n-mcp caller-controlled API path segments | strict candidate | **KEEP** | Marked target-repository integration commit `74f05e9...` added raw caller IDs to API-key-bearing paths; exact fix `1cfe9c6...` validates/encodes those segments; released ancestry closes. |
| n8n-mcp redirect-following trigger SSRF | strict candidate | **KEEP** | Marked PR member `3f698cc...` added form/chat sinks that validate only the first URL and then use redirect-following Axios; marked sibling `7d81204...` applied the same incomplete initial guard to the legacy webhook; exact fix disables redirects at all three sinks. Count once. |
| n8n-mcp mutation-telemetry residual | AI incomplete remediation | **KEEP** | Human `61fdd64...` created raw telemetry. Marked `7ac748e...` sanitized before/after workflows but left operations, validation objects, and errors raw; marked carrier `99c5907...` shipped that partial state; exact fix sanitizes each residual. Keep only as `AI_INCOMPLETE_REMEDIATION`, never strict origin. |

Net: **4 KEEP / 1 NARROW**, five mechanisms under **three public advisory identities**. `CVE-2026-72922` and `GHSA-349P-3C3R-8MJR` are one alias class. `GHSA-8G7G-HMWM-6RV2` has three mechanisms but contributes one public-ID row. No row becomes `REJECT` or `UNKNOWN` after replay.

## Local lead provenance

These mutable local files were read only as leads and frozen by SHA-256 before primary-source replay:

| Lead input | SHA-256 |
|---|---|
| `autoresearch/herdr-260812-fresh-advisories/report.md` | `29c91e17cb33aed6335e6a8dda4698981da76b8b4a7e1731811e7d22c32bc713` |
| `autoresearch/herdr-260812-fresh-advisories/source-notes.md` | `3550ba4a65e275a447bd8edd2c9333dd0a43845561c3b974df527d3071eb6b19` |
| `autoresearch/herdr-260812-fresh-advisories/result.json` | `2c5d1e041e26e5e239ec31ac97d5f7a1333d6631b50ec6da857d313bd8e64e03` |
| `autoresearch/herdr-260812-fresh-advisories/cve-api/CVE-2026-72922.json` | `eeb187b4cfce561e1d32e8c295e5646fd897a8b78be69b5b5a86adc31b96a99c` |
| `autoresearch/herdr-260812-fresh-advisories/patches/CVE-2026-72922-fix.patch` | `404c9ed882c4facfb63e6ce74efec99265ec74406114ae213c9608ff6189b4b1` |
| `autoresearch/herdr-260812-fresh-advisories/patches/CVE-2026-72922-origin-3b0d432.patch` | `21487b1fb9873eb3f5ccdcb20fa8351a01a43d1ae51d79066500400c76213d85` |
| `autoresearch/herdr-260812-fresh-advisories/patches/CVE-2026-72922-origin-pr13135.patch` | `c5362ec7c0d19076f99c31d4db7bfcff2643fefb5c8f30abe3ea1697b2b51cc9` |
| `autoresearch/herdr-260812-mcp-js-ecosystem/report.md` | `47be67ee784f15b334378348e2c3ad62bbfd35d4810e7aa57c261602592fbe52` |
| `autoresearch/herdr-260812-mcp-js-ecosystem/background_findings.md` | `60fd0782205ba6bfaba0b4f216f00780ebc5b745472ef3bb827dcf9dce02c65a` |
| `autoresearch/herdr-260812-mcp-js-ecosystem/result.json` | `f9ef2c57b3125009603b46ad76d99cc56c27d208bedd1549a1475d3119a90bfa` |

The earlier mcp-js shard's terminal `PARTIAL` was operational: a discarded cache query triggered Git auto-packing. It does not weaken the immutable objects below, which were independently re-fetched. No cache or repository was mutated in this replay.

## Fresh advisory state

### AutoGPT

The live first-party [repository advisory](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-349p-3c3r-8mjr) returned `state=published`, `withdrawn_at=null`, GHSA `GHSA-349p-3c3r-8mjr`, CVE `CVE-2026-72922`, affected `< autogpt-platform-beta-v0.6.70`, patched `autogpt-platform-beta-v0.6.70`, published `2026-08-05T04:10:41Z`, updated `2026-08-11T14:30:17Z`. The live description names the path-selected manager, missing stored-provider comparison, inherited no-op verifier, and generic-secret bypass.

The local CVE response independently records `state=PUBLISHED`, `datePublished=2026-08-11T14:32:11.812Z`, affected `< 0.6.70`, exact fix `646dd5b8...`, and exact release tag.

### n8n-mcp

The live first-party [GHSA-75HX advisory](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-75hx-xj24-mqrw) returned `state=published`, `withdrawn_at=null`, no CVE alias, affected `<=2.47.5`, patched `2.47.6`, published/updated `2026-04-10T09:59:02Z`. It identifies unauthenticated session termination and operational metadata exposure.

The live first-party [GHSA-8G7G advisory](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-8g7g-hmwm-6rv2) returned `state=published`, `withdrawn_at=null`, no CVE alias, affected `<2.50.1`, patched `2.50.1`, published/updated `2026-05-04T10:14:44Z`. It explicitly splits path-segment injection, redirect-following SSRF, and unredacted mutation-operation telemetry.

## Row-level replay

### 1. AutoGPT provider-path confusion — NARROW

**Exact objects**

- Atomic PR member [`3b0d43230901ef353c39cc3bbac36e6d81f049dc`](https://github.com/Significant-Gravitas/AutoGPT/commit/3b0d43230901ef353c39cc3bbac36e6d81f049dc), parent `94ebce7f633f40af8fd59e5cdaea75159cf2e6d1`; direct `Co-Authored-By: Claude Opus 4.7`.
- Marked mainline squash carrier [`7f08a16deed57c93654356058667293534de6994`](https://github.com/Significant-Gravitas/AutoGPT/commit/7f08a16deed57c93654356058667293534de6994), parent `e877391a55f0f834c43ab00eb3a59f60c852f428`; verified GitHub signature and direct Claude Opus 4.7 trailer.
- Exact fix [`646dd5b8cfad1206e92ec7bcc3b8312657e2a92e`](https://github.com/Significant-Gravitas/AutoGPT/commit/646dd5b8cfad1206e92ec7bcc3b8312657e2a92e), parent `3fa88a70efd2f2110506a3aaf0c5997fa915fbb8`; verified GitHub signature.
- Vulnerable tag `autogpt-platform-beta-v0.6.65` -> commit `e2711b1748bdc3fe702ab4e44c6a11df98458c53`.
- Fixed tag `autogpt-platform-beta-v0.6.70` -> commit `c45b9e35817a2037fadeaa47924cf41681573c09`.

**Mechanism and contradiction.** The carrier adds `BaseWebhooksManager.verify_signature` with a default no-op, calls it through the already-selected manager, and adds the generic webhook's optional `secret_token` / `X-Webhook-Secret` enforcement. Its direct-parent diff does **not** add `get_webhook_manager(provider)`. Fresh inspection of `router.py` at parent `e877391...` confirms URL-provider manager selection already existed. The carrier therefore creates the decisive vulnerable composition, not the whole route-selection primitive.

The fix compares `webhook.provider` with the URL provider before signature verification and adds cross-provider regression tests. GitHub compare returned `status=ahead`, `merge_base_commit=7f08a16...`, `ahead_by=121` for carrier to fix. Candidate-to-vulnerable-tag compare returned `ahead_by=11`; fix-to-fixed-tag compare returned `ahead_by=16` and merge base equal to the fix.

One first-party prose/code mismatch is harmless but should be retained: the fix commit message says provider mismatch returns 403, while its actual patch raises `NotFoundError` and the tests assert indistinguishable HTTP 404. Both fail closed before verification, so containment remains valid.

**Disposition:** `NARROW` to: *the marked carrier introduced provider-overridable signature verification, its unsigned-provider default no-op, and generic-webhook secret authentication into a pre-existing URL-provider-selected route without binding the loaded webhook's stored provider; this composition enabled the published bypass.* Do not claim that Claude-authored code originated URL-provider selection or exclusively authored the vulnerability.

### 2. GHSA-75HX session/health surface — KEEP

**Exact objects**

- Candidate [`a597ef5a924ebe17a6a202bbb841965f52328032`](https://github.com/czlonkowski/n8n-mcp/commit/a597ef5a924ebe17a6a202bbb841965f52328032), parent `a4053de998595b4321576ad6a908e65590816ee0`; direct `Generated with Claude Code` and Claude coauthor trailer.
- Exact fix [`ca9d4b3df6419b8338983be98f7940400f78bde3`](https://github.com/czlonkowski/n8n-mcp/commit/ca9d4b3df6419b8338983be98f7940400f78bde3), parent `ff486ea04f0b20460141e5ef2be3d518e1772b80`.
- Annotated vulnerable tag object `21e1e577ad9d69c2ec9d3c1088c7592e9bc97c28` (`v2.47.5`) -> commit `ff486ea04f0b20460141e5ef2be3d518e1772b80`.
- Annotated fixed tag object `06391e8bd1d2a2e23f32db94f39c1018f2548372` (`v2.47.6`) -> commit `4b161b6acbf96120492dea2a6af0f9c72a4a633e`.

The candidate parent-to-child delta adds live `GET /mcp` stream/session handling, unauthenticated `DELETE /mcp` session termination, and `/health` fields including active transport counts and session IDs. The exact fix adds `authLimiter` plus bearer authentication to GET and DELETE, removes sensitive health fields, and deletes the manual test route. Compare confirms candidate is an ancestor of the `2.47.5` git head (`ahead_by=639`), and fix is an ancestor of the fixed tag (`ahead_by=1`).

npm independently reports `n8n-mcp@2.47.5` gitHead `ff486ea...`, integrity `sha512-Bwr3NKTWuQqNk8ZIMgvIwW4+eUFWdV7qJrqXt3yNiT5kXP2qRgbaUuhyWG1f/Mq8aQDEgFXfVirW5g1G1K8m1Q==`; `2.47.6` gitHead `4b161b6...`, integrity `sha512-dgrWgpTVX+u3etzZ/GTHBzWTQMJAR2RDtdco39019cPZxnGC8agX5adyyz2DqgtiHrLCRnLN9Cj+nRkzkarxRw==`. Earlier npm `2.9.1` gitHead `35b4e77...` is also a descendant of the candidate.

**Disposition:** `KEEP`, narrowly as one new session-control/health-disclosure component. Do not generalize it to every historical HTTP authentication defect. Session termination and health metadata share the candidate/fix and advisory identity, so they remain one component.

### 3. GHSA-8G7G caller-controlled API path segments — KEEP

**Exact objects**

- Candidate [`74f05e937fa7d94babe3507510caa17ce17a698c`](https://github.com/czlonkowski/n8n-mcp/commit/74f05e937fa7d94babe3507510caa17ce17a698c), parent `150de3d1c249e518b73d91b8621db2f6a628b1b5`; direct Claude Code marker and trailer.
- Fix [`1cfe9c6bddb4b1634e6e23323c18ea35fd196999`](https://github.com/czlonkowski/n8n-mcp/commit/1cfe9c6bddb4b1634e6e23323c18ea35fd196999), parent `fefa2d9b3908f88ebb060cac28af453c612a7668`.
- Annotated pre-fix tag object `58690c76223a46a66f0c33e0480a9f532bf5a719` (`v2.50.0`) -> `1ca40ce2bdf18b8c88cd571074cec3f61471c7eb`.
- Annotated fixed tag object `0a441d32b1c58aa07d7d018c7d2af40c2ea3c4f4` (`v2.50.1`) -> exact fix `1cfe9c6...`.

The candidate adds the target repository's n8n management API client and MCP tool handlers. Raw caller strings are interpolated into workflow, execution, credential, tag, variable, and related API paths while the client carries `X-N8N-API-KEY`. The exact fix adds bounded `encodeApiPathSegment`, rejects traversal/query/fragment encodings, and applies it across the affected path parameters.

Candidate-to-`v2.50.0` compare returned `status=ahead`, merge base equal to the candidate, `ahead_by=890`; npm `2.50.0` has gitHead `1ca40ce...`; npm `2.50.1` has gitHead equal to the fix.

Containment wording needs one small correction. The candidate subject says `v2.6.0`, but `https://registry.npmjs.org/n8n-mcp/2.6.0` returned 404. npm `2.7.9` exists with gitHead `6b49b000...`, and annotated tag `v2.7.9` points through tag object `daeb876...` to commit `0f9f8d41...`; both commits are candidate descendants. Therefore claim only **candidate-bearing no later than 2.7.9**, not a verified npm 2.6.0 release.

**Disposition:** `KEEP` as direct target-repository integration/new-surface origin. The commit says it integrates another project; no claim is made about authorship of that upstream source.

### 4. GHSA-8G7G redirect-following trigger SSRF — KEEP

**Exact objects and topology**

- PR [`#460`](https://github.com/czlonkowski/n8n-mcp/pull/460), base `ddf95567591a5b0a56e9df393e368969536fce3e`, squash carrier `33690c5650e680b2c9cfbae75cac81a761742389`.
- Atomic member [`3f698cc62d2f820f83713a51fce23f71e9cc4654`](https://github.com/czlonkowski/n8n-mcp/commit/3f698cc62d2f820f83713a51fce23f71e9cc4654), parent equal to the PR base; direct Claude marker. It adds form/chat URL validation followed by Axios requests without `maxRedirects: 0`.
- Atomic member [`7d81204aecb58ba09c70497ae643b886f0d9edc4`](https://github.com/czlonkowski/n8n-mcp/commit/7d81204aecb58ba09c70497ae643b886f0d9edc4), parent `3f698cc...`; direct Claude marker. It adds the same initial-URL-only guard to the legacy webhook sibling.
- Marked carrier [`33690c5650e680b2c9cfbae75cac81a761742389`](https://github.com/czlonkowski/n8n-mcp/commit/33690c5650e680b2c9cfbae75cac81a761742389), parent `ddf95567591a5b0a56e9df393e368969536fce3e`.
- Exact fix `1cfe9c6...` adds `maxRedirects: 0` in webhook, form, and chat request sinks.
- Annotated `v2.28.0` tag object `263a3b4206aeb594ba7d41327c65306110a88929` -> carrier `33690c5...`; npm `2.28.0` gitHead equals that carrier.

The carrier is an ancestor of pre-fix `v2.50.0` (`ahead_by=132`), and the fix is the exact `v2.50.1` tag/npm gitHead. The advisory identifies the same invariant: a URL passes the initial allow/deny check, follows a redirect to a forbidden host, and returns the response to an authenticated caller.

**Disposition:** `KEEP` once. Form and chat are the marked new-surface contributor; the webhook is the same-mechanism sibling and not a second component. Do not also count `7d81204...` as a separate incomplete-remediation row: its initial-only guard sits inside the already admitted AI-origin SSRF lineage and shares the advisory, sink invariant, and final fix.

### 5. GHSA-8G7G mutation telemetry — KEEP as incomplete remediation only

**Exact objects and topology**

- Human root [`61fdd6433a4ae0a404772a0f6a53f928e4606c5e`](https://github.com/czlonkowski/n8n-mcp/commit/61fdd6433a4ae0a404772a0f6a53f928e4606c5e), parent `77151e013ee3fea15be34f009594bcde81edf8e2`; no AI marker. It creates raw `operations`, `validationBefore`, `validationAfter`, and `mutationError` storage.
- Marked partial remediation [`7ac748e73f69bcd3b43d0a321b38d79078013b91`](https://github.com/czlonkowski/n8n-mcp/commit/7ac748e73f69bcd3b43d0a321b38d79078013b91), parent `6719628350972ebdbc347ef4406b029a712c3f24`; direct Claude marker and trailer. It sanitizes before/after workflow copies but leaves the four residual fields raw in the record.
- PR [`#419`](https://github.com/czlonkowski/n8n-mcp/pull/419), base `77151e013ee3fea15be34f009594bcde81edf8e2`, squash carrier [`99c5907b71a6c3228d345a2f0879cd893f30cd7e`](https://github.com/czlonkowski/n8n-mcp/commit/99c5907b71a6c3228d345a2f0879cd893f30cd7e), itself marked and containing the partial state.
- Exact fix `1cfe9c6...` sanitizes operations, both validation objects, and mutation errors via `sanitizeTelemetryObject` before storage.
- Annotated `v2.22.16` tag object `39fe8220cc4676404e822a0d92ae2b048c9d2315` -> carrier `99c5907...`; npm `2.22.16` gitHead equals the carrier.

The PR description claims “complete data privacy” and “comprehensive sanitization,” but the carrier code stores the residual fields raw. That first-party prose/code contradiction is precisely why the role must remain incomplete remediation. Carrier-to-pre-fix `v2.50.0` compare returned merge base equal to the carrier and `ahead_by=156`; npm `2.50.1` binds the later closure to exact fix `1cfe9c6...`.

**Disposition:** `KEEP` only as released `AI_INCOMPLETE_REMEDIATION`. Explicitly preserve the human root; do not rewrite the row as `STRICT_CAUSAL` and do not count both the human root and AI partial remediation as separate accepted components.

## Deduplication and claim boundary

1. Count AutoGPT's CVE and GHSA once.
2. Count GHSA-75HX's session termination plus health disclosure as one bounded component because the same candidate/fix pair and one advisory identity cover them.
3. Count GHSA-8G7G as one public-ID row with three mechanism assessments.
4. Count redirect-following across webhook/form/chat once. The marked PR members explain sibling history; they do not multiply the mechanism count.
5. Count telemetry once and only in the incomplete-remediation role. The human root remains explicit.
6. A commit can support distinct path-segment and redirect mechanisms, but shared repository/advisory context alone is not a reason to merge those different input/sink/invariant pairs.
7. Commit trailers establish an explicit AI coauthor signal, not exclusive AI authorship, percentage attribution, or autonomous generation.
8. No build, test suite, runtime exploit, or model inference was used as causal proof in this replay. The evidence is advisory identity, immutable parent/candidate/fix deltas, PR topology, ancestry, and release containment.

## Exact read commands and URLs

No authorization header or credential was printed or stored. `gh api` used the existing credential helper internally. Representative exact commands used for every object were:

```zsh
# Live first-party advisory state.
gh api repos/Significant-Gravitas/AutoGPT/security-advisories/GHSA-349p-3c3r-8mjr
gh api repos/czlonkowski/n8n-mcp/security-advisories/GHSA-75hx-xj24-mqrw
gh api repos/czlonkowski/n8n-mcp/security-advisories/GHSA-8g7g-hmwm-6rv2

# AutoGPT commits, parent state, tags, releases, and ancestry via GitHub compare.
gh api repos/Significant-Gravitas/AutoGPT/commits/3b0d43230901ef353c39cc3bbac36e6d81f049dc
gh api repos/Significant-Gravitas/AutoGPT/commits/7f08a16deed57c93654356058667293534de6994
gh api repos/Significant-Gravitas/AutoGPT/commits/e877391a55f0f834c43ab00eb3a59f60c852f428
gh api repos/Significant-Gravitas/AutoGPT/commits/646dd5b8cfad1206e92ec7bcc3b8312657e2a92e
gh api 'repos/Significant-Gravitas/AutoGPT/contents/autogpt_platform/backend/backend/api/features/integrations/router.py?ref=e877391a55f0f834c43ab00eb3a59f60c852f428'
gh api repos/Significant-Gravitas/AutoGPT/git/ref/tags/autogpt-platform-beta-v0.6.65
gh api repos/Significant-Gravitas/AutoGPT/git/ref/tags/autogpt-platform-beta-v0.6.70
gh api repos/Significant-Gravitas/AutoGPT/releases/tags/autogpt-platform-beta-v0.6.65
gh api repos/Significant-Gravitas/AutoGPT/releases/tags/autogpt-platform-beta-v0.6.70
gh api repos/Significant-Gravitas/AutoGPT/compare/7f08a16deed57c93654356058667293534de6994...646dd5b8cfad1206e92ec7bcc3b8312657e2a92e
gh api repos/Significant-Gravitas/AutoGPT/compare/646dd5b8cfad1206e92ec7bcc3b8312657e2a92e...c45b9e35817a2037fadeaa47924cf41681573c09

# n8n-mcp PR member topology and immutable commits.
gh api repos/czlonkowski/n8n-mcp/pulls/460
gh api repos/czlonkowski/n8n-mcp/pulls/460/commits --paginate
gh api repos/czlonkowski/n8n-mcp/pulls/419
gh api repos/czlonkowski/n8n-mcp/pulls/419/commits --paginate
gh api repos/czlonkowski/n8n-mcp/commits/a597ef5a924ebe17a6a202bbb841965f52328032
gh api repos/czlonkowski/n8n-mcp/commits/ca9d4b3df6419b8338983be98f7940400f78bde3
gh api repos/czlonkowski/n8n-mcp/commits/74f05e937fa7d94babe3507510caa17ce17a698c
gh api repos/czlonkowski/n8n-mcp/commits/3f698cc62d2f820f83713a51fce23f71e9cc4654
gh api repos/czlonkowski/n8n-mcp/commits/7d81204aecb58ba09c70497ae643b886f0d9edc4
gh api repos/czlonkowski/n8n-mcp/commits/33690c5650e680b2c9cfbae75cac81a761742389
gh api repos/czlonkowski/n8n-mcp/commits/61fdd6433a4ae0a404772a0f6a53f928e4606c5e
gh api repos/czlonkowski/n8n-mcp/commits/7ac748e73f69bcd3b43d0a321b38d79078013b91
gh api repos/czlonkowski/n8n-mcp/commits/99c5907b71a6c3228d345a2f0879cd893f30cd7e
gh api repos/czlonkowski/n8n-mcp/commits/1cfe9c6bddb4b1634e6e23323c18ea35fd196999

# Annotated tags were dereferenced in two steps; example forms.
gh api repos/czlonkowski/n8n-mcp/git/ref/tags/v2.47.6
gh api repos/czlonkowski/n8n-mcp/git/tags/06391e8bd1d2a2e23f32db94f39c1018f2548372
gh api repos/czlonkowski/n8n-mcp/git/ref/tags/v2.50.1
gh api repos/czlonkowski/n8n-mcp/git/tags/0a441d32b1c58aa07d7d018c7d2af40c2ea3c4f4

# Exact releases and registry version objects.
gh api repos/czlonkowski/n8n-mcp/releases/tags/v2.47.5
gh api repos/czlonkowski/n8n-mcp/releases/tags/v2.47.6
gh api repos/czlonkowski/n8n-mcp/releases/tags/v2.22.16
gh api repos/czlonkowski/n8n-mcp/releases/tags/v2.28.0
gh api repos/czlonkowski/n8n-mcp/releases/tags/v2.50.0
gh api repos/czlonkowski/n8n-mcp/releases/tags/v2.50.1
curl -fsSL -H 'User-Agent: ai-slop-primary-audit' https://registry.npmjs.org/n8n-mcp/2.7.9
curl -fsSL -H 'User-Agent: ai-slop-primary-audit' https://registry.npmjs.org/n8n-mcp/2.22.16
curl -fsSL -H 'User-Agent: ai-slop-primary-audit' https://registry.npmjs.org/n8n-mcp/2.28.0
curl -fsSL -H 'User-Agent: ai-slop-primary-audit' https://registry.npmjs.org/n8n-mcp/2.47.5
curl -fsSL -H 'User-Agent: ai-slop-primary-audit' https://registry.npmjs.org/n8n-mcp/2.47.6
curl -fsSL -H 'User-Agent: ai-slop-primary-audit' https://registry.npmjs.org/n8n-mcp/2.50.0
curl -fsSL -H 'User-Agent: ai-slop-primary-audit' https://registry.npmjs.org/n8n-mcp/2.50.1
```

Fresh API responses were not persisted because this shard owns exactly this notes file. Therefore live response bodies have no local content hash; immutable Git object IDs, annotated-tag targets, npm integrity fields, observation cutoff, and the hashed local lead inputs are the replay anchors.
