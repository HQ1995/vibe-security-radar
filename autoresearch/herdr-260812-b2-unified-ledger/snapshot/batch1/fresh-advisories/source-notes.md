# Fresh official-advisory delta: source pass

Snapshot date: 2026-08-12  
Acquisition window: 2026-08-12T16:19:59Z–2026-08-12T16:25:17Z  
Requested publication/update lower bound: 2026-08-10T00:00:00Z  
Scope: first-party GitHub reviewed advisories and CVE Services/cvelistV5 records; exact public identity, mechanism, fix lineage, released containment, and explicit AI-origin routing only.  
Status: official-source pass, followed by independent AutoGPT lineage closure recorded below.

## Snapshot boundary and frozen exclusion set

The shared checkout was treated as volatile and read-only. The newest relevant local adjudications were read first and frozen by file hash:

| Frozen input | SHA-256 |
|---|---|
| `docs/AUDIT-CONSOLIDATED-LEDGER-156-2026-08-11.md` | `2fb6210a10802c1d9570caeb88dc8af08b1f26721c860deda005df980bf3f687` |
| `docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md` | `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md` | `a7dd3db373af0fae98c10f8c96c58180cf80fc132fb6fb53fedbd44f3aae22c2` |
| `docs/RESEARCH-PUBLIC-ID-FIRST-PARTY-CLOSURE-2026-08-11.md` | `2492294dea07939a0129db690a25eb438755eead3fdfa4edfc7c12f568535112` |
| `docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` | `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` |

The first four documents contained 256 unique public CVE/GHSA strings and 160 alias strings under the bounded extraction used here. Exact searches for every ranked public ID, repository, and fix SHA below returned no represented row. The exclusion rule was nevertheless semantic: an absent ID was not novel if a frozen row already had the same repository, mechanism, and fix. No ranked row below matched that triple.

Commands used for the freeze (read-only):

```zsh
sha256sum \
  docs/AUDIT-CONSOLIDATED-LEDGER-156-2026-08-11.md \
  docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md \
  docs/RESEARCH-PUBLIC-ID-FIRST-PARTY-CLOSURE-2026-08-11.md \
  docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md

rg -io 'CVE-[0-9]{4}-[0-9]{4,}|GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}' \
  docs/AUDIT-CONSOLIDATED-LEDGER-156-2026-08-11.md \
  docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md
```

## Official-feed acquisition and closure

### GitHub reviewed advisories

The bounded published query was:

```text
GET https://api.github.com/advisories?per_page=100&type=reviewed&sort=published&direction=desc&published=2026-08-10T00%3A00%3A00Z..2026-08-12T23%3A59%3A59Z
```

At approximately `2026-08-12T16:20:35Z` it returned HTTP 200, 21 reviewed advisories, no `Link: ... rel="next"`, and ETag:

```text
W/"ab4c3c10c95eec65286f539aba63cbf33bd39d2f0eed50706e2dfae14e9cceea"
```

The corresponding materially-updated query was:

```text
GET https://api.github.com/advisories?per_page=100&type=reviewed&sort=updated&direction=desc&updated=2026-08-10T00%3A00%3A00Z..2026-08-12T23%3A59%3A59Z
```

It returned HTTP 200 with no next-page link and ETag:

```text
W/"787c7b35ea1c3e58eb852565051c593905b5bd7354dbe892f5703e4012ff13b4"
```

Negative truncation control: the same date window without `type=reviewed` filled the 100-row page and supplied a next-page link. It was intentionally not paged because it mixed unreviewed/noisy rows and the campaign forbade broad API loops. Later GitHub core requests reached HTTP 403 rate limiting; bounded public `.patch` endpoints and official advisory/CVE references were used as fallback. Therefore this is closed for the two reviewed queries at their ETags, **not** exhaustive across every GitHub advisory type.

### CVE Services / official cvelistV5 delta

Acquisition began at `2026-08-12T16:20:08Z`. The official mechanism was `cves/deltaLog.json` plus cumulative UTC-hour release deltas from each midnight. No repository clone or shared cache was mutated.

| Official artifact | Snapshot/hash |
|---|---|
| [`cves/deltaLog.json`](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json) | `fetchTime=2026-08-12T16:16:43.868Z`; SHA-256 `5f50bf89d8c252bdd969caf9ad38d7f648b34c20e6ddab1c29c8cbf0564024c0`; 20,202,708 bytes |
| cvelistV5 delta README | SHA-256 `c9ce682b3ba6b155ec713c0b989f2ba932a25ef2e950bf6a7f683bdca2de8039` |
| 2026-08-10 2300Z cumulative release delta | SHA-256 `a8d1b348190fae8eed33f0f101fb4d9e31ef37806ca2579c640007a857084bf6` |
| 2026-08-11 2300Z cumulative release delta | SHA-256 `cfbf0d17c7573dfa0fc9909cfc1feca6b26344fab7af29fbf0fcfae68afb779f` |
| 2026-08-12 1500Z cumulative release delta | SHA-256 `8b09a867bcbf060847f13c00b5a6b17e0ca02888b26dfcd47ddb7463e8378875` |
| Ordered raw bundle for 220 IDs with `dateUpdated >= 2026-08-12T15:00:00Z` | acquired `2026-08-12T16:25:17Z`; 0 failures; 2,034,548 bytes; SHA-256 `02e509b8745c0b4ceb09f3668ef94bf0da27ef23e9d3cd39f3346e6a3fe876ba` |

The three release packages produced 4,267 unique changed records, including 1,765 newly published and 79 rejected records. The later 220-record raw fetch closes post-1500Z changes through 16:25:17Z. Because `main` is a moving raw ref and no local clone was made, the artifact hashes and fetch times—not an inferred Git commit—are the snapshot identity.

Exact request forms:

```zsh
curl -fsSL https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json
curl -fsSL https://cveawg.mitre.org/api/cve/CVE-YYYY-NNNNN
curl -fsSL https://github.com/OWNER/REPO/commit/SHA.patch
curl -fsSL https://github.com/Significant-Gravitas/AutoGPT/pull/13135.patch
```

## Ranked novel rows

Ranking favors exact same-mechanism candidate/fix lineage and released containment. “AI marker” means explicit commit/PR metadata or text; product names, repository names, bots that merely reviewed a PR, and LLM/MCP functionality are not origin evidence.

### 1. AutoGPT webhook provider-confusion signature bypass — publication-grade candidate

- Identity: [`CVE-2026-72922`](https://cveawg.mitre.org/api/cve/CVE-2026-72922), [`GHSA-349p-3c3r-8mjr`](https://github.com/advisories/GHSA-349p-3c3r-8mjr); `Significant-Gravitas/AutoGPT`; published/updated `2026-08-11T14:32Z`.
- Mechanism: the URL-selected provider could differ from the webhook's stored provider; provider-specific `verify_signature`, including a default no-op, let a request be verified under the wrong rules.
- Candidate: PR [`#13135`](https://github.com/Significant-Gravitas/AutoGPT/pull/13135), first commit [`3b0d43230901ef353c39cc3bbac36e6d81f049dc`](https://github.com/Significant-Gravitas/AutoGPT/commit/3b0d43230901ef353c39cc3bbac36e6d81f049dc), and mainline squash carrier [`7f08a16deed57c93654356058667293534de6994`](https://github.com/Significant-Gravitas/AutoGPT/commit/7f08a16deed57c93654356058667293534de6994), each explicitly `Co-authored-by: Claude Opus 4.7`. The carrier adds provider-overridable `verify_signature`, its default no-op, and invocation through the URL-selected manager without checking the stored provider. PR patch SHA-256: `c5362ec7c0d19076f99c31d4db7bfcff2643fefb5c8f30abe3ea1697b2b51cc9`.
- Fix: PR [`#13559`](https://github.com/Significant-Gravitas/AutoGPT/pull/13559), commit [`646dd5b8cfad1206e92ec7bcc3b8312657e2a92e`](https://github.com/Significant-Gravitas/AutoGPT/commit/646dd5b8cfad1206e92ec7bcc3b8312657e2a92e), which checks the stored webhook provider against the URL provider before verification. It explicitly credits Claude Opus 4.8. Fix patch SHA-256: `404c9ed882c4facfb63e6ce74efec99265ec74406114ae213c9608ff6189b4b1`.
- Containment: affected `<0.6.70`; official release [`autogpt-platform-beta-v0.6.70`](https://github.com/Significant-Gravitas/AutoGPT/releases/tag/autogpt-platform-beta-v0.6.70). Official CVE response SHA-256: `eeb187b4cfce561e1d32e8c295e5646fd897a8b78be69b5b5a86adc31b96a99c`.
- AI status: **publication-grade candidate**. Independent git closure returned `0` for `git merge-base --is-ancestor 7f08a16deed57c93654356058667293534de6994 646dd5b8cfad1206e92ec7bcc3b8312657e2a92e`, with 121 intervening commits. The atomic PR commit is not itself a direct ancestor because GitHub landed a squash carrier; the carrier has the same explicit Claude trailer and the mechanism-creating delta, so no provenance is inferred across an unmarked squash.

### 2. Typebot OpenAI-key exfiltration through attacker-selected provider — fix-side AI only

- Identity: [`CVE-2026-48766`](https://cveawg.mitre.org/api/cve/CVE-2026-48766), [`GHSA-gc3v-9whw-6wjh`](https://github.com/advisories/GHSA-gc3v-9whw-6wjh); `baptisteArno/typebot.io`; published `2026-08-11T15:55Z`.
- Mechanism: a guest could select an attacker `baseUrl`/model-list endpoint and cause a stored OpenAI API key to be sent to it.
- Fix: PR [`#2459`](https://github.com/baptisteArno/typebot.io/pull/2459), commit [`7ae4c007d0987d2ca907b47e1b7418db62b8a157`](https://github.com/baptisteArno/typebot.io/commit/7ae4c007d0987d2ca907b47e1b7418db62b8a157); `<3.17.0` to [`v3.17.0`](https://github.com/baptisteArno/typebot.io/releases/tag/v3.17.0).
- AI status: the fix explicitly credits Claude Opus 4.6. Parent-state blame crosses migration `a15673f5a62f9130c290d5bac3464d19c5015158` and reaches original custom-provider commit [`27a5f4eb74f6366181c6792e3efbf615b0af79bf`](https://github.com/baptisteArno/typebot.io/commit/27a5f4eb74f6366181c6792e3efbf615b0af79bf), which exposed no explicit AI marker. **Fix-assisted is not origin; reject as AI-causal on current evidence.**

### 3. Typebot transcription URL SSRF — distinct mechanism, fix-side AI only

- Identity: [`CVE-2026-48762`](https://cveawg.mitre.org/api/cve/CVE-2026-48762), [`GHSA-h3v3-c6cq-q763`](https://github.com/advisories/GHSA-h3v3-c6cq-q763); same repository but a distinct SSRF mechanism; published `2026-08-11T20:40Z`.
- Mechanism: the OpenAI transcription handler fetched a user-controlled URL without a safe fetcher boundary.
- Fix: PR [`#2428`](https://github.com/baptisteArno/typebot.io/pull/2428), commit [`a33051755f9e734596498851d5f61bd2e171f192`](https://github.com/baptisteArno/typebot.io/commit/a33051755f9e734596498851d5f61bd2e171f192); `<3.16.0` to [`v3.16.0`](https://github.com/baptisteArno/typebot.io/releases/tag/v3.16.0).
- AI status: the fix explicitly credits Claude Opus 4.6. The vulnerable `fetch(options.url)` line blames to [`c8ee003e56e596c642aebc0f216d9dda004bdee7`](https://github.com/baptisteArno/typebot.io/commit/c8ee003e56e596c642aebc0f216d9dda004bdee7), which exposed no explicit AI marker. **Fix-side control; AI origin `UNKNOWN`/not evidenced.**

### 4. Claude Code Templates Studio unauthenticated RCE — fix-side AI only

- Identity: [`CVE-2026-73222`](https://cveawg.mitre.org/api/cve/CVE-2026-73222), [`GHSA-79wm-x847-7cvg`](https://github.com/advisories/GHSA-79wm-x847-7cvg); `davila7/claude-code-templates`; published `2026-08-11T18:27Z`.
- Mechanism: exposed Studio server endpoints enabled unauthenticated command execution; wildcard CORS enlarged the remote attack surface.
- Fix: [`bc4618b07232633c1c0aac12a43e436268d31783`](https://github.com/davila7/claude-code-templates/commit/bc4618b07232633c1c0aac12a43e436268d31783), explicitly crediting Claude Opus; `<1.29.4` to `1.29.4`. Official CVE response SHA-256 `34541db7dda2cb2dfd67b8696f1368772f3a004fef22f5b4e02cb6b12ccdadc9`; fix patch SHA-256 `fc849642965a338d5ba3fe719fca5fe7130ddd134ebfc1b146d3e1107d11699a`.
- AI status: origin trace found server-introduction [`777b3db79e0bac6d5d7ab74e4c51e0b430e605ef`](https://github.com/davila7/claude-code-templates/commit/777b3db79e0bac6d5d7ab74e4c51e0b430e605ef) and wildcard-CORS [`4d911106d72fece34861fe107da7509b2d019f72`](https://github.com/davila7/claude-code-templates/commit/4d911106d72fece34861fe107da7509b2d019f72), neither with explicit AI attribution. Repository and “AITMPL Cloud Agent” branding are routing only. **Reject as AI-causal on current evidence.**

### 5. Goose review runs attacker-controlled git hook/config before approval

- Identity: [`CVE-2026-72718`](https://cveawg.mitre.org/api/cve/CVE-2026-72718), [`GHSA-r5pp-p5r8-466r`](https://github.com/advisories/GHSA-r5pp-p5r8-466r); `aaif-goose/goose`; published `2026-08-10T15:33Z`, updated `17:00Z`.
- Mechanism: `goose review` invoked git without neutralizing attacker `.git/config` such as `core.fsmonitor`, allowing command execution before model/tool approval.
- Fix/containment: [`f8b5b7ba1fe6d006ccf6942f6b85a1bae985a2de`](https://github.com/aaif-goose/goose/commit/f8b5b7ba1fe6d006ccf6942f6b85a1bae985a2de); `<1.44.0` to [`v1.44.0`](https://github.com/aaif-goose/goose/releases/tag/v1.44.0).
- AI status: no explicit origin marker recovered. “AI agent” branding describes the product, not authorship. **Routing only / origin `UNKNOWN`.**

### 6. Discourse private AI-bot reply stream eavesdropping

- Identity: [`CVE-2026-72726`](https://cveawg.mitre.org/api/cve/CVE-2026-72726), [`GHSA-gw88-2jw8-jf2h`](https://github.com/advisories/GHSA-gw88-2jw8-jf2h); `discourse/discourse`; published `2026-08-10T16:05Z`, updated `16:57Z`.
- Mechanism: authorization on the AI bot streaming channel allowed another user to observe a private reply stream.
- Fixes: [`01faa889830f56e02fba2f6c1731811d319c5e81`](https://github.com/discourse/discourse/commit/01faa889830f56e02fba2f6c1731811d319c5e81), [`1fb2026eb8004dfeb12553014cc534dfd8083fbc`](https://github.com/discourse/discourse/commit/1fb2026eb8004dfeb12553014cc534dfd8083fbc), [`9247666f8359f3cf214b8aea3d396e8a8237ed38`](https://github.com/discourse/discourse/commit/9247666f8359f3cf214b8aea3d396e8a8237ed38), and [`b56b98232aa4dad4a30500a65e31db0c9080c8f5`](https://github.com/discourse/discourse/commit/b56b98232aa4dad4a30500a65e31db0c9080c8f5).
- Containment: official record names fixed endpoints `2026.1.6`, `2026.5.2`, `2026.6.1`, and `2026.7.0`; it does not provide a release URL.
- AI status: AI feature context only; no explicit candidate marker recovered. **Origin `UNKNOWN`.**

### 7. Firecrawl JSON Schema `$ref` file read/SSRF

- Identity: [`CVE-2026-72904`](https://cveawg.mitre.org/api/cve/CVE-2026-72904), [`GHSA-3p54-jg6f-68r8`](https://github.com/advisories/GHSA-3p54-jg6f-68r8); `firecrawl/firecrawl`; published `2026-08-10T20:42Z`, updated `2026-08-11T14:28Z`.
- Mechanism: attacker-controlled JSON Schema `$ref` resolution enabled arbitrary local-file reads and SSRF.
- Fix/containment: [`053630fc5203df91b707a6a523e33db5896a1ee8`](https://github.com/firecrawl/firecrawl/commit/053630fc5203df91b707a6a523e33db5896a1ee8); `<2.11.32` to `2.11.32` (no release link in the CVE record).
- AI status: no explicit origin marker recovered; product branding is not evidence. **Origin `UNKNOWN`.**

### 8. sub2api Responses subpath traversal relays pooled credentials

- Identity: [`CVE-2026-73079`](https://cveawg.mitre.org/api/cve/CVE-2026-73079), [`GHSA-vrxq-qm4h-6hgg`](https://github.com/advisories/GHSA-vrxq-qm4h-6hgg); `Wei-Shaw/sub2api`; published `2026-08-11T15:54Z`, updated `16:42Z`.
- Mechanism: traversal in the Responses subpath could relay requests to unintended upstream endpoints using pooled credentials.
- Fix/containment: PR [`#5137`](https://github.com/Wei-Shaw/sub2api/pull/5137), commit [`017f6bbd5edffea0639ef3c84c0391161983f1f3`](https://github.com/Wei-Shaw/sub2api/commit/017f6bbd5edffea0639ef3c84c0391161983f1f3); `>=0.1.135,<0.1.169` to [`v0.1.169`](https://github.com/Wei-Shaw/sub2api/releases/tag/v0.1.169).
- AI status: no explicit origin marker recovered; AI-gateway functionality is routing only. **Origin `UNKNOWN`.**

### 9. Activepieces MCP validator SSRF

- Identity: [`CVE-2026-73082`](https://cveawg.mitre.org/api/cve/CVE-2026-73082), [`GHSA-7qx9-q4xx-rh59`](https://github.com/advisories/GHSA-7qx9-q4xx-rh59); `activepieces/activepieces`; published `2026-08-11T16:30Z`, updated `17:53Z`.
- Mechanism: MCP validation fetched attacker-controlled targets without a sufficient network boundary.
- Fix/containment: PR [`#12721`](https://github.com/activepieces/activepieces/pull/12721), commit [`d385079cf4a9f35ddf61ba68ecda6ac8d64cf9e1`](https://github.com/activepieces/activepieces/commit/d385079cf4a9f35ddf61ba68ecda6ac8d64cf9e1); `<0.82.0` to `0.82.0`.
- AI status: no explicit candidate marker recovered. A `.claude/rules` file and MCP/product context are not provenance. **Origin `UNKNOWN`.**

### 10. Activepieces reflected XSS in OAuth redirect — distinct mechanism

- Identity: [`CVE-2026-73084`](https://cveawg.mitre.org/api/cve/CVE-2026-73084), [`GHSA-hc39-cm5m-q8g7`](https://github.com/advisories/GHSA-hc39-cm5m-q8g7); same repository but distinct from row 9; published `2026-08-11T16:35Z`.
- Mechanism: attacker-controlled OAuth redirect state was reflected into an executable browser context.
- Fix/containment: [`8be4c8d5e6a79ccbaa74815027432a3c8c311385`](https://github.com/activepieces/activepieces/commit/8be4c8d5e6a79ccbaa74815027432a3c8c311385); `<0.83.0` to `0.83.0`.
- AI status: no explicit candidate marker recovered. **Origin `UNKNOWN`.**

### 11. CVAT request-slot DoS and predictable-ID authorization — shared carrier, two mechanisms

- Identity: [`CVE-2026-73219`](https://cveawg.mitre.org/api/cve/CVE-2026-73219) / [`GHSA-7xhx-3q27-xvcx`](https://github.com/advisories/GHSA-7xhx-3q27-xvcx), and [`CVE-2026-73221`](https://cveawg.mitre.org/api/cve/CVE-2026-73221) / [`GHSA-m7p7-6w4m-886p`](https://github.com/advisories/GHSA-m7p7-6w4m-886p); `cvat-ai/cvat`; published `2026-08-11T17:50Z` and `18:22Z`.
- Mechanisms: request-slot exhaustion DoS and predictable-ID authorization bypass are distinct even though they share a fix carrier.
- Fix/containment: PR [`#10964`](https://github.com/cvat-ai/cvat/pull/10964), commit [`20a1076a0b9de47e067b121e40f16d66d373b3f7`](https://github.com/cvat-ai/cvat/commit/20a1076a0b9de47e067b121e40f16d66d373b3f7); `>=2.17,<2.72` to [`v2.72.0`](https://github.com/cvat-ai/cvat/releases/tag/v2.72.0).
- AI status: repository name is branding, not an author marker; no explicit candidate marker recovered. **Two semantic components, shared-fix grouping only; origins `UNKNOWN`.**

### 12. SeaweedFS unauthenticated SSRF — strong official non-AI control

- Identity: [`CVE-2026-73080`](https://cveawg.mitre.org/api/cve/CVE-2026-73080), [`GHSA-87fv-vqqr-m4jr`](https://github.com/advisories/GHSA-87fv-vqqr-m4jr); `seaweedfs/seaweedfs`.
- Mechanism: an unauthenticated endpoint could be used to issue server-side requests to attacker-selected destinations.
- Fix/containment: PR [`#9441`](https://github.com/seaweedfs/seaweedfs/pull/9441), commit [`69da20bdaec923e5a43d8aa71bf3c0a2051fc019`](https://github.com/seaweedfs/seaweedfs/commit/69da20bdaec923e5a43d8aa71bf3c0a2051fc019); patched in `4.24` per the reviewed GitHub advisory.
- AI status: CodeRabbit/Gemini review-bot activity on a PR does not establish vulnerable-code authorship; the fix is human-authored on the inspected record. **Non-AI routing control.**

## Explicit duplicates, rejections, BLOCKED, and UNKNOWN controls

| Record/control | Disposition | Reason |
|---|---|---|
| `CVE-2026-69659` | **DUPLICATE / exclude** | Already adjudicated locally as `NOT_AI_CAUSAL`; exact-ID exclusion, not reworked. |
| Winter CMS `CVE-2026-32258` / `GHSA-vgp4-2fc4-qff2` and `CVE-2026-32257` / `GHSA-v7cf-8gh9-gxmj` | **same-mechanism duplicate grouping** | BrandSetting/EditorSetting custom-CSS XSS siblings share exact fix `d28f0b9474af79cfaa80eeb9d691f7a7c4469720`; do not count two causal components merely because two IDs were issued. No AI origin marker recovered. |
| `CVE-2026-72917` / `GHSA-vv8w-wg6r-hq56`, AnythingLLM | **UNKNOWN containment** | Exact fix `61766d06b77b903f66dc4afd8dffb3a39012db14`, but official record says affected through `1.15.0` without an unambiguous first patched release. Product branding is not origin. |
| `CVE-2026-73068` / `GHSA-h47x-ffhc-xqh8`, ToolJet | **BLOCKED / schema conflict** | PR `#17298`, fix `4c1dbef7487354bd4a2b5e1c633381ea783bf879`, and release `v3.20.207-lts` exist, but the affected-version object literally marks `3.20.207-lts` affected while prose calls it fixed. Do not assert released containment. |
| `CVE-2026-73032`, PapersGPT | **BLOCKED** | PR `#155`, fix `094134...`, affected through `0.6.1`, but no released containment in the inspected official record. |
| `CVE-2026-73034`, DB-GPT | **BLOCKED** | Exact fix begins `e0c741...`, affected through `0.8.1`, but no released containment in the inspected official record. |
| `CVE-2026-52776` / `GHSA-h47f-gmjp-m7rr`, compliance-trestle | **BLOCKED** | Exact SSRF fix `d107cd16efe8eb15d46be3c1d97f1ec73d32447c`; advisory reports affected `<=4.0.3` and patched versions `None`. |
| Intel `CVE-2026-20755`, `20903`, `21387`, `21400`, `27765`, `28707` | **BLOCKED / routing only** | Materially updated 2026-08-12 around 15:21–15:47Z. Intel advisory identities exist and four records give version containment, but the official CVE records do not provide repository-level exact fix lineage. AI product names do not establish causality. |
| n8n, Cursor, Microsoft Copilot fresh records | **BLOCKED / UNKNOWN** | No exact public candidate/fix lineage in the inspected official records. |

Ten fresh Linux records—`CVE-2026-68241`, `68242`, `68243`, `68244`, `68247`, `68248`, `68253`, `68254`, `68265`, and `68269`—are useful **AI-discovery positive / AI-origin negative** controls. Their first-party Linux commits state that AI-assisted static analysis discovered the issues and Intel Product Security confirmed them. Discovery is not vulnerable-code authorship, so none is promoted as an AI-origin candidate.

## Result and claim boundary

- **Novel official records routed:** 12 ranked rows/groups, representing 13 semantic mechanisms because the shared CVAT carrier fixes two distinct mechanisms.
- **Strong AI-causal candidate:** 1 (`CVE-2026-72922` AutoGPT), with explicit candidate-side and fix-side Claude coauthor metadata, a same-mechanism reversal, and closed carrier-to-fix ancestry.
- **Confirmed publication-grade additions:** 1 candidate row for downstream strict-ledger admission; this shard does not edit that shared ledger.
- **Fix-side AI controls:** Typebot's two distinct mechanisms and Claude Code Templates. An AI-assisted fix does not prove AI-caused vulnerable code.
- **AI-discovery controls:** 10 Linux CVEs; discovery provenance is deliberately not recast as origin provenance.
- **Branding/review-bot controls:** Goose, Discourse AI, Firecrawl, AnythingLLM, AutoGPT product naming, sub2api, MCP, CVAT-AI, CodeRabbit, and Gemini are not authorship evidence by themselves.
- **Coverage boundary:** closed only at the exact CVE artifact hashes/fetch times and the two reviewed GitHub query ETags above. The unreviewed GitHub query was deliberately truncated after one 100-row page, GitHub core later rate-limited, and records published or updated after the stated timestamps are outside the snapshot.
- **Lineage boundary:** exact fixes and released versions are advisory-grade evidence. Candidate causality additionally requires an explicit candidate marker, a parent-to-candidate delta that creates the mechanism, and verified git ancestry to the fix. AutoGPT clears those gates through the marked mainline squash carrier; no other ranked row does.
