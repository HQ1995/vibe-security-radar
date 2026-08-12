# Fresh official-advisory delta

Status: **COMPLETE for the bounded snapshot**  
Cutoff: records published or materially updated at or after `2026-08-10T00:00:00Z`  
Acquisition window: `2026-08-12T16:19:59Z`–`2026-08-12T16:25:17Z`  
Owned output: `/home/hanqing/agents/ai-slop/autoresearch/herdr-260812-fresh-advisories/`

## Outcome

The pass routed 12 novel official-advisory groups covering 13 mechanisms. One row, AutoGPT `CVE-2026-72922`, clears the publication-grade gates used here: exact first-party identity, a marked candidate carrier whose parent-to-candidate delta creates the vulnerable mechanism, verified carrier-to-fix ancestry, same-mechanism reversal, and an official released containment. The other 11 groups remain negative controls or `UNKNOWN`; AI product names, AI-related features, review bots, AI-assisted discovery, and AI-assisted fixes were not treated as vulnerable-code provenance.

This shard did not edit the shared strict ledger. It reports one candidate for downstream admission and preserves all exclusions and blockers.

## Snapshot and exclusion boundary

The checkout was intentionally dirty and shared. All shared inputs were read-only. Work started at the owned directory birth time `2026-08-12T16:17:42Z`; no claim covers upstream changes after the acquisition timestamps above.

The machine-readable freeze is `baseline-freeze.json`, SHA-256 `c0bc0fab38e87d416bdc6c7ebf5febcd54055f240646d2cc9bc4fa88ce08a8b4`. It contains 362 unique public IDs and 184 alias IDs from the newest consolidated, strict, new-component, and strict-ledger inputs:

| Frozen read-only input | SHA-256 |
|---|---|
| `docs/AUDIT-CONSOLIDATED-LEDGER-156-2026-08-11.md` | `2fb6210a10802c1d9570caeb88dc8af08b1f26721c860deda005df980bf3f687` |
| `docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md` | `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md` | `a7dd3db373af0fae98c10f8c96c58180cf80fc132fb6fb53fedbd44f3aae22c2` |
| `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl` | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |

Two newer semantic cross-checks were also read and hashed: `RESEARCH-PUBLIC-ID-FIRST-PARTY-CLOSURE-2026-08-11.md` = `2492294dea07939a0129db690a25eb438755eead3fdfa4edfc7c12f568535112`; `RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` = `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6`.

Every ranked public ID was absent from the freeze. Exact repository, mechanism, and fix searches also found no previously adjudicated equivalent. `CVE-2026-69659`, which was already adjudicated locally, was explicitly excluded rather than reworked.

## Official sources and exact acquisition

### GitHub advisories

The stored reviewed response used GitHub's official global-advisory endpoint with the combined publication/update selector:

```zsh
curl -fsSL -D github-reviewed.headers -G https://api.github.com/advisories \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  --data-urlencode 'type=reviewed' \
  --data-urlencode 'modified=>=2026-08-10' \
  --data-urlencode 'sort=updated' \
  --data-urlencode 'direction=asc' \
  --data-urlencode 'per_page=100' > github-reviewed.json
```

At `2026-08-12T16:20:53Z`, it returned HTTP 200, 48 rows, no next link, ETag `W/"637e746d18d9306cead7204fd3f71f26b4077c693db8084659c5e662e68c6b29"`; body SHA-256 `190a93b9f480b010519f2d44e08663ac65e3465ffb2d359ca0a0f8880722fd9f` and header SHA-256 `748a75462469d656f2a3c72ab1e39bbe83fbe8edcb068cc4b8b9b709fd07782e`.

The unreviewed control was deliberately stopped after two 100-row pages; the second page still had `rel="next"` at `2026-08-10T15:33:45Z`. Those 200 rows are a sample, not exhaustiveness. A bounded shallow clone of the official `github/advisory-database` was frozen at `b84cc9611c792f4bb2aa85b1cc83d79c3e838231` (`2026-08-12T16:20:51Z`) for path-level diagnostics only; it showed 51 reviewed and 2,182 unreviewed changed paths since the cutoff. No full unreviewed API crawl was attempted.

### CVE Services / cvelistV5

```zsh
curl -fsSL https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json \
  > cvelist-deltaLog.json
curl -fsSL https://cveawg.mitre.org/api/cve/CVE-YYYY-NNNNN \
  > cve-api/CVE-YYYY-NNNNN.json
curl -fsSL https://github.com/OWNER/REPO/commit/SHA.patch \
  > patches/CVE-YYYY-NNNNN-fix.patch
```

`deltaLog.json` was frozen at `fetchTime=2026-08-12T16:16:43.868Z`, SHA-256 `5f50bf89d8c252bdd969caf9ad38d7f648b34c20e6ddab1c29c8cbf0564024c0`. This snapshot contains 4,352 unique IDs with a qualifying `dateUpdated`, including 1,903 appearing in `new`. The official repository tip independently captured at `2026-08-12T16:16:47Z` was `9a89101fe9bdd87a3151e16b972edf646e1185dd`; the stored API response SHA-256 is `a3e8019a49b29f61b803d8d5bf0af1a5181cb83b0e5c0a3c088f06a9c47214d6`.

The complete UTC-hour release packages yielded 4,267 unique changed records through the 1500Z package; a final ordered 220-record fetch closed the post-1500Z tail through `16:25:17Z` with zero request failures. Large population counts were routing evidence. Only the 13 exact CVE responses under `cve-api/`, their first-party references, and the corresponding patches were used for ranked claims.

## Ranked novel rows

“AI status” requires explicit authorship/routing metadata on the vulnerable candidate or carrier. Fix-side AI, AI discovery, product branding, and feature context do not satisfy it.

| Rank | Official identity / repository | Mechanism | Exact fix and released containment | AI-origin disposition |
|---:|---|---|---|---|
| 1 | [`CVE-2026-72922`](https://cveawg.mitre.org/api/cve/CVE-2026-72922) / [`GHSA-349p-3c3r-8mjr`](https://github.com/advisories/GHSA-349p-3c3r-8mjr), `Significant-Gravitas/AutoGPT` | URL-selected webhook manager could differ from the stored provider; an inherited no-op verifier bypassed the configured generic-webhook secret. | [`646dd5b8cfad1206e92ec7bcc3b8312657e2a92e`](https://github.com/Significant-Gravitas/AutoGPT/commit/646dd5b8cfad1206e92ec7bcc3b8312657e2a92e); `<0.6.70` → [`autogpt-platform-beta-v0.6.70`](https://github.com/Significant-Gravitas/AutoGPT/releases/tag/autogpt-platform-beta-v0.6.70). | **Publication-grade candidate.** Marked mainline carrier, mechanism delta, ancestry, fix, and release all close; detail below. |
| 2 | [`CVE-2026-48766`](https://cveawg.mitre.org/api/cve/CVE-2026-48766) / `GHSA-gc3v-9whw-6wjh`, `baptisteArno/typebot.io` | Guest-selected `baseUrl` exfiltrated a stored OpenAI key. | `7ae4c007d0987d2ca907b47e1b7418db62b8a157`; `<3.17.0` → `v3.17.0`. | **Reject AI-causal:** fix credits Claude Opus 4.6; origin `27a5f4eb74f6366181c6792e3efbf615b0af79bf` has no explicit marker. |
| 3 | [`CVE-2026-48762`](https://cveawg.mitre.org/api/cve/CVE-2026-48762) / `GHSA-h3v3-c6cq-q763`, Typebot | Transcription fetched an attacker-controlled URL without a safe network boundary. | `a33051755f9e734596498851d5f61bd2e171f192`; `<3.16.0` → `v3.16.0`. | **Fix-side control:** fix credits Claude; blamed origin `c8ee003e56e596c642aebc0f216d9dda004bdee7` does not. |
| 4 | [`CVE-2026-73222`](https://cveawg.mitre.org/api/cve/CVE-2026-73222) / `GHSA-79wm-x847-7cvg`, `davila7/claude-code-templates` | Unauthenticated Studio endpoints enabled command execution; wildcard CORS widened reach. | `bc4618b07232633c1c0aac12a43e436268d31783`; `<1.29.4` → `1.29.4`. | **Reject AI-causal:** Claude-assisted fix only; origins `777b3db79e0bac6d5d7ab74e4c51e0b430e605ef` and `4d911106d72fece34861fe107da7509b2d019f72` are unmarked. |
| 5 | [`CVE-2026-72718`](https://cveawg.mitre.org/api/cve/CVE-2026-72718) / `GHSA-r5pp-p5r8-466r`, `aaif-goose/goose` | Review ran attacker-controlled git hook/config before approval. | `f8b5b7ba1fe6d006ccf6942f6b85a1bae985a2de`; `<1.44.0` → `v1.44.0`. | `UNKNOWN`; AI-agent branding is not authorship. |
| 6 | [`CVE-2026-72726`](https://cveawg.mitre.org/api/cve/CVE-2026-72726) / `GHSA-gw88-2jw8-jf2h`, `discourse/discourse` | Authorization gap exposed another user's private AI-bot reply stream. | `01faa889830f56e02fba2f6c1731811d319c5e81`, `1fb2026eb8004dfeb12553014cc534dfd8083fbc`, `9247666f8359f3cf214b8aea3d396e8a8237ed38`, `b56b98232aa4dad4a30500a65e31db0c9080c8f5`; fixed endpoints `2026.1.6`, `2026.5.2`, `2026.6.1`, `2026.7.0`. | `UNKNOWN`; AI feature context only. |
| 7 | [`CVE-2026-72904`](https://cveawg.mitre.org/api/cve/CVE-2026-72904) / `GHSA-3p54-jg6f-68r8`, `firecrawl/firecrawl` | JSON Schema `$ref` allowed local-file reads and SSRF. | `053630fc5203df91b707a6a523e33db5896a1ee8`; `<2.11.32` → `2.11.32`. | `UNKNOWN`; branding is not provenance. |
| 8 | [`CVE-2026-73079`](https://cveawg.mitre.org/api/cve/CVE-2026-73079) / `GHSA-vrxq-qm4h-6hgg`, `Wei-Shaw/sub2api` | Responses subpath traversal relayed pooled credentials to unintended endpoints. | `017f6bbd5edffea0639ef3c84c0391161983f1f3`; `>=0.1.135,<0.1.169` → `v0.1.169`. | `UNKNOWN`; AI-gateway function is routing only. |
| 9 | [`CVE-2026-73082`](https://cveawg.mitre.org/api/cve/CVE-2026-73082) / `GHSA-7qx9-q4xx-rh59`, `activepieces/activepieces` | MCP validator SSRF. | `d385079cf4a9f35ddf61ba68ecda6ac8d64cf9e1`; `<0.82.0` → `0.82.0`. | `UNKNOWN`; MCP and `.claude/rules` context are not authorship. |
| 10 | [`CVE-2026-73084`](https://cveawg.mitre.org/api/cve/CVE-2026-73084) / `GHSA-hc39-cm5m-q8g7`, Activepieces | OAuth redirect state reflected into executable browser context. | `8be4c8d5e6a79ccbaa74815027432a3c8c311385`; `<0.83.0` → `0.83.0`. | `UNKNOWN`; no candidate marker. |
| 11 | [`CVE-2026-73219`](https://cveawg.mitre.org/api/cve/CVE-2026-73219) + [`CVE-2026-73221`](https://cveawg.mitre.org/api/cve/CVE-2026-73221), `cvat-ai/cvat` | Two mechanisms: request-slot exhaustion DoS and predictable-ID authorization bypass. | Shared carrier `20a1076a0b9de47e067b121e40f16d66d373b3f7`; `>=2.17,<2.72` → `v2.72.0`. | Two semantic components grouped by shared fix; `UNKNOWN`, repository name is branding. |
| 12 | [`CVE-2026-73080`](https://cveawg.mitre.org/api/cve/CVE-2026-73080) / `GHSA-87fv-vqqr-m4jr`, `seaweedfs/seaweedfs` | Unauthenticated SSRF. | `69da20bdaec923e5a43d8aa71bf3c0a2051fc019`; patched in `4.24`. | **Non-AI control:** CodeRabbit/Gemini review activity is not vulnerable-code authorship. |

The exact CVE JSON and fix patches are retained under `cve-api/` and `patches/`. Expanded per-row publication/update times, PRs, release URLs, patch hashes, and origin-blame results are in `source-notes.md`, SHA-256 `3550ba4a65e275a447bd8edd2c9333dd0a43845561c3b974df527d3071eb6b19`.

## AutoGPT claim-grade closure

The official CVE response is SHA-256 `eeb187b4cfce561e1d32e8c295e5646fd897a8b78be69b5b5a86adc31b96a99c`. The PR `#13135` patch is SHA-256 `c5362ec7c0d19076f99c31d4db7bfcff2643fefb5c8f30abe3ea1697b2b51cc9`; the fix patch is `404c9ed882c4facfb63e6ce74efec99265ec74406114ae213c9608ff6189b4b1`.

Candidate lineage:

- Atomic PR commit `3b0d43230901ef353c39cc3bbac36e6d81f049dc` explicitly says `Co-Authored-By: Claude Opus 4.7`.
- GitHub landed marked squash carrier [`7f08a16deed57c93654356058667293534de6994`](https://github.com/Significant-Gravitas/AutoGPT/commit/7f08a16deed57c93654356058667293534de6994), parent `e877391a55f0f834c43ab00eb3a59f60c852f428`. The carrier itself retains `Co-authored-by: Claude Opus 4.7`, so provenance is not inferred across an unmarked squash.
- Its parent-to-carrier diff adds `BaseWebhooksManager.verify_signature`, makes the default a no-op for unsigned providers, and invokes it through the URL-selected manager without comparing the stored webhook provider. That is the mechanism named by the official CVE.
- Exact fix `646dd5b8cfad1206e92ec7bcc3b8312657e2a92e`, parent `3fa88a70efd2f2110506a3aaf0c5997fa915fbb8`, compares `webhook.provider` with the URL provider before verification and explicitly credits Claude Opus 4.8.
- `git merge-base --is-ancestor 7f08a16deed57c93654356058667293534de6994 646dd5b8cfad1206e92ec7bcc3b8312657e2a92e` returned `0`; `git rev-list --count 7f08a16deed57c93654356058667293534de6994..646dd5b8cfad1206e92ec7bcc3b8312657e2a92e` returned `121`.
- The first-party advisory declares `<0.6.70` affected and release `autogpt-platform-beta-v0.6.70` fixed.

Exact lineage commands:

```zsh
git show -s --format=fuller 7f08a16deed57c93654356058667293534de6994
git show 7f08a16deed57c93654356058667293534de6994 -- \
  autogpt_platform/backend/backend/api/features/integrations/router.py \
  autogpt_platform/backend/backend/integrations/webhooks/_base.py
git show -s --format=fuller 646dd5b8cfad1206e92ec7bcc3b8312657e2a92e
git merge-base --is-ancestor \
  7f08a16deed57c93654356058667293534de6994 \
  646dd5b8cfad1206e92ec7bcc3b8312657e2a92e
git rev-list --count \
  7f08a16deed57c93654356058667293534de6994..646dd5b8cfad1206e92ec7bcc3b8312657e2a92e
```

Claim boundary: this establishes an explicit AI coauthor signal on the mechanism-creating carrier, not exclusive authorship by an AI system and not a quantitative attribution fraction.

## Rejected, duplicate, BLOCKED, and negative controls

| Control | Disposition | Evidence boundary |
|---|---|---|
| `CVE-2026-69659` | **DUPLICATE** | Already locally adjudicated `NOT_AI_CAUSAL`; excluded without rework. |
| Winter CMS `CVE-2026-32258` + `CVE-2026-32257` | **same-mechanism duplicate group** | Custom-CSS XSS siblings share exact fix `d28f0b9474af79cfaa80eeb9d691f7a7c4469720`; no AI marker. |
| AnythingLLM `CVE-2026-72917` | **UNKNOWN containment** | Exact fix `61766d06b77b903f66dc4afd8dffb3a39012db14`; official affected range does not identify an unambiguous first patched release. Branding excluded. |
| ToolJet `CVE-2026-73068` | **BLOCKED** | Exact fix and `v3.20.207-lts` exist, but structured affected data marks that same version affected while prose calls it fixed. |
| PapersGPT `CVE-2026-73032`; DB-GPT `CVE-2026-73034`; compliance-trestle `CVE-2026-52776` | **BLOCKED** | Exact fixes exist; inspected official records do not establish released containment. |
| Intel `CVE-2026-20755`, `20903`, `21387`, `21400`, `27765`, `28707` | **BLOCKED / routing only** | Official advisory identities/version data but no repository-level exact fix lineage. Product names excluded. |
| n8n, Cursor, Microsoft Copilot fresh records | **BLOCKED / UNKNOWN** | No exact public candidate/fix lineage in the inspected first-party records. |
| Ten Linux CVEs `68241`, `68242`, `68243`, `68244`, `68247`, `68248`, `68253`, `68254`, `68265`, `68269` | **AI-discovery positive / AI-origin negative** | Records credit AI-assisted static analysis for discovery; discovery is not vulnerable-code authorship. |
| GitHub unreviewed stream | **UNKNOWN coverage** | Two 100-row pages sampled and still paginating; deliberately stopped. |

## Final claim boundary

- **Publication-grade candidate additions:** 1, AutoGPT `CVE-2026-72922`.
- **Ranked novel groups:** 12; **semantic mechanisms:** 13.
- **Fix-side AI controls:** 3 mechanisms: two Typebot rows and Claude Code Templates.
- **AI-discovery-only controls:** 10 Linux CVEs.
- **Strict exclusions:** branding, repository/product names, AI feature context, reviewers/bots, discovery assistance, and fix assistance are never promoted to origin evidence.
- **Temporal closure:** CVE data through `deltaLog.fetchTime=2026-08-12T16:16:43.868Z` plus the ordered post-1500Z fetch completed at `16:25:17Z`; GitHub reviewed query at `16:20:53Z`; later changes are out of scope.
- **Coverage caveat:** reviewed GitHub advisories and the official CVE delta are closed at the stated artifacts. The unreviewed GitHub stream is explicitly not exhaustive.
