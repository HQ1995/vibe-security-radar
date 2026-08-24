# Batch 2 fresh GitHub advisory pages

Status: **COMPLETE for the bounded eight-page pass**  
Acquisition: `2026-08-12T16:49:30Z`–`2026-08-12T16:58:34Z`  
Scope: GitHub unreviewed advisory pages 3–10 after Batch 1's first 200 rows  
Output: `/home/hanqing/agents/ai-slop/autoresearch/herdr-260812-b2-fresh-pages/`

## Result

All eight requested pages were consumed and frozen: 800 rows, 800 unique GHSA IDs, and 800 unique CVE IDs. The current exclusion freeze matched 12 rows and left 788 public-ID-novel rows. Five AI-adjacent routes were retained for adjudication: four novel and one duplicate.

No row establishes publication-grade AI origin:

- FlyEnv and mcp-grafana have exact candidate, fix, ancestry, and released containment, but their mechanism origins have no explicit AI authorship signal: security-lineage `PASS`, AI-origin `REJECT`.
- Flowise is `BLOCKED` because the official record has no exact first-party fix or unaffected release.
- SQLBot is `NARROW`: an exact fix reference exists, but origin and released containment remain `UNKNOWN`.
- KoboldCPP-MCP is a duplicate by `CVE-2026-19373` and has no fix.

No shared path or cache was changed. All responses, clones, patches, and terminal artifacts are under the owned output directory.

## Frozen inputs and exclusion set

Batch 1 was inherited without re-fetching or mutation:

| Input | SHA-256 |
|---|---|
| Batch 1 page-2 header | `476cfd9511beb5f6907a033fab44e458eadd240de2333409953081ba6c49ce63` |
| Batch 1 page-2 JSON | `54d7b1c7109d99d2349ef06534d941dd8216904bd3b3ec1219e013adbb651523` |
| Batch 1 baseline freeze | `c0bc0fab38e87d416bdc6c7ebf5febcd54055f240646d2cc9bc4fa88ce08a8b4` |
| Batch 1 `report.md` | `29c91e17cb33aed6335e6a8dda4698981da76b8b4a7e1731811e7d22c32bc713` |
| Batch 1 `result.json` | `2c5d1e041e26e5e239ec31ac97d5f7a1333d6631b50ec6da857d313bd8e64e03` |

The live exclusion artifact `evidence/dedup-freeze.json`, SHA-256 `d7b68964a54c50230afd14707b082231c33fa8a5bfe2416485a47b766ce67b97`, was generated at `2026-08-12T16:53:09.701582Z`. It contains 1,523 normalized CVE/GHSA IDs from 100 current terminal/adjudication files totaling 7,655,729 bytes. Its inventory records every input path, size, mtime, and SHA-256.

The selector covered current `docs/*`, all visible `autoresearch/**/report.md` and `result.json`, bounded current `herdr-260812-*` JSONL terminal artifacts, and Batch 1's expanded control IDs. Historical intermediate JSONL totaling roughly 13 GiB was explicitly excluded under the no-full-corpus rule; completed terminal artifacts and Batch 1's baseline represent its adjudicated IDs. Live-agent files produced after this inventory are outside the snapshot.

Dedup matched every row's `ghsa_id`, `cve_id`, and structured identifiers against this freeze. It found 12 overlaps: ten Batch 1 Linux AI-discovery controls, `CVE-2026-16578`, and `CVE-2026-19373`. Novelty was then checked semantically for the routed rows using repository, mechanism, and fix—not ID absence alone.

## Acquisition and page hashes

The exact `rel="next"` from Batch 1 page 2 was followed. Each subsequent request used only the immediately preceding response's next link:

```zsh
prev=autoresearch/herdr-260812-fresh-advisories/github-unreviewed-page2.headers
for page_no in 3 4 5 6 7 8 9 10; do
  next_url=$(sed -n 's/^link: <\([^>]*\)>; rel="next".*$/\1/p' "$prev" | tr -d '\r')
  [[ -n "$next_url" ]] || break
  curl -fsS --retry 2 --retry-delay 1 \
    -D "raw-pages/github-unreviewed-page${page_no}.headers" \
    -o "raw-pages/github-unreviewed-page${page_no}.json" \
    "$next_url" \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2026-03-10'
  jq -e 'type == "array" and (length <= 100)' \
    "raw-pages/github-unreviewed-page${page_no}.json" >/dev/null
  prev="raw-pages/github-unreviewed-page${page_no}.headers"
done
```

No search endpoint or per-row advisory API loop was used.

| Page | Rows | Updated-at span | JSON SHA-256 | Header SHA-256 |
|---:|---:|---|---|---|
| 3 | 100 | `2026-08-10T15:33:47Z`–`15:33:49Z` | `1d65056af98d66f605aa54162a5f541c3eaa12f74a44c2816c346695456f7d3f` | `1fb7c46469fb3e7d28617afca95db818de1f822563bed940a5cb709351bfb96b` |
| 4 | 100 | `15:33:49Z`–`15:33:54Z` | `a50503c80b8c381d563e6047915f61a551501f86958bc09e747a6cc1fdadda18` | `68f56081d36554edaec2f411814eac8585cd30c4194ca27ca349f69c61ca8331` |
| 5 | 100 | `15:33:54Z`–`18:30:41Z` | `6266d036602ed27d0ef9b03a1959db31a7c45ed789caba39451f26f383557309` | `19b5459a0f048573f29fc9b6980b88d90a7ac9311057828a5dca2bc36046f762` |
| 6 | 100 | `18:30:42Z`–`18:31:33Z` | `ad653b0714b79a65bc93e692124759aac235a195fdc4e38adb511de76bb4ca3c` | `ec190e2733d8b64331adbff31e5ef7a1803385d34be5784fa802639f044e4a43` |
| 7 | 100 | `18:31:33Z`–`18:32:08Z` | `c3dcc7ffbea65d6db0846db8c4c68a6e99961f82c7cd4b5384c45ea60c12f9b6` | `4bf3dce6234e1c7d95d8ec0a97ad617f26ee0fbe0ee9e47c5a3e9ce6992edbb6` |
| 8 | 100 | `18:32:08Z`–`18:33:05Z` | `7ac82dab14ca824a3c7f4946f4d5ec1356247cb65561f72747fa97925263c040` | `7af759342617acc5d8f498d02e25b2e73caf95c500b9782a5698e9c3ca6c378d` |
| 9 | 100 | `18:33:05Z`–`2026-08-11T03:31:51Z` | `f0ae0702402a302150546054b7264ccc0569c9d088462b332cef9362c170272d` | `f4e221c50a9f1ad1b2b8c1112dd1251bdcf193fab7f196e43c306e8770e405d2` |
| 10 | 100 | `03:31:51Z`–`12:30:27Z` | `ee50373bb75bced841401657d58a12befe01ff8bc8fb284105ed3ee7ebbb6442` | `31daf78c78677c89ad1a5f1ebd70af86bac46af5ee10f2e1a3e5174d32048da1` |

## Routed rows and dispositions

| Route | Novelty | Security lineage | AI-origin disposition |
|---|---|---|---|
| FlyEnv [`CVE-2026-69116`](https://cveawg.mitre.org/api/cve/CVE-2026-69116) / `GHSA-w92g-j683-fhvq` | Novel by ID and repo+mechanism+fix | **PASS**: two origins, exact fix, ancestry, release | **REJECT**: neither mechanism origin has an explicit AI marker |
| Flowise [`CVE-2026-71962`](https://cveawg.mitre.org/api/cve/CVE-2026-71962) / `GHSA-mf39-7j64-g95c` | Novel by ID | **BLOCKED**: no exact first-party fix or released containment | **UNKNOWN**; branding and referral metadata excluded |
| SQLBot `CVE-2026-72743` / `GHSA-vm6h-rfrh-ph3m` | Novel by ID | **NARROW**: exact fix named; origin/release not closed | **UNKNOWN**; product name excluded |
| KoboldCPP-MCP `CVE-2026-19373` / `GHSA-m2hf-r4mh-rrq8` | **DUPLICATE** by CVE | No project response, fix, or release in record | Branding excluded |
| mcp-grafana [`CVE-2026-19516`](https://cveawg.mitre.org/api/cve/CVE-2026-19516) / `GHSA-fr94-7cqc-vjrq` | Novel by ID and repo+mechanism+fix | **PASS**: origin, fix, ancestry, vendor release | **REJECT**: mechanism origin has no explicit AI marker |

### FlyEnv: exact negative control

Official record SHA-256 `87cd82e078c10121dc7e2484002c0dd71abb9392cc9aa259f05adeee07489d4a` declares `<4.18.0` affected, `4.18.0` unaffected, exact fix `68fd6d7b200273ad0a8bce09424b8bd87134cfb6`, PR `#810`, and release `v4.18.0`.

- `b0d10c7913913c59d2894870c3d2e94f407f4a9e` introduces unsanitized AI-chat `v-html="item.content"`.
- `afe9faffe1f7e8b55a1f4a291291603740923ad9` introduces unsanitized Markdown rendering.
- Fix `68fd6d7b200273ad0a8bce09424b8bd87134cfb6` applies DOMPurify to both sinks.
- Both origin-to-fix and fix-to-`v4.18.0` ancestry checks return `0`.
- Neither origin nor fix carries an explicit AI authorship marker. AI chat is feature context only.

Retained patches hash to `1e5b7f0a397d73282b3ff91d65ef17493df31ec9bf562ee487c962c9d7c234f4` (chat origin), `79de53dcb2860581f5ac530601ac261c0758c49a12b0837c3ab5c7b9e3b9900a` (Markdown origin), and `a06d4b7ba9f9b2d7c9d9417f1381a23244c047090e2ff42893aba6387cda955e` (fix).

### mcp-grafana: exact negative control

Official CVE JSON SHA-256 `7010125b8c1ca8485c0433c2bf274436ef76d028a906480aec6d45ed576ae1e6` describes caller-controlled `X-Grafana-URL` SSRF. Grafana's frozen advisory states fixed versions `>=1.1.0`.

- Human-authored origin `317a563d5ce2dbcf370dfe8eb627bf6fe6b46485` introduces request-header URL selection for outbound clients.
- Exact fix `4c1b338f3d7a430dcd2183ea3ae8f262eb852c07` removes caller URL control and pins the destination to `GRAFANA_URL`.
- Origin-to-fix and fix-to-release tag `v1.1.0` ancestry checks return `0`.
- Origin and fix have no explicit AI marker. Unrelated Claude coauthored commits in the repository do not transfer attribution to this mechanism.

Origin/fix patches hash to `61b5899539bbe45f9d6b04b34fc2e150f92e7846e7d4927179f98c9a240f784a` and `ada90836310a4f3be06c8fdb65beb2e63700c36debea05431b35fed05cd74d6f`; the vendor HTML and extracted text hash to `2664ad1a6afce393114078345ce8d37d7cd1d7ef4236d7a35d2f0480b0ba0259` and `faab3217163cdd6bbbeafda4b63b67ad73431968f8d3eb1b29b347d1721b9599`.

### Incomplete and duplicate controls

- Flowise: official JSON SHA-256 `498e33cece361def1190edb2a9f45a9b472fc61260ee973e1aaf2b29419b7500` provides affected `2.2.4`–`3.1.4`, but no first-party fix or unaffected release. `utm_source=chatgpt.com` is referral metadata, not provenance.
- SQLBot: the unreviewed row names exact fix `c3f40a5c05a53253b2924765b02b83f6a819948f`; no origin or release closure was recovered within the bound. Source recovery is not causal proof.
- KoboldCPP-MCP: `CVE-2026-19373` was already present in the frozen current universe; a newly observed GHSA alias does not create a new mechanism. The record says the project had not responded and identifies no fix.
- The ten Linux rows overlapping Batch 1 remain AI-discovery controls. AI-assisted discovery is not vulnerable-code origin.

## Exact remaining pagination boundary

Page 10 ends with `GHSA-85cw-qx9x-rj5j` at `updated_at=2026-08-11T12:30:27Z` and still advertises `rel="next"`. The first unconsumed request is:

```text
https://api.github.com/advisories?type=unreviewed&modified=%3E%3D2026-08-10&sort=updated&direction=asc&per_page=100&after=Y3Vyc29yOnYyOpK0MjAyNi0wOC0xMVQxMjozMDoyN1rOAAYkSw%3D%3D
```

Cursor: `Y3Vyc29yOnYyOpK0MjAyNi0wOC0xMVQxMjozMDoyN1rOAAYkSw%3D%3D`. Every later row is `UNKNOWN/unconsumed`, not a negative.

## Commands and artifact map

First-party records and histories were recovered with:

```zsh
curl -fsS https://cveawg.mitre.org/api/cve/CVE-ID > evidence/CVE-ID.json
curl -fsS https://grafana.com/security/security-advisories/cve-2026-19516/ \
  > evidence/CVE-2026-19516-grafana.html
git -c gc.auto=0 -c maintenance.auto=false clone --filter=blob:none --no-checkout \
  --depth=N https://github.com/OWNER/REPO.git evidence/REPO
git -C evidence/REPO -c gc.auto=0 -c maintenance.auto=false blame FIX^ -- PATH
git -C evidence/REPO -c gc.auto=0 -c maintenance.auto=false merge-base --is-ancestor ORIGIN FIX
git -C evidence/REPO -c gc.auto=0 -c maintenance.auto=false merge-base --is-ancestor FIX RELEASE_TAG
```

- `source-notes.md`, SHA-256 `532c9f54db487a0b67b2ffb1f1ae0d95fb69d700c5ca5c240325420e67c36618`: expanded row evidence and commands.
- `evidence/dedup-freeze.json`: exact 100-file input inventory and 1,523-ID exclusion universe.
- `raw-pages/`: eight immutable JSON/header pairs for pages 3–10.
- `evidence/CVE-2026-*.json`: official CVE Services records.
- `evidence/FlyEnv*`, `evidence/mcp-grafana*`: owned clones and exact origin/fix patches.

No tests were run: tests could validate security behavior, but they would not prove AI authorship, and exact first-party history closed the two eligible lineages without a broad build.

## Claim boundary

- Public-ID novelty is census evidence, not semantic or causal proof.
- Exact fixes, ancestry, releases, and tests establish mechanism lineage or behavior; none alone proves AI authorship.
- Explicit AI attribution must occur on the mechanism-creating candidate/carrier. Branding, AI-related functionality, discovery assistance, fix assistance, nearby AI-marked commits, reviewers, and referral parameters are controls.
- This pass yields **zero publication-grade AI-origin additions**.
- Coverage is complete only for pages 3–10 at their stored ETags. Pagination remains open after `2026-08-11T12:30:27Z` at the exact cursor above.
