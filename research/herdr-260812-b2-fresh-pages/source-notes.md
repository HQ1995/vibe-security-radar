# Batch 2: GitHub unreviewed fresh-advisory pages 3–10

Status: **COMPLETE for the bounded eight-page source pass**  
Acquisition window: `2026-08-12T16:49:30Z`–`2026-08-12T16:58:34Z`  
Owned output: `/home/hanqing/agents/ai-slop/autoresearch/herdr-260812-b2-fresh-pages/`

## Outcome

Starting from Batch 1's exact page-2 `rel="next"`, this pass fetched and froze pages 3–10: 800 rows, all 100-row pages. Twelve rows overlap the frozen current public-ID universe: ten Batch 1 Linux AI-discovery controls plus `CVE-2026-16578` / `GHSA-wcvm-4w3j-r33j` and `CVE-2026-19373`. The remaining 788 rows are public-ID novel at the stated snapshot.

Five AI-adjacent routing rows were retained. Four are public-ID novel and one is a duplicate. None supplies claim-grade AI-origin evidence. FlyEnv and mcp-grafana have exact mechanism/fix/release lineage, but their mechanism-introducing commits have no explicit AI authorship signal; they are security-lineage `PASS`, AI-origin `REJECT`. Flowise is `BLOCKED`, SQLBot is `NARROW/UNKNOWN`, and KoboldCPP-MCP is a public-ID duplicate.

No shared file or cache was written. Both repository clones and every downloaded response are inside this owned directory.

## Inherited boundary and live dedup freeze

The inherited Batch 1 inputs were read-only:

| Input | SHA-256 |
|---|---|
| `autoresearch/herdr-260812-fresh-advisories/github-unreviewed-page2.headers` | `476cfd9511beb5f6907a033fab44e458eadd240de2333409953081ba6c49ce63` |
| `autoresearch/herdr-260812-fresh-advisories/github-unreviewed-page2.json` | `54d7b1c7109d99d2349ef06534d941dd8216904bd3b3ec1219e013adbb651523` |
| `autoresearch/herdr-260812-fresh-advisories/baseline-freeze.json` | `c0bc0fab38e87d416bdc6c7ebf5febcd54055f240646d2cc9bc4fa88ce08a8b4` |
| Batch 1 `report.md` | `29c91e17cb33aed6335e6a8dda4698981da76b8b4a7e1731811e7d22c32bc713` |
| Batch 1 `result.json` | `2c5d1e041e26e5e239ec31ac97d5f7a1333d6631b50ec6da857d313bd8e64e03` |

`evidence/dedup-freeze.json`, SHA-256 `d7b68964a54c50230afd14707b082231c33fa8a5bfe2416485a47b766ce67b97`, was generated at `2026-08-12T16:53:09.701582Z` and freezes 1,523 unique CVE/GHSA IDs extracted from 100 files / 7,655,729 bytes. Its inventory records the exact path, size, mtime, and SHA-256 of every input. The selector was:

- every current file directly under `docs/`;
- every visible `autoresearch/**/report.md` and `result.json` outside this owned directory;
- current `autoresearch/herdr-260812-*` JSONL terminal artifacts to one nested level;
- Batch 1 `source-notes.md`, plus its ten fully expanded Linux-control CVE IDs because the Markdown abbreviates nine of them after the first full `CVE-2026-` prefix.

Deep historical orchestrator/snapshot JSONL was explicitly excluded: it is roughly 13 GiB and violates this task's no-full-corpus boundary. Completed current docs/reports/results and Batch 1's baseline cover its adjudicated public IDs. This is a snapshot, not a claim about files added by live agents after the frozen inventory was generated.

Dedup was by every `ghsa_id`, `cve_id`, and structured `identifiers[].value`, case-normalized, then against the 1,523-ID freeze. It yielded 800 distinct GHSA rows / 800 distinct CVEs, 12 overlapping rows, and 788 novel rows. It does not infer semantic novelty from IDs alone; the five routed rows below were separately checked for repository/mechanism/fix equivalence against the frozen terminal artifacts.

## Exact acquisition and page freeze

The next URL was extracted from the stored prior header, and every subsequent request followed only the exact `rel="next"` returned by the immediately preceding response:

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

No GitHub search endpoint or per-row advisory API loop was used.

| Page | Rows | First row / updated | Last row / updated | JSON SHA-256 | Header SHA-256 |
|---:|---:|---|---|---|---|
| 3 | 100 | `GHSA-pcxf-938w-xxq5` / `2026-08-10T15:33:47Z` | `GHSA-4j2q-qh5f-j94p` / `15:33:49Z` | `1d65056af98d66f605aa54162a5f541c3eaa12f74a44c2816c346695456f7d3f` | `1fb7c46469fb3e7d28617afca95db818de1f822563bed940a5cb709351bfb96b` |
| 4 | 100 | `GHSA-xmch-cvc7-cmxw` / `15:33:49Z` | `GHSA-c68p-69ww-4qwm` / `15:33:54Z` | `a50503c80b8c381d563e6047915f61a551501f86958bc09e747a6cc1fdadda18` | `68f56081d36554edaec2f411814eac8585cd30c4194ca27ca349f69c61ca8331` |
| 5 | 100 | `GHSA-q88g-f4fr-ffwf` / `15:33:54Z` | `GHSA-m3r4-hcc8-8q6r` / `18:30:41Z` | `6266d036602ed27d0ef9b03a1959db31a7c45ed789caba39451f26f383557309` | `19b5459a0f048573f29fc9b6980b88d90a7ac9311057828a5dca2bc36046f762` |
| 6 | 100 | `GHSA-8x3j-fggj-hxrf` / `18:30:42Z` | `GHSA-rhcm-c7c7-5wq8` / `18:31:33Z` | `ad653b0714b79a65bc93e692124759aac235a195fdc4e38adb511de76bb4ca3c` | `ec190e2733d8b64331adbff31e5ef7a1803385d34be5784fa802639f044e4a43` |
| 7 | 100 | `GHSA-636v-jm8j-6hx7` / `18:31:33Z` | `GHSA-2xcm-9h5p-f5jp` / `18:32:08Z` | `c3dcc7ffbea65d6db0846db8c4c68a6e99961f82c7cd4b5384c45ea60c12f9b6` | `4bf3dce6234e1c7d95d8ec0a97ad617f26ee0fbe0ee9e47c5a3e9ce6992edbb6` |
| 8 | 100 | `GHSA-8532-r3c4-44qx` / `18:32:08Z` | `GHSA-m376-6rq6-f84p` / `18:33:05Z` | `7ac82dab14ca824a3c7f4946f4d5ec1356247cb65561f72747fa97925263c040` | `7af759342617acc5d8f498d02e25b2e73caf95c500b9782a5698e9c3ca6c378d` |
| 9 | 100 | `GHSA-j336-jmmp-f6w9` / `2026-08-10T18:33:05Z` | `GHSA-jg6j-874m-wgjj` / `2026-08-11T03:31:51Z` | `f0ae0702402a302150546054b7264ccc0569c9d088462b332cef9362c170272d` | `f4e221c50a9f1ad1b2b8c1112dd1251bdcf193fab7f196e43c306e8770e405d2` |
| 10 | 100 | `GHSA-2wqx-fp26-qh5v` / `03:31:51Z` | `GHSA-85cw-qx9x-rj5j` / `12:30:27Z` | `ee50373bb75bced841401657d58a12befe01ff8bc8fb284105ed3ee7ebbb6442` | `31daf78c78677c89ad1a5f1ebd70af86bac46af5ee10f2e1a3e5174d32048da1` |

### Exact remaining pagination boundary

Page 10 still advertises `rel="next"`. The first unconsumed request is exactly:

```text
https://api.github.com/advisories?type=unreviewed&modified=%3E%3D2026-08-10&sort=updated&direction=asc&per_page=100&after=Y3Vyc29yOnYyOpK0MjAyNi0wOC0xMVQxMjozMDoyN1rOAAYkSw%3D%3D
```

Thus coverage ends after page-10 row `GHSA-85cw-qx9x-rj5j`, `updated_at=2026-08-11T12:30:27Z`, with cursor `Y3Vyc29yOnYyOpK0MjAyNi0wOC0xMVQxMjozMDoyN1rOAAYkSw%3D%3D`. Later rows remain **UNKNOWN / unconsumed**, not negative.

## Five routed rows

Routing was deliberately recall-oriented. Names such as AI, MCP, Flowise, and SQLBot, AI-feature descriptions, AI-assisted discovery, and `utm_source=chatgpt.com` were only routing signals. They are not authorship evidence.

| Route | Page:index | Novelty | Security lineage | AI-origin disposition |
|---|---:|---|---|---|
| FlyEnv `CVE-2026-69116` / `GHSA-w92g-j683-fhvq` | 9:66 | Public-ID and repo+mechanism+fix novel | **PASS** exact origins, fix, ancestry, release | **REJECT**: no explicit AI marker on either vulnerable origin |
| Flowise `CVE-2026-71962` / `GHSA-mf39-7j64-g95c` | 9:56 | Public-ID novel | **BLOCKED**: affected range, but no first-party fix or released containment | **UNKNOWN**; product/endpoint names and a ChatGPT-tagged disclosure URL are controls |
| SQLBot `CVE-2026-72743` / `GHSA-vm6h-rfrh-ph3m` | 9:73 | Public-ID novel | **NARROW**: unreviewed row names exact fix `c3f40a5c05a53253b2924765b02b83f6a819948f`; release containment and origin not closed | **UNKNOWN**; SQLBot branding is not provenance |
| KoboldCPP-MCP `CVE-2026-19373` / `GHSA-m2hf-r4mh-rrq8` | 10:1 | **DUPLICATE** by CVE against current artifacts | **REJECT from new work**; record says project had not responded and names no fix | MCP/LLM branding excluded |
| mcp-grafana `CVE-2026-19516` / `GHSA-fr94-7cqc-vjrq` | 10:53 | Public-ID and repo+mechanism+fix novel | **PASS** exact origin, fix, ancestry, vendor release | **REJECT**: origin has no explicit AI marker; MCP context is not authorship |

### 1. FlyEnv — lineage PASS, AI-origin REJECT

Official CVE Services JSON `evidence/CVE-2026-69116.json` (SHA-256 `87cd82e078c10121dc7e2484002c0dd71abb9392cc9aa259f05adeee07489d4a`) identifies `xpf0000/FlyEnv`, `<4.18.0` affected, `4.18.0` unaffected, exact patch `68fd6d7b200273ad0a8bce09424b8bd87134cfb6`, PR `#810`, and release `v4.18.0`.

The owned full-history clone was read with `git -c gc.auto=0 -c maintenance.auto=false` and froze repository tip `f13303099394f43409ac1dd5eeb7d244edb38028`. Exact recovery found two mechanism origins:

- `b0d10c7913913c59d2894870c3d2e94f407f4a9e` introduced the AI chat `v-html="item.content"` sink; patch SHA-256 `1e5b7f0a397d73282b3ff91d65ef17493df31ec9bf562ee487c962c9d7c234f4`.
- `afe9faffe1f7e8b55a1f4a291291603740923ad9` introduced the unsanitized Markdown `md.render` pass-through; patch SHA-256 `79de53dcb2860581f5ac530601ac261c0758c49a12b0837c3ab5c7b9e3b9900a`.
- `68fd6d7b200273ad0a8bce09424b8bd87134cfb6` adds DOMPurify to both sinks; patch SHA-256 `a06d4b7ba9f9b2d7c9d9417f1381a23244c047090e2ff42893aba6387cda955e`.

Both `git merge-base --is-ancestor ORIGIN FIX` checks returned `0`; `git merge-base --is-ancestor FIX refs/tags/v4.18.0` also returned `0`. The two origins and fix show no `Co-authored-by`, `Generated with/by`, Claude, Codex, Copilot, Cursor, ChatGPT, Gemini, or equivalent explicit attribution. The AI chat feature supplies mechanism context only. Therefore this is a high-quality **negative control**, not an AI-origin candidate.

### 2. mcp-grafana — lineage PASS, AI-origin REJECT

Grafana's CVE Services record `evidence/CVE-2026-19516.json` (SHA-256 `7010125b8c1ca8485c0433c2bf274436ef76d028a906480aec6d45ed576ae1e6`) assigns the record to Grafana and describes caller-controlled `X-Grafana-URL` SSRF. Grafana's first-party advisory was frozen as HTML SHA-256 `2664ad1a6afce393114078345ce8d37d7cd1d7ef4236d7a35d2f0480b0ba0259`; its extracted text is SHA-256 `faab3217163cdd6bbbeafda4b63b67ad73431968f8d3eb1b29b347d1721b9599` and states fixed versions `>=1.1.0`.

The owned full-history clone froze tip `d95411456bfe0a2a58ec3d1dbb4f1412739cdae4`. Blame and history identify:

- mechanism origin `317a563d5ce2dbcf370dfe8eb627bf6fe6b46485` (`Add Incident tools`), which introduced `urlAndAPIKeyFromHeaders`, copied caller `X-Grafana-URL`, and used it to construct an outbound Incident client; patch SHA-256 `61b5899539bbe45f9d6b04b34fc2e150f92e7846e7d4927179f98c9a240f784a`;
- exact fix `4c1b338f3d7a430dcd2183ea3ae8f262eb852c07` (`fix(http): drop support for undocumented X-Grafana-URL (#1052)`), which removes caller control and pins the outbound URL to `GRAFANA_URL`; patch SHA-256 `ada90836310a4f3be06c8fdb65beb2e63700c36debea05431b35fed05cd74d6f`;
- release tag `v1.1.0` at `007e8d82154899a28e19e8dfe9c2bb4452c5211a`.

`git merge-base --is-ancestor 317a... 4c1b...` returned `0`, and `git merge-base --is-ancestor 4c1b... refs/tags/v1.1.0` returned `0`. Origin and fix messages have no explicit AI-authorship marker. MCP clients and model tooling are product context only. This closes a security fix but **rejects AI-origin causality**.

### 3. Flowise — BLOCKED

Official JSON `evidence/CVE-2026-71962.json` (SHA-256 `498e33cece361def1190edb2a9f45a9b472fc61260ee973e1aaf2b29419b7500`) says versions `2.2.4` through `3.1.4` are affected by a globally whitelisted OpenAI Assistants file-download endpoint. It provides a sunset notice and third-party disclosure, but no first-party patch commit or unaffected release. The disclosure URL's `utm_source=chatgpt.com` is referral metadata, not vulnerable-code authorship. Exact fix, origin, ancestry, and released containment remain **BLOCKED/UNKNOWN**.

### 4. SQLBot — NARROW / UNKNOWN

The official unreviewed row states that `SQText` renders TinyMCE output through `v-html` without sanitization and points to issue `#1308`, PR `#1309`, and exact fix `c3f40a5c05a53253b2924765b02b83f6a819948f`. Within the timebox, origin and released containment were not recovered, and no first-party authorship marker was established. The exact-fix reference is source recovery only; this remains **NARROW**, with AI origin **UNKNOWN**.

### 5. KoboldCPP-MCP — duplicate / no fix

The current dedup freeze already contains `CVE-2026-19373`; the page's GHSA alias is new to that artifact, but alias novelty does not make the mechanism new. The unreviewed record describes caller-controlled `apiUrl` SSRF and explicitly says the project had not responded; it provides no exact fix or released containment. It was excluded as a duplicate and retained as an unresolved MCP-branding control.

## Commands for lineage and official records

```zsh
curl -fsS https://cveawg.mitre.org/api/cve/CVE-2026-69116 > evidence/CVE-2026-69116.json
curl -fsS https://cveawg.mitre.org/api/cve/CVE-2026-71962 > evidence/CVE-2026-71962.json
curl -fsS https://cveawg.mitre.org/api/cve/CVE-2026-19516 > evidence/CVE-2026-19516.json
curl -fsS https://grafana.com/security/security-advisories/cve-2026-19516/ > evidence/CVE-2026-19516-grafana.html

git -c gc.auto=0 -c maintenance.auto=false clone --filter=blob:none --no-checkout --depth=300 \
  https://github.com/xpf0000/FlyEnv.git evidence/FlyEnv
git -C evidence/FlyEnv -c gc.auto=0 -c maintenance.auto=false fetch --deepen=2000 --filter=blob:none origin

git -c gc.auto=0 -c maintenance.auto=false clone --filter=blob:none --no-checkout --depth=500 \
  https://github.com/grafana/mcp-grafana.git evidence/mcp-grafana
git -C evidence/mcp-grafana -c gc.auto=0 -c maintenance.auto=false fetch --deepen=500 --filter=blob:none origin

git -C REPO -c gc.auto=0 -c maintenance.auto=false log --all -S NEEDLE -- PATH
git -C REPO -c gc.auto=0 -c maintenance.auto=false blame -l FIX^ -L START,END -- PATH
git -C REPO -c gc.auto=0 -c maintenance.auto=false merge-base --is-ancestor ORIGIN FIX
git -C REPO -c gc.auto=0 -c maintenance.auto=false merge-base --is-ancestor FIX RELEASE_TAG
git -C REPO -c gc.auto=0 -c maintenance.auto=false format-patch -1 --stdout SHA > evidence/ROW.patch
```

No tests were run. Tests would validate behavior, not AI causality, and the requested evidence was available from exact first-party history without a broad build.

## Claim boundary

- **Eight pages consumed:** 3–10 inclusive, 800 rows.
- **Dedup:** 12 overlapping rows, 788 public-ID novel rows; this is ID-level census evidence, not causal proof.
- **Routed rows:** five AI-adjacent records, four ID-novel and one duplicate.
- **Exact security lineage and release PASS:** two (FlyEnv, mcp-grafana).
- **AI-origin PASS:** zero.
- **AI-origin REJECT:** two exact-lineage negative controls (FlyEnv, mcp-grafana).
- **NARROW:** SQLBot exact-fix reference without origin/release closure.
- **BLOCKED:** Flowise lacks exact first-party fix and released containment.
- **Duplicate:** KoboldCPP-MCP by `CVE-2026-19373`.
- Routing terms, source recovery, ancestry, and release containment establish relevance and mechanism lineage only. They do not prove AI authorship. No causality was inferred from branding, AI feature context, AI-assisted discovery, or fix-side assistance.
- Pagination remains open at the exact cursor above; every row after `2026-08-11T12:30:27Z` is **UNKNOWN/unconsumed**.
