# Batch 2: closure of seven Batch 1 alias blockers

Status: **PARTIAL**  
Live refresh: `2026-08-12T16:50:27Z`–`2026-08-12T16:50:41Z`  
Checkout snapshot: branch `dev`, HEAD `6c0d2084fd1240341d6d1b9f9096252490168f0b`  
Owned output: `/home/hanqing/agents/ai-slop/autoresearch/herdr-260812-b2-alias-blockers/`

## Result

Only the seven named Batch 1 blockers were revisited. The other 67 distinct rows were not re-audited.

| Batch 1 row | Amendment | Evidence status | Terminal result |
|---|---|---|---|
| `misp-mass-assignment@canonical` | `SPLIT` | `NARROW` | Closed as a path-partitioned 16-commit advisory; Batch 1's selected SHA is Taxonomy-only. |
| `omnifaces-combined-resource@canonical` | `SPLIT` | `NARROW` | Closed as four distinct mechanism partitions; Batch 1's selected SHA is source-map-only. |
| `gitea-draft-attachment@canonical` | `UNKNOWN` | `BLOCKED` | CVE Services still returns 404. |
| `gitea-oauth-reactivation@canonical` | `UNKNOWN` | `BLOCKED` | CVE Services still returns 404. |
| `praisonai-jwt-default@canonical` | `UNKNOWN` | `BLOCKED` | CVE Services still returns 404. |
| `gitea-private-org-members@canonical` | `UNKNOWN` | `BLOCKED` | CVE Services still returns 404. |
| `openclaw-feishu-webhook@canonical` | `SPLIT` | `NARROW` | Closed into webhook and blank-card-token mechanisms with exact file/commit identity. |

Amendment counts are `SPLIT=3`, `UNKNOWN=4`, `KEEP=0`, `ADD_ALIAS=0`, and `REMOVE_ID=0`. There are no new `PASS` or `REJECT` decisions because this batch began with blockers only. The four `UNKNOWN` rows remain externally `BLOCKED`; absence was not converted into a negative finding.

The live sweep made 49 precise first-party requests: 45 returned HTTP 200 and exactly four CVE Services requests returned HTTP 404. All 28 exact commit objects referenced by the seven current records resolved. No credential value was printed or persisted.

## Frozen input boundary

Batch 1's frozen request ledger and seven-row evidence were reused; the broader candidate population was not reconstructed. The following files were hashed before the live refresh:

| Read-only input | SHA-256 |
|---|---|
| `autoresearch/herdr-260812-alias-qa/ledger.jsonl` | `2b844af298f85345b4354bf980b59e379db4b51796b08759cc1400ed8ddf1e85` |
| `autoresearch/herdr-260812-alias-qa/requests.json` | `10a0ab510449d040d9118252d4203e955b6063ce304e414ab486ac73675b0392` |
| `autoresearch/herdr-260812-alias-qa/summary.json` | `3a1501f1d1b70e887de25ac6b54d6c182f0d6577f39da4820bae1cfc18ef3347` |
| `autoresearch/herdr-260812-alias-qa/input_snapshot.json` | `2b0c6afece157ea22caf49dd9606b6075bf5f82c723294663cb4b9fd7606dbad` |
| `autoresearch/herdr-260812-alias-qa/report.md` | `c5690ed20c39df6216822ded39db37d5faa874ae1549e5492cc0f7cf825d7012` |
| `autoresearch/herdr-260812-alias-qa/result.json` | `c8764ac7f162b50399f6afc0da57d5fe5992d3017c4fbd0b89b4f9c741ff5f51` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md` | `318912fbc789ef7f0708044d2041c24fa69198f878c2c668b04af86031d4616e` |
| `docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` | `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md` | `3a8482a6badb0b8bff5dbf64adc18b37493c68dc56a25598be91ee3be7e727cd` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md` | `f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad` |

`input_snapshot.json` also records byte size and nanosecond mtime. A final hash comparison found no input drift during this batch.

## Exact method and sources

The bounded verifier uses Python's standard library and the already-installed GitHub CLI. It runs requests sequentially, uses no shared clone/cache, and writes raw responses only under `api-cache/` in this directory.

```text
python3 -m py_compile autoresearch/herdr-260812-b2-alias-blockers/verify.py
python3 autoresearch/herdr-260812-b2-alias-blockers/verify.py

GET https://cveawg.mitre.org/api/cve/<target-CVE>
gh api advisories/<target-GHSA> -H 'Accept: application/vnd.github+json'
gh api repos/<owner>/<repo>/security-advisories/<target-GHSA> -H 'Accept: application/vnd.github+json'
gh api repos/<owner>/<repo>/commits/<exact-SHA> -H 'Accept: application/vnd.github+json'

git -c gc.auto=0 -c maintenance.auto=false rev-parse --abbrev-ref HEAD
git -c gc.auto=0 -c maintenance.auto=false rev-parse HEAD
git -c gc.auto=0 -c maintenance.auto=false status --short -- autoresearch/herdr-260812-b2-alias-blockers
```

The exact URL/command and HTTP status for every call are in `live_requests.json`; unmodified API payloads are in `api-cache/`; normalized seven-row payloads are in `live_evidence.json`; exact commit messages, file lists, and patches are in `commit_evidence.json`.

## Row-level amendments

### 1. MISP — `SPLIT` / `NARROW`

[CVE-2026-56422](https://cveawg.mitre.org/api/cve/CVE-2026-56422) remains `PUBLISHED` and deliberately aggregates mass-assignment/re-ownership defects across many controllers and model capture paths. Its 16 first-party commit references all resolve.

The two identities that matter to the Batch 1 ambiguity are not interchangeable:

- [`bc182d55dde5686a36ca2eb88fe6c2adabb9fad9`](https://github.com/MISP/MISP/commit/bc182d55dde5686a36ca2eb88fe6c2adabb9fad9) changes only `app/Model/Event.php`. Its production hunks strip client-supplied `id` from freetext attributes, module-result attributes/objects, and object-attribute capture.
- Batch 1 selected [`025f711506850aadb69cde1b57e5e5d57628c87f`](https://github.com/MISP/MISP/commit/025f711506850aadb69cde1b57e5e5d57628c87f), which changes only `app/Model/Taxonomy.php` and strips imported predicate/entry primary keys. It is not the complete CVE fix and is not the Event-path closure.

The remaining official set is path-specific: `00b2e3da…` Servers, `05aad418…` ShadowAttributes, `2cc26f38…` Templates preventative boundary, `3ff6bd9c…` TemplateElements, `57433015…` Workflow preventative boundary, `58f637aa…` Attributes, `634f1f87…` GalaxyClusterRelations, `63aebc27…` SharingGroups, `7acf8220…` central `CRUDComponent::edit()` re-pin, `8311427c…` Collections, `84bafe69…` Bookmarks, `9341690e…` a multi-controller sweep, `ab9619df…` EventReport, and `c80a3533…` TagCollections. Full SHAs and file scopes are in `amendment_ledger.jsonl`.

Amendment: split by controller/model path. Do not use `025f7115…` as the exact identity for the whole CVE or for the Event AI-partial path. This closes the identity blocker by narrowing; it does not make a new AI-causal or release claim.

### 2. OmniFaces — `SPLIT` / `NARROW`

[GHSA-FP43-VJ7G-PG92](https://api.github.com/repos/omnifaces/omnifaces/security-advisories/GHSA-FP43-VJ7G-PG92) remains published in both GitHub's global and repository objects, with no withdrawal. Its five exact commit references split cleanly into four mechanisms:

| Mechanism | Exact identity |
|---|---|
| Forged combined-resource IDs, resource-type restriction, bounded inflation, and no serve-path cache insertion | Fix [`aa42da361821ddfbb85b126564e71587347d2786`](https://github.com/omnifaces/omnifaces/commit/aa42da361821ddfbb85b126564e71587347d2786); regression test `59d6c5188c39418546fe500d05036645987a77d1` |
| Arbitrary source-map miss cache growth | [`a52b92461cf39d983f51ce8724fe7e6b944073e4`](https://github.com/omnifaces/omnifaces/commit/a52b92461cf39d983f51ce8724fe7e6b944073e4) |
| `HashParam` ajax callback script XSS | `c43eef01174a4dc09cec44eff553ff6284150af7` |
| Session/view-scoped push channel ownership | `d5cae243c4692555efaa4ba774e0f8f60e3f4db5` |

Batch 1 selected `a52b9246…`, which is source-map-only. Amendment: split the GHSA into the four scoped mechanisms above; do not let the selected source-map fix stand for combined resources, `HashParam`, or push ownership.

### 3–6. Assigned CVEs still absent from CVE Services — `UNKNOWN` / `BLOCKED`

| Row | GitHub first-party state | CVE Services state | Exact fix object |
|---|---|---|---|
| `gitea-draft-attachment@canonical` | [GHSA-Q9PG-JJ6X-J9P6](https://api.github.com/repos/go-gitea/gitea/security-advisories/GHSA-Q9PG-JJ6X-J9P6): global 200, repo 200/published, assigns CVE-2026-58432 | [CVE-2026-58432](https://cveawg.mitre.org/api/cve/CVE-2026-58432): HTTP 404 | [`f7fd51022495737cf960b8c4053a27d69148f664`](https://github.com/go-gitea/gitea/commit/f7fd51022495737cf960b8c4053a27d69148f664), HTTP 200 |
| `gitea-oauth-reactivation@canonical` | [GHSA-VRHC-JJFC-M3M3](https://api.github.com/repos/go-gitea/gitea/security-advisories/GHSA-VRHC-JJFC-M3M3): global 200, repo 200/published, assigns CVE-2026-55987 | [CVE-2026-55987](https://cveawg.mitre.org/api/cve/CVE-2026-55987): HTTP 404 | [`fce961b44aa9631f8e9f5d6b3168d16d9a6728af`](https://github.com/go-gitea/gitea/commit/fce961b44aa9631f8e9f5d6b3168d16d9a6728af), HTTP 200 |
| `praisonai-jwt-default@canonical` | [GHSA-F38V-77QJ-H4JQ](https://api.github.com/repos/MervinPraison/PraisonAI/security-advisories/GHSA-F38V-77QJ-H4JQ): global 200, repo 200/published, assigns CVE-2026-57148 | [CVE-2026-57148](https://cveawg.mitre.org/api/cve/CVE-2026-57148): HTTP 404 | [`e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747`](https://github.com/MervinPraison/PraisonAI/commit/e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747), HTTP 200 |
| `gitea-private-org-members@canonical` | [GHSA-PRR9-9MP4-5GP2](https://api.github.com/repos/go-gitea/gitea/security-advisories/GHSA-PRR9-9MP4-5GP2): global 200, repo 200/published, assigns CVE-2026-58427 | [CVE-2026-58427](https://cveawg.mitre.org/api/cve/CVE-2026-58427): HTTP 404 | [`44ea3a8d24638ca4a395d641d39f476ae1dc421d`](https://github.com/go-gitea/gitea/commit/44ea3a8d24638ca4a395d641d39f476ae1dc421d), HTTP 200 |

These are not `REJECT`: their GitHub advisory identities and exact commits remain available. They are not `PASS` either: a GitHub `cve_id` assignment is not a published CVE Services record. Preserve all four as `UNKNOWN` with an external `BLOCKED` reason.

### 7. OpenClaw Feishu — `SPLIT` / `NARROW`

All four first-party objects remain published: [CVE-2026-32974](https://cveawg.mitre.org/api/cve/CVE-2026-32974), [GHSA-G353-MGV3-8PCJ](https://api.github.com/repos/openclaw/openclaw/security-advisories/GHSA-G353-MGV3-8PCJ), [CVE-2026-44109](https://cveawg.mitre.org/api/cve/CVE-2026-44109), and [GHSA-XH72-V6V9-MWHC](https://api.github.com/repos/openclaw/openclaw/security-advisories/GHSA-XH72-V6V9-MWHC).

The exact production hunks settle the split:

- Webhook mechanism: [`7844bc89a1612800810617c823eb0c76ef945804`](https://github.com/openclaw/openclaw/commit/7844bc89a1612800810617c823eb0c76ef945804) is the initial `encryptKey` fix. In residual fix [`c8003f1b33ed2924be5f62131bd28742c5a41aae`](https://github.com/openclaw/openclaw/commit/c8003f1b33ed2924be5f62131bd28742c5a41aae), `extensions/feishu/src/monitor.transport.ts` changes missing `encryptKey` from valid to invalid, refuses webhook startup without it, and returns 401 for invalid signatures.
- Card-action mechanism: the same residual commit separately changes `extensions/feishu/src/card-action.ts`, making a blank token return false and dropping blank-token events before dispatch.

Amendment: retain `CVE-2026-32974/GHSA-G353` plus only webhook-scoped residual evidence from `CVE-2026-44109/GHSA-XH72` in the webhook lineage; create a separate blank-card-token component scoped to `CVE-2026-44109/GHSA-XH72`. The two advisory pairs are related lineage, not aliases.

## Negative controls and claim boundary

- No target advisory was withdrawn or rejected. No new alias was found and no public ID was removed.
- `SPLIT` is scope normalization for one-to-many advisory objects; it is not a claim that one CVE/GHSA pair contains formal aliases for every submechanism.
- Commit resolution, file/hunk mapping, tests mentioned by advisories, source recovery, routing, and ancestry are diagnostic identity evidence. None is independently sufficient for causal attribution.
- No release containment, vulnerable-version reproduction, exploit reproduction, model attribution, prevalence, benchmark, or performance claim was attempted.
- MISP and OmniFaces are closed only as `NARROW` partitions. The four CVE 404s remain `UNKNOWN/BLOCKED`. OpenClaw is closed only after separating the webhook and blank-token mechanisms.
- All durable writes are under the owned output directory. Shared caches and main ledgers were untouched; no clone was needed.

## Artifact map

- `report.md`: this terminal narrative.
- `result.json`: machine-readable terminal status, counts, blockers, claim boundary, and artifact map.
- `amendment_ledger.jsonl`: authoritative seven-row amendment ledger.
- `input_snapshot.json`: frozen input hashes, sizes, and mtimes.
- `live_requests.json`: exact first-party calls and statuses.
- `live_summary.json`: normalized request and row counts.
- `live_evidence.json`: normalized live advisory/CVE payloads.
- `commit_evidence.json`: exact first-party commit objects and patches.
- `api-cache/`: raw live API responses and 404 evidence.
- `first_party_research.md`: independent primary-source cross-check.
- `verify.py`: bounded reproducer with an assert-based seven-row/67-exclusion self-check.
