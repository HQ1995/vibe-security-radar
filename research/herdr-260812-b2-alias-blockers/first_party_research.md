# Batch 2 first-party blocker research

Observed at `2026-08-12T16:53:31Z`. Scope is exactly the seven Batch 1 blockers; the other 67 rows were not re-audited. No main ledger or shared cache was changed.

## Frozen input boundary

| Input | SHA-256 |
|---|---|
| `autoresearch/herdr-260812-alias-qa/ledger.jsonl` | `2b844af298f85345b4354bf980b59e379db4b51796b08759cc1400ed8ddf1e85` |
| `autoresearch/herdr-260812-alias-qa/requests.json` | `10a0ab510449d040d9118252d4203e955b6063ce304e414ab486ac73675b0392` |
| `autoresearch/herdr-260812-alias-qa/report.md` | `c5690ed20c39df6216822ded39db37d5faa874ae1549e5492cc0f7cf825d7012` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md` | `318912fbc789ef7f0708044d2041c24fa69198f878c2c668b04af86031d4616e` |
| `docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` | `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` |

Live checks were limited to the named GitHub global/repository advisory objects, their selected commit objects, and the five relevant CVE Services records. GitHub calls selected only response fields; no credential was printed or stored.

## Amendment summary

| Batch 1 row | Action | First-party conclusion |
|---|---|---|
| `misp-mass-assignment@canonical` | **SPLIT** | `CVE-2026-56422` is an umbrella over endpoint-specific mass-assignment fixes. The Batch 1 selected `025f7115...` Taxonomy fix is not the same mechanism path as the AI `bc182d55...` Event-import fix. |
| `omnifaces-combined-resource@canonical` | **SPLIT** | `GHSA-FP43-VJ7G-PG92` intentionally bundles combined-resource, source-map, HashParam, and push boundaries. `a52b9246...` is a source-map fix, not closure of `aa42da36...` combined-resource handling. |
| `gitea-draft-attachment@canonical` | **UNKNOWN** | GitHub declares the GHSA/CVE pair and released fix, but CVE Services still returns HTTP 404 for `CVE-2026-58432`. |
| `gitea-oauth-reactivation@canonical` | **UNKNOWN** | GitHub declares the GHSA/CVE pair and released fix, but CVE Services still returns HTTP 404 for `CVE-2026-55987`. |
| `praisonai-jwt-default@canonical` | **UNKNOWN** | GitHub declares the GHSA/CVE pair and released fix, but CVE Services still returns HTTP 404 for `CVE-2026-57148`. |
| `gitea-private-org-members@canonical` | **UNKNOWN** | GitHub declares the GHSA/CVE pair and fix object, but CVE Services still returns HTTP 404 for `CVE-2026-58427`. |
| `openclaw-feishu-webhook@canonical` | **SPLIT** | `GHSA-XH72-V6V9-MWHC`/`CVE-2026-44109` combines missing-`encryptKey` webhook validation and blank card-action-token validation in one commit. Only the webhook portion belongs with the earlier webhook component. |

No `ADD_ALIAS` or `REMOVE_ID` amendment is supported. None of the refreshed GitHub objects is withdrawn, and none of the available CVE records is rejected.

## Row-level evidence

### 1. MISP — SPLIT

[CVE Services](https://cveawg.mitre.org/api/cve/CVE-2026-56422) is HTTP 200 / `PUBLISHED`. Its CNA description expressly covers multiple controllers/model capture paths, multiple attacker-controlled key classes, and several remediation patterns; it references 16 commits.

- AI partial [`bc182d55dde5686a36ca2eb88fe6c2adabb9fad9`](https://github.com/MISP/MISP/commit/bc182d55dde5686a36ca2eb88fe6c2adabb9fad9) changes only `app/Model/Event.php`: it strips client `id` values from freetext, module-result, object, and object-attribute create paths.
- Batch 1 selected [`025f711506850aadb69cde1b57e5e5d57628c87f`](https://github.com/MISP/MISP/commit/025f711506850aadb69cde1b57e5e5d57628c87f) changes only `app/Model/Taxonomy.php`: it strips IDs from imported taxonomy predicates and entries.
- Other named official fixes are independently scoped: [`7acf8220...`](https://github.com/MISP/MISP/commit/7acf8220cafac58bcfb362da37aca512fe4bb396) re-pins the shared CRUD edit primary key; [`58f637aa...`](https://github.com/MISP/MISP/commit/58f637aaab4d133e72f1454ebb963191d96d3b78) pins ThreatConnect imports to the authorized route event; [`05aad418...`](https://github.com/MISP/MISP/commit/05aad418c57bb78e6b58a843d70d45de8f50db45) hardens ShadowAttribute proposal/attachment paths; [`63aebc27...`](https://github.com/MISP/MISP/commit/63aebc27a878233b9475c742985aaef909bc755b) hardens sharing-group ownership; [`00b2e3da...`](https://github.com/MISP/MISP/commit/00b2e3dae56fa24ea750eb525cc4709b7e5bee85) strips a server create-path ID.

Recommendation: split the umbrella row into endpoint/invariant families before any incomplete-remediation claim. Do not describe `bc182d55... -> 025f7115...` as a partial-to-closure lineage. Both remain legitimate references of the same umbrella CVE, but routing under one CVE is not causal closure.

### 2. OmniFaces — SPLIT

The [global advisory](https://api.github.com/advisories/GHSA-FP43-VJ7G-PG92) is reviewed and non-withdrawn; the [repository advisory](https://api.github.com/repos/omnifaces/omnifaces/security-advisories/GHSA-FP43-VJ7G-PG92) is published and non-withdrawn. The official reference set separates cleanly:

- Combined-resource implementation: [`aa42da361821ddfbb85b126564e71587347d2786`](https://github.com/omnifaces/omnifaces/commit/aa42da361821ddfbb85b126564e71587347d2786); regression-only companion [`59d6c5188c39418546fe500d05036645987a77d1`](https://github.com/omnifaces/omnifaces/commit/59d6c5188c39418546fe500d05036645987a77d1).
- Source-map cache: [`a52b92461cf39d983f51ce8724fe7e6b944073e4`](https://github.com/omnifaces/omnifaces/commit/a52b92461cf39d983f51ce8724fe7e6b944073e4), changing only `SourceMapResourceHandler.java`.
- HashParam callback escaping: [`c43eef01174a4dc09cec44eff553ff6284150af7`](https://github.com/omnifaces/omnifaces/commit/c43eef01174a4dc09cec44eff553ff6284150af7).
- WebSocket/push ownership and session caps: [`d5cae243c4692555efaa4ba774e0f8f60e3f4db5`](https://github.com/omnifaces/omnifaces/commit/d5cae243c4692555efaa4ba774e0f8f60e3f4db5).

Recommendation: split at least the combined-resource and source-map mechanisms. The Batch 1 `aa42da36... -> a52b9246...` lineage is a cross-mechanism pairing, not an incomplete fix and closure. The umbrella GHSA stays official for every family; it must not make those families one causal component.

### 3. Gitea draft attachments — UNKNOWN

- [Global GHSA](https://api.github.com/advisories/GHSA-Q9PG-JJ6X-J9P6): reviewed, non-withdrawn, declares `CVE-2026-58432` and references the exact main fix and backport.
- [Repository GHSA](https://api.github.com/repos/go-gitea/gitea/security-advisories/GHSA-Q9PG-JJ6X-J9P6): published, non-withdrawn, affected `<=1.26.4`, patched `1.27.0`.
- Exact fix [`f7fd51022495737cf960b8c4053a27d69148f664`](https://github.com/go-gitea/gitea/commit/f7fd51022495737cf960b8c4053a27d69148f664); backport [`ab10e37acf7fabf7829a485cc3e13d118638a856`](https://github.com/go-gitea/gitea/commit/ab10e37acf7fabf7829a485cc3e13d118638a856).
- [CVE Services](https://cveawg.mitre.org/api/cve/CVE-2026-58432): HTTP 404 at the observation time.

The GitHub identity and released containment are strong, but absence from CVE Services is neither publication nor rejection. Preserve `UNKNOWN` for the CVE-record closure.

### 4. Gitea OAuth reactivation — UNKNOWN

- [Global GHSA](https://api.github.com/advisories/GHSA-VRHC-JJFC-M3M3) and [repository GHSA](https://api.github.com/repos/go-gitea/gitea/security-advisories/GHSA-VRHC-JJFC-M3M3) are reviewed/published and non-withdrawn, declare `CVE-2026-55987`, and give affected `<=1.26.4`, patched `1.27.0`.
- Selected closure [`fce961b44aa9631f8e9f5d6b3168d16d9a6728af`](https://github.com/go-gitea/gitea/commit/fce961b44aa9631f8e9f5d6b3168d16d9a6728af) resolves and contains the relevant `routers/web/auth/oauth.go` change; it is a broader security rollup commit, so the frozen member/carrier lineage remains necessary for causal attribution.
- [CVE Services](https://cveawg.mitre.org/api/cve/CVE-2026-55987): HTTP 404.

Recommendation: `UNKNOWN` until the CVE record becomes available or is rejected/withdrawn; do not infer either state from 404.

### 5. PraisonAI JWT default — UNKNOWN

- [Global GHSA](https://api.github.com/advisories/GHSA-F38V-77QJ-H4JQ) and [repository GHSA](https://api.github.com/repos/MervinPraison/PraisonAI/security-advisories/GHSA-F38V-77QJ-H4JQ) are reviewed/published and non-withdrawn, declare `CVE-2026-57148`, and give patched `>=0.1.5`.
- Exact closure [`e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747`](https://github.com/MervinPraison/PraisonAI/commit/e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747) resolves and changes `praisonai_platform/services/auth_service.py`.
- [CVE Services](https://cveawg.mitre.org/api/cve/CVE-2026-57148): HTTP 404.

Recommendation: `UNKNOWN`; the official GitHub mapping does not make a nonexistent CVE Services object `PUBLISHED`.

### 6. Gitea private organization members — UNKNOWN

- [Global GHSA](https://api.github.com/advisories/GHSA-PRR9-9MP4-5GP2) and [repository GHSA](https://api.github.com/repos/go-gitea/gitea/security-advisories/GHSA-PRR9-9MP4-5GP2) are reviewed/published and non-withdrawn, declare `CVE-2026-58427`, and give patched `1.27.0`.
- Exact atomic fix [`44ea3a8d24638ca4a395d641d39f476ae1dc421d`](https://github.com/go-gitea/gitea/commit/44ea3a8d24638ca4a395d641d39f476ae1dc421d) resolves and changes only the `/members` handler and regression test relevant to the residual.
- [CVE Services](https://cveawg.mitre.org/api/cve/CVE-2026-58427): HTTP 404.

Recommendation: `UNKNOWN` for CVE-record closure. The exact fix is present, but candidate and closure first enter the same release; this remains commit-only regardless of alias status.

### 7. OpenClaw Feishu — SPLIT

[GHSA-XH72-V6V9-MWHC](https://api.github.com/advisories/GHSA-XH72-V6V9-MWHC) is reviewed/non-withdrawn and aliases [CVE-2026-44109](https://cveawg.mitre.org/api/cve/CVE-2026-44109), which is `PUBLISHED`. Both descriptions name two independent fail-open inputs: missing webhook `encryptKey` and blank card-action callback tokens.

- Initial webhook-only pair: `GHSA-G353-MGV3-8PCJ` / `CVE-2026-32974`, exact fix [`7844bc89a1612800810617c823eb0c76ef945804`](https://github.com/openclaw/openclaw/commit/7844bc89a1612800810617c823eb0c76ef945804).
- Residual umbrella pair: `GHSA-XH72-V6V9-MWHC` / `CVE-2026-44109`, exact fix [`c8003f1b33ed2924be5f62131bd28742c5a41aae`](https://github.com/openclaw/openclaw/commit/c8003f1b33ed2924be5f62131bd28742c5a41aae). The commit changes both `monitor.transport.ts` and `card-action.ts`, with separate regressions.

Recommendation: `SPLIT`. Retain only XH72's missing-`encryptKey` webhook evidence with the earlier webhook component; route its blank card-action-token branch to a separate component or exclude it. The two GHSA/CVE pairs are not formal aliases, so do not emit `ADD_ALIAS`.

## Claim boundary

These checks close routing and identity questions, not causal or performance claims. A published advisory, exact commit object, shared release, ancestry, or regression test does not by itself establish same-mechanism incomplete remediation. MISP, OmniFaces, and OpenClaw require mechanism splits. The four CVE Services 404s remain `UNKNOWN`: the live GitHub declarations are evidence of assigned mappings and released fixes, while the absent CVE records cannot be reported as published, rejected, or withdrawn.
