# First-party identity and alias QA for post-strict-baseline rows

Status: **PARTIAL**  
Campaign shard: `herdr-260812-alias-qa`  
Snapshot window: 2026-08-12T16:17:32Z to 2026-08-12T16:34:56Z  
Owned output: `/home/hanqing/agents/ai-slop/autoresearch/herdr-260812-alias-qa/`

## Result first

I audited 76 input row instances representing 74 distinct post-baseline semantic rows. The row-instance ledger is:

| Action | Count | Meaning |
|---|---:|---|
| `KEEP` | 65 | Declared identity closed against available first-party objects; exact proposed fix object resolved. |
| `ADD_ALIAS` | 2 | A repository advisory is a declared alias of the row CVE and was absent from the input row. |
| `SPLIT` | 1 | One advisory pair also covers a different mechanism and cannot be imported wholesale into the row. |
| `REMOVE_ID` | 2 | Remove the duplicate *row occurrence* from the aggregate; retain the canonical row and its IDs. |
| `UNKNOWN` | 6 | First-party identity or exact same-mechanism fix-set closure is incomplete. |

The two additions are `GHSA-CGJ8-7M5Q-X5GV` for `CVE-2026-34198` and `GHSA-48P8-G2FX-3WWM` for `CVE-2026-54526`. The two removals are duplicate Coolify occurrences, not invalid public IDs. The split is the OpenClaw Feishu webhook row. No source ledger was edited.

The de-duplicated input census is 15 strict released rows, 47 incomplete-remediation released rows, and 12 commit-only rows: 172 released rows including the 110-row strict baseline, or 184 including commit-only rows. Those are source-census arithmetic only. They are **not** publication-grade totals because one strict released row requires a mechanism split and six rows remain `UNKNOWN`. The source aggregate's 173/186 arithmetic is inflated by one released and one commit-only duplicate Coolify occurrence.

Across the frozen candidate set, 119 distinct declared input IDs expanded to 121 official declared IDs after the two alias additions. All 71 distinct proposed exact fix objects resolved through the repository commit API. I found zero baseline-ID overlaps, zero declared-ID collisions across different semantic rows, zero repository mismatches, zero global/repository declared-identifier conflicts, zero withdrawn advisories, and zero rejected CVE records. These are bounded negative controls, not proof that no future first-party record can change.

## Scope and exclusion boundary

The strict baseline was `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl`: 110 semantic components and 200 public IDs. Every baseline public ID was loaded into an exclusion set before evaluating additions; the post-baseline candidate intersection with that set was empty. Already adjudicated baseline rows and prior negative/neutral controls were not rerun. There was no 51,218-unit census, broad build, release re-test, or main-ledger mutation.

Candidate rows came only from the newest post-baseline reports listed below. A second, independent read-only inventory is preserved in `candidate_inventory.md`; it also found 15 strict additions, 47 distinct released incomplete-remediation rows, 12 distinct commit-only rows, and the two duplicate Coolify occurrences.

All input hashes were taken before the first-party sweep and again at finalization. Start and end SHA-256 values were identical (`input_changed_during_run=false`).

| Read-only input | SHA-256 |
|---|---|
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md` | `a7dd3db373af0fae98c10f8c96c58180cf80fc132fb6fb53fedbd44f3aae22c2` |
| `docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` | `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md` | `318912fbc789ef7f0708044d2041c24fa69198f878c2c668b04af86031d4616e` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-C-2026-08-12.md` | `b1e03cb193003ebbba83b73b8d8bbcbcd72f02148ba00812967a2721e60a8ffd` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md` | `3a8482a6badb0b8bff5dbf64adc18b37493c68dc56a25598be91ee3be7e727cd` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md` | `f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad` |
| `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl` | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |

`input_snapshot.json` contains sizes, nanosecond mtimes, and both snapshots.

## Method, exact commands, and primary sources

The bounded driver uses the Python standard library plus the already-installed GitHub CLI. It performs exact, per-ID/per-repository calls and caches every response only below this owned directory:

```text
python3 autoresearch/herdr-260812-alias-qa/qa.py
python3 -m py_compile autoresearch/herdr-260812-alias-qa/qa.py

gh api advisories/<GHSA> -H 'Accept: application/vnd.github+json'
gh api repos/<owner>/<repo>/security-advisories/<GHSA> -H 'Accept: application/vnd.github+json'
GET https://cveawg.mitre.org/api/cve/<CVE>
gh api repos/<owner>/<repo>/commits/<SHA> -H 'Accept: application/vnd.github+json'
```

The final authoritative request plan contains 269 exact lookups. `requests.json` records every endpoint and HTTP status; `api-cache/` preserves raw JSON/error objects. The final rerun was cache-only and took under one second. No credential value is present in the report, request log, or cache.

Alias closure uses only first-class GitHub `ghsa_id`, `cve_id`, and `identifiers` fields, plus a CVE record's direct reference to a concrete repository advisory when that advisory declares the same CVE. IDs merely mentioned in descriptions, generic references, predecessor notes, or sibling-advisory prose are recorded under `related_cross_links` and never promoted to aliases. An early diagnostic sweep demonstrated the failure mode of treating prose IDs as aliases; the final ledger excludes that polluted closure. There are 39 row instances (38 distinct rows) with 59 distinct non-alias related IDs preserved for review.

For each proposed fix, the exact repository commit endpoint had to resolve to a concrete full SHA. Object resolution proves identity/existence only; it does not by itself prove remediation, released containment, or same-mechanism lineage. Where an official advisory lists a larger carrier/fix set, the row's narrower exact fix is preserved separately.

## Material row decisions

### ADD_ALIAS

1. `coolify-trust-host-cache@canonical`: add `GHSA-CGJ8-7M5Q-X5GV` beside `CVE-2026-34198`. The [repository advisory object](https://api.github.com/repos/coollabsio/coolify/security-advisories/GHSA-CGJ8-7M5Q-X5GV) is published and declares the CVE; the [CVE Services record](https://cveawg.mitre.org/api/cve/CVE-2026-34198) is `PUBLISHED` and points back to the advisory. GitHub's global advisory endpoint returned 404, so the repository object is the authoritative GitHub side. Exact row fix: [`e1d4b4682efc898ba5aa3751b2da2072f89c7e24`](https://github.com/coollabsio/coolify/commit/e1d4b4682efc898ba5aa3751b2da2072f89c7e24). The CVE record also cites carrier commit [`98569e4edbfc316877c9e0d27ea89fab3c49e3bd`](https://github.com/coollabsio/coolify/commit/98569e4edbfc316877c9e0d27ea89fab3c49e3bd); it does not replace the row's atomic member.

2. `argo-artifactgc-podspec@canonical`: add `GHSA-48P8-G2FX-3WWM` beside `CVE-2026-54526`. The [repository advisory object](https://api.github.com/repos/argoproj/argo-workflows/security-advisories/GHSA-48P8-G2FX-3WWM) is published and declares the CVE; the [CVE Services record](https://cveawg.mitre.org/api/cve/CVE-2026-54526) is `PUBLISHED` and cites both exact branch fixes. GitHub's global advisory endpoint returned 404. Exact fixes: [`358cc3968c8f06f1be0967e41df191088db0b662`](https://github.com/argoproj/argo-workflows/commit/358cc3968c8f06f1be0967e41df191088db0b662) and [`277e9cef0ad16d7eaaab253573d0695951a65dbd`](https://github.com/argoproj/argo-workflows/commit/277e9cef0ad16d7eaaab253573d0695951a65dbd). References to `CVE-2026-31892`, `GHSA-3775-99MW-8RP4`, and `GHSA-3WF5-G532-RCRR` are predecessor/sibling cross-links, not aliases.

### SPLIT

`openclaw-feishu-webhook@canonical` currently combines two published advisory pairs:

- [`CVE-2026-32974`](https://cveawg.mitre.org/api/cve/CVE-2026-32974) / [`GHSA-G353-MGV3-8PCJ`](https://api.github.com/repos/openclaw/openclaw/security-advisories/GHSA-G353-MGV3-8PCJ), exact fix [`7844bc89a1612800810617c823eb0c76ef945804`](https://github.com/openclaw/openclaw/commit/7844bc89a1612800810617c823eb0c76ef945804).
- [`CVE-2026-44109`](https://cveawg.mitre.org/api/cve/CVE-2026-44109) / [`GHSA-XH72-V6V9-MWHC`](https://api.github.com/repos/openclaw/openclaw/security-advisories/GHSA-XH72-V6V9-MWHC), exact fix [`c8003f1b33ed2924be5f62131bd28742c5a41aae`](https://github.com/openclaw/openclaw/commit/c8003f1b33ed2924be5f62131bd28742c5a41aae).

The second advisory includes the webhook fail-open surface **and** a distinct blank card-action-token mechanism. Keep only webhook-scoped evidence with this component; split the token mechanism rather than treating the whole advisory as one mechanism.

### REMOVE_ID (duplicate row occurrences only)

- `coolify-shell-grammar@batch-e` (`Batch-E:34`) is byte-for-field equivalent at the QA key level to `coolify-shell-grammar@main` (`Main:149`): same mechanism, `CVE-2026-42204`, `GHSA-CHG4-63HM-XV9X`, repository, tier, and exact fix `817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1`. Remove the Batch-E occurrence from aggregate counting; keep the canonical IDs.
- `coolify-activity-scope@batch-e` (`Batch-E:49`) duplicates `coolify-activity-scope@main` (`Main:159`): same mechanism, `CVE-2026-34167`, `GHSA-962V-GXMW-56HC`, repository, tier, and exact fix `3e0d48faeaab950bfd063dfca908f1d140316ede`. Remove the Batch-E occurrence from aggregate counting; keep the canonical IDs.

### UNKNOWN

| Row | First-party state at snapshot | Exact selected fix | Why it remains unknown |
|---|---|---|---|
| `misp-mass-assignment@canonical` | [CVE-2026-56422](https://cveawg.mitre.org/api/cve/CVE-2026-56422) is `PUBLISHED` and contains 16 exact commit references. | [`025f711506850aadb69cde1b57e5e5d57628c87f`](https://github.com/MISP/MISP/commit/025f711506850aadb69cde1b57e5e5d57628c87f) | The official record is a multi-mechanism, multi-fix set; the row does not isolate the exact AI-partial-to-complete same-mechanism subset. |
| `omnifaces-combined-resource@canonical` | [GHSA-FP43-VJ7G-PG92](https://api.github.com/repos/omnifaces/omnifaces/security-advisories/GHSA-FP43-VJ7G-PG92) is published globally and in-repository and cites five exact commits. | [`a52b92461cf39d983f51ce8724fe7e6b944073e4`](https://github.com/omnifaces/omnifaces/commit/a52b92461cf39d983f51ce8724fe7e6b944073e4) | The advisory is multi-mechanism/multi-fix; the selected same-mechanism subset is not closed. |
| `gitea-draft-attachment@canonical` | [GHSA-Q9PG-JJ6X-J9P6](https://api.github.com/repos/go-gitea/gitea/security-advisories/GHSA-Q9PG-JJ6X-J9P6) is published globally and in-repository and assigns CVE-2026-58432; [CVE Services](https://cveawg.mitre.org/api/cve/CVE-2026-58432) returned 404. | [`f7fd51022495737cf960b8c4053a27d69148f664`](https://github.com/go-gitea/gitea/commit/f7fd51022495737cf960b8c4053a27d69148f664) | The CVE-side record does not yet close. |
| `gitea-oauth-reactivation@canonical` | [GHSA-VRHC-JJFC-M3M3](https://api.github.com/repos/go-gitea/gitea/security-advisories/GHSA-VRHC-JJFC-M3M3) is published globally and in-repository and assigns CVE-2026-55987; [CVE Services](https://cveawg.mitre.org/api/cve/CVE-2026-55987) returned 404. | [`fce961b44aa9631f8e9f5d6b3168d16d9a6728af`](https://github.com/go-gitea/gitea/commit/fce961b44aa9631f8e9f5d6b3168d16d9a6728af) | The CVE-side record does not yet close. |
| `praisonai-jwt-default@canonical` | [GHSA-F38V-77QJ-H4JQ](https://api.github.com/repos/MervinPraison/PraisonAI/security-advisories/GHSA-F38V-77QJ-H4JQ) is published globally and in-repository and assigns CVE-2026-57148; [CVE Services](https://cveawg.mitre.org/api/cve/CVE-2026-57148) returned 404. | [`e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747`](https://github.com/MervinPraison/PraisonAI/commit/e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747) | The CVE-side record does not yet close. |
| `gitea-private-org-members@canonical` | [GHSA-PRR9-9MP4-5GP2](https://api.github.com/repos/go-gitea/gitea/security-advisories/GHSA-PRR9-9MP4-5GP2) is published globally and in-repository and assigns CVE-2026-58427; [CVE Services](https://cveawg.mitre.org/api/cve/CVE-2026-58427) returned 404. | [`44ea3a8d24638ca4a395d641d39f476ae1dc421d`](https://github.com/go-gitea/gitea/commit/44ea3a8d24638ca4a395d641d39f476ae1dc421d) | The CVE-side record does not yet close. |

## Complete row-level ledger

This is the human-readable view of all 76 input instances. Full official URLs, endpoint states, mechanisms, official commit references, related-but-not-alias IDs, and resolved commit URLs are in `ledger.jsonl`. For every CVE, the official URL is `https://cveawg.mitre.org/api/cve/<CVE>`; for every GHSA, both `https://api.github.com/advisories/<GHSA>` and `https://api.github.com/repos/<repo>/security-advisories/<GHSA>` were attempted. Every full SHA below resolved at `https://api.github.com/repos/<repo>/commits/<SHA>`.

| Row key | Source | Declared input IDs | Exact selected fix identity | Action |
|---|---|---|---|---|
| `bsv-arc-status@canonical` | Batch-A:15 | CVE-2026-40069<br>GHSA-9HFR-GW99-8RHX | `db97de475518eef752ed52b25f49f09cbe24c187` | **KEEP** |
| `bsv-certificate-signature@canonical` | Batch-A:16 | CVE-2026-40070<br>GHSA-HC36-C89J-5F4J | `db97de475518eef752ed52b25f49f09cbe24c187` | **KEEP** |
| `claude-cache-statusline-injection@canonical` | Batch-A:17 | CVE-2026-45136<br>GHSA-G3XQ-3GMV-QQ8G | `0a3e3c130e1ec803a2107fe83775d97f5f8f6dde` | **KEEP** |
| `hermes-first-user-takeover@canonical` | Main:63 | CVE-2026-49973<br>GHSA-P52P-4VMG-4VQ3 | `f2ef2851d389cf7a41308dcf0180d7cfbe446379` | **KEEP** |
| `hermes-profile-search@canonical` | Main:64 | CVE-2026-49956<br>GHSA-MGXW-V6RH-WCV6 | `8d8ae89d27a4547b2edc388a986ef0d55549f7d4` | **KEEP** |
| `coolify-trust-host-cache@canonical` | Main:65 | CVE-2026-34198 | `e1d4b4682efc898ba5aa3751b2da2072f89c7e24` | **ADD_ALIAS** |
| `openclaw-minimax-redirect@canonical` | OpenClaw:57 | CVE-2026-44992<br>GHSA-H2VW-PH2C-JVWF | `2f06696579a1ab0cb5bbbbb6a900414a6b2e3cd1` | **KEEP** |
| `openclaw-gateway-url@canonical` | OpenClaw:58 | CVE-2026-25253<br>GHSA-G8P2-7WF7-98MQ | `a7534dc22382c42465f3676724536a014ce0cbf7` | **KEEP** |
| `openclaw-prompt-image@canonical` | OpenClaw:59 | GHSA-9F72-QCPW-2HXC | `370d115549c0dadace0902775eea0d5094aedfdc` | **KEEP** |
| `openclaw-browserbase-dns@canonical` | OpenClaw:60 | CVE-2026-43582<br>GHSA-XQ94-R468-QWGJ | `121c452d666d4749744dc2089287d0227aae2ed3` | **KEEP** |
| `openclaw-sips-pixel@canonical` | OpenClaw:61 | CVE-2026-41334<br>GHSA-W85G-3H6X-4XH2 | `0ed4f8a72bb140045962e97ab01c94c076b758a4` | **KEEP** |
| `openclaw-synology-rate-limit@canonical` | OpenClaw:62 | CVE-2026-35646<br>GHSA-MF5G-6R6F-GHHM | `0b4d07337467f4d40a0cc1ced83d45ceaec0863c` | **KEEP** |
| `openclaw-workspace-shadow@canonical` | OpenClaw:63 | CVE-2026-41295<br>GHSA-2QRV-RC5X-2G2H<br>CVE-2026-43571<br>GHSA-82QX-6VJ7-P8M2 | `53c29df2a9eb242a70d0ff29f3d1e67c8d6801f0`<br>`1fede43b948df40ca8674511d4bd08d39f6c5837` | **KEEP** |
| `openclaw-feishu-webhook@canonical` | OpenClaw:65 | CVE-2026-32974<br>GHSA-G353-MGV3-8PCJ<br>CVE-2026-44109<br>GHSA-XH72-V6V9-MWHC | `7844bc89a1612800810617c823eb0c76ef945804`<br>`c8003f1b33ed2924be5f62131bd28742c5a41aae` | **SPLIT** |
| `openclaw-feishu-tool-gate@canonical` | OpenClaw:66 | CVE-2026-62187<br>GHSA-2Q7J-2VHX-56G8<br>CVE-2026-62188<br>GHSA-W8WF-3QVJ-6XQF | `d4f11d3005a56abc709ebc8e715972593ebed96e` | **KEEP** |
| `zeptoclaw-shell-filter@canonical` | Main:107 | GHSA-5WP8-Q9MX-8JX8 | `68916c3e4f3af107f11940b27854fc7ef517058b` | **KEEP** |
| `praisonai-ssrf@canonical` | Main:108 | CVE-2026-47390<br>GHSA-5C6W-WWFQ-7QQM | `179cab02dbec0c1e9b601507a65908e079876004` | **KEEP** |
| `praisonai-python-exec@canonical` | Main:109 | CVE-2026-47392<br>GHSA-4MR5-G6F9-CFRH | `179cab02dbec0c1e9b601507a65908e079876004` | **KEEP** |
| `argo-artifactgc-podspec@canonical` | Main:110 | CVE-2026-54526 | `358cc3968c8f06f1be0967e41df191088db0b662`<br>`277e9cef0ad16d7eaaab253573d0695951a65dbd` | **ADD_ALIAS** |
| `fission-capabilities@canonical` | Main:111 | CVE-2026-50570<br>GHSA-QF5V-M7P4-95RP | `2569b42bfadbcb7d78b55a00a60f77937e522699` | **KEEP** |
| `mcp-registry-ssrf@canonical` | Main:112 | CVE-2026-44430<br>GHSA-R48C-V28R-PF6V | `f5f40bd98084466eaf18fe48ea62a0d534caa774` | **KEEP** |
| `fission-standalone-container@canonical` | Main:113 | CVE-2026-50566<br>GHSA-M63V-2G9W-2W6V | `695d3e97e3a20463ab7c8c081843e69e65e952e5` | **KEEP** |
| `fission-path-prefix@canonical` | Main:114 | CVE-2026-50568<br>GHSA-R5JH-Q2MW-GCX4 | `8298e33ea7457702f893eae11077987cf905edb4` | **KEEP** |
| `clearancekit-auth-clone@canonical` | Main:115 | CVE-2026-33632<br>GHSA-WPXJ-VHFP-HHVM | `6181c4a22eccbeca973c77f4bd023eb795c13786` | **KEEP** |
| `fireshare-checksum-path@canonical` | Main:116 | CVE-2026-34745<br>GHSA-FVVP-RJ8G-C7GC | `70b5b35aadd55c7936a25effd6f3e9ee4c124879` | **KEEP** |
| `filebrowser-scoped-fs@canonical` | Main:117 | CVE-2026-54094<br>GHSA-239W-M3H6-CH8V | `64511ce45e3be379e965f7f4fb0929a068d5bb81` | **KEEP** |
| `kiota-path-decoding@canonical` | Main:118 | GHSA-P5RM-JG5C-8C77 | `430008e9d700b3fe80f206c672415cfbd8e830e7` | **KEEP** |
| `vm2-nesting-require@canonical` | Main:119 | CVE-2026-47137<br>GHSA-M4WX-M65X-GHRR | `86ab819f202c3a8dad88cef5705f2e416c5188d7` | **KEEP** |
| `gitpython-kwarg-option@canonical` | Main:131 | GHSA-R9MR-M37C-5FR3 | `e8d0fbf774d1f6baa3b481adfe48bd262e43b453` | **KEEP** |
| `gitpython-url-env@canonical` | Main:132 | GHSA-94P4-4CQ8-9G67 | `863417457a0633db7ea5aed4fd01e0b291a41162` | **KEEP** |
| `gitpython-clone-template@canonical` | Main:133 | GHSA-6P8H-3WGX-97GF | `ffcb5359e87619f4fe4a70a4aff5f08c5580ba97` | **KEEP** |
| `gitpython-config-section@canonical` | Main:134 | GHSA-3RP5-JJMW-4WV2 | `1ed1b924f4e2d2ee7bab296df77b978af21853f1` | **KEEP** |
| `gitpython-archive-options@canonical` | Main:135 | GHSA-539M-9XH6-Q6RR | `7a4f5dcb7bf3cbcbf6e438017efcdfe0bc0d36ca` | **KEEP** |
| `gitpython-revlist-output@canonical` | Main:136 | GHSA-P538-C434-8V24 | `38553b6fddc7f6a667cdb45a6762343a08fc72b2` | **KEEP** |
| `gitpython-checkout-tag-options@canonical` | Main:137 | GHSA-3F7W-8RR8-F37F | `3af0c2516c5e18c829da30338614688f6b69b49c` | **KEEP** |
| `coolify-shell-grammar@main` | Main:149 | CVE-2026-42204<br>GHSA-CHG4-63HM-XV9X | `817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1` | **KEEP** |
| `coolify-activity-scope@main` | Main:159 | CVE-2026-34167<br>GHSA-962V-GXMW-56HC | `3e0d48faeaab950bfd063dfca908f1d140316ede` | **KEEP** |
| `n8n-mcp-ipv6-ssrf@canonical` | Batch-B:13 | CVE-2026-42449<br>GHSA-56C3-VFP2-5QQJ | `9639f757853149f0cb16663cc8b6b6468f27a25f` | **KEEP** |
| `prospero-permission-save@canonical` | Batch-B:27 | CVE-2026-59233 | `86a7d6557bd111518a221f4575ad6e36087e19d3` | **KEEP** |
| `prospero-calendar-delete@canonical` | Batch-B:40 | CVE-2026-59234 | `8c26eed4d80544c30e55448e12a8e999af6d2b70` | **KEEP** |
| `prospero-notification-delete@canonical` | Batch-B:50 | CVE-2026-59240 | `eaee2ae018701d116164976cbfa37fa9294ab4cc` | **KEEP** |
| `dynatrace-mcp-auth@canonical` | Batch-B:64 | GHSA-P7W7-4929-VPJ5 | `8f12972481e9165e8bd24d63b0a9e71976f85a43` | **KEEP** |
| `wacrm-automation-tenant@canonical` | Batch-B:72 | CVE-2026-49141 | `b4f18537bbf6787d18a9abafce53c557ac36f475` | **KEEP** |
| `misp-mass-assignment@canonical` | Batch-B:81 | CVE-2026-56422 | `025f711506850aadb69cde1b57e5e5d57628c87f` | **UNKNOWN** |
| `omnifaces-combined-resource@canonical` | Batch-B:90 | GHSA-FP43-VJ7G-PG92 | `a52b92461cf39d983f51ce8724fe7e6b944073e4` | **UNKNOWN** |
| `prospero-order-idor@canonical` | Batch-B:99 | CVE-2026-59237 | `9a859c4de3d49674916773d346c60d89ad7febe0` | **KEEP** |
| `langroid-pandas-eval@canonical` | Batch-C:15 | CVE-2026-25481<br>GHSA-X34R-63HX-W57F | `30abbc1a854dee22fbd2f8b2f575dfdabdb603ea` | **KEEP** |
| `vitest-cdp-gate@canonical` | Batch-C:34 | CVE-2026-53633<br>GHSA-G8MR-85JM-7XHM | `385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7` | **KEEP** |
| `mistune-percent-scheme@canonical` | Batch-C:48 | CVE-2026-59923<br>GHSA-8C25-4J27-2RV3 | `c7101fcbb6e8790e8e39157c5ca2238fc6dd6cbc` | **KEEP** |
| `mistune-legacy-scheme@canonical` | Batch-C:59 | CVE-2026-59929<br>GHSA-QFRW-5RXM-MHH2 | `c7101fcbb6e8790e8e39157c5ca2238fc6dd6cbc` | **KEEP** |
| `fast-uri-authority@canonical` | Batch-D:9 | CVE-2026-18446<br>GHSA-7P8R-X3MC-P8W7 | `f3c6c905f47831007490f466c5945012e905cc52` | **KEEP** |
| `locutus-prototype-pollution@canonical` | Batch-D:10 | CVE-2026-33994<br>GHSA-VC8F-X9PP-WF5P | `345a6211e1e6f939f96a7090bfeff642c9fcf9e4` | **KEEP** |
| `gitea-draft-attachment@canonical` | Batch-D:11 | CVE-2026-58432<br>GHSA-Q9PG-JJ6X-J9P6 | `f7fd51022495737cf960b8c4053a27d69148f664` | **UNKNOWN** |
| `scriban-array-multiply@canonical` | Batch-D:12 | GHSA-Q6RR-FM2G-G5X8 | `205ca6a7c2349d3d388bd5f1f7729ee198c0d5e5` | **KEEP** |
| `faraday-uri-authority@canonical` | Batch-D:13 | CVE-2026-33637<br>GHSA-5RV5-XJ5J-3484 | `3f1280c69e93297d574e85a2d462d05ebadf1d09` | **KEEP** |
| `filebrowser-delete-scope@canonical` | Batch-D:14 | CVE-2026-55667<br>GHSA-FMM7-X4GX-8JHR | `64511ce45e3be379e965f7f4fb0929a068d5bb81` | **KEEP** |
| `filebrowser-dangling-write@canonical` | Batch-D:15 | CVE-2026-55668<br>GHSA-8WC8-HF36-MJH9 | `64511ce45e3be379e965f7f4fb0929a068d5bb81` | **KEEP** |
| `scriban-parser-depth@canonical` | Batch-E:31 | GHSA-6Q7J-XR26-3H2C | `8fdbd687bbe8f00085c4c4c5b2b3b8d529933949` | **KEEP** |
| `gitea-oauth-reactivation@canonical` | Batch-E:32 | CVE-2026-55987<br>GHSA-VRHC-JJFC-M3M3 | `fce961b44aa9631f8e9f5d6b3168d16d9a6728af` | **UNKNOWN** |
| `praisonai-jwt-default@canonical` | Batch-E:33 | CVE-2026-57148<br>GHSA-F38V-77QJ-H4JQ | `e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747` | **UNKNOWN** |
| `coolify-shell-grammar@batch-e` | Batch-E:34 | CVE-2026-42204<br>GHSA-CHG4-63HM-XV9X | `817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1` | **REMOVE_ID** |
| `gitpython-joined-short-option@canonical` | Batch-E:35 | GHSA-V396-V7Q4-X2QJ | `56806080c1348749b07daa4a2024ce47b3cad285` | **KEEP** |
| `gitpython-section-newline@canonical` | Batch-E:36 | GHSA-MV93-W799-CJ2W | `54538428f79b0c91ba52cda5229856a6edf7ac06` | **KEEP** |
| `gitpython-diff-output@canonical` | Batch-E:37 | GHSA-FJR4-X663-MWXC | `1d51b891d7f236044a6aa17498ec682b63dad6e6` | **KEEP** |
| `gitpython-pathspec-file@canonical` | Batch-E:38 | GHSA-HH9P-6WH2-4MFC | `f2550b65bf60ca087190981e2c7b6865e201f40c` | **KEEP** |
| `gitpython-init-template@canonical` | Batch-E:39 | GHSA-9RJ7-RF2P-W77R | `d9ddb55bdc66ffe8c9932fe460e6b8c8211e47c7` | **KEEP** |
| `gitpython-read-tree-index@canonical` | Batch-E:40 | GHSA-4GMW-GG2M-W46P | `9b5dcaf85da5946dbf69dcd53f9edba08f760b32` | **KEEP** |
| `gitpython-split-mode@canonical` | Batch-E:41 | GHSA-WVPP-8HX9-P66J | `96a888f4d782cb2f80452148e48e60ce4af6d541` | **KEEP** |
| `gitpython-option-name@canonical` | Batch-E:42 | GHSA-JM78-9FVV-MHGR | `a495ccd3b547ccd60b2187215823b72a9c0188bf` | **KEEP** |
| `gitpython-config-reserialize@canonical` | Batch-E:43 | GHSA-284H-M62Q-GF8W | `4b4e47fc1224e23b0c8ee7220a7192818f2e4abb` | **KEEP** |
| `gitpython-separate-git-dir@canonical` | Batch-E:44 | GHSA-8MCC-HRX5-HVXC | `b68afff45af0f49e79a3e2d2162018986b37ad5d` | **KEEP** |
| `gitpython-blame-contents@canonical` | Batch-E:45 | GHSA-5XXX-QHH7-9287 | `1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6` | **KEEP** |
| `gitpython-tag-positional-file@canonical` | Batch-E:46 | GHSA-3WXW-XV34-2FRG | `1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6` | **KEEP** |
| `scriban-lazy-range@canonical` | Batch-E:47 | GHSA-89CF-6HMV-8RXM | `973edd1f1c10fae7d3a8650ac0d309d52072102c` | **KEEP** |
| `gitea-private-org-members@canonical` | Batch-E:48 | CVE-2026-58427<br>GHSA-PRR9-9MP4-5GP2 | `44ea3a8d24638ca4a395d641d39f476ae1dc421d` | **UNKNOWN** |
| `coolify-activity-scope@batch-e` | Batch-E:49 | CVE-2026-34167<br>GHSA-962V-GXMW-56HC | `3e0d48faeaab950bfd063dfca908f1d140316ede` | **REMOVE_ID** |

## Negative controls and claim boundary

- The first-party objects found no withdrawn or rejected candidate IDs at this snapshot.
- No declared public ID was shared by different canonical row IDs. Reused fix commits were not treated as identity collisions: one commit can repair multiple mechanisms.
- GitHub global 404 is not automatically absence: repository advisories for the two added aliases and several other private-origin objects are authoritative and published even when the global endpoint is unavailable.
- The four assigned Gitea/PraisonAI CVEs whose CVE Services endpoints returned 404 remain `UNKNOWN`; a GitHub-assigned `cve_id` was not presented as a published CVE record.
- Related/predecessor/sibling IDs remain cross-links. They are not aliases unless first-class identifier fields close the pair.
- `KEEP` means first-party identity QA passed within this frozen input, not that the vulnerability, partial fix, release containment, or benchmark claim was independently reproduced.
- Commit endpoint resolution is diagnostic object evidence. Publication-grade claims still require exact candidate/fix lineage, the same security mechanism, first-party advisory identity, and a release that contains the fix.
- Source recovery, local routing, candidate discovery, and this QA do not produce a performance or prevalence claim.

One early diagnostic created two short-lived `/tmp/aliasqa-*` files before the owned temp boundary was enforced; they were removed immediately and no persistent out-of-scope file was left. All durable artifacts and every API cache entry are under the owned directory.

## Artifact map

- `report.md`: this narrative and row-level ledger.
- `result.json`: terminal status, counts, blockers, and timestamps.
- `ledger.jsonl`: authoritative machine-readable row decisions with official URLs and exact fix objects.
- `summary.json`: counts, duplicate map, input snapshots, and request failures.
- `input_snapshot.json`: frozen start/end input metadata.
- `requests.json`: exact final request plan and endpoint status.
- `api-cache/`: raw GitHub/CVE/commit responses, including 404 objects.
- `candidate_inventory.md`: independent diagnostic inventory.
- `qa.py`: bounded reproducible driver.
