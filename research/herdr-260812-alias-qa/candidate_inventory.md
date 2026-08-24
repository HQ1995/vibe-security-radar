# Post-baseline first-party identity / alias QA inventory

## Scope and claim boundary

This is a **read-only, diagnostic inventory** for the API-verifying parent task. It does not alter any ledger and does not promote routing, source recovery, model output, a shared fix SHA, or a report count into publication-grade evidence. Final row dispositions remain `KEEP`, `ADD_ALIAS`, `SPLIT`, `REMOVE_ID`, or `UNKNOWN` only after repository advisory, GitHub global advisory, CVE Services, mechanism, and released-fix identity agree.

Snapshot boundary: current shared-checkout bytes read between 2026-08-12 12:18 and 12:55 America/New_York. The checkout is volatile; the SHA-256 values below bind every input used. No network or API call was made by this reader.

## Strict baseline and rows excluded from re-adjudication

The strict baseline is:

- `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl`
- byte SHA-256 `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81`
- 110 JSONL rows / 110 distinct `component_id` values / 200 case-normalized public IDs (101 CVE, 99 GHSA), independently counted from the snapshot
- canonical JSON hash `afc810cec757df378cc63be935a53fe6635dbb7ede72bc32035880ffcde23c23` is a different, intentionally canonicalized hash documented in `docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md:92-94`; it is not a byte-hash mismatch

**Exclude all 110 baseline components and all 200 normalized baseline IDs.** They are already adjudicated. In particular, do not redo the four alias amendments in `strict-200-v3/supplement.json` (WACRM GHSA-8JQH-598V-RFXC; OpenClaw GHSA-H3X4-HC5V-V2GM with polluted CVE-2026-34426 explicitly excluded; Ruflo GHSA-C4HM-4H84-2CF3; agentic-flow GHSA-VCV2-R9JH-99M5), or the three supplemental semantic components. Source: `supplement.json:1-137` and `summary.json:1-25`.

Also exclude these already adjudicated negative controls rather than reopening them:

- OpenClaw frontier rows 8, 11, and 12: AI hunk erased before squash, ghost-blame, and unrelated ancestor, respectively (`docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md:159-171,209-217`).
- File Browser CVE-2026-62843: baseline duplicate (`docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md:99-110`).
- Batch A Pydantic CVE-2026-54249 strict candidate: squash projection failure; n8n-mcp is excluded only from `STRICT_CAUSAL` and retained below under incomplete remediation (`docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md:258-287`).
- The negative/NR controls in the aggregate at `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md:204-213`, including PraisonAI CVE-2026-62181 / GHSA-CV3G-HJ65-PCFH; preserve them as FAIL/NR, not inferred negatives for another mechanism.

## High-priority alias/collision diagnostics

1. **Coolify released duplicate occurrence.** `CVE-2026-42204 / GHSA-CHG4-63HM-XV9X`, mechanism `shellSafeCommandRules()` bare `&`, exact fix member `817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1`, carrier `e1aac50b745cf499e710b7e35cd2a9d6a1538dd9`, appears in the aggregate before Batch B (`MAIN:147-150`) and again as Batch E row 4 (`BATCH-E:34,69-73`). It is one component; the GHSA is an alias amendment candidate, not a new component.
2. **Coolify commit-only duplicate occurrence.** `CVE-2026-34167 / GHSA-962V-GXMW-56HC`, ActivityMonitor fail-open, exact fix member `3e0d48faeaab950bfd063dfca908f1d140316ede`, carrier `2729dffb3e30167c1ffd642357b7e0bb99b7d180`, appears in the aggregate's initial commit-only section (`MAIN:153-163`) and again as Batch E row 19 (`BATCH-E:49,69-73`). It is one component; the GHSA is an alias amendment candidate.
3. Consequently, direct row enumeration yields **47 distinct released incomplete-remediation components / 67 listed distinct public IDs** and **12 distinct commit-only components / 18 listed distinct public IDs**, versus the aggregate's 48/68 and 13/19. The one-component/one-ID inflation in each lane is exactly consistent with re-counting the pre-existing Coolify CVE when Batch E added or surfaced its GHSA. This is diagnostic; parent must verify the first-party objects before changing counts.
4. OpenClaw has three deliberate one-to-many semantic groupings that are **not formal aliases** and need mechanism-level API review: workspace shadow (two CVE/GHSA pairs), Feishu webhook (two pairs, with XH72 also containing a separate blank card-action-token mechanism), and account tool gate (two pairs). Do not convert “same central fix” into alias identity automatically.
5. Shared candidate/fix SHAs are not alias evidence: PraisonAI 47390/47392, Fission 50570/50566, Mistune 59923/59929, File Browser 55667/55668, Scriban resource-bound rows, and the GitPython families are explicitly separate mechanisms in their source reports.

## Candidate rows: released `STRICT_CAUSAL` after strict-200-v3 (15 distinct)

`fix` below is the exact atomic reversal; a `member => carrier` pair preserves squash topology.

| # | Public IDs | Repository | Exact fix identity | Local source |
|---:|---|---|---|---|
| S1 | CVE-2026-40069 / GHSA-9HFR-GW99-8RHX | sgbett/bsv-ruby-sdk | `db97de475518eef752ed52b25f49f09cbe24c187 => 4992e8a265fd914a7eeb0405c69d1ff0122a84cc` | `MAIN:67`; `BATCH-A:48-99` |
| S2 | CVE-2026-40070 / GHSA-HC36-C89J-5F4J | sgbett/bsv-ruby-sdk | same member `db97de475518eef752ed52b25f49f09cbe24c187` / carrier `4992e8a265fd914a7eeb0405c69d1ff0122a84cc`, distinct certificate mechanism | `MAIN:68`; `BATCH-A:110-163` |
| S3 | CVE-2026-45136 / GHSA-G3XQ-3GMV-QQ8G | cnighswonger/claude-code-cache-fix | `0a3e3c130e1ec803a2107fe83775d97f5f8f6dde => 613e4df30547f3e6baf32d161eddc828f171da17` | `MAIN:69`; `BATCH-A:174-237` |
| S4 | CVE-2026-49973 / GHSA-P52P-4VMG-4VQ3 | nesquena/hermes-webui | `f2ef2851d389cf7a41308dcf0180d7cfbe446379 => 1126e541325d401538f6a272a9c024c37d47ae08` | `MAIN:70` |
| S5 | CVE-2026-49956 / GHSA-MGXW-V6RH-WCV6 | nesquena/hermes-webui | `8d8ae89d27a4547b2edc388a986ef0d55549f7d4 => 2c7b530071bb29ae4184e83e33be5799d529568e` | `MAIN:71` |
| S6 | CVE-2026-34198 (GHSA discovery priority) | coollabsio/coolify | `e1d4b4682efc898ba5aa3751b2da2072f89c7e24 => 98569e4edbfc316877c9e0d27ea89fab3c49e3bd` | `MAIN:72` |
| S7 | CVE-2026-44992 / GHSA-H2VW-PH2C-JVWF | openclaw/openclaw | `2f06696579a1ab0cb5bbbbb6a900414a6b2e3cd1` | `OPENCLAW:57,84-90,175-176` |
| S8 | CVE-2026-25253 / GHSA-G8P2-7WF7-98MQ | openclaw/openclaw | `a7534dc22382c42465f3676724536a014ce0cbf7` | `OPENCLAW:58,92-97,178-179` |
| S9 | GHSA-9F72-QCPW-2HXC (reported GHSA-only) | openclaw/openclaw | `370d115549c0dadace0902775eea0d5094aedfdc` | `OPENCLAW:59,99-104,181-182` |
| S10 | CVE-2026-43582 / GHSA-XQ94-R468-QWGJ | openclaw/openclaw | `121c452d666d4749744dc2089287d0227aae2ed3` | `OPENCLAW:60,106-113,184-185` |
| S11 | CVE-2026-41334 / GHSA-W85G-3H6X-4XH2 | openclaw/openclaw | `0ed4f8a72bb140045962e97ab01c94c076b758a4` | `OPENCLAW:61,115-123,187-188` |
| S12 | CVE-2026-35646 / GHSA-MF5G-6R6F-GHHM | openclaw/openclaw | `0b4d07337467f4d40a0cc1ced83d45ceaec0863c` (origin member `cc048a... => 03586e...`) | `OPENCLAW:62,74-81,125-132,190-193` |
| S13 | CVE-2026-41295 / GHSA-2QRV-RC5X-2G2H **and** CVE-2026-43571 / GHSA-82QX-6VJ7-P8M2 | openclaw/openclaw | `53c29df2a9eb242a70d0ff29f3d1e67c8d6801f0` then `1fede43b948df40ca8674511d4bd08d39f6c5837` | `OPENCLAW:63,134-142,195-199`; non-formal-alias grouping, `KEEP` vs `SPLIT` priority |
| S14 | CVE-2026-32974 / GHSA-G353-MGV3-8PCJ **and webhook part of** CVE-2026-44109 / GHSA-XH72-V6V9-MWHC | openclaw/openclaw | `7844bc89a1612800810617c823eb0c76ef945804` then `c8003f1b33ed2924be5f62131bd28742c5a41aae` | `OPENCLAW:65,144-149,201-205`; XH72 also contains unrelated card-action mechanism: likely `SPLIT`/scoped-ID review |
| S15 | CVE-2026-62187 / GHSA-2Q7J-2VHX-56G8 **and** CVE-2026-62188 / GHSA-W8WF-3QVJ-6XQF | openclaw/openclaw | `d4f11d3005a56abc709ebc8e715972593ebed96e` | `OPENCLAW:66,151-157,207-208`; non-formal-alias grouping, `KEEP` vs `SPLIT` priority |

## Candidate rows: released `AI_INCOMPLETE_REMEDIATION` (47 distinct)

The source aggregate claims 48; `I19` is the single Coolify row re-listed as Batch E row 4 and is counted once here.

| # | Public IDs | Repository | Exact complete closure / fix identity | Local source |
|---:|---|---|---|---|
| I1 | GHSA-5WP8-Q9MX-8JX8 | qhkm/zeptoclaw | `68916c3e4f3af107f11940b27854fc7ef517058b` | `MAIN:107`; exact lineage `AUDIT-CONSOLIDATED-LEDGER-156-2026-08-11.md:70` |
| I2 | CVE-2026-47390 / GHSA-5C6W-WWFQ-7QQM | MervinPraison/PraisonAI | `179cab02dbec0c1e9b601507a65908e079876004` | `MAIN:108` |
| I3 | CVE-2026-47392 / GHSA-4MR5-G6F9-CFRH | MervinPraison/PraisonAI | same `179cab02dbec0c1e9b601507a65908e079876004`, distinct Python-exec mechanism | `MAIN:109` |
| I4 | CVE-2026-54526 (GHSA discovery priority) | argoproj/argo-workflows | branch fixes `358cc3968c8f06f1be0967e41df191088db0b662` and `277e9cef0ad16d7eaaab253573d0695951a65dbd` | `MAIN:110`; exact lineage `RESEARCH-CAUSAL-LEDGER-V2-2026-08-11.md:95` |
| I5 | CVE-2026-50570 / GHSA-QF5V-M7P4-95RP | fission/fission | `2569b42bfadbcb7d78b55a00a60f77937e522699` | `MAIN:111`; exact lineage `RESEARCH-CAUSAL-LEDGER-V2-2026-08-11.md:97` |
| I6 | CVE-2026-44430 / GHSA-R48C-V28R-PF6V | modelcontextprotocol/registry | `f5f40bd98084466eaf18fe48ea62a0d534caa774` | `MAIN:112`; exact lineage `RESEARCH-CAUSAL-LEDGER-V2-2026-08-11.md:98` |
| I7 | CVE-2026-50568 / GHSA-R5JH-Q2MW-GCX4 | fission/fission | `8298e33ea7457702f893eae11077987cf905edb4` | `MAIN:114`; exact lineage `RESEARCH-CAUSAL-LEDGER-V2-2026-08-11.md:100` |
| I8 | CVE-2026-33632 / GHSA-WPXJ-VHFP-HHVM | craigjbass/clearancekit | `6181c4a22eccbeca973c77f4bd023eb795c13786` | `MAIN:115` |
| I9 | CVE-2026-34745 / GHSA-FVVP-RJ8G-C7GC | ShaneIsrael/fireshare | `70b5b35aadd55c7936a25effd6f3e9ee4c124879 => b76915607924756e6fa1a5f6c8823c38d611fb24` | `MAIN:116` |
| I10 | CVE-2026-54094 / GHSA-239W-M3H6-CH8V | filebrowser/filebrowser | final `64511ce45e3be379e965f7f4fb0929a068d5bb81` after `7c2c0a11b31b2bb214d741005a0b02b1764208b3` | `MAIN:117` |
| I11 | CVE-2026-47137 / GHSA-M4WX-M65X-GHRR | patriksimek/vm2 | final `86ab819f202c3a8dad88cef5705f2e416c5188d7` after `01a7552add345d5a6862623884e6b79a85bf0568` | `MAIN:119` |
| I12 | GHSA-R9MR-M37C-5FR3 | gitpython-developers/GitPython | `e8d0fbf774d1f6baa3b481adfe48bd262e43b453` | `MAIN:131` |
| I13 | GHSA-94P4-4CQ8-9G67 | gitpython-developers/GitPython | `863417457a0633db7ea5aed4fd01e0b291a41162` | `MAIN:132` |
| I14 | GHSA-6P8H-3WGX-97GF | gitpython-developers/GitPython | `ffcb5359e87619f4fe4a70a4aff5f08c5580ba97` | `MAIN:133` |
| I15 | GHSA-3RP5-JJMW-4WV2 | gitpython-developers/GitPython | `1ed1b924f4e2d2ee7bab296df77b978af21853f1` | `MAIN:134` |
| I16 | GHSA-539M-9XH6-Q6RR | gitpython-developers/GitPython | `7a4f5dcb7bf3cbcbf6e438017efcdfe0bc0d36ca` | `MAIN:135`; advisory patched-version operator reportedly malformed (`MAIN:141`) |
| I17 | GHSA-P538-C434-8V24 | gitpython-developers/GitPython | `38553b6fddc7f6a667cdb45a6762343a08fc72b2` | `MAIN:136` |
| I18 | GHSA-3F7W-8RR8-F37F | gitpython-developers/GitPython | `3af0c2516c5e18c829da30338614688f6b69b49c` | `MAIN:137`; advisory patched-version operator reportedly malformed (`MAIN:141`) |
| I19 | CVE-2026-42204 / GHSA-CHG4-63HM-XV9X | coollabsio/coolify | `817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1 => e1aac50b745cf499e710b7e35cd2a9d6a1538dd9` | `MAIN:149`; duplicate occurrence `BATCH-E:34,69-73` |
| I20 | CVE-2026-42449 / GHSA-56C3-VFP2-5QQJ | czlonkowski/n8n-mcp | `9639f757853149f0cb16663cc8b6b6468f27a25f` | `BATCH-B:17-27` |
| I21 | CVE-2026-59233 | Prospero Flow CRM repo named by source (CVE-only discovery priority) | `86a7d6557bd111518a221f4575ad6e36087e19d3` | `BATCH-B:29-39` |
| I22 | CVE-2026-59234 | Prospero Flow CRM | `8c26eed4d80544c30e55448e12a8e999af6d2b70` | `BATCH-B:41-49` |
| I23 | CVE-2026-59240 | Prospero Flow CRM | `eaee2ae018701d116164976cbfa37fa9294ab4cc` | `BATCH-B:51-60` |
| I24 | CVE-2026-25481 / GHSA-X34R-63HX-W57F | langroid/langroid | `30abbc1a854dee22fbd2f8b2f575dfdabdb603ea` | `BATCH-C:16-27` |
| I25 | CVE-2026-18446 / GHSA-7P8R-X3MC-P8W7 | fastify/fast-uri | `f3c6c905f47831007490f466c5945012e905cc52` | `BATCH-D:34-41` |
| I26 | CVE-2026-33994 / GHSA-VC8F-X9PP-WF5P | locutusjs/locutus | `345a6211e1e6f939f96a7090bfeff642c9fcf9e4` | `BATCH-D:43-50` |
| I27 | CVE-2026-58432 / GHSA-Q9PG-JJ6X-J9P6 | go-gitea/gitea | `f7fd51022495737cf960b8c4053a27d69148f664` (backport `ab10e37acf7fabf7829a485cc3e13d118638a856`) | `BATCH-D:52-59` |
| I28 | GHSA-Q6RR-FM2G-G5X8 | scriban/scriban | `205ca6a7c2349d3d388bd5f1f7729ee198c0d5e5` | `BATCH-D:61-68` |
| I29 | CVE-2026-33637 / GHSA-5RV5-XJ5J-3484 | lostisland/faraday | `3f1280c69e93297d574e85a2d462d05ebadf1d09` | `BATCH-D:70-77` |
| I30 | CVE-2026-55667 / GHSA-FMM7-X4GX-8JHR | filebrowser/filebrowser | `64511ce45e3be379e965f7f4fb0929a068d5bb81` | `BATCH-D:79-86`; distinct delete/permission invariant |
| I31 | CVE-2026-55668 / GHSA-8WC8-HF36-MJH9 | filebrowser/filebrowser | same `64511ce45e3be379e965f7f4fb0929a068d5bb81` | `BATCH-D:88-97`; distinct dangling-write invariant |
| I32 | GHSA-6Q7J-XR26-3H2C | scriban/scriban | `8fdbd687bbe8f00085c4c4c5b2b3b8d529933949` | `BATCH-E:31,53-57` |
| I33 | CVE-2026-55987 / GHSA-VRHC-JJFC-M3M3 | go-gitea/gitea | `fce961b44aa9631f8e9f5d6b3168d16d9a6728af` | `BATCH-E:32,59-63` |
| I34 | CVE-2026-57148 / GHSA-F38V-77QJ-H4JQ | MervinPraison/PraisonAI | `e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747` | `BATCH-E:33,65-67` |
| I35 | GHSA-V396-V7Q4-X2QJ | gitpython-developers/GitPython | `56806080c1348749b07daa4a2024ce47b3cad285` | `BATCH-E:35,81` |
| I36 | GHSA-MV93-W799-CJ2W | gitpython-developers/GitPython | `54538428f79b0c91ba52cda5229856a6edf7ac06` | `BATCH-E:36,82` |
| I37 | GHSA-FJR4-X663-MWXC | gitpython-developers/GitPython | `1d51b891d7f236044a6aa17498ec682b63dad6e6` | `BATCH-E:37,83` |
| I38 | GHSA-HH9P-6WH2-4MFC | gitpython-developers/GitPython | `f2550b65bf60ca087190981e2c7b6865e201f40c` | `BATCH-E:38,84` |
| I39 | GHSA-9RJ7-RF2P-W77R | gitpython-developers/GitPython | `d9ddb55bdc66ffe8c9932fe460e6b8c8211e47c7` | `BATCH-E:39,85` |
| I40 | GHSA-4GMW-GG2M-W46P | gitpython-developers/GitPython | `9b5dcaf85da5946dbf69dcd53f9edba08f760b32` | `BATCH-E:40,86` |
| I41 | GHSA-WVPP-8HX9-P66J | gitpython-developers/GitPython | `96a888f4d782cb2f80452148e48e60ce4af6d541` | `BATCH-E:41,87` |
| I42 | GHSA-JM78-9FVV-MHGR | gitpython-developers/GitPython | `a495ccd3b547ccd60b2187215823b72a9c0188bf` | `BATCH-E:42,88` |
| I43 | GHSA-284H-M62Q-GF8W | gitpython-developers/GitPython | `4b4e47fc1224e23b0c8ee7220a7192818f2e4abb` | `BATCH-E:43,89` |
| I44 | GHSA-8MCC-HRX5-HVXC | gitpython-developers/GitPython | `b68afff45af0f49e79a3e2d2162018986b37ad5d` | `BATCH-E:44,90` |
| I45 | GHSA-5XXX-QHH7-9287 | gitpython-developers/GitPython | `1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6` | `BATCH-E:45,91` |
| I46 | GHSA-3WXW-XV34-2FRG | gitpython-developers/GitPython | same `1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6`, distinct API/sink | `BATCH-E:46,92` |
| I47 | GHSA-89CF-6HMV-8RXM | scriban/scriban | `973edd1f1c10fae7d3a8650ac0d309d52072102c` | `BATCH-E:47,53-57` |

## Candidate rows: commit-only (12 distinct; do not call released)

The source aggregate claims 13; `C3` is the same Coolify component re-listed as Batch E row 19 and is counted once here. `C8` is the sole strict-origin commit-only row; the other 11 are incomplete-remediation rows.

| # | Public IDs | Repository | Exact closure / fix identity | Local source / caveat |
|---:|---|---|---|---|
| C1 | CVE-2026-50566 / GHSA-M63V-2G9W-2W6V | fission/fission | `695d3e97e3a20463ab7c8c081843e69e65e952e5` | `MAIN:113,153`; exact lineage `RESEARCH-CAUSAL-LEDGER-V2-2026-08-11.md:99` |
| C2 | GHSA-P5RM-JG5C-8C77 | microsoft/kiota | `430008e9d700b3fe80f206c672415cfbd8e830e7` | `MAIN:118,154` |
| C3 | CVE-2026-34167 / GHSA-962V-GXMW-56HC | coollabsio/coolify | `3e0d48faeaab950bfd063dfca908f1d140316ede => 2729dffb3e30167c1ffd642357b7e0bb99b7d180` | `MAIN:155-163`; duplicate occurrence `BATCH-E:49,69-73` |
| C4 | GHSA-P7W7-4929-VPJ5 | dynatrace-oss/dynatrace-mcp | `8f12972481e9165e8bd24d63b0a9e71976f85a43` | `BATCH-B:64-69` |
| C5 | CVE-2026-49141 (GHSA discovery priority) | WACRM repository named by source | `b4f18537bbf6787d18a9abafce53c557ac36f475 => 73041bfa6420f5e1ecbfa1dd4fa847d8529320f5` | `BATCH-B:71-77` |
| C6 | CVE-2026-56422 (GHSA discovery priority) | MISP/MISP | exact closure is a multi-patch set; report gives exact AI partial `bc182d55dde5686a36ca2eb88fe6c2adabb9fad9` but only abbreviated remaining patch IDs | `BATCH-B:79-84`; **UNKNOWN exact complete fix-set until first-party objects are read** |
| C7 | GHSA-FP43-VJ7G-PG92 | omnifaces/omnifaces | exact closure is a multi-patch set; exact AI patches include `aa42da361821ddfbb85b126564e71587347d2786` and `a52b92461cf39d983f51ce8724fe7e6b944073e4` | `BATCH-B:86-91`; **UNKNOWN complete fix-set from report alone** |
| C8 | CVE-2026-59237 (strict commit-only; GHSA discovery priority) | Prospero Flow CRM | `9a859c4de3d49674916773d346c60d89ad7febe0` | `BATCH-B:93-101` |
| C9 | CVE-2026-53633 / GHSA-G8MR-85JM-7XHM | vitest-dev/vitest | `385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7` | `BATCH-C:31-41` |
| C10 | CVE-2026-59923 / GHSA-8C25-4J27-2RV3 | lepture/mistune | `c7101fcbb6e8790e8e39157c5ca2238fc6dd6cbc` | `BATCH-C:43-51` |
| C11 | CVE-2026-59929 / GHSA-QFRW-5RXM-MHH2 | lepture/mistune | same `c7101fcbb6e8790e8e39157c5ca2238fc6dd6cbc`, distinct grammar/policy residual | `BATCH-C:53-60` |
| C12 | CVE-2026-58427 / GHSA-PRR9-9MP4-5GP2 | go-gitea/gitea | `44ea3a8d24638ca4a395d641d39f476ae1dc421d => 122ebcf0a8f6f187575a42ad3023d8f8c5e9181b` | `BATCH-E:48,59-63` |

## Precise first-party lookup targets for the parent

For every GHSA above, query both objects and retain the raw response in the owned output directory:

```text
GET https://api.github.com/advisories/{GHSA-UPPER}
GET https://api.github.com/repos/{owner}/{repo}/security-advisories/{GHSA-lower-or-upper}
```

For every CVE above:

```text
GET https://cveawg.mitre.org/api/cve/{CVE-UPPER}
```

Minimum comparison fields: global `.ghsa_id,.cve_id,.withdrawn_at,.references[].url,.vulnerabilities[].package,.vulnerabilities[].vulnerable_version_range,.vulnerabilities[].first_patched_version`; repository `.ghsa_id,.cve_id,.state,.published_at,.withdrawn_at,.identifiers,.credits,.vulnerabilities,.references`; CVE Services `cveMetadata.cveId,state,datePublished,dateUpdated` plus CNA/ADP affected products, descriptions, references, and provider metadata. A global object may be polluted while the repository advisory and CNA are coherent; do not import an alias solely because it appears in a generic reference URL.

Highest-yield one-sided-ID discovery queue:

- CVE-only: S6 CVE-2026-34198; I4 CVE-2026-54526; I21-I23 CVE-2026-59233/59234/59240; C5 CVE-2026-49141; C6 CVE-2026-56422; C8 CVE-2026-59237.
- GHSA-only: S9 GHSA-9F72-QCPW-2HXC; I1; I12-I18; I28; I32; I35-I47; C2, C4, C7. “GHSA-only” is a lookup status, not evidence that no CVE exists.
- Known alias-amendment candidates rather than new rows: I19 GHSA-CHG4-63HM-XV9X for CVE-2026-42204 and C3 GHSA-962V-GXMW-56HC for CVE-2026-34167.

## Input hashes and exact read-only commands

| Input | SHA-256 |
|---|---|
| `strict-200-v3/ledger.jsonl` | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| `strict-200-v3/summary.json` | `69dd6c35de1455bf9cee88420aed570c576a190a4d143202d01a26cc3d37b81e` |
| `strict-200-v3/supplement.json` | `09a45c145313862f2d60b47cfe1df23bce9a1d7d3b6140592a913a364dfcbd4d` |
| `docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md` | `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md` | `a7dd3db373af0fae98c10f8c96c58180cf80fc132fb6fb53fedbd44f3aae22c2` |
| `docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` | `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md` | `318912fbc789ef7f0708044d2041c24fa69198f878c2c668b04af86031d4616e` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-C-2026-08-12.md` | `b1e03cb193003ebbba83b73b8d8bbcbcd72f02148ba00812967a2721e60a8ffd` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md` | `3a8482a6badb0b8bff5dbf64adc18b37493c68dc56a25598be91ee3be7e727cd` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md` | `f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad` |
| `docs/RESEARCH-CAUSAL-LEDGER-V2-2026-08-11.md` | `8372522ac34e865eed02d264f3f2c5e5687cf829adf43a12d999b6ae48eee812` |
| `docs/AUDIT-CONSOLIDATED-LEDGER-156-2026-08-11.md` | `2fb6210a10802c1d9570caeb88dc8af08b1f26721c860deda005df980bf3f687` |

Commands executed (all read-only; no cache mutation, clone, build, or network):

```zsh
sed -n '1,240p' /home/hanqing/.agents/skills/research/SKILL.md
rg -n -i 'strict baseline|alias class|enrichment-overlay|bidirectional ledger|refresh-delta|adjudicat|ai-slop' /home/hanqing/.codex/memories/MEMORY.md
ls -lt autoresearch
rg --files autoresearch/orchestrator-260811-atomic150
rg -l -i 'strict baseline|strict_baseline|baseline snapshot|post[-_ ]baseline|added after|adjudicat' autoresearch/orchestrator-260811-atomic150 -g '*.md' -g '*.json' -g '*.jsonl' -g '!**/responses/**'
ls -ltd autoresearch/orchestrator-260811-atomic150/strict-*
sed -n ... <the summary, supplement, aggregate, Batch A-E, and OpenClaw files listed above>
rg -n ... <targeted headings, IDs, fix prefixes, and baseline references in those files>
sha256sum <all inputs listed in the hash table>
python3 -c '<read strict-200-v3 JSONL and count rows/component_ids/normalized public_ids/CVE/GHSA>'
ls -l autoresearch/herdr-260812-alias-qa/candidate_inventory.md
```

The huge `rg --files` listing was truncated by the command-output budget; no conclusion depends on omitted output. Newest named reports and strict artifacts were then selected by targeted `rg` and mtime checks.

## Stop boundary

This reader stopped at candidate inventory. No GitHub/CVE API object, withdrawal state, alias mapping, released version, or exact fix reference was independently refreshed over the network. `C6` and `C7` retain `UNKNOWN` complete-fix-set identity because the post-baseline reports do not spell out every full SHA. All row actions remain for the parent verifier.
