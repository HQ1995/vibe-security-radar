# Snapshot-based primary-source notes

Snapshot read boundary: `2026-08-12T16:25:25Z`. I read only the immutable copies under `snapshot/docs/`; no source/cache/API was read or changed. All line references below are to those copies.

## Snapshot manifest

| Snapshot | SHA-256 |
|---|---|
| `AUDIT-CONSOLIDATED-LEDGER-156-2026-08-11.md` | `2fb6210a10802c1d9570caeb88dc8af08b1f26721c860deda005df980bf3f687` |
| `AUDIT-STRICT-LEDGER-156-2026-08-11.md` | `e95059199f35756a0c95970c5c2950e9c846ffd701c810126a58ff808baf98bb` |
| `RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md` | `a7dd3db373af0fae98c10f8c96c58180cf80fc132fb6fb53fedbd44f3aae22c2` |
| `RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` | `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` |
| `RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md` | `318912fbc789ef7f0708044d2041c24fa69198f878c2c668b04af86031d4616e` |
| `RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-C-2026-08-12.md` | `b1e03cb193003ebbba83b73b8d8bbcbcd72f02148ba00812967a2721e60a8ffd` |
| `RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md` | `3a8482a6badb0b8bff5dbf64adc18b37493c68dc56a25598be91ee3be7e727cd` |
| `RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md` | `f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad` |
| `RESEARCH-PUBLIC-ID-FIRST-PARTY-CLOSURE-2026-08-11.md` | `2492294dea07939a0129db690a25eb438755eead3fdfa4edfc7c12f568535112` |
| `RESEARCH-STRICT-150-CLOSURE-2026-08-11.md` | `1c6ac880ff41aff9ec65a03214393983213ab4d54280ea80f6e28c0e17efa51f` |
| `RESEARCH-STRICT-150-COMPLETION-V3-2026-08-11.md` | `b5bf51e19ea53e0a6abb7793ed6395d6a13783cf9c4749ea1b4a23e7f69e7463` |
| `RESEARCH-STRICT-200-CLOSURE-2026-08-12.md` | `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` |

Read-only commands used: `find .../snapshot/docs -type f`, `sha256sum .../snapshot/docs/*`, `wc -l`, `rg -n`, and `nl -ba ... | sed -n ...`. Two `python3` read-only set checks extracted case-normalized `CVE-YYYY-NNNN+` / `GHSA-XXXX-XXXX-XXXX` tokens from the explicitly positive component rows; no broad rerun or build was performed.

## Artifact lineage and every material stated total

These totals are different artifact versions or different units; they must not be added together.

| Snapshot / lines | Stated result | Reconciliation |
|---|---|---|
| `AUDIT-STRICT...`, 5-14, 20-23 | 156 source rows; summary had 156 positive classes, 271 IDs, 111 promoted edges. Audit: 57 PASS, 39 FAIL (35 causal/attribution failures + 4 duplicate rows), 60 `NEEDS_REVIEW`, 0 BLOCKED; unique-class upper bound 117. | Early audit, superseded row-by-row by the consolidated audit. |
| `AUDIT-CONSOLIDATED...`, 5-14 | 156 rows: 80 PASS, 53 FAIL, 23 `NEEDS_REVIEW`, 0 BLOCKED. After 3 proven duplicate-row merges and the row 37/139 split: 153 unique component classes = 80/50/23. | Canonical adjudication for this 156-row source, not the later frozen 110-component strict artifact. |
| `RESEARCH-STRICT-150-CLOSURE...`, 5-14, 30-38 | union-v1: 118 semantic components, 207 IDs = 108 CVE + 99 GHSA; 92/157 baseline + 26/50 supplement. | Older union-v1. It is not the base used by strict-200. |
| `RESEARCH-STRICT-150-COMPLETION-V3...`, 7-22, 32-46 | union-v2: 190 IDs = 98 CVE + 92 GHSA; 107 components; 117 edge occurrences / 116 unique pairs; 81 direct, 29 squash, 7 upstream; 76 direct-root/reintroduction + 31 new-surface; 11 components / 17 edges rejected. | Later cleaned strict base. The drop from 118/207 to 107/190 is versioned cleaning, not an arithmetic contradiction. |
| `RESEARCH-PUBLIC-ID...`, 11-20, 68-76 | 31 anomalies all PASS: 3 missing CVEs, 28 GHSAs (5 reviewed, 23 unreviewed), mapping to 29 components; 26/28 GHSAs cite exact fix; 0 removal. | Provenance closure only, not a causal audit. Adds WACRM GHSA alias; preserves H3X4 warning. |
| `RESEARCH-STRICT-200...`, 11-25 | strict-200-v3: exactly 200 published IDs = 101 CVE + 99 GHSA; 110 components; 120 edge occurrences / 119 unique pairs; 0 duplicate/malformed IDs. Arithmetic: `190 + 3*2 + 4 = 200`. | Current frozen strict baseline used by the 2026-08-12 reports. The `200` here is an **ID target**, not 200 components. |
| `RESEARCH-ALIASFREE...BATCH-A`, 5-19 | 5 candidates: 3 PASS / 6 IDs, 2 FAIL / 4 IDs, NR 0; baseline 110/200; proposed local result 113/206. | Proposal only; no ledger write. |
| `RESEARCH-OPENCLAW...`, 12-18, 51-68 | 12 provisional rows -> 9 semantic PASS (4 direct, 5 contributor), 3 FAIL, 0 row-level NR; 15 advisories, 14 CVE-backed + 1 GHSA-only; 9 accepted atomic edges. | Adds 9 only after excluding #8/#11/#12 and narrowing #9. |
| `RESEARCH-ALIASFREE...MAIN`, 12-25 | stated current census: 110 baseline + 6 strict + 9 OpenClaw = **125 strict released**; +48 incomplete released = **173 broad released**; +13 commit-only = **186 widest workset**. | Strict 125 arithmetic is supported. The 48/173/13/186 portion contains exact duplicate rows; see discrepancies below. |
| Batch B, 7-13, 117-123 | +4 released incomplete, +4 commit-only incomplete, +1 commit-only strict. Progression stated: incomplete 23, broad release 148, commit-only 8, workset 156. | Component progression is internally consistent up to B. |
| Batch C, 5-12, 73-79 | +1 released incomplete, +3 commit-only incomplete; 8 public IDs across all 4. Progression: incomplete 24, broad release 149, commit-only 11, workset 160. | Internally consistent. |
| Batch D, 5-15, 116-123 | +7 released incomplete / 13 IDs, no commit-only. Progression: incomplete 31, broad release 156, commit-only 11, workset 167; claims 31 released incomplete have 48 IDs. | Component progression is consistent; the 48-ID subtotal disagrees with the enumerated positive rows (49), below. |
| Batch E, 5-12, 108-115 | claims +17 released / 20 IDs and +2 commit-only / 4 IDs. Progression: incomplete 48, broad release 173, commit-only 13, workset 186; IDs 68/19; gaps to 200 = 27/14. | Exact duplicates with the already integrated Main invalidate the novelty and downstream totals. |

There is no snapshot total equal to exactly 180. The “180-ish” region is the stated 173 released / 186 widest workset, corrected below to no more than 172 / 184 before resolving a separate File Browser semantic-overlap UNKNOWN.

## Deterministic discrepancies

### D1: released Coolify component is counted twice

- Main lines 145-149 already count `CVE-2026-42204 / GHSA-CHG4-63HM-XV9X`, repo `coollabsio/coolify`, partial `c9922c30c2a6bf922653a5f2d631aab4fea685c4`, closure member `817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1`, carrier `e1aac50b745cf499e710b7e35cd2a9d6a1538dd9`, beta.471-.473 -> beta.474.
- Batch E lines 34 and 71 repeat the same IDs, repo, mechanism, candidate, member, carrier, and release gate, yet Batch E lines 109-110 add it again inside `31 + 17 = 48` and `156 + 17 = 173`.
- Exact snapshots: Main `7c41296f...11db0a`; Batch E `f889a12d...c27ad`.
- Deterministic correction: Batch E contributes at most **16 new released components / 18 new released IDs**, not 17/20, relative to Main/A-D.

### D2: commit-only Coolify component is counted twice

- Main lines 151-164 already include `CVE-2026-34167` ActivityMonitor as one of the “first 3” commit-only components: partial `a94517f452e225046e01c08385d6a7aedf085c7d`, closure member `3e0d48faeaab950bfd063dfca908f1d140316ede`, carrier `2729dffb3e30167c1ffd642357b7e0bb99b7d180`, both first in beta.471.
- Batch B line 120 explicitly carries those original 3 into its `3 + 5 = 8`; C and D then carry 8 -> 11 unchanged/incremented.
- Batch E lines 49 and 73 repeat the exact component, add the official alias `GHSA-962V-GXMW-56HC`, and lines 111-112 count it again inside `11 + 2 = 13` and `167 + 19 = 186`.
- The CVE is an exact repeated ID; the GHSA is a newly stated alias, not a new component.
- Deterministic correction: Batch E contributes **1 new commit-only component / 3 net-new commit-only IDs** (Gitea pair + the Coolify GHSA alias), not 2/4.

### D3: downstream component totals

Counting the positive component rows, with only exact public-ID/repo/mechanism/fix duplicates removed:

- strict released remains **125** (`110 + 6 + 9`);
- released incomplete is at most **47**, not 48;
- broad released is at most **172**, not 173;
- commit-only is at most **12** = 11 incomplete + 1 strict, not 13 = 12 + 1;
- widest component workset is at most **184**, not 186;
- corrected gaps to a 200-**component** target are at least **28 released** and **16 including commit-only**, not 27/14.

“At most” is deliberate because File Browser has a separate semantic-overlap UNKNOWN below. These corrections do not alter the frozen strict-200 artifact.

### D4: public-ID subtotals

A case-normalized union of only the explicitly positive component rows gives:

- Through Batch D, released-incomplete rows contain **49 unique public IDs**, not the 48 stated at Batch D line 121.
- Batch E's 20 released-ID occurrences contain the already counted Coolify CVE/GHSA pair, so only 18 are new; the final released-incomplete union is **67 IDs**, not 68.
- Pre-E commit-only rows contain 15 unique IDs. E repeats `CVE-2026-34167` and adds `GHSA-962V-GXMW-56HC` plus the two Gitea IDs, so the final commit-only union is **18 IDs**, not 19.
- Batch E line 12's claim that all 24 IDs were absent from A-D/Main is false for at least `CVE-2026-42204`, `GHSA-CHG4-63HM-XV9X`, and `CVE-2026-34167`. Its true net-new union against Main/A-D is 21 IDs.

The released-ID discrepancy is not simply `68 - 2 = 66`: Batch D's own subtotal is already low by one; explicit row union is therefore 67.

### D5: File Browser umbrella versus split residuals is UNKNOWN

- Main line 117 counts `CVE-2026-54094 / GHSA-239W-M3H6-CH8V` using `847d08bd... -> 7c2c0a11... -> 64511ce4...` and describes the final missing **dangling write and unguarded delete**, then says those two residuals are counted separately in Batch D.
- Batch D lines 79-97 count `CVE-2026-55667 / GHSA-FMM7-X4GX-8JHR` (delete/permission) and `CVE-2026-55668 / GHSA-8WC8-HF36-MJH9` (dangling write) with that exact same candidate/intermediate/final chain.
- D proves the two residuals are distinct from each other. It does not explain what third, non-overlapping mechanism remains for the Main `CVE-2026-54094` umbrella row after both named residuals are split out.
- Preserve as `UNKNOWN_POSSIBLE_SEMANTIC_DOUBLE_COUNT`; do not reduce totals without first-party component/ledger adjudication. If the umbrella is only a series header, released-incomplete/broad/workset totals fall by one more.

### D6: older duplicate decision was superseded

- Strict audit lines 44-53 originally treated four row pairs as duplicates, including rows 37/139.
- Consolidated lines 34-40 proves only rows 3/142, 36/41, and 81/88 merge; row 37 (`CVE-2026-34426`, environment normalization) and row 139 (`CVE-2026-34510`, media/UNC) must split.
- Use the consolidated result. H3X4 global metadata is polluted and cannot merge the two CVEs.

### D7: stale provenance sentence

Main lines 193-200 integrate Batch E and cite its hash, but Main line 275 says the turn “only added Batch D evidence and updated this report.” This is stale narrative/provenance text, not a count change.

### D8: OpenClaw says 9 atomic edges but prints 11 candidate-to-fix endpoints

- OpenClaw lines 18 and 173-175 call the accepted set “9” atomic edges, matching the 9 accepted semantic-component rows.
- The printed relations at lines 177-209 contain **11 candidate-to-fix endpoint pairs**: one each for components 1-6 (6), two for workspace-shadow component 7 (first fix + residual), two for Feishu webhook component 9 (first fix + residual), and one for component 10. All 11 `(candidate, fix endpoint)` pairs are distinct; `8d74578c...` is also deliberately reused across components 3 and 5 with different fixes.
- This does not change the 9-component count. For machine-readable edge totals, call these **9 component/edge groups containing 11 accepted candidate-to-fix endpoint occurrences**, not 9 atomic pairs.

## Current positive identity inventory

### Strict additions outside frozen 110

Main lines 63-72 define six released strict additions:

| Public component | Repo | Candidate -> fix identity |
|---|---|---|
| `CVE-2026-40069 / GHSA-9HFR-GW99-8RHX` | `sgbett/bsv-ruby-sdk` | `a1f2e62cb3dc48014c1770ec44d61811ae4b7105` -> member `db97de475518eef752ed52b25f49f09cbe24c187` (carrier `4992e8a...`) |
| `CVE-2026-40070 / GHSA-HC36-C89J-5F4J` | same | `d14dd19f...` + `6a4d8984...` -> same `db97de475...`; one certificate-signature component |
| `CVE-2026-45136 / GHSA-G3XQ-3GMV-QQ8G` | `cnighswonger/claude-code-cache-fix` | member `e19169011a7ca59c3ccee67c626c658ba47eb275` -> member `0a3e3c130e1ec803a2107fe83775d97f5f8f6dde`; carriers `7b9322a...` / `613e4df...` |
| `CVE-2026-49973 / GHSA-P52P-4VMG-4VQ3` | `nesquena/hermes-webui` | `b8b62722...` -> member `f2ef2851...` (carrier `1126e541...`) |
| `CVE-2026-49956 / GHSA-MGXW-V6RH-WCV6` | same | `d2b27f6f...` -> member `8d8ae89d...` (carrier `2c7b5300...`) |
| `CVE-2026-34198` | `coollabsio/coolify` | `e1fe5863...` -> member `e1d4b468...` (carrier `98569e4e...`) |

Batch A lines 25-30 contain the full machine-readable identities for its first three rows and explicitly prove no baseline/public-ID/repo/edge/mechanism overlap at lines 246-256.

### OpenClaw 9 accepted semantic components

OpenClaw lines 20-33, 55-68, and 173-209 are authoritative:

1. `GHSA-H2VW-PH2C-JVWF / CVE-2026-44992`, MiniMax credentialed dotenv redirect, `7d7f5d85... -> 2f066965...`.
2. `GHSA-G8P2-7WF7-98MQ / CVE-2026-25253`, gatewayUrl token exfiltration, `c74551c2... -> a7534dc2...`.
3. GHSA-only `GHSA-9F72-QCPW-2HXC`, native prompt image `workspaceOnly`, `8d74578c... -> 370d1155...`.
4. `GHSA-XQ94-R468-QWGJ / CVE-2026-43582`, Browserbase CDP/DNS split contributor, `75602014... -> 121c452d...`.
5. `GHSA-W85G-3H6X-4XH2 / CVE-2026-41334`, sips pixel DoS contributor, `8d74578c... -> 0ed4f8a7...`; old ledger CVE/GHSA double row counts once.
6. `GHSA-MF5G-6R6F-GHHM / CVE-2026-35646`, Synology pre-auth rate limit, member `cc048a29...` => carrier `03586e3d...` -> `0b4d0733...`.
7. `GHSA-2QRV-RC5X-2G2H / CVE-2026-41295` plus `GHSA-82QX-6VJ7-P8M2 / CVE-2026-43571`, one workspace-shadow residual series, member `fc1b156d...` => carrier `f4cc93dc...` -> fixes `53c29df2...` + `1fede43b...`.
8. `GHSA-G353-MGV3-8PCJ / CVE-2026-32974` plus only the webhook half of `GHSA-XH72-V6V9-MWHC / CVE-2026-44109`, one Feishu webhook series, member `b0c67ea0...` => carrier `5c2cb6c5...` -> `7844bc89...` + webhook half of `c8003f1b...`.
9. `GHSA-2Q7J-2VHX-56G8 / CVE-2026-62187` plus `GHSA-W8WF-3QVJ-6XQF / CVE-2026-62188`, one Feishu account-family gate, `5f6e1c19... -> d4f11d30...`.

OpenClaw line 72 corrects a first-party release-metadata error: Synology's planned nonexistent 2026.3.25 is not the fixed release; first actual stable fix is `v2026.3.28`.

### Released incomplete-remediation inventory

The stated 48 occurrences reduce to 47 exact-identity-unique rows (and possibly 46 if the File Browser umbrella is rejected):

- Main initial released 11 (lines 107-121): Zeptoclaw `GHSA-5WP8`; PraisonAI `CVE-47390/GHSA-5C6W` and `CVE-47392/GHSA-4MR5`; Argo `CVE-54526`; Fission `CVE-50570/GHSA-QF5V`; MCP Registry `CVE-44430/GHSA-R48C`; Fission `CVE-50568/GHSA-R5JH`; ClearanceKit `CVE-33632/GHSA-WPXJ`; Fireshare `CVE-34745/GHSA-FVVP`; File Browser umbrella `CVE-54094/GHSA-239W` (UNKNOWN overlap); vm2 `CVE-47137/GHSA-M4WX`.
- Main GitPython 7 (lines 125-143): `GHSA-R9MR`, `GHSA-94P4`, `GHSA-6P8H`, `GHSA-3RP5`, `GHSA-539M`, `GHSA-P538`, `GHSA-3F7W`; the table gives exact candidates/fixes and shipped tag separation.
- Main Coolify shell component (lines 145-149): `CVE-42204/GHSA-CHG4`; do not count again in E.
- Batch B released 4 (lines 17-60): n8n-mcp `CVE-42449/GHSA-56C3`, Prospero `CVE-59233`, `CVE-59234`, `CVE-59240`.
- Batch C released 1 (lines 16-27): Langroid `CVE-25481/GHSA-X34R`, contributor only.
- Batch D released 7 (lines 7-15, 32-97): fast-uri `CVE-18446/GHSA-7P8R`; Locutus `CVE-33994/GHSA-VC8F`; Gitea `CVE-58432/GHSA-Q9PG`; Scriban `GHSA-Q6RR`; Faraday `CVE-33637/GHSA-5RV5`; File Browser `CVE-55667/GHSA-FMM7` and `CVE-55668/GHSA-8WC8`.
- Batch E truly new released 16 after removing duplicate Coolify (lines 31-47): Scriban `GHSA-6Q7J`; Gitea `CVE-55987/GHSA-VRHC`; PraisonAI `CVE-57148/GHSA-F38V`; 12 GitPython advisories `V396`, `MV93`, `FJR4`, `HH9P`, `9RJ7`, `4GMW`, `WVPP`, `JM78`, `284H`, `8MCC`, `5XXX`, `3WXW`; Scriban `GHSA-89CF`.

Shared candidate/fix identities are not automatically duplicates when the snapshots give separate first-party advisory, input, sink, and invariant: Praison SSRF vs Python exec; Fission capability vs container validation; Mistune percent encoding vs legacy schemes; Scriban parser recursion vs eager/lazy multiplication; GitPython's separate option/API/config sinks. Batch E lines 75-94 make the GitPython split explicit.

### Commit-only inventory

The stated 13 occurrences reduce to 12 unique components:

- incomplete: Fission `CVE-2026-50566/GHSA-M63V-2G9W-2W6V`; Kiota `GHSA-P5RM-JG5C-8C77`; Coolify `CVE-2026-34167/GHSA-962V-GXMW-56HC` (one component, not two); Dynatrace `GHSA-P7W7-4929-VPJ5`; WACRM `CVE-2026-49141`; MISP `CVE-2026-56422`; OmniFaces `GHSA-FP43-VJ7G-PG92`; Vitest `CVE-2026-53633/GHSA-G8MR-85JM-7XHM`; Mistune `CVE-2026-59923/GHSA-8C25-4J27-2RV3`; Mistune `CVE-2026-59929/GHSA-QFRW-5RXM-MHH2`; Gitea `CVE-2026-58427/GHSA-PRR9-9MP4-5GP2`.
- strict commit-only: Prospero `CVE-2026-59237`.

All are excluded from release-grade totals because no tag contains candidate/partial without closure. Exact release-gate evidence is in Main 121-123, B 64-101, C 29-60, and E 48-49/63/73.

## Alias and cross-document identity rules

- Consolidated proven merges: row 3/142 (`CVE-2026-41334` / `GHSA-W85G`, edge `8d74578c -> 0ed4f8a7`); row 36/41 (`GHSA-48VW` / `CVE-2026-35638`, `20523b91 -> ccf16cd8`); row 81/88 (`GHSA-68V4` / `CVE-2026-41345`, `06dd9b8e -> e704323f`).
- Consolidated proven split: `CVE-2026-34426` environment-normalization is not `CVE-2026-34510` media/UNC. Public-ID closure lines 64-66 and strict-200 lines 60-63 preserve this.
- OpenClaw multi-publication one-component groupings are listed above. They are often same-mechanism equivalence/residual series, not formal aliases.
- Public-ID closure lines 60-62: `GHSA-7JM2-G593-4QRC` does not itself carry `CVE-2026-45001`; it is same-component equivalent to `GHSA-9FC9-8V4X-F5CP / CVE-2026-45001` through reciprocal first-party references and identical fix.
- Strict-200 public-ID amendments, lines 54-63: add `GHSA-8JQH-598V-RFXC` to WACRM `CVE-2026-67530`; add repository advisory `GHSA-H3X4-HC5V-V2GM` to `CVE-2026-34510` without importing polluted `CVE-2026-34426`; add `GHSA-C4HM-4H84-2CF3` to `CVE-2026-59726`; add `GHSA-VCV2-R9JH-99M5` to `CVE-2026-58195`.
- Batch A classes: `alias-a807...` = CVE-40069/GHSA-9HFR; `alias-77f9...` = CVE-40070/GHSA-HC36; `alias-2ad5...` = CVE-45136/GHSA-G3XQ.
- Exact edge reuse does not imply alias by itself: consolidated line 214 allows rows 15/133, 53/105, and 106/123 to reuse an edge because their first-party mechanisms differ.

## Already adjudicated exclusions and UNKNOWN controls

Do not redo the 156-row audit. Consolidated final row sets are:

- FAIL strict rows (53): `2,6,10,11,13,17,18,22,26,36,37,38,39,41,47,51,54,59,61,64,66,67,68,70,71,74,75,79,80,81,83,84,86,94,97,99,100,104,107,118,121,128,132,136,138,142,143,146,149,151,153,154,155`.
- `NEEDS_REVIEW` strict rows (23): `3,7,19,25,28,44,45,50,57,72,76,77,78,93,109,113,117,120,124,125,127,141,147`.
- PASS rows are only PASS under their accepted atomic edge; rejected sibling edges remain negative controls (consolidated 208-214).

Later reports supersede only explicitly named edges/taxonomies: e.g. row 3 W85G receives a new OpenClaw contributor closure; rows 104/153's old import-carrier Feishu edges remain rejected while frontier #9 accepts a different atomic integration member; strict FAIL incomplete-hardening rows may be reclassified only as `AI_INCOMPLETE_REMEDIATION`, never restored as strict origin.

Named negative/unknown controls to preserve:

- Strict-200 lines 65-75: SolidCAM CVE-42213, UltraDAG CVE-42278, Trek 40184/40185, CPhalcon 54736/57584 excluded; AutoBangumi 59101 remains unresolved.
- Batch A lines 258-287: Pydantic UI 54249 FAIL carrier-attribution laundering; n8n 42449 FAIL **strict** incomplete hardening. Batch B later accepts n8n only under the broader released-incomplete taxonomy and corrects the one-parent topology (B 17-27).
- OpenClaw #8, #11, #12 FAIL; #9 blank card-action token submechanism excluded. Advisories are real; AI edges fail (OpenClaw 29-35, 134-171, 211-217).
- Main lines 202-214: CSS Parser 53727, vm2 47208, OpenC3 42085, Fiber 30246, CPython 15366, PraisonAI 62181 excluded; AutoBangumi NR; GitPython GHSA-2F96 commit-only/excluded from release.
- Batch B lines 103-111: melange 25143, Prospero 59235/59236, Vulnogram 32774, ChurchCRM 67751 fail.
- Batch C lines 62-70: Flowise 41269/30821/41276, WorkOS 42565, FormNotify 5229 fail.
- Batch D lines 99-112: File Browser 62843 duplicate with frozen strict; MCP Atlassian, ProjectCapsule, LightRAG, OpenClaw followups, 9Router, Fedify, Pydantic followups fail.
- Batch E lines 96-104: PraisonAI 62181 insufficient reversal; GitPython 2F96 no released intermediate; GitPython HMQ2/7833 attribution failure; Pydantic UI 54249 carrier projection; FastChat/Kyverno remediation order.

There are no stated row-level BLOCKED results in these snapshots (`BLOCKED=0` in both audits). Preserve as UNKNOWN: the 23 consolidated pending rows, AutoBangumi 59101, and the File Browser umbrella/split reconciliation above.

## Claim boundary

This is document/ledger consistency QA only. Hashes, row arithmetic, exact identity equality, and explicit snapshot supersession are evidence for duplication/count corrections. They do not independently prove exploitability or causality. Publication-grade claims still require the snapshots' own gates: exact atomic AI member, parent delta, same mechanism, first-party advisory identity, exact fix reversal, and a released candidate-without-fix witness. Commit-only, FAIL, `NEEDS_REVIEW`, NR, and the File Browser overlap must not be promoted to released unique components.
