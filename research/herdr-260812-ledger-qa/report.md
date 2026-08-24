# Snapshot-based ledger consistency QA

Date: 2026-08-12  
Owned output: autoresearch/herdr-260812-ledger-qa/  
Task boundary: consistency and identity reconciliation only; no causal re-research and no source repair.

## Result

QA is complete for the frozen snapshot.

- The frozen strict-200-v3 artifact is internally consistent: 110 semantic components, 200 unique published public IDs (101 CVE, 99 GHSA), 120 accepted edge occurrences, 119 unique candidate/fix pairs, four alias amendments, and no duplicate or malformed public IDs.
- The later document-level strict released census of 125 is arithmetically supported as 110 frozen + 6 new strict + 9 OpenClaw. It has not been materialized into the frozen strict-200 ledger.
- The stated 48 incomplete-remediation released components, 173 broad released components, 13 commit-only components, and 186 widest workset are not consistent. One released Coolify component and one commit-only Coolify component are exact cross-document duplicates.
- After removing only those deterministic duplicates, the maximums are 47 incomplete released, 172 broad released, 12 commit-only, and 184 widest workset.
- A File Browser umbrella/split overlap remains UNKNOWN. If that umbrella is not a third independent semantic component, the component maximums become 46, 171, and 183 respectively.
- The case-normalized positive-row unions contain 67 released-incomplete public IDs and 18 commit-only public IDs, not 68 and 19.

There is no literal total of exactly 180 in the snapshot. The relevant “180-ish” statements are 173 released and 186 widest; the deterministic corrections are at most 172 and 184.

## Snapshot and volatility boundary

The checkout was already intentionally dirty on branch dev. The initial status was read only. No existing path was edited, deleted, renamed, formatted, staged, committed, reset, cleaned, or pushed.

Thirteen current relevant documents were copied at 2026-08-12T12:18:35-04:00 into snapshot/docs/ and made read-only. Nine ledger artifacts cited by those documents were copied at 2026-08-12T12:21:09-04:00 into snapshot/artifacts/ and made read-only. At 2026-08-12T12:37:38-04:00, every original still matched its copy. Conclusions remain bound to the copied bytes even if the shared checkout changes later.

No build, full census, 51,218-unit rerun, cache write, API loop, or web search was performed. One bounded background reader inspected only the immutable document copies and wrote background-primary-source-notes.md inside the owned directory. Foreground and background work stayed within the two-process limit.

One current cached CVEList record for CVE-2026-54094 was read diagnostically after the snapshot. It did not resolve the File Browser semantic overlap and is not used in any total or publication claim.

## Input hashes

### Documents

| Snapshot document | SHA-256 |
|---|---|
| AUDIT-CONSOLIDATED-LEDGER-156-2026-08-11.md | 2fb6210a10802c1d9570caeb88dc8af08b1f26721c860deda005df980bf3f687 |
| AUDIT-STRICT-LEDGER-156-2026-08-11.md | e95059199f35756a0c95970c5c2950e9c846ffd701c810126a58ff808baf98bb |
| RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md | a7dd3db373af0fae98c10f8c96c58180cf80fc132fb6fb53fedbd44f3aae22c2 |
| RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md | 7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a |
| RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md | f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6 |
| RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md | 318912fbc789ef7f0708044d2041c24fa69198f878c2c668b04af86031d4616e |
| RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-C-2026-08-12.md | b1e03cb193003ebbba83b73b8d8bbcbcd72f02148ba00812967a2721e60a8ffd |
| RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md | 3a8482a6badb0b8bff5dbf64adc18b37493c68dc56a25598be91ee3be7e727cd |
| RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md | f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad |
| RESEARCH-PUBLIC-ID-FIRST-PARTY-CLOSURE-2026-08-11.md | 2492294dea07939a0129db690a25eb438755eead3fdfa4edfc7c12f568535112 |
| RESEARCH-STRICT-150-CLOSURE-2026-08-11.md | 1c6ac880ff41aff9ec65a03214393983213ab4d54280ea80f6e28c0e17efa51f |
| RESEARCH-STRICT-150-COMPLETION-V3-2026-08-11.md | b5bf51e19ea53e0a6abb7793ed6395d6a13783cf9c4749ea1b4a23e7f69e7463 |
| RESEARCH-STRICT-200-CLOSURE-2026-08-12.md | e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b |

### Cited ledger artifacts

| Artifact | Byte SHA-256 |
|---|---|
| strict-ledger-union-v1/ledger.jsonl | 996e81f5298bf695a7d91bc0b2646a314146aaad97aa417fbc4fa5b255ab078c |
| strict-ledger-union-v1/summary.json | e378a7185b642a6b933d5eb2a16c55adb84db2ff3b9656923165ecfb58dd5801 |
| strict-ledger-union-v2/ledger.jsonl | 282d2975d0ee24e9949cc4d108ad5a1ffd9b045ad8548cc6b1661aaf2c18392e |
| strict-ledger-union-v2/rejected.jsonl | 6264f79e1c74ed8b0511c772ded43fdf9b377b9591bdc3d065011a0e631aa4be |
| strict-ledger-union-v2/rejected_edges.jsonl | 139eaa96fc6be47bdb57b6c9d43660580ef4b883709a6dbafb28ba8324af47e6 |
| strict-ledger-union-v2/summary.json | 3b2132589fe01f16d94e24313c99c4a44feab113aa4fc4385e861439b439201b |
| strict-200-v3/ledger.jsonl | 0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81 |
| strict-200-v3/summary.json | 69dd6c35de1455bf9cee88420aed570c576a190a4d143202d01a26cc3d37b81e |
| strict-200-v3/supplement.json | 09a45c145313862f2d60b47cfe1df23bce9a1d7d3b6140592a913a364dfcbd4d |

The union-v1 report also prints a canonical JSON hash of 990974f2..., while the copied JSONL byte hash is 996e81f5.... Those are explicitly different digest contracts, not treated as a discrepancy.

## Ledger lineage and stated totals

These are different versions or units. They must not be summed.

| Source | Stated counts | Reconciliation |
|---|---|---|
| Strict 156 audit, lines 5-23, hash e9505919... | 156 source rows; 57 PASS, 39 FAIL, 60 NEEDS_REVIEW, 0 BLOCKED; unique-class upper bound 117 | Early audit; superseded row-by-row by the consolidated audit |
| Consolidated 156 audit, lines 5-22, hash 2fb6210a... | 156 rows = 80 PASS + 53 FAIL + 23 NEEDS_REVIEW; after three merges and one split, 153 unique classes = 80/50/23 | Canonical for this 156-row source, not the later strict-200 artifact |
| Strict union-v1 report, lines 5-14, hash 1c6ac880... | 118 semantic components, 207 IDs = 108 CVE + 99 GHSA | Older union-v1 |
| Strict union-v2 report, lines 7-22 and 137-169, hash b5bf51e1... | 107 components, 190 IDs = 98 CVE + 92 GHSA; 117 accepted occurrences / 116 unique pairs; 11 components and 17 occurrences rejected | Cleaned base used by strict-200 |
| Public-ID closure, lines 11-20, hash 2492294d... | 31/31 anomalies PASS; 3 CVEs + 28 GHSAs map to 29 components; 0 removal; one known alias addition | Provenance closure only; it does not replace causal review |
| Strict-200 report, lines 11-25 and 125-155, hash e255c227... | 110 components, 200 IDs = 101 CVE + 99 GHSA; 120 edge occurrences / 119 unique pairs | Frozen current strict baseline; 200 is an ID target, not a component count |
| Alias-free Batch A, lines 5-19, hash a7dd3db3... | 3 PASS / 6 IDs, 2 FAIL / 4 IDs, 0 NR; proposed 113/206 if absorbed | Proposal; no ledger write |
| OpenClaw closure, lines 12-18, hash f0e9655b... | 12 provisional rows become 9 component PASS, 3 FAIL, 0 row-level NR | Nine additions only; row 9 is narrowed |
| Main, lines 12-25, hash 7c41296f... | 125 strict released, 173 broad released, 186 widest | 125 supported; 173/186 overcount exact duplicates |

The drop from union-v1 118/207 to union-v2 107/190 is versioned causal cleaning: union-v2 rejected 11 components and 17 edge occurrences. It is not an arithmetic contradiction.

## Reconciled current totals

| Metric | Stated | Snapshot-consistent result | Boundary |
|---|---:|---:|---|
| Frozen strict public IDs | 200 | 200 | 101 CVE + 99 GHSA; 110 components |
| Strict released components | 125 | 125 | Document-level 110 + 6 + 9; not materialized into strict-200 |
| Released incomplete-remediation components | 48 | at most 47 | 46 if File Browser umbrella is not independent |
| Broad released components | 173 | at most 172 | 171 under the File Browser conditional |
| Commit-only components | 13 | 12 | 11 incomplete + 1 strict |
| Widest component workset | 186 | at most 184 | 183 under the File Browser conditional |
| Gap to 200 released components | 27 | at least 28 | At least 29 under the File Browser conditional |
| Gap to 200 widest workset | 14 | at least 16 | At least 17 under the File Browser conditional |
| Released-incomplete public IDs | 68 | 67 | Case-normalized union of explicit positive rows |
| Commit-only public IDs | 19 | 18 | Case-normalized union of explicit positive rows |
| Batch E all-new public IDs | 24 | 21 net-new | Three IDs already appeared before E |

The phrases “lower bound 173” and “widest 186” are unsafe on this snapshot. After exact duplicate removal they are ceilings, not confirmed semantic lower bounds, because the File Browser overlap is unresolved.

## Row-level discrepancies

### D1 — exact released duplicate: Coolify shell validation

Main lines 145-149, hash 7c41296f...11db0a, already count:

| Field | Identity |
|---|---|
| Public IDs | CVE-2026-42204 / GHSA-CHG4-63HM-XV9X |
| Repository | coollabsio/coolify |
| Mechanism | shellSafeCommandRules accepts bare ampersand until token-aware grammar closes it |
| AI candidate | c9922c30c2a6bf922653a5f2d631aab4fea685c4 |
| Fix member | 817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1 |
| Fix carrier | e1aac50b745cf499e710b7e35cd2a9d6a1538dd9 |
| Release witness | beta.471–beta.473 partial; beta.474 fixed |

Batch E lines 34, 71, and 108-115, hash f889a12d...c27ad, repeat the same IDs, repo, mechanism, candidate, fix member/carrier, and release gate, then add it inside 31 + 17 = 48 and 156 + 17 = 173.

Correction: Batch E has at most 16 new released components and 18 new released IDs, not 17 and 20.

### D2 — exact commit-only duplicate: Coolify ActivityMonitor

Main lines 151-164, hash 7c41296f...11db0a, already count the first three commit-only rows, including:

| Field | Identity |
|---|---|
| Existing public ID | CVE-2026-34167 |
| Later additive alias | GHSA-962V-GXMW-56HC |
| Repository | coollabsio/coolify |
| Mechanism | ActivityMonitor team lookup fails open when team_id is absent |
| AI candidate | a94517f452e225046e01c08385d6a7aedf085c7d |
| Fix member | 3e0d48faeaab950bfd063dfca908f1d140316ede |
| Fix carrier | 2729dffb3e30167c1ffd642357b7e0bb99b7d180 |
| Release witness | candidate and closure first appear together in beta.471 |

Batch B lines 115-123, hash 318912fb...d4616e, carries those original three into 3 + 5 = 8; C and D carry the sequence to 11. Batch E lines 49, 73, and 108-115, hash f889a12d...c27ad, repeat the same component and count it again in 11 + 2 = 13. The GHSA is a new alias, not a new component.

Correction: Batch E has one new commit-only component and three net-new commit-only IDs, not two and four.

### D3 — downstream totals

D1 and D2 explain the deterministic component corrections:

- 48 becomes at most 47.
- 173 becomes at most 172.
- 13 becomes 12.
- 186 becomes at most 184.
- Released gap to a 200-component target becomes at least 28.
- Widest-workset gap becomes at least 16.

The exact affected statements are Main lines 12-25 and 216-222, hash 7c41296f...11db0a, and Batch E lines 106-115, hash f889a12d...c27ad.

### D4 — public-ID subtotals

Case-normalized union of explicit positive component rows yields:

- Through Batch D: 49 released-incomplete IDs, not the 48 stated at Batch D line 121, hash 3a8482a6...e727cd.
- Batch E released rows have 20 occurrences but repeat the Coolify CVE/GHSA pair, so only 18 are new; final released union is 67, not 68.
- Pre-E commit-only rows have 15 unique IDs. E repeats CVE-2026-34167 and adds its GHSA alias plus the Gitea pair, so final union is 18, not 19.
- Batch E line 12 says all 24 IDs are absent from Main/A-D. CVE-2026-42204, GHSA-CHG4-63HM-XV9X, and CVE-2026-34167 are counterexamples. Net-new is 21.

The released correction is not 68 minus two equals 66: Batch D's pre-E subtotal was already low by one, so the explicit final union is 67.

### D5 — UNKNOWN File Browser semantic overlap

Main line 117, hash 7c41296f...11db0a, counts CVE-2026-54094 / GHSA-239W-M3H6-CH8V on:

    847d08bdd135e5c3659f2e6dea2f0cd36617af9b
      -> 7c2c0a11b31b2bb214d741005a0b02b1764208b3
      -> 64511ce45e3be379e965f7f4fb0929a068d5bb81

It describes the final missing dangling-write and unguarded-delete behavior, then says those two residuals are counted separately in Batch D. Batch D lines 79-97, hash 3a8482a6...e727cd, count exactly those residuals on exactly that chain:

- CVE-2026-55667 / GHSA-FMM7-X4GX-8JHR: delete/permission invariant.
- CVE-2026-55668 / GHSA-8WC8-HF36-MJH9: dangling-write invariant.

Batch D proves those two are distinct from each other. The snapshot does not explain a third non-overlapping mechanism for the umbrella row after both are split out. This remains UNKNOWN_POSSIBLE_SEMANTIC_DOUBLE_COUNT. No deterministic subtraction was made. If the umbrella is only a residual-series header, subtract one released component.

### D6 — resolved alias conflict

Strict audit lines 42-53, hash e9505919...af98bb, initially merged four row pairs including 37/139. Consolidated lines 34-40, hash 2fb6210a...3f687, supersede that decision:

- Proven merges: 3/142, 36/41, 81/88.
- Proven split: row 37 CVE-2026-34426 environment normalization and row 139 CVE-2026-34510 media/UNC handling.

Public-ID closure lines 64-76, hash 2492294d...112f, confirms that H3X4 global CVE linkage is polluted metadata. The consolidated split is the current decision.

### D7 — stale provenance sentence

Main lines 193-200 integrate Batch E and cite hash f889a12d..., but Main line 275 says the turn only added Batch D evidence. This is stale provenance text, not a numeric change.

### D8 — OpenClaw edge-group terminology

OpenClaw lines 18 and 173-175, hash f0e9655b...cd6f6, call the accepted set nine atomic edges. Lines 177-209 print eleven distinct candidate-to-fix endpoints:

- One endpoint each for component groups 1 through 6.
- Two endpoints for workspace-shadow group 7.
- Two endpoints for Feishu-webhook group 9.
- One endpoint for account-gate group 10.

Use “9 semantic component/edge groups containing 11 candidate-to-fix endpoint occurrences.” The nine-component count is unchanged.

## Public-ID aliases and component identities

Strict-200 adds four IDs without creating components:

| Existing component | Added ID | Relationship |
|---|---|---|
| CVE-2026-67530 WACRM webhook SSRF | GHSA-8JQH-598V-RFXC | Formal first-party CVE alias |
| CVE-2026-34510 media/UNC | GHSA-H3X4-HC5V-V2GM | Same-mechanism repo advisory; explicitly exclude polluted CVE-2026-34426 link |
| CVE-2026-59726 Ruflo MCP bridge RCE | GHSA-C4HM-4H84-2CF3 | Formal first-party CVE alias |
| CVE-2026-58195 agentic-flow injection | GHSA-VCV2-R9JH-99M5 | Formal first-party CVE alias |

Public-ID closure also requires these wording boundaries:

- GHSA-7JM2-G593-4QRC does not itself carry CVE-2026-45001. It is same-component equivalent to GHSA-9FC9-8V4X-F5CP / CVE-2026-45001 through reciprocal first-party references and the identical fix.
- OpenClaw workspace-shadow CVE/GHSA pairs are a first-fix/residual series, not formal aliases.
- OpenClaw Feishu account-family CVE/GHSA pairs share one centralized gate component, not a formal alias class.
- Shared fix SHA alone is not alias evidence.

## Repo, mechanism, and fix collision QA

The collision key used here is the tuple:

    case-normalized public IDs
    + repository
    + security input/trust-boundary/sink invariant
    + atomic candidate
    + semantic fix endpoint/member
    + release classification

Only D1 and D2 are deterministic exact duplicates across the current positive inventories. D5 is the sole unresolved same-repository/same-chain semantic overlap found.

The following shared identities are retained as non-duplicates because the snapshots give separate first-party advisories and separate mechanisms:

- BSV ARC failure-as-success versus certificate-signature persistence: same hotfix member, different input, sink, invariant, and IDs.
- PraisonAI SSRF versus Python-exec residuals: same partial/fix, different security mechanisms.
- Fission capability allowlist versus container validation: same broad hardening family, different sinks.
- Mistune percent-encoded scheme versus legacy/chained schemes: same candidate/fix, different bypass grammar and advisories.
- Scriban parser recursion versus eager/lazy multiplication: different resource boundary and fix.
- GitPython rows sharing hardening candidates or a closure: different option/config inputs and API sinks.
- OpenClaw prompt-image workspace policy versus pixel DoS: same candidate, different fixes and invariants.

## Release-grade versus commit-only

Release-grade requires at least one stable tag or release containing the candidate or carrier and not the complete fix. Candidate and closure appearing first in the same release is commit-only.

After exact deduplication, the 12 commit-only components are:

1. CVE-2026-50566 / GHSA-M63V-2G9W-2W6V — Fission.
2. GHSA-P5RM-JG5C-8C77 — Kiota.
3. CVE-2026-34167 / GHSA-962V-GXMW-56HC — Coolify, counted once.
4. GHSA-P7W7-4929-VPJ5 — Dynatrace MCP.
5. CVE-2026-49141 — WACRM.
6. CVE-2026-56422 — MISP.
7. GHSA-FP43-VJ7G-PG92 — OmniFaces.
8. CVE-2026-53633 / GHSA-G8MR-85JM-7XHM — Vitest.
9. CVE-2026-59923 / GHSA-8C25-4J27-2RV3 — Mistune percent encoding.
10. CVE-2026-59929 / GHSA-QFRW-5RXM-MHH2 — Mistune legacy/chained schemes.
11. CVE-2026-58427 / GHSA-PRR9-9MP4-5GP2 — Gitea.
12. CVE-2026-59237 — Prospero strict origin.

The first eleven are incomplete remediation; Prospero is strict commit-only. None enters a released count.

The released-incomplete inventory has 47 exact-identity-unique rows before resolving D5:

- Main: 11 initial released rows, seven GitPython rows, one Coolify shell row.
- Batch B: four released rows.
- Batch C: one released contributor row.
- Batch D: seven released rows.
- Batch E: 16 truly new released rows after removing the duplicated Coolify shell row.

Full row identities and document line pointers are in background-primary-source-notes.md lines 144-165. That note is an auxiliary extraction, not an additional evidence source.

## Already adjudicated exclusions and negative controls

The 156-row audit was not redone. The consolidated final status is 80 PASS, 53 FAIL, 23 NEEDS_REVIEW, 0 BLOCKED; after component reconciliation it is 80 unique PASS, 50 unique FAIL, 23 unique NEEDS_REVIEW.

Consolidated FAIL rows:

    2, 6, 10, 11, 13, 17, 18, 22, 26, 36, 37, 38, 39, 41, 47,
    51, 54, 59, 61, 64, 66, 67, 68, 70, 71, 74, 75, 79, 80, 81,
    83, 84, 86, 94, 97, 99, 100, 104, 107, 118, 121, 128, 132, 136,
    138, 142, 143, 146, 149, 151, 153, 154, 155

Consolidated NEEDS_REVIEW rows:

    3, 7, 19, 25, 28, 44, 45, 50, 57, 72, 76, 77, 78, 93, 109,
    113, 117, 120, 124, 125, 127, 141, 147

Later reports supersede only an explicitly named edge or taxonomy. For example, n8n CVE-2026-42449 remains a failed strict origin but is accepted later only as released incomplete remediation. A new OpenClaw atomic member does not revive an older rejected import-carrier edge.

Preserved named controls include:

- Strict-200 exclusions: SolidCAM CVE-2026-42213, UltraDAG CVE-2026-42278, Trek CVE-2026-40184/40185, CPhalcon CVE-2026-54736/57584; AutoBangumi CVE-2026-59101 remains unresolved.
- Batch A: Pydantic UI CVE-2026-54249 carrier-attribution laundering; n8n strict-origin failure.
- OpenClaw: rows 8, 11, 12 FAIL; row 9 blank card-action submechanism excluded.
- Main: CSS Parser, vm2, OpenC3, Fiber, CPython, PraisonAI CVE-2026-62181 exclusions; GitPython GHSA-2F96 excluded from release.
- Batch B: melange, Prospero 59235/59236, Vulnogram, ChurchCRM failures.
- Batch C: Flowise, WorkOS, FormNotify failures.
- Batch D: File Browser CVE-2026-62843 duplicate with frozen strict; MCP Atlassian, ProjectCapsule, LightRAG, OpenClaw followups, 9Router, Fedify, Pydantic followups fail.
- Batch E: PraisonAI insufficient reversal, GitPython no-release/attribution negatives, Pydantic carrier projection, FastChat/Kyverno remediation order.

UNKNOWN is preserved for the 23 consolidated pending rows, AutoBangumi CVE-2026-59101, and D5 File Browser semantic overlap. There are no stated row-level BLOCKED results in these snapshots.

## Exact commands and sources

The principal commands executed from /home/hanqing/agents/ai-slop were:

    mkdir -p autoresearch/herdr-260812-ledger-qa
    date --iso-8601=seconds
    pwd
    git status --short --branch | sed -n '1,80p'

    mkdir -p autoresearch/herdr-260812-ledger-qa/snapshot/docs
    cp --preserve=timestamps docs/AUDIT-CONSOLIDATED-LEDGER-156-2026-08-11.md docs/AUDIT-STRICT-LEDGER-156-2026-08-11.md docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-C-2026-08-12.md docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md docs/RESEARCH-PUBLIC-ID-FIRST-PARTY-CLOSURE-2026-08-11.md docs/RESEARCH-STRICT-150-CLOSURE-2026-08-11.md docs/RESEARCH-STRICT-150-COMPLETION-V3-2026-08-11.md docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md autoresearch/herdr-260812-ledger-qa/snapshot/docs/
    chmod a-w autoresearch/herdr-260812-ledger-qa/snapshot/docs/*.md
    sha256sum autoresearch/herdr-260812-ledger-qa/snapshot/docs/*.md
    wc -l autoresearch/herdr-260812-ledger-qa/snapshot/docs/*.md

    rg -n -i '(125|173|180|186|200|target|total|unique|duplicate|alias|release.grade|commit.only|UNKNOWN|BLOCKED|FAIL)' autoresearch/herdr-260812-ledger-qa/snapshot/docs/*.md
    nl -ba autoresearch/herdr-260812-ledger-qa/snapshot/docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md
    nl -ba autoresearch/herdr-260812-ledger-qa/snapshot/docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md
    nl -ba autoresearch/herdr-260812-ledger-qa/snapshot/docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md

    jq -s 'def edges: [.[].evidence[]?.accepted_edges[]?]; {components:length,component_ids_unique:([.[].component_id]|unique|length),public_id_occurrences:([.[].public_ids[]]|length),public_ids_unique:([.[].public_ids[]|ascii_upcase]|unique|length),cves:([.[].public_ids[]|ascii_upcase|select(startswith("CVE-"))]|length),ghsas:([.[].public_ids[]|ascii_upcase|select(startswith("GHSA-"))]|length),accepted_edge_occurrences:(edges|length),accepted_unique_pairs:(edges|map([.candidate_sha,.fix_sha]|join("->"))|unique|length),alias_amendments:([.[].evidence[]?|select(.kind=="public_id_alias_amendment")]|length)}' autoresearch/herdr-260812-ledger-qa/snapshot/artifacts/autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl

    python3 autoresearch/herdr-260812-ledger-qa/verify.py

All first-party claims in this QA are quotations or reconciliations of the frozen reports and artifacts. No new first-party advisory status was fetched. The only live shared paths read were the initial source files for copying/hashing, the cited read-only ledger artifacts, and the diagnostic cached CVE record noted above.

## Claim boundary

This QA supports only:

- exact byte provenance;
- stated-total arithmetic;
- case-normalized public-ID set comparisons;
- exact repo + mechanism + candidate + fix identity collision checks;
- explicit document supersession;
- release versus commit-only classification as stated and evidenced in the snapshots.

It does not independently prove exploitability, AI authorship, causality, or release containment. Publication-grade admission still requires the underlying reports’ full gates: exact atomic AI member, candidate parent delta, same security mechanism, first-party advisory identity, exact fix reversal, and a released candidate-without-fix witness. Routing, source recovery, tests, model votes, OSV introduced ranges, same-file overlap, and this QA itself remain diagnostic evidence.

Do not publish 173 or 186 from this snapshot. The defensible QA wording is:

> The frozen strict artifact has 110 components and 200 public IDs. The later document census supports 125 strict released components. After removing two exact cross-document component duplicates, the broader inventories contain at most 172 released components and at most 184 components including commit-only work; one File Browser semantic overlap remains unresolved.
