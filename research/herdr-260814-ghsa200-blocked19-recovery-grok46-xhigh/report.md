# Blocked-19 recovery: 0 PASS, 0 whole-case REJECT

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This packet proposes no admissions and does not claim more than 200. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`.

## Claim boundary

No-hit recovery is not a GHSA-wide causal negative. Recovered fix-deleted or parent-context lines with zero AI blame do **not** convert a case into whole-case causal REJECT and do **not** prove GHSA-wide NOT_AI.

Set A (11 promisor fix-blame identities): human origin on the claimed fix-parent deleted source hunks rejects **that candidate edge only** (`REJECT_CANDIDATE_EDGE`, `ai_hunk_gate=FAIL` on that edge). Residual recall remains open for AI new-caller surfaces and incomplete-remediation elsewhere.

Set B (8 additive-guard identities): completed mining window with no hard hit is `NOT_SELECTED` and seven gates stay `NOT_OPENED`. There is no positive parent/candidate but-for counterevidence. No-hit alone is not causal REJECT.

Equation: **19=11+8**. PASS=0. Whole-case REJECT=0. BLOCKED=0. packet_delta=0. Selected empty.

## Assignment

Exactly 19 unique GHSA identities reconstructed from machine artifacts, fail-closed: 11 `blocked_ids` from `autoresearch/herdr-260814-ghsa200-fixblame-promisor389-consolidated-grok46-low/work/blocked.json` plus 8 `worker_verdict=BLOCKED` rows from the three additiveguard packets (first30=0, next30=6, final36=2). Overlap is empty. Did not broaden or backfill.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`.
Canonical84 ledger SHA-256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`.
Shared tracked files, canonical84, and prior packets were not edited.
Clones and raw pages stayed under `/tmp/ghsa200-blocked19-recovery/`.
No commit, push, or credential output.

## Conservation

| Class | N | Meaning |
|---|---:|---|
| Assigned | 19 | Union of set A and set B, unique |
| REJECT_CANDIDATE_EDGE | 11 | Set A claimed fix-parent deleted-hunk edge |
| NOT_SELECTED | 8 | Set B additive mining window, gates not opened |
| Whole-case causal REJECT | 0 | Not inferred from no-hit |
| PASS proposal | 0 | All-seven-PASS rows |
| BLOCKED remaining | 0 | Prior technical blockers cleared |
| Selected | 0 | |
| Canonical strict | 84 | Unchanged |

## Set A: claimed origin-edge rejections (11)

Each row binds first-party GHSA identity and official repository, then blames deleted source hunks at the first-party fix parent. AI-marked origins: 0. The listed human SHAs reject the claimed direct-origin edge. They do not close other contribution classes.

| Identity | Repository | Claimed fix | Edge files | Verdict |
|---|---|---|---|---|
| GHSA-RMJ7-2VXQ-3G9F | FasterXML/jackson-databind | `24529da29fdf,01d1692c8d0e` | BasicPolymorphicTypeValidator.java,BasicPolymorphicTypeValidator.java | REJECT_CANDIDATE_EDGE |
| GHSA-833P-95JQ-929Q | phenixdigital/phoenix_storybook | `96d524690af0` | extra_assigns_helpers.ex,theme_helpers.ex,playground.ex | REJECT_CANDIDATE_EDGE |
| GHSA-Q2M9-6JP9-C6MC | dgraph-io/dgraph | `cee702c93f14` | current_user.go,query.go,query_rewriter.go | REJECT_CANDIDATE_EDGE |
| GHSA-F2R5-5M7W-P5CX | open-telemetry/opentelemetry-ebpf-profiler | `234b685cab31` | file.go,process.go | REJECT_CANDIDATE_EDGE |
| GHSA-4X76-22X2-RX8V | OpenZeppelin/contracts-wizard | `ec12c44f8d9e` | sanitize.ts,zip-foundry.ts,zip-hardhat.ts | REJECT_CANDIDATE_EDGE |
| GHSA-C27G-Q93R-2CWF | vitejs/launch-editor | `971291e8a6a9` | index.js | REJECT_CANDIDATE_EDGE |
| GHSA-R854-JRXH-36QX | phpseclib/phpseclib | `ffe48b6b1b1a` | SSH2.php | REJECT_CANDIDATE_EDGE |
| GHSA-94G3-G5V7-Q4JG | phpseclib/phpseclib | `ccc21aef71eb` | Base.php | REJECT_CANDIDATE_EDGE |
| GHSA-XJ4F-8JJG-VX4Q | openmrs/openmrs-core | `8d1c19323431` | ConceptReferenceRangeUtility.java | REJECT_CANDIDATE_EDGE |
| GHSA-MP2F-45PM-3CG9 | XhmikosR/decompress | `281cefa00cd4,60b5299402e7,aca5aac415dc` | index.js,test.js | REJECT_CANDIDATE_EDGE |
| GHSA-W3CP-G2PF-65WH | silverstripe/silverstripe-cms | `62f9912baa18` | CMSMain.php | REJECT_CANDIDATE_EDGE |

### GHSA-RMJ7-2VXQ-3G9F

First-party jackson-databind GHSA, aliases CVE-2026-54513. Official repo FasterXML/jackson-databind. Fixes `24529da29fdf` and `01d1692c8d0e` (Tatu Saloranta, not AI-marked) delete source in `BasicPolymorphicTypeValidator.java` on the 3.x and 2.18 lines. Blame of those deleted hunks maps to human commits including `533fe319abda`. Prior blocker was blame timeout. Claimed direct-origin edge fails `ai_hunk_gate`. Residual recall: AI new-caller or incomplete rem elsewhere.

### GHSA-833P-95JQ-929Q

First-party phenixdigital/phoenix_storybook, CVE-2026-8469. Fix `96d524690af0` deletes source in `story_live.ex` and playground helpers. Blame maps to human commits including `56ab8464d437`. Prior blocker was blame timeout. Edge reject only.

### GHSA-Q2M9-6JP9-C6MC

First-party dgraph-io/dgraph, CVE-2026-44840. Fix `cee702c93f14` deletes source in `query.go` / `query_rewriter.go`. Blame maps to human commits including `186c9c23c46d` and `261eda002e58`. Tag `v25.3.4` contains the fix. Prior blocker was blame timeout. Edge reject only.

### GHSA-F2R5-5M7W-P5CX

First-party open-telemetry/opentelemetry-ebpf-profiler, CVE-2026-48496. Fix `234b685cab31` deletes source in `process/process.go`. Blame maps to human commits including `3c6d811e6ff4` and the repo initial commit. Prior `^` markers were root-commit boundaries, not a truncated clone. Edge reject only.

### GHSA-4X76-22X2-RX8V

First-party OpenZeppelin/contracts-wizard, CVE-2026-48054. Fix `ec12c44f8d9e` deletes source in `zip-foundry.ts`, `zip-hardhat.ts`, and `sanitize.ts`. Blame maps to human commits including `b603d099a8d6`. Tag `@openzeppelin/wizard@0.10.9` contains the fix. Edge reject only.

### GHSA-C27G-Q93R-2CWF

First-party GHSA is published on vitejs/launch-editor (yyx990803/launch-editor is the prior owner URL). Fix `971291e8a6a912` deletes source in `packages/launch-editor/index.js`. Blame maps to human `5366f3ee3add` (Windows filename allowlist) and root commit `7927d8a8b01f`. Prior `blocked_shallow_boundary` was that root-commit `^` prefix, not missing history. Claimed direct-origin edge fails. Residual recall remains open.

### GHSA-R854-JRXH-36QX

First-party phpseclib/phpseclib, CVE-2026-40194, SSH2 HMAC compare. Fix `ffe48b6b1b1a` deletes one source hunk in `phpseclib/Net/SSH2.php`. Blame maps to human `efd3b96dc8e3`. Distinct from GHSA-94G3 (different SHA, file, mechanism). Shared repository is not uniqueness evidence. Edge reject only.

### GHSA-94G3-G5V7-Q4JG

First-party phpseclib/phpseclib, CVE-2026-32935, AES-CBC unpadding. Fix `ccc21aef71eb` deletes one source hunk in `phpseclib/Crypt/Base.php`. Blame maps to human `55ff00cc35e8`. Distinct from GHSA-R854. Edge reject only.

### GHSA-XJ4F-8JJG-VX4Q

First-party openmrs/openmrs-core, CVE-2026-41258. Advisory listed short SHA `8d1c193`; full clone resolved `8d1c19323431`, which deletes source in `ConceptReferenceRangeUtility.java`. Blame maps to human commits including `7c9cc9bc5e1f`. Prior blocker was short-SHA fetch against a promisor clone. Edge reject only.

### GHSA-MP2F-45PM-3CG9

First-party XhmikosR/decompress, CVE-2026-53486. Short SHAs `281cefa`, `60b5299`, `aca5aac` resolved on the official repo to `281cefa00cd4`, `60b5299402e7`, `aca5aac415dc`, each deleting source in `index.js`. Blame maps to human commits including `22dea38e5ead`. Prior blocker was short-SHA fetch. Bind per GHSA; do not merge with other decompress identities. Edge reject only.

### GHSA-W3CP-G2PF-65WH

First-party silverstripe/silverstripe-cms, CVE-2026-54717. Fix `62f9912baa18` deletes source in `code/Controllers/CMSMain.php`. Blame maps to human `5336a999b5c8`. Tag `6.2.1` contains the fix. Prior blocker was shallow plus blame timeout. Edge reject only.

## Set B: additive mining NOT_SELECTED (8)

Each row completed the additive-guard window (added hunks plus unchanged parent context) after full or ref-scoped public fetches. AI-marked origins: 0. Seven gates were not opened. No positive but-for counterevidence was recorded.

| Identity | Repository | Cited fix | Verdict |
|---|---|---|---|
| GHSA-97F8-7CMV-76J2 | mmaitre314/picklescan | `2a8383cfeb41,b9997634683a` | NOT_SELECTED |
| GHSA-7C4H-VH2M-743M | n8n-io/n8n | `ae0669a736cc` | NOT_SELECTED |
| GHSA-6J5F-24FW-PQP4 | ImageMagick/ImageMagick | `23fde73188ea` | NOT_SELECTED |
| GHSA-8VRH-3PM2-V4V6 | gtsteffaniak/filebrowser | `a8c9b9419ec5,c51b0ee9738f` | NOT_SELECTED |
| GHSA-8398-GMMX-564H | n8n-io/n8n | `8607d372f78c` | NOT_SELECTED |
| GHSA-96PC-27RX-PR36 | ImageMagick/ImageMagick | `51c9d33f4770` | NOT_SELECTED |
| GHSA-WF6X-7X77-MVGW | immutable-js/immutable-js | `16b3313fdf2c,6e2cf1cfe613,6ed4eb626906` | NOT_SELECTED |
| GHSA-M272-9RP6-32MC | middleapi/orpc | `1dba06fc6f93` | NOT_SELECTED |

### GHSA-97F8-7CMV-76J2

First-party mmaitre314/picklescan, CVE-2026-53875. Advisory URL `.../picklescan/commit/134179474539...` is not a picklescan object (HTTP 404 / not our ref). That SHA is a PyTorch citation in the advisory body and was excluded; evidence is not unioned across repositories. `2a8383cfeb41` adds no source (image link). `b9997634683a` is the named picklescan fix; additive parent-context blame has no AI marker. NOT_SELECTED. Residual recall remains open.

### GHSA-7C4H-VH2M-743M

First-party n8n-io/n8n, CVE-2026-21893. Fix `ae0669a736cc`. Prior blocker was missing blob `aeead3b20f59` during log -L. Ref-scoped fetch cleared it. Additive window has no AI marker. Distinct from GHSA-8398. NOT_SELECTED.

### GHSA-6J5F-24FW-PQP4

First-party ImageMagick/ImageMagick, CVE-2026-25897. Fix `23fde73188ea` on `coders/sun.c`. Prior missing-blob / boundary notes resolved on a blobless clone with lazy blob fetch. Additive window has no AI marker. Distinct from GHSA-96PC. NOT_SELECTED.

### GHSA-8VRH-3PM2-V4V6

First-party gtsteffaniak/filebrowser, CVE-2026-27611. Fixes `a8c9b9419ec5` and `c51b0ee9738f`. Prior log -L could not read `d8321b9543f5`. Fetch cleared it. Additive window has no AI marker. NOT_SELECTED.

### GHSA-8398-GMMX-564H

First-party n8n-io/n8n, CVE-2026-25115. Fix `8607d372f78c` on the Python task-runner files. Same missing-blob class as GHSA-7C4H; different SHA, files, and mechanism. Additive window has no AI marker. NOT_SELECTED.

### GHSA-96PC-27RX-PR36

First-party ImageMagick/ImageMagick, CVE-2026-24481. Fix `51c9d33f4770` on `coders/psd.c`. Distinct from GHSA-6J5F. Additive window has no AI marker. NOT_SELECTED.

### GHSA-WF6X-7X77-MVGW

First-party immutable-js/immutable-js, CVE-2026-29063. Fixes `16b3313fdf2c`, `6e2cf1cfe613`, `6ed4eb626906`. Two are merges; member walk found no AI-marked member. `src/utils/protoInjection.ts` is a new file (not blamed as parent context). Additive window has no AI marker. A squash or merge carrier does not transfer authorship. NOT_SELECTED.

### GHSA-M272-9RP6-32MC

First-party middleapi/orpc, CVE-2026-28794. Fix `1dba06fc6f93` on `rpc-json-serializer.ts`. Prior missing blobs `de07bc32516c` and `2dfcb9671128` were fetched. Additive window has no AI marker. NOT_SELECTED.

## Uniqueness

None of the 19 IDs is in canonical84 `strict_released_case_ids` (84). No selected row. Shared repository, shared closer author, or shared candidate/fix SHA does not merge identities. Mechanism fingerprints were not admitted. uniqueness_gate was not opened for counting.

## Residual recall

This packet does not exhaust AI_NEW_SURFACE_CONTRIBUTOR, AI_INCOMPLETE_REMEDIATION, or AI_REINTRODUCTION on these 19 identities. A later worker may still propose a different scoped edge if all seven gates independently PASS. Canonical strict stays 84 unless the leader separately red-teams and integrates a proposal.

## Missing objects

None remaining. Prior technical blockers (blame timeout, short SHA, root-commit `^` treated as shallow, not-our-ref foreign SHA, missing blobs) were cleared with full or ref-scoped public fetches under /tmp.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| Whole-case REJECT | 0 |
| REJECT_CANDIDATE_EDGE | 11 |
| NOT_SELECTED | 8 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |

## Claim boundary (repeat)

Countable PASS requires all seven gates PASS and leader admission. Proposed PASS: 0. Whole-case causal REJECT: 0. Publication remains HOLD. Greater-than-200 remains HOLD. This packet does not rebuild canonical84.
