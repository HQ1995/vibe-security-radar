# Promisor389 residual11: 0 PASS, 1 candidate-edge reject, 10 UNKNOWN

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This packet proposes no admissions. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. packet_delta=0.

## Claim boundary

Prior recovery rejected only the claimed fix-parent deleted-hunk origin edge. `ghsa_wide_not_ai=false`. `whole_case_causal_reject=false`. This packet audits the two still-open mechanisms on the same 11 identities, exact assigned order:

1. `AI_NEW_SURFACE_CONTRIBUTOR`: an atomic AI commit adding a new call site or exposure to an inherited vulnerable helper.
2. `AI_INCOMPLETE_REMEDIATION`: an explicit AI-authored security attempt released with a same-boundary residual later fixed.

Path overlap, same repository, shared SHA, carrier branding, and deleted-line absence are not causality. Missing residual evidence is UNKNOWN, not GHSA-wide reject. Candidate-edge failure is not GHSA-wide rejection.

## Conservation

Equation: **11=10+1**. Assigned 11. Reviewed 11. Unreviewed 0. Did not pad, backfill, replace, or silent-drop.

| Class | N |
|---|---:|
| Assigned | 11 |
| UNKNOWN | 10 |
| REJECT_CANDIDATE_EDGE | 1 |
| PASS proposal | 0 |
| Whole-case causal REJECT | 0 |
| BLOCKED | 0 |
| Selected | 0 |

## Method

First-party repository security-advisory HTML plus public git. Global advisory-database and OSV are routing only. GitHub API was not used. Temporary clones lived only under `/home/hanqing/.cache/ai-slop-ghsa200/promisor389-residual11` and must be absent at handoff. Replay does not clone, fetch, or call APIs.

## Outcomes in assigned order

| Order | Identity | Repository | Residual new-surface | Residual incomplete rem | Verdict |
|---|---|---|---|---|---|
| 1 | GHSA-RMJ7-2VXQ-3G9F | FasterXML/jackson-databind | NO_HIT | NO_HIT | UNKNOWN |
| 2 | GHSA-833P-95JQ-929Q | phenixdigital/phoenix_storybook | candidate fail | NO_HIT | REJECT_CANDIDATE_EDGE |
| 3 | GHSA-Q2M9-6JP9-C6MC | dgraph-io/dgraph | NO_HIT | NO_HIT | UNKNOWN |
| 4 | GHSA-F2R5-5M7W-P5CX | open-telemetry/opentelemetry-ebpf-profiler | NO_HIT | NO_HIT | UNKNOWN |
| 5 | GHSA-4X76-22X2-RX8V | OpenZeppelin/contracts-wizard | NO_HIT | NO_HIT | UNKNOWN |
| 6 | GHSA-C27G-Q93R-2CWF | vitejs/launch-editor | NO_HIT | NO_HIT | UNKNOWN |
| 7 | GHSA-R854-JRXH-36QX | phpseclib/phpseclib | NO_HIT | NO_HIT | UNKNOWN |
| 8 | GHSA-94G3-G5V7-Q4JG | phpseclib/phpseclib | NO_HIT | NO_HIT | UNKNOWN |
| 9 | GHSA-XJ4F-8JJG-VX4Q | openmrs/openmrs-core | NO_HIT | NO_HIT | UNKNOWN |
| 10 | GHSA-MP2F-45PM-3CG9 | XhmikosR/decompress | NO_HIT | NO_HIT | UNKNOWN |
| 11 | GHSA-W3CP-G2PF-65WH | silverstripe/silverstripe-cms | NO_HIT | NO_HIT | UNKNOWN |

Identity_gate is PASS on all 11: first-party GHSA HTML, not withdrawn, not a login wall. Seven counting gates were opened only on the one residual candidate edge.

### GHSA-RMJ7-2VXQ-3G9F

Helper is `allowIfSubTypeIsArray` on `BasicPolymorphicTypeValidator`. No AI-marked atomic commit adding a new caller of that helper, and no AI security attempt with a later same-boundary residual. UNKNOWN.

### GHSA-833P-95JQ-929Q

GHSA is unbounded atom creation from LiveView event params. Mining pickaxe found `a0bcd9d25f6a` (single-parent, Copilot Autofix trailer) adding `String.to_atom` in `theme_sandbox_data_attribute`. That candidate fails: it is dated 2026-05-28, after fix `96d524690af0` (2026-05-20), is not an ancestor of the fix, and converts an already-atom theme strategy name rather than playground params. ai_hunk_gate FAIL, topology_gate FAIL, but_for_gate FAIL, fix_reversal_gate FAIL. Residual incomplete rem: no hit. REJECT_CANDIDATE_EDGE only. Not GHSA-wide NOT_AI.

### GHSA-Q2M9-6JP9-C6MC

Helper is GraphQL `checkUserPassword` DQL injection. No AI new-caller and no AI incomplete rem on that boundary. UNKNOWN.

### GHSA-F2R5-5M7W-P5CX

No AI-marked residual new-caller or incomplete rem on the unprivileged-process DoS helper. UNKNOWN.

### GHSA-4X76-22X2-RX8V

Claude-marked `89e9fabcd6e7` touches `zip-hardhat.ts` / `zip-foundry.ts` while adding cross-chain options. Path overlap is not promoted: the commit is not an ancestor of the fix parent, and the parent already interpolated unsanitized `opts.name` / `opts.uri`. No residual incomplete rem. UNKNOWN.

### GHSA-C27G-Q93R-2CWF

Windows cmd injection helper in `packages/launch-editor/index.js`. No AI new-caller and no AI incomplete rem. UNKNOWN.

### GHSA-R854-JRXH-36QX

SSH2 `get_binary_packet` variable-time HMAC compare. Distinct from GHSA-94G3 (different SHA, file, mechanism). Shared repository is not uniqueness evidence. No residual AI hit. UNKNOWN.

### GHSA-94G3-G5V7-Q4JG

AES-CBC unpadding timing in `Crypt/Base.php`. Distinct from GHSA-R854. No residual AI hit. UNKNOWN.

### GHSA-XJ4F-8JJG-VX4Q

Velocity SSTI via `ConceptReferenceRangeUtility`. No residual AI hit. UNKNOWN.

### GHSA-MP2F-45PM-3CG9

Archive extraction path traversal. Bind this GHSA only. No residual AI hit. UNKNOWN.

### GHSA-W3CP-G2PF-65WH

Breadcrumb XSS in `CMSMain.php`. No residual AI hit. UNKNOWN.

## Uniqueness

None of the 11 IDs is in canonical84 `strict_released_case_ids` (84). Selected empty. uniqueness_gate was not opened for counting. The two phpseclib identities stay separate.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim. Stop at zero PASS.
