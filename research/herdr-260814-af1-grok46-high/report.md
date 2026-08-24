# AI fix slice 1 adjudication

## Verdict first

All 25 assigned rows are terminal and non-countable. Every `fix_ref` is presented by the local first-party GitHub-reviewed GHSA as a closing patch for a vulnerability that predates that commit. The final verdict is therefore `REJECT_AI_FIX_ONLY` for all 25 rows. No row is `AI_INCOMPLETE_REMEDIATION`, no row is `AI_NEW_SURFACE_CONTRIBUTOR`, and the packet contributes zero countable proposals. Because there are no incomplete-remediation verdicts, no populated `original_vulnerability` block is required; every case records it as `null` rather than inventing an original advisory or introducing SHA.

Thirteen rows carry an explicit AI authorship marker (Claude, Copilot, or Cursor) on the closer. That still fails `ai_hunk_gate`: the study counts AI-authored vulnerable hunks, not AI-authored final fixes. Twelve rows are scanner false positives (human coauthors, a Gemini review bot, or a subject that mentions AI-generated HTML as XSS payload). Three Open Babel identities are withdrawn duplicates; they fail identity and uniqueness in addition to the closing-patch exclusion.

Locutus GHSA-RXRV names a residual bypass of an earlier `includes()` guard, but the assigned SHA `042af9` is the later regex closer, not the incomplete prior attempt. Fedify references a second SHA `bf2f078` that is absent from the local bare pool; that missing object is not converted into patch-delta proof. Canonical84 overlap is empty. These are worker adjudications only. Canonical84 remains the claim layer, publication remains `HOLD`, and the greater-than-200 claim remains unsupported.

## Gate accounting

Gate order in the per-row table is identity / AI hunk / topology / but-for / fix reversal / release / uniqueness.

| Gate | PASS | FAIL | UNKNOWN | Decisive boundary |
| --- | ---: | ---: | ---: | --- |
| `identity_gate` | 22 | 3 | 0 | Three Open Babel GitHub-reviewed objects are withdrawn duplicates. |
| `ai_hunk_gate` | 0 | 25 | 0 | Explicit AI markers are on closing patches, not vulnerable hunks. |
| `topology_gate` | 25 | 0 | 0 | Each assigned SHA is the advisory-referenced closer; no authorship is transferred from a carrier. |
| `but_for_gate` | 0 | 25 | 0 | Removing a closer restores the older vulnerability; it does not shrink a candidate-authored surface. |
| `fix_reversal_gate` | 25 | 0 | 0 | Each first-party object names the candidate as a patch for the same invariant. |
| `release_gate` | 0 | 25 | 0 | The candidate sits on the fixed side of the GHSA range, not in a vulnerable artifact as an AI-introduced hunk. |
| `uniqueness_gate` | 22 | 3 | 0 | No active assigned identity is in canonical84; withdrawn duplicates fail uniqueness. |

## Per-row

| case_id | verdict | class | I/A/T/B/F/R/U | marker | disagreement |
| --- | --- | --- | --- | --- | --- |
| `GHSA-6363-V5M4-FVQ3` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | P/F/P/F/P/F/P | scanner FP | none |
| `GHSA-RXRV-835Q-V5MH` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | P/F/P/F/P/F/P | explicit closer | advisory residual language refers to a prior includes() guard; assigned SHA is the closer |
| `GHSA-GXJX-7M74-HCQ8` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | P/F/P/F/P/F/P | explicit closer | none |
| `GHSA-W5FM-68J4-FPC4` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | P/F/P/F/P/F/P | explicit closer | none |
| `GHSA-9W53-XR52-MWGJ` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | P/F/P/F/P/F/P | scanner FP | none |
| `GHSA-HVXG-77MG-VRVP` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | P/F/P/F/P/F/P | scanner FP | none |
| `GHSA-2G4F-4PWH-QVX6` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | P/F/P/F/P/F/P | scanner FP | none |
| `GHSA-RCHF-XWX2-HM93` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | P/F/P/F/P/F/P | explicit closer | second SHA bf2f078 missing locally; not treated as incomplete rem |
| `GHSA-246W-JGMQ-88FG` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | P/F/P/F/P/F/P | explicit closer | none |
| `GHSA-R87G-78MX-3WG4` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | P/F/P/F/P/F/P | explicit closer | none |
| `GHSA-HM5P-X4RQ-38W4` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | P/F/P/F/P/F/P | explicit closer | none |
| `GHSA-XXJ9-F6RV-M3X4` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | P/F/P/F/P/F/P | scanner FP | none |
| `GHSA-QG2P-9JWR-MMQF` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | P/F/P/F/P/F/P | scanner FP | none |
| `GHSA-QCGG-J2X8-H9G8` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | P/F/P/F/P/F/P | scanner FP | none |
| `GHSA-8J24-CJRQ-GR2M` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | P/F/P/F/P/F/P | scanner FP | none |
| `GHSA-VVJJ-XCJG-GR5G` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | P/F/P/F/P/F/P | explicit closer | none |
| `GHSA-X6XQ-WHH3-GG32` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | P/F/P/F/P/F/P | scanner FP | none |
| `GHSA-WXCX-GG9C-FWP2` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | P/F/P/F/P/F/P | scanner FP | none |
| `GHSA-299V-8PQ9-5GJQ` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | P/F/P/F/P/F/P | scanner FP | AI-generated in subject is payload class, not authorship |
| `GHSA-XF94-H87H-G9WR` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | P/F/P/F/P/F/P | scanner FP | none |
| `GHSA-2M54-8M6G-QF93` | `REJECT_AI_FIX_ONLY` | `WITHDRAWN_DUPLICATE_FINAL_CLOSURE_EXPLICIT_AI_MARKER` | F/F/P/F/P/F/F | explicit closer | withdrawn duplicate identity |
| `GHSA-3F56-W4G2-MX64` | `REJECT_AI_FIX_ONLY` | `WITHDRAWN_DUPLICATE_FINAL_CLOSURE_EXPLICIT_AI_MARKER` | F/F/P/F/P/F/F | explicit closer | withdrawn duplicate identity |
| `GHSA-FG6R-XGP8-X64R` | `REJECT_AI_FIX_ONLY` | `WITHDRAWN_DUPLICATE_FINAL_CLOSURE_EXPLICIT_AI_MARKER` | F/F/P/F/P/F/F | explicit closer | withdrawn duplicate identity |
| `GHSA-4W5W-4FHM-Q483` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | P/F/P/F/P/F/P | explicit closer | none |
| `GHSA-6XW4-2G22-26H8` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | P/F/P/F/P/F/P | explicit closer | none |

## Evidence paths

- Slice: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-fix-slice-1.jsonl`
- Contract: `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md`
- Truth layers: `docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md`
- Advisory clone: `/home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/advisory-database` (HEAD 6e8a7ca9)
- Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>`
- Canonical84 ledger observed sha256 a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06 (truth-layers declared hash differs by two hex chars; ledger was not edited)

## Constraints kept

Owned directory only. No GitHub API, no commits, no ledger/web/scripts edits. English only. Worker PASS is a proposal; this packet emits none.

