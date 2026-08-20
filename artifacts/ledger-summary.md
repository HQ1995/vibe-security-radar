# Vibe Security Radar - canonical research ledger summary

The JSONL ledger is the source of truth. Refreshed 2026-08-20 after the BLOCKED boundary review, direct Git rechecks for the remaining stale NOT_AI attributions, and final evidence reconciliation.

## Canonical status

| Status | Classes | Meaning |
|---|---:|---|
| AI_ROOT_CAUSE | 148 | AI code directly introduced or enabled the vulnerability mechanism. |
| AI_CODE_FLAWED | 52 | AI-written code was flawed, including incomplete fixes and copied vulnerable logic. |
| NOT_AI | 39 | AI attribution is resolved as not AI-caused; remediation and history are tracked separately below. |
| PARTIALLY_ANALYZED | 6170 | Some evidence exists, but the complete causal chain is not closed. |
| BLOCKED | 22 | A required implementation, fix, ownership, or history boundary is unavailable. |
| UNANALYZED | 17430 | No individual causal research has been completed. |
| Total | 23861 | One row per canonical advisory class. |

## NOT_AI causal review

The current 39 NOT_AI classes were reviewed at the semantic-causality level. NOT_AI is an attribution result, not a claim that remediation is complete.

- Second review coverage: 39/39.
- Attribution conclusion: 39/39 have a semantic attribution record.
- Evidence gate: 39/39 have mechanism, introducer, AI-role, and fix-or-no-fix evidence.
- Remediation dimensions: 36 FIX_VERIFIED; 1 FIXED_AFTER_INCOMPLETE_INTERMEDIATE_FIX; 1 FIX_WITH_KNOWN_DNS_REBINDING_RESIDUAL; 1 NO_FIX_HEAD_STILL_VULNERABLE.
- Lineage dimensions: 3 ROOT_OR_IMPORT_BOUNDARY; 1 PUBLIC_SOURCE_MOVE_BOUNDARY; 28 MULTI_INTRODUCER_BOUNDARY; 7 PARENT_VERIFIED.
- Causal review dimensions: 33 MECHANISM_AND_ATTRIBUTION_CLOSED; 3 history boundary; 2 remediation boundary; 1 no-fix.
- Local and remote Git lineage, root/import boundaries, and multi-introducer parent maps are materialized for all 39 rows.
- The ciguard symlink case is recorded separately as AI_ROOT_CAUSE because its introducer carries a Claude co-author marker and creates the vulnerable walker.
- Multi-introducer and aggregate-fix boundaries remain explicit; they are not collapsed into a fake single BIC.
- Direct Git recheck: 9/39 NOT_AI rows are now routed through `.ai-slop/state/notai-review/notai-direct-recheck-20260819.jsonl`; this corrected stale package-import/dependency/release SHAs for SVGO, Kubewarden, Hatchet, OpenAM, and five MotionEye advisories.
- Independent raw-source manifest: 39/39 `SOURCE_COMPLETE`, 0 identity mismatches.
- Ledger projection reconciliation: 39/39 NOT_AI rows now project the canonical causal fields; the 9 direct rechecks override only non-empty fields, so they cannot erase canonical mechanism or closure evidence with nulls. Projection conflict audit: 0.
- OpenAM retains an explicit public source-move boundary; MotionEye retains separate atomic introducers for media preview/delete, movie playback, config permissions, restore/action execution, and filename validation.
- Explicit no-fix cases: 1.
- Canonical reconciliation: .ai-slop/state/notai-review/notai-causal-canonical-20260819.jsonl.
- Per-row semantic provenance: .ai-slop/state/notai-review/notai-provenance-audit-20260819.jsonl (39/39 matched semantic and second-review manifests).
- Detailed second review: .ai-slop/state/notai-review/notai-second-review-20260819.jsonl.
- Final second-review manifest: 39/39 rows. Attribution evidence is closed; remediation and lineage dimensions remain visible above.
- Legacy closure dossier: .ai-slop/state/notai-review/legacy-9router-causal-20260819.jsonl.
- ciguard causal dossier: .ai-slop/state/notai-review/ciguard-causal-20260819.jsonl.
- Kiota causal dossier: .ai-slop/state/notai-review/kiota-causal-20260819.jsonl.
- AI-role adversarial review: 39/39 rows passed. It found no AI introducer evidence: 30 rows have no causal AI marker, 5 have AI only on a complete fix, 1 has AI only in a PR documentation summary, and 3 have remediation caveats without causal AI evidence. Artifact: .ai-slop/state/notai-review/notai-ai-role-adversarial-20260820.jsonl.
- The 5 AI-fix-only rows remain NOT_AI because the vulnerable behavior was introduced by a human commit and the AI-assisted fixes are complete; this is distinct from AI_CODE_FLAWED. Incomplete or residual remediation is recorded separately and is not silently treated as fixed.

## Final NOT_AI re-audit correction - 2026-08-20

- Three prior NOT_AI rows were requeued to PARTIALLY_ANALYZED: two ciguard cases whose available root/aggregate metadata does not resolve the introducer AI role, and the Nexent case whose 199-file Code-transfer import root hides pre-import authorship and AI provenance.
- Two ImageMagick cases were retained after correcting their causal boundaries against the real repository: the MIFF allocation-failure leak starts at the 2009 import root; the LZMA writer flaw starts at 263771792, not the later 330af6c refactor.
- MasterGo was retained after correcting its immediate parent to dd3169bbf2fd8bace8393035d42bf7ec83b35ccb; the head remains unfixed, and the human GetC2d addition is now parent-verified.
- Correction log: .ai-slop/state/notai-review/notai-reaudit-corrections-20260820.jsonl.

## BLOCKED boundary review - 2026-08-19

All 22 current BLOCKED rows carry a deduplicated boundary dossier. The dossiers establish mechanism and ownership boundary, but do not promote a case without atomic introducer, parent absence, direct fix hunk, squash decomposition, and causal AI evidence.

- Claude Code: 20 cases; 19/20 have an exact published npm/platform fixed-version transition with a changed bundled artifact. Within those 19, CVE-2026-54316 now has a real Linux x64 target-context diff confirming the vulnerable bare `huggingface.co` allowlist was narrowed to `huggingface.co/docs`; one fixed version is no longer retrievable from npm. These package transitions close published behavior, but not the atomic Git introducer, direct fix hunk, squash decomposition, or AI authorship.
- NestJS devtools: 1 case; npm 0.0.1--0.2.0 vulnerable behavior and 0.2.1 remediation are closed from local tarballs. The package has no reachable public Git object history, so introducer/fix lineage and AI role remain unverified.
- Arnold USD: 1 case; affected importer is closed Autodesk code, while arnold-usd is a carrier.

Status remains BLOCKED for all 22 rows; missing causal history is not evidence for NOT_AI.
- Final machine-readable boundary fields are present on 22/22 rows: implementation boundary, causal status, fix status, AI-role status, and evidence reference.
- Boundary evidence index: .ai-slop/state/blocked-deepwave/blocked-boundary-evidence-index-20260819.jsonl (22/22 rows, no GitHub API).
- Evidence integrity: 22/22 second-review dossiers have concrete mechanisms, conclusions, remaining gaps, next boundaries, and evidence references; 65 references resolve to local artifacts and 1 is an explicitly recorded Autodesk advisory URL.
- Interpretation boundary: BLOCKED means the vulnerability mechanism is understood where stated, but atomic introducer/fix lineage and AI causality remain unavailable; it is not equivalent to a completed causal review.

## BLOCKED second boundary reconciliation - 2026-08-20

- Reconciled all 22 current BLOCKED rows against the canonical boundary audit and evidence index; coverage is 22/22 unique class IDs.
- Second-review summary: `.ai-slop/state/blocked-deepwave/blocked-second-review-summary-20260820.jsonl`.
- All 22 remain `RETAIN_BLOCKED`: 20 private/closed Claude Code implementation-history boundaries, 1 NestJS public-package-history boundary, and 1 closed Autodesk Arnold implementation boundary.
- NestJS is now classified as `SOURCE_UNAVAILABLE` rather than `CAUSAL_CHAIN_OPEN`: the package mechanism and 0.2.1 fix are understood; only commit-level provenance and AI-role evidence remain unavailable.
- Claude Code cli.js.map snapshot evidence is recorded separately in .ai-slop/state/blocked-deepwave/claude-code-source-map-evidence-20260820.jsonl. Its 20 records have null class_id values and broad keyword matches, so it is retained as raw material only and excluded from per-case mechanism/lineage acceptance. The authoritative mechanism evidence is the canonical semantic dossier plus the 20 case-specific deep reviews; none of these proves the vulnerable-line introducer, parent absence, direct fix, squash members, or AI role.
- The second reconciliation produced no new causal Git lineage and did not change ledger bucket counts.
- Claude Code cached before/fixed bundle comparison is recorded in .ai-slop/state/blocked-deepwave/claude-code-bundle-diff-20260820.jsonl: 18/20 cases show mechanism-related keyword context changes, 1/20 has the fixed artifact unavailable (0.2.111), and the former 1/20 platform-binary result for CVE-2026-54316 was a Windows placeholder comparison and is superseded by the real Linux x64 targeted evidence below. These are published-artifact behavior signals only, not Git fix commits or AI attribution.
- All 20 Claude tarballs were checked for source/history material; they contain bundled CLI/platform members but no parented Git history, atomic source lineage, squash members, or causal AI metadata. They therefore remain BLOCKED.
- The 20 Claude bundle signals are projected into the BLOCKED boundary index as supplemental evidence; the primary causal boundary remains SOURCE_UNAVAILABLE.
- CVE-2026-54316 targeted binary evidence: `.ai-slop/state/blocked-deepwave/claude-code-54316-linux-bundle-evidence-20260820.jsonl`; the Windows placeholder comparison was discarded as invalid evidence.

## Integrity

- JSONL rows: 23861/23861 parse successfully.
- Unique class_id: 23861/23861.
- Status counts: {"AI_CODE_FLAWED": 52, "AI_ROOT_CAUSE": 148, "BLOCKED": 22, "NOT_AI": 39, "PARTIALLY_ANALYZED": 6170, "UNANALYZED": 17430}.
- BLOCKED boundary dossiers: 22/22 unique class_ids.
- NOT_AI evidence audit: 39/39 passed; no row is counted as fully remediated unless remediation_status is FIX_VERIFIED.
- NOT_AI dimension fields: notai_attribution_status, notai_remediation_status, notai_lineage_status, notai_causal_review_status.
- Ledger backup: funnel-account-20260817.jsonl.bak-final-reconcile-20260819.

- Canonical manifest repair: 39/39 records rebuilt from ledger causal_research; direct_fix_sha/fix_sha unified and explicit no-fix preserved.
- Direct-recheck overrides: 9; each retains newer targeted Git evidence while preserving canonical fields not covered by that recheck.
- Multi-introducer causal boundaries: 9 projected review states (8 multi-introducer cases plus 1 explicit source-move boundary); each retains separate introducer roles and is not collapsed into a fake single BIC.
- Projection repair script: reconcile_notai_projection_20260820.py; it applies canonical evidence first and non-empty direct-recheck fields second.
- Direct Git recheck artifact: `.ai-slop/state/notai-review/notai-direct-recheck-20260819.jsonl`; generator: `reconcile_notai_direct_recheck_20260820.py`.
- ImageMagick squash evidence: short 9d72f1a800 resolved to 9d72f1a800b88a59673d77b1da69d047daa88523 with parent b9cfe27bef51dbbd1f05aef89c767749d7e37864.
