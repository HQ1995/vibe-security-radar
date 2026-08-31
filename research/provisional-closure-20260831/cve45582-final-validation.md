# CVE-2026-45582 final validation

## Overall assessment: PASS

The ledger patch draft and generated code-evidence entry are internally consistent and ready for leader review. This validation was read-only against the target artifacts, local Git objects, and live Neon revision `1`; no database apply, site publication, or commit was performed.

## Artifacts checked

- `research/provisional-closure-20260831/cve45582-ledger-patch.jsonl`
- `scripts/generated-code-evidence.json` entry `CVE-2026-45582`
- Local repository `.ai-slop/state/repos/czlonkowski_n8n-mcp`
- Live Neon row `alias-ad08edcf98825ffa3306395b`

## Ledger patch validation

- JSONL contains exactly one parseable patch with `expected_revision: 1`; live Neon is still revision `1`.
- `blocked535` and its companion `blocked535_verdict` are absent.
- `ledger_best` is `CAUSAL_CHAIN_CLOSED`, consistent with the closed `AI_ROOT_CAUSE` result. The value already has nine precedents in the canonical recovery export and is recognized by `scripts/select_round7_pool.py`.
- Publication scope is `AI_INCOMPLETE_FIX`, tier is `ALL_GATES_PASS`, and all seven gates are exactly `PASS`.
- Corrected edge: candidate `597bd290b69459c3b84bbd7cffc5e51c4aa0f28b`, no carrier, direct fix `6cf6fef653fcd6d598f2f356aac4754931c7329f`.
- `ir_chain.attempted_remediation.candidate_shas` and `ir_chain.final_closure.minimum_fix_shas` exactly match the top-level candidate and fix sets.
- The corrected `causal_research` envelope supplies the same introducer/fix pair and direct Claude marker.
- `ledger_store.validate_update()` passes against the live revision-1 row.

## Generated code-evidence validation

- Candidate URL resolves to `597bd290b69459c3b84bbd7cffc5e51c4aa0f28b`; fix URL resolves to `6cf6fef653fcd6d598f2f356aac4754931c7329f`.
- The stale `47510ef6…` candidate is absent from the complete entry.
- Candidate marker and subject match the local commit object: Claude coauthor marker and `fix: critical telemetry improvements for data quality and security (#421)`.
- Candidate evidence contains one causally relevant hunk from `src/telemetry/workflow-sanitizer.ts`; unrelated same-commit Tool-variant hunks are absent.
- Fix evidence contains three hunks from `src/telemetry/workflow-sanitizer.ts`, `src/telemetry/event-validator.ts`, and `dist/telemetry/workflow-sanitizer.js`.
- `comparison_hunks` is exactly the one candidate hunk followed by the three fix hunks.
- Hash contract `sha256("\n".join(hunk.code))` recomputes exactly:
  - candidate: `5465b6006543a73e281ec842927d1e3829bc5bcdebf1fb61ebc538cebe9396bb`
  - fix: `61f4382499f69431fdd30006df8b557e0c4d9a5d79c5ceafbbee6af0fc5e6c25`
- Both commit objects exist locally. Every displayed removed line exists in the corresponding parent blob, every added line exists in the commit blob, and every referenced file is changed by that commit.
- The `CVE-2026-45582` entry itself matches the validated candidate and fix;
  other entries may change independently in the same publication batch.

## Issues and caveats

No target-specific validation errors remain. The patch is still a draft: applying it to Neon, exporting the ledger, rebuilding the site, and committing are deliberately outside this validation task.
