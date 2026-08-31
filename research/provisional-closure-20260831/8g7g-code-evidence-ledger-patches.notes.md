# GHSA-8G7G / GHSA-56C3 code-evidence follow-up notes

Status: unapplied atomic follow-up for leader review. This artifact does not
modify the already-applied identity un-fold patch.

## Live revision basis

Both complete rows were freshly read from live Neon after the identity un-fold:

| Class | Expected revision | Live change set | Follow-up scope |
|---|---:|---|---|
| `alias-c5a7e76e9787edf4ea076555` | `2` | `367e9a5e-5d34-49ec-bfd3-9e645f867df6` | `code_evidence` only |
| `alias-f8d8e53edbeacc7b689a133b` | `2` | `367e9a5e-5d34-49ec-bfd3-9e645f867df6` | `code_evidence` only |

The two full rows are in one JSONL file so `ledger_store.py apply` would lock,
revision-check, and update them in one database transaction. Do not split the
file. No apply or finalize command was run.

## Correction

The revision-2 evidence used abbreviated pseudo-diffs: some stored `@@` counts
did not match their bodies, and some objects combined non-contiguous source
regions under one hunk. This follow-up replaces those objects with blocks
extracted verbatim from `git diff --no-ext-diff --unified=3 <parent> <commit>`.

### GHSA-56C3 / c5a7

- Candidate `d9d847f230923d96e0857ccecf3a4dedcc9b0096`: one complete hunk,
  `@@ -184,4 +184,66 @@`, from `src/utils/ssrf-protection.ts`.
- Fix `9639f757853149f0cb16663cc8b6b6468f27a25f`: two complete hunks,
  `@@ -51,6 +52,55 @@` and `@@ -244,6 +289,14 @@`, from the same file.
- Candidate selected-hunk SHA-256:
  `825ff67214187288f214e3fdee477e26157bfe7677ddf06f0e92aae1e5eeb349`.
- Fix selected-hunk SHA-256:
  `9c937f9e6c8f88910119fedef32eabe1b96e0b4d2bc9a86c61f34c2f3420405c`.

### GHSA-8G7G / f8d8

- Candidate `74f05e937fa7d94babe3507510caa17ce17a698c` creates
  `src/services/n8n-api-client.ts`. Because its parent has no such file, the
  only truthful unified hunk is retained in full: `@@ -0,0 +1,390 @@`.
- Fix `1cfe9c6bddb4b1634e6e23323c18ea35fd196999`: three exact seven-line
  replacement hunks for workflow, execution, and credential paths plus the
  complete helper hunk `@@ -13,6 +13,34 @@` in
  `src/utils/validation-schemas.ts`.
- Candidate selected-hunk SHA-256:
  `2fb93cb2e3356b86dfb0df4a214fdf731e138da2e90228d42e6a9888eac985f5`.
- Fix selected-hunk SHA-256:
  `6c3f5ed71c963dfd560505f2ed1a5c8ed75b50e10992cdfe4095ca51809e7cd0`.

Every displayed hunk keeps a distinct reader annotation. Required anchors and
candidate/fix patch-file witnesses were recomputed from these exact blocks.

## Validation

- Physical JSONL: 2 lines, 2 unique class IDs, 35,881 bytes.
- File SHA-256:
  `19fd79f2229540a8dbdab259980129a7004530f580962668b213daf5742bb5d9`.
- Every physical line passed `json.loads` and
  `ledger_store.read_patches(require_assessments=False)`.
- Both rows still matched live revision `2`, preserved the live
  `advisory_ids`, and passed `ledger_store.validate_update()`.
- Replacing each proposed row's `code_evidence` with the live value reproduced
  the live row exactly; no field outside `code_evidence` changed.
- All eight stored hunks are byte-for-byte members of the corresponding raw
  `-U3` Git diff. Each `@@` old/new count matches its body, and the reconstructed
  old and new line sequences match the exact parent and child blobs at the
  declared positions.
- The file-birth hunk was specifically checked as old count `0`, new count
  `390`, against an absent parent blob and the complete 390-line child blob.
- All four selected-hunk hashes were recomputed; `candidate_patch_files` and
  `fix_patch_files` were checked against `git diff-tree` for the named commits.
- Required anchors, distinct public annotations, empty publication issues, and
  the existing GHSA-56C3 remediation chain all passed their local checks.
- No Neon mutation, publisher run, web/generated write, or commit was
  performed.
