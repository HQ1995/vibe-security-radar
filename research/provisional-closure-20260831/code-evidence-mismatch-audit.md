# Generated code-evidence mismatch audit

Scope: the target rows in `ready-ledger-patches.jsonl` (26) plus
`cve45582-ledger-patch.jsonl` (1), compared read-only with
`scripts/generated-code-evidence.json`.

The comparison treats a generated candidate or fix as compatible only when
the full SHA from its `/commit/<sha>` URL belongs to the target row's
`candidate_set` or `minimum_fix_set`. A generated fix may match either member
of a multi-fix set. Carrier SHAs do not satisfy the candidate check.

At audit time the live Neon rows had not yet incorporated these patch fields,
so the findings below describe the post-application target state. Of 27 target
rows, 20 have a matching generated-evidence key: 19 have a complete
candidate/fix pair to compare and one has candidate-only evidence because its
target `minimum_fix_set` is empty. Seven have no generated entry and thus no
SHA in this file to conflict. Before repair, 15 of the 19 complete pairs were
SHA-compatible and four had an actual conflict.

## Resolution

The four conflicts below are now repaired in
`scripts/generated-code-evidence.json`. A post-repair replay finds all 19
complete generated-evidence pairs compatible with their target
`candidate_set` and `minimum_fix_set`, with zero SHA conflicts. The sections
below retain the pre-repair finding and field-level disposition for auditability.

## Actual SHA mismatches

### GHSA-VFGX-5Q85-58Q3

- Target: candidate `5f60678d7da2eef6404355ecdad28148cb1a37f7`, fix
  `09e96e090417d34d2f533f6810d3cd4f77810101`.
- Generated: candidate `990c09c4f33649b9120d4995c385151652bc5cd9`
  (the later carrier/refactor), same fix.
- Update or discard and regenerate the candidate-bound fields:
  `candidate_url`, `candidate_hunks`, `candidate_patch_sha256`, `ai_marker`,
  the `AI change` step, and `comparison_hunks`.
- The fix-bound fields are compatible and may be retained: `fix_url`,
  `fix_hunks`, `fix_patch_sha256`, `fix_marker`, and the `Fix` step. The
  mechanism-only `summary` does not name the stale SHA and may also remain.

### CVE-2026-46383 / GHSA-MQ5J-PW29-JCV3

- Target: candidate `d6f919476feab3ddbf6ad76c9cf0afb0c5ea8248`, fix
  `77d1dda8303c8d7ccb6148788a6274fdece98499`.
- Generated: candidate `491c9da0c158e40bbbd43127f6ca64096aad7ddb`
  (a later unrelated install change), same fix.
- Update or discard and regenerate `candidate_url`, `candidate_hunks`,
  `candidate_patch_sha256`, `ai_marker`, the `AI change` step, and
  `comparison_hunks`.
- Discard/rewrite `summary`: it explicitly names `491c9da0...` and is
  truncated. The fix-bound fields and `Fix` step may be retained.

### CVE-2026-2393 / GHSA-65H7-C7C4-MGHX

- Target: candidate `42a1acb091e737e457fbafb21c4abbe2214f01fe`;
  accepted fixes `fec1670e7edbd5e7f97087a5299feb3c634826e4` and
  `64aa0ab7207f9c649b59ba1a5f40d82196817389`.
- Generated: candidate `2e0adcfe2d80a3c4f6a379d9db85504c05ce2b60`
  (the later aggregate merge), fix `64aa0ab7...`.
- Update or discard and regenerate `candidate_url`, `candidate_hunks`,
  `candidate_patch_sha256`, `ai_marker`, the `AI change` step, and
  `comparison_hunks`.
- Discard/rewrite `summary`: it explicitly names `2e0adcfe...` and is
  truncated. The generated fix is one of the accepted minimum fixes, so all
  fix-bound fields and the `Fix` step may be retained.

### GHSA-64VR-4GR2-M642

- Target: candidate `5f71e9ece07d9a85655f18fb8b4aa92b9d217408`, fix
  `21de369a5819931d2ad4e88fb71c3baa7524066f`.
- Generated: candidate `32230bc7acff055a089eaf682d6717ca945b6c7d`
  (the main-line carrier), fix `066b31ef8d343d5897ae1c0acdc04672289b1dff`
  (documentation/agent material, not a semantic fix).
- Both sides must be regenerated: `candidate_url`, `fix_url`,
  `candidate_hunks`, `fix_hunks`, both patch SHA-256 fields, both marker
  fields, both `steps`, and `comparison_hunks`.
- `advisory_url` and the mechanism-only `summary` are not SHA-bound and may be
  retained; the summary's truncation is a separate readability defect.

## Accepted archival mirror (not a mismatch)

### CVE-2026-42278

- Candidate and fix SHAs already match the target:
  `8f000e9403a33c693eeb630771bc3d4846473991` and
  `fb6ef59d6c1385400e7acea7ae31fc6a473c3051`.
- The original `UltraDAGcom/core` repository is deleted. The generated URLs
  intentionally use the accessible archival mirror `sumitshahorg/core`.
- Local Git verification shows that the mirror URLs name the same candidate
  and fix objects. Keep both mirror URLs; the hunks, patch hashes, markers,
  steps, and summary remain bound to the original SHAs.

No other generated candidate/fix SHA conflicts were found in the 27-row target
set. The repair modified only the four generated-evidence entries named above;
it did not apply Neon patches, update exports or site data, or modify Git
history.
