# GHSA-64VR potential-fix ledger patch notes

Status: **draft, validated against live revision 2, not applied**. No Neon mutation, export, publisher run, generated output, commit, or web access was performed.

## Live base

- Class: `alias-75103365dffacc4143581f32` / `GHSA-64VR-4GR2-M642` / `CVE-2026-30635`.
- The live transaction-read-only query on 2026-08-30 returned revision `2`, change set `da7d00db-b73d-413e-9b76-ca34bbc2b62c`.
- Live revision 2 still has `minimum_fix_set=["21de369a5819931d2ad4e88fb71c3baa7524066f"]`, `fixed_release=null`, and no `unpatched.potential_fix`.

## Evidence and bounded delta

- The first-party advisory cache at `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/05/GHSA-64vr-4gr2-m642/GHSA-64vr-4gr2-m642.json` identifies CWE-78 in `automagik-genie` 2.5.27 through `view_task` / `readTranscriptFromCommit` with an external `FORGE_BASE_URL`.
- Local tag `v2.5.27` resolves to `9811c738054d817ce39ea05f05e28ae9312819f4`. Its `src/mcp/server.ts` interpolates Forge-supplied `commitSha` and container-derived `gitDir` into an `execSync` shell string.
- The evidence-backed v2 remediation approach is to validate a full hexadecimal commit ID and invoke Git without a shell, using separate arguments. This removes shell interpretation and Git option injection while preserving the transcript lookup.
- Merge `21de369a5819931d2ad4e88fb71c3baa7524066f` deletes the 1,183-line v2 MCP server on promotion to v3. It is successor/removal evidence only, not a v2 patch, fixed release, or minimum fix set.
- Relative to live revision 2, the single full-row update clears the contradictory v3 successor from `minimum_fix_set` and adds only `unpatched.potential_fix.approach` and `unpatched.potential_fix.rationale`. `fixed_release` remains null and advisory IDs are unchanged.

## Validation

- `json.loads`: PASS (one JSON object / one JSONL line).
- `scripts/ledger_store.read_patches(..., require_assessments=False)`: PASS.
- `scripts/ledger_store.validate_update`: PASS against the live revision-2 row.
- Exact live-delta assertion: only `minimum_fix_set` and `unpatched.potential_fix` change.
- `scripts/site_preflight.unpatched_errors`: PASS; advisory IDs remain exactly `["CVE-2026-30635", "GHSA-64vr-4gr2-m642"]`.
- Patch SHA-256: `a229ebfd27c67aa149f5c510093e78236b2488668b92de2d07dcebba2bec8f44`.
