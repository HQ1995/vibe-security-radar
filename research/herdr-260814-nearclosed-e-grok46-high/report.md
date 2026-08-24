# Near-closed released wave E (fp211 ordinals 123, 126, 133)

Verdict first: **1 PASS proposal**. Two NARROW. 0 REJECT. 0 UNKNOWN. 0 BLOCKED.

Assigned 3, reviewed 3, unreviewed 0. Conservation 3=3+0. Worker PASS is a proposal only. Canonical88 remains 88 HOLD. Packet delta 0. Publication and greater-than-200 stay HOLD. This packet does not rebuild the strict-released ledger.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical88 summary SHA-256 `81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921`. Ledger SHA-256 `35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074`. fp211 public_cases.jsonl SHA-256 `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`. Shared tracked files and canonical ledgers were not edited. No commit, push, or credential output.

## Assignment

Exactly three first-party identities, fp211 ordinals 123, 126, 133: GHSA-2QRV-RC5X-2G2H, GHSA-5WP8-Q9MX-8JX8, GHSA-R5JH-Q2MW-GCX4. Overlay routing is release_gate PASS with exactly one inherited causal gate NARROW (identity, topology, but_for). That vector is not truth. All seven contract gates were rebuilt from Git objects, first-party advisories, tags, and public artifacts.

PASS_PROPOSAL required all seven gates exact PASS for the counted scope. Scoped-contributor rule: PASS only if removing the exact atomic AI change eliminates or materially shrinks a precisely named advisory mechanism, even when an older sibling path remains, and the later minimum fix reverses that exact new surface. Incomplete remediation uses the patch-delta rule. Preservation, refactor, sibling caller of a preexisting helper, and packed second identities are rejected. Non-ancestor squash members are not transferred onto carriers.

Clones used read-only: `/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw`, `/home/hanqing/.cache/cve-analyzer/repos/qhkm_zeptoclaw`, `/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/fission`. No clone writes. No durable pages.

## Per case

1. GHSA-2QRV-RC5X-2G2H ordinal 123 NARROW ai_hunk_gate, but_for_gate, fix_reversal_gate. Identity PASS: reviewed first-party GHSA-2qrv aliases CVE-2026-41295 only, untrusted workspace channel shadows during built-in setup, patched 2026.4.2 by 53c29df2. Distinct from GHSA-82QX-6VJ7-P8M2 / CVE-2026-43571 (catalog lookups, fix 1fede43b, patched 2026.4.10). Neither identity is a formal alias of the other. Count squash f4cc93dc on its own Claude Opus 4.6 marker. Member fc1b156d is not a tag ancestor; catalog.ts blob equals its parent; no authorship transfer. Parent already called reloadOnboardingPluginRegistry. Squash adds onlyPluginIds scoped snapshots. Closer ignores untrusted workspace shadows in catalog setup resolution, not the OOM snapshot. Contained in v2026.4.1 / fixed v2026.4.2. Uniqueness PASS versus canonical88 and versus 82QX.

2. GHSA-5WP8-Q9MX-8JX8 ordinal 126 PASS_PROPOSAL. Identity PASS: reviewed first-party zeptoclaw GHSA, crates.io <= 0.6.1, fixed 0.6.2. Topology PASS by counting squash 1712debb, n_parents=1, Co-authored-by Claude Sonnet 4.6. Member 3c4368da is not an ancestor of the squash, of v0.6.1, or of 68916c3e; do not transfer it. Parent c5bd830c lacks ShellAllowlistMode. Squash authors the allowlist and the empty-strict skip `!self.allowlist.is_empty()`. First-parent pickaxe for that string on v0.6.1 hits the squash. Patch-delta incomplete remediation PASS: v0.6.1 contains that AI allowlist without the closure; GHSA-5WP8 quotes the empty-skip residual in that boundary; closer 68916c3e removes the skip and comments the previous guard. Release PASS: squash in v0.6.1 peel ad14ed8d; fix not in v0.6.1; fix equals v0.6.2 peel f052aa21. Distinct from GHSA-HHJV. Uniqueness PASS versus canonical88.

3. GHSA-R5JH-Q2MW-GCX4 ordinal 133 NARROW but_for_gate. Identity PASS: reviewed first-party fission GHSA aliases CVE-2026-50568. Count squash 5a3d68a34 on its own Claude Opus 4.7 marker. Member 0d851525 is not an ancestor of the squash or of v1.23.0/v1.24.0/v1.25.0; no authorship transfer. Scoped contributor applied to the AI-added Builder.Clean caller without transferring the preexisting HasPrefix helper. Parent already defined SanitizeFilePath and called it from Handler and fetcher. Squash wires that helper onto Clean. Deleting the squash restores unsanitized Clean join and leaves the named helper plus original callers. That is not material shrink of the titled HasPrefix mechanism. Incomplete-rem patch-delta fails: residual is the parent helper; closer 8298e33e migrates every call site to os.Root. Contained in v1.24.0 / fixed v1.25.0.

## Uniqueness

None of the three IDs is in canonical88 strict_released_case_ids (88). None is GHSA-8RW6-P7M8-63JP. CVE aliases are stored and not counted. GHSA-2QRV is not GHSA-82QX. Shared closer SHA of 5WP8 with HHJV is not a uniqueness collision. Replay uniqueness reads only the pinned canonical88 summary plus the pinned 2QRV/82QX advisory objects.

## Claim boundary

Countable PASS requires all seven gates PASS plus leader admission. Proposed PASS: 1 (GHSA-5WP8-Q9MX-8JX8). Publication remains HOLD. Greater-than-200 remains HOLD. This packet does not support a greater-than-200 claim. Canonical88 was not rebuilt. Expansion stopped. Did not pad.
