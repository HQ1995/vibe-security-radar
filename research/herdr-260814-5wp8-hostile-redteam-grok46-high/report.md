# Hostile red-team: GHSA-5WP8-Q9MX-8JX8

**PASS_PROPOSAL.** Countable PASS remains 0 until leader admission. Packet delta 0. Canonical88 stays **88 HOLD**.

This is an independent hostile review of the proposal that squash `1712debbea60af6adf4a8a5939a43f7ef9a1ac16` is the AI origin of the GHSA-5WP8 empty-strict allowlist skip. nearclosed-e is routing only and is not evidence. Worker PASS is proposal only. This packet does not admit the row, does not rebuild canonical88, and does not support a greater-than-200 claim.

Conservation: assigned=1, reviewed=1, unreviewed=0. Equation `1=1+0`.

## Mechanism (first-party)

GitHub-reviewed GHSA-5wp8-q9mx-8jx8 on qhkm/zeptoclaw is published, not withdrawn, and has no CVE alias. crates.io zeptoclaw last known affected `<= 0.6.1`, patched 0.6.2. The advisory quotes `src/security/shell.rs` at `fe2ef07c` (tag `v0.5.8`, same `shell.rs` blob as `v0.6.1`) including:

`if self.allowlist_mode != ShellAllowlistMode::Off && !self.allowlist.is_empty()`

and states that in Strict mode an empty allowlist should reject all commands. Sibling vectors (first-token injection, regex argument injection, literal glob) are named. This row is scoped only to the empty-strict skip inside the AI-added allowlist.

## Topology

Squash `1712debb` is a single-parent GitHub squash of PR #104 onto `c5bd830c`. Trailer: Co-authored-by Claude Sonnet 4.6. Parent `shell.rs` has `validate_command` and the older blocklist and lacks `ShellAllowlistMode`. The squash adds the allowlist enum, the first-token check, and the empty-skip. First-parent pickaxe for `allowlist.is_empty` on `v0.6.1` hits only the squash.

Member `3c4368da` is Claude Sonnet 4.6 and authors the same skip on a side branch. It is not an ancestor of the squash, of `v0.6.1`, or of closer `68916c3e`. Blobs are unequal (member `a09e6171`, squash `165b10b5`, `v0.6.1` `87b9d900`). This packet does not transfer that member onto the squash. The squash is the first-parent atomic commit that authors the hunk on the released history and carries its own Claude marker. That is not the HHJV carrier-transfer failure, where a human member authored the counted hunk.

Blocklist member `91f6c2bf` (Claude Opus 4.5) is a first-parent ancestor of the squash and of `v0.6.1`. It has no allowlist. Human member `5059bea` adds BubblewrapRuntime with no AI marker. Neither is this empty-allowlist origin.

Later `df8159e` (Claude Opus 4.6) adds `.zeptoclaw/config.json` literal blocklist lines between the squash and `v0.6.1`. Pickaxe shows it does not introduce or remove `allowlist.is_empty`. The skip remains.

## Patch-delta incomplete remediation

The squash is an explicit security attempt that introduces an allowlist boundary. crates.io 0.6.1 checksum `6df2cb16...` is not yanked; its `shell.rs` equals git `v0.6.1` and contains the skip. GitHub release `v0.6.1` is published and not prerelease; peel `ad14ed8d`. Reverting the squash removes that AI allowlist residual and leaves the older `91f6c2bf` blocklist in place. That is the patch-delta test. It does not require eliminating the broader pre-allowlist blocklist holes, and it does not transfer blocklist authorship.

Closer `68916c3e` (#248) is an ancestor of `v0.6.2` peel `f052aa21` and not of `v0.6.1`. It changes the guard to `if self.allowlist_mode != ShellAllowlistMode::Off`, comments that the previous `!self.allowlist.is_empty()` skip made empty allowlist equivalent to Off, and adds an empty-Strict test. crates.io 0.6.2 checksum `1b834e0d...` is not yanked; archive `shell.rs` equals the git fix blob `d923a585`. The same commit also patches GHSA-HHJV Android `device_shell` and sibling 5WP8 blocklist vectors. Shared SHA does not merge identities. AI-on-fix (Claude Code / Opus 4.6) is not origin.

## Uniqueness

GHSA-5WP8 is absent from canonical88 strict 88. Counted GHSA-46Q5 is a different zeptoclaw webhook mechanism. GHSA-HHJV is a canonical88 negative-control REJECT (human Android `device_shell`). GHSA-J8Q9 is a different SSRF identity. Other 5WP8 worker rows that listed `3c4368da` / `91f6c2bf` as candidates were NARROW and not counted. This packet counts the GHSA once, at squash scope.

## Gates

1. identity_gate: PASS
2. ai_hunk_gate: PASS
3. topology_gate: PASS
4. but_for_gate: PASS (patch-delta)
5. fix_reversal_gate: PASS
6. release_gate: PASS
7. uniqueness_gate: PASS

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical88. Publication and more-than-200 stay HOLD.
