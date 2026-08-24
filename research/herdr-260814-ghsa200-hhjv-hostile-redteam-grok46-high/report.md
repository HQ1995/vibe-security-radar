# Hostile red-team: GHSA-HHJV-JQ77-CMVX

**REJECT.** KEEP proposal 0. Packet delta 0. Current leader-accepted count remains 82.

This is an independent hostile review of the origin20 proposal that GHSA-HHJV is an AI-origin Android `device_shell` argument-permutation case at squash `8f1c1db4`, parent `5dad36b9`, fix `68916c3e`, crates.io 0.6.1/0.6.2. Worker PASS is proposal only. This packet does not admit the row, does not rebuild canonical82, and does not support a greater-than-200 claim.

Conservation: assigned=1, reviewed=1, unreviewed=0.

## Minimal counterexample

PR #93 human member `92396b576d1ec8a39600ad510930d3e1a21484e7` has no AI marker and first-parent-introduces `src/tools/android/actions.rs` `device_shell` with the GHSA literal array `"rm -rf"` / `"rm -r"` plus `lower.contains`. Claude-marked member `e7c1a68d5e7cd99ba0edc32f7d376f00246b6c76` edits clipboard and `open_url` in that file and does not touch the rm blocklist. The `device_shell` function on the human member is byte-identical to squash `8f1c1db4`, tag `v0.6.1`, and crates.io 0.6.1. Both members are not ancestors of `v0.6.1`. Blame at the fix parent hits the squash carrier because GitHub squash #93 is a new single-parent commit. An AI-marked squash cannot transfer authorship to a human member (canonical82 negative control GHSA-2MHJ).

## Gates

1. `identity_gate`: PASS. GitHub-reviewed GHSA-hhjv-jq77-cmvx, not withdrawn, no CVE alias. Repo advisory published on qhkm/zeptoclaw. crates.io zeptoclaw, last known affected `<= 0.6.1`, patched 0.6.2.

2. `ai_hunk_gate`: FAIL. The GHSA hunk is the human member's `device_shell` literal substring blocklist. The squash Claude Opus 4.6 trailer is inherited from the later hardening member, which does not author that hunk.

3. `topology_gate`: FAIL. `8f1c1db4` is a single-parent squash of PR #93 onto `5dad36b9`. Members `92396b57` and `e7c1a68d` are not ancestors of the squash or of tags `v0.6.1` / `v0.6.2`. Counting the squash as AI origin of `device_shell` is carrier transfer.

4. `but_for_gate`: FAIL. Removing the AI-marked member leaves the human `device_shell` path intact on the PR branch. The AI delta is clipboard / URL-scheme work, not rm argument permutation.

5. `fix_reversal_gate`: PASS as a mechanism check, not a save. Official closer `68916c3e` (#248) rewrites the same `device_shell` function with `rm_invocation_args` / `is_rm_recursive_force` and drops the literal `"rm -rf"` entry. That reverses the human-authored hole.

6. `release_gate`: PASS as artifact containment, not a save. Tag `v0.6.1` = `ad14ed8d` contains the candidate blob `c1b86011` and not the fix. Tag `v0.6.2` peel `f052aa21` contains fix blob `e544f53b`. crates.io 0.6.1 checksum `6df2cb16...` is not yanked; the crate archive `actions.rs` equals the git `v0.6.1` function (literal `"rm -rf"`, no `rm_invocation_args`). crates.io 0.6.2 checksum `1b834e0d...` is not yanked; the archive equals the git fix function. GitHub releases v0.6.1 and v0.6.2 are published and not prerelease. First crates.io archive with the hunk is 0.5.1; 0.6.1 remains a valid vulnerable containment point.

7. `uniqueness_gate`: PASS, not a save. GHSA-HHJV is absent from canonical82 strict 82. Distinct from counted GHSA-46Q5 (webhook sender chat-id) and from non-counted GHSA-5WP8 (host `src/security/shell.rs` allowlist/blocklist injection). Shared closer `68916c3e` also patches GHSA-5WP8 and mentions GHSA-J8Q9 (already-fixed SSRF). Shared SHA does not merge cases. Parent `5dad36b9` has host shell, not Android `device_shell`.

Feature gating does not void the range: `default = []` and `android` is optional, but both crate archives still ship `src/tools/android/actions.rs`. The advisory PoC requires the Android tool. Identity stays PASS.

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical82. Publication and more-than-200 stay HOLD.
