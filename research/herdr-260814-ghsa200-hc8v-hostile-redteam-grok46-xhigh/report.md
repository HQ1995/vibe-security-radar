# Hostile red-team: GHSA-HC8V-WWC9-VGXM

KEEP proposal 1. Packet delta 0. Current leader-accepted count remains 82.

This is an independent hostile review of the residual-security20 proposal that GHSA-HC8V is AI incomplete remediation in go-git at candidate `d83871ed`, parent `c6d8721a`, fix `008a78f2`, GitHub v5.19.1 / v5.19.2. Worker KEEP is proposal only. This packet does not admit the row, does not rebuild canonical82, and does not support a greater-than-200 claim.

Conservation: assigned=1, reviewed=1, unreviewed=0.

## Hostile questions

The residual packet already recorded "Backport of #2081" and still passed authorship on the v5 commit. This review reconstructed PR members, the original #2081 history, parent validPath, rollback, the closer, and public tags/tarballs without trusting `releases/v5.x`.

1. Is `d83871ed` a carrier or copy of human #2081 code? No. PR #2081 first member `a0e19691` has `Assisted-by: Claude Opus 4.6 <noreply@anthropic.com>` and creates `worktree_fs.go`. It is not an unmarked human member. `d83871ed` is PR #2100's first member, has the same Claude trailer, and creates the v5 file. The two `worktree_fs.go` blobs differ only by billy v5 versus v6 and `os.FileMode` versus `fs.FileMode`. `a0e19691` is not an ancestor of `d83871ed` or of tag v5.19.1. `d83871ed` is an any-parent ancestor of v5.19.1 and is absent from `git rev-list --first-parent 3c3be601`. PR #2100 merge `b1fab6cb` is a two-parent merge, not a squash, and is on that first-parent chain. `carrier_set=[b1fab6cb]`. That records the merge onto the release line; it is not authorship transfer.

2. Does parent `c6d8721a` already have an equivalent wrapper? No. Parent has no `worktree_fs.go` and no `worktreeFilesystem`. It has package-level `validPath` used on checkout From/To path strings only. `Worktree()` returns `Filesystem: r.wt`. The candidate wraps that field with `newWorktreeFilesystem(r.wt)` and calls `validPath` on mutating filesystem ops.

3. Does removing the candidate eliminate the exact wrapper residual, or only restore a broader old symlink hole? Both. Reverting `d83871ed` deletes the wrapper, so the GHSA-named residual (string-safe path follows an existing symlink through `worktreeFilesystem`) is gone. Checkout-only `validPath` remains and still follows symlinks. `AI_INCOMPLETE_REMEDIATION` allows reopening that older hole. The candidate is itself a security attempt at the same write-path boundary, so the patch-delta rule applies.

4. Does `008a78f2` amend that same wrapper and block leading symlink traversal? Yes. Create/OpenFile/Remove/Rename/Symlink/MkdirAll change from `validPath` / `sfs.validPath` to `sfs.validWritePath`. `validWritePath` is `validPath` plus `validNoLeadingSymlink`, which Lstats each leading directory component and rejects `ModeSymlink` with `leading component %q is a symlink`. `TestWorktreeFilesystemRejectsSymlinkTraversal` requires operations on `s/<name>` to fail with `is a symlink` while `validPath` alone would allow the innocent string. That is the GHSA example (`s` -> `.git`, write `s/config`).

5. Do public GitHub tag/release/source tarball v5.19.1 and v5.19.2 contain attempt versus fix? Yes, independently of the moving branch. GitHub git ref `v5.19.1` is lightweight commit `3c3be601`. GitHub git ref `v5.19.2` is lightweight commit `3eeb238d`. Releases are published, not draft, not prerelease, immutable. `target_commitish` is `releases/v5.x`. Local `origin/releases/v5.x` is `2263fb5f`, contains the candidate, and does not contain the fix. Compare API: candidate is merge-base of v5.19.1 (ahead 30, behind 0); fix is merge-base of v5.19.2 (ahead 5, behind 0). Source tarball `archive/refs/tags/v5.19.1.tar.gz` sha256 `91b44587...` has `worktreeFilesystem` Create via `sfs.validPath` and no `validNoLeadingSymlink`. Source tarball `v5.19.2.tar.gz` sha256 `6c4524af...` `worktree_fs.go` sha256 `11d7a155...` equals `git show 008a78f2:worktree_fs.go`.

6. Identity and uniqueness versus GHSA-3R9X and GHSA-CMW6? GHSA-hc8v-wwc9-vgxm is github-reviewed, not withdrawn, aliases CVE-2026-71556, repo go-git/go-git, Go module `github.com/go-git/go-git/v5`, last known affected `<= 5.19.1`, fixed 5.19.2. GHSA-3R9X is onnx PyPI symlink path traversal. GHSA-CMW6 is onnx PyPI hardlink bypass. Different repositories and mechanism fingerprints. None of the three are in canonical82 strict 82. v5 and v6 ranges are one first-party GHSA case.

## Gates

1. `identity_gate`: PASS. Frozen github-reviewed GHSA-hc8v-wwc9-vgxm at advisory-database `a42c4368`. Repo advisory state published, `withdrawn_at` null. Mechanism named in the GHSA details is the incomplete `worktreeFilesystem` string check.

2. `ai_hunk_gate`: PASS. Atomic `d83871ed` with explicit Claude Opus 4.6 Assisted-by authors the wrapper hunk. Not a later AI review. Not a squash inheriting a trailer from a member that did not touch the hunk.

3. `topology_gate`: PASS. Single-parent onto `c6d8721a`. Any-parent ancestor of closer and of peeled v5.19.1; not on `git rev-list --first-parent 3c3be601`. PR #2100 merge `b1fab6cb` is the first-parent carrier onto the release line (`candidate_on_release_first_parent=false`, `carrier_on_release_first_parent=true`, `candidate_any_parent=true`). This is not authorship transfer. Closer is not in v5.19.1. Import from AI `a0e19691` is a parallel v6 commit, not a human member whose authorship is transferred onto an unmarked carrier.

4. `but_for_gate`: PASS under the incomplete-remediation patch-delta rule, not under origin rollback. See question 3.

5. `fix_reversal_gate`: PASS. Official closer `008a78f2` (PR #2277 only commit; merge/tag `3eeb238d`) amends the same wrapper. Claude Opus 4.8 on the closer is not origin.

6. `release_gate`: PASS on GitHub tags, published releases, and source tarballs. Moving branch `releases/v5.x` is not used as containment.

7. `uniqueness_gate`: PASS. Absent from canonical82. Distinct from GHSA-3R9X and GHSA-CMW6.

`remediation_patch_delta_gate`: PASS. All five incomplete-remediation bullets hold: explicit AI security boundary, released attempt without closure, GHSA residual in that boundary, closer amends the omitted case, not a sibling hole.

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical82. Publication and more-than-200 stay HOLD.
