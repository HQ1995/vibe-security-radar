# Hostile red-team: GHSA-F63H-WC26-PMVC

**REJECT.** KEEP proposal 0. Packet delta 0. Current leader-accepted count remains 84.

This is an independent hostile review of GHSA-F63H in AstrBotDevs/AstrBot. The proposal packet was used only as a route to the ID. Worker PASS is proposal only. This packet does not admit the row, does not rebuild canonical84, and does not support a greater-than-200 claim.

Conservation: assigned=1, reviewed=1, unreviewed=0.

## Minimal counterexample

The advisory mechanism is `post_file` in `astrbot/dashboard/routes/chat.py`: client `file.filename` is joined onto the attachments directory and saved with no basename or containment check (CWE-22).

Human PR #3845 member `7a669119884041a3a751c7f8c8eb6442e67709c1` has no AI marker and changes

`filename = f"{uuid.uuid4()!s}"`

to

`filename = file.filename or f"{uuid.uuid4()!s}"`.

GitHub squash `f7a716af43f238e75c50251422666539265c4ef3` is the PR merge commit, has no AI trailer, and is the first-parent landing of that hunk. Default and first-parent blame of the filename line at tag `v4.23.5` hit that squash.

Git blame of the deleted join at the fix parent hits squash `a404436f2cddf6b7e49d7e9c60dc240748d0767d` (PR #5280) only because human member `590e7f3e1e6df546e860485ddab79142d31525eb` renamed `self.imgs_dir` to `self.attachments_dir`. Parent `bcb12a071732c694e37a42fcea419ef866b9d127` already has `filename = file.filename or uuid` and `os.path.join(self.imgs_dir, filename)`. The Copilot Autofix trailer on the squash comes from member `ea615cb3858188a265b25b8ffb101e3c10e41149`, which edits `astrbot/dashboard/server.py` hashing and does not touch `chat.py`. All listed members are missing from the first-party clone and are not ancestors of the squash or of tags `v4.23.5` / `v4.23.6`. An AI-marked squash cannot transfer authorship from a hashing Autofix member onto a human directory rename, and cannot transfer authorship from an unmarked filename member on a different PR (canonical84 negative controls GHSA-2MHJ and GHSA-HHJV).

## Hostile checks

1. Post-fix hit: the unsanitized join is absent from `v4.23.6` and from PyPI 4.23.6. `a404436f` remaining an ancestor of the fixed tag is ordinary history, not a surviving hole.
2. Carrier trailer transfer: confirmed. Copilot Autofix is the hashing member, not the join rename.
3. Human blame of the vulnerable lines: confirmed for `file.filename`. Join-line blame is a rename of that inherited hole.
4. Inherited old bug: confirmed versus parent `bcb12a07`.
5. Remediation-as-origin: not this class. `a404436f` does not add a post_file path-traversal guard. `get_file` already used `os.path.basename`.
6. Incomplete fix on a different boundary: `900f14d37` / `get_file` basename+realpath is a read path. GHSA-F63H names the upload `filename` argument.
7. Wrong advisory/fix: official closer `aaec41e5054569ceaa1113593a34da7568e2d211` (PR #7751) adds `_sanitize_upload_filename` and `Path.is_relative_to` on the same join. Human members `8145ba639341` and `1fc1942b1c0d`. Not AI origin.
8. Sibling mechanism: GHSA-XRJ9 is `plugin/install-upload`. Shared repository does not merge cases.
9. Release blob mismatch: tag `v4.23.6` chat.py blob is not byte-identical to `aaec41e` because later `f0a1dd79c` (#7772) also touches the file. The sanitizer and `post_file` extract are identical. PyPI 4.23.5 / 4.23.6 wheels match the git tag files. That mismatch does not void containment and does not save origin.

## Gates

1. `identity_gate`: PASS. GitHub-reviewed GHSA-f63h-wc26-pmvc, type reviewed, `withdrawn_at` null, alias CVE-2026-8754. No repo advisory object (HTTP 404, `repository_advisory_url` null). PyPI AstrBot, last affected `< 4.23.6`, patched 4.23.6.
2. `ai_hunk_gate`: FAIL. No AI-authored atomic hunk for the advisory mechanism. The Copilot-marked member does not edit `post_file`. The filename origin is unmarked human.
3. `topology_gate`: FAIL. `a404436f` is a single-parent GitHub squash of PR #5280. Members are absent from the first-party clone. Counting the squash Copilot trailer as origin of the join is carrier transfer.
4. `but_for_gate`: FAIL. Removing the AI-marked member or rolling the squash back to `imgs_dir` leaves client `file.filename` on an unsanitized join. The hole predates `a404436f`.
5. `fix_reversal_gate`: PASS as a mechanism check, not a save. `aaec41e` reverses the same `post_file` filename join.
6. `release_gate`: PASS as artifact containment, not a save. Lightweight tag `v4.23.5` equals the fix parent and contains the unsanitized join. Tag `v4.23.6` contains the sanitizer. GitHub releases are published, not draft, not prerelease. PyPI 4.23.5 / 4.23.6 are not yanked; wheel `chat.py` equals the matching git tag.
7. `uniqueness_gate`: PASS, not a save. Absent from canonical84 strict 84. Distinct from GHSA-XRJ9 and from the earlier `get_file` guard. Shared SHA or repository does not merge cases.

`remediation_patch_delta_gate` is NOT_APPLICABLE.

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical84. Publication and more-than-200 stay HOLD.
