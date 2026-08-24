# Hostile red-team: GHSA-FRVJ-C5QP-XJ4W

**KEEP proposal.** Packet delta 0. Current leader-accepted count is **85**. Prospective count if admitted is **86**.

This is an independent hostile review of GHSA-FRVJ in open-webui/open-webui. `herdr-260814-fresh-strict-grok46-xhigh/cases.jsonl` was used only as a claim to attack. Worker PASS is proposal only and was not inherited. This packet does not admit the row, does not rebuild canonical85, and does not support a greater-than-200 claim. Leader may admit after independently replaying this packet. Uniqueness is against canonical85 only.

Conservation: assigned=1, reviewed=1, unreviewed=0.

## Minimal positive case

First-party repo advisory GHSA-frvj-c5qp-xj4w (CVE-2026-59221) names `_sanitize_proxy_path()` in `backend/open_webui/routers/terminals.py`. It states the GHSA-r2wg-2mcr-66rv fix is incomplete in v0.9.6 because the documented decode-until-stable loop stops after 8 `unquote()` passes. A 9x percent-encoded `../` path remains once-encoded, passes `posixpath.normpath()` and `cleaned.startswith('..')`, and is forwarded to the terminal server, which then decodes the traversal.

Git candidate `03547759179672d216d2e1376dd1ae4fdad76a94` is a single-parent GitHub squash of PR #25157. Author Classic298, committer GitHub. Explicit trailer `Co-authored-by: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`. The entire first-parent diff is one file and one hunk: replace `decoded = unquote(path)` with a `range(8)` loop. Blame of those loop lines is the candidate.

Parent `d4030a8aa5d48c2a1cb06c461566844aca2530ab` already had the single-unquote sanitizer. Behavioral replay of the GHSA encoding helper:

- 1x `../admin/system`: parent/candidate/fix all reject.
- 2x: parent accepts still-encoded traversal; candidate and fix reject.
- 8x: parent accepts; candidate and fix reject.
- 9x (285 bytes): parent accepts; candidate accepts `%2E%2E%2F...`; fix returns None.
- 10x: parent and candidate accept; fix returns None.

That is an explicit AI security rewrite that closed the 2x-8x encodings and left a residual inside the new cap. It is not pure old-bug preservation of the parent single-decode hole.

Closer `05098d25a58d03738e01c4e85e8852c3b4ad849c` (PR #26050) inserts `if unquote(decoded) != decoded: return None` immediately after the same `range(8)` loop. Blame of that fail-closed is the closer. The same commit also fail-closes `models.py` `_safe_static_redirect_path` (cap 2). GHSA-FRVJ does not name that sibling. Candidate 0354775917 does not touch models.py. Counted reversal is the terminals.py hunk.

PyPI `open-webui` 0.9.6 wheel sha256 `ce5fdd1b8acf2b823c87417242dea4e6686d6130a98e766954ec6f04e5e146ed` is not yanked. Its `_sanitize_proxy_path` equals git 0354775917 (range(8), no fail-closed). PyPI 0.10.0 wheel sha256 `4bd16d93dc86e955939bb1b40409a7013108708bf4cba61871e0ff5112802460` is not yanked. Its function equals git 05098d25 (range(8) plus fail-closed). GitHub releases v0.9.6 and v0.10.0 are published, not draft, not prerelease. v0.9.6 notes name PR #25157. v0.10.0 notes name PR #26050. The local clone has no those tags; wheels are the peeled artifacts.

## Hostile checks

1. Parent already vulnerable / AI merely reduced risk: parent accepts 2x encoding (GHSA-R2WG vector 2). Candidate rejects 2x-8x and leaves 9x. First-party GHSA names the 9x residual of that cap. Incomplete rem is allowed. Pure old-bug preservation is not this row.

2. Eight-pass cap unrelated to later GHSA: first-party GHSA quotes the `for _ in range(8)` loop and the 9x payload. Attack fails.

3. AI trailer on an aggregate carrier: squash is single-parent, single-file, 9-line sanitizer rewrite. Trailer is on that commit. PR members are absent from the clone, so this review does not transfer authorship from a missing member. Attack fails.

4. 0.9.6 may not contain candidate bytes: function-level equality holds between the 0.9.6 wheel and git 0354775917. Attack fails.

5. 0.10.0 may not contain exact reversal: function-level equality holds between the 0.10.0 wheel and git 05098d25 fail-closed. Attack fails.

6. GHSA duplicates GHSA-R2WG: different GHSA, different CVE, different ecosystem range (R2WG fixed 0.9.6; FRVJ introduced 0.9.6). R2WG is not in canonical85. Shared repository and shared function do not merge cases when the counted residual is the later cap bypass.

7. models.py sibling invalidates minimum-fix scope: extra fail-closed is a different function and a different cap. GHSA identity is terminals 9x. Attack fails.

## Gates

1. `identity_gate`: PASS. GitHub-reviewed GHSA-frvj-c5qp-xj4w, alias CVE-2026-59221, `withdrawn_at` null. First-party repo advisory exists and names the 8-pass residual. PyPI open-webui introduced 0.9.6, fixed 0.10.0.

2. `ai_hunk_gate`: PASS. Atomic single-parent commit with an explicit Claude trailer authors the range(8) hunk. Blame agrees.

3. `topology_gate`: PASS. Parent is first-parent. Candidate is an ancestor of the closer. No member-to-carrier transfer. Closer is also Claude-marked and is not treated as origin.

4. `but_for_gate` / `remediation_patch_delta_gate`: PASS. AI rewrite of the guard; released 0.9.6 ships the incomplete cap; GHSA names the omitted 9x case; closer amends that loop. Residual is inside the AI-added cap.

5. `fix_reversal_gate`: PASS. 05098d25 fail-closes the same loop. models.py extra hunk is out of scope, not a failed reversal.

6. `release_gate`: PASS. PyPI 0.9.6 contains the attempt without fail-closed. PyPI 0.10.0 contains the fail-closed reversal. Wheels are not yanked. GitHub releases are published.

7. `uniqueness_gate`: PASS. Absent from all 85 counted canonical85 IDs (ledger SHA 2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568). Distinct from uncounted GHSA-R2WG. Canonical84 is not the uniqueness source.

## Durable packet

Raw PyPI wheels, advisory page copies, and replay logs are not stored in this directory. `replay.zsh` creates an `mktemp` directory, fetches the two recorded public wheels and first-party advisory inputs, verifies the recorded SHA256 values, extracts only `_sanitize_proxy_path`, then deletes the temp directory on EXIT. Retained files are ASCII. Verdict is unchanged: KEEP proposal, packet delta 0, current leader-accepted count 85, prospective count 86. Canonical85 is not rebuilt by this packet. Exact retained size after cleanup: 105337 bytes (du 196K), 28 files.

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical85. Publication and more-than-200 stay HOLD. Leader may admit GHSA-FRVJ after an independent leader replay of this packet. This review itself does not admit the row. If admitted, the prospective strict count is 86.
