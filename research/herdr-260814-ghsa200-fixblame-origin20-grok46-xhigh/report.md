# Fix-blame origin20: GHSA-HHJV is a PASS proposal; the other 13 fail

Verdict first: 1 PASS proposal (GHSA-HHJV-JQ77-CMVX), 13 REJECT. Assigned 14, reviewed 14, unreviewed 0. Conservation 14=14+0. Worker PASS is proposal only. Start count is not rebuilt. Current leader-accepted count 82 (canonical82, commit 6800d212, ledger hash 58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23). Packet delta 0. Publication and greater-than-200 stay HOLD. This packet does not rebuild canonical82.

## Method

This is not another direct-root rank-queue pass. Direct-root rank-hits are exhausted after batch28. This worker:

1. Built a terminal-ID exclusion set from canonical82 (strict 82 plus ledger identities) and every completed directroot, incomplete-remediation, nearpass, contributor, and redteam packet under herdr-260813-ghsa200-* and herdr-260814-ghsa200-* (61 completed packets, 1294 excluded IDs).
2. Scanned github-reviewed first-party 2025-05-01+ advisories with exact same-repo commit refs.
3. Blamed deleted/changed source lines at the fix parent with `git blame -l -w -M -C` (rename following). File-history without hunk identity is not a hit.
4. Required a live AI marker on the blamed earlier commit.
5. Froze every qualifying identity, sorted by GHSA ID, cap 20, without padding. 14 qualified.

Scan pool 3431 after exclusion. Hits 14. Unreviewed hits 0.

## PASS proposal

### GHSA-HHJV-JQ77-CMVX (qhkm/zeptoclaw)

All seven gates PASS at origin scope. Worker PASS is a proposal; leader plus independent hostile red-team must accept before the count moves.

- Identity: github-reviewed GHSA-hhjv-jq77-cmvx, not withdrawn. First-party repo advisory published. crates.io zeptoclaw, range <= 0.6.1, patched 0.6.2.
- AI hunk: 8f1c1db4 single-parent Co-authored-by Claude Opus 4.6. First-parent creates src/tools/android/actions.rs. Parent 5dad36b9 has no android paths. device_shell uses literal `rm -rf` / `rm -r` substring contains.
- Topology: atomic first-parent squash #93. No carrier/member transfer. Later 68916c3e is the closer, not origin.
- But-for: removing the AI android module eliminates device_shell. The GHSA path does not exist without that file.
- Fix reversal: 68916c3e replaces the literal array with `rm_invocation_args` / `is_rm_recursive_force` on the same function. Bundled PR #248 also patches GHSA-5WP8 host shell; that is a different identity and a different mechanism.
- Release: crates.io 0.6.1 not yanked, git tag v0.6.1 = ad14ed8d4e6f982af272523f4accc107b191fb18 contains the AI commit and not the fix, GitHub release v0.6.1 published and not prerelease. crates.io 0.6.2 not yanked, peeled annotated tag v0.6.2 = f052aa21f298559729aa19b770da988f00a193df contains the fix, GitHub release v0.6.2 published.
- Uniqueness: not in canonical82 strict 82. Distinct from counted GHSA-46Q5 and from non-counted GHSA-5WP8. Shared closer SHA does not merge cases.

## REJECT (13)

| ID | Class | Why |
| --- | --- | --- |
| GHSA-39MP-545Q-W789 | sibling | Typing indicator vs /send policy |
| GHSA-5XRQ-8626-4RWP | sibling | importDurations UI vs UI file-read |
| GHSA-64QX-VPXX-MVQF | old bug | Topic filenames; sessionFile passthrough already on the AI parent |
| GHSA-77V3-R3JW-J2V2 | license/copy | Copilot license headers; getSecretKey pickaxe is not that commit |
| GHSA-8883-9W57-VWV6 | sibling | Twitch allowlist vs Mattermost callbacks |
| GHSA-9GH8-9R95-3FC3 | sibling | iOS .app glob vs .a zip-slip |
| GHSA-CCC3-FVFX-MW3V | sibling | iOS .app glob vs /download traversal |
| GHSA-FP25-P6MJ-QQG6 | old bug | injectweb p-map vs call_user_func_array |
| GHSA-M2CQ-XJGM-F668 | refactor | ESM imports vs missing bank-sync auth |
| GHSA-MP66-RF4F-MHH8 | sibling | Twitch allowlist vs Google Chat principals |
| GHSA-PG2V-8XWH-QHCC | sibling | SSE timeouts vs Tlon SSRF |
| GHSA-QMJJ-P7M9-WJRV | sibling | Delete-file ACL vs /sync ownership |
| GHSA-XHQ5-45PM-2GJR | sibling | Twitch allowlist vs Nextcloud room tokens |

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 82. Only leader-reviewed rows with all seven gates PASS enter that bound after independent hostile red-team. This packet does not rebuild canonical82 and does not support a greater-than-200 claim.
