# Hostile red-team: GHSA-V52W-28XH-V562

**KEEP proposal.** Packet delta 0. Canonical85 remains 85. L0 canonical84 remains 84 HOLD.

Independent review of kozou-dev/kozou, scoped to first-party GHSA issues 1 and 2 on the MCP Streamable HTTP server. The G-N worker row was treated as a claim to attack, not as evidence. Worker KEEP is proposal only. This packet does not admit the row and does not support a greater-than-200 claim. Leader may admit after independently replaying this packet.

Conservation: assigned=1, reviewed=1, unreviewed=0.

## Minimal positive case

GitHub-reviewed GHSA-v52w-28xh-v562 (not withdrawn, no CVE alias) names four bundled holes. Counted scope is only:

1. Unauthenticated MCP Streamable HTTP without Host/Origin validation (DNS rebinding).
2. Unbounded MCP request-body buffering.

Issues 3 (READ ONLY GET transactions) and 4 (compose/all-interface bind) have other origins and are not attributed to AI.

Candidate `4f86724bd112b07e68033098562c1c4ddc37d93b` is `refs/pull/20/head`. Single parent `c84c70c7088f`. Parent has `startStdioServer.ts` and no `startHttpServer.ts`. The commit adds `packages/mcp/src/startHttpServer.ts` blob `1c4a96662fa37741472954bae28a834156802ded`: default bind `127.0.0.1`, no Host/Origin allowlist, `readJsonBody` concatenates every chunk with no cap. Message: Codex 5th-pass N2 for that factory. Trailer Claude Opus 4.7. Pull/20 HTML is 1 commit.

Main-line carrier `bc9dc69d62aaa567a2ccefee12d28a58b96d96c4` is the GitHub squash "Add: MCP Streamable HTTP transport (#11) (#20)". Same parent, same tree, same blob, same Claude trailer. Candidate is not on main; the squash is an ancestor of the fix and of v1.8.0.

Fix `7c3ae2e3b7c996571acc07c96222b6dc2de01a3e` (#163) adds hostname Host/Origin allowlist and `maxBodyBytes` streaming cap on `startHttpServer.ts` (fix blob `91cc618dbf3ccc448f13deb0e72e0f48b7616898`). Extra compose/dev hunks in that commit map to issue 4 and are out of counted scope.

Git tag `v1.8.0` = `e631527918dc2e90c3f324d64af6cf75db8f8aa2` contains later blob `9643e54351d621ce8af90ef5b8f8365d6b9cd643` still without allowedHosts/maxBodyBytes. Git tag `v1.8.1` = `17f3207e24ca0e7858d6836824539bfb0628415b` matches the fix blob. npm `@kozou/mcp` 1.8.0 tarball sha256 `bf19ad97d101a2a08327811c9b91aee9c38eb3d48be633a2d1511e79e52d6ff2` dist JS has unbounded `for await` and no allowedHosts. 1.8.1 tarball sha256 `d785844b2c97d7c274a5fc5b08523daaab9338fd181b251b6d818a27f51b7eb8` has both guards. GitHub releases v1.8.0 and v1.8.1 exist.

## Hostile checks

1. Peel PR #11 / member refs: `refs/pull/11/head` is `088497087274c822a64be1cdf7598eb0f511657f`, a tmp override. It does not add the HTTP server. The `(#11)` token in the candidate subject is not pull/11. Attack fails.

2. Generic AI squash transferring a human member: PR #20 is one commit. That member already carries the Claude trailer and the new-file hunk. Squash tree equals member tree. No unmarked member exists to transfer from. Attack fails.

3. Parent already had the HTTP surface: parent blob for `startHttpServer.ts` is absent. Attack fails.

4. Candidate did not introduce issues 1/2: the new file is unauthenticated HTTP without Host/Origin and with unbounded body read. REST unbounded body is a sibling (`07368b7`, #164) and is excluded from this scope. Attack fails for the scoped MCP pair.

5. Fix does not reverse both MCP mechanisms / is not minimum: #163 inserts both MCP guards on the same file. REST cap is a later sibling commit, not a missing MCP reversal. Compose edits are issue 4. Attack fails at scoped issue 1/2.

6. Releases: v1.8.0 contains the unguarded MCP file and not the fix. v1.8.1 git blob equals the fix. npm 1.8.0/1.8.1 JS agrees. Attack fails.

7. Bundled advisory falsely attributing 3/4: issue 3 is #161 (`41f68fe`); issue 4 is compose/bind files. Scope statement excludes them. Attack fails.

8. Uniqueness: GHSA-V52W is absent from canonical84, canonical85, and foundation.jsonl. No alias class. Attack fails.

## Gates

1. `identity_gate`: PASS. GitHub-reviewed first-party GHSA-v52w-28xh-v562, `withdrawn_at` null, repo kozou-dev/kozou, npm `kozou` / `@kozou/mcp` last affected 1.8.0, fixed 1.8.1.

2. `ai_hunk_gate`: PASS. Atomic single-commit PR #20 member with explicit Claude trailer authors the new `startHttpServer.ts` hunk.

3. `topology_gate`: PASS. Member peeled. Carrier squash recorded. No member-to-carrier authorship transfer. Candidate is not required to sit on first-parent main when the carrier tree matches.

4. `but_for_gate`: PASS. Removing the added HTTP server removes issues 1 and 2 on MCP. Parent had only stdio.

5. `fix_reversal_gate`: PASS. 7c3ae2e reverses Host/Origin absence and unbounded MCP body read.

6. `release_gate`: PASS. git+npm v1.8.0 unguarded; git+npm v1.8.1 guarded.

7. `uniqueness_gate`: PASS. Not in canonical85/foundation/canonical84.

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical85. Publication and more-than-200 stay HOLD. Leader may admit GHSA-V52W after an independent leader replay. This review itself does not admit the row.
