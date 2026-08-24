# Hostile red-team: GHSA-76PC-MQXP-3RQ5

**PASS_PROPOSAL.** Countable PASS remains 0 until leader admission. Packet delta 0. Canonical91 stays **91 HOLD**.

This is an independent hostile review of the proposal that atomic `051f27474d85d7f3299b56fc61bfcb0666a4e198` is the AI origin of GHSA-76PC dashboard sessionId path traversal through `session-log-${sessionId}.jsonl`. `herdr-260814-fresh-reviewed-delta3-grok46-medium` is routing only and is not evidence. Worker PASS is proposal only. This packet does not admit the row, does not rebuild canonical91, and does not support a greater-than-200 claim.

Conservation: assigned=1, reviewed=1, unreviewed=0. Equation `1=1+0`.

Identity is pinned as an offline normalized first-party advisory projection in cases.jsonl and result.json: exact GHSA id, repository, package ecosystem/name, vulnerable range, patched version, published/withdrawn state, first-party URL, retrieved timestamp, and SHA-256 of the canonical projection. Replay validates those fields without GitHub credentials. Git objects and npm tarballs are re-fetched from public URLs with pinned hashes.

## Mechanism (first-party)

GitHub-reviewed GHSA-76pc-mqxp-3rq5 on ooples/token-optimizer-mcp is published, not withdrawn, and aliases CVE-2026-55156. The repo advisory quotes both `/api/session-summary` and `/api/session-events` concatenating caller `sessionId` into `path.join(hooksDataPath, \`session-log-${sessionId}.jsonl\`)` with no authentication. Global catalog package is npm `@ooples/token-optimizer-mcp`, range `< 5.1.0`, first patched `5.1.0`. Repo advisory names affected version `5.0.1` and leaves `patched_versions` empty. Repo package name `ooples/token-optimizer-mcp` omits the npm scope; the global object has the scoped name. Neither discrepancy withdraws the identity.

The advisory table also writes `commit 8137147`. That short prefix peels to `8137147c028771510271d5b4c7ea44134fbf866b` (`Create SECURITY.md`), which is not tag `v5.0.1`. Tag `v5.0.1` / npm gitHead is `8138f3a6d32eff80387f24d6068039ae8fb7bfa9`. The mistyped short SHA is not a second identity and does not move the named 5.0.1 range.

## Topology and marker-transfer attack

`051f27474d85` is `n_parents=1`, parent `5fe1380e53ee`. Author Franklin Moormann. MATCHER_CONTRACT `coauthor_trailer` / `claude_code` matches `Co-Authored-By: Claude <noreply@anthropic.com>`. The `claude.com/claude-code` footer is not the frozen `claude.ai/code` explicit-attribution line and is not required because the coauthor trailer already matches. Parent tree has no `src/server/web-server.ts` and no `session-log-` / `/api/session-summary` hits.

The commit adds both endpoints and both unsanitized `path.join` sites. All-parent pickaxe `-S 'session-log-${sessionId}.jsonl'` on `v5.0.1` hits only `051f27474d85`.

First-parent pickaxe on `v5.0.1` hits merge `90e3a4b8d271` (`Merge pull request #29`, `n_parents=2`, GitHub committer, MATCHER_CONTRACT empty). Second parent is `9f1cea9a8fcb`, not `051f27474d85`. Merge blob `b2038a0995ae` equals the second parent and is not equal to origin blob `1cdd93c63455`. The merge does not author the hunk versus its second parent. Counting the merge would be authorship transfer. This packet counts the atomic AI member that added the file. `carrier_set` is empty. That is not the squash-carrier failure mode.

Later Claude-marked commits `5d73bfba6244` and `9f1cea9a8fcb` only change returns, BOM handling, and `import.meta` startup. They do not rewrite `session-log-${sessionId}.jsonl`. Human merge `ed4391acdeca` produces the `v5.0.1` blob `d8cf67f68b5b` by reformatting the same interpolation. None of those SHAs are transferred onto `051f27474d85`.

Closer `b4ee96dac799` (`#169`, `n_parents=1`, GitHub squash) carries Claude Opus 4.8 and Claude Fable 5 trailers and names GHSA-76pc plus GHSA-49mq / GHSA-29p3 / GHSA-8w8q. That is AI-on-fix, not origin. Those closer trailers are not transferred onto `051f27474d85`.

## Parent / earlier-release attack

Parent `5fe1380e53ee` has no equivalent endpoint. Removing `051f27474d85` removes both session-log routes.

Earlier version numbers `v2.19.1` through `v5.0.0` (and npm 4.2.0 / 5.0.0 tarballs) contain the same `d8cf67f68b5b` blob as `v5.0.1`. Those tags are dated after 2025-10-17 and are descendants of `051f27474d85`, not ancestors of the parent. Extra descendant containment does not create a pre-existing parent endpoint and does not merge this GHSA with another identity. Repo-named vulnerable npm remains 5.0.1. Global `< 5.1.0` is consistent with those descendants still being unfixed.

## Fix-reversal attack

Fix parent `4ae7c351659b` still has blob `d8cf67f68b5b` (no `isValidSessionId`). Closer `b4ee96dac799` adds `SESSION_ID_RE = /^[A-Za-z0-9_-]{1,64}$/`, exported `isValidSessionId`, and `resolveSessionLogPath` containment, then calls `isValidSessionId` on both named routes. That is the advisory's first remediation (strict allowlist) plus path containment. Missing authentication middleware is additional advisory advice and is not this path-traversal invariant. First-parent pickaxe `-S isValidSessionId` on `v5.1.1` hits only the closer.

Closer blob `3f750e6ce7be` differs from `v5.1.0` / `v5.1.1` blob `40e8be9bbd27` because later `0408bee1a476` (#177) adds SIGINT/SIGTERM shutdown around `app.listen` and does not remove `isValidSessionId`. That later blob delta is not a reversal failure.

## Release

Vulnerable npm `@ooples/token-optimizer-mcp` 5.0.1 tarball sha256 `4594c2d6140c20dd64d85fb5ceee660c8f943ff76f779d610d8554eea7267761` sha1 `5838756a76cda2ae775e9b7d141bfcecef36e811` gitHead `8138f3a6d32eff80387f24d6068039ae8fb7bfa9`. Dist `web-server.js` has `session-log-` and zero `isValidSessionId`. Origin is an ancestor of that gitHead; the closer is not.

npm 5.1.0 returns HTTP 404. Git tag `v5.1.0` peels to `94815a16e3322101694e97561fc1dc8b5af904dc`, is a published non-prerelease GitHub release, contains the closer, and has the fixed `web-server.ts` blob. That tag supports containment and is not a published npm artifact.

Fixed published npm 5.1.1 tarball sha256 `1828e97d1c7dabfb7d6d27ac786b88e1977c5fa95f3da1f12bb1630533e670da` sha1 `0b21bd9dd55c1e95a35a60e732cad6c0ea3d59d4` gitHead `687b55460d752fa4ee011c58535c733191b831c8`. Dist `web-server.js` has `isValidSessionId` and `SESSION_ID_RE`. Closer and origin are ancestors. GitHub release `v5.0.1` `target_commitish` `master` is not used as containment; peel and npm gitHead are.

## Uniqueness / sibling GHSA-49MQ / shared closer

GHSA-76PC is absent from canonical91 strict 91. GHSA-49MQ-FC6Q-3H46 is a distinct first-party reviewed identity (CVE-2026-55157, `smart_user` `getent` interpolation). Shared closer SHA `b4ee96dac799` is not a merge of cases. This packet does not count 49MQ. Closer-named GHSA-29p3-56wx-ggfh and GHSA-8w8q-fgv9-j286 are 404 in both the global catalog and the repo advisory API; they are not this sessionId path-traversal identity.

CVE alias CVE-2026-55156 is stored and is not a counting unit.

## Gates

1. identity_gate: PASS
2. ai_hunk_gate: PASS
3. topology_gate: PASS
4. but_for_gate: PASS
5. fix_reversal_gate: PASS
6. release_gate: PASS
7. uniqueness_gate: PASS

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical91. Publication and more-than-200 stay HOLD.
