# Hostile red-team: GHSA-Q447-RJ3R-2CGH

**PASS_PROPOSAL.** Countable PASS remains 0 until leader admission. Packet delta 0. Canonical90 stays **90 HOLD**.

This is an independent hostile review of the proposal that member `b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517` is the AI origin of the GHSA-q447 Feishu unbounded webhook body. nearclosed-h is routing only and is not evidence. Worker PASS is proposal only. This packet does not admit the row, does not rebuild canonical90, and does not support a greater-than-200 claim.

Conservation: assigned=1, reviewed=1, unreviewed=0. Equation `1=1+0`.

## Mechanism (first-party)

GitHub-reviewed GHSA-q447-rj3r-2cgh on openclaw/openclaw is published, not withdrawn, and aliases CVE-2026-28478. The advisory names unbounded webhook body buffering without unified `maxBytes` + `timeoutMs`, lists SDK-backed handlers that parse bodies internally, and names Feishu among the stream-guard migrations. npm `openclaw` range is introduced `0` / fixed `2026.2.13`. Details prose that says affected `<2026.2.12` is stale against that range and against git/npm bytes; this packet does not treat that line as containment.

This row is scoped only to the new Feishu `Lark.adaptDefault` webhook body path. Sibling channel `req.on("data")` readers are named by the same GHSA and preexist; they are not this origin.

## Topology

Squash `5c2cb6c5` is a single-parent GitHub squash of PR #12662 onto `49c60e90`. Trailer: Co-authored-by Claude Opus 4.6. Parent `monitor.ts` blob `24ba1211` logs `webhook mode not implemented in monitor` and lacks `adaptDefault`. The squash adds `http.createServer()` and `Lark.adaptDefault` with no byte/time guard. First-parent pickaxe for `adaptDefault` on `v2026.2.12` hits only the squash. No later first-parent rewrite of that file exists between the squash and `v2026.2.12`.

Member `b0c67ea0` is Claude Opus 4.6 and authors the same `monitor.ts` blob `31a890c2` on a side branch. It is not an ancestor of the squash, of peel `d8d69ccb`, of npm `2026.2.12` gitHead `f9e444dd`, or of closer `3cbcba10`. Identical blobs do not transfer that member onto the squash. The squash is the first-parent atomic commit that authors the hunk on the released history and carries its own Claude marker. That is not the HHJV carrier-transfer failure, where a human member authored the counted hunk.

## But-for and fix reversal

Parent Feishu webhook HTTP is absent. Removing the squash eliminates the scoped SDK body surface. Pre-existing LINE/Nextcloud/Zalo/gateway body readers remain; they are out of scope. Whole-GHSA product-wide AI origin is not claimed.

Closer `3cbcba10` (unmarked, Peter Steinberger) wraps `Lark.adaptDefault` with `installRequestBodyLimitGuard` (`maxBytes` 1 MiB, `timeoutMs` 30000), adds `src/infra/http-body.ts`, and also migrates sibling handlers. Shared SHA across those sibling files is not a merge of identities. The Feishu hunk reverses the same unbounded-SDK-body invariant. `http-body.ts` is absent from `v2026.2.12` and present on `v2026.2.13`.

## Release

Annotated tag `v2026.2.12` object `ed0a4cb3` peels to `d8d69ccb`. Lightweight tag `v2026.2.13` is `e91d957d`. GitHub releases are published and not prerelease; `target_commitish` `main` is not containment. npm `2026.2.12` tarball sha256 `0adafbff...` gitHead `f9e444dd` (ancestor of the peel) equals git `monitor.ts` blob `31a890c2` and still has unbounded `adaptDefault`. npm `2026.2.13` tarball sha256 `52a6d49b...` gitHead `203b5bdf` (ancestor of peel `e91d957d`) equals git blob `51af5a4a` and has the guard. The squash is an ancestor of the vulnerable tag and npm gitHead. The fix is not.

## Uniqueness

GHSA-Q447 is absent from canonical90 strict 90. Source-layer ordinal 47 remains NARROW and uncounted. Ordinal 124 GHSA-G353 / GHSA-XH72 share member SHA `b0c67ea0` for a different Feishu encryptKey/card-token invariant and are not counted. CVE-2026-28478 is a formal alias, not a second case.

## Gates

1. identity_gate: PASS
2. ai_hunk_gate: PASS
3. topology_gate: PASS
4. but_for_gate: PASS (scoped new surface)
5. fix_reversal_gate: PASS
6. release_gate: PASS
7. uniqueness_gate: PASS

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical90. Publication and more-than-200 stay HOLD.
