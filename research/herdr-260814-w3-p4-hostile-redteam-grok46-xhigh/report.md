# Hostile red-team: canvas wave2 adjudication-4 (14 rows)

**KEEP 0. REJECT 3. UNKNOWN 11.** Packet delta 0. Current leader-accepted count remains 84.

Independent hostile review of every row in `autoresearch/orchestrator-260814-ghsa200-canvas/wave2/adjudication-4.jsonl`. Concurrent g46h P4 output was not read. Stored `best.parent` values were not trusted. KEEP requires all seven gates PASS at HIGH confidence. None did.

Unclosed gates stay UNKNOWN. Missing release or fix-reversal peel is not converted to FAIL or PASS. A row with any UNKNOWN gate is not closed.

Conservation: assigned=14, reviewed=14, unreviewed=0.

Worker PASS remains proposal only. This packet does not admit a row, does not edit canonical84, and does not support a greater-than-200 claim.

Routing-signal trap: for every kind-1 row, `best.parent` is the parent of the listed fix, not the first parent of the candidate. True parents were replayed from git.

## Verdict table

| Case | Kind | This review | Unclosed | Closed FAILs |
|---|---|---|---|---|
| GHSA-4F78-QHMW-8J8M | 1 | UNKNOWN | release | ai_hunk, topology, but-for |
| GHSA-F2R8-JV7C-XQMP | 1 | UNKNOWN | release | ai_hunk, topology, but-for |
| GHSA-C4C3-PG64-4M4V | 1 | UNKNOWN | release | ai_hunk, but-for |
| GHSA-87X5-VMC3-756J | 1 | REJECT | none | ai_hunk, but-for |
| GHSA-XC48-889X-5QMW | 1 | REJECT | none | ai_hunk, topology, but-for |
| GHSA-JR45-8VMC-QM54 | 1 | UNKNOWN | release | ai_hunk, but-for |
| GHSA-W62W-66V9-VVGV | 1 | UNKNOWN | release | ai_hunk, but-for |
| GHSA-RQ84-P6RR-VF89 | 1 | UNKNOWN | release | ai_hunk, topology, but-for |
| GHSA-QHJ8-Q5R6-8Q6J | 2 | UNKNOWN | fix_reversal, release | ai_hunk, but-for |
| GHSA-JQ43-27X9-3V86 | 2 | UNKNOWN | release | ai_hunk, but-for |
| GHSA-4HX9-48XH-5MXR | 2 | UNKNOWN | release | ai_hunk, but-for |
| GHSA-RJ4J-2JPH-GG43 | 2 | UNKNOWN | release | ai_hunk, but-for |
| GHSA-7C4H-VH2M-743M | 2 | UNKNOWN | release | ai_hunk, but-for |
| GHSA-26GQ-GRMH-6XM6 | 2 | REJECT | none | ai_hunk, but-for |

## Kind-1

### GHSA-4F78-QHMW-8J8M -- UNKNOWN

Identity PASS. Unsanitized dock_state_ / openDevTools mode.

True parent `bab6bd3dae351d8f49203a26468d58482f754c84`. Listed parent `964cf07e` is the trop fix parent.

Candidate `fe477ce3` is electron-roller chromium bump PR 49145 with Claude patch-conflict members plus Keeley Hammond and clavin. Parent already concatenates `dock_state_` into DevTools JS. Candidate inspectable diff is a Chromium git-revision include swap. The dock_side patch already exists on the parent; the candidate only rebases hunk headers.

Fix-reversal PASS as a mechanism check: trop allowlist commits such as `969741f9`. Release stays UNKNOWN: v41.2.0 contains both the candidate and `969741f9`, so this packet does not peel a vulnerable-without-closer artifact.

### GHSA-F2R8-JV7C-XQMP -- UNKNOWN

Same candidate SHA, distinct GHSA (CVE-2026-70611). Parent already calls `platform_util::ShowItemInFolder`. Listed parent `4bd7aa8d` is the trop fix parent of `10fb5b39`. Shared SHA does not merge cases and does not save either edge.

### GHSA-C4C3-PG64-4M4V -- UNKNOWN

Cursor coauthor on Sidharth Vinod beta-policy tests. True parent `980db3f8`. `mermaidAPI.spec.ts` changes one swimlane parse string to `swimlane-beta`. `assignWithDepth.ts` is already on the parent and is not in the candidate diff. Fix `2cd6dcf` by Alois Klink edits `assignWithDepth.ts`. Listed parent `630aa7e5` is that fix's parent. gn clone lacks the advisory tags; release_gate UNKNOWN. Row cannot close.

### GHSA-87X5-VMC3-756J -- REJECT

Claude coauthor on Simon Mo fingerprint PR 40537. True parent `8d8062d0`. `completion/protocol.py` only adds `system_fingerprint` on `CompletionStreamResponse`. Parent already accepts prompt lists. Fix `675f4295` bounds the prompt list. Candidate is in v0.25.0; fix is not. v0.26.0 contains the fix. Containment does not save origin.

### GHSA-XC48-889X-5QMW -- REJECT

gemini-code-assist review trailer on mskitroot workspaceId plumbing in `CustomMCP.ts`. Advisory sink is `core.ts` `validateEnvironmentVariables` (CVE-2025-8943 denylist bypass via `npm_config_yes`). Candidate does not edit that function. Not AI incomplete remediation: the assigned SHA is not the security attempt. Fix `a4c4e498` switches to an allow-list. Candidate in `flowise@3.1.2`; fix in `flowise@3.1.3`. Listed parent `746d203a` is the fix parent.

### GHSA-JR45-8VMC-QM54 -- UNKNOWN

Claude coauthor on Matthew Robertson `determineDeleteAt` TTL change. Advisory is OWS around `=` in `parseCacheControlHeader` (`lib/util/cache.js`). Candidate does not touch that file. Fix `85a24055` trims qualified field names. Listed parent `d0574cc4` is the fix parent. gn clone lacks v7.29.0 / v8.9.0; release_gate UNKNOWN. Row cannot close.

### GHSA-W62W-66V9-VVGV -- UNKNOWN

Claude-coauthored GetObjectAttributes feature. True parent `9e26d6f5`. Parent already has `mux.NewRouter().SkipClean(true)` on S3 and Iceberg and already registers `GetObjectHandler`. Candidate adds `GetObjectAttributesHandler` that calls the same `GetBucketAndObject`. Iceberg is untouched. Removing the new route leaves GetObject and Iceberg traversal. The closer `dd1b4287` is generic `..` rejection, not an amendment of an AI-added security boundary. Feature, not an explicit security attempt, so not incomplete remediation. Listed parent `1355c7a1` is the fix parent.

### GHSA-RQ84-P6RR-VF89 -- UNKNOWN

Classic298 plus Tim Baek plus Claude log-env cleanup. `auths.py` / `oauth.py` diffs only drop `SRC_LOG_LEVELS`. Advisory is OAuth token exchange. Listed parent `56183fcb` is the parent of `b190dcf3`.

## Kind-2 (advisory blobs; assigned SHA is the listed fix)

### GHSA-QHJ8-Q5R6-8Q6J -- UNKNOWN

`ce3b67f8` by Damir Jelic / Ivan Enderlin. name-only: `bindings/matrix-sdk-ffi/CHANGELOG.md`. No AI marker. Not the `normalized_power_level` panic hunk.

### GHSA-JQ43-27X9-3V86 -- UNKNOWN

`1782e8c2` Merge commit from fork by DepthFirst Disclosures with Norman Maurer and Chris Vest. Edits `SmtpUtils.java`. This is the closer. A blog that an AI agent found the bug is discovery, not introducing-hunk authorship.

### GHSA-4HX9-48XH-5MXR -- UNKNOWN

`754c070c` Pedro Igor LDAP URL restriction. Human coauthors only. Closer, not origin. Sibling `b90fec41` is the 26.2 backport.

### GHSA-RJ4J-2JPH-GG43 -- UNKNOWN

`58362b08` Yisaer / odaysec path-validation fix PR 3911. `pkg/path/path.go` and zip extraction. Human reporter, not an AI trailer. Closer, not origin.

### GHSA-7C4H-VH2M-743M -- UNKNOWN

`ae0669a7` RomanDavydchuk / Elias Meire. github-actions is the committer. Subject validates community-package versions. Closer, not origin.

### GHSA-26GQ-GRMH-6XM6 -- REJECT

`71a72a72` Jakub Domeracki / Joe Chen mermaid plugin bump. Absent from `v0.13.3`, present in `v0.13.4`. Advisory also points at mermaid GHSA-7rqq / GHSA-8gwm. Closer, not origin.

## Cross-proposal uniqueness

All fourteen identities are absent from canonical84 counted 84. GHSA-4F78 and GHSA-F2R8 share candidate `fe477ce3` and remain distinct failed edges. GHSA-C4C3 (mermaid pollution) and GHSA-26GQ (gogs mermaid XSS bump) are distinct repositories and mechanisms.

## Claim boundary

KEEP is empty. Eleven rows are UNKNOWN because release and/or fix-reversal did not close. Three REJECT rows have every gate closed with origin FAIL. Leader replay is still required before any admission. Canonical84 was not edited. Publication and more-than-200 stay HOLD.

## Replay

`zsh replay.zsh` exited 0 with `REPLAY_OK reviewed=14 KEEP=0 REJECT=3 UNKNOWN=11 BLOCKED=0`. See `replay.zsh` and `replay.txt`. No GitHub API. No ledger edits. No commit or push. Owned temporary clones deleted.

## Input hashes (SHA-256)

- adjudication-4.jsonl `3264d02737cfef400e3e70cd45a6e88c852b46f6d98f3a5320c85af1ca9b563f`
- CONTRACT.md `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- canonical84 ledger.jsonl `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`
