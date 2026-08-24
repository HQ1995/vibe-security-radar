# Missing-ref final13 GHSA mining (grok46-medium)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions. Prior freeze-hits that unioned Gitea SHAs across GHSA-44QC and GHSA-RQHX is superseded as `work/freeze-hits.superseded-contaminated-v1.json` and is not used.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen scan-miss SHA-256 `5ec5265e65d957d8a7877a1c27465e9463b404f73790cfb03fc9f011d5625e40`. Canonical84 commit `ca034f064fd696201c81baae7392c14f0d501d2b` untouched. Shared tracked files were not edited. No commit, push, or credential output.

## Conservation

Raw unique pure missing_ref pool 141 = frozen already-covered 98 + eligible 43 (`141=98+43`). Eligible 43 = first30 assigned 30 + this leftover 13 (`43=30+13`). No padding. No backfill. First30 outcomes were not trusted; only its frozen `assigned30.jsonl` exclusion was used.

Assigned 13, reviewed 13, unreviewed 0. Deep freeze hits 0. GHSA-RQHX is a heuristic HIT reviewed as REJECT (remediation-as-origin); it is not promoted to origin or incomplete rem. Heuristic misses are NOT_SELECTED with gates NOT_OPENED. Brace-expansion history/shallow failures are BLOCKED, not causal REJECT.

## Closure rule

Each row's closer set is that GHSA's OSV JSON commit and PR references only. PR members enter only when they score uniquely against this advisory/mechanism, not because they share a repository or a bundled PR. Multi-fix squash 9e84deb is blamed only on mechanism files.

- GHSA-44QC closers: `9e84deb969af`, `33e70a01fe13`. Mechanism file: `services/convert/notification.go`. Excluded: a746372, 492a914, a5339e0, db7eb, mirror 1b1edda.
- GHSA-RQHX closers: `9e84deb969af`, `a7463723257f`, `492a9145b775`. Mechanism files: `modules/git/repo.go`, `services/repository/migrate.go`. Excluded: 33e70a01, a5339e0, 1b1edda, db7eb.

## Seven-gate row

### GHSA-RQHX-647V-WX32 - reviewed REJECT, never PASS

Heuristic HIT only. a746372 is the SSRF remediation member inside multi-fix PR 38108 / carrier 9e84deb, not origin. Claude-assisted does not promote.

Identity PASS. AI hunk FAIL: the AI change authors the guard, not the vulnerable migrate 302 path. Topology FAIL: carrier/member rem, not origin ancestry. But-for FAIL: removing a746 reopens an old hole rather than proving AI introduced this GHSA. Fix-reversal FAIL: later human 492a914 cleanup / other followRedirects edits are not a same-boundary residual named by this advisory. Release FAIL: peeled v1.26.2/3/4 do not contain a746. Incomplete-rem class not met (no separately released AI attempt). Uniqueness PASS versus canonical84.

## GHSA-44QC-PGVP-WX7V - NOT_SELECTED, kept separate

Parent of 33e70a01 already filled `subject` after a permission gate that only hid `result.Repository`. db7eb only renamed that helper. But-for fails. 33e70a01 is Claude-assisted remediation. This row does not consume SSRF/mirror/label fixes. Gates not opened.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| REJECT | 1 |
| BLOCKED | 2 |
| NOT_SELECTED | 10 |

## Claim boundary

Countable PASS requires all seven gates and leader admission. Proposed PASS: 0. Publication remains HOLD. Greater-than-200 remains HOLD. This packet does not change the canonical count.

## Replay

Self-contained. Deterministic replay does not use network and does not require `/tmp/ghsa200-missingref-final13` (that clone was deleted after capture and must stay absent). Git and advisory command outputs are pinned under `notes/` with provenance in `notes/pinned-facts.json` and hashes in `notes/pin-manifest.sha256`. Optional public refresh commands are in `notes/optional-public-refresh.txt` and are not executed by `replay.zsh`.
