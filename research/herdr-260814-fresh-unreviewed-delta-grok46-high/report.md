# Fresh unreviewed delta (f2c6 versus 39d888)

Verdict first: **0 PASS_PROPOSAL**. Inspected **12**. **12 REJECT**. Bound 12 reached. Did not pad. Packet delta **0**. Canonical88 stays **88**. Publication and greater-than-200 remain **HOLD**. Worker PASS is proposal only; this packet emits none.

## Freeze

Official unreviewed tree at `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` was listed with `git ls-tree` from `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` (tree `8cdc0a0b741cc5df87e9f2b7fa582debca410fdb`). Older unreviewed worktree `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226` (tree `09d03333897c6e461074008a7f2663ffed8fb219`).

New unreviewed IDs 323477. Old unreviewed IDs 317316. Added **6296**. Removed 135. Exact sorted-ID sha256 `ce4927c40efa5db05ee070c23ea5d9acc39bbc0f01beb947bae2243602cc477c`. All 6296 paths are 2026. Cross-bound overlap with github-reviewed at f2c6: 0.

All 6296 JSON objects have empty `affected[]`. Identity therefore fails closed for the whole delta. Ranking still required a real GitHub repository/advisory or exact fix reference.

## Rank

Nonwithdrawn 2026 objects with a GitHub repo advisory URL, GitHub repo, or exact fix SHA: **2079**. Structured prior IDs plus canonical88: **8189** (sha256 `f9b9bcbe7c20e4f96d0db282ddb114aa362e144de87d97f691f9323a3ae86811`, 2473 artifact files). Delta overlap with that exclusion: 4. Eligible remaining: **2075**.

Rank: repo advisory, then exact GitHub commit, then local clone, then GitHub repo, then published descending, then GHSA ID. Inspect cap 12. Strongest 12 all had a repo advisory plus a listed GitHub commit. Nine had local fix objects. Three used bounded read-only fetch into `/tmp` (Flowise SHA is not on origin; FreeRDP and Gitea recovered). Temporary clones deleted at handoff. Shared caches were not mutated.

## Seven gates

identity, AI hunk, topology, but-for, fix reversal, release, uniqueness. Exact PASS required. Unreviewed empty affected or cross-bound identity fails closed. AI-on-fix, old-bug preservation, and release-unknown are not strict PASS.

## Inspected set

| n | ID | First-party ID | Closer | Verdict |
| --- | --- | --- | --- | --- |
| 1 | GHSA-9RMJ-FH79-GF6W | GHSA-94P4 / GHSA-RWJ8 | GPT 5.6 openai_codex 8ac5a305 | REJECT |
| 2 | GHSA-32PR-94PQ-34PJ | GHSA-V3JV | Henrique Dias 72faf6dd | REJECT |
| 3 | GHSA-56H4-P63W-W4WM | GHSA-RQH4 | 4211bfc8 missing | REJECT |
| 4 | GHSA-WX2X-G9FW-53FC | GHSA-77X8 | Henrique Dias 72faf6dd | REJECT |
| 5 | GHSA-336F-J5CQ-6C4F | GHSA-RQGV | Armin Novak b05a9510 | REJECT |
| 6 | GHSA-MG62-J9W6-5HFH | GHSA-CFVQ | Daniel Neto 1adcb754 | REJECT |
| 7 | GHSA-Q6C7-VM4C-28MJ | GHSA-V7P7 | Daniel Neto 1b55a9b3 | REJECT |
| 8 | GHSA-3M6R-M23G-M2W9 | GHSA-XWV3 | Andy Miller merge 694f1dae | REJECT |
| 9 | GHSA-685P-FM6J-C445 | GHSA-2WM4 | bircni chore b969123b | REJECT |
| 10 | GHSA-642R-3GJ9-2PJ5 | GHSA-R7WM / GHSA-72HV | Tatu merge / tonghuaroot 4cdd5297 | REJECT |
| 11 | GHSA-6QM2-MCQ7-53QP | GHSA-72HV | PJ Fanning b0c428e6 | REJECT |
| 12 | GHSA-MFCJ-9FRG-F2R4 | GHSA-PCFH | Ryan Kurtz c03a70dd | REJECT |

### GHSA-9RMJ-FH79-GF6W REJECT

Identity FAIL: empty affected and three GHSA IDs for one CVE. AI hunk FAIL: closer is the AI change. Topology PASS: n_parents=1. But-for FAIL: deleting an AI fix does not prove AI origin of the bug. Fix reversal FAIL for counting: AI-on-fix is not origin. Release UNKNOWN: no local tag contains 8ac5a305. Uniqueness PASS versus canonical88.

Commands:

- `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gitpython-developers__GitPython log -1 --format=%an%n%ae%n%s 8ac5a30519b6f4af85398b9b9d7064ff4d452da2`

### GHSA-32PR-94PQ-34PJ and GHSA-WX2X-G9FW-53FC REJECT

Both are unreviewed NVD shadows of different first-party filebrowser advisories. Shared closer 72faf6dd is Henrique Dias. Same-file Claude 847d08bdd names other GHSAs and is not JWT expiry or recursive ACL. Shared SHA is routing, not a merge of 32PR with WX2X.

### GHSA-56H4-P63W-W4WM REJECT

Identity FAIL from empty affected and GHSA-RQH4. Listed SHA 4211bfc8 is not a GitHub ref. Git gates UNKNOWN. Missing objects never mint PASS.

### GHSA-336F-J5CQ-6C4F REJECT

Bounded fetch recovered Armin Novak closer b05a9510 with parent 0adf5e30. source_matcher empty.

### GHSA-MG62-J9W6-5HFH and GHSA-Q6C7-VM4C-28MJ REJECT

Daniel Neto human closers. Q6C7 Copilot hit 4af90404 is a video-ID refactor, not encoder-chunk writes.

### GHSA-3M6R-M23G-M2W9 REJECT

Listed SHA is merge 694f1dae. Member f81bbd1f is Andy Miller naming GHSA-xwv3. No transfer. Topology FAIL on the listed merge. Tags 2.0.9+ contain the merge.

### GHSA-685P-FM6J-C445 REJECT

Cross-bound to reviewed GHSA-2WM4. Listed SHA b969123b is an unrelated merge-box chore. Fix reversal FAIL.

### GHSA-642R-3GJ9-2PJ5 and GHSA-6QM2-MCQ7-53QP REJECT

NVD shadows of reviewed jackson-core GHSA-R7WM and GHSA-72HV. Prior constraint closer is PJ Fanning. Residual closer 4cdd5297 is tonghuaroot. Incomplete rem of a human parser is not AI patch-delta.

### GHSA-MFCJ-9FRG-F2R4 REJECT

Ryan Kurtz human PATH check on the Swift demangler. Identity FAIL on the unreviewed shadow of GHSA-PCFH.

## Conservation

12 assigned = 0 reviewed + 12 unreviewed. Equation `12=0+12`. Eligible 2075. Inspected 12. Shortfall 0 versus cap 12. Did not pad. cve_aliases_counted=false. canonical88_overlap=0. packet_delta=0.

## Claim boundary

This packet does not admit cases. Current leader-accepted strict count remains 88 HOLD. Greater-than-200 remains unsupported. Canonical88 was not rebuilt. No commit, push, or edits outside this directory.
