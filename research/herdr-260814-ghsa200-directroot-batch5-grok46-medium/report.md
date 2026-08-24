# Direct-root GHSA mining, batch 5

**Status: TERMINAL / HOLD. Assigned = 30. Reviewed = 30. Remaining UNREVIEWED ranking hits from the frozen 770 after this slice = 740. Proposed PASS = 2. Countable PASS = 0. REJECT = 28.**

Worker PASS is a proposal only. Publication and any more-than-200 claim remain HOLD. `causal_admission` is false. Expansion stopped. No further candidates will be inspected.

This lane continues the first packet's advisory-first method. It does not re-rank. It takes frozen `rank-hits.jsonl` identities 121-150 after excluding canonical73 (prior 72 plus independently red-teamed `GHSA-Q855-8RH5-JFGQ`) and the first 60 reviewed (batches 1-2). Other disjoint slices of the original 770 remain UNREVIEWED by this lane; no verdicts are inferred for them.

Bound to leader `CONTRACT.md` SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Shared tracked files were not edited. No commit, push, or credential output.

## Provenance (two hashes, two roles)

- **Frozen conservation inputs:** `CONTRACT.md` `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`, leader `baseline.json` `d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132`, fp211 public cases `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`, fp211 ledger `1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6`, fp211 final mechanisms `0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2`, netnew22 `result.json` `c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829`, netnew22 `cases.jsonl` `d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889`. Frozen routing indexes: GN `a6d7ca1584dbeb1596c57643092df0178001925efe0de60ca3eee5f72182481a`, AF `9659e93e82df4428df361507c6728ac83988211b0282ffbc3c12e3aba529d6d0`, OZ `047bbb068b09194a59a934117fec1448563e073147bf2e005d53f427bdc8c18a`. Frozen first-packet ranking: `selected-30.jsonl` `908f64f5f00195dae78574e86e9379f0b65cdd34c92ed1217c18702e35c59365`, `rank-hits.jsonl` `7247f2cd6d3835385eb96a1acad945702b15cd8a618b0465bf73551de0af7e49`. Canonical72 `fb3b97c7b5d207119cc22d255ba48cbda568d56c8fffb447fb0e58ac8878f4fb`. Canonical73 HOLD snapshot `summary.json` `699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8`. Replay fails if any of these bytes move.
- **Current overlap check:** live `scripts/publication_adjudications.json` SHA-256 `9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f`. None of the batch-5 selected identities appear as adjudications. This check does not re-select the reviewed set.

## Conservation

| Set | Count |
|---|---:|
| github-reviewed 2025+2026 JSON parsed | 12817 |
| First-party window active | 8757 |
| Rank pool | 3473 |
| File-history / blame hits (routing) | 830 |
| First 60 reviewed (batches 1-2) | 60 |
| Deep-reviewed here (ranks 121-150) | 30 |
| Remaining ranking hits UNREVIEWED | 740 |
| Rank-pool misses UNREVIEWED | 2643 |

Proven equalities: assigned = reviewed = 30; 60 + 30 + 740 + 2643 = 3473. Reconstructing frozen `rank-hits.jsonl` with the same score key yields this selected 30 as ranks 121-150. Unreviewed rows are UNREVIEWED, not REJECT.

## Terminal outcomes

| Worker verdict | Rows |
|---|---:|
| PASS (proposal only, uncounted) | 2 |
| REJECT | 28 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |

### Proposed PASS (2)

`GHSA-F229-3862-4942`, `GHSA-33RQ-M5X2-FVGF`

1. `GHSA-33RQ-M5X2-FVGF` (`AI_DIRECT_ROOT`): Claude-marked Twitch plugin squash authors `access-control.ts` with allowFrom fall-through default-allow. Closer inserts deny. First-party 2026.1.29 release contains the AI hunk; 2026.2.1 bump contains the reversal.
2. `GHSA-F229-3862-4942` (`AI_INCOMPLETE_REMEDIATION`): Claude-marked Object/prototype denylist rewrite; later closer amends the same identifier rule with array/object coercion covering the GHSA PoC. 2.11.0 branch cut has the attempt without closure; v2.11.1 first-parent is the closer.

### REJECT (28)

The remaining 28 are first-party github-reviewed identities with exact same-repo commit refs and an atomic AI-marked commit on the fix-file history. Deeper blame of the closer's deleted source hunks did not attribute the named mechanism to that ranked AI commit.

High-signal failures: Fickling denylist sibling omit and OBJ-opcode sibling; FrankenPHP hot-reload vs CGI unicode split; OpenClaw voice-call credential helper reused across three GHSAs; n8n Chat Trigger XSS attempt vs later bundle; Gogs pkg/errors / util-rename / com-replace chores; quic-go :path error string plus Copilot qpack refactor of an old trailer parser.

REJECT identities: `GHSA-QMJ2-8R24-XXCQ`, `GHSA-CV22-72PX-F4GH`, `GHSA-4CHV-4C6W-W254`, `GHSA-83PF-V6QQ-PWMR`, `GHSA-R3XH-3R3W-47GP`, `GHSA-7777-FHQ9-592V`, `GHSA-F229-3862-4942`, `GHSA-JJ5M-H57J-5GV7`, `GHSA-33RQ-M5X2-FVGF`, `GHSA-5G94-C2WX-8PXW`, `GHSA-4HG8-92X6-H2F3`, `GHSA-WPPC-7CQ7-CGFV`, `GHSA-MQPR-49JJ-32RC`, `GHSA-2W4F-9FGG-Q2V9`, `GHSA-MXHJ-88FX-4PCV`, `GHSA-78QV-3MPX-9CQQ`, `GHSA-G966-83W7-6W38`, `GHSA-5JVP-M9H4-253H`, `GHSA-75G8-RV7V-32F7`, `GHSA-M3C2-496V-CW3V`, `GHSA-3M3Q-X3GJ-F79X`, `GHSA-W235-X559-36MG`, `GHSA-4RJ2-GPMH-QQ5X`, `GHSA-JH8H-6C9Q-7GMW`, `GHSA-FHVM-J76F-QMJV`, `GHSA-MP5H-M6QJ-6292`, `GHSA-5C3F-6486-3G7G`, `GHSA-VVGJ-X9JQ-8CJ9`, `GHSA-QF6P-P7WW-CWR9`, `GHSA-HCXC-WF8J-23HV` excluding the two PASS ids.

The 740 remaining ranking hits are UNREVIEWED, listed in `work/unreviewed-hit-ids.txt`. `replay.sh` is fail-fast, offline, and English-only.

## Claim boundary

- Countable PASS requires all seven gates **and** leader admission.
- Proposed PASS: **2**. Countable PASS: **0**.
- Publication HOLD. A more-than-200 claim is not supported here.
- OSV `introduced`, commit subjects, later AI review, carrier/member authorship transfer, old-bug preservation, aliases, unrelated sibling fixes, incomplete-remediation security attempts without patch-delta, and file-history without blame-hunk identity were not promoted except the two proposed rows above.
- This worker did not edit tracked canonical files, did not mutate other worker directories, commit, or push.
