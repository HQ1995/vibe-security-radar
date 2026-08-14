# Direct-root GHSA mining, batch 2

**Status: TERMINAL / HOLD. Final-round checkpoint. Expansion stopped. Assigned = 30. Reviewed = 30. Remaining UNREVIEWED ranking hits = 770. Proposed PASS = 0. Countable PASS = 0. REJECT = 30.**

No further candidates will be inspected. Worker PASS is a proposal only. Publication and any more-than-200 claim remain HOLD. `causal_admission` is false.

This lane continues the first packet's advisory-first method. It does not re-rank. It takes the next 30 unique identities after the 30 frozen in `autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh/work/selected-30.jsonl`, excluding canonical72, frozen proposals/pending identities including Q855, and the entire first batch. GitHub-unreviewed 2025-2026 objects that mention a repository advisory URL all name a *different* GHSA identity (684 aliases, 0 same-id first-party rows) and are not counted.

Bound to leader `CONTRACT.md` SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Shared tracked files were not edited. The first packet was not mutated. No commit, push, or credential output.

## Provenance (two hashes, two roles)

- **Frozen conservation inputs:** `CONTRACT.md` `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`, leader `baseline.json` `d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132`, fp211 public cases `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`, fp211 ledger `1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6`, fp211 final mechanisms `0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2`, netnew22 `result.json` `c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829` (21 KEEP identities), netnew22 `cases.jsonl` `d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889`. Frozen routing indexes: GN `ai-commit-scans.jsonl` `a6d7ca1584dbeb1596c57643092df0178001925efe0de60ca3eee5f72182481a`, AF `ai-commits.jsonl` `9659e93e82df4428df361507c6728ac83988211b0282ffbc3c12e3aba529d6d0`, OZ `ai_mine.jsonl` `047bbb068b09194a59a934117fec1448563e073147bf2e005d53f427bdc8c18a`. Frozen first-packet ranking: `selected-30.jsonl` `908f64f5f00195dae78574e86e9379f0b65cdd34c92ed1217c18702e35c59365`, `rank-hits.jsonl` `7247f2cd6d3835385eb96a1acad945702b15cd8a618b0465bf73551de0af7e49`. Canonical72 uniqueness packet `result.json` `fb3b97c7b5d207119cc22d255ba48cbda568d56c8fffb447fb0e58ac8878f4fb`. Replay fails if any of these bytes move.
- **Current overlap check:** live `scripts/publication_adjudications.json` after `5620e01` is SHA-256 `9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f`. None of the batch-2 selected identities appear. This check does not re-select the reviewed set. Pending Actual/B3/Gogs case files are pinned in `replay.sh` as current overlap only.

## Exclusion (not counted, not proposed)

| Set | Count |
|---|---:|
| Strict 48 baseline | 48 |
| Frozen netred 21 KEEP | 21 |
| Pending Actual / B3 / Gogs | 5 |
| fp211 public-case identities | 212 |
| Canonical72 strict-released | 72 |
| First-batch selected 30 (includes Q855) | 30 |
| Unique discovery-exclude union (first packet) | 215 |

Pending identities: `GHSA-7GH7-258J-4MPQ`, `GHSA-6P9M-Q3JP-47H4`, `GHSA-G3XQ-3GMV-QQ8G`, `GHSA-PV2J-RGHR-V5R9`, `GHSA-F38V-77QJ-H4JQ`. Q855 is in the first batch and is not re-proposed.

## Conservation

| Set | Count |
|---|---:|
| github-reviewed 2025+2026 JSON parsed | 12817 |
| First-party window active (published >= 2025-05-01, not withdrawn) | 8757 |
| With exact same-repo commit refs | 4652 |
| Eligible after discovery-exclude | 4507 |
| Rank pool (clone + AI-marked commits present) | 3473 |
| File-history / blame hits (routing) | 830 |
| First-batch deep-reviewed (excluded here) | 30 |
| Deep-reviewed here | 30 |
| Remaining ranking hits UNREVIEWED | 770 |
| Rank-pool misses (no AI history on fix files) UNREVIEWED | 2643 |
| Eligible skipped (no AI commits or clone missing) UNREVIEWED | 1034 |
| github-unreviewed same-id first-party | 0 |

Proven equalities: 30 + 30 + 770 + 2643 = 3473; 3473 + 1034 = 4507; 1025 + 9 = 1034. Reconstructing the frozen `rank-hits.jsonl` with the same score key yields the frozen first 30, then this selected 30 as ranks 31-60. Unreviewed rows are UNREVIEWED, not REJECT. REJECT applies only to the 30 identities reviewed here.

## Terminal outcomes

| Worker verdict | Rows |
|---|---:|
| PASS (proposal only, uncounted) | 0 |
| REJECT | 30 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |

### Proposed PASS

None. Countable PASS remains 0.

### REJECT (30)

All 30 are first-party github-reviewed identities with exact same-repo commit refs and an atomic AI-marked commit on the fix-file history. Independent blame of the closer's deleted source hunks attributed **zero** lines to that AI commit. File history without hunk identity is routing, not a proposal.

High-signal subjects that still failed: OpenC3 Claude path-traversal *guard* (later closer, not origin); go-git path-validating wrapper; hubuum trio sharing one SHA and one closer; datamodel-code-generator SHA already seen in batch 1; Gogs `util`->`x` rename already rejected in batch 1; Arc gemini-review sibling denylist; docs/chore/merge/license commits.

REJECT identities (30): `GHSA-F45Q-W629-WR25`, `GHSA-QQC3-94QV-7FW3`, `GHSA-2625-RW7M-5Q5X`, `GHSA-7WPJ-VVMV-PGM8`, `GHSA-HC8V-WWC9-VGXM`, `GHSA-J6XF-JWRJ-V5QP`, `GHSA-3CPP-FV95-MPR5`, `GHSA-8XQ3-W9FX-74RV`, `GHSA-J6V5-G24H-VG4J`, `GHSA-4JVX-93H3-F45H`, `GHSA-3RMJ-9M5H-8FPV`, `GHSA-9R75-G2CR-3H76`, `GHSA-G3VG-VX23-3858`, `GHSA-FQ7H-9X26-6J22`, `GHSA-QX5F-GHC2-7G5C`, `GHSA-VX7X-VCC2-C44G`, `GHSA-4VGR-H27G-CF9P`, `GHSA-WHWG-VH4F-PMMF`, `GHSA-WP87-MGVQ-5J93`, `GHSA-J2W3-9C3R-G83Q`, `GHSA-8359-H9FX-J6V9`, `GHSA-4JWF-M4WG-8P66`, `GHSA-5QFP-32CF-69JH`, `GHSA-9GQJ-5W7C-VX47`, `GHSA-4RMQ-MC2C-R495`, `GHSA-24P2-J2JR-386W`, `GHSA-WF93-3GHH-H389`, `GHSA-282G-FHMX-XF54`, `GHSA-P2J4-C4G6-RPF5`, `GHSA-WV27-2VQP-J7G5`.

The 770 remaining ranking hits are UNREVIEWED, listed in `work/unreviewed-hit-ids.txt`. They are not REJECT. `replay.sh` is fail-fast, offline, and English-only.

## Claim boundary

- Countable PASS requires all seven gates **and** leader admission.
- Proposed PASS: **0**. Countable PASS: **0**.
- Publication HOLD. A more-than-200 claim is not supported here.
- OSV `introduced`, commit subjects, later AI review, carrier/member authorship transfer, old-bug preservation, aliases, unrelated sibling fixes, incomplete-remediation security attempts without patch-delta, and file-history without blame-hunk identity were not promoted.
- This worker did not edit tracked canonical files, did not mutate the first packet, commit, or push.
