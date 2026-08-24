# Direct-root GHSA mining, batch 4

**Status: TERMINAL / HOLD. Final-round checkpoint. Expansion stopped. Assigned = 30. Reviewed = 30. Remaining UNREVIEWED ranking hits = 710. Proposed PASS = 5. Countable PASS = 0. REJECT = 25.**

No further candidates will be inspected. Worker PASS is a proposal only. Publication and any more-than-200 claim remain HOLD. `causal_admission` is false.

This lane continues the first packet's advisory-first method. It does not re-rank. It takes original ranks 91-120 from frozen `rank-hits.jsonl` after excluding canonical73 and the first 90 deep-reviewed identities (batch1+batch2+batch3). That slice is a disjoint 30 of the 770 unreviewed hits that remained after the first 60. GitHub-unreviewed 2025-2026 objects that mention a repository advisory URL all name a *different* GHSA identity (684 aliases, 0 same-id first-party rows) and are not counted.

Bound to leader `CONTRACT.md` SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Shared tracked files were not edited. Other worker directories were not mutated. No commit, push, or credential output.

## Provenance (two hashes, two roles)

- **Frozen conservation inputs:** `CONTRACT.md` `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`, leader `baseline.json` `d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132`, fp211 public cases `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`, fp211 ledger `1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6`, fp211 final mechanisms `0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2`, netnew22 `result.json` `c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829`, netnew22 `cases.jsonl` `d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889`. Frozen routing indexes: GN `a6d7ca1584dbeb1596c57643092df0178001925efe0de60ca3eee5f72182481a`, AF `9659e93e82df4428df361507c6728ac83988211b0282ffbc3c12e3aba529d6d0`, OZ `047bbb068b09194a59a934117fec1448563e073147bf2e005d53f427bdc8c18a`. Frozen first-packet ranking: `selected-30.jsonl` `908f64f5f00195dae78574e86e9379f0b65cdd34c92ed1217c18702e35c59365`, `rank-hits.jsonl` `7247f2cd6d3835385eb96a1acad945702b15cd8a618b0465bf73551de0af7e49`. Canonical72 `fb3b97c7b5d207119cc22d255ba48cbda568d56c8fffb447fb0e58ac8878f4fb`. Canonical73 summary `699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8`. Batch2 selected-30 `05ff6f4b3a0de2d61be00bbcbd3adda9587e9897303b3fc595948dd4071e189e`. Batch3 selected-30 `cc9357feda897f591a4ce0e6a060d8da724c85aa0a6ecce5d9add9c487249a1c`. Replay fails if any of these bytes move.
- **Current overlap check:** live `scripts/publication_adjudications.json` after `5620e01` is SHA-256 `9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f`. None of this slice's identities appear. This check does not re-select the reviewed set.

## Exclusion (not counted, not proposed as already admitted)

| Set | Count |
|---|---:|
| Strict 48 baseline | 48 |
| Frozen netred 21 KEEP | 21 |
| Pending Actual / B3 / Gogs | 5 |
| fp211 public-case identities | 212 |
| Canonical72 strict-released | 72 |
| Canonical73 HOLD snapshot | 73 |
| First-batch selected 30 (includes Q855) | 30 |
| Batch2 selected 30 | 30 |
| Batch3 selected 30 | 30 |
| Unique discovery-exclude union (first packet) | 215 |

Q855 is in canonical73 and in batch1. It is not re-proposed.

## Conservation

| Set | Count |
|---|---:|
| github-reviewed 2025+2026 JSON parsed | 12817 |
| First-party window active (published >= 2025-05-01, not withdrawn) | 8757 |
| With exact same-repo commit refs | 4652 |
| Eligible after discovery-exclude | 4507 |
| Rank pool (clone + AI-marked commits present) | 3473 |
| File-history / blame hits (routing) | 830 |
| Batch1 deep-reviewed | 30 |
| Batch2 deep-reviewed | 30 |
| Batch3 deep-reviewed | 30 |
| Deep-reviewed here | 30 |
| Remaining ranking hits UNREVIEWED | 710 |
| Rank-pool misses UNREVIEWED | 2643 |
| Eligible skipped (no AI commits or clone missing) UNREVIEWED | 1034 |
| github-unreviewed same-id first-party | 0 |

Proven equalities: 30 + 30 + 30 + 30 + 710 + 2643 = 3473; 3473 + 1034 = 4507; 1025 + 9 = 1034. Reconstructing frozen `rank-hits.jsonl` with the same score key yields batch1 as ranks 1-30, batch2 as 31-60, batch3 as 61-90, and this selected 30 as ranks 91-120. Unreviewed rows are UNREVIEWED, not REJECT. REJECT and PASS apply only to the 30 identities reviewed here. Assigned = reviewed = 30.

## Terminal outcomes

| Worker verdict | Rows |
|---|---:|
| PASS (proposal only, uncounted) | 5 |
| REJECT | 25 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |

### Proposed PASS (5, uncounted)

All five are first-party github-reviewed `@asymmetric-effort/specifyjs` identities. Each is `AI_INCOMPLETE_REMEDIATION` under the patch-delta rule. Worker PASS is a proposal. Countable PASS remains 0 until leader admission.

Git tag `v0.2.135` (`a84103e7`) has `core/package.json` name `@asymmetric-effort/specifyjs` version `0.2.135` and contains the AI attempts without closer `25d1fb49`. Git tag `v0.2.136` is the closer itself and has version `0.2.136`. First-party advisory range is npm `@asymmetric-effort/specifyjs` fixed `0.2.136`.

1. `GHSA-5C7W-4WM3-85VW` — Claude-marked atomic `caa8fbfa` added a gql metacharacter **warn** (M-8) that still concatenated. Fix PT-002 throws. Deleted warn lines blame `caa8fbfa` only.
2. `GHSA-93Q6-WWJH-JC6H` — same `caa8fbfa` added CSS `expression(`/`url(javascript:` strip (L-6). Residual unicode-escape/comment bypass. Fix PT-003 amends that sanitizer. Deleted strip lines blame `caa8fbfa` only.
3. `GHSA-8882-FRVV-92W4` — Claude-marked atomic `30f9b76f` introduced `assertSecureUrl` with `catch { return }` on parse failure. Ranking SHA `caa8fbfa` did not own those deleted lines. Fix PT-001 throws. Count the introducing HTTPS guard, not the later protocol-relative add-on.
4. `GHSA-J5QP-P44G-2M49` — same `30f9b76f` introduced `secureFetch` as `fetch(input, init)` with default redirect follow. Fix PT-004 sets `redirect: 'error'`.
5. `GHSA-2944-57XV-2682` — same `30f9b76f` allowlisted unbounded `data:` URIs inside that HTTPS guard. Fix PT-005 caps at 1MB.

Shared SHA is not duplication. These are five first-party GHSA identities with five mechanism keys. None are in canonical73.

### REJECT (25)

`GHSA-4G3V-8H47-V7G6`, `GHSA-RWJ8-PGH3-R573`, `GHSA-C2J3-45GR-MQC4`, `GHSA-PW9M-5JXM-XR6H`, `GHSA-FWG2-GR34-Q3W8`, `GHSA-QCR8-X557-7CP3`, `GHSA-M34R-V34R-RF9Q`, `GHSA-2F96-G7MH-G2HX`, `GHSA-4V76-CW68-4VC9`, `GHSA-X9VC-9FFQ-P3GJ`, `GHSA-7W99-5WM4-3G79`, `GHSA-2Q4P-G7HV-5RGV`, `GHSA-2JWF-F4XQ-F24H`, `GHSA-FJGC-3MJ7-8RG8`, `GHSA-M42H-3232-VPV3`, `GHSA-87FV-VQQR-M4JR`, `GHSA-P5W8-M249-4R4V`, `GHSA-HM5P-X4RQ-38W4`, `GHSA-9H52-P55H-VW2F`, `GHSA-W48Q-CV73-MX4W`, `GHSA-46GC-MWH4-CC5R`, `GHSA-X4M5-4CW8-VC44`, `GHSA-XQ4H-WQM2-668W`, `GHSA-V3GR-W9GF-23CX`, `GHSA-J26P-6WX7-F3PW`

High-signal rejects: commonmark `GHSA-2Q4P` first DoS approach never shipped without the same-day merged closure (release_gate FAIL); NetLicensing `GHSA-X9VC` AI safety tokens sit beside pre-existing `ApiKeyMiddleware` from `81f799ac`; Astro merge `GHSA-4G3V`; GitPython sibling option guards; etherpad GDPR features vs Math.random / x-proxy-path; specifyjs `GHSA-QCR8` SPDX chore.

The 710 remaining ranking hits are UNREVIEWED, listed in `work/unreviewed-hit-ids.txt`. They are not REJECT. `replay.sh` is fail-fast, offline, and English-only.

## Claim boundary

- Countable PASS requires all seven gates **and** leader admission.
- Proposed PASS: **5**. Countable PASS: **0**.
- Publication HOLD. A more-than-200 claim is not supported here.
- OSV `introduced`, commit subjects, later AI review, carrier/member authorship transfer, old-bug preservation, aliases, unrelated sibling fixes, incomplete-remediation security attempts without a released residual, and file-history without hunk identity were not promoted.
- This worker did not edit tracked canonical files, did not mutate other workers, commit, or push.
