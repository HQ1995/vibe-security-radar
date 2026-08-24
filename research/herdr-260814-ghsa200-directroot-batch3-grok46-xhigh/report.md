# Direct-root GHSA mining, batch 3

**Status: TERMINAL / HOLD. Final-round checkpoint. Expansion stopped. Assigned = 30. Reviewed = 30. Remaining UNREVIEWED ranking hits = 740. Proposed PASS = 0. Countable PASS = 0. REJECT = 30.**

No further candidates will be inspected. Worker PASS is a proposal only. Publication and any more-than-200 claim remain HOLD. `causal_admission` is false. First-party GHSA identity is counted once.

This lane continues the first packet's advisory-first method. It does not re-rank. It takes frozen ranks 61-90 from `autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh/work/rank-hits.jsonl` after excluding canonical73 and the first 60 reviewed identities (batch 1 + batch 2). That slice is disjoint from those 60 and from canonical73. GitHub-unreviewed 2025-2026 objects that mention a repository advisory URL all name a *different* GHSA identity (684 aliases, 0 same-id first-party rows) and are not counted.

Bound to leader `CONTRACT.md` SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Shared tracked files were not edited. Other worker directories were not mutated. No commit, push, or credential output.

## Provenance (two hashes, two roles)

- **Frozen conservation inputs:** `CONTRACT.md` `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`, leader `baseline.json` `d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132`, fp211 public cases `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`, fp211 ledger `1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6`, fp211 final mechanisms `0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2`, netnew22 `result.json` `c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829`, netnew22 `cases.jsonl` `d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889`. Frozen routing indexes: GN `a6d7ca1584dbeb1596c57643092df0178001925efe0de60ca3eee5f72182481a`, AF `9659e93e82df4428df361507c6728ac83988211b0282ffbc3c12e3aba529d6d0`, OZ `047bbb068b09194a59a934117fec1448563e073147bf2e005d53f427bdc8c18a`. Frozen first-packet ranking: `selected-30.jsonl` `908f64f5f00195dae78574e86e9379f0b65cdd34c92ed1217c18702e35c59365`, `rank-hits.jsonl` `7247f2cd6d3835385eb96a1acad945702b15cd8a618b0465bf73551de0af7e49`. Frozen batch-2 `selected-30.jsonl` `05ff6f4b3a0de2d61be00bbcbd3adda9587e9897303b3fc595948dd4071e189e`. Canonical73 HOLD summary `699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8`. Replay fails if any of these bytes move.
- **Current overlap check:** live `scripts/publication_adjudications.json` after `5620e01` is SHA-256 `9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f`. None of the batch-3 selected identities appear. This check does not re-select the reviewed set.

## Exclusion (not counted, not proposed)

| Set | Count |
|---|---:|
| Strict 48 baseline | 48 |
| Frozen netred 21 KEEP | 21 |
| Pending Actual / B3 / Gogs | 5 |
| fp211 public-case identities | 212 |
| Canonical73 strict-released HOLD | 73 |
| First-batch selected 30 (includes Q855) | 30 |
| Batch-2 selected 30 | 30 |
| Unique discovery-exclude union (first packet) | 215 |

Q855 is already in batch 1 and in canonical73. It is not re-proposed.

## Conservation

| Set | Count |
|---|---:|
| github-reviewed 2025+2026 JSON parsed | 12817 |
| First-party window active (published >= 2025-05-01, not withdrawn) | 8757 |
| With exact same-repo commit refs | 4652 |
| Eligible after discovery-exclude | 4507 |
| Rank pool (clone + AI-marked commits present) | 3473 |
| File-history / blame hits (routing) | 830 |
| Batch-1 deep-reviewed (excluded here) | 30 |
| Batch-2 deep-reviewed (excluded here) | 30 |
| Deep-reviewed here | 30 |
| Remaining ranking hits UNREVIEWED | 740 |
| Rank-pool misses (no AI history on fix files) UNREVIEWED | 2643 |
| Eligible skipped (no AI commits or clone missing) UNREVIEWED | 1034 |
| github-unreviewed same-id first-party | 0 |

Proven equalities: 30 + 30 + 30 + 740 + 2643 = 3473; 3473 + 1034 = 4507; 1025 + 9 = 1034. Reconstructing the frozen `rank-hits.jsonl` with the same score key yields the frozen first 60, then this selected 30 as ranks 61-90. The 770 unreviewed hits after the first 60 are the source pool; this worker reviews 30 of them and leaves 740 UNREVIEWED. Unreviewed rows are UNREVIEWED, not REJECT. REJECT applies only to the 30 identities reviewed here.

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

All 30 are first-party github-reviewed identities with exact same-repo commit refs. Independent first-parent blame of deleted source hunks was run on the closer, not just ranking history files.

Eight identities had ranked-AI deleted-line hits and were still rejected after seven-gate review: ONNX Copilot save/checker attempt versus load/symlink GHSAs without peelable release tags (`GHSA-CMW6-HCPP-C6JP`, `GHSA-3R9X-F23J-GC73`); ONNX setattr sibling (`GHSA-538C-55JV-C5G9`); n8n-mcp SSE auth versus sibling `/mcp` GET/DELETE (`GHSA-75HX-XJ24-MQRW`); OpenClaw squash #1757 toolsBySender member-to-carrier transfer (`GHSA-WPPH-CJGR-7C39`); WeChat localhost skip copied into Stripe (`GHSA-Q938-GHWV-8GVC`); n8n-mcp test-only hunk (`GHSA-JXX9-PX88-PJ69`); specifyjs allowlist expansion without git tags (`GHSA-XW57-23P8-9WC5`).

Other high-signal misses: n8n-mcp webhook SSRF guard versus instance-URL header SSRF; OpenC3 table-prefix chore versus QuestDB SQLi; Gogs errors rename reused on two identities; SPDX/log-env chores; ComfyUI-Manager mapped to PyPI `comfy-cli`.

REJECT identities (30): `GHSA-W5C7-9QQW-6645`, `GHSA-G2F5-GJR4-QJVM`, `GHSA-29JH-8CFQ-RR8X`, `GHSA-5WX6-MG75-V57R`, `GHSA-CMW6-HCPP-C6JP`, `GHSA-4GGG-H7PH-26QR`, `GHSA-V529-VHWC-WFC5`, `GHSA-75HX-XJ24-MQRW`, `GHSA-538C-55JV-C5G9`, `GHSA-8F24-V5VV-GM5J`, `GHSA-G374-MGGX-P6XC`, `GHSA-CJ4V-437J-JQ4C`, `GHSA-WPPH-CJGR-7C39`, `GHSA-VQX8-9XXW-F2M7`, `GHSA-WW6V-V748-X7G9`, `GHSA-MFG5-7Q5G-F37J`, `GHSA-H656-5VCF-CM23`, `GHSA-Q938-GHWV-8GVC`, `GHSA-62F6-MRCJ-V8H5`, `GHSA-56PX-HM34-XQJ5`, `GHSA-3R9X-F23J-GC73`, `GHSA-X3QM-P8HR-3C3H`, `GHSA-3V85-FQVH-7RXF`, `GHSA-JXX9-PX88-PJ69`, `GHSA-M69W-P7M4-585J`, `GHSA-QJVR-435C-5FJH`, `GHSA-RJ4G-RQGH-RX9H`, `GHSA-V6QF-75PR-P96M`, `GHSA-562R-8445-54R2`, `GHSA-XW57-23P8-9WC5`.

The 740 remaining ranking hits are UNREVIEWED, listed in `work/unreviewed-hit-ids.txt`. They are not REJECT. `replay.sh` is fail-fast, offline, and English-only.

## Claim boundary

- Countable PASS requires all seven gates **and** leader admission.
- Proposed PASS: **0**. Countable PASS: **0**.
- Publication HOLD. A more-than-200 claim is not supported here.
- OSV `introduced`, commit subjects, later AI review, carrier/member authorship transfer, old-bug preservation, aliases, unrelated sibling fixes, incomplete-remediation security attempts without patch-delta and release peel, weak package mapping, and file-history without blame-hunk identity were not promoted.
- This worker did not edit tracked canonical files, did not mutate other worker directories, commit, or push.
