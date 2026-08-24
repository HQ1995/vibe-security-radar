# GHSA 200+ gap inventory and dispatch QA

Status: **COMPLETE for mechanical inventory**. No PASS rows. Worker PASS is not emitted and would not be admission.

## Answer

**48** is the strict released starting lower bound. Target minimum is **201**. Gap to target is **153**. No PASS rows.

Active worker assignment coverage from leader `baseline.json` is **58** upgrade_a ordinals and **48** upgrade_b ordinals. Those sets are disjoint and their union is **106**. They are not interchangeable with census lane buckets.

The 231 unique-ID census rows are a lossless identity inventory. They are not assigned research obligations.

## Denominator

Exact routing denominator is first-party GHSA identity. Each ID is routed once.

| Quantity | Count |
|---|---:|
| fp211 source public IDs | 381 |
| fp211 source GHSA IDs | 217 |
| fp211 kept public-case GHSAs | 212 |
| fp211 removed GHSA identities | 5 |
| inventory rows / unique GHSA IDs | 231 / 231 |
| duplicate IDs dropped after first route | 0 |

Evidence is limited to completed Aug-12 `herdr-260812*` result/report artifacts and dated research docs. Live `herdr-260813-ghsa200*` sibling directories are excluded: autoresearch/herdr-260813-ghsa200-current-delta, autoresearch/herdr-260813-ghsa200-fresh-am, autoresearch/herdr-260813-ghsa200-fresh-nz, autoresearch/herdr-260813-ghsa200-gap, autoresearch/herdr-260813-ghsa200-remediation, autoresearch/herdr-260813-ghsa200-upgrade-b. Novel rows require record-local binding (same JSON object, table row, or list item). File-level GHSA/AI marker co-occurrence is not a candidate.

fp211 public-case census (not publication admission): CONFIRM 65, NARROW 84, FALSE_POSITIVE 54, UNKNOWN 9; total 212. Causal-valid (CONFIRM+NARROW): 149.

Canonical overlay also reports 48 released-admitted mechanisms and 51 strict-confirmed mechanisms; in this join those match the case-level 48/51 split. Posthold `released_pass_rows=144` is a pre-fp211 envelope. Dashboard `web/data/stats.json` lists 36 curated CVEs.

## Lane dispatch

Two different quantities:

| Kind | upgrade_a | upgrade_b | Notes |
|---|---:|---:|---|
| Active assignment (leader baseline ordinals) | 58 | 48 | Disjoint; union 106. These are worker assignments. |
| Identity census buckets (`census_inventory_by_lane`) | 111 | 65 | Include FALSE_POSITIVE, released baseline, and other identities. Not assignments. |

Census-only lanes: remediation 41, fresh-am 10, fresh-nz 4.

Incomplete-remediation cases may appear in the remediation census lane while their ordinal still belongs to an assignment set. Assignment counts remain 58 and 48 ordinals.

## CONFIRM/MEDIUM upgrade pool (14)

These are CONFIRM cases whose joined mechanism confidence is MEDIUM. Canonical overlay requires another review before strict confirmation. They are not released-admitted.

| GHSA | ordinal | verdict | missing gates | lane | status |
|---|---:|---|---|---|---|
| `GHSA-P52P-4VMG-4VQ3` | 114 | CONFIRM | none | upgrade-b | ROUTE |
| `GHSA-MF5G-6R6F-GHHM` | 122 | CONFIRM | none | upgrade-b | ROUTE |
| `GHSA-5C6W-WWFQ-7QQM` | 127 | CONFIRM | none | remediation | ROUTE |
| `GHSA-4MR5-G6F9-CFRH` | 128 | CONFIRM | none | remediation | ROUTE |
| `GHSA-QF5V-M7P4-95RP` | 130 | CONFIRM | none | remediation | ROUTE |
| `GHSA-R48C-V28R-PF6V` | 131 | CONFIRM | none | remediation | ROUTE |
| `GHSA-M63V-2G9W-2W6V` | 132 | CONFIRM | none | upgrade-b | ROUTE |
| `GHSA-WPXJ-VHFP-HHVM` | 134 | CONFIRM | none | remediation | ROUTE |
| `GHSA-P5RM-JG5C-8C77` | 136 | CONFIRM | none | upgrade-b | ROUTE |
| `GHSA-R9MR-M37C-5FR3` | 138 | CONFIRM | none | remediation | ROUTE |
| `GHSA-94P4-4CQ8-9G67` | 139 | CONFIRM | none | remediation | ROUTE |
| `GHSA-3RP5-JJMW-4WV2` | 141 | CONFIRM | none | remediation | ROUTE |
| `GHSA-539M-9XH6-Q6RR` | 142 | CONFIRM | none | remediation | ROUTE |
| `GHSA-P538-C434-8V24` | 143 | CONFIRM | none | remediation | ROUTE |

## CONFIRM/HIGH commit-only (not in the 48)

| GHSA | ordinal | verdict | missing gates | lane | status |
|---|---:|---|---|---|---|
| `GHSA-X2W7-XR2G-QHJR` | 152 | CONFIRM | none | remediation | ROUTE |
| `GHSA-X8QQ-M4QC-RPJ5` | 155 | CONFIRM | none | upgrade-b | ROUTE |
| `GHSA-G8MR-85JM-7XHM` | 157 | CONFIRM | none | remediation | ROUTE |

## NARROW cases by missing-gate count

| GHSA | ordinal | verdict | missing gates | lane | status |
|---|---:|---|---|---|---|
| `GHSA-5J8P-5RRJ-8WJG` | 88 | NARROW | identity_gate=NARROW, topology_gate=NARROW, but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-2JRP-274C-JHV3` | 101 | NARROW | identity_gate=NARROW, topology_gate=NARROW, but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-2CM6-R77W-6G96` | 103 | NARROW | identity_gate=NARROW, but_for_gate=NARROW, fix_reversal_gate=NARROW, release_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-QJ77-C3C8-9C3Q` | 28 | NARROW | topology_gate=NARROW, but_for_gate=NARROW, release_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-8JPQ-5H99-FF5R` | 31 | NARROW | topology_gate=NARROW, but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-3CVX-236H-M9FJ` | 33 | NARROW | but_for_gate=NARROW, fix_reversal_gate=NARROW, release_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-7C3W-FXGH-FRC7` | 52 | NARROW | identity_gate=NARROW, topology_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-JFV4-H8MC-JCP8` | 62 | NARROW | identity_gate=NARROW, topology_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-HHFF-FJ5F-QG48` | 71 | NARROW | identity_gate=NARROW, topology_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-W4H3-GPV2-82QC` | 77 | NARROW | identity_gate=NARROW, but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-VMW2-QWM8-X84C` | 79 | NARROW | topology_gate=NARROW, but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-4PQR-V6C3-X77J` | 82 | NARROW | topology_gate=NARROW, fix_reversal_gate=NARROW, release_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-RXXP-482V-7MRH` | 85 | NARROW | identity_gate=NARROW, but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-H4RQ-P45C-642R` | 87 | NARROW | topology_gate=NARROW, but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-X2XQ-QHJF-5MVG` | 91 | NARROW | topology_gate=NARROW, but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-WXW3-Q3M9-C3JR` | 97 | NARROW | topology_gate=NARROW, but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-VW3V-WHVP-33V5` | 102 | NARROW | topology_gate=NARROW, but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-W28W-GP39-M4P6` | 105 | NARROW | identity_gate=NARROW, topology_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-2HFG-4FH4-QP7F` | 199 | NARROW | identity_gate=NARROW, ai_hunk_gate=NARROW, release_gate=NARROW | remediation | ROUTE |
| `GHSA-PWF7-47C3-MFHX` | 3 | NARROW | but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-FWPR-59HH-GR98` | 5 | NARROW | identity_gate=NARROW, release_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-J4XF-96QF-RX69` | 8 | NARROW | topology_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-42M6-XH7C-6XM4` | 22 | NARROW | topology_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-2M67-CXXQ-C3H8` | 24 | NARROW | but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-Q9J6-XCVX-PX63` | 34 | NARROW | but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-GC24-PX2R-5QMF` | 37 | NARROW | identity_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-HFF7-CCV5-52F8` | 40 | NARROW | identity_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-Q447-RJ3R-2CGH` | 47 | NARROW | identity_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-C339-W3CQ-2RJR` | 55 | NARROW | identity_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-Q6QF-4P5J-R25G` | 60 | NARROW | identity_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-3636-3MQQ-Q7X9` | 61 | NARROW | identity_gate=NARROW, release_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-Q5PP-GVJG-H7V4` | 70 | NARROW | identity_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-RQPP-RJJ8-7WV8` | 80 | NARROW | but_for_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-7X5Q-8F6H-RJRC` | 86 | NARROW | topology_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-G5CG-8X5W-7JPM` | 95 | NARROW | topology_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-RQP8-Q22P-5J9Q` | 96 | NARROW | topology_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-5GVR-V6QV-H5MM` | 98 | NARROW | topology_gate=NARROW, fix_reversal_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-7GH7-258J-4MPQ` | 99 | NARROW | topology_gate=NARROW, release_gate=UNKNOWN | upgrade-a | ROUTE |
| `GHSA-C4M7-2GWP-VW76` | 100 | NARROW | topology_gate=NARROW, but_for_gate=NARROW | upgrade-a | ROUTE |
| `GHSA-WJHR-76VG-2HVC` | 108 | NARROW | topology_gate=NARROW, release_gate=UNKNOWN | upgrade-a | ROUTE |
| … | | | 44 more | | |

## UNKNOWN cases by missing-gate count

| GHSA | ordinal | verdict | missing gates | lane | status |
|---|---:|---|---|---|---|
| `GHSA-MF7V-X7R6-FQ57` | 153 | UNKNOWN | ai_hunk_gate=UNKNOWN, topology_gate=UNKNOWN, but_for_gate=UNKNOWN, fix_reversal_gate=FAIL, release_gate=UNKNOWN | upgrade-b | UNKNOWN |
| `GHSA-FP43-VJ7G-PG92` | 154 | UNKNOWN | ai_hunk_gate=UNKNOWN, but_for_gate=UNKNOWN, fix_reversal_gate=FAIL, release_gate=UNKNOWN | upgrade-b | UNKNOWN |
| `GHSA-8JQH-598V-RFXC` | 53 | UNKNOWN | identity_gate=NARROW, topology_gate=NARROW, release_gate=UNKNOWN | upgrade-a | UNKNOWN |
| `GHSA-48P8-G2FX-3WWM` | 129 | UNKNOWN | ai_hunk_gate=UNKNOWN, topology_gate=UNKNOWN, but_for_gate=UNKNOWN | upgrade-b | UNKNOWN |
| `GHSA-4MPW-WCJ4-V9PP` | 35 | UNKNOWN | ai_hunk_gate=UNKNOWN, but_for_gate=NARROW | upgrade-a | UNKNOWN |
| `GHSA-CGJ8-7M5Q-X5GV` | 116 | UNKNOWN | ai_hunk_gate=UNKNOWN, but_for_gate=UNKNOWN | upgrade-b | UNKNOWN |
| `GHSA-VJP8-WPRM-2JW9` | 51 | UNKNOWN | ai_hunk_gate=UNKNOWN | upgrade-a | UNKNOWN |
| `GHSA-8G98-M4J9-QWW5` | 56 | UNKNOWN | release_gate=UNKNOWN | upgrade-a | UNKNOWN |
| `GHSA-VH5J-5FHQ-9XWG` | 84 | UNKNOWN | release_gate=UNKNOWN | remediation | UNKNOWN |

## Novel GHSA identities absent from the 381-ID source set

These IDs appear in Aug-12 research result/report artifacts together with exact AI marker text or structured AI/commit fields, and they are not members of the fp211 381 public-ID set. They are **ROUTE** only. Deduplication is GHSA identity plus mechanism key; SHA overlap is recorded as a warning, not a merge.

Count: **14**. Absent from the stale local reviewed advisory-database: 6.

| GHSA | ordinal | verdict | missing gates | lane | status |
|---|---:|---|---|---|---|
| `GHSA-2G8C-6QFQ-528M` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-am | ROUTE |
| `GHSA-349P-3C3R-8MJR` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-nz | ROUTE |
| `GHSA-3M3Q-X3GJ-F79X` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-am | ROUTE |
| `GHSA-4HG8-92X6-H2F3` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-am | ROUTE |
| `GHSA-4RJ2-GPMH-QQ5X` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-nz | ROUTE |
| `GHSA-5FC8-GG7W-3G5C` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-am | ROUTE |
| `GHSA-75HX-XJ24-MQRW` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-am | ROUTE |
| `GHSA-8G7G-HMWM-6RV2` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-am | ROUTE |
| `GHSA-8MH7-PHF8-XGFM` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-am | ROUTE |
| `GHSA-FWGR-FPV9-VF5X` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-am | ROUTE |
| `GHSA-HC4M-Q9JH-XW4J` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-am | ROUTE |
| `GHSA-MFG5-7Q5G-F37J` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-am | ROUTE |
| `GHSA-P8RR-9CVG-CX5J` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-nz | ROUTE |
| `GHSA-RM2P-J3R7-4X4J` |  |  | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate, uniqueness_gate | fresh-nz | ROUTE |

## Overlap warnings

- 65 CONFIRM cases ≠ 51 CONFIRM/HIGH/all-gates ≠ 48 released-admitted. Start from 48. Gap ≥ 153.
- The 14 CONFIRM/MEDIUM cases are upgrade work, not part of the 48.
- Census upgrade-a/upgrade-b identity buckets are not the 58/48 assignment ordinals.
- Each first-party GHSA identity is routed once (231 IDs). Extra mechanism keys do not create extra routes. Shared SHAs do not merge IDs. The 231 census rows are not assigned research obligations.
- ChurchCRM ordinal 200 is two first-party GHSAs on one mechanism fingerprint.
- Local advisory-database HEAD `39d8887723797efc1804585dd06585c9fd751226` is 2026-07-23; 102 fp211 case GHSAs are absent from that clone. That absence is coverage UNKNOWN, not identity FAIL.
- STRICT_RELEASED source envelope 134 is not 134 admitted cases.
- Removed identities (5) stay REJECT.
- Upper bound if every NARROW, UNKNOWN, unreleased CONFIRM (14 MEDIUM + 3 commit-only), and novel row later closed all gates: 172. That bound is below 201 and is not a claim. Reaching >200 requires additional first-party GHSA identities beyond this inventory.

## Inputs hashed

See `result.json` `input_sha256`. Replay is `python3 autoresearch/herdr-260813-ghsa200-gap/build_inventory.py`.
