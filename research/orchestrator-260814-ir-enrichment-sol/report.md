# Original-vulnerability enrichment report

## Result

The enrichment conserves all 51 foundation rows: 1 row has every requested field and 50 rows are partial. The input count includes 49 `AI_INCOMPLETE_REMEDIATION` rows and 2 `AI_INCOMPLETE_REMEDIATION_COMMIT_ONLY` rows, which is the only interpretation that matches the specification's stated 51-row boundary.

## Method

Each selected foundation line was retained byte-for-byte through the byte immediately before its closing brace, then the `original_vulnerability` and `missing_fields` members were appended. Candidate and minimum-fix SHA arrays come directly from the foundation. Descriptions were bounded to the fp211 final rows, canonical84 ledger, and named Batch B-G documents. The requested Batch A document is absent. The 248 rows in the named `incomplete-remediation20*` worker packets have no direct `case_id` overlap with this slice, so none was used as row evidence. Missing original advisories, introducing commits, and pre-attempt artifacts remain null.

## Missing-field census

| Field | Missing rows |
|---|---:|
| `original_advisory_ids` | 1 |
| `original_mechanism` | 0 |
| `original_sink` | 0 |
| `original_introducing_commit` | 50 |
| `vulnerable_artifact` | 44 |
| `attempted_remediation` | 0 |
| `residual_bypass` | 0 |
| `final_closure` | 0 |
| `evidence_paths` | 0 |

## Per-row gaps

| Case | Coverage | Missing fields |
|---|---|---|
| `GHSA-2944-57XV-2682` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-2HFG-4FH4-QP7F` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-2X93-H3HG-2XFP` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-3FP5-V549-9V66` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-3RP5-JJMW-4WV2` | partial | `original_introducing_commit` |
| `GHSA-3WXW-XV34-2FRG` | partial | `original_introducing_commit` |
| `GHSA-425G-FJHQ-5H92` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-4FXP-2M36-QV64` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-4MR5-G6F9-CFRH` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-539M-9XH6-Q6RR` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-56C3-VFP2-5QQJ` | partial | `original_advisory_ids`, `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-5C6W-WWFQ-7QQM` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-5C7W-4WM3-85VW` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-5RV5-XJ5J-3484` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-5WP8-Q9MX-8JX8` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-5XXX-QHH7-9287` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-6P9M-Q3JP-47H4` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-6Q7J-XR26-3H2C` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-7JX6-764P-FGG9` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-7P8R-X3MC-P8W7` | partial | `original_introducing_commit` |
| `GHSA-8882-FRVV-92W4` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-8WC8-HF36-MJH9` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-93Q6-WWJH-JC6H` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-94P4-4CQ8-9G67` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-9C3V-684M-579C` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-F2FQ-4RMP-9X8C` | complete | - |
| `GHSA-F38V-77QJ-H4JQ` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-FVVP-RJ8G-C7GC` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-G8MR-85JM-7XHM` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-HC8V-WWC9-VGXM` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-J4CX-JVQ7-79VM` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-J5QP-P44G-2M49` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-JM78-9FVV-MHGR` | partial | `original_introducing_commit` |
| `GHSA-M4WX-M65X-GHRR` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-M63V-2G9W-2W6V` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-MV93-W799-CJ2W` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-P538-C434-8V24` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-P5RM-JG5C-8C77` | partial | `original_introducing_commit` |
| `GHSA-PMCH-G965-GRMR` | partial | `original_introducing_commit` |
| `GHSA-PV2J-RGHR-V5R9` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-Q6RR-FM2G-G5X8` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-Q9PG-JJ6X-J9P6` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-QF5V-M7P4-95RP` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-QJPC-QF9M-XWMR` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-R48C-V28R-PF6V` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-R9MR-M37C-5FR3` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-V396-V7Q4-X2QJ` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-VC8F-X9PP-WF5P` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-WP73-F3GG-W4VR` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-WPXJ-VHFP-HHVM` | partial | `original_introducing_commit`, `vulnerable_artifact` |
| `GHSA-X2W7-XR2G-QHJR` | partial | `original_introducing_commit`, `vulnerable_artifact` |

## Examples

- `GHSA-F2FQ-4RMP-9X8C` is complete: Batch F identifies the earlier login-regression advisory, its AI introducing commit, the affected ChurchCRM releases, the incomplete restoration, the bad-OTP residual, and the two-part final closure.
- `GHSA-PMCH-G965-GRMR` is partial: the canonical ledger identifies the earlier COPY PROGRAM advisory and pre-AI `langroid 0.62.0` artifact, but no frozen source identifies the commit that first introduced that original SQL execution surface.
- `GHSA-6P9M-Q3JP-47H4` is partial: the canonical mechanism key and release edge support the LFS deduplication residual and closure, but no named frozen source identifies a pre-attempt version or original introducing commit.

## Boundary

This output is an evidence overlay only. Nulls are unresolved local-source gaps, not negative findings, and no row changes the foundation verdict, count, or canonical ledger.
