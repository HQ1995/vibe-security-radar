# AI fix slice 2 adjudication

## Verdict first

All 25 assigned rows are terminal and non-countable. Every `fix_ref` is presented by the local first-party GitHub-reviewed GHSA object as a closing patch for a vulnerability that predates that commit. AI-authored final fixes are `REJECT_AI_FIX_ONLY`. Promisor blob fetch failed for every pool (`Could not resolve host: github.com`), so `ai_hunk_gate` and `fix_reversal_gate` stay `UNKNOWN`. No row is `AI_INCOMPLETE_REMEDIATION` or `AI_NEW_SURFACE_CONTRIBUTOR`. Countable proposals: 0. `original_vulnerability` is null on every row.

13 rows carry an explicit Copilot/Claude/agent/AI-assisted marker, all on the closing patch. The remaining rows are human authors, generic coauthor trailers, an authentik automation backport, or a Gemini review-bot trailer. `GHSA-8J7F-G9GV-7JHC` is withdrawn as a duplicate of `GHSA-RHFG-J8JQ-7V2H` and fails identity and uniqueness. Canonical84 overlap is empty. Publication remains HOLD. Greater-than-200 remains unsupported.

Closest disagreements, all still rejected:

- `GHSA-RHFG-J8JQ-7V2H` / withdrawn twin `GHSA-8J7F-G9GV-7JHC` (openclaw): advisory title says incomplete fix of CVE-2026-28476, but the assigned SHA `f92c92515` is the named closure of this GHSA, not residual proof.
- `GHSA-VM8Q-M57G-PFF3` (django): incomplete older Truncator fixes are historical; `072963e4` is the named CVE-2024-27351 closer.
- `GHSA-XJ37-QJG2-XWV2` (qinglong): Copilot authored the assigned SHA, but the GHSA names it as the /open/user/init guard.
- `GHSA-379Q-355J-W6RJ` (pnpm): `blockExoticSubdeps` is a feature-shaped closer, still the named patch rather than a new introducing surface.
- Shared SHA `f92c92515` across rows 17-18 is uniqueness failure only on the withdrawn duplicate identity.

## Gate accounting

Gate order is identity / AI hunk / topology / but-for / fix reversal / release / uniqueness. Unclosed gates remain UNKNOWN.

| Gate | PASS | FAIL | UNKNOWN | Decisive boundary |
| --- | ---: | ---: | ---: | --- |
| `identity_gate` | 24 | 1 | 0 | Withdrawn duplicate fails. |
| `ai_hunk_gate` | 0 | 0 | 25 | Diffs unavailable; unclosed. |
| `topology_gate` | 25 | 0 | 0 | Commit object present in sweep-fetch pool. |
| `but_for_gate` | 0 | 25 | 0 | Named closer is not the introducing hunk. |
| `fix_reversal_gate` | 0 | 0 | 25 | Reversal not executed; unclosed. |
| `release_gate` | 0 | 25 | 0 | Candidate is the named patch, not a residual in a vulnerable release. |
| `uniqueness_gate` | 24 | 1 | 0 | Withdrawn duplicate fails. |

## Per-row decisions

| n | case_id | verdict | class | marker |
| ---: | --- | --- | --- | --- |
| 1 | `GHSA-RXPR-WQ63-JR7P` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | `SCANNER_FALSE_POSITIVE_GENERIC_COAUTHOR_TRAILER` |
| 2 | `GHSA-2WW6-868G-2C56` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | `SCANNER_FALSE_POSITIVE_GENERIC_COAUTHOR_TRAILER` |
| 3 | `GHSA-HHJV-JQ77-CMVX` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 4 | `GHSA-XJ37-QJG2-XWV2` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 5 | `GHSA-86HP-QXQP-W9WV` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | `SCANNER_FALSE_POSITIVE_GENERIC_COAUTHOR_TRAILER` |
| 6 | `GHSA-2R69-QGV3-HR65` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 7 | `GHSA-V8VW-GW5J-W7M6` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 8 | `GHSA-HVQH-JW65-WCPQ` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 9 | `GHSA-C3M2-JQMQ-PVP3` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | `SCANNER_FALSE_POSITIVE_GENERIC_COAUTHOR_TRAILER` |
| 10 | `GHSA-4J28-22QP-RJCF` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 11 | `GHSA-MJ4X-VF5C-5XG8` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 12 | `GHSA-9M6G-WC8R-Q59C` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | `SCANNER_FALSE_POSITIVE_REVIEW_BOT` |
| 13 | `GHSA-VV7Q-7JX5-F767` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 14 | `GHSA-RM43-82J9-R4MJ` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 15 | `GHSA-379Q-355J-W6RJ` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | `SCANNER_FALSE_POSITIVE_GENERIC_COAUTHOR_TRAILER` |
| 16 | `GHSA-P8P7-X288-28G6` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | `SCANNER_FALSE_POSITIVE_GENERIC_COAUTHOR_TRAILER` |
| 17 | `GHSA-RHFG-J8JQ-7V2H` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 18 | `GHSA-8J7F-G9GV-7JHC` | `REJECT_AI_FIX_ONLY` | `WITHDRAWN_DUPLICATE_FINAL_CLOSURE_EXPLICIT_AI_MARKER` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 19 | `GHSA-G2HM-779G-VM32` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 20 | `GHSA-VM8Q-M57G-PFF3` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | `SCANNER_FALSE_POSITIVE_GENERIC_COAUTHOR_TRAILER` |
| 21 | `GHSA-R836-HH6V-RG5G` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | `SCANNER_FALSE_POSITIVE_GENERIC_COAUTHOR_TRAILER` |
| 22 | `GHSA-FXR3-GVM4-M8VC` | `REJECT_AI_FIX_ONLY` | `AI_AUTHORED_FINAL_CLOSURE_EXCLUDED` | `EXPLICIT_AI_MARKER_ON_CLOSING_PATCH` |
| 23 | `GHSA-MR6F-H57V-RPJ5` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | `SCANNER_FALSE_POSITIVE_GENERIC_COAUTHOR_TRAILER` |
| 24 | `GHSA-4MMR-2W8P-WHCR` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | `SCANNER_FALSE_POSITIVE_GENERIC_COAUTHOR_TRAILER` |
| 25 | `GHSA-FR3W-2P22-6W7P` | `REJECT_AI_FIX_ONLY` | `FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER` | `SCANNER_FALSE_POSITIVE_GENERIC_COAUTHOR_TRAILER` |

Timebox packet. Worker did not commit, push, or edit tracked/canonical files. English only.
