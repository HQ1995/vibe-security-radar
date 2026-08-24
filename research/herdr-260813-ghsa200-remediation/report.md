# GHSA 200+ remediation lane

**Verdict: 0 PASS proposals on 19 adjudicated new IDs.** Worker PASS is only a proposal. COMPLETE applies only to that bounded set. This lane does not claim ecosystem coverage.

## What the verifier may consume

| row_role | N | seven_gate_row | In reviewed totals |
| --- | ---: | --- | --- |
| `ADJUDICATED_NEW_ID` | 19 | true | yes (all REJECT) |
| `CROSS_REVIEW_ROUTE` | 15 | false | no |
| `SCREENED_NOT_ADJUDICATED` | 5 | false | no |

The 15 existing fp211 rem identities are cross-review routes only. Their seven gate fields are omitted. The unified verifier must not treat them as seven-gate rows from this worker.

The 5 dump-keyword screens (2MQJ, 8HJW, RG5Q, 6G6R, XCMW) are also omitted from reviewed totals and are not seven-gate consumable.

## Reviewed set (19 new IDs, all REJECT)

Residual kinds inside the 19:

| Kind | N | Meaning |
| --- | ---: | --- |
| `AI_CREATED_RESIDUAL` | 2 | AI rem/revert created a named bypass the parent did not have |
| `OLD_VULN_LEFT_INCOMPLETE` | 11 | Named hole already existed in the parent |
| `NOT_REMEDIATION` | 6 | Original vuln, AI-as-fixer, new surface, or pre-coverage reintroduction |

The two created-residual rows are still not PASS:

- GHSA-WVPP-8HX9-P66J: GPT `e8d0fbf7` carved out the unsplit path. Same series as already-counted R9MR. `ROUTE_CONFLICT` with fresh-am.
- GHSA-P8RR-9CVG-CX5J: Claude `61ff20fe` re-allows private/loopback. Unreviewed identity; 3.2.8 closer still allows private/loopback. `ROUTE_CONFLICT` with fresh-am.

The other 17 are leftover old holes, originals, or new-surface (JXX9). None close all seven gates as a countable rem/reintro admission.

## Counts the verifier should use

| Bucket | N |
| --- | ---: |
| Reviewed / adjudicated new IDs | 19 |
| PASS proposals | 0 |
| REJECT | 19 |
| Cross-review routes (excluded) | 15 |
| Screened, not adjudicated (excluded) | 5 |
| Emitted rows on disk | 39 |

## Cross-review routes (not reviewed here)

Preserve fp211 verdicts. upgrade-a owns ordinal 84. upgrade-b owns 126 and 169-199. This lane does not propose PASS and does not emit seven-gate values for those identities.

## Terminal state

`result.json` status is COMPLETE for `completeness_scope=bounded_adjudicated_new_ids` only. `ecosystem_coverage_claimed` is false.
