# GHSA 200+ commit-first O-Z

**Status: PARTIAL / HOLD. 0 PASS proposals.**

Bound to leader `CONTRACT.md` SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.

Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc` equals `origin/main` at fetch. Worker PASS is a proposal, never admission. This shard proposes no admissions.

Leader issued a bounded-stop. The owned matcher `confirm_match.py` (shell pid 2557804) stalled on `vllm-project/vllm` (ordinal 657/743) and was terminated. It wrote no durable intersections. Broad ancestry scans were not resumed. Unreviewed novel IDs are UNKNOWN or BLOCKED. No row is an implicit REJECT.

## Conservation

Campaign window: published date >= 2025-05-01. First-party iff the official reviewed JSON references `github.com/{owner}/{repo}/security/advisories/GHSA-*`. This shard is owner first character O-Z or non-letter (casefold).

| Population | Count |
|---|---:|
| Window first-party active | 8757 |
| A-N active | 5046 |
| O-Z active | 3680 |
| Other (digit/non-letter) active | 31 |
| This shard (O-Z + other) | 3711 |
| Excluded (fp211 public cases / current corpus) | 88 |
| Novel in-scope | 3623 |

Proven equalities:

- 5046 + 3680 + 31 = 8757
- 3680 + 31 = 3711
- 88 + 3623 = 3711
- missing-owner first-party rows = 0

Exclusion set was computed from fp211 `public_cases.jsonl`, `public_id_dispositions.jsonl`, `scripts/publication_adjudications.json`, and `web/data` IDs. Sibling worker conclusions were not used as evidence.

## Terminal outcomes

| Verdict | Count | Meaning |
|---|---:|---|
| PASS | 0 | No seven-gate admission |
| REJECT | 0 | No completed origin REJECT |
| UNKNOWN | 2151 | Clone and official fix SHA present; review stopped |
| BLOCKED | 1472 | No official fix SHA (1470) or clone failed (2) |
| **Total** | **3623** | Every novel shard ID has a terminal row |

Coverage: denominator freeze COMPLETE; clones 741/743; AI grep 743 repos (routing only); seven-gate closed rows 0. Matcher durable intersections 0. Stalled process/repo is a blocker, not a REJECT.

AI grep over 741 successful clones found 30666 trailer/author hits in 449 repos. That is routing only.

Incomplete-remediation patch-delta was not applied because no rem row was opened. Origin and contributor but-for are unchanged.

## What was frozen and what was not

Completed: source revision, exclusion freeze, owner-partition conservation, novel ID list, repo clones into `/home/hanqing/.cache/ghsa200-worker-clones/commit-oz`, and a first-pass AI-marker grep.

Not completed: confirmed AI-hunk identity, member topology, minimum-fix reversal, release containment, and rem patch-delta. Those gates stay UNKNOWN or BLOCKED.
