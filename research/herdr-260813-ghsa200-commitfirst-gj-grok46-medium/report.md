# G-J commit-first GHSA discovery

**Status: TERMINAL / HOLD. Proposed PASS = 1. Countable PASS = 0. REJECT = 29.**

Worker PASS is a proposal only. The Gogs row stays uncounted until leader admission.

Bound to leader `CONTRACT.md` SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc` from commitfirst-gn freeze.
Independence: first-party github-reviewed JSON, frozen G-N assignment/scans, and clones under `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn`. Sibling worker conclusions were not used as causal evidence. Shared tracked files were not edited. No commit, push, or credential output.

## Provenance (two hashes, two roles)

The reviewed population is the frozen G-N novel assignment, owner G-J, minus identities already in frozen G-N `cases.jsonl`. It is **not** re-derived from the current publication file.

- **Frozen GN selection:** `publication_adjudications.json` SHA-256 `bfec060f7705014d11e58dc386294264eac47027cd64d3b934a17422bb1be7a6` from commitfirst-GN `freeze.json`. That exclusion hash built `assigned.jsonl`.
- **Current overlap check:** live `scripts/publication_adjudications.json` SHA-256 `9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f` after commit `5620e01`. `GHSA-6P9M-Q3JP-47H4` is absent from that live GHSA set. This check does not change the frozen denominator.

## Conservation (30/995)

| Set | Count |
|---|---:|
| G-N assigned (frozen novel) | 2577 |
| G-J assigned | 1072 |
| G-J already in frozen G-N `cases.jsonl` | 47 |
| G-J unreviewed pool before this shard | 1025 |
| Reviewed here | 30 |
| Remaining UNREVIEWED | 995 |

Proven equalities: 47 + 1025 = 1072; 30 + 995 = 1025.

Exact SHA G-J intersections remaining in the unreviewed slice were 0. Remaining G-J rows outside these 30 are UNREVIEWED, not REJECT.

## Terminal outcomes

| Worker verdict | Rows |
|---|---:|
| PASS (proposal only, uncounted) | 1 |
| REJECT | 29 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| UNREVIEWED | 995 |

### Proposed PASS

**GHSA-6P9M-Q3JP-47H4** / `CVE-2026-52812` (`gogs/gogs`) — `AI_INCOMPLETE_REMEDIATION`.
Claude-marked PR #8166 members added the LFS exist/dedupe shortcut that binds an OID without hashing the body. `v0.14.2` contains blob `b53522f10a33f5021b005c6577a8492ecd1202fc`. `v0.14.3` hashes that shortcut via cherry-pick `e2fae5d0455d4f92c6382433d21c3a16da077d64` of `f35a767af74e05342bafc6fdda02c791816426f8`. Mainline squash `81ee8836445ac888d99da8b652be7d5cbc5c4d5c` is not a git ancestor of tag `v0.14.2`; containment is blob/patch-id identity on the release line.

## Claim boundary

- Countable PASS requires all seven gates and leader admission.
- Proposed PASS: **1**. Countable PASS: **0**.
- REJECT applies only to the 29 reviewed non-PASS rows. The other 995 G-J rows are UNREVIEWED.
