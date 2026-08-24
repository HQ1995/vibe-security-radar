# Marker A25 adjudication (canonical85)

Verdict first: **0 PASS_PROPOSAL**. **21 REJECT**. **4 UNKNOWN**. Assigned **25**, reviewed **25**, unreviewed **0**. Conservation `25=25+0`. Packet delta **0**. Canonical85 stays **85**. Publication and more-than-200 remain **HOLD**. Worker PASS is proposal-only and this packet emits none.

This is not a recall task. Each assigned identity is terminal PASS_PROPOSAL, REJECT, or UNKNOWN. The prefilter routed an exact AI marker on an advisory-listed SHA. That marker is routing, not causality.

## Routed-SHA roles

Every routed SHA is an advisory-listed fix object. None is an origin or prior security-attempt hunk of a residual that this packet can count.

- closer (atomic named commit): 20
- closer_test: 1 (GHSA-FP43)
- closer_carrier_merge_from_fork: 4 (GHSA-48P8, GHSA-7RQJ, GHSA-V2HH, GHSA-PF56)

Do not transfer squash trailers to human members. Do not treat an AI closer as origin. PASS_PROPOSAL requires all seven gates exactly PASS.

## Sources (read-only)

- Canonical85 ledger sha256 `2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568`
- Canonical85 summary sha256 `47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c`
- Canonical85 manifest sha256 `5781078c8b286a454b647c84447fa8c9ff4dc2068f3c45acb45acddb50167abd`
- Prefilter candidates.jsonl sha256 `d2fca17de6592ebea84f38c49f791dc516a0be6e47b56912de91343a71f798b0`
- Advisory-database cache used by the prefilter: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` (read-only)
- Shared worker clones under `/home/hanqing/.cache/ghsa200-worker-clones/` (read-only). GIT_NO_LAZY_FETCH=1. No GitHub REST API.
- No owned temporary clones were created. No pages were fetched into the owned directory.

## Conservation

- Assigned ordinals 1-25 from the prefilter candidates.jsonl
- Reviewed 25
- Unreviewed 0
- Equation 25=25+0
- Already-terminal IDs were not dropped. Source refs are on each row.
- Did not pad, drop, or invent assigned identities.
- Assigned identities absent from canonical85 strict 85: 25

## Already-terminal source refs

| Ordinal | ID | Prior | This packet |
| --- | --- | --- | --- |
| 1 | GHSA-48P8-G2FX-3WWM | fresh-strict UNKNOWN | UNKNOWN |
| 2 | GHSA-WVPP-8HX9-P66J | fresh-strict REJECT uniqueness vs R9MR | REJECT |
| 4 | GHSA-HH9P-6WH2-4MFC | canonical85 PRESERVE | REJECT (AI closer) |
| 5 | GHSA-9RJ7-RF2P-W77R | canonical85 PRESERVE | REJECT (AI closer) |
| 6 | GHSA-4GMW-GG2M-W46P | canonical85 PRESERVE | REJECT (AI closer) |
| 10 | GHSA-P538-C434-8V24 | canonical85 NARROW not counted | REJECT (routed SHA is closer) |
| 11 | GHSA-3F7W-8RR8-F37F | canonical85 PRESERVE; SHA counted as 3WXW origin | REJECT |
| 14 | GHSA-FP43-VJ7G-PG92 | fresh-strict REJECT AI closer | REJECT |
| 16 | GHSA-94P4-4CQ8-9G67 | canonical85 NARROW not counted | REJECT (routed SHA is closer) |
| 17 | GHSA-6P8H-3WGX-97GF | canonical85 PRESERVE | REJECT |
| 18 | GHSA-FJR4-X663-MWXC | canonical85 PRESERVE | REJECT |

NARROW is not an allowed terminal in this packet. Uncounted NARROW rows are REJECT because the routed SHA is the closer.

## UNKNOWN (4)

Merge-from-fork closer carriers. Member mapping is unrecovered. Unclosed gates stay UNKNOWN.

| ID | Routed SHA | Why UNKNOWN |
| --- | --- | --- |
| GHSA-48P8-G2FX-3WWM | 277e9cef0ad1 | Claude trailer on squash-from-fork closer; cherry-pick 08763d1c missing; prior UNKNOWN preserved |
| GHSA-7RQJ-J65F-68WH | 19d2feb24359 | Claude trailer on squash-from-fork closer; sibling a63eee12 same pattern |
| GHSA-V2HH-GCRM-F6HX | 0542a216860f | Claude trailer on squash-from-fork; Matteo Collina atomic SHAs are not the routed object |
| GHSA-PF56-329R-95RW | 85c58380758b | Copilot trailer on squash-from-fork closer |

## REJECT (21)

ai_hunk_gate FAIL: the routed AI-marked SHA is this advisory's closer (or a closer test), not origin/security-attempt ownership of the vulnerable surface.

| Ord | ID | Role | Extra FAIL |
| --- | --- | --- | --- |
| 2 | GHSA-WVPP-8HX9-P66J | closer | uniqueness vs counted R9MR |
| 3 | GHSA-HMQ2-W58F-27JC | closer | |
| 4 | GHSA-HH9P-6WH2-4MFC | closer | |
| 5 | GHSA-9RJ7-RF2P-W77R | closer | |
| 6 | GHSA-4GMW-GG2M-W46P | closer | |
| 7 | GHSA-F6WF-28G6-769X | closer | |
| 8 | GHSA-2Q4P-G7HV-5RGV | closer | |
| 9 | GHSA-29PJ-957V-52MC | closer | |
| 10 | GHSA-P538-C434-8V24 | closer | |
| 11 | GHSA-3F7W-8RR8-F37F | closer | uniqueness vs counted 3WXW |
| 12 | GHSA-34RH-WP3J-6CXC | closer | |
| 13 | GHSA-XGR6-PQJV-3PF8 | closer | |
| 14 | GHSA-FP43-VJ7G-PG92 | closer_test | |
| 15 | GHSA-P6PH-3JX2-3337 | closer | |
| 16 | GHSA-94P4-4CQ8-9G67 | closer | |
| 17 | GHSA-6P8H-3WGX-97GF | closer | uniqueness vs 539M/R9MR |
| 18 | GHSA-FJR4-X663-MWXC | closer | uniqueness vs 701ce32 family |
| 20 | GHSA-7488-6R32-C95Q | closer | |
| 22 | GHSA-RWJ8-PGH3-R573 | closer | |
| 23 | GHSA-956X-8GVW-WG5V | closer | uniqueness vs R9MR/539M on 701ce32 |
| 24 | GHSA-2F96-G7MH-G2HX | closer | uniqueness vs R9MR family |

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 85. Only leader-reviewed rows with all seven gates PASS enter that bound after independent hostile red-team. This packet did not edit canonical85 and does not support a greater-than-200 claim.

Owned temporary clones and fetched pages: none created, none left. Canonical ledger was not edited. No commit or push.

