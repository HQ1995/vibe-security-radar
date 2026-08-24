# AI route-surface20 terminal report

Verdict: freeze 1. Deep review 1 REJECT. PASS_proposal 0. packet_delta 0. Canonical strict count remains 82.

## Counts

- Start strict count: 82
- Current leader-accepted strict count: 82
- Canonical82 ledger sha256: 58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23 at commit 6800d2127c19532160cc88880115ae28cc446aa5
- Scan: 12817 github-reviewed 2025-2026; 7574 first-party after exclusion in window; 3603 with exact same-repo fix commits; 1 surface hit
- Cross-lane mechanical exclusion: 14 fixblame20x selected IDs and 20 residual-security20 selected IDs, regardless of outcomes
- Exact frozen IDs: GHSA-73HC-M4HX-79PJ
- PASS proposals: none
- REJECT: GHSA-73HC-M4HX-79PJ
- Padding: none

## Cross-lane exclusion hashes

- fixblame20x selected.jsonl sha256: 344761d2c9c683ee6bf2b451f79b70b9e0b12802f037f972e8b159dc9b20f43e
- residual-security20 selected.jsonl sha256: f179f86d9097f71a0d632b2ea572dba0d1f6b1bb16743a332f331f66af6aba3f
- This lane selected ID is in neither set.

## Seven-gate review

GHSA-73HC-M4HX-79PJ is first-party doobidoo/mcp-memory-service. The advisory names unauthenticated GET /api/health/detailed system information and database_path disclosure, plus unauthenticated GET /health. Claimed AI commit fd2bbf49 is atomic and Claude-marked, but it adds sibling GET /memory-stats and POST /clear-caches. Parent be7c5b95 already had /health and /health/detailed. Those routes were first added by 4e796e28 with no AI marker. The later first-party fix 18f4323c closes the pre-existing health disclosure. Removing the AI sibling route does not eliminate the advisory mechanism. Uniqueness vs canonical82 holds. identity_gate PASS, uniqueness_gate PASS, all other gates FAIL. reject_class SIBLING_ROUTE_PARENT_HAD_EQUIVALENT_ENTRYPOINT.

A pre-existing vulnerable shared helper would not by itself reject, but here the parent already had the equivalent reachable health entrypoint. That is not AI new-surface causality.

## Claim boundary

This packet does not admit cases. Canonical count is unchanged at 82. Publication and a greater-than-200 claim remain unsupported. Worker PASS is a proposal only; this packet emits none. Independent hostile red-team plus leader acceptance would still be required before any count change.
