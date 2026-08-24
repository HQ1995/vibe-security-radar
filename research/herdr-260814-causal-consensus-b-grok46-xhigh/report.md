# Adversarial official-GHSA consolidation B

Verdict first: **2 PASS_PROPOSAL**. Frozen **12**. Reviewed **12**. Unreviewed **0**. Equation **12=12+0**. **10 REJECT**. **0 NARROW**. Causal-only six-gate rows **0**. Did not pad. Canonical strict count remains **88 HOLD**. Publication and more-than-200 remain unsupported. Worker PASS is proposal only.

Scoped-contributor reopen inside this packet tested exactly GHSA-6C8G-7P36-R338, GHSA-PQH8-P93P-2RX7, and GHSA-XMXX-7P24-H892. CONTRACT.md but_for PASSes when removing the AI change eliminates or materially shrinks the exact counted scope. Older sibling mechanisms were not required to vanish. The other nine frozen12 rows are unchanged. Inherited PASS and same-model agreement are not used.

## Sources

- github-reviewed: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` (34389 files)
- unreviewed lookup only: `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226`
- CONTRACT.md `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- canonical88 ledger `35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074`
- canonical88 summary `81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921`

Pointer scan of herdr-260813 and herdr-260814 terminal case files, excluding inventory packets and this directory: 8165 GHSA IDs. After canonical88, withdrawn, missing candidate or fix, candidate-equals-fix, and no official GHSA: 902 ranked. Freeze cap 12. Shortfall 0.

## Frozen twelve

PASS_PROPOSAL requires exact PASS on identity, AI hunk, topology, but-for, complete minimum fix reversal, uniqueness, and release containment.

1. GHSA-3RMJ-9M5H-8FPV REJECT. Claude merge-into-next edits encrypted componentExport. Closer adds serverIslandBodySizeLimit. Same-file routing.
2. GHSA-C32J-VQHX-RX3X REJECT. Copilot ruby-head compatibility. Overlap with HMAC closer is CHANGELOG and version.rb only.
3. GHSA-FQ7H-9X26-6J22 REJECT. Copilot license-header megapatch. Validator overlap is copyright text. Closer adds privileged-template rejection. Tags v2.4.0 / v2.4.1 exist and still do not make origin.
4. GHSA-M98R-6667-4WQ7 REJECT. Claude worker-architecture cleanup names dead re-exports in runs.py. Closer enforces thread ownership. Parent blobs are promisor-missing; the candidate message still rejects origin.
5. GHSA-PQH8-P93P-2RX7 PASS_PROPOSAL. Copilot-swe-agent, n_parents=1, adds unvalidated `from: now()-${timeframe}` to list-vulnerabilities and get-events-for-cluster, both named in the GHSA table. Parent lacks that parameter on those two files. Closer 15d3546c0618 calls validateTimeframe on both. Tags v2.1.0 / v2.1.1 pair. Sibling additionalFilter and clusterId remain out of scope.
6. GHSA-X2HW-PX52-WP4M REJECT. Bn254 Fr without reduction is new in squash #1667, but the commit has seven human or bot trailers including Copilot. Atomic AI hunk authorship fails. Tags v25.0.0 / v25.3.0 pair.
7. GHSA-W85G-3H6X-4XH2 REJECT. Claude adds EXIF orientation. Parent already runs sips. Closer adds pixel caps. Named tag v2026.3.31 does not contain the candidate in this clone.
8. GHSA-6C8G-7P36-R338 REJECT. Named failing gate is ai_hunk_gate, not whole-advisory persistence. Candidate 8b95e0a76d6b adds WriteToDirectoryAsync on IArchiveExtensions.cs and does not contain WriteToDirectoryAsyncInternal. Human b501bac54ae3 adds IAsyncArchiveExtensions.cs as a new file. Deleting the AI commit does not eliminate the advisory-named Internal branch. Tags 0.43.0 / 0.48.0 still pair the candidate and closer.
9. GHSA-G3VG-VX23-3858 REJECT. Claude hatch migration. Overlap with the closer is cache.py formatter wrap only; closer adds security.py.
10. GHSA-H2VW-PH2C-JVWF REJECT. Claude TTS reads MINIMAX_API_HOST. Parent VLM already reads that env. New caller of old host override. Named tag v2026.4.20 does not contain the candidate.
11. GHSA-J6V5-G24H-VG4J REJECT. Copilot Feat/modules. Parent already has pkg/stdlib/io/fs/write.go. Closer is Feat/fs sandbox. Tags v2.0.0-alpha.3 / v2.0.0-alpha.4 pair.
12. GHSA-XMXX-7P24-H892 PASS_PROPOSAL. Claude-coauthored atomic commit adds /v1/responses and passes startup resolvedAuth into authorizeGatewayConnect. Parent lacks that file. Closer acd4e0a32f12 re-resolves via getResolvedAuth() per request, including the openresponses stage. Tag v2026.4.14 contains the candidate and excludes the closer. Tag v2026.4.15 contains the closer. Parent Chat Completions stale snapshot remains out of scope.

## Causal-only six-gate rows

None. The two PASS_PROPOSAL rows close all seven gates, including release. No frozen row has six causal gates PASS with release not PASS. Six-gate inventory from other packets is not inherited.

## Claim boundary

Proposal count 2. Canonical 88 untouched. No commit, push, tracked edits, durable clones, pages, or helper scripts in the owned directory. Prefer zero false positives: 6C8G was not upgraded.

Status TERMINAL.
