# Near-closed released wave B

TERMINAL. Assigned 3, reviewed 3, PASS_PROPOSAL 2, REJECT 1. Conservation 3=3+0. Canonical88 remains 88 HOLD. Packet delta 0. No causal or publication admission.

This packet independently reopened fp211 ordinals 29 and 30 under the scoped-contributor rule and left ordinal 74 unchanged. A contributor need not eliminate the whole advisory. It must materially shrink a precisely named covered mechanism, and the exact released fix must reverse that new surface. Worker PASS is proposal-only.

## Per case

1. GHSA-XMXX-7P24-H892 ordinal 29 PASS_PROPOSAL. Reviewed first-party GHSA names Gateway HTTP handlers that captured resolved bearer auth at start. Claude f4b03599 adds POST /v1/responses. Parent lacks that file and handler. v2026.4.14 ships handleOpenResponsesHttpRequest with captured resolvedAuth. Default-off matches parent Chat Completions and does not remove the shipped HTTP surface. Deleting f4b03599 removes that advisory-covered HTTP surface. Closer acd4e0a32 calls getResolvedAuth() before the openresponses stage. Contained in v2026.4.14 / fixed v2026.4.15. Parent Chat Completions and WebSocket capture are out of scope.

2. GHSA-PQH8-P93P-2RX7 ordinal 30 PASS_PROPOSAL. Reviewed first-party GHSA table names list-vulnerabilities.ts:19 timeframe and get-events-for-cluster.ts:20 timeframe. Copilot 66ff2a7c adds those interpolations. Parent lacks now()-${timeframe} on those two files. Deleting 66ff2a7c removes those two advisory-covered surfaces. Closer 15d3546c applies validateTimeframe to both files. list-vulnerabilities blob 57a674e6 is identical at candidate and v1.2.0. Contained in v1.2.0 / fixed v2.1.1. Parent list-problems/list-exceptions timeframe, entityNames, and get-events clusterId are out of scope.

3. GHSA-4524-X6PC-RR9X ordinal 74 REJECT unchanged. Unreviewed global GHSA with empty affected[] and no repository advisory. Named closer 234d9aad is realpathSync only. Absolute /etc/passwd still canonicalizes to a readable path. Incomplete closer is REJECT.

## Uniqueness

None of the three are in canonical88 strict_released_case_ids (88, including GHSA-8RW6-P7M8-63JP). CVE aliases are stored and not counted. The two proposals use narrowed mechanism keys and do not merge with other openclaw or dynatrace identities.

## Boundary

Worker PASS is proposal-only. This packet proposes GHSA-XMXX-7P24-H892 and GHSA-PQH8-P93P-2RX7 and does not admit them to the canonical ledger. This packet did not edit canonical ledgers, did not commit or push, and did not store durable pages, clones, packages, or caches.
