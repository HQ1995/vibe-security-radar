# Near-closed released wave H

TERMINAL. Assigned 3, reviewed 3, PASS_PROPOSAL 1, NARROW 2. Conservation 3=3+0. Canonical90 remains 90 HOLD. Packet delta 0. No causal or publication admission.

This packet independently reopened fp211 ordinals 37, 40, and 47. A scoped contributor counts only when removing the exact AI change eliminates or materially shrinks an advisory-covered released surface. Worker PASS is proposal-only.

## Per case

1. GHSA-GC24-PX2R-5QMF ordinal 37 NARROW. Reviewed first-party GHSA names hardcoded JWT plus many unauthenticated API routes. PoC is /api/v1/system/info. Claude a7319f0e adds POST /{printer_id}/debug/simulate-print-complete with get_db only. Parent lacks that route and already ships unauthenticated printers routes. v0.1.6 still has SECRET_KEY bambuddy-secret-key-change-in-production. Deleting a7319f0e does not materially shrink the named JWT or many-routes class. Closers c31f2968 and a82f9278 are product-wide. simulate-print is not named.

2. GHSA-HFF7-CCV5-52F8 ordinal 40 NARROW. Reviewed first-party GHSA names tokenless Tailscale header auth on HTTP gateway routes. Claude f4b03599 adds /v1/responses calling authorizeGatewayConnect. Parent openai-http.ts already calls that helper; parent auth.ts already applies Tailscale on HTTP. v2026.2.19 OpenResponses and Chat Completions both use handleGatewayPostJsonEndpoint. Closer 356d61aa gates the shared helper and does not edit openresponses-http.ts. Shared SHA with counted GHSA-XMXX is a different captured-resolvedAuth fingerprint and does not merge this identity. Parent HTTP Tailscale remains if /v1/responses is deleted.

3. GHSA-Q447-RJ3R-2CGH ordinal 47 PASS_PROPOSAL. Reviewed first-party GHSA names unbounded webhook bodies and lists Feishu as an SDK handler needing stream guards. Landing squash 5c2cb6c5 is Claude-marked, parent_count=1, and first adds Lark.adaptDefault. Member b0c67ea0 has the same monitor.ts blob 31a890c2 but is not a tag ancestor; no authorship transfer. v2026.2.12 equals that blob. Deleting the Feishu adaptDefault landing removes that named SDK surface. Parent LINE req.on(data) stays out of scope. Closer 3cbcba10 wraps Feishu with maxBytes/timeout. Contained in v2026.2.12 / fixed v2026.2.13.

## Uniqueness

None of the three IDs are in canonical90 strict_released_case_ids (90). CVE aliases are stored and not counted. GHSA-HFF7 shares candidate SHA f4b03599 with counted GHSA-XMXX and remains a distinct identity. GHSA-Q447 does not merge with GHSA-VJ3G Feishu media path traversal.

## Boundary

Worker PASS is proposal-only. This packet proposes GHSA-Q447-RJ3R-2CGH and does not admit it to the canonical ledger. This packet did not edit canonical ledgers, did not commit or push, and did not store durable pages, clones, packages, or caches.
