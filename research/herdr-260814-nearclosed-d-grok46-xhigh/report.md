# Near-closed released wave D

TERMINAL. Assigned 3, reviewed 3, PASS_PROPOSAL 0. Conservation 3=3+0. Canonical88 remains 88 HOLD. Packet delta 0. No causal or publication admission.

This packet independently closed fp211 ordinals 117, 120, and 121: GHSA-H2VW-PH2C-JVWF, GHSA-XQ94-R468-QWGJ, and GHSA-W85G-3H6X-4XH2. Prior scoped but_for NARROW labels were routing hypotheses only. PASS_PROPOSAL required all seven gates exact PASS for the counted scope. For contributor rows, deleting the AI change must eliminate or materially shrink a first-party-advisory-covered surface, and the exact released fix must reverse that new surface. Existing sibling MiniMax env use, older CDP URLs, or older sips decoding may remain only if the counted scope is an AI-added credential consumer, ws branch, or ingest caller explicitly covered by the advisory. None of the three first-party texts names those new surfaces.

## Per case

1. GHSA-H2VW-PH2C-JVWF ordinal 117 NARROW but_for_gate. Reviewed first-party GHSA for openclaw/openclaw workspace dotenv MINIMAX_API_HOST redirect of credentialed MiniMax requests. Claude 7d7f5d85 adds TTS that reads that env and sends Authorization Bearer. Parent minimax-vlm.ts already did both. VLM intro 36a02b3e is an ancestor of v2026.3.22 and of affected v2026.4.5. TTS is not named. Closer 2f066965 denylists MINIMAX_API_HOST in dotenv.ts and does not change speech-provider.ts. Contained in v2026.4.5 / fixed v2026.4.20.

2. GHSA-XQ94-R468-QWGJ ordinal 120 NARROW but_for_gate. Reviewed first-party GHSA for browser hostname/IP DNS rebinding generally, not uniquely Browserbase. Claude 75602014 teaches cdpUrl to accept ws/wss. Parent already did HTTP /json/version CDP discovery. Closer 121c452d is a shared hostname navigation guard; isWebSocketUrl remains. Shared SHA with GHSA-F7FH is a different websocket-validation identity. Contained in v2026.4.5 / fixed v2026.4.10.

3. GHSA-W85G-3H6X-4XH2 ordinal 121 NARROW but_for_gate. Reviewed first-party GHSA for openclaw sips fail-open pixel-limit. Claude 8d74578c adds images.ts ingest. Parent image-ops.ts already had sipsMetadataFromBuffer/sipsResizeToJpeg without limitInputPixels. Closer 0ed4f8a72 amends the parent decoder, not images.ts. Shared SHA with counted GHSA-9F72 is prompt-image workspaceOnly, not this identity. Contained in v2026.3.28 / fixed v2026.3.31.

## Uniqueness

None of the three are in canonical88 strict_released_case_ids (88, including GHSA-8RW6-P7M8-63JP). CVE aliases are stored and not counted. W85G pinned OSV aliases are empty. Shared openclaw SHAs with GHSA-F7FH and GHSA-9F72 are different invariants and are not merged.

## Boundary

Prefer no PASS over weak evidence. Worker PASS is proposal-only; this packet emits none. This packet did not edit canonical ledgers, did not commit or push, and did not store durable pages, clones, packages, or caches.
