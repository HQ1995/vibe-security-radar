# But-for-10 hostile red-team

**KEEP proposal: 0. NARROW: 10. REJECT/UNKNOWN/BLOCKED: 0.**

Worker PASS is proposal only. Causal admission is false. Publication and more-than-200 remain HOLD. Canonical73 still holds 73 strict released first-party GHSA identities. None of the ten assigned IDs are in that set. GHSA-WXHM-2MQ7-7697 was not reviewed.

Conservation: assigned=10, reviewed=10, unreviewed=0.

Hostile hypothesis: each row is old-bug preservation, a sibling path, incomplete-fix misclassification, or a non-necessary chain until exact parent/candidate/fix proves otherwise. Rechecked all seven gates, not only but-for. KEEP would require removing the AI hunk to eliminate or materially shrink the exact GHSA mechanism, or a complete incomplete-remediation patch-delta that is not an untouched sibling.

## GHSA-5WQV-FHMR-PJGH — NARROW (identity, but-for, fix-reversal)

Unreviewed global GHSA, empty `source_code_location`, empty `vulnerabilities`, repo advisory 404. That fails first-party identity.

Claude-marked `ee672df46` adds `profile=` to `get_state_db_session_messages`. Parent `465b97a9` already serves GET `/api/session` from `SESSION_DIR/{sid}.json` without `_profiles_match`. Fix `2a3baa71` (tag `v0.51.443`) scopes that sidecar IDOR. Removing the AI hunk leaves the named cross-profile transcript path.

## GHSA-6C8G-7P36-R338 — NARROW (but-for)

Reviewed NuGet SharpCompress `< 0.48.0`. Copilot `8b95e0a76` renames parent `ExtractToDirectory` to a `WriteToDirectory` overload and copies the uncontained directory-entry `Path.Combine` into `WriteToDirectoryAsync`. Parent already had that zip-slip. Tag `0.47.4` contains the AI commit; `0.48.0` contains fix `2021a066`. Deleting Copilot restores the parent directory-entry hole.

## GHSA-PQGX-6WG3-GMVR — NARROW (but-for)

Global GHSA 404; published repo advisory. Count squash `67c7b766` with its own Copilot author. Member `40331e610` is not an ancestor of the squash or of tags `0.99.48`/`0.99.49`; authorship is not transferred. Preimage `62fe0533` already runs unsanitized `NodeVM` `timeEntryRule`. Carrier blob `a8cef402` equals `0.99.48`; fix `2e2ac5cbe` adds `validateSandboxCode` and equals `0.99.49`. vm2-to-native-vm is a worse sandbox, not origin of admin RCE.

## GHSA-XMXX-7P24-H892 — NARROW (but-for)

Claude-marked `f4b03599` adds `/v1/responses`. Parent already captures `resolvedAuth` for Chat Completions HTTP and WebSocket. GHSA names that startup capture, range `< 2026.4.15`. Fix `acd4e0a32` is a shared later per-request re-resolve. npm `gitHead` is omitted for 2026.4.14/15; peeled tags `v2026.4.14` / `v2026.4.15` map the versions.

## GHSA-PQH8-P93P-2RX7 — NARROW (but-for)

Package `@dynatrace-oss/dynatrace-mcp-server` `< 2.1.1`. Copilot `66ff2a7c` copies parent `now()-${timeframe}` interpolation onto `list-vulnerabilities` and `get-events-for-cluster`. The GHSA table already names parent `list-problems`, `list-exceptions`, and `find-monitored-entity-by-name`. npm 1.2.0 `gitHead` `1c192a04` equals tag `v1.2.0`; 2.1.1 equals `v2.1.1`. Fix `15d3546c` sanitizes all five files.

## GHSA-H2VW-PH2C-JVWF — NARROW (but-for)

Claude-marked `7d7f5d85` adds MiniMax TTS that reads `MINIMAX_API_HOST`. Parent VLM already consumes that env. Fix `2f066965` denylists it in `dotenv.ts`. Range `>= 2026.4.5` tracks the TTS tag; that is routing, not origin. npm `gitHead` omitted; peeled `v2026.4.5` / `v2026.4.20`.

## GHSA-XQ94-R468-QWGJ — NARROW (but-for)

Claude-marked `75602014` adds Browserbase `ws://`/`wss://` CDP. Parent already has `cdpUrl` and `assertBrowserNavigationAllowed`. GHSA range `< 2026.4.10` has no lower bound and does not name Browserbase. npm 2026.3.8 `gitHead` equals `v2026.3.8`; 2026.4.10 `gitHead` omitted, peel `44e5b62c`. Fix `121c452d` is a shared DNS/navigation guard.

## GHSA-W85G-3H6X-4XH2 — NARROW (but-for)

Claude-marked `8d74578c` adds image ingest. Parent `image-ops.ts` already runs sips without `limitInputPixels`. GHSA is fail-open pixel-limit / decompression-bomb on sips. npm 2026.1.20 is 404; vulnerable containment is `v2026.3.28` / npm 2026.3.28. Fixed npm 2026.3.31 `gitHead` equals `v2026.3.31`. Fix `0ed4f8a72` patches the parent decoder.

## GHSA-R5JH-Q2MW-GCX4 — NARROW (but-for)

Count squash `5a3d68a34` with its own Claude trailer. Member `0d851525` is not an ancestor of `v1.24.0`/`v1.25.0`. Carrier parent already defines `SanitizeFilePath` (`HasPrefix`) and calls it from Handler and fetcher. Carrier adds Clean. Fix `8298e33e` (`v1.25.0`) replaces the helper with `os.Root` for those callers. Cleanup `5aac6f0b` only deletes the unused helper and is not the minimum fix. Incomplete-remediation patch-delta does not apply: the AI change attached a pre-existing broken helper.

## GHSA-7JX6-764P-FGG9 — NARROW (but-for, patch-delta)

Global GHSA 404; published repo advisory. `[AI]` commit `6e498a1f` introduces `authorizeQQBotApprovalAction` (parent had none). That is an explicit security attempt, so origin rollback is the wrong test. Patch-delta still fails: the GHSA does not explicitly cover a residual bypass of that AI-added boundary, and fix `08a73dbe` also gates fallback buttons through a sibling slash-command auth path (`sdk-adapter.ts`, plugin-sdk helpers). Tags `v2026.5.26` / `v2026.5.27`; npm `gitHead` omitted.

## Claim boundary

No worker or red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical73 and does not support a more-than-200 claim.
