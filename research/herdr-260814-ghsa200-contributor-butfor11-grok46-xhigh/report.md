# Contributor but-for-11 independent closure

Verdict first: 0 PASS proposals. 11 NARROW. 0 REJECT. 0 UNKNOWN. 0 BLOCKED.

Assigned 11, reviewed 11, unreviewed 0. Conservation 11=11. Worker PASS is proposal only; this packet emits none. Start count 81 (canonical81 freeze). Current leader-accepted count 82 (canonical82, commit 6800d212, ledger hash 58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23). Packet delta 0. Publication and greater-than-200 stay HOLD. This packet does not rebuild canonical82.

Source labels and the six old PASS gates are routing only. All seven current gates were re-audited from first-party GHSA/repo advisory, atomic git topology, releases, and exact fix reversal. The user-approved contributor rule was applied: a new surface counts only if the GHSA exploit depends on it and parent lacked an equivalent reachable path. Rollback need not wipe every broader old bug, but a demonstrated material delta on the exact first-party mechanism is required. Incomplete remediation uses the same-boundary patch-delta rule. Squash members were expanded; AI-marked carrier authorship was not transferred onto a human hunk. Same-repo OpenClaw identities stayed separate.

## PASS proposals for separate red-team

None.

## NARROW (uncounted)

| ID | Repo | Unresolved gate | Why not strict |
| --- | --- | --- | --- |
| GHSA-5WQV-FHMR-PJGH | nesquena/hermes-webui | identity, but-for, fix-reversal | Unreviewed empty-vuln GHSA; repo advisory 404. Claude ee672df46 adds state.db profile=. Parent GET /api/session IDOR remains. Closer 2a3baa71 scopes sidecar by-id reads. |
| GHSA-6C8G-7P36-R338 | adamhathcock/sharpcompress | but-for | Copilot 8b95e0a76 renames ExtractToDirectory and copies uncontained Path.Combine into WriteToDirectoryAsync. Parent already had WriteToDirectory. |
| GHSA-7C3W-FXGH-FRC7 | zereight/gitlab-mcp | but-for | Repo GHSA PoC is parent get_pipeline_job_output unencoded job_id. Claude c156ac76 copies that onto artifacts tools. npm 2.1.18 vulnerable; 2.1.38 has closer e2a81a04. |
| GHSA-7JX6-764P-FGG9 | openclaw/openclaw | but-for, patch-delta | [AI] 6e498a1f introduces authorizeQQBotApprovalAction. GHSA does not name a residual of that boundary. Closer 08a73dbe also gates sibling slash-command auth. |
| GHSA-H2VW-PH2C-JVWF | openclaw/openclaw | but-for | Claude 7d7f5d85 adds MiniMax TTS. Parent VLM already reads MINIMAX_API_HOST in v2026.4.1. Range >= 2026.4.5 is routing. Closer 2f066965 denylists dotenv. |
| GHSA-PQGX-6WG3-GMVR | kromitgmbh/titra | but-for | Count squash 67c7b766 Copilot. Member 40331e610 is not a tag ancestor. Preimage 62fe0533 already runs unsanitized NodeVM timeEntryRule. |
| GHSA-PQH8-P93P-2RX7 | dynatrace-oss/dynatrace-mcp | but-for | Copilot 66ff2a7c copies timeframe interpolation onto sibling tools. GHSA table already names parent list-problems, list-exceptions, and entityNames. |
| GHSA-R5JH-Q2MW-GCX4 | fission/fission | but-for | Count squash 5a3d68a34 Claude. Member 0d851525 is not a tag ancestor. Parent already has HasPrefix SanitizeFilePath plus Handler and fetcher callers. Carrier only wires Clean. |
| GHSA-W85G-3H6X-4XH2 | openclaw/openclaw | but-for | Claude 8d74578c adds ingest and extra sips EXIF. Parent image-ops.ts already runs sips without limitInputPixels. npm 2026.1.20 absent; use v2026.3.28 / 2026.3.31. |
| GHSA-XMXX-7P24-H892 | openclaw/openclaw | but-for | Claude f4b03599 adds /v1/responses. Parent already captures resolvedAuth for HTTP/WS. GHSA verifies /ready. Shared closer acd4e0a32. |
| GHSA-XQ94-R468-QWGJ | openclaw/openclaw | but-for, fix-reversal | Claude 75602014 adds Browserbase ws/wss. GHSA names DNS-rebinding hostname navigation, range < 2026.4.10, no Browserbase. Named closer 121c452d is that shared guard. Distinct from GHSA-F7FH. |

## Contract notes

OSV introduced, commit subjects, overlay PASS labels, and advisory version lower bounds were not treated as causal proof. An AI-marked carrier was not used to transfer authorship onto a non-ancestor member. Five OpenClaw GHSAs remain five cases. NA/null fail closed. Prefer NARROW over a weak narrowed contributor when parent still exposes an equivalent reachable GHSA path.

## Claim boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 82. Only leader-reviewed rows with all seven gates PASS enter that bound. This packet does not rebuild canonical82 and does not support a greater-than-200 claim.
