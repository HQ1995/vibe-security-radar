# CF3 release-6 closure: six foundation NARROW identities

Zero PASS_PROPOSAL. Packet delta 0. Canonical86 stays 86.

Independent seven-gate review of GHSA-2X93, 9C3V, F2FQ, F38V, V396, WP73. Canonical86 is exclusion only. Terminal releaseonly/nearpass packets were hypotheses, not inherited verdicts. Conservation: assigned=6, reviewed=6, unreviewed=0.

PASS_PROPOSAL requires all seven gates exact PASS and public artifacts containing candidate and fix. None qualify. Unreleased AI member is REJECT for strict released and is not relabeled NOT_AI. UNKNOWN is unused: each identity closed on first-party git plus published tags or PyPI metadata.

## Per identity

1. GHSA-2X93-H3HG-2XFP openclaw/openclaw. NARROW. Identity PASS (repo advisory, npm openclaw patched 2026.5.26). Candidate b75ad800 is single-parent [AI] Chrome-MCP tab.url SSRF on snapshot routes. v2026.5.22 contains candidate without closer 06047005; v2026.5.26 contains both (release_gate PASS). Named residual is current-tab validation on local-managed CDP, a sibling of the AI usesChromeMcp gate. Parent already had /snapshot. but_for and fix_reversal NARROW. Uniqueness PASS (not in strict 86). Distinct from 9C3V/WP73.

2. GHSA-9C3V-684M-579C openclaw/openclaw. NARROW. Advisory names SSE Authorization forwarding. Candidate 47eb2d48 [AI] adds STREAMABLE_HTTP redirect scrubbing in mcp-transport.ts. v2026.6.1/v2026.6.5 git window exists. Named SSE residual is not that attempt. but_for NARROW.

3. GHSA-F2FQ-4RMP-9X8C ChurchCRM/CRM. REJECT (UNRELEASED_AI_MEMBER), not_ai=false. Identity PASS via repository advisory (7.5.1 / 7.6.0). Claude Haiku member cbea916e restores 2FA on API login. Zero tags contain the member. 7.5.1 public-user.php blob is not the member blob. Unmarked squash carrier 1bfc187a is not authorship transfer. Strict released cannot count an unreleased AI member. Do not call this NOT_AI.

4. GHSA-F38V-77QJ-H4JQ MervinPraison/PraisonAI alias CVE-2026-57148. NARROW. Cursor-marked 179cab02 is a security batch including JWT issuance. Clone has no tags for candidate or closer e0fb8e7. Candidate pyproject 0.1.2; closer 0.1.4. PyPI has 0.1.4 and 0.1.6, no 0.1.5. Named 0.1.4 residual is PLATFORM_ENV defaulting to dev around a hardcoded JWT secret, not a proven omitted case of the AI rewrite. Canonical86 already holds F38V as noncounting B3 NARROW. release/but_for/fix_reversal NARROW. Not unreleased-commit REJECT because public PyPI 0.1.4 exists; mapping from SHA to wheel is not a counted pair.

5. GHSA-V396-V7Q4-X2QJ gitpython-developers/GitPython. NARROW. GPT 5.4 c9a26789 splits multi-options in git/repo/base.py; cmd.py unchanged. GHSA names joined short options closed in cmd.py by 56806080. Tags 3.1.50/3.1.51 contain candidate then closer. cmd.py at 3.1.50 is not the candidate-era blob. but_for NARROW. Uniqueness PASS versus canonical86.

6. GHSA-WP73-F3GG-W4VR openclaw/openclaw. NARROW. Advisory names ClickClack toolsAllow. Candidate 6c918ca8 [AI] inherits embedded-runner tool deny; zero ClickClack files. Closer 797bcd5b is a human ClickClack reply adapter. v2026.5.18/v2026.6.5 window exists. Unattempted sibling provider. but_for NARROW.

## Claim boundary

No worker PASS. Leader admission is unchanged. Publication and more-than-200 stay HOLD. This packet does not edit canonical86, web, or scripts.
