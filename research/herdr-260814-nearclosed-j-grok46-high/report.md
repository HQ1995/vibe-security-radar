# Near-closed released wave J (fp211 ordinals 80, 86, 95)

Verdict first: **0 PASS proposal**. Three NARROW. 0 REJECT. 0 UNKNOWN. 0 BLOCKED.

Assigned 3, reviewed 3, unreviewed 0. Conservation 3=3+0. Worker PASS is a proposal only. Canonical90 remains 90 HOLD. Packet delta 0. Publication and greater-than-200 stay HOLD. This packet does not rebuild the strict-released ledger.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical90 summary SHA-256 `5222879219a975fa4388f3f07f5c62cd6687a642b6509afe48a4250fb4be81ef`. Ledger SHA-256 `daf706e14d514ad62d197e61aa8ec7f52eefd958bc19a4a7c58591a0be8654ec`. fp211 public_cases.jsonl SHA-256 `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`. Shared tracked files and canonical ledgers were not edited. No commit, push, or credential output.

## Assignment

Exactly three first-party identities, fp211 ordinals 80, 86, 95: GHSA-RQPP-RJJ8-7WV8, GHSA-7X5Q-8F6H-RJRC, GHSA-G5CG-8X5W-7JPM. Overlay routing is prior NARROW / release PASS. That vector is not truth. All seven contract gates were rebuilt from Git objects, first-party advisories, tags, blame, and copy/blob equality.

PASS_PROPOSAL required all seven gates exact PASS for the counted scope. Scoped-contributor rule: PASS only if removing the exact atomic AI change eliminates or materially shrinks a precisely named advisory mechanism. Incomplete remediation uses the patch-delta rule. Marker transfer, remediation-as-origin, older-hole preservation, multi-purpose fix ambiguity, and scope not named by the advisory are rejected. Non-ancestor squash or merge members are not transferred onto carriers.

Clones used read-only: `/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw`, `/home/hanqing/.cache/cve-analyzer/repos/conductor-oss_conductor`. Advisories from `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database` and `/home/hanqing/.cache/cve-analyzer/advisory-database`. No clone writes. No durable pages.

## Per case

1. GHSA-RQPP-RJJ8-7WV8 ordinal 80 NARROW but_for_gate (also ai_hunk, topology, fix_reversal, release). Identity PASS: reviewed first-party GHSA-rqpp aliases CVE-2026-22172 only, self-declared unbound scopes on shared-token auth, patched 2026.3.12 by 5e389d5e. Distinct from counted GHSA-RV39-79C4-7459 / CVE-2026-28472 (token-presence skip, fix fe81b1d7, patched 2026.2.2). Shared candidate SHA 079af0d0 is not duplication. Count member 079af0d0 on its own Claude Opus 4.5 marker. Unmarked merge ec51bb70 is the first-parent landing; do not transfer. Parent already bound connectParams.scopes. 079af0d0 has no scopes hunk. v2026.3.11 blame of hasTokenAuth is human f76e3c14; blame of the sharedAuthOk exception is unmarked human 9c142993. Closer 5e389d5e tightens clearUnboundScopes and reverses that human residual, not the AI device-skip. Candidate blob e4a8dbd5 differs from v2026.3.11 blob 0897b51e. Uniqueness PASS versus canonical90 and versus RV39.

2. GHSA-7X5Q-8F6H-RJRC ordinal 86 NARROW identity_gate (also topology, but_for, fix_reversal, release). Identity NARROW: unreviewed GHSA, github_reviewed=false, affected=[]. No github-reviewed repository advisory. References include CVE-2025-26074, a different-year identity. AI hunk PASS on member 840ec19c: Nashorn --no-java to GraalJS HostAccess.ALL, Claude trailer. PythonEvaluator.java blob 1a71ee9b equals parent; allowAllAccess(true) is a parent hole, not an AI hunk. Unmarked merge d874e6e5 is first-parent of v3.21.21; member is ancestor of second parent only. Do not transfer. Advisory names JS HostAccess.ALL or Python allowAllAccess(true) plus an unauthenticated workflow API. Deleting the member restores Nashorn and leaves Python plus the API. F1 87a7d96a is multi-purpose (JS deny-list plus Python host-access). v3.30.0/v3.30.1 still ship HostAccess.ALL without js.load false. F2 c691e35e still builds from HostAccess.ALL. Uniqueness PASS versus canonical90.

3. GHSA-G5CG-8X5W-7JPM ordinal 95 NARROW but_for_gate (also ai_hunk, fix_reversal, release). Identity PASS: reviewed first-party GHSA-g5cg aliases CVE-2026-41329, senderIsOwner heartbeat inheritance, patched 2026.3.31 by a30214a6. Maintainer triage Status: open is not withdrawn. Topology PASS by counting squash 483fba41 on its own Claude Opus 4.5 marker, n_parents=1. Member 01d568c9 is not an ancestor of the squash or of v2026.3.28/v2026.3.31; heartbeat-runner.ts blob 71c41394 equals member and squash. No member transfer. First-parent pickaxe for EXEC_EVENT_PROMPT on v2026.3.28 hits the squash then unmarked e2362d35, which removes the prompt before the affected tag. v2026.3.28 blob b4c863b9 has no EXEC_EVENT_PROMPT. Parent already scheduled exec-event heartbeats. Closer adds ForceSenderIsOwnerFalse and does not reverse the prompt. Uniqueness PASS versus canonical90.

## Uniqueness

None of the three IDs is in canonical90 strict_released_case_ids (90). None is GHSA-8RW6-P7M8-63JP. CVE aliases are stored and not counted. GHSA-RQPP is not GHSA-RV39. Replay uniqueness reads only the pinned canonical90 summary plus the pinned RQPP/RV39/G5CG/7X5Q advisory objects.

## Claim boundary

Countable PASS requires all seven gates PASS plus leader admission. Proposed PASS: 0. Publication remains HOLD. Greater-than-200 remains HOLD. This packet does not support a greater-than-200 claim. Canonical90 was not rebuilt. Expansion stopped. Did not pad.
