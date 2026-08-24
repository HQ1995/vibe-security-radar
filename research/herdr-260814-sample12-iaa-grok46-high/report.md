# Blind IAA sample-12 re-review (grok-4.6 high)

Independent seven-gate re-review of the 12 assigned counted-strict rows. Ledger gate values were treated as non-evidence. GitHub API was not used. terminal=true.

## Counts

Reviewed 12/12. CONFIRM 10, NARROW 1, FALSE_POSITIVE 0, UNKNOWN 1. Agree with counted-strict status on 10 rows; disagree on 2.

## Findings

Ten rows close all seven gates at an explicit AI-hunk scope. Faraday (GHSA-5RV5-XJ5J-3484) is countable as AI_INCOMPLETE_REMEDIATION under the patch-delta rule: the AI commit is an explicit host-scoping security rewrite, the GHSA names the residual protocol-relative URI bypass, and fix 3f1280c6 amends that same boundary. The two Prompty advisories share candidate a0e61088 but remain unique: Nunjucks SSTI (GHSA-W28W-GP39-M4P6, fix e4a0ebf4) versus JavaScript frontmatter execution (GHSA-C4GH-RV8H-Q9VW, fix c27402da). The three OpenClaw advisories are also unique mechanisms (Synology Chat path collision, Feishu temp-file traversal, Matrix thread allowlist).

Gate failures / non-PASS outcomes are confined to GHSA-X9QH-W4C4-54F9, where identity could not be recovered from frozen local advisory sources, so every gate is UNKNOWN. No row was rejected as FALSE_POSITIVE. FP class observed: IDENTITY_NOT_RECOVERED (1). NARROW class observed: candidate-versus-carrier scope (1).

## Per-row verdicts

1. GHSA-C4HM-4H84-2CF3 ruvnet/ruflo: CONFIRM (HIGH, AI_DIRECT_ROOT; failing=none)
2. GHSA-X9QH-W4C4-54F9 coollabsio/coolify: UNKNOWN (LOW, UNRESOLVED; failing=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
3. GHSA-RQP8-Q22P-5J9Q openclaw/openclaw: CONFIRM (HIGH, AI_DIRECT_ROOT; failing=none)
4. GHSA-5RV5-XJ5J-3484 lostisland/faraday: CONFIRM (HIGH, AI_INCOMPLETE_REMEDIATION; failing=none)
5. GHSA-G3XQ-3GMV-QQ8G cnighswonger/claude-code-cache-fix: CONFIRM (HIGH, AI_DIRECT_ROOT; failing=none)
6. GHSA-W28W-GP39-M4P6 microsoft/prompty: CONFIRM (HIGH, AI_DIRECT_ROOT; failing=none)
7. GHSA-C4GH-RV8H-Q9VW microsoft/prompty: CONFIRM (HIGH, AI_DIRECT_ROOT; failing=none)
8. GHSA-J5QP-P44G-2M49 asymmetric-effort/specifyjs: CONFIRM (HIGH, AI_DIRECT_ROOT; failing=none)
9. GHSA-Q6QC-XP4Q-RJQ5 enderfga/claw-orchestrator: CONFIRM (HIGH, AI_DIRECT_ROOT; failing=none)
10. GHSA-VJ3G-5PX3-GR46 openclaw/openclaw: NARROW (MEDIUM, AI_DIRECT_ROOT; failing=none)
11. GHSA-46Q5-G3J9-WX5C qhkm/zeptoclaw: CONFIRM (HIGH, AI_DIRECT_ROOT; failing=none)
12. GHSA-RG8M-3943-VM6Q openclaw/openclaw: CONFIRM (HIGH, AI_DIRECT_ROOT; failing=none)

## Disagreement

Counted status for the sample is strict admission. Independent verdicts match that status on 10 of 12 rows and diverge on 2:

- GHSA-X9QH-W4C4-54F9 (coollabsio/coolify): counted strict vs independent UNKNOWN. Frozen advisory-database clones and OSV caches used here did not contain a first-party GHSA object; local coolify clone search was empty; GitHub API is disallowed. Identity_gate cannot close, so the remaining gates are not inferred from the ledger.
- GHSA-VJ3G-5PX3-GR46 (openclaw/openclaw): counted strict vs independent NARROW. The assigned set distinguishes candidate a604df8c from carrier 2267d58a. The AI hunk and but-for story stay on the candidate; treating the carrier as the authoring commit would be authorship transfer. The case remains causal at candidate scope, not as an unqualified carrier confirmation.

No other verdict disagreements. Contribution-class note that is not a verdict disagreement: GHSA-5RV5-XJ5J-3484 is labeled AI_INCOMPLETE_REMEDIATION rather than AI_DIRECT_ROOT because the advisory is an incomplete fix of a prior Faraday host-scoping hole.
