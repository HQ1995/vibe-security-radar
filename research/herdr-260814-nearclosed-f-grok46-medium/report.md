# Near-closed released wave F

TERMINAL. Assigned 4 first-party identities on fp211 ordinals 156, 198, and 200. Reviewed 4, PASS_PROPOSAL 0, NARROW 2, REJECT 2. Conservation 4=4+0. Canonical88 remains 88 HOLD. Packet delta 0. No causal or publication admission.

This packet independently reopened fp211 ordinals 156, 198, and 200. Ordinal 200 is two distinct first-party identities, not padding. Inherited overlay is routing only. All seven contract gates were rebuilt from first-party advisories and Git/release artifacts. PASS requires every gate PASS for the counted scope. Worker PASS is proposal-only; this packet emits none.

## Per case

1. GHSA-X34R-63HX-W57F ordinal 156 REJECT topology_gate. Reviewed first-party GHSA names pandas_utils WAF dunder / _literal_ok residual reaching pandas_eval, patched 0.59.32. Copilot member b1c45e3f (n_parents=1, parent 556196b8) changes `if not config.full_eval` to `if not self.config.full_eval` and edits only table_chat_agent.py. pandas_utils blob equals the parent. Human b68a8a79 authored Mitigation for CVE-2025-46724. Member is not an ancestor of squash 0d9e4a7b, 0.59.31, or closer 30abbc1a. Mixed squash quotes Copilot and Claude Consistent use of self.config.full_eval. table_chat blobs: member ba8bc96c != carrier c7b32065 != 0.59.31/fix 28c3c288. Mainline never shipped the PR-branch NameError fail-closed state. 0.59.31 table_chat equals the closer. visit_Attribute appears only on 30abbc1a. Authorship is not transferred. Distinct from counted GHSA-PMCH.

2. GHSA-7JX6-764P-FGG9 ordinal 198 NARROW but_for_gate. Published repo advisory. Class AI_INCOMPLETE_REMEDIATION. [AI] 6e498a1f introduces authorizeQQBotApprovalAction; parent grep count is 0. Undefined execApprovals still returns authorized true. Patch-delta: AI creates the approval boundary and closer 08a73dbe amends that return to markImplicitSameChatApprovalAuthorization, but the GHSA does not name a residual of that boundary and the closer also gates sibling slash-command fallback buttons. Contained in v2026.5.26 / fixed v2026.5.27.

3. GHSA-3J8Q-FWPJ-F8J5 ordinal 200 NARROW identity_gate. Published repo advisory is an omnibus of nine findings. Counted scope is narrowed to the AI-added notes API: only VULN-02/03 name notes.php. Claude squash b3edc225 adds that file. Parent lacks notes.php. Closer 83c19611 names GHSA-jjcj and also patches family profile, timeline, and FamilyMiddleware. 7.3.3 contains the candidate without the closer; 7.4.0 contains the closer. CVE-2026-58407 is a stored alias and is not counted. Uniqueness versus canonical88 PASSes. JJCJ is not a second notes-mechanism count.

4. GHSA-JJCJ-H3CM-P7X7 ordinal 200 REJECT uniqueness_gate. Distinct first-party object, not a formal alias of GHSA-3J8Q. After notes-only narrowing the remaining overlap is the same churchcrm-notes-object-scope-authorization fingerprint. Family profile predates the notes candidate. timeline.php is not added by b3edc225. Two public GHSAs may not both count for the same mechanism. Duplicate mechanism is fatal. Zero count.

## Uniqueness

None of the four IDs is in canonical88 strict_released_case_ids (88, including GHSA-8RW6-P7M8-63JP). CVE aliases are stored and not counted. X34R is not merged with counted GHSA-PMCH. Ordinal 200 keeps two identities in the source layer and admits neither.

## Boundary

Worker PASS is proposal-only. This packet proposes none. Canonical88 was not rebuilt. No live autoresearch scan, canonical edit, commit, or push. Expansion stopped. Did not pad.
