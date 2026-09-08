# Audit protocol

Research each advisory's cause, smallest BIC, minimum fix and AI role. Retain every
case, whatever the verdict.

One fresh-context subagent owns each case; parallelize within host limits. Supply
this protocol, the linked schema and primary sources. Save independent findings
before reading prior verdicts. Prefer local Git and GitHub patch/raw/PR pages;
avoid GitHub API requests while rate-limited.

1. **Cause:** Explain trigger → vulnerable code → security impact, including
   preconditions and counterevidence. Separate distinct mechanisms.
2. **BIC:** Find the smallest original introducing change and compare its immediate
   parent; trace moves and separate introduction from later exposure. For BIC and fix,
   decompose merge/squash history into logically atomic causal changes across PR members
   and hunks/files; distinguish landing commits from those changes. If history is
   unavailable, isolate the causal diff and state the limit on commit-level minimality.
3. **Fix:** Identify the minimum repairing hunks/commit set and explain why it closes
   the defect. Follow partial repairs through the residual defect to closure.
   Verify affected/fixed versions separately; substantiate an unpatched state and
   propose a repair when no fix exists.

   Record the fix side explicitly and consistently:
   - Set fix_ai_marker (state PRESENT/ABSENT/UNKNOWN with per-sha evidence) on the
     fix commit objects. Fix-side AI is informational: it never substitutes for
     BIC-side attribution, and a fix-side marker alone does not change the verdict.
   - If the remediation is partial or a claimed patched release does not contain
     the fix, set remaining_gap and name the still-open surface plus closing commit
     (or none). When evidence/reasoning already uses wording like "remains unbounded",
     "still ships", "not closed", "residual", or "incomplete remediation", remaining_gap
     must not be empty; keep the record consistent with its own evidence.
4. **AI:** Tie AI evidence to causal changes throughout the history, within its
   disclosed scope. A TP requires demonstrated AI contribution to the defect:
   introduction, new exposure or incomplete remediation can qualify after a human
   BIC. Successful repair alone does not qualify; unknown does not mean `NOT_AI`.
   Keep the verdict consistent with this account.

   Record fix_ai_marker on the fix itself, keeping BIC-side and fix-side attribution
   distinct. Placeholder identities (*@localhost, test@test.com, generic Test <...>) are
   not named-human proof and are not commit-object AI attribution; leave EVIDENCE_GAP
   unless a positive marker or recovered named identity closes the case.
5. **Evidence:** Retain a per-case report and primary-source snapshots with exact
   SHAs, paths/hunks, URLs and capture dates. Explain comparisons, counterevidence,
   uncertainties and their effect on conclusions. Complete available decisive
   checks; preserve findings and explain revisions.

   The per-case report and remaining_gap must agree with the evidence: if the evidence
   shows a residual open surface, say so in the report and in remaining_gap; do not carry
   a closed verdict while the record's own evidence names an unclosed path.

Review causal conclusions before ledger updates or publication; saved reports and
passing format checks do not establish correctness. Keep a batch index of outcomes
and remaining gaps. Follow the [data schema](DATA-SCHEMA.md) and
[write boundaries](../AGENTS.md).
