# Audit protocol

Understand the real vulnerability first, then judge AI's causal contribution.
Choose methods, order and depth to resolve facts that could change the conclusion.
Give each independent case a fresh context with its task and primary evidence;
form your own judgment before consulting prior verdicts.

**Origin and attribution.** Find the smallest original commit that first wrote
the defective code (BIC); compare its immediate parent to establish the causal change.
Trace through moves/refactors and reconstruct merge/squash members needed to
identify the first-write. A surviving first-write is acceptable only when no
finer public member is recoverable; state that limit. Tie AI evidence to causal
code, not neighboring markers or authorship of the final fix.

**Fix and lifecycle.** Find the direct fix or minimum fix set even when none is
supplied. Verify that it closes the same mechanism and matches affected/fixed
versions. If truly unpatched, document why and propose a concrete fix with rationale.
For incomplete fixes, explain the entire chain: original flaw → attempted fixes
→ what remained insecure and why → final closure or verified unpatched state.
Identify advisories, commits and authorship throughout; distinguish original
introduction, new exposure and incomplete remediation.

**Evidence and judgment.** Use primary sources, seek counterevidence and limit
claims to what is proved. Missing facts remain explicit gaps, never inferred
`NOT_AI`. `FALSE_POSITIVE` needs authoritative advisory invalidation or withdrawal.
Save a standalone report for each wave before landing: scope and actual coverage,
per-case judgments with causal reasoning and exact evidence links, gaps and
proposed ledger changes. Passing scripts cannot replace causal judgment.
Default to reports; use existing explicit authorization for ledger updates or publication.

Formats: [Data schema](DATA-SCHEMA.md). Write boundaries: [AGENTS.md](../AGENTS.md).
