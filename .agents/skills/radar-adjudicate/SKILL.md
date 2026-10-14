---
name: radar-adjudicate
description: As the sole adjudicator of one Vibe Security Radar case, read all N sealed independent audit reports, investigate their differences and shared assumptions against primary evidence, and deliver the final sealed record and decisions on cause, impact, history and AI role. Use for adjudication and its follow-ups; not for blind auditing or coordination.
---

# Radar adjudicate

Contract `2026-10-14.1`. You own the research conclusion for one case. Your assignment
supplies the case, the sealed lane paths, your directory and the time budget.

## Boundary

- The audit protocol's research boundary applies: static analysis and isolated
  reproduction only, no third-party targets, no working payloads.
- All N sealed reports are required; never substitute one or reduce N. Write only your
  owned output; preserve the auditors' originals.
- A safety refusal or operating stop ends the work: record it and hand off.

## Steps

1. **Check the assignment.** Both lanes must exist and be sealed (read-only); otherwise say
   so in `SUMMARY.md` and stop.
2. **Read every lane in full**: report, record, sidecar and decisive receipts. Treat each
   conclusion as a hypothesis and each source as a lead.
3. **Align before comparing.** Make sure the lanes describe the same product, revision,
   configuration, authority and advisory scope; apparent conflicts often address
   different conditions, and agreement can hide a shared unsupported premise.
4. **Investigate the four questions yourself**, starting with the one that decides the
   case: compare the introducing change with its parent, follow the repair into its real
   caller and omitted routes, and read the AI marker on the causal object. One correct
   minority report can outweigh the others; if every lane is wrong, write a new account.
5. **Record each difference**: the competing claims, the decisive observation, why each
   reading holds or fails, and your choice. Correct the explanation even when the verdict
   stays.
6. **Decide**: `ACCEPTED` when the whole chain is supported, `BLOCKED` when a decisive fact
   is still unknown after its bounded probe (name it and the next question). Keep an
   unknown AI role separate from an established mechanism or repair.
7. **Deliver together**: `REPORT.md`, the accepted `record.json`, `research.json` and
   `decision.json`. Read them back, replace superseded statements, and run
   `radar_case.py check --dry-run` until it reports ready (or outcome BLOCKED).
8. **Hand off**: write `SUMMARY.md` (decisions per question, what changed relative to the
   lanes, questions still open with their next owner) and reply with it only.

Work in your own session; do not start further subagents. A follow-up that returns to you is a labeled
continuation of the same case, not a new blind audit.

## References

| Read | When |
| --- | --- |
| [protocol.md](references/protocol.md) | Before step 2; comparison, decision and closeout rules |
| [../radar-audit/references/protocol.md](../radar-audit/references/protocol.md) | At step 4; what each question requires and when it is finished |
| [../radar-audit/references/ai-markers.md](../radar-audit/references/ai-markers.md) | When checking AI attribution |
| [../radar-audit/references/record.md](../radar-audit/references/record.md) | When writing the accepted `record.json` |
| [../radar-audit/references/research-work.md](../radar-audit/references/research-work.md) | When writing `research.json` and the decisions' research objects |
| [decisions.md](references/decisions.md) | When writing `decision.json` and running the reduction gate |
| [../radar-audit/references/submission.md](../radar-audit/references/submission.md) | Before step 7, for receipts, checks and sealing |
