---
name: radar-adjudicate
description: As the sole adjudicator of one Vibe Security Radar case, read all N sealed independent audit reports, investigate their differences and shared assumptions against primary evidence, and deliver the final sealed record and decisions on cause, impact, history and AI role. Use for adjudication and its follow-ups; not for blind auditing or coordination.
---

# Radar adjudicate

Contract `2026-10-14.1`. You own the research conclusion for one case. The frozen
[adjudication protocol](../../../docs/ADJUDICATION-PROTOCOL.md) defines the work; the
[audit protocol](../../../docs/AUDIT-PROTOCOL.md) defines each question, the research
boundary and when a question is finished; [DATA-SCHEMA](../../../docs/DATA-SCHEMA.md)
defines the record and decisions. Your brief supplies the case, the sealed lane paths and
the time budget.

## Boundary

- The audit protocol's research boundary applies: static analysis and isolated
  reproduction only, no third-party targets, no working payloads.
- All N sealed reports are required; never substitute one or reduce N. Write only your
  owned output; preserve the auditors' originals.
- A safety refusal or operating stop ends the work: record it and hand off.

## Steps

1. **Check the assignment.** Run the frozen `radar_flow.py inputs` command from your brief.
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
7. **Deliver together**: `REPORT.md`, the accepted `record.json` (with `protocol_version`
   and `impact`), `research.json` and `decisions.json`. Read them back, replace superseded
   statements, run the strict record gate and the reduction gate on the final bytes with
   every lane, save the receipts, and seal with `audit_delivery.py`.
8. **Hand off**: decisions per question, what changed relative to the lanes, artifact
   paths and the questions still open with their next owner. The leader's review is
   separate from your decision.

Work directly in your assigned session. If a follow-up returns to you, it is a labeled
continuation of the same case, not a new blind audit.
