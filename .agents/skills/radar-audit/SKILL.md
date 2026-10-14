---
name: radar-audit
description: Independently research one assigned Vibe Security Radar case - its cause, impact, history (introduction, exposure, repair, release) and the role AI played - and deliver a sealed, evidence-backed audit record. Use for an auditor assignment in a bound batch; not for ordinary code review or adjudication.
---

# Radar audit

Contract `2026-10-14.1`. You are one of N independent auditors of a case. Answer its four
questions from primary evidence, alone, and deliver a sealed record. The frozen
[audit protocol](../../../docs/AUDIT-PROTOCOL.md) defines the research, its boundary and
when a question is finished; [DATA-SCHEMA](../../../docs/DATA-SCHEMA.md#audit-records)
defines the record; [AI markers](../../../docs/AI-MARKERS.md) lists where AI tools leave
traces. Your brief supplies the case, paths and time budget.

## Boundary

- Defensive analysis of a published vulnerability: advisories, source, history, releases.
  Reproduce only as an isolated regression check in an owned scratch checkout. Never run
  exploits against anything, build working payloads or contact deployed systems.
- Independence: use primary sources and your own work. Never read other auditors'
  reports, earlier verdicts, website labels or evaluator material. If you see one, stop,
  record what you saw and hand off; that attempt is no longer blind.
- Write only your owned output. You never claim, land or publish.
- A safety refusal or operating stop ends the work: record it and hand off. Do not rephrase
  or route around it.

## Steps

1. **Check the assignment.** Run the frozen `radar_flow.py inputs` command from your brief.
   A failure is a setup defect for the leader, not a research finding.
2. **Advisory status.** Read the keyed advisory itself before anything else (protocol
   step 0).
3. **Cause and impact.** Trace the real input, caller, validation and consuming operation
   at the affected revision; establish who can trigger it and what they obtain (steps 1-2).
4. **History.** Find the introducing or exposing change and compare it with its parent;
   find the repair, follow it into its real callers, and verify the released content
   (steps 3-4).
5. **AI role.** Read the marker on the object that carries the causal change, and say
   which activity it discloses. Absence of a marker is not `NOT_AI` (step 5).
6. **Stop when answered.** End each question when evidence answers it or its bounded probe
   is exhausted; name the observation that would close any remaining gap.
7. **Write and check.** Write `REPORT.md` first, organized by the four questions, then
   derive `record.json` (with `protocol_version` and `impact`) and the research-work
   sidecar `research.json`. Read them back and make them agree. Run the strict record gate
   and save each check receipt.
8. **Seal and hand off.** Write the delivery spec and run `audit_delivery.py seal`. Your
   final message gives the findings per question, artifact paths, open questions and any
   execution failures. Submission is not acceptance.

Work directly in your assigned session; do not spawn sub-agents. Preserve failed
commands and their output. A crash, timeout or empty response is an execution failure,
never an evidence gap.
