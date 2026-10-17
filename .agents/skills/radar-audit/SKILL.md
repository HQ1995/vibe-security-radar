---
name: radar-audit
description: Independently research one assigned Vibe Security Radar case - its cause, impact, history (introduction, exposure, repair, release) and the role AI played - and deliver a sealed, evidence-backed audit record. Use for an auditor assignment from radar-lead; not for ordinary code review or adjudication.
---

# Radar audit

Contract `2026-10-15.1`. You are one of N independent auditors of a case. Answer its four
questions from primary evidence, alone, and deliver a record. Your assignment supplies
the case, your directory, a scratch directory and the time budget.

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

1. **Check the assignment.** Make sure the inputs and directories it names exist. If one is
   missing, say so in `SUMMARY.md` and stop: that is a setup defect, not a finding.
2. **Advisory status.** Read the keyed advisory itself before anything else.
3. **Cause and impact.** Trace the real input, caller, validation and consuming operation
   at the affected revision; establish who can trigger it and what they obtain.
4. **History.** Find the introducing or exposing change and compare it with its parent;
   find the repair, follow it into its real callers, and verify the released content.
   Get parent comparisons, landings, release ranges and package contents from
   `scripts/radar_git.py`, not hand-written git commands.
5. **AI role.** Read the marker on the object that carries the causal change and say which
   activity it discloses. Absence of a marker is not `NOT_AI`; `radar_git.py carriers`
   lists every local object that carries the causal content.
6. **Stop when answered.** End each question when evidence answers it or its bounded probe
   is exhausted; name the observation that would close any remaining gap.
7. **Write and check.** Write `REPORT.md` first, organized by the four questions, then
   derive `record.json` and `research.json`. Read them back, make them agree, and run
   `radar_case.py lint` and the strict record gate.
8. **Hand off.** Write `SUMMARY.md` (the answer to each question, open questions, execution
   failures) and reply with it only. The leader seals your directory; submission is not
   acceptance.

Work in your own session; do not start further subagents. A crash, timeout or empty
response is an execution failure, never an evidence gap.

## References

| Read | When |
| --- | --- |
| [protocol.md](references/protocol.md) | Before step 2; it defines every step, the boundary and when a question is finished |
| [ai-markers.md](references/ai-markers.md) | At step 5, for where AI tools leave traces |
| [record.md](references/record.md) | When deriving `record.json`: fields, enums, verdict rules |
| [research-work.md](references/research-work.md) | When writing `research.json` |
| [submission.md](references/submission.md) | Before step 7, for receipts, checks and sealing |
| [scripts/radar_git.py](scripts/radar_git.py) | For every commit, parent, landing, release, carrier, PR, advisory or package fact: `commit`, `parent-diff`, `landing`, `releases`, `carriers`, `github`, `artifact` (`--help` on each). Write receipts with `--out <your directory>/evidence` |
