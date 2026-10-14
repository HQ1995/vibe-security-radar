# Adjudication protocol

Contract version: `2026-10-14.1`. Existing batches retain their frozen contracts.

N auditors independently apply [audit protocol](../../radar-audit/references/protocol.md). One adjudicator
(the reducer role) reads all N reports, investigates the case and owns the final
research conclusion on the same four questions: cause, impact, history and AI role.
Reports are hypotheses and evidence leads, not ground truth. The audit protocol's
research boundary and stopping rule apply unchanged.

## Compare and investigate

1. Pin the manifest, all assigned auditor names and original outputs, contracts,
   brief and gate code. Keep originals immutable. Separate execution failures from independent research;
   reducer recovery does not retroactively make a failed audit successful.
2. Compare **every case** across advisory, cause, impact, BIC/landing, AI role,
   fix, versions and residual/flip condition:

       python3 scripts/compare_slots.py --lane auditor1=<cases1> --lane auditor2=<cases2> \
           --lane auditor3=<cases3> --json <comparison.json>

   `research_differences` includes missing values and member/carrier differences.
   Text differences need interpretation; matching verdicts never auto-accept a case.
   Each lane argument accepts a record file or a directory containing only records.
   For a one-case task, use the original `record.json` paths. Do not pass a case
   directory containing arbitrary source JSON or scratch checkouts: the directory
   loader recursively reads JSON. For multiple cases, the leader supplies a
   records-only view pinned byte-for-byte to every original record; retain the
   full manifest, every assigned lane and all sealed source/report directories.
3. Build your own causal account before choosing among reports. For each research
   dimension, ask what all auditors may have missed and seek counterevidence to their
   shared conclusion. Read primary sources; do not limit investigation to flagged differences.
   For a TP in any lane or the synthesis, always scrutinize BIC granularity,
   AI scope and the repair chain. Re-derive NOT_AI identity from the actual object.
4. For each differing dimension record: **the competing claims, the decisive
   observation, why each reading fails or holds, and your final choice**. One correct
   minority report can outweigh all others. If every report is wrong, replace their
   conclusions with a new synthesis, citing the retained receipts.
5. Continue the causal chain yourself: follow partial fixes, test the remaining bypass,
   inspect shipped versions and recover missing source within the bounded probe rules.
   Close each next decisive question that available evidence can answer. A longer
   summary, majority vote or unexplained choice of a report is not adjudication.

Keep the same adjudicator through follow-ups. Only that owner writes shared decisions,
accepted records and the final report. Other auditors preserve their owned outputs.

## Decide and close

- **ACCEPTED:** the entire research chain is supported, with counterevidence addressed.
  Confirmed unpatched defects or qualified release boundaries can be accepted research;
  publication eligibility is separate.
- **BLOCKED:** a decisive fact is still unknown after the bounded probe. Name it and
  the next decisive question. Calling it an upstream obligation does not settle it.
- Unattempted work stays pending. Crashes/timeouts remain execution failures.

Track work separately using the local [research-work contract](../../radar-audit/references/research-work.md).
Its completion claim is limited to the recorded questions and observations. Check whether
an omitted caller, earlier member, partial repair or contrary source could change the
conclusion before accepting an evidence boundary. Evidence sufficiency ends a question;
route counts and terminal labels cannot establish that sufficiency.

A vendor correction is unnecessary when code and release evidence settle the conclusion.
State exactly which conclusion depends on any unresolved answer.

For new assignments, store frozen decisions in a dedicated `decisions.json` using
the [decision format](decisions.md). Keep
execution status and a pointer to that file in the mutable batch index. Preserve
legacy frozen layouts; adopting this layout requires an explicit new binding.
Bind all N inputs, accepted records and primary receipts by SHA-256. Explain required
resolutions, including TP BIC/AI/fix checks despite agreement. Before closeout:

1. Finish records, report and any staging payload; check that staging preserves the
   accepted research. Freeze these deliverables and their pins.
2. Run the [record checks](../../radar-audit/references/submission.md) and the delivery gate:

       python3 scripts/audit_reduction_gate.py --manifest <batch.txt-or-manifest.jsonl> \
           --lane auditor1=<cases1> --lane auditor2=<cases2> --lane auditor3=<cases3> \
           --accepted <accepted-cases> \
           --research-contract causal-work-v1 \
           --decisions <decisions.json>

3. Save gate output and the decision-file hash outside the frozen decision file. Changed
   evidence/records reopen affected decisions; re-review before refreshing hashes.
   Re-run against final bytes before ingestion. Contract changes require explicit migration.

The gate checks coverage, required decisions and unchanged bytes, **not causal truth**.
The reducer owns that judgment. Report execution, accepted/blocked research and publication
separately. Assembler counts, format PASS and released claims cannot replace acceptance.
Claim handoff, ledger landing and publication follow the
[release reference](../../radar-lead/references/release.md); research acceptance alone does not
establish either landing or publication.

## Before scaling a model or profile

Use the evaluator-only calibration set and scoring rules (`.ai-slop/audit-calibration.json`,
kept local and out of the public repository), then verify the first five production cases. Compare the same evidence, tools, context,
budgets and retry policy in fresh contexts. Auditors get neutral inputs; reducers also
get independent reports. Neither gets the evaluator key or previous leader judgments.
Score without model names; keep failures and retries visible. A small set qualifies a
pilot, not a general model ranking. Detailed cases and scoring belong in the linked set.
