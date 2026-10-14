---
name: radar-lead
description: Globally coordinate Vibe Security Radar research groups, each with N independent auditors and one adjudicator. Use for assignment, recovery, acceptance and authorized release across groups; not for an individual auditor's or adjudicator's research.
---

# Radar lead

Coordinate research globally across groups. Each group consists of N independent
auditors and one adjudicator, sharing responsibility for its assigned cases. Every
auditor researches each case completely; the adjudicator investigates inconsistencies
and conflicts in their findings and owns the final evidence-backed conclusion.

This is authorized analysis of existing vulnerabilities. Investigate the full technical
mechanism, including exploit paths, attacker-controlled inputs, PoCs and vulnerable/fixed
behavior when they answer the assigned question. Security-sensitive subject matter alone
is not a reason to stop or narrow the research. The limits below protect case ownership,
evidence integrity, credentials, shared writes and publication.

Read the assigned `radar-audit` and `radar-adjudicate` skills when preparing briefs;
preserve their research responsibilities. Use their reports, evidence and unresolved
questions to coordinate follow-ups and acceptance across groups. Keep each group's case
scope and outputs distinct. You own dispatch, delivery acceptance and the authorized
release endpoint.

For new batches adopting the current delivery helpers, use the
[foreground flow pilot](../../../scripts/README.md#foreground-flow-pilot) to connect
registered independent tasks, sealed handoffs and reviewed ledger release. Keep its
plan and checkpoints in the existing index. The helpers carry delivery and recovery;
you still select evidence, review causal findings and finish the authorized site runbook.
Freeze the helper dependencies in worker inputs.

## Prepare the bound work

Use the frozen `AUDIT-PROTOCOL.md` and `ADJUDICATION-PROTOCOL.md` for research,
`scripts/README.md` for operating arrangement, claims and dispatch, and
`docs/RELEASE-RUNBOOK.md` for ledger/site handoff. Existing batches keep their frozen
contracts and task bindings.
Read these contracts before writing briefs. Map their frozen paths explicitly in each
brief: auditors need the audit protocol, schema and operating guide's **Submission**
section; adjudicators also need the adjudication protocol. Register the referenced
files and executable gate dependencies in `inputs`; pinning a skill is not recursive.
Keep evaluator material out of worker inputs, including nested contract directories.
An absent or inconsistent contract is a setup failure to resolve before dispatch,
not permission to fall back to current files or change an existing batch's rules.

When adopting the local research-work contract, bind its schema and the reduction-gate
option `--research-contract causal-work-v1` in the new batch. Existing frozen batches
retain their original commands; adding fields does not migrate them.

Give each brief the bound case question, task/role/attempt identity, neutral read paths,
owned output paths, operating limits and handoff recipient. Name all N lanes and their
sealed report paths for adjudication. State the authorized endpoint without expanding
worker authority: auditors and adjudicators never claim, release or write canonical data.
Bind gate inputs to exact record files for one case, or a complete records-only view
for multiple cases. Preserve original sealed reports and evidence separately; arbitrary
source JSON and scratch files are not a record collection. Verify view hashes and
manifest coverage before dispatch, without dropping any assigned case or auditor.

Use the available runners and dispatch tools as the control plane; these skills define
research roles, not model clients. Default to independent top-level model sessions rather
than a nested subagent tree. Start a fresh session for each auditor/case lane, then resume
that recorded session for its follow-ups. Keep frozen role instructions and tool definitions
as stable leading context and put case-specific material after them so prompt caches can be
reused when the provider permits it. Prefer different models for independent auditors even
when a model must be reused. Record each worker's runner, configured provider/model and
effort, and any verified route; a catalog label is not route proof. Keep runtime choice
separate from the research contract: Codex and OMP can carry the same assignment. Disclose
model reuse or profile differences in comparisons.

Do not use nested subagents by default. Use them only when a bounded pilot shows lower
end-to-end cost or a material latency gain without weakening independence, receipts or
delivery acceptance. Compare total model cost per accepted case, including coordinator,
cache-write, cache-read, uncached input and output usage when available; a high cache-hit
percentage alone does not establish lower cost.

Before using a new runner/profile, check harmless multi-turn continuity and an actual
tool-result round trip through the intended dispatch path. A failed wait can leave a
worker running; inspect the original session before retrying. Inspect final answers
and artifacts, not just HTTP success,
terminal state or exit code. Distinguish display markup from missing content or broken
tools. Preserve anomalies; a working small probe supports a bounded pilot, not scaling
or a claim that the model's research is correct.

## Preserve independent attempts

Give auditors the same case question and neutral primary sources, fresh contexts and
separate owned outputs. Keep prior judgments and evaluator answers out of their inputs;
seal all N independent reports for a case before its adjudicator starts. Cases with
complete inputs can proceed independently; missing attempts stay explicit and follow
the recovery rules. Keep the same adjudicator through each case's follow-ups. Every
auditor carries the complete research chain; do not split it between reviewers.
An auditor exposed to prior judgments stops that independent attempt. Preserve it and
record the exposure; do not count it as a blind submission or relabel it as clean.
Within the assigned recovery limits, use a labeled new attempt with a fresh context and
neutral inputs, not the contaminated account as its starting point. Otherwise record
the blocked handoff without reducing N. A different cwd alone does not isolate reads.

Match the brief and expected conclusions to the scope. Give case researchers access to
relevant primary sources and history within scope. A restricted evidence check tests
only its stated question; grade it within that scope. Make time, resource and evidence
limits explicit, and keep calibration success separate from research acceptance.

Published cases can seed retrospective skill improvements, not blind answers or gold
verdicts. Freeze the website snapshot and follow selected claims to primary sources;
keep site labels, annotations, PASS fields and retrospective conclusions out of worker
packets. Reconstruct neutral packets from the sources, not by merely deleting a verdict
field. Missing projected evidence is not proof of missing original research. A published
TP-only set cannot measure false-positive rejection or general audit accuracy: include
relevant negative/authorized-operation contrasts and held-out cases before claiming an
improvement. Record corpus coverage, primary-source checks and execution failures
separately; inspecting many displayed records is not that many completed audits.

Resolve the manifest, claims, assigned agents, inputs and endpoint from batch bindings.
Create new batches with `audit_dispatch.py create`, keep the leader receipt private,
and register the frozen role skills using the existing dispatch tools. Diagnose failures
from original receipts and confirm the earlier execution stopped. Classify unavailable
runtime/profile and retrieval-tool failures separately from exhausted evidence probes
and source access denials; labels alone do not establish their scope. Within existing
authorization and recovery limits, repair the runtime fault and use one inspected retry.
For an unchanged active binding, use dispatch `run --resume` only after the original
runner stops. Changed briefs, commands or outputs require a new registered attempt
with a fresh output directory inside the allocated batch; retirement does not free
the old output path. Runner conversation resumption is separate: retain its recorded
session and case owner, bind the new cwd/output, and pin transferred prior artifacts.
Such a continuation is not a fresh blind audit.
If an auditor's context remains unavailable, retain its failed submission and register a
labeled fresh blind attempt from neutral sources with a recorded handoff; do not present
it as the original author's correction. Preserve the original adjudicator and all N lanes.
Correct a mistaken resource measurement without relaxing the actual workload bound.
Apply the operating gates required for the actual workload and current authorization;
do not import a timing campaign's quiet gate into static evidence work by default.

## Accept and close the authorized handoff

Route advisory refreshes through `radar-incremental`. Verify its frozen export,
overlapping source window and complete prior delta/summary chain; preserve unresolved
off-ledger, status, conflict and foreign-owner queues. Source coverage is separate
from causal acceptance. The leader owns authorized UNANALYZED intake and readback;
accepted research updates still use assessments and finalize. Keep source capture,
research, ledger and publication checkpoints distinct through the handoff.

Review each case's causal explanation against primary evidence, competing explanations
and every assigned report. Challenge what could still change it, including omitted
routes and shared assumptions. For every outstanding case, connect the supported claim,
blocking fact or missing submission, next owner and decisive acceptance observation.
Before accepting attribution to a change, ask whether its immediate parent already
permits the same effect under matched configuration, authority and state. For a claimed
repair, inspect the consuming caller and any material omitted route. Request the
observation that would distinguish the competing explanations, rather than a tool list.
Recover eligible missing/invalid independent submissions through their assigned auditor;
return causal questions to the same adjudicator. Neither action substitutes for the other.
Under the adopted research-work contract, combine its worklist and unassessed cases with
input completeness; verdicts and evidence grades alone are not work queues. Inspect actual
outcomes and report new facts, valid submissions and accepted cases separately. If a return
adds none, diagnose the unresolved dependency before repeating the assignment. An empty
recorded queue proves neither complete discovery nor causal truth. Keep these findings
and owners in the existing index, distinguishing unfinished work, researched uncertainty,
protocol acceptance and publication.

Bind acceptance to exact records, reports, decisive receipts and check results. Individual
research acceptance and batch delivery are separate. Before batch closeout, run the frozen
gate against the original manifest, all N lanes, final records and decisions; a smaller
passing subset cannot replace it. Re-review changed findings before refreshing receipts.
Format checks do not establish causal truth.

Reconcile counts and digest bindings with the frozen snapshot parser and decision schema;
raw JSON-file counts can include non-record artifacts. Reuse a successful check only when
its inputs, code, contract and command remain unchanged and the frozen contract permits;
identify reused results and retain failed runs. If only packaging remains, finish that
delivery with the same owner and immutable reviewed payload instead of repeating causal
research. Seal stable payloads; bind runner receipts written after return separately.
Keep mutable execution/status data outside frozen decision files. For new assignments,
use the operating guide's dedicated decision file and keep pointers in the coordination
index. Write new status summaries outside pinned inputs; preserve existing frozen layouts.

Record the disposition, evidence or concrete return, next owner and endpoint before
retiring assignments or releasing claims. A worker's handoff returns work to the leader;
continue the remaining authorized cases and recoverable tasks. Close the overall task
when its endpoint is achieved, or report the specific unresolved external dependencies
and applicable limits after available work is exhausted. Keep execution, research
acceptance and publication separate.
