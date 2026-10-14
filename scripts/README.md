# Audit operations

Run from the canonical checkout, with the NUMA binding in [AGENTS.md](../AGENTS.md).
Research follows [AUDIT-PROTOCOL](../docs/AUDIT-PROTOCOL.md); causal adjudication follows
[ADJUDICATION-PROTOCOL](../docs/ADJUDICATION-PROTOCOL.md). The
[release runbook](../docs/RELEASE-RUNBOOK.md) covers landing and publication.

## Operating arrangement

One project leader dispatches, accepts deliveries and runs release. Each research group
has N independent auditors and one adjudicator, who keeps each case's follow-ups.
Parallel groups have disjoint manifests and output roots, with one writer per decision
file; they share the same canonical writer. The controlling agent can be the leader.
The user supplies scope and the authorized endpoint; the leader handles routine routing.

| Role | Owned workspace/output | Responsibility |
| --- | --- | --- |
| [Leader](../.agents/skills/radar-lead/SKILL.md) | Canonical checkout; manifest, assignment/status index and release receipts | Claim the case, freeze inputs, dispatch, recover execution, accept deliverables and release |
| [Auditor](../.agents/skills/radar-audit/SKILL.md) | Own case/attempt workspace, final records and evidence | Independently complete AUDIT-PROTOCOL and submit the report |
| [Adjudicator](../.agents/skills/radar-adjudicate/SKILL.md) | Group's investigation, accepted records and frozen decisions | Read all sealed reports, resolve conflicts and complete causal research |

These three project skills are role entry points. They use the protocols for research
standards and this document for commands; they do not define another workflow or state
store. Release is part of the leader's role and loads the runbook only when needed.

**Only the leader claims the case.** Auditors and adjudicators are assignments within
that ownership; they do not acquire or release claims. Record their completion, errors,
research acceptance and publication in the existing batch index, never in claim results.

Before launching, freeze the neutral manifest, N auditor names, assigned role skill,
both protocols, schema, operating guide, brief and gate code as copies with SHA-256 hashes.
Record absolute input/cwd/output paths,
canonical claim path, each case's assigned owners/lanes/attempts, actual model/profile,
source snapshot, budgets and concurrency/recovery limits. Register the authorized
endpoint: research handoff, ledger landing or verified live site. Claim only admitted
work. Calibrate new profiles/contracts and check the first five cases before scaling.

Keep local batch files under `research/<batch>/`, for example:

```text
manifest.txt, brief.md, index.json     leader-owned coordination
neutral/<case>/                       neutral primary inputs and pinned contracts
auditors/<lane>/work/<case>/<attempt>/ working files
auditors/<lane>/records/               final reports; one selected attempt per case
auditors/<lane>/evidence/              retained receipts
adjudication/work/<case>/             adjudicator's investigation
adjudication/accepted/                final synthesis records
adjudication/decisions.json           frozen research decisions
release/                              leader's landing/deployment receipts
```

Each auditor gets a fresh context per case without the leader's conversation. Permitted
reads are neutral inputs, primary source clones, required tool code and its own workspace.
Keep prior verdicts, other lanes, adjudication outputs, canonical research rows and website
judgments out of audit inputs. Source clones are read-only; fetches/experiments use owned
scratch clones. A different cwd/worktree is not filesystem isolation: configure runner
read restrictions/mounts when available and record instruction-only isolation otherwise.
An attempt that saw another judgment is no longer blind.
Stop and preserve that attempt, record the exposure source and extent, and let the
leader arrange a labeled fresh-context attempt within the recovery limits or a blocked
handoff. Do not feed the contaminated account to the new independent attempt, erase
the original or reduce N to count only clean completions.

## Dispatch and handoff

1. The leader selects pending case IDs from the manifest/index, claims each case once,
   saves the returned `claim_id` in coordination metadata and assigns the same case to
   all N auditors. Keep claim receipts outside frozen research decisions.
2. Auditors save reports, evidence and check receipts in their owned paths. The leader
   verifies identity, coverage and submission completeness, then records submission in
   the index. Freeze reports/hashes before cross-reading. Subsequent substantive work
   belongs to adjudication or a labeled new attempt; never overwrite the blind report.
3. Once a case has all N sealed reports, its adjudicator starts research. Unrelated cases
   need not wait. Missing/failed attempts remain visible and do not reduce the declared N;
   the leader handles bounded recovery or a documented blocked handoff.
4. The adjudicator submits the final synthesis, competing readings, decisive receipts,
   residual conclusions and frozen decisions. The leader checks the delivery gate for
   the declared manifest and traces disputed dimensions and TP BIC/AI/fix conclusions
   to evidence. Return a specific missing observation to the same adjudicator when
   needed; a green format gate does not establish research acceptance.
5. The leader continues the release runbook to the authorized endpoint, records the
   outcome, then releases the exact claim. For an unfinished handoff, record the next
   question and stop the old attempt before releasing. Unclaimed does not mean completed,
   accepted, landed or published; a researched BLOCKED handoff stays research BLOCKED.

Claims do not select tasks, launch agents, count reports or trigger adjudication.
Use the existing index and dispatcher/watcher for those responsibilities; do not start
another writer. Retain execution failures and bounded retries. A safety refusal is a
recorded handoff, never a reason to retry the refused investigation.

## Dispatch guard

Use `scripts/audit_dispatch.py` from the canonical checkout. The leader first creates
the batch from a selection manifest staged outside the new batch directory:

```json
{"batch":"r23", "leader":"leader", "endpoint":"research", "manifest":"/path/to/selection.txt"}
```

```sh
python3 scripts/audit_dispatch.py create batch-spec.json > /path/to/leader-private/r23-receipt.json
```

This replaces manual directory/manifest creation: it copies the manifest and fixes the
batch identity in `research/r23/index.json`. Existing directories and occupied cases
are refused. Creation does not claim cases; the leader then claims the copied manifest
as above. Keep the returned receipt in leader-only storage, outside auditor inputs and
shared batch files. The index stores only its token hash. A batch name, owner name or
task binding cannot substitute for this receipt.

The leader registers each assignment with that receipt; agents receive only their own
task binding for execution/resumption. Registration stores immutable bindings under
`dispatch` in the same index, preserving its other fields. Relative paths resolve from
the registration cwd. Example task spec (replace the batch and discovered pane):

```json
{
  "batch": "r23", "task": "review-a", "agent": "w8:pEXAMPLE",
  "role": "auditor", "leader": "leader", "endpoint": "research",
  "manifest": "research/r23/manifest.txt",
  "cwd": "/home/hanqing/agents/ai-slop",
  "output": "research/r23/auditors/a",
  "brief": "research/r23/neutral/review-a.md",
  "skill": "research/r23/contract/skills/radar-audit/SKILL.md",
  "inputs": ["research/r23/neutral/evidence", "research/r23/contract"],
  "command": ["herdr", "agent", "prompt", "w8:pEXAMPLE", "{brief}", "--wait"]
}
```

```sh
python3 scripts/audit_dispatch.py register <task-spec.json> --batch-receipt /path/to/leader-private/r23-receipt.json
python3 scripts/audit_dispatch.py check --batch r23 --task review-a --binding <returned-binding-sha256>
python3 scripts/audit_dispatch.py run --batch r23 --task review-a --binding <returned-binding-sha256>
# Only after inspecting the previous attempt and confirming it has stopped:
python3 scripts/audit_dispatch.py run --batch r23 --task review-a --binding <returned-binding-sha256> --resume
python3 scripts/audit_dispatch.py retire --batch r23 --task review-a --binding <returned-binding-sha256>
```

For new role-based assignments, copy the chosen project `SKILL.md` into the batch's
contract snapshot and supply its path in `skill`: `radar-audit` for an auditor,
`radar-adjudicate` for an adjudicator. Registration pins that file automatically and
the dispatched prompt explicitly tells the worker to read it, even in runners without
native skill discovery. Referenced files are not copied or pinned recursively: include
the frozen protocols, schema, this operating guide and gates in `inputs`. Map their
absolute frozen paths in the brief. Keep executable gate dependencies together as
specified in DATA-SCHEMA, and keep evaluator keys out of all worker input directories.
Repository paths in a skill locate source templates; workers use the frozen paths
supplied by their assignment. A missing, changed or conflicting binding/contract stops
the affected assignment for leader repair or explicit migration; never silently use
the current checkout or classify broken setup as a researched case-level gap.

`skill` is optional for compatibility with older task specs. Omission does not inject
a current skill into a legacy task. Existing bindings remain unchanged; adopting a
new skill or protocol requires a new assignment after the old work is stopped and sealed.

Registration verifies the leader receipt and batch allocation, then pins the manifest,
exact claim acquisitions, brief, supplied skill, inputs and command;
retain its receipt in the leader's task assignment. Inputs are files or small sealed
directories, including frozen contracts; do not hash an entire source clone. Every
check/run validates those pins and current ownership. Cross-batch case overlap, a second
active adjudicator, occupied agents, shared/nested outputs and active writers of inputs
are refused. A process lock excludes concurrent runs and retirement; a persisted send
marker refuses duplicate dispatch even after the foreground command exits. `--resume`
is explicit recovery, never an automatic retry after a timeout or safety refusal.

The command is fixed argv, with exactly one `{brief}` argument replaced by the pinned
brief and a task-identity header. Use a foreground runner that waits for its actual work;
Herdr prompts require `--wait`. Follow the Herdr skill's environment/readiness checks;
the guard also requires the exact bound pane/cwd to be idle or done. After ambiguous
delivery, inspect the actual pane before any resume. Keep NUMA binding
on the invocation. The guard is not a sandbox: configure runner read/write limits and
fresh case contexts separately. Free-form tool calls bypass it, so do not dispatch around it.

Retire an assignment only after its runner has stopped and outputs/handoff are recorded.
Retirement does not accept research or release claims. A new task needs a new output
directory; changing batches also requires a fresh conversation and a batch-specific tab
label. Preserve old bindings and reports. Keep frozen adjudication decisions in their
own file so execution metadata changes cannot rewrite a frozen decision-file hash.
Legacy directories cannot be silently enrolled. Preserve their originals; a fresh
closeout batch can use sealed legacy outputs after the former work has stopped and
claims have been handed off. Old dispatches without a batch allocation can be retired
but cannot resume through this entry point. Peer checks cover registered assignments,
not arbitrary background processes. A lost creation receipt requires recovery by the
leader, never automatic adoption or replacement of the existing allocation.

## Foreground flow pilot

For **new** batches adopting `causal-work-v1`, `radar_flow.py`, `audit_delivery.py`
and `radar_release.py` replace repeated delivery/routing/release glue. They use the
existing allocation, task bindings, index, claims and ledger CLI. Frozen or stopped
batches are not enrolled. Freeze these helpers with the record/reduction gates,
comparison code and `audit_envelope.py`/`ledger_store.py` dependencies; map their
absolute frozen paths in briefs and runner mounts. Evaluator fixtures are not worker
inputs. The controlling leader keeps its private allocation receipt and public plans
outside worker inputs. Workers see only their own `INPUT-BINDING.json`, their assigned
neutral sources and frozen contracts; the adjudicator also sees all sealed lane outputs.

After creating, claiming and registering all N independent auditors, save a leader plan:

```json
{
  "batch": "r23", "n": 2,
  "auditors": [
    {"batch":"r23", "task":"a", "binding_sha256":"<registration hash>"},
    {"batch":"r23", "task":"b", "binding_sha256":"<registration hash>"}
  ],
  "adjudicator": {"...":"complete unregistered adjudicator task spec"}
}
```

The adjudicator spec must include each complete auditor output directory as an absolute
`inputs` path. The role briefs name the same independent lanes (default task names;
an optional `lane` on each auditor receipt supplies another name). Register the adjudicator
only through the flow, after every delivery is sealed and its writer is retired.
Paths are absolute. A one-case record is an exact file; a multi-case delivery uses a
complete records-only directory, separate from reports, evidence and checks.

```sh
python3 scripts/radar_flow.py advance <flow-plan.json> --batch-receipt <leader-private-receipt.json>
```

The pilot runs one foreground worker at a time, then its sole adjudicator. Bound group
concurrency under the shared host policy separately; this is not a background broker.
It writes a public `INPUT-BINDING.json` within each fresh output before dispatch. The
worker runs the frozen helper in its actual sandbox before research:

```sh
python3 <frozen>/radar_flow.py inputs <owned-output>/INPUT-BINDING.json --binding <prompt-binding-hash>
```

Missing mounts are setup failures. Input hashing never imports another auditor's judgments.
After the frozen Submission checks, the worker creates an owned delivery spec:

```json
{
  "batch":"r23", "task":"a", "binding_sha256":"<prompt-binding-hash>",
  "manifest":"/absolute/frozen/manifest.txt", "output":"/absolute/owned/output",
  "report":"/absolute/owned/output/report.md",
  "records":{"class-id":"/absolute/owned/output/records/class-id.json"},
  "research_work":{"class-id":"/absolute/owned/output/research/class-id.json"},
  "evidence":["/absolute/owned/output/evidence/source.txt"],
  "checks":["/absolute/owned/output/checks/strict.json"]
}
```

Check receipts contain the actual `argv` and integer `exit_code`; optional `outputs`
entries pin raw stdout/stderr with `path`/`sha256`. Keep all receipts inside the owned
output. Auditor sidecars contain `research` (or its six dimensions directly), with
evidence paths relative to the sidecar or absolute owned paths. Adjudicators additionally
supply `decisions` as an absolute path to their frozen decisions; their research is also
validated by the reduction gate. Packaging pins all supplied files and sidecar receipts,
rejects duplicate JSON keys and exact-manifest omissions, and refuses to overwrite a seal.
It does not replace structural/local-object checks or substantive research.

```sh
python3 <frozen>/audit_delivery.py seal <delivery-spec.json>
python3 <frozen>/audit_delivery.py check <owned-output>/DELIVERY.json
```

The flow collects only a successful recorded terminal command plus valid final bytes.
It reuses that delivery on another invocation, without sending another prompt. A timeout,
ambiguous send or incomplete delivery creates `HOLD` with the leader and next action;
it does not reduce N or become a researched blocker. The final checkpoint is
`AWAITING_LEADER_SOURCE_REVIEW`. The leader reviews primary evidence and competing
explanations, including matched parent behavior and the actual repair caller. A passing
gate or unanimous labels never create that review.

For an inspected ordinary fault requiring a new binding, stop/retire the exact old
assignment, register the new attempt in a fresh output with the original leader receipt,
then use `radar_flow.py migrate <replacement-plan.json> --batch-receipt <private-receipt.json>
--inspection <inspection.json>` before `advance`. Replace one failed lane at a time,
retain its original `lane` name and N, and update the not-yet-registered adjudicator's
brief/input paths to all complete reports. The inspection has the same original-attempt
fields as dispatch recovery, plus a substantive `next_question`. Original plans and
failures stay under `flow.migrations`/`dispatch`. A valid sealed blind input remains
original even if leader collection was interrupted; repeat the original plan to collect
it without a new prompt. Subsequent causal corrections belong to adjudication. A registered adjudicator
continuation retains its owner, pins its original artifacts, and uses a new task/output;
its inspection may classify `research_followup`. Migration never bypasses a batch stop,
alters the manifest/endpoint/N or reopens a release already started.

After source review, save a `leader_review` JSON with `batch`, `leader`, the final
`delivery_sha256`, and a `cases` object covering the original manifest. Each case has
a substantive `basis` and primary `evidence` entries (`path`, `sha256`) from the sealed
accepted delivery. Prepare full stable-ID assessments from actual registered runs and
revision-checked canonical patches under the existing data contract, including envelope
and duplicate-TP review. Save the leader release plan:

```json
{
  "batch":"r23", "description":"Reviewed research landing",
  "patches":"/absolute/leader/patches.jsonl",
  "assessments":"/absolute/leader/assessments.jsonl",
  "leader_review":"/absolute/leader/leader-review.json"
}
```

```sh
python3 scripts/radar_release.py <release-plan.json> --batch-receipt <leader-private-receipt.json>
```

This reruns the assigned frozen reduction gate against all N sealed lanes and the
original manifest. It pins the release intent in the same index, compares existing
assessment contents (not only IDs), stores missing assessments, finalizes once, then
checks the complete row, revision, history, checksum, actor and supporting assessments.
On interruption it reads Neon before any write. A matching committed transaction resumes
at export/check; a prior finalize intent without matching landing holds for inspected
reconciliation, never blind replay. Receipts keep real argv, output hashes and exit codes.
The ledger endpoint records its outcome before releasing exact original claim IDs.
For `site`, it reports `AWAITING_PUBLICATION` and retains claims; the same leader completes
[generation, deployment and live content verification](../docs/RELEASE-RUNBOOK.md#3-generate-and-check-the-website)
without asking for routine permission again. Site automation is not implemented by this
pilot. Scan-run completion still follows the runbook and actual assessment coverage.

The dispatcher now stores `attempts` before/after execution. A lost wrapper stays
`STARTED` with null exit; it is never invented as successful. An inspected ordinary
fault can use `run --resume --inspection <json>`: the inspection binds `batch`, `task`,
`binding_sha256`, original `attempt_id` (null for legacy), `classification` (`runtime_fault`
or `delivery_fault`), `previous_work_stopped:true`, and pinned `evidence` receipts.
Generic `TARGET_FAILED` alone is insufficient; inspect upstream logs for the real cause.
Record an actual safety refusal or operating stop immediately:

```sh
python3 scripts/audit_dispatch.py stop --batch <batch> --batch-receipt <private-receipt.json> \
  --reason safety_refusal --evidence <original-refusal-receipt>
```

This blocks registration/resumption/new flow research, including other tasks in the
batch. It does not signal workers, declare them stopped or clear occupancy. Confirm
owned processes have stopped, preserve their real terminal receipts, record stopped-work
handoffs and release exact own claims under the runbook. Do not reroute refused research.

Offline validation uses `scripts/tests/test_radar_flow.py`: harmless real foreground
workers, real reduction gates, isolated claim logs and a fake canonical store. It tests
delivery/transaction invariants, not first-pass vulnerability understanding. Measure the
latter on a fresh permitted held-out batch, preserving pre-correction outputs and counting
leader interventions, substantive revisions, unsupported claims and the full denominator.

## Claim commands

Run the canonical `scripts/claims.py` from `/home/hanqing/agents/ai-slop` on this host.
Its shared log is `/home/hanqing/agents/ai-slop/artifacts/claims/claims.jsonl`; an alternate
cwd must still invoke this script's absolute path. Do not create a private log in another
checkout: the canonical ledger guard reads this default path. `--claims-file` selects an
isolated log for tests; using it elsewhere does not redirect the ledger guard.

```sh
python3 scripts/claims.py claim --class-id <id> --owner <leader> --scope <batch>
python3 scripts/claims.py list --class-id <id>
python3 scripts/claims.py claim --class-id <id> --owner <leader> --scope <batch> --claim-id <receipt-id>
python3 scripts/claims.py release --class-id <id> --owner <leader> --claim-id <receipt-id>
```

The first command acquires; the second reads; the third renews the same acquisition;
the fourth releases it. Output is JSON/JSONL with `claimed: true/false`. `list` defaults
to occupied cases; `--all` includes historical unclaimed cases. A specific unknown case
returns false. Scope/owner filters select cases, but all their current holders stay
visible, including historical slots. Scope is metadata; it does not create another lock.

Claim and release checks are atomic. Retain the receipt ID: neither another owner nor
an old receipt can release a new acquisition, even if the owner name is reused.
An exact repeated release is harmless until that slot is acquired again. Leases default
to 24 hours (`--hours`); expiration sets `expired: true` while `claimed` remains true.
Investigate a lost owner and stop the former process before releasing/reassigning;
time alone never releases the lock. An expired foreign claim also blocks ledger writes.

Historical logs stay append-only and readable; no bulk rewrite or cleanup is needed.
Old slot holders remain occupied until individually released, so a new leader cannot
claim that case prematurely. `release --slot <old-slot>` targets such a holder; legacy
records may close without a receipt ID, and old `done` calls remain a release-only alias.
New claims always require their receipt ID for release; `--result` stores no verdict.
New per-lane claims, `pick` and `sweep` are disabled. Update old dispatchers/TSV readers
before reuse; `list` now emits JSONL. Never run frozen old claim tools against new claims.

## Submission

Save the independent report and primary receipts before cross-reading. Receipts can be
plain text: command/URL, repository, full object SHA/version, capture time, exit/HTTP
result and raw output. Preserve failed probes. Hash the receipts and keep original
outputs immutable; corrections are new attempts linked to their originals.

Write report text and structured records with file patches or a script that serializes
data from files. Do not interpolate source quotations or whole JSON documents into
nested shell command strings. After a quoting/write failure, inspect the actual files
and diagnostics before continuing; a later successful check does not erase that failure.

```sh
python3 scripts/audit_record_gates.py --strict <case.json>
python3 scripts/audit_record_gates.py --strict --repo <clone-dir> <case.json>
```

Use the frozen gate code and retain both outputs. The first checks structure; the second
checks commit quotes and parent links without fetching. Neither proves causal truth,
atomicity, absent AI use or web disclosure scope. Retain a failed local check with its
alternative primary evidence or explicit research gap; never invent a value for `ok`.
Prefer local Git and patch/raw/PR sources; avoid API calls while rate-limited.

Reject duplicate JSON keys and unfinished drafts. A crash, timeout, rate limit or empty
response belongs in execution errors; resume within the assigned limits. Do not turn
it into a researched gap or completed independent audit. An actual EVIDENCE_GAP names
the evidence sought, bounded probes/results and the next decisive question.
Submission, research acceptance and publication are separate states in the batch index.

For new batches adopting the research-work sidecar introduced in `2026-09-25.1`, bind the schema's
[research-work contract](../docs/DATA-SCHEMA.md#research-work-contract) and invoke the
reduction gate with `--research-contract causal-work-v1`. Its `research_work.worklist`
includes unfinished qualified conclusions as well as unresolved ones. Review
`unassessed_cases` and the actual findings before treating an empty list as a handoff.
Before sealing an auditor sidecar, validate it with the frozen `check_research_work`
and verify its receipt hashes. The leader checks each supplied sidecar before relying
on its work states; an invalid sidecar remains unassessed. Keep the independent
sidecars with their sealed reports; the reduction gate validates the adjudicator's
recorded work, not the completeness of source discovery. Frozen old
batches continue using their pinned commands and contracts.

Comparison/reduction lane and accepted arguments accept exact record files or
records-only directories. Use the original `record.json` for a one-case task; for a
batch, bind a complete view whose record bytes match the sealed originals. The directory
loader recursively parses JSON, so source-response arrays, receipts and scratch checkouts
belong outside that view. Keep every manifest case and assigned lane, and retain the
original reports and evidence for research and decision pins. A packaging retry preserves
the failed invocation and is not a fresh independent research attempt.

A pass that changes accepted records after their decision digest exists is diagnostic until
it ships a fresh `audit_reduction_gate.py` receipt for the changed bytes; the
earlier digest and the earlier pin set are historical from that moment.

Handoffs identify the case/task/attempt, owned report and record paths, decisive receipts,
exact check commands/results (including failures or checks not run), and any unresolved
question with its next owner. Auditors give the leader sealed independent outputs for
routing; adjudicators also supply final decisions and the reduction-gate receipt for
all assigned lanes. Put gate output and decision-file hashes outside the frozen files.
Do not narrow the manifest or omit missing/failed lanes to obtain PASS. A worker's
completed command, sealed submission or accepted research grants no claim-release,
ledger or publication authority; the leader continues only to the authorized endpoint.
