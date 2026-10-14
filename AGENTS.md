# Vibe Security Radar

Public AI-vulnerability catalog: https://vibesecradar.com/.
Keep committed content in English.

## Working rules

- Make the smallest complete change; fix root causes, reuse code and preserve unrelated work.
- Prefer parallel work across independent cases, with isolated contexts and owned
  outputs. Bound total concurrency by the shared host budget. Keep the same owner
  through each case's causal chain and follow-up; record the next decisive question.
- Only the leader claims a case: `python3 scripts/claims.py claim --class-id <id>
  --owner <leader> --scope <batch>`. Keep its returned `claim_id` through the authorized
  endpoint or recorded handoff, then `release --class-id <id> --owner <leader>
  --claim-id <receipt-id>`. Auditors/adjudicators are assignments in the batch index;
  they do not claim separately. Claims mean occupied/unoccupied, never research progress.
  A foreign claim blocks ledger writes even after lease expiry; expiry is diagnostic.
  Claims live in the append-only `artifacts/claims/claims.jsonl`, never exported to the
  ledger or site. Commands and legacy handoff: [Audit operations](scripts/README.md).
- Reuse neutral primary evidence for blind review; hide prior judgments.
- Audit role entry points: [radar-lead](.agents/skills/radar-lead/SKILL.md) for
  coordination, recovery and release; [radar-audit](.agents/skills/radar-audit/SKILL.md)
  for each independent reviewer; [radar-adjudicate](.agents/skills/radar-adjudicate/SKILL.md)
  for the sole reducer. Dispatch the assigned frozen skill explicitly. Skills route
  work to the protocols and tools below; they do not replace the research contract.
- Create new batches with `scripts/audit_dispatch.py create`; never adopt an existing
  directory as a new task. Only the leader uses its private batch receipt to `register`
  assignments; agents use their assigned task binding for `run`/resumption. This binds
  the manifest, claims, agent, inputs and output. Never infer ownership from a tab,
  directory or report. Follow the [dispatch guard](scripts/README.md#dispatch-guard).
- N auditors (including review and verify) independently research each case under
  the same audit protocol, without reading one another's judgments. One adjudicator
  (the reducer role) reads all reports, resolves conflicts and completes the research
  under the [Adjudication protocol](docs/ADJUDICATION-PROTOCOL.md).
  Default roles, workspace boundaries, shared claim paths and handoffs follow the
  [operating arrangement](scripts/README.md#operating-arrangement): the leader owns
  dispatch, delivery acceptance and release; the adjudicator owns causal research.
  Freeze both protocols, schema, briefs and gate code per batch. Briefs supply
  assignments and operating limits, not alternative research rules.
- Before fanning out a new runner/profile, run one harmless multi-turn check.
- In the existing run index, separate execution status, research acceptance,
  and publication status. A released claim or a passing format gate does not
  establish research acceptance. Worker crashes and timeouts remain execution failures.
  Research closeout requires `scripts/audit_reduction_gate.py` against the final
  case manifest, all assigned auditor inputs, accepted records and decisions; an assembler's
  agreement count cannot replace it. Changed bytes invalidate the affected acceptance.
- Follow the assigned scope, file ownership, read-only and stop instructions.
  Shared files have one writer; the leader resolves conflicts.
- Audits: [Audit protocol](docs/AUDIT-PROTOCOL.md).
  Fields: [Data schema](docs/DATA-SCHEMA.md).
- Keep research, caches and worktrees local; do not commit ignored files.
- Run checks relevant to the change. Analyzer code uses dataclasses, synchronous
  httpx and argv-only subprocesses; unit tests use fixtures, not live APIs.
- Reader-facing copy says "AI-assisted change" and "AI-assisted fix"; the word
  "candidate" stays internal to data fields and audit prose.

## Data and commands

- Neon `ledger_rows` is the canonical ledger: updating the database and updating
  the ledger are one operation. JSONL is a generated export; site data is a projection.
- Only the leader writes canonical data: `scripts/ledger_store.py`
  (`assessment-add`, `finalize`, `export`) and `scripts/publish_tp_ledger.py`
  (generated site data).
  Check records and duplicate TPs before `finalize`; export/publish only after
  the transaction succeeds. Publish reads Neon `ledger_rows`; the jsonl file is
  a recovery export, and `--prefer-export` uses it only when its sha256 matches
  the Neon snapshot digest (stale exports fall back to Neon). Never hand-edit
  exports or generated site data.
- In `web/`, `npm run dev` and `npm run build` use committed generated site
  data and do not read Neon. Push deploys come from the Cloudflare Pages Git
  integration (root directory `web/`, output `out/`, build command installs
  `pytest` then runs `npm run build`), whose build container has no Neon
  credentials; only a manual `Deploy Pages (manual, from Neon)` dispatch runs
  `publish_tp_ledger.py` against Neon. Keep CI and tests off Neon: the free
  tier is metered.
  Public data must pass `scripts/site_preflight.py`; never use allowlisting as a filter.

## Case lifecycle and release

Follow the [Case lifecycle runbook](docs/RELEASE-RUNBOOK.md) for case ownership,
handoff, assessment ingestion, ledger landing, export recovery and website publication.
One named release owner carries accepted research through the authorized endpoint;
Release occupancy only after recording the authorized outcome or a stopped-work handoff;
never infer release from ledger status or use `sweep`.

## host-1 NUMA

- Verify topology with `numactl -H` before heavy work. Node 0 is reserved for
  SORT; preserve its timing bindings. Run all other commands with
  `numactl --cpunodebind=1 --membind=1 <cmd>`; never guess CPU ranges.
- Docker: `--cpuset-cpus=32-63,96-127 --cpuset-mems=1` after topology verification.
  Check affinity before and after long runs (`numactl --show` or `taskset -pc $$`).
  Timing benchmarks require node isolation.
- For a declared memory bound, record node-local
  `MemFree + FilePages + SReclaimable - Shmem`, global `MemAvailable`, cgroup
  `memory.max`/`memory.high`, memory PSI and swap. Stop if capacity or limits
  fall below the bound, or pressure/swap gates fail. Never spill onto node 0;
  raw `MemFree` is not capacity.
