# Operations

Commands for the research workflow. Research rules are in
[audit protocol](../../radar-audit/references/protocol.md) and [adjudication protocol](../../radar-adjudicate/references/protocol.md);
landing and publication are in the [release reference](release.md). Run from the
repository root with the repository environment and the NUMA binding in [AGENTS.md](../../../../AGENTS.md):

```sh
uv venv .venv && uv pip install --python .venv/bin/python -r scripts/requirements.txt
numactl --cpunodebind=1 --membind=1 .venv/bin/python scripts/<tool>.py ...
```

## Workflow

```
radar-incremental: fetch.py -> build_delta.py -> intake_rows.py -> ledger_store.py intake -> watermark.py
                                                                          | manifest of new cases
radar-lead:        select cases -> radar_run.py admit -> run -> (review) -> land -> release
                                          | per case, each in a fresh sandboxed session
                         auditor1, auditor2 (radar-audit) -> adjudicator (radar-adjudicate) -> reviewer
```

## Operating arrangement

| Role | Skill | Owns |
| --- | --- | --- |
| Leader | [radar-lead](../SKILL.md), [radar-incremental](../../radar-incremental/SKILL.md) | Selection, claims, runs, acceptance, canonical writes, publication |
| Auditor | [radar-audit](../../radar-audit/SKILL.md) | One independent case report, record and evidence |
| Adjudicator | [radar-adjudicate](../../radar-adjudicate/SKILL.md) | The case's final record and decisions |
| Reviewer | radar-lead, "Review one case" | The leader's source review of one sealed case, in a fresh session |

Only the leader claims cases and writes canonical data. Each case is its own batch under
`research/<run>-<NNN>/`; independent lanes never read each other, and the adjudicator starts
only when both sealed auditor outputs exist. A different directory is not isolation: the
runner profile's sandbox enforces it.

## Case research

`radar_run.py` drives the whole case path through the guarded tools below.

```sh
python3 scripts/radar_run.py admit --run <run> --manifest <class ids> --leader <name> \
  --endpoint ledger --profile .ai-slop/runner.json --cutoff <UTC>
python3 scripts/radar_run.py run --run <run> --parallel 4
python3 scripts/radar_run.py status --run <run>
python3 scripts/radar_run.py land --run <run>
python3 scripts/radar_run.py resume --run <run> --case <NNN> --task <task> --inspection <json>
python3 scripts/radar_run.py stop --run <run> --reason <text>
```

- **admit** reads each row (`ledger_store.py get`), refuses occupied cases, creates the
  batch, claims the case, retains its advisory records (GitHub/NVD, with receipts) as the
  neutral packet, and registers both auditors. The run freezes one contract per role under
  `.ai-slop/runs/<run>/contract/`: that role's skill, the protocols it applies, the schema,
  this guide, AI markers, the briefs and the import closure of the worker-side helpers.
- **run** advances cases in parallel, starting a case only while node-local memory covers
  the profile's bound. Each case runs auditor1, auditor2, the adjudicator and then a
  reviewer. A failed task becomes `HOLD`; nothing is retried automatically. A refusal marker
  in any task's streams records a batch stop and stops the run (`SAFETY_STOP`).
- **land** stores every attempt as a scan run and assessment, lands accepted research with
  `radar_release.py` (reduction gate on all lanes, revision-checked finalize, readback,
  export check, exact claim release), or closes a researched blocker without changing the row.
- **status** prints one line per case; the case directory keeps receipts, review and
  release files. Workers' exact prompts and terminal streams are in `research/<batch>/.logs/`.

The runner profile describes the command: see `runner.example.json`. `prefix` and
`agent` are argv lists with `{timeout}`, `{memory_bytes}`, `{model}`, `{output}` and `{cwd}`
placeholders and exactly one `{brief}`; `sandbox` binds the workspace read-only, the output
writable, every registered input read-only and the profile's `ro_binds` and `shared_clones`.
Keep the real profile in `.ai-slop/runner.json`. Before scaling a new profile, run one
harmless multi-turn prompt through it and inspect the actual output.

## Dispatch guard

`audit_dispatch.py` binds each task before it runs; `radar_run.py` uses it for you.

```sh
python3 scripts/audit_dispatch.py create <batch-spec.json> > <leader-private receipt>
python3 scripts/audit_dispatch.py register <task-spec.json> --batch-receipt <receipt>
python3 scripts/audit_dispatch.py check|run|retire --batch <b> --task <t> --binding <sha256>
python3 scripts/audit_dispatch.py run ... --resume --inspection <json>
python3 scripts/audit_dispatch.py stop --batch <b> --batch-receipt <receipt> --reason safety_refusal --evidence <file>
```

`create` refuses an existing directory or an occupied case and returns a receipt only the
leader keeps. Registration pins the manifest, claim acquisitions, brief, skill, inputs and
fixed argv; every check and run re-verifies them and refuses overlapping outputs, a second
active adjudicator or an input still owned by an active writer. A persisted send marker
refuses duplicate dispatch. Each attempt records its start, exit, exact prompt and streams.
`--resume` needs an inspection binding the original attempt, an ordinary
`runtime_fault`/`delivery_fault` classification, `previous_work_stopped: true` and evidence
pins. `stop` blocks further dispatch in the batch; it does not signal processes.

## Dispatch and handoff

`radar_flow.py advance` connects the registered auditors to the sole adjudicator: it writes
each worker's public `INPUT-BINDING.json`, runs it, collects only a successful terminal
receipt with a valid sealed delivery, retires the task and registers the adjudicator once
every lane is sealed. Anything else is `HOLD` with the next action; N never shrinks.
`radar_flow.py migrate` replaces one inspected failed lane, or binds a labeled adjudicator
continuation for a returned review, without rewriting history. `radar_release.py` lands a
leader-reviewed case. Execution, research acceptance, landing and publication are separate
states; a released claim, a passing format gate or an exit code proves none of the others.

## Claim commands

The shared log is `artifacts/claims/claims.jsonl` (local, never published); always run this
checkout's `scripts/claims.py`.

```sh
python3 scripts/claims.py claim --class-id <id> --owner <leader> --scope <batch>
python3 scripts/claims.py list [--class-id <id>] [--all]
python3 scripts/claims.py release --class-id <id> --owner <leader> --claim-id <receipt id>
```

Claims mean occupied or free, never research progress. Keep the receipt ID; neither another
owner nor an old receipt can release a newer acquisition. Leases expire after 24 hours but an
expired foreign claim still blocks ledger writes: find the owner and arrange a real handoff.
`pick` and `sweep` are disabled.

## Incremental intake

`fetch.py`, `build_delta.py`, `intake_rows.py` and `watermark.py` live with the
[radar-incremental](../../radar-incremental/SKILL.md) skill, which gives their order.
`artifacts/source-watermark.json` records the verified source cutoff and the full delta chain;
its data files are kept in `.ai-slop/sources/`. Frozen batches from before 2026-10-14 that
imported `cve_analyzer` replay with `PYTHONPATH=<worktree at f857e3f>/cve-analyzer/src`.

## Publication

`publish_tp_ledger.py` builds `web/src/generated/research-data.json` from Neon (or a
digest-matching export) plus the committed editorial inputs in `scripts/*.json`;
`site_preflight.py`, `check_advisory_links.py` and `build_publication_adjudications.py
--verify-committed` gate the build. The radar-lead skill's Publish section lists the inputs a
new or changed AI case needs; [release](release.md) covers build, deploy and live verification.

Offline tests: `python3 -m pytest scripts/tests` and the skill's `scripts/` tests use
harmless fixture workers, real gates and fake ledgers; they never contact Neon.
