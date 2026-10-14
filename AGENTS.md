# Vibe Security Radar

Public catalog of vulnerabilities where AI-assisted changes played a role:
https://vibesecradar.com/. For every advisory we research its cause, its impact, its history
(introduction, exposure, repair, release) and the role AI played, from primary evidence.
Keep committed content in English.

## Workflow

Four skills carry the work; each links the protocol and commands it needs.

- [radar-lead](.agents/skills/radar-lead/SKILL.md): select cases, run research with
  `scripts/radar_run.py`, review, land in the ledger, prepare publication.
- [radar-incremental](.agents/skills/radar-incremental/SKILL.md): capture new and revised
  advisories since the source watermark and admit them as UNANALYZED rows.
- [radar-audit](.agents/skills/radar-audit/SKILL.md): one independent auditor, one case.
- [radar-adjudicate](.agents/skills/radar-adjudicate/SKILL.md): the sole adjudicator of a case.

Research rules: [Audit protocol](docs/AUDIT-PROTOCOL.md),
[Adjudication protocol](docs/ADJUDICATION-PROTOCOL.md), fields in [Data schema](docs/DATA-SCHEMA.md).
Commands: [Audit operations](scripts/README.md). Landing and publication:
[Release runbook](docs/RELEASE-RUNBOOK.md).

## Layout

| Path | Contents |
| --- | --- |
| `.agents/skills/` | The four skills, brief templates and the incremental tools |
| `docs/` | Protocols, data schema, runbook, AI marker catalog |
| `scripts/` | Ledger store, research driver and guards, publisher and site gates, editorial inputs (`*.json`) |
| `artifacts/` | Ledger export and history (generated from Neon), source watermark, universe policy |
| `web/` | The Next.js site; reads only `web/src/generated/research-data.json` |
| `research/`, `.ai-slop/` | Local batches, evidence, runs, clones and sources; never committed |

## Rules

- Research is defensive analysis of published vulnerabilities. Reproduce only in owned,
  isolated checkouts; never contact deployed third-party systems or build working payloads.
  A safety refusal stops the work; record it and ask the user, never reroute it.
- Independent auditors never see each other's work, prior verdicts or site labels. Reuse
  neutral primary evidence for blind review.
- Only the leader claims cases (`scripts/claims.py`) and writes canonical data. Neon
  `ledger_rows` is the canonical ledger; landing research and updating the database are one
  operation (`ledger_store.py finalize`/`intake`, usually through `radar_run.py land`). The
  JSONL export and site data are generated; never hand-edit them.
- Execution, research acceptance, ledger landing and publication are separate states. A
  passing gate, released claim or exit code establishes none of the others.
- `npm run dev`/`build` in `web/` use the committed generated data and never read Neon. Push
  deploys come from the Cloudflare Pages Git integration (root `web/`, output `out/`);
  pushing `main` is publication. The manual `Deploy Pages (manual, from Neon)` workflow is the
  only build that reads Neon. Keep CI and tests off Neon: the free tier is metered.
- Public data must pass `scripts/site_preflight.py`; never use allowlisting as a filter.
- Reader-facing copy says "AI-assisted change" and "AI-assisted fix"; "candidate" stays
  internal to data fields and audit prose.
- Make the smallest complete change and run the checks relevant to it. Tests use fixtures,
  not live APIs. Tools use dataclasses, synchronous httpx and argv-only subprocesses.

## host-1 NUMA

- Verify topology with `numactl -H` before heavy work. Node 0 is reserved for SORT; preserve
  its timing bindings. Run all other commands with `numactl --cpunodebind=1 --membind=1 <cmd>`;
  never guess CPU ranges.
- Docker: `--cpuset-cpus=32-63,96-127 --cpuset-mems=1` after topology verification. Check
  affinity before and after long runs (`numactl --show` or `taskset -pc $$`).
- For a declared memory bound, record node-local `MemFree + FilePages + SReclaimable - Shmem`,
  global `MemAvailable`, cgroup `memory.max`/`memory.high`, memory PSI and swap. Stop if
  capacity or limits fall below the bound, or pressure/swap gates fail. Never spill onto
  node 0; raw `MemFree` is not capacity.
