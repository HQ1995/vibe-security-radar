# Vibe Security Radar

Public AI-vulnerability catalog: https://vibesecradar.com/.
Keep committed content in English.

## Working rules

- Make the smallest complete change; fix root causes, reuse code and preserve unrelated work.
- Prefer parallel work across independent cases, with isolated contexts and owned
  outputs. Bound total concurrency by the shared host budget, and keep one owner
  responsible for each case's complete causal chain.
- Follow the assigned scope, file ownership, read-only and stop instructions.
  Shared files have one writer; the leader resolves conflicts.
- Audits: [Audit protocol](docs/AUDIT-PROTOCOL.md).
  Fields: [Data schema](docs/DATA-SCHEMA.md).
- Keep research, caches and worktrees local; do not commit ignored files.
- Run checks relevant to the change. Analyzer code uses dataclasses, synchronous
  httpx and argv-only subprocesses; unit tests use fixtures, not live APIs.

## Data and commands

- Only the leader writes canonical data: `scripts/ledger_store.py`
  (`assessment-add`, `finalize`, `export`), `scripts/sync_display_to_db.py`
  (display content) and `scripts/publish_tp_ledger.py` (generated site data).
  Check records and duplicate TPs before `finalize`; export/publish only after
  the transaction succeeds. Never hand-edit exports or generated site data.
- In `web/`, `npm run dev` runs the publisher; `npm run build` runs publication
  checks and tests.
  Public data must pass `scripts/site_preflight.py`; never use allowlisting as a filter.

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
