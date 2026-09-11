# Vibe Security Radar

Public AI-vulnerability catalog: https://vibesecradar.com/.
Keep committed content in English.

## Working rules

- Make the smallest complete change; fix root causes, reuse code and preserve unrelated work.
- Prefer parallel work across independent cases, with isolated contexts and owned
  outputs. Bound total concurrency by the shared host budget. Keep the same owner
  through each case's causal chain and follow-up; record the next decisive question.
- Reuse neutral primary evidence for blind review; hide prior judgments.
- Before fanning out a new runner/profile, run one harmless multi-turn check.
- In the existing run index, separate execution status, research acceptance,
  and publication status.
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

## Publish flow (research -> site)

1. Land the research first: `scripts/ledger_store.py` `assessment-add` ->
   `finalize` -> `export`, and check the export sha matches the Neon snapshot
   digest.
2. Regenerate site data, `cd web`: `npm run research:data:sync` (export +
   `export-history` + `audit_envelope.py` + `publish_tp_ledger.py
   --prefer-export`) writes `web/src/generated/research-data.json`. It reads
   Neon, so run it only when a ledger change needs publishing.
3. Gate locally: `npm run build` (prebuild runs `site_preflight.py`,
   `--verify-fix-objects-live` and the advisory links; postbuild runs vitest)
   plus `npm run research:data:check`. Offline payload check: run
   `publish_tp_ledger.py --from-export` in a scratch root and diff it against
   the committed payload - only `snapshot.generated_at`, the ledger counters
   and the `snapshot.ledger` provenance label may differ.
4. Commit the payload with its overlays and push `main`; the Cloudflare Pages
   Git integration deploys `web/`. Dispatch `Deploy Pages (manual, from Neon)`
   only to republish straight from Neon.
5. Verify live: `curl -sL -o /dev/null -w '%{http_code}'`
   `https://vibesecradar.com/cves/<UPPERCASE-ID>/` - the trailing slash is
   required, a bare or lowercase path 404s.

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
