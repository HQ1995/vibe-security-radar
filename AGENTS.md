# Vibe Security Radar

Public catalog of vulnerabilities where AI-assisted changes played a role:
https://vibesecradar.com/. For every advisory we research its cause, its impact, its history
(introduction, exposure, repair, release) and the role AI played, from primary evidence.
Keep committed content in English.

The skills run in a local Codex or Claude Code session: the leader starts every other role as a
fresh session on one of the project's preferred models (`.agents/skills/radar-lead/models.json`). Work through the skill for your role; each one says
which of its references to read when.

| Skill | Role |
| --- | --- |
| [radar-lead](.agents/skills/radar-lead/SKILL.md) | Select cases, start the other roles as subagents, seal, check and land with `scripts/radar_case.py`, publish |
| [radar-incremental](.agents/skills/radar-incremental/SKILL.md) | Capture new advisories since the watermark and admit them |
| [radar-audit](.agents/skills/radar-audit/SKILL.md) | One independent auditor, one case |
| [radar-adjudicate](.agents/skills/radar-adjudicate/SKILL.md) | The sole adjudicator of a case |

## Rules

- Research is defensive analysis of published vulnerabilities. Reproduce only in owned,
  isolated checkouts; never contact deployed third-party systems or build working payloads.
  A safety refusal stops the work; record it and ask the user, never reroute it.
- Independent auditors never see each other's work, prior verdicts or site labels.
- Only the leader claims cases and writes canonical data. Neon `ledger_rows` is the
  canonical ledger; the JSONL export in `artifacts/` and the site data in `web/src/generated/`
  are generated, never hand-edited.
- Execution, research acceptance, ledger landing and publication are separate states. A
  passing gate, released claim or exit code establishes none of the others.
- Pushing `main` deploys the site through the Cloudflare Pages Git integration from committed
  data. Keep CI and tests off Neon: the free tier is metered. Public data must pass
  `scripts/site_preflight.py`; never use allowlisting as a filter.
- Reader-facing copy says "AI-assisted change" and "AI-assisted fix"; "candidate" stays
  internal to data fields and audit prose.
- `research/` and `.ai-slop/` hold local batches, evidence, runs, clones and sources; never
  commit them. Make the smallest complete change and run the checks relevant to it; tests
  use fixtures, not live APIs.

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
