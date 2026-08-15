# Recall-first advisory candidates

## Input

- The latest forward-cohort `outcomes.jsonl`.
- Local OSV bulk archives, without a publication-date exclusion by default.
- Existing local Git clones. No clone or commit-object fetch is part of this task.

## Output

- `candidates.jsonl`: every observed cohort SHA reachable before an advisory fix.
- `fix_roots.jsonl`: every unique fix root as `RESOLVED` or `BLOCKED`.
- `routing.jsonl`: every candidate edge initially routed to `DEFER`.
- `summary.json`: input seals, scope, blocked reasons, and both conservation equations.

## Acceptance

- SZZ, path overlap, commit messages, time distance, sampling, and model scores do
  not exclude candidate edges.
- Parent topology is not date-filtered; a timeout is recorded as `BLOCKED`.
- Missing clones, unresolved references, shallow history, and malformed graphs
  remain explicit `BLOCKED` roots.
- Proven reachable edges survive a later shallow or missing-parent boundary;
  `BLOCKED` means the root may contain additional unknown candidates.
- Advisory aliases and abbreviated references that resolve to the same commit do
  not duplicate an edge.
- Targeted contract tests and existing forward-cohort tests pass.
- A diagnostic one-repository run produces all four artifacts with zero model/API calls.
