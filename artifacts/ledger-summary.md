# Vibe Security Radar — research total account

Window: 2025-05-01 .. 2026-08-09 (official census) / 2026-08-14 (our pools).
Last updated: 2026-08-16.

## Global denominator (official census, local mirror)

- Distinct advisory alias-classes (CVE+GHSA deduped): **84,798**
  - states: PUBLISHED 79,808 / ACTIVE 79,161 / WITHDRAWN 382 / REJECTED 363
  - source: autoresearch/orchestrator-260809-0539/current-official-census/alias_classes.jsonl
- Subject rows (advisory x repo/pkg associations): 159,714

## Our research pool (what we actually hold)

- Advisories in pool: **10,083** = 11.9% of the global denominator
  - fixrefs pool: 5,964
  - nofix pool: 4,119
- Distinct repos in pool: 5,824
- AI-commit scan coverage: 39 / 5,824 repos (observation bound, not population)

## AI-causality buckets (derived from artifacts/ledger.jsonl, ledger-row口径)

| Bucket | Count | Meaning |
|---|---|---|
| B1_AI_FAULT | 41 | AI introduced the flaw (verified) |
| B2_NOT_AI | 1,951 | studied, not AI's fault |
| B3_BLOCKED | 664 | unresolved / evidence missing |
| fix recovered, pending review | 3,867 | fix found, dossier not yet done |
| unreviewed rows | 2,735 | no verdict at all yet |

## Rules

- This file is derived; regenerate with scripts/build_ledger_summary.py.
- All numbers are lower bounds: unstudied advisories are never assumed clean.
- Never present pool coverage as global coverage.

