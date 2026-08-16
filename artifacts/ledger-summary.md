# Vibe Security Radar — research total account

Window: 2025-05-01 .. 2026-08-14 (advisory publication date). Last updated: 2026-08-16.

## Denominator (hard counts from local pools)

- Total distinct advisories in window: **10,083**
  - fixrefs pool (advisory -> fix known): 5,964
  - nofix pool (frozen with no fix at freeze time): 4,119
  - overlap: 0
- Distinct repositories behind those advisories: 2,442 (fixrefs+nofix repos)
- AI-commit census: 66 repos scanned, 66/66 have >=1 AI-marked commit
  - AI-marked commits: 23,977 / 160,719

## AI-causality buckets (derived from artifacts/ledger.jsonl)

| Bucket | Count | Meaning |
|---|---|---|
| B1_AI_FAULT | 41 | AI introduced the flaw (verified) |
| B2_NOT_AI | 1,951 | studied, not AI's fault |
| B3_BLOCKED | 664 | unresolved / evidence missing |
| fix recovered, pending review | 3,867 | fix found, dossier not yet done |
| unreviewed rows | 2,735 | no verdict at all yet |

> Note: ledger rows and advisory ids do not map 1:1 (aliases, per-edge rows).
> The denominator 10,083 is advisories; the buckets are ledger rows. A
> strict advisory-level account is the next derivation step.

## Rules

- This file is derived; regenerate with scripts/build_ledger_summary.py.
- All numbers are lower bounds: unstudied advisories are never assumed clean.

