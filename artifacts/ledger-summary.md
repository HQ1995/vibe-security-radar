# Vibe Security Radar — research total account

Window: 2025-05-01 .. 2026-08-14 (advisory publication date). Last updated: 2026-08-16.

## Denominator (hard counts from local pools)

- Total distinct advisories in window: **10,083**
  - fixrefs pool (advisory -> fix known): 5,964
  - nofix pool (frozen with no fix at freeze time): 4,119
  - overlap: 0
- Distinct repositories behind those advisories: **5,824**

## AI-commit observation coverage (NOT the true total)

- Repos with an AI-commit scan: **39** of 5,824 (0.7%)
- Repos never scanned for AI commits: **5,785**
- In the scanned 39: 23,977 AI-marked commits / 160,719 total
- So the true number of AI commits across all 5,824 repos is UNKNOWN;
  every unscanned repo is a potential AI-causality source.

## AI-causality buckets (derived from artifacts/ledger.jsonl, ledger-row口径)

| Bucket | Count | Meaning |
|---|---|---|
| B1_AI_FAULT | 41 | AI introduced the flaw (verified) |
| B2_NOT_AI | 1,951 | studied, not AI's fault |
| B3_BLOCKED | 664 | unresolved / evidence missing |
| fix recovered, pending review | 3,867 | fix found, dossier not yet done |
| unreviewed rows | 2,735 | no verdict at all yet |

> Ledger rows and advisory ids are not 1:1 (aliases, per-edge rows).
> Advisory-level account is the next derivation step.

## Rules

- This file is derived; regenerate with scripts/build_ledger_summary.py.
- All numbers are lower bounds: unstudied advisories are never assumed clean.
- The 39-repo AI scan is an observation bound, never a population claim.

