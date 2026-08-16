# Vibe Security Radar — research total account

Window: 2025-05-01 .. 2026-08-09 (official census) / 2026-08-14 (our pools).
Last updated: 2026-08-16.

## Global denominator (official census, local mirror)

- Distinct advisory alias-classes (CVE+GHSA deduped): 84,798
- Excluding WITHDRAWN/REJECTED: **84,060** usable classes
- Subject rows (advisory x repo/pkg): 159,714

## Repo-level AI-commit scan (deterministic set)

- current-ai-scan (2026-08-09): 8,909 scanned / 8,455 complete;
  **2,992 repos HAVE_AI**, 5,463 complete-with-zero (NO_AI), 454 incomplete
- 411-queue completion sweep (2026-08-16, treeless shallow fetch, no API):
  **210 HAS_AI_COMMIT / 77 NO_AI_COMMIT / 124 UNSCANNABLE**
- Total verified HAS_AI repos: **3,202**
- Total verified NO_AI repos: **5,540**
- UNSCANNABLE: 454 + 124 = 578 (no repo / failed fetch / cgit+gerrit hosts)
- Repos resolvable to a clone target: ~9.5k of the 84,060 classes' universe

## Our research pool

- Advisories in pool: 10,083 = 12.0% of usable denominator
- AI-causality buckets (ledger rows): B1 41 / B2 1,951 / B3 664 /
  fix-recovered-pending 3,867 / unreviewed 2,735

## Rules

- Derived file; regenerate with scripts/build_ledger_summary.py.
- Lower bounds only; UNSCANNABLE is never assumed clean.
- Never present pool coverage as global coverage.

