# Canvas status - 200-target union ledger (tiered)

Updated 2026-08-15. Final state of the local-evidence exhaustion pass.

## Count

- unique GHSA ids: 168
  - all_pass (seven gates PASS, leader replayed): 94
  - scoped_contribution (fp211 NARROW rows at recorded scope): 74
- demonstrated false positives: 0

## Pools exhausted with evidence (all zero countable beyond the 168)

- reviewed fix refs: 17,757 rows -> 1,688 AI-marked fixes -> 0 countable IR
- unreviewed advisories: 85,196 files -> 1,816 in-window with fix ref ->
  105 strict AI-identity fixes -> 19 residual-language -> 0 countable
- ancestry overlap: 753 -> 125 adjudicated -> 0
- no-fix forward: 4,119 -> ~100 adjudicated -> 0
- IR chains: 51 recorded; originals are human or already counted
- daily advisory delta: ~0-3/day, term-scan is wired

## Blocking condition

The remaining 32 countable GHSAs do not exist in current public data at the
zero-FP bar. Progress now depends on external supply (new advisories) plus the
monthly incremental run: sweep/incremental.py, gate.py v2, and the SPECs are
ready. Monthly: run incremental.py, dispatch the manifest to lanes, gate the
proposals, append leader-verified rows.

