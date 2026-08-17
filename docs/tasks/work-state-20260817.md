# Work state checkpoint — 2026-08-17

## Canonical book
artifacts/funnel-account-20260817.jsonl (23,868 classes, one row each).
Old books frozen in git at 649505a, removed at 4778fae.

## Buckets
TP_SITE_STRICT 81 | TP_SITE_NARROW 70 | TP_B1 87 | NOT_AI 1,385 |
BLOCKED 535 | PARTIAL 4,280 | PENDING 17,430

## Current attack: TP_SITE_NARROW 70 (bucket 2)
- Input: .ai-slop/state/narrow70/cases.jsonl (case_id, repo, candidates,
  fixes, gate gaps, decisive evidence)
- Gate gaps to close: release 30, topology 39, but_for 33, fix_reversal 16,
  identity 18, ai_hunk 14
- Goal per case: close all NARROW gates to PASS -> promote STRICT; or find
  counterevidence -> downgrade B2/B3. Evidence first-party local only,
  no GitHub API.
- Workers: codex --yolo + deepseek-v4-flash, one worker per repo shard.
  Results -> .ai-slop/state/narrow70/results/<worker>.jsonl then merge into
  funnel-account status (TP_SITE_STRICT / downgrade).

## Next buckets (queued)
535 BLOCKED -> PENDING 17,430 by repo shards -> PARTIAL 4,280 causality.
