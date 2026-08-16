# TP mining: flash SKIP audit (2026-08-15)

## Goal

Gemini pre-filter SKIPped 1,240 rows. Audit each SKIP to catch false skips
(rows that might actually link an AI-authored commit to a vulnerability).
This is a recall guard, not a verdict.

## Input

.ai-slop/state/tp-mining-wave1/skipaudit/sa-<N>.json — rows with row_id, id,
repo, subject, ai_ancestor, fix_ref, gemini_why.

## Job (per row)

1. If the row has ai_ancestor, fetch the commit header only:
   curl -sS -H "Authorization: Bearer $GITHUB_TOKEN"
   "https://github.com/<repo>/commit/<ai_ancestor>.patch" | head -40
   Look at the commit message and author for AI markers (Co-Authored-By,
   bot/agent emails, "[AI]", agent names) and whether the commit touches
   code that could be security-relevant.
2. If the row has no ai_ancestor, judge from the subject only.

Audit verdict:

- FLAG: the skip looks wrong — AI marker exists AND the subject/files
  suggest security-relevant mechanism code. This row goes back to deepseek
  review.
- OK: the skip was correct (no AI marker, or docs/deps/tests only).

Do not fetch full diffs, do not clone. One header fetch per row max.

## Output

.ai-slop/state/tp-mining-wave1/skipaudit/sa-results-<N>.jsonl — one JSON per
input row, same order:

{"row_id","audit":"FLAG|OK","why":"<=10 words"}

Reply with the output path and FLAG/OK counts. Do not modify tracked files.

## Acceptance

- One line per input row, row_id set matches exactly.
- FLAG requires an actual AI marker plus a security-relevant subject.
