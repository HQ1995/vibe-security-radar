# TP mining wave 1: gemini pre-filter (2026-08-15)

## Goal

Route each unreviewed shortlist row to a later deepseek logic review, or cut it
as clearly-not-AI. Recall-first: when unsure, route REVIEW.

## Input

.ai-slop/state/tp-mining-wave1/shard-<N>.json — a JSON array of rows with
fields row_id, source, id, repo, subject, ai_ancestor, fix_ref,
ai_commits_before, recent_ai_commits, published.

## Job (cheap pass — judge from row fields only)

Do NOT fetch diffs, do NOT browse GitHub, do NOT clone anything. For each row,
pick exactly one route:

- REVIEW: the row plausibly links an AI-authored commit to the advisory
  mechanism (AI commit in the advisory repo, subject suggests mechanism or
  security-relevant code; any real chance the AI commit introduced or
  materially shaped the vulnerability).
- SKIP: clearly not AI's fault — no AI marker anywhere, AI commit is only
  docs/changelog/config/tests, or repo/id mismatch makes the advisory unrelated.

If uncertain, choose REVIEW.

## Output

.ai-slop/state/tp-mining-wave1/prefilter-<N>.jsonl — one JSON per input row:

{"row_id": "...", "route": "REVIEW|SKIP", "why": "<=10 words"}

Same row order as the input shard. Do not modify any other file. When done,
reply with the output path and the REVIEW/SKIP counts.

## Acceptance

- One output line per input row, same row_id set.
- SKIP only where the reason is a clear not-AI fact.
- No diffs, no network fetches.
