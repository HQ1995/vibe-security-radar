# TP mining wave 2: deepseek logic review (2026-08-15)

## Goal

For each row in your assigned list, decide whether the AI-authored commit's
added lines themselves constitute the advisory's vulnerability mechanism.
Verdicts feed the three-bucket ledger: B1 = AI introduced the problem,
B2 = clearly not AI's fault, B3 = cannot decide (missing/ambiguous evidence).

## Input

.ai-slop/state/tp-mining-wave1/w2-lists/w2-<N>.json — rows with row_id, id
(advisory), repo, subject, ai_ancestor (candidate commit sha), fix_ref
(fix commit sha), published.

## Protocol (per row)

1. Fetch the candidate diff:
   curl -sS -H "Authorization: Bearer $GITHUB_TOKEN"
   "https://github.com/<repo>/commit/<ai_ancestor>.patch"
2. Fetch the fix diff the same way with <fix_ref>.
3. AI lines = lines ADDED by the candidate patch (the "+" hunks).
4. Mechanism = the source/guard/sink the advisory describes (use the row
   subject plus the advisory text if the subject is unclear).
5. One question: do the AI-added lines themselves constitute the mechanism
   flaw (missing/wrong guard, wrong sink, unsafe source handling)?

## Verdicts

- B1_AI_FAULT: the AI-added lines are the flawed mechanism (line-level match
  between AI hunks and the flaw; fix patch changes those same lines or their
  immediate mechanism).
- B2_NOT_AI: the flaw clearly lives in other lines; AI commit is benign or
  unrelated (docs, deps, tests, or code not on the vulnerability path).
- B3_BLOCKED: patch fetch failed, repo missing, or evidence ambiguous. Any
  doubt -> B3, never B1 or B2.

## Output

.ai-slop/state/tp-mining-wave1/w2-results/w2-<N>.jsonl — one JSON per input
row, same order:

{"row_id","id","verdict":"B1_AI_FAULT|B2_NOT_AI|B3_BLOCKED",
 "mechanism_element":"source|guard|sink|none",
 "ai_refs":["file:line"],"fix_refs":["file:line"],"reasoning":"<=5 lines"}

Never modify tracked files. Reply with the output path and verdict counts.

## Acceptance

- One line per input row, row_id set matches exactly.
- B1 requires ai_refs and fix_refs with line-level evidence.
- B2 requires a concrete not-AI reason.
- Everything uncertain goes to B3.
