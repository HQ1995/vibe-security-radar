# TP mining wave 3: direct review (2026-08-15)

## Goal

Verdict rows that already carry candidate+fix commit pairs. Same three-bucket
question as wave 2: do the AI candidate's added lines constitute the advisory
mechanism flaw?

## Input

.ai-slop/state/tp-mining-wave1/w3/l1-<N>.json — rows with row_id, id,
public_ids, reason_code, optional mechanism, and edges: list of
{candidate_sha, fix_sha, repository}.

## Protocol (per row)

1. Fetch the advisory summary once if mechanism is unclear:
   curl -sS -H "Authorization: Bearer $GITHUB_TOKEN"
   "https://api.github.com/advisories/<GHSA-id>"
2. For each edge, fetch candidate patch and fix patch:
   curl -sS -H "Authorization: Bearer $GITHUB_TOKEN"
   "https://github.com/<owner/repo>/commit/<sha>.patch"
3. AI lines = "+" hunks of the candidate patch. Mechanism = source/guard/sink
   from the advisory.
4. Single question: do the AI-added lines constitute the mechanism flaw?

## Verdicts

- B1_AI_FAULT: AI lines are the flawed mechanism (line-level match; fix
  changes those same lines or their immediate mechanism).
- B2_NOT_AI: flaw clearly elsewhere; candidate benign/unrelated.
- B3_BLOCKED: fetch failed, repo missing, or ambiguous. Doubt -> B3.

## Output

.ai-slop/state/tp-mining-wave1/w3/results-l1-<N>.jsonl — one JSON per input
row, same order:

{"row_id","id","verdict","mechanism_element","ai_refs":[],"fix_refs":[],
 "reasoning":"<=5 lines"}

Reply with the output path and verdict counts. Do not modify tracked files.

## Acceptance

- Row_id set matches input exactly.
- B1 requires ai_refs and fix_refs line-level evidence.
- B2 requires a concrete not-AI reason.
