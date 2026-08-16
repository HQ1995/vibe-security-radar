# TP mining Lane A phase 2: review recovered candidates (2026-08-16)

## Goal

Verdict the 83 recovered (candidate+fix) rows with the standard three-bucket
logic review. Same protocol as wave 2: do the AI-added lines constitute the
advisory mechanism flaw?

## Input

.ai-slop/state/laneA/p2/laneA-p2-<N>.json — rows with class_id, id,
public_ids, repo, candidate_sha, fix_sha, mechanism.

## Per row

1. If mechanism is empty, fetch the advisory summary first:
   curl -sS -m 25 -H "Authorization: Bearer $GITHUB_TOKEN"
   "https://api.github.com/advisories/<GHSA-id>"
2. Fetch candidate patch and fix patch:
   curl -sS -m 40 -H "Authorization: Bearer $GITHUB_TOKEN"
   "https://github.com/<repo>/commit/<sha>.patch"
3. AI lines = the "+" hunks of the candidate patch.
4. Verdict:
   - B1_AI_FAULT: AI lines are the mechanism flaw; fix changes those lines or
     their immediate mechanism (line-level refs from both patches).
   - B2_NOT_AI: flaw clearly elsewhere; candidate benign/unrelated.
   - B3_BLOCKED: fetch failed or ambiguous. Doubt -> B3.

## Output

.ai-slop/state/laneA/p2/laneA-p2-results-<N>.jsonl — one JSON per input row,
same order:

{"class_id","id","verdict","mechanism_element","ai_refs":[],"fix_refs":[],
 "reasoning":"<=5 lines"}

Never modify tracked files. Reply with the output path and verdict counts.

## Acceptance

- class_id set matches input exactly.
- B1 requires ai_refs and fix_refs line-level evidence.
