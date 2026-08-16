# TP mining Lane C: advisory-class deep dive (2026-08-16)

## Goal

For each advisory class, study its AI-introduced commit(s) and the fix, and
answer the one question: did the AI-written code introduce the vulnerability?
One class = one deep-dive, but bounded: max 12 candidates per class.

## Input

.ai-slop/state/laneC/laneC-<N>.json — classes with class_id, advisories
(id+published), repo, candidate_shas, fix_sha, n_edges, route.

## Per class

1. Fetch the fix patch:
   curl -sS -m 40 -H "Authorization: Bearer $GITHUB_TOKEN"
   "https://github.com/<repo>/commit/<fix_sha>.patch"
   Identify the mechanism (which files/lines the fix changes) and, from the
   advisory ids, the vulnerability description (fetch the GHSA if unclear).
2. For each candidate sha (up to 12, stop early once the real culprit is
   found), fetch the candidate patch and check:
   - does it ADD the mechanism lines the fix later changes? (line overlap)
   - does the commit carry an AI marker (Co-Authored-By, [AI], agent email)?
3. Verdict per class:
   - B1_AI_FAULT: a specific AI candidate added the flawed mechanism, fix
     reverses those lines (give shas + file:line refs).
   - B2_NOT_AI: no candidate relates to the mechanism (flaw predates or lives
     elsewhere) with the best negative evidence.
   - B3_BLOCKED: patches unfetchable or ambiguous.

## Output

.ai-slop/state/laneC/laneC-results-<N>.jsonl — one JSON per class, same order:

{"class_id","verdict":"B1_AI_FAULT|B2_NOT_AI|B3_BLOCKED",
 "culprit_sha":null or "...", "advisory_ids":[...], "repo":"...",
 "mechanism_element":"...", "ai_refs":[], "fix_refs":[], "reasoning":"<=5 lines"}

Never modify tracked files. Reply with output path and verdict counts.

## Acceptance

- class_id set matches input exactly.
- B1 requires culprit_sha + ai_refs + fix_refs line-level evidence.
