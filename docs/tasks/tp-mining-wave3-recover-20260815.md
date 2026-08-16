# TP mining wave 3: evidence recovery + review (2026-08-15)

## Goal

For rows missing fix commits (or AI ancestors), recover the missing evidence
with bounded effort, then run the same three-bucket review. Fail-closed:
anything not recovered becomes B3, never a guess.

## Input

.ai-slop/state/tp-mining-wave1/w3/l2-<N>.json (triage rows: id, repo, subject,
ai_commits) or l3-<N>.json (rows: id, public_ids, reason_code, reason).

## Recovery protocol (per row, budget: max 5 network calls, then stop)

1. Advisory: curl -sS -H "Authorization: Bearer $GITHUB_TOKEN"
   "https://api.github.com/advisories/<GHSA-id>" (try the CVE id if no GHSA).
   Read affected package, fixed version, references, description.
2. Repo: from the advisory affected[0].package or references.
3. Fix commit: look in references and the advisory text for a commit link;
   fallback: curl "https://api.github.com/repos/<repo>/commits?until=<published>&per_page=5"
   and pick the security fix touching the mechanism files. Do not guess:
   missing evidence -> stop with B3.
4. AI candidate: if the row already lists ai_commits, use them. Otherwise
   check the fix's parent commits for AI markers (author email/trailer,
   "[AI]", "Co-Authored-By", agent signature) touching the same files.
5. Then fetch candidate patch + fix patch and answer the one question below.

## Verdicts

- B1_AI_FAULT: AI-added lines are the mechanism flaw (line-level refs from
  both patches).
- B2_NOT_AI: flaw clearly elsewhere; candidate benign/unrelated.
- B3_BLOCKED: not recovered within budget, or ambiguous.

## Output

.ai-slop/state/tp-mining-wave1/w3/results-<l2|l3>-<N>.jsonl — one JSON per
input row, same order:

{"row_id","id","verdict","mechanism_element","ai_refs":[],"fix_refs":[],
 "recovered_fix":null,"recovered_candidate":null,"reasoning":"<=5 lines"}

Reply with the output path and verdict counts. Do not modify tracked files.

## Acceptance

- Row_id set matches input exactly.
- B1 requires line-level refs from both patches.
- B3 must state which evidence is missing.
