# TP mining Lane A phase 3: AI ancestor search (2026-08-16)

## Goal

For rows with a recovered fix but no AI candidate, find AI-authored commits
that plausibly introduced or shaped the vulnerable mechanism. Fail-closed:
no marker evidence = no candidate.

## Input

.ai-slop/state/laneA/p3/laneA-p3-<N>.json — rows with class_id, public_ids,
repo, fix_sha, note (mechanism hint).

## Per row (budget max 8 network calls)

1. Fetch the fix patch:
   curl -sS -m 40 -H "Authorization: Bearer $GITHUB_TOKEN"
   "https://github.com/<repo>/commit/<fix_sha>.patch"
   Record the changed file paths.
2. For the top 3 mechanism-looking files (skip docs/locks/tests first pass),
   list commits that touched the file before the fix:
   curl -sS -m 30 -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json"
   git clone --filter=blob:none the repo once, then git log -- <file> locally (no GitHub API).
3. Look at each commit's message + author for AI markers:
   Co-Authored-By, "[AI]", agent emails (anthropic/openai/cursor/copilot/
   claude/codex), or agent-typical subjects. Also check whether the commit
   plausibly INTRODUCED the mechanism (subject mentions the feature the note
   describes).
4. If found: fetch that commit patch to confirm it ADDS the mechanism lines.

## Output

.ai-slop/state/laneA/p3/laneA-p3-results-<N>.jsonl — one JSON per input row,
same order:

{"class_id","public_ids","repo","fix_sha","candidate_sha":null or "...",
 "marker":"marker text or empty", "note":"<=80 chars"}

Never modify tracked files. Reply with output path and found counts.

## Acceptance

- class_id set matches input exactly.
- candidate_sha non-null requires marker text AND a verified patch that adds
  mechanism lines.
