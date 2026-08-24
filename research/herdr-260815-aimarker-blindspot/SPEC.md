# Mission: quantify the unmarked-AI-commit blind spot

## Hypothesis (from the lead)
Our discovery -> attribution pipeline detects AI authorship mainly from
self-reporting markers (Co-Authored-By trailers, "[AI]", "[AI-assisted]",
AI-identifiable author names/emails). Tools without a self-marking convention
(Cursor, GPT/Codex, some Copilot workflows) are systematically undercounted.
If the denominator is blind, we may also have missed candidate commits
entirely -> missed true positives.

Evidence already on disk:
- `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-commit-census.json`
  shows openai_gpt_codex text=5084 vs marked=244; cursor text=1332 vs marked=743.
- 4 admitted cases have coverage=generic (AI-assisted, tool unknown):
  GHSA-2HFG-4FH4-QP7F, GHSA-2X93-H3HG-2XFP, GHSA-3FP5-V549-9V66,
  GHSA-J4CX-JVQ7-79VM (all openclaw/openclaw).

## Scope
1. For the 73 repositories in `web/src/generated/research-data.json`, quantify
   the gap: how many commits in 2025-05-01..2026-08-16 look AI-authored by
   stronger signals but carry NO tool marker. Signals to test (mechanically,
   from local git only): PR-body attribution via
   /home/hanqing/.cache/cve-analyzer/api-responses/gh_commit_prs and
   gh_pr_commits; author identity patterns; repo-specific conventions.
2. Try to identify the actual tool for the 4 generic cases from local PR caches
   and commit context. Only record a tool if there is a citable local source.
3. Produce ranked LEADS for potential missed true positives: commits that
   (a) are plausibly AI-authored but unmarked, (b) touch security-sensitive
   code, (c) were later fixed by a security fix. These are hypotheses, not
   admitted cases.

## Hard constraints
- Local git clones only. NO GitHub API (rate limits), no network fetch.
- Clone pools: /home/hanqing/.cache/ghsa200-sweep-fetch,
  /home/hanqing/.cache/cve-analyzer/repos,
  /home/hanqing/.cache/ghsa200-worker-clones/*/clones, /tmp/*/clones.
  Set GIT_NO_LAZY_FETCH=1 for all git calls.
- Do NOT modify web/src/generated/research-data.json, foundation.jsonl, or any
  canonical ledger. Write only inside this directory.
- Zero-fabrication: every lead needs evidence fields (repo, sha, signal,
  excerpt) and an explicit confidence. Unknown tool stays unknown.
- Timebox: 2 hours of work. A partial, honest census + top-ranked leads beats
  an exhaustive fake.

## Deliverables (in this directory)
- report.md  : gap quantification, method, caveats, top leads summary.
- leads.jsonl: one JSON per lead {repo, sha, signal, excerpt, security_note,
              fix_sha?, confidence, status="LEAD"}.

Start by reading the census JSON and the 4 generic cases, then scan repos
ranked by AI-commit density. Report progress in your final message with exact
file paths and counts.
