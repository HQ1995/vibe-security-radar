# Forward-map worker spec: did an AI commit introduce a no-fix-ref advisory's mechanism

Owner: your own output dir. Proposal worker; leader replays every PASS.

## Method - agentic, no blame/SZZ

For each row (ghsa, repo, published, summary, ai_commits_before, recent[sha,date,
files,kinds]):

1. Read the advisory JSON from the local advisory-database clone (search for the
   ghsa id under advisories/github-reviewed/; the clones live under
   /home/hanqing/.cache/ghsa200-worker-clones/*/advisory-database). Understand the
   exact vulnerable mechanism from summary + description.
2. For the recent AI commits (up to 6), fetch and READ each diff via git protocol
   (git fetch --filter=blob:none --deepen=N into the pool at
   /home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>; no GitHub API; every
   git command timeout 30s).
3. Judge by READING the diffs whether any AI commit creates the advisory's
   mechanism (new surface, removed check, changed parsing, copied code). Do not
   use git blame or SZZ attribution; you must see it in the diff.
4. If yes: verdict CONFIRM (AI_DIRECT_ROOT or AI_NEW_SURFACE_CONTRIBUTOR per the
   gate contract autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md) with
   the candidate sha and gate matrix; gates you cannot close stay UNKNOWN.
   If no AI commit creates the mechanism: FALSE_POSITIVE (class no_ai_origin).
5. No fix ref exists, so the fix_reversal/release gates need the advisory's
   affected/fixed versions plus a later commit that reverses the mechanism; if you
   cannot locate it locally, those gates stay UNKNOWN and the row is not countable.

## Outputs (English only)

- result.json: per-row verdict + gate matrix + counts + terminal flag.
- cases.jsonl: one row per assigned row.
- report.md: per-row reasoning with evidence commands.

## Hard constraints

- Only your owned dir writable; never edit ledgers/web/scripts; never commit/push;
  no credentials; no GitHub API; never convert missing evidence into FAIL.
