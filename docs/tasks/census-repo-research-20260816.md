# Census structure research: repo-level AI-commit queue (2026-08-16)

## Mission

Study the official census files and answer: for the 84,060 usable advisory
alias-classes (2025-05-01..2026-08-09, excluding WITHDRAWN/REJECTED), what are
the distinct repositories behind them, and how do we build a repo-level
AI-commit scan queue (local git clone + git log marker scan, NO GitHub API).

## Inputs (read these fully)

- autoresearch/orchestrator-260809-0539/current-official-census/alias_classes.jsonl
  (84,798 rows: analysis_subject, class_id, member_ids, published, sources, states)
- autoresearch/orchestrator-260809-0539/current-official-census/subjects.jsonl
  (159,714 rows: id, aliases, lane, source, path, state, published, in_window)
- ls autoresearch/orchestrator-260809-0539/current-official-census/ (other files)
- our pools: autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fixrefs.jsonl
  and nofix-advisories.jsonl (10,083 advisories, 5,824 repos)

## Questions to answer with evidence

1. Where do REPOSITORIES live in the census? (repo fields in subjects/alias
   classes? a package field? do we need OSV/GHSA to resolve repo per advisory?)
2. How many distinct repositories for the 84,060 usable classes? (compute)
3. How many of those repos are ALREADY covered by our pool (5,824) vs new?
4. Any existing repo-level AI scan artifacts in autoresearch/ we can reuse
   instead of re-scanning? (search for ai census / scan outputs beyond the
   66-repo census; check herdr-* dirs, orchestrator-* dirs)
5. Proposed pipeline: repo list -> local clone pool (bounded, delete after)
   -> git log --all --format with AI-marker regex -> repo-level verdict:
   HAS_AI_COMMIT / NO_AI_COMMIT / UNSCANNABLE. Write the exact commands and
   marker regex list (Co-Authored-By, [AI], bot emails, agent signatures).

## Output

Write .ai-slop/state/census-research/census-findings.md with: file/field map,
computed counts, reuse candidates, and the pipeline design. Reply with the
path and the key numbers (distinct repos, new repos, scan queue size).

## Rules

- Read-only research; do not modify tracked files.
- NO api.github.com calls; OSV allowed only if absolutely needed for field
  semantics (quote it, do not hammer it).
- Be precise about what is computed vs what is estimated.
