# Direct-root worker spec: verify whether an AI ancestor authored the vulnerable hunk

Owner: your own output directory only. Proposal worker; leader replays every PASS.

## Read first

- Gates: autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md.
- Truth layers: docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md.

## Assigned slice

Your prompt names a slice file under
autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-N.jsonl.
Each row: case_id (the GHSA), repository, fix_ref (final fix), ai_ancestor (an
AI-authored commit in the fix's history), overlap_files, subject, published.

## For each row

1. Read the advisory JSON from the local advisory-database clone to learn the
   vulnerable mechanism and (if named) file/route.
2. Compare the ai_ancestor's diff against the vulnerable file/hunk:
   - If the AI ancestor introduced or materially rewrote the vulnerable hunk,
     verdict AI_DIRECT_ROOT (or AI_NEW_SURFACE_CONTRIBUTOR for a new surface).
   - If the AI ancestor is unrelated (e.g. tests, deps, other modules), verdict
     FALSE_POSITIVE with class wrong_edge.
3. The commits live in the bare pool
   /home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo> (blobless, deepened 150).
   Fetch missing blobs via git smart-HTTP (git fetch --filter=blob:none --deepen=N;
   NEVER GitHub API).
4. Fill all seven gates. Unclosable gates stay UNKNOWN and the row is not
   countable. Never convert missing evidence into FAIL.

## Outputs (English only)

- result.json: per-row gate matrix + final verdict + counts + terminal flag.
- cases.jsonl: one row per assigned row with SHAs and evidence paths.
- report.md: per-row reasoning.

## Hard constraints

- Only your owned dir is writable; never edit ledgers/web/scripts/other
  campaigns; never commit/push/reset/checkout; no credentials; no GitHub API.
