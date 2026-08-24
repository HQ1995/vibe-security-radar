# Wave-5 worker spec: adjudicate AI-authored fix commits from the sweep pool

Owner: your own output directory only. Proposal worker; leader replays every PASS.

## Read first

- Gates: autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md (seven gates
  plus the AI_INCOMPLETE_REMEDIATION patch-delta rule).
- Truth layers: docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md.

## Assigned slice

Your prompt names one slice file under
autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-fix-slice-N.jsonl.
Each row: case_id (the GHSA), repository, fix_ref (an AI-authored commit found in
that advisory's references), subject, published.

## For each row

1. Read the first-party advisory JSON from the local advisory-database clone
   (search advisories/github-reviewed/.../ for the case_id; the clones live under
   /home/hanqing/.cache/ghsa200-worker-clones/*/advisory-database).
2. Decide the fix_ref commit's role:
   - If the advisory names fix_ref as its final closure for a pre-existing
     vulnerability that the AI commit did NOT create, the row is NOT countable
     (AI-authored fix is excluded by the study definition). Record REJECT_AI_FIX_ONLY.
   - If the advisory covers a RESIDUAL of this AI-authored fix (the AI fix is an
     explicit security attempt that was released and later found incomplete),
     record AI_INCOMPLETE_REMEDIATION with the patch-delta evidence.
   - If the AI fix commit itself introduced a new vulnerable surface later named
     by the advisory, record AI_NEW_SURFACE_CONTRIBUTOR.
3. Evidence for the mechanism comes from the commit objects already fetched in
   the bare pool /home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>.
   Use git smart-HTTP only to deepen/fetch parent diffs or blobs you need
   (git fetch --filter=blob:none --deepen=N; NEVER GitHub API).
4. Fill the seven gates. Any gate that cannot close stays UNKNOWN; the row is
   then not countable. Never convert missing evidence into FAIL.

## Original vulnerability block (required for AI_INCOMPLETE_REMEDIATION)

original_advisory_ids, original_mechanism, original_sink,
original_introducing_commit (or null), vulnerable_artifact, attempted_remediation
(sha + changed + missed), residual_bypass, final_closure (sha + closed).

## Outputs (English only)

- result.json: per-row gate matrix + final verdict + counts + terminal flag.
- cases.jsonl: one row per assigned row.
- report.md: per-row reasoning, evidence paths, disagreements.

## Hard constraints

- Only your owned dir is writable; never edit ledgers, web/, scripts/, other
  campaigns; never commit/push/reset/checkout; no credentials; no GitHub API.
