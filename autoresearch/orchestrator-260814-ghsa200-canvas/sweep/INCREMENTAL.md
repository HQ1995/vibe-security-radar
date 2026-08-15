# Incremental analysis runbook (weekly / monthly)

The methodology is split into deterministic stages (local git + regex, no LLM)
and adjudication lanes (gpt-5.6-sol / grok-4.6 via Herdr, one SPEC each).
Persistent state lives here under sweep/; the counted union is
foundation.jsonl in the canvas dir.

## One-time setup (already done on this host)

- local advisory-database clone at
  /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
- bare blobless repo pool at /home/hanqing/.cache/ghsa200-sweep-fetch
- AI-commit corpus at autoresearch/orchestrator-260809-0539/current-ai-scan/commits.jsonl
- model gateway http://127.0.0.1:10100/v1 (primary: deepseek/deepseek-v4-pro,
  command-code/zai-org/GLM-5.3; secondary: cursor/grok-4.6; gpt-5.6-sol is
  out of quota and must not be used)

## Weekly run

1. python3 sweep/incremental.py
   -> refreshes the advisory DB, scans only the delta since the last adb_head,
      emits sweep/next-run-manifest.jsonl and advances sweep/state.json.
2. Dispatch the manifest to worker lanes by the applicable stage:
   - rows with fix_ref  -> DR-SPEC.md (agentic hunk/diff reading; no blame/SZZ)
   - rows without fix_ref -> FWD-SPEC.md (forward AI-commit map, no-fix path)
   - residual/IR rows -> CHAIN-SPEC.md + IRCHAIN-SPEC.md (record the full chain).
   Slice the manifest at ~25 rows per lane; start agents with
   herdr agent start <name> --kind codex --pane <p> -- -m deepseek/deepseek-v4-pro
   -c 'model_reasoning_effort="high"' -s workspace-write -a never
   (or command-code/zai-org/GLM-5.3; cursor/grok-4.6 only as overflow).
   -a never is REQUIRED so unattended lanes never block on approval prompts.
3. Leader replay every worker PASS before counting: explicit AI identity on the
   candidate commit, topology/ancestry, exact reversal hunk, vulnerable vs fixed
   release, uniqueness against foundation.jsonl. See leader_replay.py.
4. Append leader-verified rows to foundation.jsonl; update STATUS.md.

## Recurring deterministic stages (reuse, do not rewrite)

- enumerate_fixrefs.py: all first-party fix commit refs from the ADB tree.
- fetch_markers.py: blobless fetch of fix commits + AI-identity marker scan.
- ancestry_scan.py: AI commits in each fix's 150-commit ancestry (window
  >= 2025-05-01).
- marker_check.py: strict AI-identity regex over fetched commit messages.

## Method traps (from experience)

- git blame / SZZ: mis-attributes renames/squashes/refactors and times out;
  use only as bounded lookup, never as the conclusion. Agentic diff-reading wins.
- 'Co-authored-by' with a human email is NOT an AI marker; require an explicit
  AI identity (anthropic.com/openai.com/copilot/cursor bot or 'Generated with').
- Every git command in a lane gets a 30s timeout; missing evidence is UNKNOWN,
  never FAIL.
- Never relax the zero-FP rule to make a number.
