# Wave-2 worker spec: 7-gate adjudication of one assigned candidate slice

Owner: your own output directory only (given in your prompt). Proposal worker;
the leader independently replays every PASS before anything counts.

## Read first

- Gate contract: autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
  (all seven gates; note the AI_INCOMPLETE_REMEDIATION patch-delta rule).
- Truth layers: docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md (never edit ledgers).

## Assigned slice

Your prompt names one slice file under
autoresearch/orchestrator-260814-ghsa200-canvas/wave2/slice-NN.jsonl.
Process every row in it. Do not expand the slice. Do not mine new candidates.

Rows of kind 1 (directroot, have best.ai_sha + fix): adjudicate the seven
gates for that candidate/fix pair.

Rows of kind 2 (advisory blobs: ghsa, path, packages, published): bounded
pipeline per row: first-party advisory object at the local advisory-database
path (or the frozen clones under /home/hanqing/.cache/ghsa200-worker-clones/)
-> fix references -> blame the vulnerable hunk to an atomic commit -> check
explicit AI marker (trailer/bot identity/message) -> seven gates. If no AI
marker is reachable, stop at ai_hunk_gate UNKNOWN; do not dig beyond 2000
commits of history.

## Evidence sourcing - NO GitHub API (rate limits)

Local clones first (/home/hanqing/.cache/ghsa200-worker-clones/*/<owner>__<repo>),
then frozen advisory-database clones, then local OSV caches
(.ai-slop/cache/osv-advisory-fix-index-v1/), then git smart-HTTP shallow
blobless single-commit fetches into your work/ dir. No gh api, no REST.
No full clones; disk is tight.

## Original vulnerability capture (required for AI_INCOMPLETE_REMEDIATION)

Whenever the verdict is AI_INCOMPLETE_REMEDIATION, add an
original_vulnerability block to the row:

- original_advisory_ids: the advisory/IDs of the vulnerability the AI was
  trying to fix (often an earlier, distinct GHSA/CVE from the residual case).
- original_mechanism: one-line description of that pre-existing bug.
- original_sink: file/route/symbol where the pre-existing bug lives.
- original_introducing_commit: SHA if recoverable, else null.
- attempted_remediation: candidate SHA plus what it changed and what it
  missed (the residual).
- residual_bypass: the mechanism named by THIS case_id.
- final_closure: minimum_fix_set SHA plus what it closed.

Missing fields stay null; never invent an original advisory or mechanism.

## Outputs (English only, in your owned dir)

- result.json: per-row gate matrix + final verdict (CONFIRM / NARROW /
  FALSE_POSITIVE / UNKNOWN) + confidence + counts + terminal flag. Rows
  whose gates cannot close are terminal=false and stay UNKNOWN.
- cases.jsonl: one proposal row per assigned row, including the
  original_vulnerability block where applicable.
- report.md: per-gate failures, evidence paths, and any disagreement with
  stored labels.

## Hard constraints

- Only your owned dir is writable. Never edit canonical ledgers, web/,
  scripts/, or other campaigns. Never commit/push/reset/checkout.
- A worker PASS/CONFIRM is a proposal only.
- Never convert missing evidence into FAIL/FALSE_POSITIVE.
- No credential printing or storage.
