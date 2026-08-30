# Artifact ledger

Single source of truth for the 24,124-class research account (window
2025-05-01 .. 2026-08-26, CVE+GHSA deduped, withdrawn/rejected excluded).

## Files

- funnel-account-20260817.jsonl — THE book. One row per advisory class:
  class_id, repo, advisory count, and unified status
  (AI_ROOT_CAUSE / AI_CODE_FLAWED / NOT_AI / BLOCKED /
  PARTIALLY_ANALYZED / UNANALYZED), with site tier/scope, ledger best verdict,
  dossier best verdict.
- code-writer-repos-20260816.json — verified repos with 2025+ code-writing AI
  commits (bot-excluded).
- host-reasons-20260816.txt — per-repo scan audit trail: one reason per repo,
  no UNKNOWN verdicts.
- chromium-ai-scan-20260817.jsonl — chromium-family records outside the
  census alias classes (214 records, per-record repo verdicts).
- ledger-summary.md — human-readable total account.
- manifests.jsonl — sha256/size/row manifests of local-only raw pools that are
  too large for git (the pools themselves stay on disk, not committed).

## History

Pre-unification books (per-case ledger.jsonl, dossiers.jsonl, tp-registry,
funnel-narrowed, repo-ai-scan) were frozen and removed from the working tree
in commit 4778fae; recover with:
  git show 649505a:artifacts/ledger.jsonl
(and likewise for the other files).

## Status transitions

Every status update appends/updates a row in funnel-account-20260817.jsonl;
nothing else becomes a source of truth.
