 # Artifact ledger
 
 Canonical account: `artifacts/funnel-account-20260817.jsonl` (29,593 rows,
 CVE+GHSA deduped, withdrawn/rejected excluded), mirror of the Neon Postgres
 canonical ledger. This directory keeps only the GitHub recovery JSONL, its
 universe census metadata, and the mandatory immutable history.
 
 ## Files
 
 - funnel-account-20260817.jsonl — THE book. One row per advisory class:
   class_id, repo, advisory count, unified status, and site tier/scope, ledger
   best verdict, dossier best verdict. Deterministic GitHub recovery export;
   written only by the leader via `scripts/ledger_store.py export`.
 - funnel-universe-meta-20260826.json — universe census metadata (window,
   dedup identity, layer counts).
 - ledger-history/ — immutable audit history (assessments, versions,
   change-sets, scan-runs, export fingerprint).
 
 ## History
 
 Pre-unification books (per-case ledger.jsonl, dossiers.jsonl, tp-registry,
 funnel-narrowed, repo-ai-scan, code-writer-repos, host-reasons,
 chromium-ai-scan, ledger-summary, manifests) were frozen and removed from
 the working tree in commit 4778fae; recover with
   git show 649505a:artifacts/ledger.jsonl
 (and likewise for the other files).
 
 ## Status transitions
 
 Every status update appends/updates a row in funnel-account-20260817.jsonl
 (mirrored from Neon); nothing else becomes a source of truth.
