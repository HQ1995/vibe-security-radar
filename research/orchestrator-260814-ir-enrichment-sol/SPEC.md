# Worker spec: original-vulnerability enrichment for incomplete-remediation rows

Owner: autoresearch/orchestrator-260814-ir-enrichment-sol/ only. Read-only
elsewhere. This lane extracts structured fields from frozen local artifacts;
no network, no GitHub API, no ledger edits.

## Task

For every foundation row with contribution_class AI_INCOMPLETE_REMEDIATION in
autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl (51 rows),
produce an enriched JSONL where each row keeps its original fields and adds an
original_vulnerability block:

- original_advisory_ids (list; often an earlier GHSA/CVE distinct from case_id)
- original_mechanism (one line)
- original_sink (file/route/symbol)
- original_introducing_commit (SHA or null)
- vulnerable_artifact (version/tag before the AI attempted remediation)
- attempted_remediation (candidate SHA + what it changed + what it missed)
- residual_bypass (mechanism named by this case_id)
- final_closure (minimum_fix_set SHA + what it closed)
- evidence_paths (list of frozen files the fields came from)

## Sources (frozen, local)

- docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-{A,B,C,D,E}-2026-08-12.md
- docs/RESEARCH-POST-HOLD-PUBLIC-MECHANISM-BATCH-{F,G}-2026-08-12.md
- autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl
- autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl
- worker packets: autoresearch/herdr-260814-ghsa200-incomplete-remediation20*

Fields that cannot be recovered stay null and are listed in a per-row
missing_fields array. Do not invent advisories, SHAs, or mechanisms.

## Outputs (English only)

- enriched.jsonl (one row per input row, byte-preserving original fields plus
  the new block)
- summary.json (row count, how many rows have all fields, how many partial,
  missing-field census)
- report.md (method, per-row gaps, examples)

## Hard constraints

- Read-only outside the owned dir. No commits/pushes. No credentials.
- Fail open: a missing original advisory is reported, not guessed.
