# IR chain-recording worker spec: full history per AI_INCOMPLETE_REMEDIATION case

Owner: your own output dir. Read-only on all else. This task records history; it
does not change counting (the case_id rows are already counted).

## Task

For every row in autoresearch/orchestrator-260814-ir-enrichment-sol/enriched.jsonl
(51 rows), produce one chain record into ir-chains.jsonl:

- case_id (the residual GHSA, key)
- original_advisory_ids (from the enriched row)
- original_mechanism + original_sink (from the enriched row)
- original_introducing_commit: the commit that first introduced the ORIGINAL
  vulnerability, plus its author name/email and authored_date. Trace agentically:
  read the advisory + the fix/pre-fix code, use bounded git log -S / git show as
  evidence lookup (deepen max 500, every git command timeout 30s). Never use git
  blame or SZZ attribution as the conclusion. Unresolvable = null + reason.
- original_author_kind: AI or HUMAN, judged ONLY from an explicit AI identity in
  the BIC commit (Claude/Copilot/Codex/Cursor bot trailer, 'Generated with ...');
  anything else is HUMAN or UNKNOWN. Do not infer from commit style.
- attempted_remediation + residual_bypass + final_closure (from the enriched row).
- evidence_paths: files/commands used.

The repos live in /home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>;
advisories in /home/hanqing/.cache/ghsa200-worker-clones/*/advisory-database.

## Outputs (English only)

- ir-chains.jsonl: one row per input row, in the same order.
- summary.json: how many BICs resolved, how many HUMAN/AI/UNKNOWN.
- report.md: notable chains worth displaying.

## Hard constraints

- Only your owned dir writable; never edit ledgers/web/scripts; never commit/push;
  no credentials; no GitHub API; missing evidence stays null/UNKNOWN.
