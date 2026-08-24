# Worker spec: closure packet (FP taxonomy, prevalence estimate, claim boundary)

Owner: this directory only. This lane does analysis over frozen artifacts; it
does no new candidate mining, no network research, no ledger edits, and no
GitHub API calls.

## Inputs (read-only, all frozen/local)

- autoresearch/orchestrator-260813-fp211-audit/experience.json
- autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl
- autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl
- autoresearch/orchestrator-260813-fp211-audit/FINAL_REPORT.md
- autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json
- autoresearch/orchestrator-260809-0539/current-official-census/summary.json
- autoresearch/orchestrator-260809-1127/ lane artifacts
  (web-literature-adjudications.json, deepseek receipts, official-ai-term-hits)

## Deliverables (English only)

1. fp_taxonomy.md: the 54 FALSE_POSITIVE dispositions grouped by
   false_positive_class, with exact counts and one representative SHA-level
   example per class; add the NARROW and UNKNOWN disposition counts for the
   full funnel (211 hypotheses / 212 cases / 149 causal-valid / 84 strict
   released).

2. estimate.json + estimate.md: a two-source capture-recapture estimate
   (Lincoln-Petersen with Chapman correction) of the total AI-contributed
   CVE/GHSA population in the frozen study window, using only lane-level
   counts recoverable from the frozen artifacts: n1 and n2 from two
   independent lanes and their overlap m, each at a named, comparable
   counting unit. If lane counts at a comparable unit cannot be recovered
   from these artifacts, state estimate=BLOCKED, list exactly which counts
   are missing, and give the formula and inputs that would unblock it. Do
   not invent or extrapolate counts. Every number must cite its frozen file.

3. closure.md: the final claim boundary - 84 strict released first-party
   GHSA cases, greater-than-200 unsupported, 9 UNKNOWN + IAA lanes pending
   leader reconciliation - plus a one-paragraph publication-ready statement
   and a short list of what a follow-up study should measure (signal-level
   precision/recall, inter-rater reliability, sampling-based prevalence).

## Hard constraints

- Read-only outside this directory. No commits/pushes. No network calls, no
  GitHub API, no credentials. No synthetic or guessed counts; a missing input
  is a BLOCK, not an opportunity to estimate from vibes.
