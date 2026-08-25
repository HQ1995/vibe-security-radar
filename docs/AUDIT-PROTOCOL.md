# Audit protocol

The standing rules for judging a case. Core principle: **no mechanical
scanning** — fully understand the vulnerability's root cause and its
complete lifecycle before judging the AI role.

## Required for every case

1. **Understand the vulnerability**: root cause, trigger path, affected
   versions, fixed behavior. Do not start until understood.
2. **Minimal BIC**: the smallest atomic commit that first wrote the
   vulnerable lines; decompose squashes to PR constituents; record
   `introducer_sha` + `decomposed_shas`.
3. **Find the fix**: record `fix_sha`/`direct_fix_sha`; if unfixed,
   record `unpatched` explicitly.
4. **Incomplete-fix chain**: original introducer → attempted remediation
   → residual bypass → final closure (`ir_chain`); no closure without
   every link.
5. **Judge the AI role** from signals **on the minimal BIC only**; a
   squash-level aggregated Co-Authored-By is not a vulnerable-line
   signal (downgrade when the signal is not on the BIC).
6. **Record the research in the ledger**: `roundN_research` with
   verdict / reasoning / flaw_origin / bug_semantics / ai_marker / all
   SHAs, then run `scripts/merge_funnel_lane.py` to update the ledger
   promptly.
7. **Backfill required info**: advisory identity (no ALIAS publishing —
   dig the real GHSA/CVE via repo security-advisories → OSV commit query
   → OSV package query → NVD → web search) and the advisory date (never
   the introducer commit date).

## Forbidden

- Template-word fields (`introduced_with_feature` / `ai` / `introducer`)
- Publishing `ALIAS-*` cases
- Using the introducer commit date as `published_at`
- Deduplicating at publish time (dedup belongs at ledger level via
  `site_publication.publish=false`)

Publication gates (duplicates / dates / ir_chain / SHA / hunks / release)
are enforced by `scripts/publish_tp_ledger.py`; this file does not repeat
code details. Field semantics: `docs/DATA-SCHEMA.md`; file ownership:
`docs/AGENT-OWNERSHIP.md`.
