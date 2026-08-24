# Site data-reality reconciliation worker

Owner: your own dir autoresearch/orchestrator-260815-site-fix/. Deepseek lane.
The repo is dirty with other agents' work; only touch the files listed below.

## Facts (truth sources)

- autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl (168 rows, tiers)
- autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl (94 strict)
- autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl (scoped rows)
- autoresearch/orchestrator-260814-irchains-sol/ir-chains.jsonl
- .ai-slop/state/data-refresh/source-before-final/cvelistV5.head (CVE records)

## Tasks

1. In web/src/generated/research-data.json, fix the 25 cases with published_at null:
   resolve the date from cvelistV5 for CVE aliases, else the advisory-database;
   leave null ONLY when the id is absent everywhere. Never invent dates.
2. Fill empty repository and repository_metadata.language where derivable from
   fp211 final_mechanisms.jsonl or the advisory ecosystem. Never invent repos.
3. Run scripts/publish_research_ledger.py to check your fixes do not get
   overwritten; if they do, fix the generator instead and re-run.
4. web/data/index.json and stats.json still describe the 36-page legacy catalog
   while the site header says 168: either regenerate both consistent with the
   168 research ledger or add an explicit legacy_catalog flag; do not leave
   mixed denominators. data.ts validator must still pass.
5. Update web tests that hard-code 84 (ui-regressions.test.tsx) to match 168
   and the tiered snapshot; add one test that every case has a non-empty
   case_id and gates object.
6. Verify: npx tsc --noEmit, npx eslint on changed files, node smoke.mjs
   (Playwright), and record every remaining null/UNKNOWN in report.md.

## Hard constraints

No GitHub API. No commits. No fabrication: every fill must cite its source
file. Report unresolved gaps instead of guessing.
