# Enrichment worker: fill null fields in the 168-case site data

Owner: your own dir autoresearch/herdr-260815-enrich-ds/. Read-only elsewhere.

## Task

For every case in web/src/generated/research-data.json whose fields are null/empty,
derive and write a persistent table at
autoresearch/orchestrator-260814-ghsa200-canvas/sweep/enrichment-fixes.json:
  { CASE_ID: { repository, mechanism, language, family, cause_category,
              scope_statement, evidence_paths } }
Only include fields you actually filled. Never fabricate.

## Sources (local, in order of trust)

- autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl
  (decisive_evidence/counterevidence: repo URLs, mechanism sentences, tool names)
- autoresearch/orchestrator-260814-irchains-sol/ir-chains.jsonl
  (original_introducing_commit author/email -> AI family; attempted_remediation
  text -> mechanism)
- advisory-database clone at /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/
  advisory-database (origin/main, reviewed+unreviewed) for ecosystem/summary
- git pool /home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo> for candidate
  commit author/email (git log -1) -> AI family

## Field rules

- repository: extract github.com/owner/repo from evidence; else null.
- mechanism: one-line description of the vulnerable mechanism.
- language: advisory ecosystem mapped to a language name (PyPI=Python, npm=JS,
  Go=Go, Maven=Java, RubyGems=Ruby, Packagist=PHP, crates.io=Rust); else from
  the git pool's dominant file extension.
- family: claude / copilot / cursor / openai_gpt_codex / claude_flow ONLY from an
  explicit author identity or trailer; else omit the field.
- cause_category: pick from auth_access, injection, path_link, ssrf_network,
  resource_abuse, validation_fail_open, other_ambiguous based on the mechanism.
- scope_statement: for scoped rows, the decisive_evidence sentence that scopes it.

## Verify

Run scripts/publish_research_ledger.py and report the remaining null counts; the
table must make them decrease. Write report.md with per-field before/after.
## Task 2 - code evidence (line-by-line comparison)

For every case in web/src/generated/research-data.json with candidate_set and
minimum_fix_set non-empty, build sweep/code-evidence.json keyed by case_id with
the ResearchCodeEvidence shape:
  { ai_marker, fix_marker, candidate_url, fix_url, advisory_url, summary,
    steps:[{title,detail}], candidate_hunks:[{file,code,annotation}],
    fix_hunks:[{file,code,annotation}], comparison_hunks:[...],
    candidate_patch_sha256, fix_patch_sha256 }

- Resolve each commit in /home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>;
  blobless fetch + deepen via git smart-HTTP when missing (no GitHub API).
- git show --format=fuller the candidate and fix; take up to 3 files per commit,
  cap each hunk code at 60 lines; annotation = one line describing the change.
- ai_marker = the candidate trailer line; summary = mechanism sentence.
- Truncate the table so research-data.json stays under ~2MB.
- Unresolvable cases are omitted (not fabricated).

Re-run scripts/publish_research_ledger.py and report how many cases got
code_evidence before/after in report.md.
