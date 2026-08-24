# Deterministic repo matching for repo-less advisory classes (2026-08-16)

## Mission

The census shows 44,979 usable advisory alias-classes with NO parseable repo
from official GHSA+CVE. This is likely overstated. Do deterministic matching
to attach a repository wherever one truly exists, and produce the honest
repo-less remainder with a closed-source vs parse-miss breakdown.

## Inputs (local, no api.github.com)

- research/orchestrator-260809-0539/current-official-census/alias_classes.jsonl
  (class_id, member_ids, sources, states; filter: no WITHDRAWN/REJECTED, in window)
- research/orchestrator-260809-0539/current-official-census/subjects.jsonl
  (id, lane, path, source; lane: cve_list_v5 / unreviewed / github-reviewed)
- current-source-snapshots/ (advisory-database tar.gz, cvelistV5 tar.gz, osv/*.zip)
- Existing parsers to reuse: cve_analyzer.git_url.parse_repo_url/parse_commit_url,
  scripts/cohort/advisories.py:commit_reference_rows_from_record,
  cve_analyzer.ghsa_local (first GIT range repo, else first PACKAGE URL)

## Matching strategy (in priority order)

1. GHSA records: parse EVERY reference URL (not just PACKAGE): commit links,
   security/advisories links (host repo!), issues/PRs, releases, bare repo URLs.
   A https://github.com/OWNER/REPO/security/advisories/GHSA-... reference
   IS the repo. Also affected[].ranges with type=GIT .repo.
2. Ecosystem determinism for package names:
   - Go: module path itself is the repo (github.com/..., gitlab.com/...).
   - crates.io / npm / PyPI / Maven / NuGet: resolve via local OSV zip
     affected[].package.purl/name -> OSV often carries the GIT range repo.
   - For remaining npm/PyPI: registry metadata lookup is allowed
     (registry.npmjs.org/<pkg>, pypi.org/pypi/<pkg>/json) - NOT api.github.com.
     Extract repository.url field. This is deterministic, not guessing.
3. Recompute: classes WITH repo after this pass; the true repo-less remainder;
   and of that remainder, how many are closed-source/EOL/abandoned (evidence
   from the advisory text) vs simply missing references.

## Output

.ai-slop/state/census-research/repo-match-findings.md with:
- methods used, per-method recovered counts
- new repo-attached class count, new distinct repos
- final repo-less count + closed-source/parse-miss breakdown (with samples)
- a repo-attachment CSV/JSONL at .ai-slop/state/census-research/repo-matches.jsonl
  (class_id, repo, method)

Reply with the path and the three headline numbers.

## Rules

- Read-only research; no tracked file changes; no api.github.com.
- Registry lookups only for npm/PyPI/crates (bounded, polite).
- Distinguish COMPUTED vs ESTIMATED in the report.
