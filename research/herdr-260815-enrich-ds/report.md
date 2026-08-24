# Enrichment worker report — 168-case site data

Owner: `autoresearch/herdr-260815-enrich-ds/`. Fill null fields in
`web/src/generated/research-data.json`, then measure the remaining nulls.

## Task 1 — null field enrichment

Wrote `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/enrichment-fixes.json`
(99 cases), sourced from fp211 `final_mechanisms.jsonl`, `ir-chains.jsonl`, the
advisory-database clone, the git pool, and cached repo clones. Fields were only
set when currently null/empty; nothing was fabricated.

Per-field before/after null counts (168 cases):

| field | before | after | delta |
|---|---|---|---|
| repository | 7 | 0 | -7 |
| mechanism | 15 | 0 | -15 |
| language | 34 | 0 | -34 |
| family | 32 | 4 | -28 |
| cause_category | 84 | 0 | -84 |
| scope_statement (scoped rows) | 0 | 0 | 0 |

Notes:
- `repository`: 7 repo-less scoped rows recovered from fp211 decisive evidence
  and the canonical ledger (openclaw, gitlab-mcp, solidcam-gppl-ide, coolify x2,
  titra, AutoGPT).
- `mechanism`: 15 rows filled from ir-chains `original_mechanism` or advisory
  `summary`.
- `language`: 34 rows filled from advisory ecosystem / git-pool dominant
  extension / cached repo clones. The 4 remaining family nulls and the
  publisher's own commit-metadata detection are independent of this table.
- `family`: only explicit author identity or trailer was used (14 rows:
  claude x11, copilot x2, openai_gpt_codex x1). The remaining 4 nulls have no
  explicit AI identity/trailer, so they are intentionally left unresolved.
- `cause_category`: 84 rows classified from the mechanism into the canonical
  7-way taxonomy (`auth_access`, `injection`, `path_link`, `ssrf_network`,
  `resource_abuse`, `validation_fail_open`). 84 -> 0.

## Task 2 — code evidence

Wrote `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/code-evidence.json`
(line-by-line candidate/fix hunks, `ResearchCodeEvidence` shape), and added
`code-evidence.json` loading to `scripts/publish_research_ledger.py`.

Resolution: commits were resolved in `/home/hanqing/.cache/ghsa200-sweep-fetch`
via blobless `git fetch`/deepen (no GitHub API). Cap applied: 3 files x 60 lines
per commit.

| code_evidence | before | after |
|---|---|---|
| null | 166 | 48 |
| filled | 2 | 120 |

Resolved 119 cases. 49 not resolvable:
- 45 repo not present in the git pool (e.g. ChurchCRM, coolify, titra, ha-mcp,
  NogginLessDom).
- 4 candidate commit could not be resolved even after deepen.

Each entry carries `ai_marker`/`fix_marker` (trailer only), `candidate_url`,
`fix_url`, `advisory_url`, `summary`, `steps`, `candidate_hunks`, `fix_hunks`,
`comparison_hunks`, and sha256 digests of the raw candidate/fix patches.
