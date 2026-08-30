# Round8 verdict report — 2026-08-26

Wave: round8 causal research over 202 PARTIALLY_ANALYZED ledger targets
(`.ai-slop/state/research-queue/round8/cases-202.jsonl`, indices 0–201 ↔
workers w000–w201). One subagent per case, clean context per case, BIC
discipline per `docs/AUDIT-PROTOCOL.md` (smallest first-writer; moves /
renames / refactors / squash aggregates are carriers, never BIC; AI role
judged only from signals on the BIC).

## Landing

- Script: `scripts/update_ledger_round8_20260826.py` (dry-run check-only
  passed, then real run).
- Backup: `artifacts/funnel-account-20260817.jsonl.bak-round8-20260826`
  (24,124 rows, taken pre-merge).
- Merge result: 202 archived, 0 skipped, terminal-TP duplicate gate pass.
- Post-land verification: 202/202 ledger rows carry `round8_research`
  byte-identical to their `records-wNNN.jsonl` record, `round8_verdict`
  and flipped `status` match, `round8_research_source` points at the
  worker file; row count 24,124 with 24,124 unique class_ids.

## Verdict distribution (202/202)

| Verdict | Count |
|---|---|
| NOT_AI | 195 |
| AI_ROOT_CAUSE | 3 |
| AI_CODE_FLAWED | 2 |
| BLOCKED | 2 |

Ledger status counts after landing: UNANALYZED 16,511;
PARTIALLY_ANALYZED 5,960 (−202); NOT_AI 1,367 (+195); AI_ROOT_CAUSE 192
(+3); AI_CODE_FLAWED 61 (+2); BLOCKED 33 (+2).

## AI-anchored cases (5)

- **w076 AI_ROOT_CAUSE** anubissbe/projecthub-mcp (CVE-2026-19340 /
  GHSA-qp9j-gfjj-6h3v). BIC 31dd902d1234… carries "🤖 Generated with
  Claude Code" + Claude co-author trailer. Unpatched (issue #176 open).
- **w080 AI_ROOT_CAUSE** hulupeep/mcp-ui-probe (CVE-2026-19270 /
  GHSA-h8jj-pqww-5m4w). BIC ada347ec04db… carries "Generated with Claude
  Code" + Claude co-author. Unpatched through HEAD 85ec1882.
- **w166 AI_ROOT_CAUSE** astralisone/rive-mcp-server-core (CVE-2026-19288 /
  GHSA-4p6x-rj5h-hg93). BIC db1d0cc4cd52… carries "Generated with Claude
  Code" + Claude co-author; HEAD == BIC, project dead → unpatched.
- **w020 AI_CODE_FLAWED** budibase/budibase (GHSA-j9fc-w3mr-x6mv). BIC
  84ae2210cfe1… "Restrict public API global role changes" (PR #18771) has
  no on-commit marker but was merged from a `codex/*` AI-agent work
  branch — Budibase's convention for Codex work (31 such merges since
  3.38.0); the advisory's own fix used `codex/validate-public-role-app-scope`.
  Fix 453391d3245d.
- **w195 AI_CODE_FLAWED** dynatrace-oss/dynatrace-mcp (GHSA-p7w7-4929-vpj5).
  BIC 00b7649a78ab… (#107 HTTP server mode, 2025-08-20) carries
  "Co-authored-by: Copilot"; fix 8f12972481e9 (Claude Sonnet 4.6 co-author
  on fix, demoted).

## BLOCKED (2)

- **w087** anthropics/claude-code (CVE-2026-44470): vulnerable component
  (CoworkVMService) is closed-source; no BIC exists to inspect.
- **w189** guardrails-ai/guardrails (CVE-2026-45758 / GHSA-xmpw-2vmm-p4p6):
  supply-chain compromise — malicious 0.10.1 was published off-platform
  via stolen employee PAT → Actions secrets → PyPI deploy tokens; tags
  skip v0.10.1 and no in-repo introducer exists (exhaustive
  `+version =` enumeration over `git log --all -p -- pyproject.toml`
  shows 0.9.3 → 0.10.0 → 0.10.2). Clean re-release 52d24e68 (v0.10.2)
  recorded as fix. Leader reclassified from a gate-failing NOT_AI (closed
  verdicts require a 40-hex introducer) to BLOCKED with the boundary
  documented in `remaining_gap`.

## Unpatched cases (15, fix_sha null)

w007 budibase, w023 mercury-agent, w076 projecthub-mcp (AI), w078
agentscope, w080 mcp-ui-probe (AI), w087 claude-code (BLOCKED), w088
agentscope, w092 vanna-ai, w093 aws-mcp-server, w129 vllm, w155 mlflow,
w166 rive-mcp-server-core (AI), w168 Office-Word-MCP-Server (repo
archived 2026-03-03), w183 pretalx, w197 mercury-agent.

## Process observations

- All 202 worker records passed `scripts/audit_record_gates.py` (final
  sweep: zero failures) and the canon sweep (record `class_id` ==
  `cases-202.jsonl[N].class_id` for all 202).
- Squash decomposition: 58/202 records `squash_decomposed=true`.
- Fix-side AI markers (Claude/GPT/Copilot/Cursor co-authors on fix
  commits) were demoted per protocol in 73/202 records; the verdict
  rests only on BIC signals.
- Distinct repos: 106; largest concentrations: vllm-project/vllm (20),
  apache/airflow (20), django/django (9), langflow (5), pyload (5),
  open-webui (5). MCP-server projects: 8 records — of the 5 AI-anchored
  verdicts, 3 are MCP-server repos (w076, w080, w166) plus
  dynatrace-mcp (w195), consistent with the small-team/fast-ship profile
  of that ecosystem.
- Advisory-vs-repo conflicts (open-webui 0.6.44 tag gap, ghost v6.21.1
  ancestry vs advisory floor, vllm w129 explicit unpatched): resolved by
  trusting git tag state and recording both facts in evidence.
- Stale dispatch-id pitfall recurred (w173, w174, w176, w177, w178, w180,
  w183): hand-typed task headers carried wrong alias ids; every worker
  resolved via its `prompt-wNNN.txt` / bundle contract and all 202
  records canon-match `cases-202.jsonl`. Trust only `cases-202.jsonl`.
- Ghost repo-wide `git log -S --all` times out (>300s at 53k commits);
  scoped per-path pickaxe + rename-chain walks are the working method.
- Gate-strictness note: `merge_funnel_lane.check_record` requires a
  40-hex introducer for closed verdicts; structurally introducer-less
  cases (supply-chain publishes, closed-source components) must land as
  open BLOCKED, not NOT_AI.

## Correction appendix — 2026-08-27 (post double-confirm)

Three-way consensus (round8 workers, independent Grok re-audit, Claude
session git re-verification) applied to 5 records; ledger rows updated
in place (backup: funnel-account-20260817.jsonl.bak-round8-correction-20260827;
records backup: /tmp/round8-pre-correction-20260827).

| Worker | Change | Basis (re-verified in clones) |
|---|---|---|
| w020 budibase | AI_CODE_FLAWED -> NOT_AI | codex/* branch name is off-commit delivery metadata; all PR #18771 branch commits clean |
| w195 dynatrace-mcp | AI_CODE_FLAWED -> NOT_AI; BIC -> 6cca70b23c | squash 00b7649 tree == member tip tree (pure aggregate); first writer 6cca70b (Kreuzberger) object clean; Copilot member d2e79dd is a 1-line type tweak |
| w156 helm | NOT_AI -> BLOCKED | assigned clone has 0 JS/TS files; sink in closed langsmith-frontend; no public BIC |
| w186 ironic-python-agent | NOT_AI -> BLOCKED | IPA clone lacks molds.py; 15e20fe not in clone (not our ref); record repo field contradicted packet (canon defect) |
| w147 mayan-edms | NOT_AI stands; BIC -> 5ba6f2ef87 | new first-writer found: parent-clean, human, reachable from master via series/3.3/3.4 chain, parallel to squash 9f8c7cb9 (now a carrier) |

Final round8 verdict distribution: NOT_AI 195, AI_ROOT_CAUSE 3,
AI_CODE_FLAWED 0, BLOCKED 4 (w087, w189, w156, w186).

Policy ruling applied: AI signal = commit-object markers only (trailers /
Generated-with). PR-body disclosure (w169) and source-branch names do not
qualify; w169 remains NOT_AI.

Published catalog (web/src/generated/research-data.json): 237 rows =
234 previous + 3 new TPs (w076 GHSA-QP9J-GFJJ-6H3V, w080
GHSA-H8JJ-PQWW-5M4W, w166 GHSA-4P6X-RJ5H-HG93), each with comparison
hunks from the clones and CVE published dates (2026-08-08/09); preflight
OK (errors 0); zero ALIAS-* published; demoted w020/w195 correctly
absent. Advisory dates supplied via scripts/first-party-advisory-dates.json;
missing-release allowlist entries added for the 3 unpatched MCP repos.
Verification: 202/202 ledger rows byte-identical to corrected records,
statuses flipped, 29,593 rows / 29,593 unique class_ids, TP-duplicate
gate pass.
