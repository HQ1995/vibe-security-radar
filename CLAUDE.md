# Vibe Security Radar

Detect AI-introduced vulnerabilities by analyzing CVE fix commits for AI co-author signatures.

## Project Structure

| Directory | What | Stack |
|-----------|------|-------|
| `cve-analyzer/` | CLI tool — 7-tier fix discovery, git blame, AI signal detection | Python 3.13, uv |
| `web/` | Dashboard — CVE browser, analytics, tool pages | Next.js 16, React 19, TailwindCSS |
| `scripts/` | Data pipeline, audit, and regression test scripts |

Analyzer source: `cve-analyzer/src/cve_analyzer/`. Tests: `cve-analyzer/tests/`.

## Data Flow

The site has one data source: the 168-case research pipeline.

```
python3 scripts/publish_research_ledger.py   # → web/src/generated/research-data.json
cd web && npm run build
```

npm run dev / npm run build in web/ run the generator automatically
(predev/prebuild). Legacy artifacts:

- The old curated-CVE web catalog is archived at
  archives/legacy-36-web-catalog/ (was web/data/).
- The frozen data-refresh campaign (generate_web_data.py, web_data/,
  run_data_refresh.py, quality gates, tests, web release gates) is archived
  under archives/legacy-web-data-campaign/. Nothing in the live pipeline
  reads it.nothing in the site reads them.

## Key Commands

```bash
cd cve-analyzer
uv run cve-analyzer analyze CVE-XXXX        # Single CVE
uv run cve-analyzer batch --ecosystem PyPI   # Batch by ecosystem
uv run pytest                                # Tests
uv run ruff check src/ tests/                # Lint
```

## Data Scope

Default batch start date: **May 2025**. Always pass `--since 2025-05-01` to batch commands. CVEs before 2025-05 are outside coverage.

## Research Direction (2026-07-26)

The formal data-refresh campaign is **archived** under
archives/legacy-web-data-campaign/ (`scripts/run_data_refresh.py`, the release
gate, and the no-token pilot get no further investment). The CVE→blame→AI direction provedCVE→blame→AI direction proved
structurally expensive on large repos and can never produce a denominator.

New main line: a **forward cohort study** — enumerate AI-attributed commits,
pair them with controls, then link outcomes. Entry point:
`scripts/cohort_scan_ai_commits.py`. The web dashboard continues as a curated
case collection of confirmed AI-introduced CVEs; it needs no coverage proof.

## Quality Assurance

- **Unit tests**: Algorithm correctness (`cve-analyzer/tests/`)
- **Deep verifier**: Single investigation loop with an ordered API-model fallback chain and constrained git tools. Replaced the old 3-model tribunal voting.
- **Coding-agent diagnostics**: optional Codex, Claude Code, or Kimi Code CLI review over bounded evidence. Every CLI uses the shared LiteLLM gateway, provider tools are disabled, and diagnostic output stays separate from BIC verdicts.
- **`/audit`**: Independent deep verification of individual CVEs
- **Audit queue**: `python scripts/audit_queue.py` — picks the next audit target by priority. Use this instead of the default Phase 0 selection when running `/audit` without a specific CVE ID.
- **Audit scripts**: `scripts/audit_select.py` (stratified sampling), `audit_actionable.py` (worth-investigating filter), `audit_patterns.py` (cross-audit patterns), `audit_recurring.py` (repeat findings)
- **Regression tests**: `scripts/regression_tag_search.py`, `regression_desc_search.py`, `regression_ref_search.py` — algorithm regression suites with ground-truth fixtures in `scripts/fixtures/`

## Code Conventions

- Dataclasses (no pydantic), httpx sync (no async), argv-only subprocesses (no GitPython)
- JSON file cache in `~/.cache/cve-analyzer/`
- Tests use JSON fixtures in `tests/fixtures/`, no real API calls

## Development Workflow

- **TDD**: Use `/tdd` workflow — write tests first, then implement, verify 80%+ coverage.
- **After major changes**: Run `/simplify` to check for reuse/quality issues, and use code-review agent to catch problems early.
- Run code review and fixes in sub-agents to keep the main context window clean.

## Bug Fixes

Don't patch symptoms. Before writing a fix, trace the bug to its root cause — figure out why it happened, not just where it surfaced. Consider whether the design or data flow made this bug likely, and fix at that level. A one-line band-aid that doesn't address the underlying problem just moves the bug somewhere else.

## Commit Messages

Use `/humanizer` to review commit messages before committing. Keep messages natural and concise.

## LLM Cost Reporting

After any operation that calls external LLMs (e.g. `--llm-verify`), report token usage and estimated cost.

## Context Management

Actively manage context. Do not wait for the context window to fill up.

When context becomes noisy, repetitive, stale, or drifted, compress early. Use /compact when available, otherwise produce a brief handoff summary that preserves goals, decisions, constraints, open questions, and next actions.

If hallucination or confusion appears, stop and move to a fresh session immediately with a compact handoff.

Externalize work through SDD into small task files with clear inputs, outputs, and acceptance criteria so each task needs only minimal context.
