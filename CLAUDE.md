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

```
cd cve-analyzer && uv run cve-analyzer batch --all --since 2025-05-01
python scripts/generate_web_data.py   # → web/data/cves.json + stats.json
cd web && npm run build
```

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

## Quality Assurance

- **Unit tests**: Algorithm correctness (`cve-analyzer/tests/`)
- **Deep verifier**: Single-model investigator with tool access (git log, file read, etc.) to filter false positives. Replaced the old 3-model tribunal voting.
- **Conflict resolver**: Claude Agent SDK with MCP git tools resolves divergent BIC verdicts. Batched execution to minimize subprocess overhead.
- **`/audit`**: Independent deep verification of individual CVEs
- **Audit queue**: `python scripts/audit_queue.py` — picks the next audit target by priority. Use this instead of the default Phase 0 selection when running `/audit` without a specific CVE ID.
- **Audit scripts**: `scripts/audit_select.py` (stratified sampling), `audit_actionable.py` (worth-investigating filter), `audit_patterns.py` (cross-audit patterns), `audit_recurring.py` (repeat findings)
- **Regression tests**: `scripts/regression_tag_search.py`, `regression_desc_search.py`, `regression_ref_search.py` — algorithm regression suites with ground-truth fixtures in `scripts/fixtures/`

## Code Conventions

- Dataclasses (no pydantic), httpx sync (no async), subprocess.run (no GitPython)
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
