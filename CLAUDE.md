# Vibe Security Radar

Detect AI-introduced vulnerabilities by analyzing CVE fix commits for AI co-author signatures.

## Project Structure

| Directory | What | Stack |
|-----------|------|-------|
| `cve-analyzer/` | CLI tool — CVE discovery, git blame, AI signal detection | Python 3.13, uv |
| `web/` | Dashboard — visualizes results | Next.js 16, React 19, TailwindCSS |
| `scripts/` | Data pipeline scripts (`generate_web_data.py`) |

Analyzer source: `cve-analyzer/src/cve_analyzer/`. Tests: `cve-analyzer/tests/`.

## Data Flow

```
cd cve-analyzer && uv run cve-analyzer batch --all --since 2025-05-01 --llm-verify
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

## Regression

Baseline: `cve-analyzer/regression/baseline-2026-03-09.md` (92 TPs). Use `/regression` after pipeline changes to check for lost or new true positives. See `regression/history.md` for changelog and `regression/lessons.md` for patterns and improvement ideas.

## Code Conventions

- Dataclasses (no pydantic), httpx sync (no async), subprocess.run (no GitPython)
- JSON file cache in `~/.cache/cve-analyzer/`
- Tests use JSON fixtures in `tests/fixtures/`, no real API calls

## Code Review

Run code review and fixes in sub-agents to keep the main context window clean.

## Commit Messages

Use `/humanizer` to review commit messages before committing. Keep messages natural and concise.

## LLM Cost Reporting

After any operation that calls external LLMs (e.g. `--llm-verify`), report token usage and estimated cost.
