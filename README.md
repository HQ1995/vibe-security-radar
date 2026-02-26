# Vibe Security Radar

Public tracker for security vulnerabilities introduced by AI coding tools.

The project has two parts:

| Directory | What | Stack |
|-----------|------|-------|
| `cve-analyzer/` | CLI tool that discovers and analyzes vulnerabilities | Python 3.13, uv |
| `web/` | Dashboard that visualizes the results | Next.js 16, React 19, TailwindCSS |

Data flows from the analyzer to the web frontend:

```
cve-analyzer batch --all --llm-verify
        ↓  (cached in ~/.cache/cve-analyzer/results/)
python scripts/generate_web_data.py
        ↓  (writes web/data/cves.json + stats.json)
cd web && npm run build
```

## Quick Start

### 1. Set up the analyzer

```bash
cd cve-analyzer
uv sync
```

### 2. Configure API tokens

```bash
export GITHUB_TOKEN="ghp_..."       # Required for reasonable rate limits
export NVD_API_KEY="..."            # Optional, improves NVD rate limit
```

### 3. Run a batch analysis

```bash
# Analyze all ecosystems from May 2025 onward, with LLM verification
uv run cve-analyzer batch --all --since 2025-05-01 --llm-verify
```

### 4. Generate web data and preview

```bash
python scripts/generate_web_data.py
cd web && npm install && npm run dev
# Open http://localhost:3000
```

See [cve-analyzer/README.md](cve-analyzer/README.md) for full CLI reference and architecture details.

## Repository Layout

```
├── cve-analyzer/           # Python CLI tool
│   ├── src/cve_analyzer/   # Source code
│   ├── tests/              # Pytest suite (JSON fixtures, no real API calls)
│   └── pyproject.toml
├── web/                    # Next.js dashboard
│   ├── src/                # App Router pages + components
│   └── data/               # Generated JSON (cves.json, stats.json)
├── scripts/
│   └── generate_web_data.py  # Transforms cached results → web JSON
└── slop-detector/          # Related experimental tool
```

## License

MIT
