# Vibe Security Radar

Tracking real CVEs where AI-generated code introduced the vulnerability.

We scan public advisory databases (OSV, GitHub Advisory Database, NVD), trace each fix commit back to the code that introduced the bug via git blame, check for AI tool signatures (co-author trailers, bot emails, commit message markers), and verify causality with an LLM investigator.

**This is a research project from [Georgia Tech SSLab](https://gts3.org)** (Systems Software & Security Lab, School of Cybersecurity and Privacy).

> Detection relies on commit metadata — not all AI-assisted code leaves traces. Our numbers are a strict lower bound. The project is under active development and results may contain errors. See the [methodology & limitations](https://vibe-radar-ten.vercel.app/about) page.

## Quick Start

A full `--all` run clones ~10k repos and requires **2TB+ disk space**. For a quick test, use `--ecosystem` or `--cve-list` to analyze a smaller set.

```bash
# 1. Set up
cd cve-analyzer && uv sync
export GITHUB_TOKEN="ghp_..."

# 2. Run batch analysis (full run needs ~2TB disk)
uv run cve-analyzer batch --all --since 2025-05-01 --llm-verify

# 3. Generate web data and preview
python scripts/generate_web_data.py
cd web && npm install && npm run dev
```

Run `uv run cve-analyzer --help` for full CLI reference.

## How It Works

1. **Find the fix commit** — aggregate from OSV, GHSA, Gemnasium, NVD; fall back to LLM-assisted git log search
2. **Trace who introduced the bug** — SZZ-style git blame, squash-merge decomposition via GitHub API
3. **Detect AI signals** — co-author trailers, bot emails, commit message markers from 15+ AI tools
4. **Screen** — per-CVE LLM triage filters out cases where AI commits are clearly unrelated (~80% precision)
5. **Deep investigate** — LLM agent with git tool access (50 tool calls) answers: did AI-authored code help cause this vulnerability?
6. **Fallback** — Claude Agent SDK subprocess retries when the primary model fails

## Contributing

Found a false positive? Think we missed something? Want to add a new AI tool signature or improve detection?

- [Open an issue](https://github.com/HQ1995/vibe-security-radar/issues) to report bugs or suggest improvements
- [Submit a PR](https://github.com/HQ1995/vibe-security-radar/pulls) — new signal patterns, pipeline fixes, and web UI improvements are all welcome
- Email hanqing@gatech.edu for research collaboration

## License

MIT
