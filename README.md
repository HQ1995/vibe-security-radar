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
export LITELLM_API_BASE="https://litellm.example/v1"
export LITELLM_API_KEY="..."
export CVE_REASONING_EFFORT=max

# 2. Run batch analysis (full run needs ~2TB disk)
uv run cve-analyzer batch --all --since 2025-05-01 --llm-verify \
  --llm-model gpt-5.6-luna --verify-model gpt-5.6-luna

# Optional: capture an evidence-only diagnostic when every API model fails.
# Set the LiteLLM gateway, exact proxy model ID, and user-owned CLI SHA-256 pin;
# see
# cve-analyzer/README.md.
uv run cve-analyzer analyze CVE-2024-27304 --llm-verify --coding-agent codex

# 3. Generate a formally certified Web release and preview
python scripts/generate_web_data.py \
  --heldout-selection scripts/heldout_studies/selection-<sha256>.json \
  --heldout-labels scripts/heldout_studies/labels-<sha256>.json \
  --recall-selection scripts/heldout_studies/recall-selection-<sha256>.json \
  --recall-labels scripts/heldout_studies/recall-labels-<sha256>.json \
  --recall-report .ai-slop/state/data-refresh/end-to-end-recall-current.json
cd web && npm install && npm run dev
```

Run `uv run cve-analyzer --help` for full CLI reference.

## How It Works

1. **Find the fix commit** — aggregate from OSV, GHSA, Gemnasium, NVD; fall back to LLM-assisted git log search
2. **Trace who introduced the bug** — SZZ-style git blame, squash-merge decomposition via GitHub API
3. **Detect AI signals** — exact co-author trailers, bot identities, agent-log links, and commit markers from current coding agents, including Codex, Claude Code, Copilot CLI, Mistral Vibe, Warp Oz, Qwen Code, OpenWork, Qoder, CodeRabbit, and Ellipsis; unverified Kimi, Antigravity, and Grok identities stay below the high-confidence path
4. **Screen** — per-CVE LLM triage removes cases where the AI-attributed commit is unrelated to the vulnerability
5. **Deep investigate** — LLM agent with git tool access (50 tool calls) answers: did AI-authored code help cause this vulnerability?
6. **Failure diagnostics** — optional Codex, Claude Code, or Kimi Code CLI review of a bounded evidence bundle after the model chain fails; diagnostics are audited separately from BIC verdicts

## Publication curation and independent quality gates

Independent CVE-level adjudications control both audited inclusions and known
false-positive exclusions. This command checks that the published allowlist is
consistent with those same curation inputs:

```bash
uv run --project cve-analyzer python scripts/evaluate_publication_quality.py
```

The schema-2 report calls these values `curation_precision` and
`curation_recall`. They measure publication-curation implementation consistency,
including complete coverage of every page and zero known-negative,
inconclusive, or unadjudicated leaks. Their scope is publication-curation
implementation consistency. Independent held-out evidence supplies the
detector-accuracy claim. The generator publishes only source-alias equivalence
classes adjudicated as `AI_CAUSAL`.

Detector quality comes from the precommitted independent workflow in
[`scripts/HELDOUT_QUALITY.md`](scripts/HELDOUT_QUALITY.md). Formal generation
requires the sealed selection and its independently created labels, replays the
held-out evaluator in process, and requires precision and conditional recall
point estimates plus both one-sided 95% exact lower bounds to reach 0.95.
Inconclusive labels, infrastructure failures, unresolved cases, campaign/source/
contract drift, selection or label drift, and incomplete denominators all block
promotion. Conditional recall covers the discovered raw AI-signal candidate
population; advisory discovery and signature discovery remain separate study
boundaries.

The reproducible Luna/max refresh, source-freeze, staged-result, and full
campaign proof contract is documented in [`scripts/DATA_REFRESH.md`](scripts/DATA_REFRESH.md).

## Contributing

Found a false positive? Think we missed something? Want to add a new AI tool signature or improve detection?

- [Open an issue](https://github.com/HQ1995/vibe-security-radar/issues) to report bugs or suggest improvements
- [Submit a PR](https://github.com/HQ1995/vibe-security-radar/pulls) — new signal patterns, pipeline fixes, and web UI improvements are all welcome
- Email hanqing@gatech.edu for research collaboration

## License

MIT
