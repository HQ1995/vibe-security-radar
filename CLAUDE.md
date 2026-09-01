# Vibe Security Radar

Public catalog of confirmed AI-introduced vulnerabilities. Live site: https://vibesecradar.com/

## Layout

| Path | Role |
|------|------|
| `web/` | Next.js 16 static catalog (Cloudflare Pages) |
| `scripts/ledger_store.py` | Canonical ledger (Neon Postgres): assessments, finalize, export |
| `scripts/sync_display_to_db.py` | Syncs publication display content into Neon `ledger_display` |
| `artifacts/funnel-account-20260817.jsonl` | Deterministic GitHub export of the ledger (schema: `docs/DATA-SCHEMA.md`) |
| `docs/AUDIT-PROTOCOL.md` | How a case gets judged (vulnerability first, AI second) |
| `docs/AGENT-ONBOARDING.md` | New-agent walkthrough: claim, audit, verify, hand off |
| `scripts/publish_tp_ledger.py` | Builds `web/src/generated/research-data.json` |
| `scripts/site_preflight.py` | Publication gates before `web/` build |
| `cve-analyzer/` | Older CVE → blame CLI; not the live catalog source |

## Data flow

Canonical ledger lives in Neon Postgres (`scripts/ledger_store.py`). The publisher
reads Neon `ledger_display` first and falls back to committed files only when Neon
is unavailable; `scripts/sync_display_to_db.py` pushes source display content in.

```
python3 scripts/publish_tp_ledger.py   # → web/src/generated/research-data.json
cd web && npm run build
```

`npm run dev` / `npm run build` in `web/` run the publisher automatically (predev/prebuild). Coverage window is the ledger window (`2025-05-01` .. `2026-08-26`), not generate time.

Public site copy, README, and committed files are English-only.

## Key commands

```bash
cd web && npm ci && npm run dev        # local catalog
cd web && npm run build                # static export + preflight
cd cve-analyzer && uv run pytest       # analyzer tests
cd cve-analyzer && uv run ruff check src/ tests/
```

Default analyzer batch start: `--since 2025-05-01`. CVEs before 2025-05 are outside coverage.

## Conventions

- Dataclasses (no pydantic), httpx sync (no async), argv-only subprocesses (no GitPython)
- JSON file cache in `~/.cache/cve-analyzer/`
- Tests use JSON fixtures; no real API calls in unit tests
- Fix root causes, not symptoms
- Public JSON must pass `scripts/site_preflight.py`; do not allowlist-as-filter

## Local-only (gitignored)

`.ai-slop/` (cloned-repo cache), `research/` dump dirs (work/, clones/, api-cache/, ...), root `*.py` one-offs, `.tmp_*`, and agent worktrees. Do not commit them. Lane evidence files (result.json, report.md, cases.jsonl, manifests) ARE committed at round close.
