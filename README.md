# Vibe Security Radar

Georgia Tech SSLab. A public catalog of disclosed GHSA/CVE cases where AI-written code introduced, enabled, or failed to close the flaw.

**https://vibesecradar.com/**

Coverage is public advisories from 2025-05 through 2026-08. The site publishes 195 confirmed true positives from a 23,861-class ledger. That count is a lower bound: not every AI-assisted change leaves a trail.

## Run locally

```bash
cd web
npm ci
npm run dev
```

`npm run build` rebuilds `web/src/generated/research-data.json` from the ledger, runs publication preflight, and writes the static export to `web/out/`. Public fields are English-only.

## Deploy

Pushes to `main` deploy through `.github/workflows/deploy-pages.yml`.

```bash
cd web && npm run deploy
```

## Repo

| Path | Role |
|------|------|
| `web/` | Next.js static catalog (Cloudflare Pages) |
| `artifacts/funnel-account-20260817.jsonl` | Canonical research ledger |
| `scripts/publish_tp_ledger.py` | Ledger → site JSON |
| `scripts/site_preflight.py` | Dates, diffs, releases, English-only gates |

Campaign dumps, cloned-repo caches, and one-off scripts stay local and are gitignored.

## Contact

False positive or a case we missed: [open an issue](https://github.com/HQ1995/vibe-security-radar/issues) or email hanqing@gatech.edu.

## License

MIT
