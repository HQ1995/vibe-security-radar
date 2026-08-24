# Vibe Security Radar

Georgia Tech SSLab. A public catalog of disclosed vulnerabilities where AI-written code introduced, enabled, or failed to close the flaw.

**Site:** https://vibesecradar.com/

Coverage is public GHSA/CVE from 2025-05-01 through 2026-08-16. The published catalog is 195 confirmed true positives from a 23,861-advisory ledger. That count is a lower bound: not every AI-assisted change leaves a trail.

## Layout

| Path | Role |
|------|------|
| `web/` | Next.js static catalog (Cloudflare Pages) |
| `artifacts/funnel-account-20260817.jsonl` | Canonical research ledger |
| `scripts/publish_tp_ledger.py` | Builds `web/src/generated/research-data.json` |
| `cve-analyzer/` | Older CVE → blame CLI; not the live catalog source |

## Local site

```bash
cd web
npm ci
npm run dev
```

`npm run build` regenerates the public JSON, runs preflight, and writes `web/out/`. Public fields are English-only.

## Deploy

Pushes to `main` deploy through `.github/workflows/deploy-pages.yml`.

```bash
cd web && npm run deploy
```

## Contributing

False positive or a case we missed: [open an issue](https://github.com/HQ1995/vibe-security-radar/issues) or email hanqing@gatech.edu.

## License

MIT
