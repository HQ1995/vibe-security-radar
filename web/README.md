# Catalog site

Next.js 16 static export of the public catalog. Data comes from
`../scripts/publish_tp_ledger.py` reading `../artifacts/funnel-account-20260817.jsonl`.

```bash
npm ci
npm run dev      # http://localhost:3000
npm run build    # publisher + preflight + web/out/
npm test         # vitest
```

| Route | Page |
|-------|------|
| `/` | Covered advisories, counts, disclosure trend |
| `/cves` | Findings list |
| `/cves/[id]` | Case detail |
| `/about` | How we verify |
| `/analytics`, `/tools` | Compatibility redirects |

Production: https://vibesecradar.com/. Pushes to `main` deploy via GitHub Actions.
