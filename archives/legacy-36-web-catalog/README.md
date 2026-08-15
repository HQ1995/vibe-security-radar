# Legacy 36-case web catalog (archived 2026-08-15)

Snapshot of the old curated-CVE dashboard data (index.json, stats.json,
cves/*.json) previously served from web/data/.

- The site now runs exclusively on the 168-case research pipeline:
  scripts/publish_research_ledger.py -> web/src/generated/research-data.json.
- The generator that produced this catalog (scripts/generate_web_data.py +
  scripts/web_data/) is part of the frozen data-refresh campaign and is kept
  on disk per CLAUDE.md; it is no longer used by the site.
- Some frozen audit artifacts still cite web/data/cves/*.json as historical
  source paths; those citations refer to this archived snapshot and are left
  unchanged to preserve provenance.
