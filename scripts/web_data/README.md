# web_data — published data pipeline

Package that turns cached CVE analysis results into the JSON artifacts the
website is built from. Orchestrated by `scripts/generate_web_data.py`.

## Pipeline overview

```
~/.cache/cve-analyzer/ (analysis cache, reviews, NVD/GHSA feeds, repo clones)
        │  loader.py       read cached results + supplementary dates/severities
        │  filters.py      should_include(): drop errors, rejects, stale verdicts
        │  entry_builder.py build_entry(): transform to published shape;
        │                  evidence conflicts are QUARANTINED (recorded with
        │                  reasons in QuarantineLog), never guessed
        │  severity.py / languages.py / stats.py
        ▼
schema.py validation (every entry, index, stats — before any file is written)
        ▼
writer.py          atomic writes + stale-file cleanup
        ▼
web/data/  →  committed  →  Next.js build (web/src/lib/data.ts assembles)
```

Run it (after `cve-analyzer batch` has populated the cache):

```bash
python scripts/generate_web_data.py
```

The run ends with a summary plus a **Quarantined N CVE(s)** section listing
each dropped CVE and why. A quarantine spike after a pipeline change means
something regressed upstream — investigate before committing the data.

## Published artifact layout (per-CVE)

```
web/data/
├── index.json        {"generated_at", "total", "ids": [...]} — manifest, ids in display order
├── cves/<ID>.json    one CveEntry per file
└── stats.json        aggregate statistics
```

**Why per-CVE files:** the previous monolithic `cves.json` was rewritten in
full on every run, so an incremental update of a few CVEs produced an
unreviewable thousand-line diff. One file per CVE makes data PRs
reviewable: added/removed CVEs appear as added/deleted files, field fixes
as small diffs in a single entry. `writer.py` also deletes stale files
(entries that left the dataset) and any leftover legacy `cves.json`.

## The schema contract (Python → JSON → TypeScript)

`schema.py` is the single source of truth for every published field:

- **Producer gate** — `generate_web_data.py` validates every entry, the
  index, and stats against it before writing anything.
- **TypeScript sync** — `ts_types.py` maps the same definitions to
  `web/src/lib/types.generated.ts` (`web/src/lib/types.ts` re-exports it).
  After changing the contract, regenerate with:
  ```bash
  python scripts/web_data/ts_types.py          # rewrite types.generated.ts
  python scripts/web_data/ts_types.py --check  # CI gate: fails if stale
  ```
- **Release gates** — `scripts/tests/test_web_data_schema.py` validates the
  committed artifacts; `test_published_web_data.py` checks cross-file
  consistency (manifest ↔ files on disk ↔ stats) and published-data
  invariants.

Field conventions: `published` is exactly `YYYY-MM-DD`, `YYYY`, or `""`;
`verification.confidence` is `number | null`; ids are filenames verbatim.

## Consumers

- `web/src/lib/data.ts` — imports `index.json`, reads `cves/*.json` from
  disk at build time, assembles the in-memory `CvesData` (server-only).
- `scripts/pipeline_funnel.py` — reads the same layout for drop-off
  diagnostics.

## Module map

| Module | Role |
|--------|------|
| `loader.py` | Read cache, reviews, NVD/GHSA dates, severities, fix-commit dates, audit overrides |
| `filters.py` | `should_include()` inclusion logic + `FilteringLog` |
| `entry_builder.py` | `build_entry()` transform; `QuarantineLog` for recorded drops |
| `severity.py` | CVSS 3.1/4.0 scoring + GHSA/keyword fallbacks |
| `languages.py` | Language inference from commit diffs |
| `stats.py` | Aggregate stats (by tool/severity/language/repo/month) |
| `schema.py` | Published contract + validator |
| `ts_types.py` | TypeScript codegen from the schema |
| `writer.py` | Validated, atomic artifact writes + stale cleanup |
