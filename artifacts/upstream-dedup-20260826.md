# Upstream advisory universe, deduped (2026-08-26)

Independent rebuild. Ledger **not** modified.
Window `2025-05-01` .. `2026-08-26`.
Identity = CVE+GHSA connected component; withdrawn GHSA and REJECTED CVE dropped.
Repo parse = GitHub / gitlab.com / kernel, plus OSS forges the simple parser missed.

## Raw → unique

- GHSA files (reviewed all years + unreviewed 2025/2026): **124787**
- NVD 2025/2026 CVE records: **94119**
- Raw public IDs before union: **218906**
- After alias-union, drop withdrawn/rejected: **130406** unique classes
- In window (min published): **93038**
  - reviewed: **11609**
  - unreviewed-only: **75289**
  - NVD-only (no GHSA): **6140**
- In window with a parsed product repo: **36645**
  - simple GitHub / gitlab.com / kernel: **36045**
  - recovered (Bitbucket, self-hosted GitLab, googlesource, cgit/gitweb, …): **600**
- Dropped advisory / PoC / no-source GitHub facade (no product git left): **6036**
  - advisory 495 / poc 4390 / no_source 1151
- In window, still no cloneable product OSS git: **56393**
- In window, reviewed, with repo: **11380**

## vs current ledger (24,124 rows, unchanged)

- Ledger class_id = an upstream class: **24003**
- In-window upstream class not in the book: **69036**
  - reviewed+repo: **2680**

## Fill table (missing / hash-fail rows only)

Current ledger is hash-ok on all 24,124 rows; fill sidecar is empty.

Recovered OSS-git clusters: `.ai-slop/state/refresh-20260826/recovered-oss-git-20260826.jsonl`
Summary: `artifacts/no-repo-oss-git-20260826.json`. Ledger not written.
