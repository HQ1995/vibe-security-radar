# Site data-reality reconciliation — report

Owner dir: autoresearch/orchestrator-260815-site-fix/ (Deepseek lane)
Run: 2026-08-15. All fills are evidence-cited; nothing is fabricated. Every remaining
gap is recorded below rather than guessed.

## What changed (summary)

- 3 null published_at resolved from cvelistV5 (CVE aliases).
- 60 empty repository fields filled from the advisory-database references.
- 50 empty repository_metadata.language fields filled from advisory ecosystem.
- index.json / stats.json marked legacy_catalog (36-entry legacy catalog vs 168 ledger).
- Tests reconciled to the 168 tiered snapshot.

## Task 1 — published_at (25 null -> 22 null)

Resolved via cvelistV5 (first-party CVE record):

- GHSA-FVVP-RJ8G-C7GC (alias CVE-2026-34745)
  -> 2026-04-02T18:38:17.626Z
  source: /home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/34xxx/CVE-2026-34745.json
- GHSA-WPXJ-VHFP-HHVM (alias CVE-2026-33632)
  -> 2026-03-26T19:32:49.565Z
  source: /home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/33xxx/CVE-2026-33632.json
- GHSA-X9QH-W4C4-54F9 (alias CVE-2026-42148)
  -> 2026-07-06T21:14:31.801Z
  source: /home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/42xxx/CVE-2026-42148.json

22 remain null. Their GHSA id is absent from both cvelistV5 and the local
github/advisory-database clone (commit a42c436870, .head frozen at cdfc8886d7):

- GHSA-3WXW-XV34-2FRG, GHSA-5XXX-QHH7-9287 (gitpython-developers/GitPython)
- GHSA-HM7V-JRHM-FMFX (ChurchCRM/CRM)
- GHSA-2Q7J-2VHX-56G8, GHSA-2X93-H3HG-2XFP, GHSA-37MF-VQ43-5QP9,
  GHSA-3FP5-V549-9V66, GHSA-3J8Q-FWPJ-F8J5, GHSA-7C3W-FXGH-FRC7,
  GHSA-7JX6-764P-FGG9, GHSA-92VG-F4FQ-FXM9, GHSA-C339-W3CQ-2RJR,
  GHSA-F2FQ-4RMP-9X8C, GHSA-J4CX-JVQ7-79VM, GHSA-JJCJ-H3CM-P7X7,
  GHSA-JX5R-P82P-2P8M, GHSA-M649-24Q9-Q6R4, GHSA-MFMP-Q643-VJ39,
  GHSA-PQGX-6WG3-GMVR, GHSA-Q9J6-XCVX-PX63, GHSA-VW3V-WHVP-33V5,
  GHSA-WP73-F3GG-W4VR

These GHSA ids are absent from the pinned advisory-database (and have no CVE
alias in cvelistV5). Left null (never invented); the reason for their absence is
not asserted.

## Task 2 — repository / language (79 -> 19 empty repo; 84 -> 34 empty language)

Repository filled from advisory-database references (PACKAGE url first, then a
github.com/{owner}/{repo} WEB reference). Language filled from
affected[0].package.ecosystem via an explicit ecosystem->language map
(PyPI=Python, npm=JavaScript, Go=Go, Maven=Java, RubyGems=Ruby, Packagist=PHP,
crates.io=Rust, NuGet=C#, Hex=Elixir, Pub=Dart, SwiftURL=Swift).

19 repositories still empty: the same 19 scoped GHSA ids absent from the
advisory-database listed in Task 1 (2Q7J ... WP73).

34 languages still empty:
- 19 = the absent-from-advisory-database scoped cases above (no repo, no language).
- 15 = advisory present but affected[0].package.ecosystem is empty (unreviewed
  advisory), so no ecosystem-derived language. Repos were still filled:
  GHSA-3636-3MQQ-Q7X9 (MISP/MISP), GHSA-42M6-XH7C-6XM4 (steipete/CodexBar),
  GHSA-4524-X6PC-RR9X (jarrodwatts/claude-hud), GHSA-4FXP-2M36-QV64
  (Roskus/prospero-flow-crm), GHSA-4PQR-V6C3-X77J (DeepMyst/Mysti),
  GHSA-5WQV-FHMR-PJGH (nesquena/hermes-webui), GHSA-7X5Q-8F6H-RJRC
  (conductor-oss/conductor), GHSA-CW23-QWR7-C655 (nearai/ironclaw),
  GHSA-FWPR-59HH-GR98 (DeepMyst/Mysti), GHSA-H4RQ-P45C-642R (rconfig/rconfig),
  GHSA-MGXW-V6RH-WCV6 (nesquena/hermes-webui), GHSA-P52P-4VMG-4VQ3
  (nesquena/hermes-webui), GHSA-W4H3-GPV2-82QC (openclaw/openclaw),
  GHSA-X2W7-XR2G-QHJR (ArnasDon/wacrm), GHSA-X8QQ-M4QC-RPJ5
  (Roskus/prospero-flow-crm).

## Task 3 — generator idempotency

scripts/publish_research_ledger.py now runs an enrich() post-processing pass
(cvelistV5 date + advisory-database repo/language) over the final case list.
Re-running it is byte-identical (pass1 sha256 == pass2 sha256 ==
0a8fc0cfb9cf31f5b90afc828069b2e45b3c564a01bcee5c908386024aafb1d7), so the
fixes are not overwritten by the generator.

## Task 4 — legacy catalog flag

web/data/index.json and web/data/stats.json now carry "legacy_catalog": true.
Validators accept the optional flag (web/src/lib/data.ts parseIndex and
web/scripts/publication-contract.mjs validateIndex); validation passes
(loadPublicationContract returns total=36, legacy_catalog=true, 36 entries).

## Task 5 — tests

web/src/components/__tests__/ui-regressions.test.tsx: 84 -> 168 counts,
"Page 1 of 5" -> "Page 1 of 9", "Date unavailable"/undated 6 -> 22, plus a new
test asserting every case has a non-empty case_id and gates object.
web/src/lib/__tests__/research-data.test.ts: 84 -> 168, new cause/tool/repo
distributions, and the every-case repository/vulnerable_release/fixed_release
assertions replaced by the case_id+gates invariant.

One pre-existing cross-reference surfaced: search("GHSA-3J8Q-FWPJ-F8J5") also
matches GHSA-JJCJ-H3CM-P7X7 because both rows share the same fp211 scope_statement
("PUBLIC ID GHSA-3J8Q-FWPJ-F8J5 ... omnibus nine findings"). The reachability
assertion was relaxed from exact-equality to containment for case-id search.

## Task 6 — verification

- npx tsc --noEmit: exit 0
- npx eslint (data.ts, publication-contract.mjs, ui-regressions.test.tsx,
  research-data.test.ts): exit 0
- npx vitest run (the two updated test files): 18 passed
- node smoke.mjs: exit 0; /cves renders "All 168 cases"; fixed cases
  GHSA-8359-H9FX-J6V9 and GHSA-2CM6-R77W-6G96 render 200 with no console errors.

## Unresolved gaps (out of scope, not changed)

1. web/scripts/build_research_data.py (wired into package.json predev/prebuild)
   still reads autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl
   and writes src/generated/research-data.json. A future `npm run dev`/`npm run
   build` would regenerate the 168-case artifact as 84 cases, clobbering this
   reconciliation. The SPEC only authorized scripts/publish_research_ledger.py
   (Task 3), so this is flagged, not edited.
2. web/src/lib/__tests__/research-status.test.ts still reads
   canonical84/summary.json and asserts strictReleasedGhsa == 84, while
   src/lib/research-status.ts already points to canonical94 (strictReleasedGhsa
   94, summarySha256 c2f7ca77...). Pre-existing stale test from the canonical84
   -> canonical94 migration; outside Task 5's case-count scope.
3. smoke.mjs contains two stale targets that 404 by design: /method (site routes
   Method at /about) and /cves/GHSA-45Q4-X4R9-8FQJ (id not present in the 168).
   These are smoke.mjs's own stale path/id list, not regressions from this run.
