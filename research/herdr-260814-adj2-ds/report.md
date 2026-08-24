# herdr-260814-adj2-ds - unreviewed-adjudication slice-2

**Verdict-first: 25/25 FALSE_POSITIVE (WRONG_EDGE_DISJOINT_FILES). 0 countable, 0 PASS proposals.**

No candidate AI commit introduces the named advisory mechanism. Every candidate
touches files disjoint from the advisory's mechanism file, or (where the diff was
read) demonstrably does not author the vulnerable hunk. Packet delta = 0; the
canonical count is unchanged and publication stays HOLD.

## Method

- Advisory descriptions read from the local advisory-database clone (stream
  advisories/unreviewed/, stream origin/main head e6f87ed4d230d03c7f5b820f2961898b1590d1aa).
- Candidate diffs read from local clones in /home/hanqing/.cache/cve-analyzer/repos/
  and .ai-slop/cache/cve-analyzer/repos/; two partial-clone blobs (check-peer-dependencies,
  DumbAssets) were fetched via git smart-HTTP on escalation. No GitHub API, no blame/SZZ.
- Disjoint-file rows are marked changed_files evidence; overlapping-file rows are
  diff_read evidence.

## Gates

identity=NARROW (unreviewed GHSA, not a github-reviewed first-party identity),
ai_hunk=FAIL, topology=NARROW, but_for=FAIL, fix_reversal=UNKNOWN (no fix ref),
release=UNKNOWN, uniqueness=PASS (none of the 25 ids/aliases are in foundation.jsonl).

## Per-row

| # | GHSA | CVE | repo | mechanism file | candidate | evidence | verdict |
|---|---|---|---|---|---|---|---|
| 1 | GHSA-9F49-2J27-6F79 | CVE-2026-1200 | rgaufman/live555 | liveMedia/MediaSink.cpp / MediaSink.hh | f4a4e8fb05 | diff_read | FALSE_POSITIVE |
| 2 | GHSA-VC6W-J78G-3GCH | CVE-2026-3407 | YosysHQ/yosys | kernel/rtlil.h / BLIF parser | 6ac8c8cb05 | diff_read | FALSE_POSITIVE |
| 3 | GHSA-RFP8-6VGG-V2XV | CVE-2026-32296 | sipeed/NanoKVM | web Wi-Fi config route | 140812606f | diff_read | FALSE_POSITIVE |
| 4 | GHSA-F2G2-3GV9-7Q7G | CVE-2026-7084 | HBAI-Ltd/Toonflow-app | src/routes/setting/vendorConfig/getCodeByLink.ts | 8dbcaadfaf | changed_files | FALSE_POSITIVE |
| 5 | GHSA-J94J-6GP3-2XMH | CVE-2026-7086 | HBAI-Ltd/Toonflow-app | src/routes/.../replaceUrl.ts | 8dbcaadfaf | changed_files | FALSE_POSITIVE |
| 6 | GHSA-X2WM-3JVX-7WWX | CVE-2026-7085 | HBAI-Ltd/Toonflow-app | src/routes/setting/about/downloadApp.ts | 8dbcaadfaf | changed_files | FALSE_POSITIVE |
| 7 | GHSA-4G75-R3GH-96XH | CVE-2026-7714 | crocodilestick/Calibre-Web-Automated | cps/cwa_functions.py | 0c39a10e8b | changed_files | FALSE_POSITIVE |
| 8 | GHSA-5V4V-3G9Q-MH5J | CVE-2026-45248 | hashgraph/guardian | demo registered-users route | 657cd2bfbd | changed_files | FALSE_POSITIVE |
| 9 | GHSA-CQG8-V99M-GV9M | CVE-2021-47942 | hacs/integration | hacsfiles endpoint | fd7889a8fa | changed_files | FALSE_POSITIVE |
| 10 | GHSA-7X5Q-37JC-HQ6P | CVE-2026-45230 | DumbWareio/DumbAssets | server.js /api/delete-file | c410a5d280 | diff_read | FALSE_POSITIVE |
| 11 | GHSA-9CCF-75HJ-3V32 | CVE-2026-45231 | DumbWareio/DumbAssets | asset render (innerHTML) | c410a5d280 | diff_read | FALSE_POSITIVE |
| 12 | GHSA-7PJJ-942Q-WRWG | CVE-2026-26379 | Koha-Community/Koha | Z39.50 module | 713c5c3343 | diff_read | FALSE_POSITIVE |
| 13 | GHSA-J9M8-FW2W-FRCQ | CVE-2026-26378 | Koha-Community/Koha | Invoice file upload | 713c5c3343 | diff_read | FALSE_POSITIVE |
| 14 | GHSA-XCX6-J7V3-9H57 | CVE-2026-25558 | Qloapps/QloApps | admin file manager | 8179b4457a | diff_read | FALSE_POSITIVE |
| 15 | GHSA-C4G4-FG7Q-8P3C | CVE-2026-57954 | yahoo/elide | SortingImpl | 759bd0e1c3 | changed_files | FALSE_POSITIVE |
| 16 | GHSA-FMMH-7QJR-FP9G | CVE-2026-15033 | christopherthielen/check-peer-dependencies | src/packageUtils.ts resolvePackageDir | 0a250ec635 | diff_read | FALSE_POSITIVE |
| 17 | GHSA-25JF-QR89-V245 | CVE-2026-62185 | argoproj/argo-helm | network policy templates | ac92cdc8bb | changed_files | FALSE_POSITIVE |
| 18 | GHSA-5293-6WQF-75GR | CVE-2026-15619 | mosaxiv/clawlet | tools/tool_web_fetch.go | 63eb386558 | changed_files | FALSE_POSITIVE |
| 19 | GHSA-9FWC-2X22-7M65 | CVE-2026-15618 | mosaxiv/clawlet | tools/tool_exec.go | 63eb386558 | changed_files | FALSE_POSITIVE |
| 20 | GHSA-9HG3-M3P7-MJM6 | CVE-2026-15621 | mosaxiv/clawlet | tools/fs_ops.go | 63eb386558 | changed_files | FALSE_POSITIVE |
| 21 | GHSA-Q2GC-2P96-WXG9 | CVE-2026-15620 | mosaxiv/clawlet | tools/tool_web_fetch.go | 63eb386558 | changed_files | FALSE_POSITIVE |
| 22 | GHSA-8G6F-QW9X-4Q6Q | CVE-2026-15736 | snowflakedb/snowflake-sqlalchemy | merge/compile/render paths | c7eff30f97 | changed_files | FALSE_POSITIVE |
| 23 | GHSA-FGWG-8QWR-QVW3 | CVE-2026-63085 | axelor/axelor-open-platform | save/persistence layer | 329a17c792 | changed_files | FALSE_POSITIVE |
| 24 | GHSA-XP4X-W877-82XM | CVE-2026-16017 | mosaxiv/clawlet | tools/tool_cron.go | 63eb386558 | changed_files | FALSE_POSITIVE |
| 25 | GHSA-37V5-GPCX-W9FC | CVE-2026-64623 | Jovancoding/Network-AI | APSAdapter | 27b549f4d3 | changed_files | FALSE_POSITIVE |

## Detail (diff-read rows)

- live555 f4a4e8fb: MediaSink.cpp diff is only a copyright-year bump (1996-2024 -> 1996-2025).
  grep increaseBufferTo over the full commit diff = 0 hits. Mechanism untouched.
- yosys 6ac8c8cb: adds SystemVerilog array-to-array assignment in frontends/ast/simplify.cc.
  Disjoint from kernel/rtlil.h Const::set / BLIF parser.
- NanoKVM 14081260: Chrome clipboard paste.tsx + en.ts. Disjoint from Wi-Fi config endpoint.
- DumbAssets c410a5d2 (2 rows): adds parseCSV() + refactors /api/import-assets only.
  No /api/delete-file change, no innerHTML/asset-field render change.
- Koha 713c5c33 (2 rows): DBIC +count relationship aliases. Disjoint from Z39.50 module and
  Invoice upload.
- QloApps 8179b445: AdminOrdersController.php only. Disjoint from admin file manager.
- check-peer-dependencies 0a250ec6: adds a path fallback in resolvePackageDir
  (node_modules/packageName endsWith). No shelljs.exec touch -> no command injection introduced.

## Conclusion

This packet admits no countable case. All 25 rows close at ai_hunk/but_for FAIL
(wrong edge). Identity stays NARROW on unreviewed advisories; fix_reversal/release
stay UNKNOWN (no first-party fix ref). Canonical ledger untouched; publication HOLD.

