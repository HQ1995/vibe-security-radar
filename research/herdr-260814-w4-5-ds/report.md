# unr-adj4-slice-5 adjudication — verdict-first evidence summary

## Verdict

Proposed admissions: **0 / 25** (`CONFIRM`/`AI_DIRECT_ROOT`/`AI_NEW_SURFACE_CONTRIBUTOR` = 0).
Every row is **FALSE_POSITIVE (class `no_ai_origin`)**: each candidate AI commit's diff authors an unrelated hunk and does not create the advisory's named mechanism.

- 25/25 unreviewed advisory objects are `github_reviewed=false` with `affected=[]`; the `details` field names the mechanism and the references name the repository, but there is no first-party reviewed identity, so `identity_gate` = UNKNOWN (never PASS).
- 18 unique candidate commits fetched by git smart-HTTP into `/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>`; parent→child diffs read. All 18 carry an explicit AI marker (Claude/Copilot/Cursor/Copilot-Autofix co-author trailer or `Generated with Claude Code`).
- 18/18 diffs touch files disjoint from the vulnerable file named in each advisory, so `ai_hunk_gate` and `but_for_gate` are FAIL (affirmative non-authorship, not missing evidence).
- `topology_gate`, `fix_reversal_gate`, `release_gate`, `uniqueness_gate` stay UNKNOWN after causal exclusion.

## Frozen evidence and method

- Contract: `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md`, SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
- Spec: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/FWD-SPEC.md`, SHA-256 `672c45d1f98054a597ce12aa0879daa00b884d9207884e9a10e23c0fdc2d5750`.
- Slice: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj4-slice-5.jsonl`, SHA-256 `7eef33eb9056a8eadbcbab82a671cf575616ecac1574418ffd07ce748a3a90ab` (25 rows).
- Advisory database: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database` at `origin/main` = `8b901fa43d0e3d09e9bece095afb760dd9dff6e8` (2026-08-15 `Publish Advisories`); every advisory blob read from that exact tree.
- Commit pool: `git --filter=blob:none` blobless bare clones; new repos (rsync, teable) initialized and fetched with `--deepen=80` via git smart-HTTP. No GitHub API, no `git blame`, no SZZ.

## Row-by-row finding

| GHSA | CVE | Repository | Named mechanism | Verdict |
|---|---|---|---|---|
| GHSA-7V6H-J59W-8QFP | CVE-2026-73609 | siyuan-note/siyuan | getBookmarkLabels returns all bookmark labels without publish-access filtering | FALSE_POSITIVE (no_ai_origin) |
| GHSA-8J5P-6PF5-6PQC | CVE-2026-73610 | siyuan-note/siyuan | Local storage filter returns admin storage map with only three keys sanitized | FALSE_POSITIVE (no_ai_origin) |
| GHSA-GQ43-VCRH-6JW8 | CVE-2026-73606 | siyuan-note/siyuan | /api/block/getRefIDs fails to check password-protected document tiers | FALSE_POSITIVE (no_ai_origin) |
| GHSA-V372-PHQ5-6MX6 | CVE-2026-73607 | siyuan-note/siyuan | /api/storage/getOutlineStorage performs no authorization checks | FALSE_POSITIVE (no_ai_origin) |
| GHSA-XXM9-W59Q-M66X | CVE-2026-73605 | siyuan-note/siyuan | getUniqueFilename path traversal lets anonymous readers probe filesystem | FALSE_POSITIVE (no_ai_origin) |
| GHSA-3X24-FVRH-W27X | CVE-2026-67613 | usmannasir/cyberpanel | cloudAPI ReadReport path traversal reads arbitrary server files | FALSE_POSITIVE (no_ai_origin) |
| GHSA-JR78-52G9-XCM6 | CVE-2026-67614 | usmannasir/cyberpanel | WebTerminal FastAPI SSH hard-coded JWT secret allows forged tokens/root shell | FALSE_POSITIVE (no_ai_origin) |
| GHSA-P8CP-78HP-WMQ8 | CVE-2026-72811 | siyuan-note/siyuan | SQL injection in backlink/mention search query (kernel/model/backlink.go) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-Q6G5-M978-C6V9 | CVE-2026-72810 | siyuan-note/siyuan | WebSocket broadcast publish-boundary bypass leaks unfiltered edits | FALSE_POSITIVE (no_ai_origin) |
| GHSA-WW86-C2QF-W8FW | CVE-2026-72812 | siyuan-note/siyuan | /api/ref/refreshBacklink missing authorization triggers server-side writes | FALSE_POSITIVE (no_ai_origin) |
| GHSA-6XVP-3RFV-G2G2 | CVE-2026-73049 | siyuan-note/siyuan | getAttributeViewBacklinks consults forbidden list instead of visibility list | FALSE_POSITIVE (no_ai_origin) |
| GHSA-P6G3-J3G7-H96W | CVE-2026-73048 | siyuan-note/siyuan | getRefIDsByFileAnnotationID returns block IDs without publish-access filtering | FALSE_POSITIVE (no_ai_origin) |
| GHSA-VG9Q-FC8F-43F3 | CVE-2026-73630 | siyuan-note/siyuan | /api/filetree/authFilePublishAccess reachable anonymously, never sets failure code | FALSE_POSITIVE (no_ai_origin) |
| GHSA-M34R-4V3R-PP9V | CVE-2026-41035 | RsyncProject/rsync | receive_xattr untrusted length in qsort causes receiver use-after-free (-X) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-6MMC-C65C-3CJP | CVE-2026-9566 | Teableio/Teable | LoginPage.tsx Sign-up redirect argument open redirect | FALSE_POSITIVE (no_ai_origin) |
| GHSA-325V-M87X-26CP | CVE-2026-56773 | teableio/teable | v2 REST API ORPC endpoints lack @Permissions metadata (auth bypass) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-49FM-7W64-4WQC | CVE-2026-56781 | teableio/teable | Share-view records projection leaks hidden field data to anonymous users | FALSE_POSITIVE (no_ai_origin) |
| GHSA-39J5-W47M-2GMV | CVE-2026-67317 | axios/axios | maxBodyLength not enforced for WHATWG ReadableStream (fetch adapter) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-4WW2-RJH2-XPV9 | CVE-2026-67312 | axios/axios | Uncontrolled recursion in formDataToJSON | FALSE_POSITIVE (no_ai_origin) |
| GHSA-6HQM-HM2V-3P2P | CVE-2026-67315 | axios/axios | 0.0.0.0 not recognized as loopback in shouldBypassProxy.js (NO_PROXY bypass) | FALSE_POSITIVE (no_ai_origin) |
| GHSA-F2R5-PQH9-R8F8 | CVE-2026-67316 | axios/axios | Read-side prototype-pollution gadgets alter request construction | FALSE_POSITIVE (no_ai_origin) |
| GHSA-FQ2J-3J99-RX65 | CVE-2026-67313 | axios/axios | formDataToJSON recursion on deeply nested bracket field names | FALSE_POSITIVE (no_ai_origin) |
| GHSA-FQJ3-H9PC-443H | CVE-2026-67318 | axios/axios | maxBodyLength not enforced on streamed bodies with httpVersion 2 | FALSE_POSITIVE (no_ai_origin) |
| GHSA-3MCP-22MF-VRW3 | CVE-2026-67321 | axios/axios | toFormData.js depth-limit bypass on keys ending in {} | FALSE_POSITIVE (no_ai_origin) |
| GHSA-9WX3-P993-35VP | CVE-2026-67319 | axios/axios | Inherited properties consumed from nested request option objects | FALSE_POSITIVE (no_ai_origin) |

## Why each candidate set is not the origin

- **siyuan-note/siyuan (11 rows)** — candidates are TypeScript-frontend edits (bazaar `siyuan://` readme URI handling, SYLink/openLink processing, `onGetConfig`). The advisories live in the Go kernel backend (`kernel/model/backlink.go` SQL injection, `/api/*` endpoints, WebSocket sessions, filetree auth); none is touched.
- **usmannasir/cyberpanel (2 rows)** — candidates delete `simple_install.sh` and edit TODO docs. The advisories target `cloudAPI ReadReport` (path traversal) and the `WebTerminal` FastAPI JWT secret; neither installer path is touched.
- **RsyncProject/rsync (1 row, CVE-2026-41035)** — `receive_xattr` untrusted-length qsort use-after-free. The candidates are a *sender*-side TOCTOU fix (`sender.c`, a different CVE-2026-29518), an AVX2 checksum fix, and a CI-workflow edit; `receive_xattr`/xattr receive path is untouched.
- **Teableio/teable (3 rows)** — candidates are v2 backend/devtools changes (MetaChecker, tsconfig aliases, FieldDependencyGraph, devtools CLI, a type-only import). The advisories target `LoginPage.tsx` (open redirect), ORPC `@Permissions`, and share-view projection; none is touched.
- **axios/axios (8 rows)** — candidates are a cross-origin auth-header redirect fix (`lib/adapters/http.js`), a `THREATMODEL.md` docs edit, and a `shouldBypassProxy` *test* expansion. The advisories target `maxBodyLength` (fetch/http2), `formDataToJSON`/`toFormData` recursion, `0.0.0.0` loopback in `shouldBypassProxy.js` (source, not the test file), and prototype pollution; none is introduced by these hunks.

## Gate matrix

| Gate | PASS | FAIL | UNKNOWN |
|---|---|---|---|
| identity_gate | 0 | 0 | 25 |
| ai_hunk_gate | 0 | 25 | 0 |
| topology_gate | 0 | 0 | 25 |
| but_for_gate | 0 | 25 | 0 |
| fix_reversal_gate | 0 | 0 | 25 |
| release_gate | 0 | 0 | 25 |
| uniqueness_gate | 0 | 0 | 25 |

## Claim boundary

Negative diff reading proves no AI origin for these 25 rows; it is not evidence of global semantic uniqueness. No `PASS` is proposed, so the leader has nothing to replay beyond confirming the no_ai_origin exclusions.
