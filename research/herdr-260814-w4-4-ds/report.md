# Unreviewed forward-map adjudication: unr-adj4-slice-4.jsonl

Verdict-first: **0 countable**. All 25 assigned rows are `FALSE_POSITIVE` (class `no_ai_origin`): no candidate AI commit authors the advisory's named vulnerable hunk. No PASS proposals for leader replay.

## Method
- Read each unreviewed advisory JSON from the local advisory-database clone (`advisories/unreviewed/`, `github_reviewed=false`).
- Read the candidate AI commit diffs from the sweep pool (no GitHub API, no blame/SZZ).
- Compared the advisory's named vulnerable function/file against the candidate commit diffs.
- All 25 rows are siyuan-note/siyuan; the three candidates (Copilot co-authored) are TypeScript frontend changes.

## Result

| ord | case_id | repository | verdict | class | vulnerable surface | AI-commit surface |
|---:|---|---|---|---|---|---|
| 1 | GHSA-PQPF-6VQV-6W92 | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | kernel publish API fullTextSearchAssetContent (SQLi) | app/src URI/bazaar/SYLink (frontend) |
| 2 | GHSA-X7JR-GVVR-P9W7 | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | attribute-view read endpoints (avID validation) | app/src URI/bazaar/SYLink (frontend) |
| 3 | GHSA-2QQV-3JGQ-VPM9 | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | /api/system/getConf unmasked fields | app/src URI/bazaar/SYLink (frontend) |
| 4 | GHSA-CJWM-9H7G-PCR9 | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | getBlockDOMWithEmbed / getBlockDOMsWithEmbed | app/src URI/bazaar/SYLink (frontend) |
| 5 | GHSA-CM9F-W4H4-7J85 | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | server mux static-file routes | app/src URI/bazaar/SYLink (frontend) |
| 6 | GHSA-F68G-4XV8-2G75 | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | /api/tag/getTag | app/src URI/bazaar/SYLink (frontend) |
| 7 | GHSA-FXMW-RV85-5HWH | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | getAttributeViewKeysByID / getBlockDefIDsByRefText / getBlockRelevantIDs | app/src URI/bazaar/SYLink (frontend) |
| 8 | GHSA-HG4J-W33M-P7G4 | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | /api/system/getConf CookieKey | app/src URI/bazaar/SYLink (frontend) |
| 9 | GHSA-HPMW-8PGP-X77J | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | getConf UILayout filter | app/src URI/bazaar/SYLink (frontend) |
| 10 | GHSA-HR3F-QFRH-H7W5 | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | unauthenticated publish endpoints (Argon2id salt / wrapped keys) | app/src URI/bazaar/SYLink (frontend) |
| 11 | GHSA-MG8Q-52J3-W5F8 | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | renderAttributeView (Relation/Rollup cells) | app/src URI/bazaar/SYLink (frontend) |
| 12 | GHSA-MXJF-VFMV-QFM6 | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | /api/notebook/getNotebookInfo | app/src URI/bazaar/SYLink (frontend) |
| 13 | GHSA-RCHC-G58M-88JM | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | getEncryptedNotebookStatus | app/src URI/bazaar/SYLink (frontend) |
| 14 | GHSA-V3V5-7J3J-CC6F | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | getFullHPathByID/getHPathByID/getPathByID/getIDsByHPath/getHPathByPath | app/src URI/bazaar/SYLink (frontend) |
| 15 | GHSA-XF8J-HFM6-VC9V | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | /api/av/getAttributeViewFieldViews (introduced acfc02ee8) | app/src URI/bazaar/SYLink (frontend) |
| 16 | GHSA-XX34-6CJG-PRH8 | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | publish API encrypted-notebook access | app/src URI/bazaar/SYLink (frontend) |
| 17 | GHSA-2JMX-Q9JF-WP3W | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | attribute-view template columns queryBlocks (2nd-order SQLi) | app/src URI/bazaar/SYLink (frontend) |
| 18 | GHSA-72XP-24P9-7VPF | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | resolveAssetPath (absolute path) | app/src URI/bazaar/SYLink (frontend) |
| 19 | GHSA-89HF-XCX5-R9R6 | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | getBlockBreadcrumb/getRefText/getBlockTreeInfos | app/src URI/bazaar/SYLink (frontend) |
| 20 | GHSA-8WX9-J7J5-H9VP | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | kernel CheckAuth loopback admin (fixed-port proxy) | app/src URI/bazaar/SYLink (frontend) |
| 21 | GHSA-H4W7-MGQ4-WG6X | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | getBlockAttrs / batchGetBlockAttrs | app/src URI/bazaar/SYLink (frontend) |
| 22 | GHSA-J26H-R8JX-887C | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | FilterViewByPublishAccess (renderAttributeView) | app/src URI/bazaar/SYLink (frontend) |
| 23 | GHSA-MHCC-G592-267J | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | /api/asset/getFileAnnotation | app/src URI/bazaar/SYLink (frontend) |
| 24 | GHSA-V598-7627-G9FX | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | getGraph / getLocalGraph | app/src URI/bazaar/SYLink (frontend) |
| 25 | GHSA-75XH-MP4F-F2RF | siyuan-note/siyuan | FALSE_POSITIVE | no_ai_origin | /api/av/getAttributeViewSearchTarget (introduced 9b8e8956f) | app/src URI/bazaar/SYLink (frontend) |

## Gate summary
Every row: `identity_gate=PASS` (advisory names repo + mechanism + identity, `github_reviewed=false`), `ai_hunk_gate=FAIL` (candidate diffs read; they do not author the vulnerable hunk), `topology_gate=PASS` (no authorship transfer), `but_for_gate=FAIL` (removing the AI commit does not remove the named mechanism), `fix_reversal_gate=UNKNOWN` and `release_gate=UNKNOWN` (no first-party fix/version evidence closes them locally), `uniqueness_gate=PASS`.

## Evidence
- Advisory DB: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` @ `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`
- siyuan pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/siyuan-note__siyuan`; candidates 16760a559738093913880f49ba7210ac1bb98400, 24c9c5fdc7b4ea25a125bd780fd29ac9d725c004, 129a9c2ac83af691b1989a2b3c57c2dcbc4f2656

Candidate diffs (all read in full):
- `16760a55` / `24c9c5fd` "Open bazaar resource readme via siyuan://bazaar URI (#17938)" - `app/src/config/bazaar.ts`, `app/src/config/index.ts`, `app/src/editor/openLink.ts`, `app/src/util/uri.ts`, `app/src/util/pathName.ts`, `app/src/boot/onGetConfig.ts`, `app/src/layout/dock/agent/AgentMessageRenderer.ts`.
- `129a9c2a` "Enhance SYLink processing for plugin and block handling (#17843)" - `app/src/editor/openLink.ts`, `app/src/util/pathName.ts`, `app/src/protyle/*`, `app/src/types/index.d.ts`.
All three touch only the TypeScript desktop frontend (`app/src/*`). None touches the Go kernel (`kernel/*`) publish API, `CheckAuth`, or publish-access filters (`FilterViewByPublishAccess`, `FilterAttributeViewByPublishAccess`) named by the advisories.
Two advisories name their own introducing commits outside the candidate set: CVE-2026-72791 -> `acfc02ee8`, CVE-2026-73608 -> `9b8e8956f`.
