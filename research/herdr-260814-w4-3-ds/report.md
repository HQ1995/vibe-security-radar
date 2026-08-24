# unr-adj4-slice-3 unreviewed forward-map adjudication (deepseek-v4-pro)

Verdict first: reviewed 25/25. CONFIRM 0, FALSE_POSITIVE 24, UNKNOWN 1. countable_proposal=0. terminal=false. The single UNKNOWN row is a near-miss AI_NEW_SURFACE_CONTRIBUTOR candidate (siyuan bazaar-readme deep-link XSS) whose AI authorship is on a PR squash with a human primary author. The canonical ledger was not edited and greater-than-200 stays HOLD.

## Method

FWD-SPEC forward-map for no-fix-ref unreviewed advisories. First-party (unreviewed) GHSA objects were loaded from the local advisory-database clone. Candidate diffs were read from the sweep pool; missing repos (InvoicePlane, whisper.cpp, azerothcore-wotlk) were fetched via git smart-HTTP. No GitHub API, no git blame/SZZ. FALSE_POSITIVE is used only where the candidate files/subject positively show a fix or non-matching surface; missing evidence is never converted to FAIL.

## Counts

- assigned 25, reviewed 25, unreviewed 0. Conservation 25=25+0.
- CONFIRM 0, FALSE_POSITIVE 24, UNKNOWN 1, countable_proposal 0.
- identity_gate PASS 25 (unreviewed GHSA objects name mechanism + public identity; none withdrawn).
- ai_hunk/topology/but_for FAIL 24 (wrong surface / fix-only); UNKNOWN 1 (siyuan bazaar-readme).
- fix_reversal/release UNKNOWN 25 (unreviewed affected=[] and no structured fix commit).
- uniqueness PASS 25 (absent from foundation.jsonl and canonical84 ledger).

## Per-row

| # | case_id | repo | verdict | mechanism | note |
|---|---|---|---|---|---|
| 0 | GHSA-588V-59VC-3XH9 | portainer/portainer | FALSE_POSITIVE | portainer-docker-proxy-auth-bypass | Candidates are a stacks prune fix (a2fee4fc, Claude Sonnet 4.6) and se |
| 1 | GHSA-G5JQ-GH88-3GMW | wg-easy/wg-easy | FALSE_POSITIVE | wg-easy-postup-command-injection | Candidates rename WG_PORT/WG_CLIENT_PORT init vars (8b5e6c4c/e1928552) |
| 2 | GHSA-JPVH-V7H3-V24C | InvoicePlane/InvoicePlane | FALSE_POSITIVE | invoiceplane-file-upload-rce | 75e6d903 is a Copilot-authored SECURITY FIX (guest/Get.php file-access |
| 3 | GHSA-MFR5-898V-5WMR | InvoicePlane/InvoicePlane | FALSE_POSITIVE | invoiceplane-report-sqli | 75e6d903 is a Copilot-authored SECURITY FIX (guest/Get.php file-access |
| 4 | GHSA-R995-4VFX-PPGF | InvoicePlane/InvoicePlane | FALSE_POSITIVE | invoiceplane-directory-traversal | 75e6d903 is a Copilot-authored SECURITY FIX (guest/Get.php file-access |
| 5 | GHSA-8V3Q-HMMJ-942M | bludit/bludit | FALSE_POSITIVE | bludit-svg-upload-xss | Single candidate ee057f2f (Claude) adds router.php (PHP built-in serve |
| 6 | GHSA-FJJ5-FJ78-H28J | bludit/bludit | FALSE_POSITIVE | bludit-session-fixation | Single candidate ee057f2f (Claude) adds router.php (PHP built-in serve |
| 7 | GHSA-VFMC-78C4-2F7W | bludit/bludit | FALSE_POSITIVE | bludit-api-unrestricted-upload-rce | Single candidate ee057f2f (Claude) adds router.php (PHP built-in serve |
| 8 | GHSA-W5X8-257X-9RV5 | bludit/bludit | FALSE_POSITIVE | bludit-page-creation-xss | Single candidate ee057f2f (Claude) adds router.php (PHP built-in serve |
| 9 | GHSA-JX42-8F9X-G57F | ggml-org/whisper.cpp | FALSE_POSITIVE | whisper-model-load-null-deref | Candidate 6fb7f1af is a SYCL BF16 DMMV GPU-kernel perf change |
| 10 | GHSA-JVGC-4PC6-8X5F | bludit/bludit | FALSE_POSITIVE | bludit-site-logo-svg-xss | Single candidate ee057f2f (Claude) adds router.php (PHP built-in serve |
| 11 | GHSA-FPF6-H6P9-9RJR | jupyterlab/jupyterlab | FALSE_POSITIVE | jupyterlab-plugin-lock-rule-bypass | Candidates are spell-check CI workflows, a file-browser filter, and XS |
| 12 | GHSA-R336-HQVQ-MFJH | jupyterlab/jupyterlab | FALSE_POSITIVE | jupyterlab-allowlist-await-bypass | Candidates are spell-check CI workflows, a file-browser filter, and XS |
| 13 | GHSA-J644-XC9Q-497G | azerothcore/azerothcore-wotlk | FALSE_POSITIVE | azerothcore-zlib-inflate-oob | Candidates are game-content/database fixes and a CMake ARM-detection r |
| 14 | GHSA-3G85-XPC2-P2HQ | HKUDS/nanobot | FALSE_POSITIVE | nanobot-whatsapp-websocket-noauth | Candidates are a configurable web-search provider (71d90de3) and POC-i |
| 15 | GHSA-47JC-H939-7PJ5 | usmannasir/cyberpanel | FALSE_POSITIVE | cyberpanel-filemanager-symlink | Candidates remove simple_install.sh in favor of install.sh (4ec55c64/d |
| 16 | GHSA-5P6M-3744-5C8G | siyuan-note/siyuan | FALSE_POSITIVE | siyuan-svg-sanitization-xss | Candidates are the bazaar-readme deep-link handler (16760a55/24c9c5fd) |
| 17 | GHSA-PWP5-QQ97-MCQC | siyuan-note/siyuan | FALSE_POSITIVE | siyuan-title-img-xss | Candidates are the bazaar-readme deep-link handler (16760a55/24c9c5fd) |
| 18 | GHSA-X52J-M89G-WH64 | siyuan-note/siyuan | UNKNOWN | siyuan-bazaar-readme-xss | Candidates are the bazaar-readme deep-link handler (16760a55/24c9c5fd) |
| 19 | GHSA-2MMH-4RF8-7XG6 | siyuan-note/siyuan | FALSE_POSITIVE | siyuan-backlink-publish-filter | Candidates are the bazaar-readme deep-link handler (16760a55/24c9c5fd) |
| 20 | GHSA-3RFW-7FXW-6JXM | siyuan-note/siyuan | FALSE_POSITIVE | siyuan-getblockinfo-metadata | Candidates are the bazaar-readme deep-link handler (16760a55/24c9c5fd) |
| 21 | GHSA-85XQ-27M5-59M9 | siyuan-note/siyuan | FALSE_POSITIVE | siyuan-heading-transaction-disclosure | Candidates are the bazaar-readme deep-link handler (16760a55/24c9c5fd) |
| 22 | GHSA-G64V-QQPG-V37H | siyuan-note/siyuan | FALSE_POSITIVE | siyuan-publish-auth-bypass | Candidates are the bazaar-readme deep-link handler (16760a55/24c9c5fd) |
| 23 | GHSA-5W4J-HCHP-R332 | siyuan-note/siyuan | FALSE_POSITIVE | siyuan-filetree-search-sqli | Candidates are the bazaar-readme deep-link handler (16760a55/24c9c5fd) |
| 24 | GHSA-P2X7-4C4P-8WH6 | siyuan-note/siyuan | FALSE_POSITIVE | siyuan-searchembedblock-sqli | Candidates are the bazaar-readme deep-link handler (16760a55/24c9c5fd) |

## UNKNOWN row detail

- GHSA-X52J-M89G-WH64 (CVE-2026-66395) siyuan bazaar-readme reflected XSS: candidate 16760a55/24c9c5fd (PR #17938) introduces the siyuan://bazaar readme deep-link handler with copilot-swe-agent/Copilot co-author markers, but is a squash with human primary author Yingyi, so per-hunk AI authorship is unresolved and ai_hunk/topology/but_for/fix_reversal/release stay UNKNOWN. Requires leader replay.

## Per-repo candidate disposition

- **portainer/portainer**: Candidates are a stacks prune fix (a2fee4fc, Claude Sonnet 4.6) and settings/auth UI migrations (SessionLifetimeSelect, oauth auto-provision, auth-method select, azure form). None touches the Docker proxy URL-normalization / authorization middleware (CWE-287).
- **wg-easy/wg-easy**: Candidates rename WG_PORT/WG_CLIENT_PORT init vars (8b5e6c4c/e1928552), add setup-override vars (7fbc1cef), and add a metrics password (fbf24410). None touches the WireGuard client create / PostUp directive path (the OS command injection sink).
- **InvoicePlane/InvoicePlane**: 75e6d903 is a Copilot-authored SECURITY FIX (guest/Get.php file-access traversal) - a remediation, not the origin; 98ccbe4c is version/logging; 9d11e726 removes deprecated docker libs. None introduces file-upload RCE, report SQLi, or traversal.
- **bludit/bludit**: Single candidate ee057f2f (Claude) adds router.php (PHP built-in server) and sibling commits are theme navbar/SEO changes. None touches SVG upload, session handling, API upload, page-creation XSS, or site-logo SVG.
- **ggml-org/whisper.cpp**: Candidate 6fb7f1af is a SYCL BF16 DMMV GPU-kernel perf change. None touches whisper_model_load / ggml.c (null-pointer dereference).
- **jupyterlab/jupyterlab**: Candidates are spell-check CI workflows, a file-browser filter, and XSRF cookie selection. None touches the plugin manager lock rules or PyPIExtensionManager.install().
- **azerothcore/azerothcore-wotlk**: Candidates are game-content/database fixes and a CMake ARM-detection refactor (1b35971f, Copilot co-author). None touches deps/zlib inflate.c.
- **HKUDS/nanobot**: Candidates are a configurable web-search provider (71d90de3) and POC-infrastructure removal (f8711f6a). None touches the WhatsApp bridge WebSocket (0.0.0.0:3001 no-auth).
- **usmannasir/cyberpanel**: Candidates remove simple_install.sh in favor of install.sh (4ec55c64/dc666c44, Cursor co-author). None touches the filemanager controller symlink path.
- **siyuan-note/siyuan**: Candidates are the bazaar-readme deep-link handler (16760a55/24c9c5fd) and SYLink processing (129a9c2a). Only the bazaar-readme handler matches the bazaar-readme XSS advisory; the other named surfaces (SVG sanitization, title-img, publish filters, auth bypass, SQL injection) are not touched by these candidates.

## Evidence paths

- Slice: /home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj4-slice-3.jsonl (sha256 57f8c0cceb2e0a5c0444c606d101461e2053aa8c56bec96fc4635f197bea79ba)
- Contract: /home/hanqing/agents/ai-slop/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md (sha256 cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3)
- FWD spec: /home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/FWD-SPEC.md (sha256 672c45d1f98054a597ce12aa0879daa00b884d9207884e9a10e23c0fdc2d5750)
- Advisories: /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database (advisories/unreviewed/...)
- Repo clones: portainer, wg-easy, InvoicePlane (fetched), bludit, whisper.cpp (fetched), jupyterlab, azerothcore-wotlk (fetched), nanobot, cyberpanel, siyuan-note
- Uniqueness: foundation.jsonl (168) and canonical84/ledger.jsonl (read-only).

## Claim boundary

Worker FALSE_POSITIVE/UNKNOWN is a proposal. Leader replay is required before anything counts. Canonical84 remains the only claim source.
