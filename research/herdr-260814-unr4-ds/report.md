# Direct-root adjudication: unr-dr-slice-4 (unreviewed GHSA rows)

## Verdict

All 27 assigned rows are terminal `FALSE_POSITIVE` proposals; this lane proposes **zero countable cases**.

Every input is a community-unreviewed GHSA object (`database_specific.github_reviewed=false`, `affected=[]`), so the first-party `identity_gate` and the vulnerable/fixed `release_gate` are `UNKNOWN` for all 27 rows. On the decisive question — did the assigned AI ancestor author the vulnerable hunk — no candidate does: 24 are wrong causal edges (CI/docs/metadata, or a different file/function/module), 2 are the final fix itself (`ai_authored_fix_not_root`), and 1 is a human-authored remediation (`non_ai_remediation_not_root`).

Gate order: `identity / AI hunk / topology / but-for / fix reversal / release / uniqueness`. `U` marks UNKNOWN (unreviewed, never converted to FAIL).

## Row-by-row adjudication

| # | GHSA | Class | Gates | Causal comparison |
|---:|---|---|---:|---|
| 1 | `GHSA-P3P9-6PR6-MR9M` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate e786a13e is a CI-only change to .github/workflows/testsuite.yml (adds an ASan job). It never touches the libsyck C sources (syck_.c, handler.c, emitter.c, token.c) that fix 44c90a10 changes. Claude Opus 4.8 co-authored the CI job, not the vulnerable parser. |
| 2 | `GHSA-Q6X2-VFPR-9J7P` | `wrong_edge` | `U/F/P/F/F/U/P` | Same candidate e786a13e; CI-only workflow change. The anchor-key UAF fix 44c90a10 lives in the bundled libsyck C sources, which the candidate does not touch. |
| 3 | `GHSA-3Q78-FQJ5-G3MC` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 436a9078 adds TLS raw-public-key support (tls/.../JcaTlsCrypto.java, JcaTlsRawKeyCertificate.java). Fix 311cabbb changes core/pqc/crypto/lms/HSS/LMS public-key parameters. Only docs/releasenotes.html overlaps. |
| 4 | `GHSA-9MMJ-J2R4-96MP` | `wrong_edge` | `U/F/P/F/F/U/P` | Same candidate (TLS raw-key). Fix 7bbd7fe5 changes prov/.../keystore/bc/BcKeyStoreSpi.java. Candidate never touches the keystore provider. |
| 5 | `GHSA-R7H8-35PV-FWGX` | `wrong_edge` | `U/F/P/F/F/U/P` | Same candidate (TLS raw-key). Fix a43c40dc changes pg/.../UserAttributeSubpacketInputStream.java. Candidate never touches the OpenPGP module. |
| 6 | `GHSA-73JW-FP74-P77X` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 2995349f (2022) simplifies the ws+unix: URL doc and test only; no AI marker (human Luigi Pinca). Fix f197ac65 changes lib/websocket-server.js and lib/websocket.js. |
| 7 | `GHSA-8CP5-FQ7R-3VQ2` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate e1109efc adds prd/code-audit-develop-vs-main.md (a markdown audit note). Fix 84ddc064 changes src/ui/elements/Sidebar/PropertyList.ts. Candidate is docs-only. |
| 8 | `GHSA-4FXP-2M36-QV64` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 1bf43242 adds EmailCreateService and email validation to EmailRequest.php (id/bcc/signature) plus email controllers. Fix 86a7d655 rewrites Permission/PermissionSaveController.php to use a new PermissionSaveRequest. Candidate never touches the permission endpoint. Canonical84 already registers this case as identity NARROW, counted=false. |
| 9 | `GHSA-8WQQ-45FP-2XMP` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 757289bf fixes a different CVE (2026-58102, hv_exts OOB-read) by resizing the OID key buffer. Fix 4c1e2370 adds NULL checks in basicC/ia5string/auth_att/keyid_data. Both touch X509.xs but different functions. |
| 10 | `GHSA-4X4Q-MX3G-G3M2` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate b49e0e2b (Copilot) prevents users updating their own active status (modules/System/Controller/Users.php). Fix 28813596 changes modules/Assets/Utils/Ffmpeg.php and Vips.php. Different modules. |
| 11 | `GHSA-F37P-PC7R-RGHM` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 9028b813 fixes dec_lit_index argument order in cow_hpack.erl (introduced in cb11a4f1). The vulnerable dec_big_int lives in cow_hpack_common.hrl, which the candidate does not touch. Fix f5824304 adds a `when M < 32` guard to dec_big_int. |
| 12 | `GHSA-FCVP-V754-R7RH` | `ai_authored_fix_not_root` | `U/F/P/F/P/U/P` | Candidate f04c9f45 IS the assigned fix_ref f04c9f4 (same commit). Claude Opus 4.6 co-authored the reversal (getWebServerName() comparison), not the vulnerable early-return it removes. |
| 13 | `GHSA-FQ2P-HX59-R7G8` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate f23faaab migrates agent instructions to AGENTS.md (also touches costmodel/inferencecost files for doc relocation). Fix a49a25bc changes pkg/costmodel/router.go (routing/auth). Candidate never touches router.go. |
| 14 | `GHSA-FQJ2-R74G-4GFP` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 040b7b91 resets paginator background colors (apps/client + libs/ui styles). No AI marker (human). Fix 697ef59e changes apps/api/services/fetch. Different layer. |
| 15 | `GHSA-W8J2-252J-WP53` | `wrong_edge` | `U/F/P/F/F/U/P` | Same candidate 040b7b91 (pagination CSS). Fix 697ef59e changes apps/api/services/fetch. Different layer. |
| 16 | `GHSA-P3JW-Q4JG-X8W9` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate db980c12 adds getMyClosedTicketsForDate (new @api method, ~line 2382). Fix 68898eeb modifies getMilestone (~line 2835) to add projectIdParam + isUserAssignedToProject. Different methods in the same file. |
| 17 | `GHSA-HR36-79F7-75X7` | `ai_authored_fix_not_root` | `U/F/P/F/P/U/P` | Candidate 0778b93 IS the assigned fix_ref (same commit). Claude Opus 4.7 co-authored the bounds-check reversal, not the vulnerable parser it patches. |
| 18 | `GHSA-M894-WGPG-HWPV` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate ac547bbf (oauth integration) changes session.ts to add oauth session fields and a timing-safe password check. The weak CRC32 token lives in oneTimeLink/service.ts generate(), which the candidate does not touch. Fix 66b292b changes oneTimeLink/service.ts + route + session.ts (DISABLE_PASSWORD_AUTH). |
| 19 | `GHSA-P9XJ-3649-7QP8` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 8a7b7128 is a behavior-preserving HPACK split (adds HeaderIndexingStrategy forward decl). Fix f28742f2 adds SlowConsumerTimer + setSlowConsumerParams in HTTPSessionBase.h. Different machinery. |
| 20 | `GHSA-QC6R-WRM6-23PM` | `non_ai_remediation_not_root` | `U/F/P/F/P/U/P` | Candidate e0a9ef96 ("Merge commit from fork", human Stanislas Kita, no AI marker) ADDS htmlentities($name, ENT_QUOTES) escaping. Fix 49e6b6eb refines to htmlentities((string)$name). The candidate is a human remediation, not the vulnerable unescaped origin. |
| 21 | `GHSA-QHPW-W7P5-4C7M` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 585ea341 is a dependabot CI-workflow bump (9 actions). Fix 6c8a7dbc changes internal/http/handlers/api/v1/auth.go. Candidate never touches auth handler. |
| 22 | `GHSA-V376-5PPG-XP5V` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 6cdb13d5 adds pgvector hnsw/halfvec config (PGVECTOR_USE_HALFVEC, PGVECTOR_INDEX_METHOD). Fix 02238d31 adds DEFAULT_WEB_FETCH_FILTER_LIST + retrieval/web changes. Different config sections and subsystems. |
| 23 | `GHSA-6QM2-MCQ7-53QP` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 671f8edd fixes surrogate utf8 output in UTF8JsonGenerator. Fix b0c428e6 changes NonBlockingUtf8JsonParserBase.java. Different classes. |
| 24 | `GHSA-J6JV-J266-988H` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 971f51f5 adds a manual hunt-stats refresh button (Recalculate field in HuntMutation). Fix d7de958e changes the ModifyHunt permission switch (COLLECT_CLIENT vs START_HUNT/DELETE_RESULTS). Different regions of api/hunts.go. |
| 25 | `GHSA-JM4C-88WP-RFJQ` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 87b9ec3b adds security notes to docs/references/server.config.yaml. Fix dc38bd6a changes acl_manager and api-service JSX. Candidate is docs-only. |
| 26 | `GHSA-QPGW-RGMQ-2367` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate 4899529e changes open_max (MAXFILESPERPROC sysctl) in main(). Fix 2467fe0a changes run_utility() strlcpy->memcpy with bounds. Different functions in entr.c. |
| 27 | `GHSA-W92G-J683-FHVQ` | `wrong_edge` | `U/F/P/F/F/U/P` | Candidate dcd21c17 adds MiniMax Hermes provider presets (package.json + Hermes components). Fix 68fd6d7b changes AI/Chat/Main/index.vue and NodeFn.ts v-html sanitization. Different components. |

## Evidence and controls

- Advisory blobs were read from the local advisory-database clone at ref `e6f87ed4d230d03c7f5b820f2961898b1590d1aa` under `advisories/unreviewed/...`; none of the 27 objects carries a structured `repository`/`vulnerabilities` field or an `affected` range.
- Candidate/fix messages, paths, and ancestry came from the blobless pools `/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>`. `git merge-base --is-ancestor` confirms every candidate is an ancestor of its assigned fix, except MeshCentral `f04c9f45` and OpenHTJ2K `0778b93`, which are the fix commit itself.
- Exact hunks were diffed for the 12 source-overlapping rows (EmailRequest.php, X509.xs, cow_hpack.erl, Tickets.php, session.ts, HTTPSessionBase.h, tag.class.php, config.py, hunts.go, entr.c). Missing blobs were fetched via git smart-HTTP; no GitHub API was used.
- Canonical84 ledger observed SHA-256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`. GHSA-4FXP-2M36-QV64 is already registered there as identity NARROW / counted=false; no other row collides.
- 13 candidates carry no explicit generative-AI marker (human or bot co-authors); they are flagged as over-included by the ancestry scan and are additionally wrong_edge.
- No `AI_INCOMPLETE_REMEDIATION` issued; no `original_vulnerability` block applies.

