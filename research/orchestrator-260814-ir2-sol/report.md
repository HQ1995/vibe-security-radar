# Residual-remediation adjudication

## Verdict

All 10 assigned rows are terminal `FALSE_POSITIVE` proposals with class `wrong_edge`; this lane proposes zero `AI_INCOMPLETE_REMEDIATION` cases and zero countable cases. In every row, the selected AI-marked ancestor is topologically real but does not author or materially rewrite the security boundary amended by the advisory's final fix.

The matrix uses gate order `identity / AI hunk / topology / but-for / fix reversal / release / uniqueness`. `fix reversal` is `PASS` because each supplied `final_fix` closes the advisory's exact invariant; that does not rescue an unrelated prior edge, whose `AI hunk` and `but-for` gates fail. `release` is `PASS` only when a tagged vulnerable artifact contains the selected prior commit without the final closure.

## Gate matrix

| # | GHSA | Gates | Verdict and causal comparison |
|---:|---|---|---|
| 1 | `GHSA-RXRV-835Q-V5MH` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` | `FALSE_POSITIVE (wrong_edge)`. AI-marked `e26010c` is a two-line documentation update. Human `f2868ae` authored the earlier `includes()` guard, and `042af9c` replaces that guard with a regular-expression check. |
| 2 | `GHSA-RP36-8XQ3-R6C4` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` | `FALSE_POSITIVE (wrong_edge)`. AI-marked `093494c` fixes an async-generator exception-capture bug for a different advisory in `setup-sandbox.js`; `a1ed47a` closes missing `process` and `inspector/promises` denylist entries in `builtin.js`. |
| 3 | `GHSA-42H5-H8QH-VV9V` | `PASS / FAIL / PASS / FAIL / PASS / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. Copilot `1824478` fixes `RestException` handling; `6e801f4` validates model-version prompt sources in the server handler. The first release containing the prior also contains the closure. |
| 4 | `GHSA-G867-7843-WF8Q` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` | `FALSE_POSITIVE (wrong_edge)`. Claude-marked `4d8ebce` repairs stale object-stream caching; `5a33a46` terminates malformed ASCII85/ASCIIHex inline-image loops. |
| 5 | `GHSA-P3PQ-HXMR-VQQR` | `PASS / FAIL / PASS / FAIL / PASS / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. Claude-marked `3458636` propagates `_UnpicklingFuture` errors; its direct child `7c70ac5` adds connection-time DNS validation and pinning for webhook SSRF. No release separates them. |
| 6 | `GHSA-29PJ-957V-52MC` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` | `FALSE_POSITIVE (wrong_edge)`. Claude-marked `51b529f` fixes tab accounting in fenced-code parsing; `493a5aa` normalizes control bytes before the unsafe-protocol check. |
| 7 | `GHSA-MXHJ-88FX-4PCV` | `PASS / FAIL / PASS / FAIL / PASS / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. Claude-marked `a22a9a9` prevents recursive traversal of cyclic AST structures; `ff423da` persists `OBJ`, `NEWOBJ`, and `NEWOBJ_EX` calls so safety analysis cannot lose them. The first release containing the prior also contains the closure. |
| 8 | `GHSA-VVXF-WJ5W-6GJ5` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` | `FALSE_POSITIVE (wrong_edge)`. Copilot `de4cbe0` turns a UI sign-in button into a login link; `6c909e5` adds DNS/IP validation and disables webhook redirects to close SSRF bypasses. |
| 9 | `GHSA-5MWJ-V5JW-5C97` | `PASS / FAIL / PASS / FAIL / PASS / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. Claude-marked `5b03f00` implements progressive agent-document loading; `3327b29` removes the forgeable XOR auth header and API-key truthiness fallback. The first release containing the prior also contains the closure. |
| 10 | `GHSA-XJ37-QJG2-XWV2` | `PASS / FAIL / PASS / FAIL / PASS / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. Copilot `dc0b3f2` adds base-path URL rewriting; `6bec52d` adds `/open/user/init` siblings to the pre-existing initialization guard. The rewrite neither authored nor attempted to repair that guard. |

## Per-case evidence

### 1. Locutus prototype-pollution residual

- First-party advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/02/GHSA-rxrv-835q-v5mh/GHSA-rxrv-835q-v5mh.json` (`CVE-2026-25521`). Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/locutusjs__locutus`.
- `e26010c52ce6c05b4628ac9db4ba38b822fdbe57` has the Claude Opus 4.5 trailer but changes only `docs/prompts/LOG.md`; it is 24 commits before the closure and never touches `src/php/strings/parse_str.js`.
- The actual earlier forbidden-key guard is human-authored `f2868ae0`; final `042af9ca7fde2ff599120783e720a17f335bb01c` changes `parse_str.js` from `key.includes(...)` to `/__proto__|constructor|prototype/.test(key)` and adds the matching regression test.
- Release containment is closed: `v2.0.38` contains `e26010c` without `042af9c`, and `v2.0.39` contains the final fix.
- The advisory accurately describes a residual of a previous guard, but the selected prior SHA is not that guard. Separately, local `GHSA-VC8F-X9PP-WF5P` identifies `042af9c` itself as an incomplete fix later closed by `345a6211e1e6f939f96a7090bfeff642c9fcf9e4`; that later edge does not transfer to `e26010c` or this row.

### 2. vm2 dangerous-builtin denylist

- First-party advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/05/GHSA-rp36-8xq3-r6c4/GHSA-rp36-8xq3-r6c4.json` (`CVE-2026-47140`). Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/patriksimek__vm2`.
- Claude-marked `093494c0c3ef2390d2e56909f9d56e290e6f18b0` fixes `GHSA-248R-7H7Q-CR24`, an async-generator `yield*`/thenable exception-capture problem in `lib/setup-sandbox.js`.
- Thirteen commits later, `a1ed47a98d1cc36cb48c0d566d55889688e0b59b` amends `lib/builtin.js` so `process` and the `inspector/*` family cannot bypass the builtin denylist. Only documentation overlaps. The actual prior exact-match denylist attempt, `cc15af4b2ea71614d83f81669fecc78e0f87300c`, is not AI-authored.
- `v3.11.3` points to `093494c`; `v3.11.4` contains `a1ed47a`.

### 3. MLflow model-version source validation

- First-party advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/05/GHSA-42h5-h8qh-vv9v/GHSA-42h5-h8qh-vv9v.json` (`CVE-2026-2614`). Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/mlflow__mlflow`.
- Copilot `1824478edbc7a117a612fbed371ea87fa3e0563d` changes `mlflow/exceptions.py` and its tests to tolerate a null `error_code` and correct an exception clause. Final `6e801f4259d96804c73107315b24cef0f6aa115a` changes `_create_model_version()` in `mlflow/server/handlers.py` and its tests to validate the prompt-source scheme.
- The prior is four commits before the final, but the files and invariants are disjoint. Patch-equivalent branch carriers are resolved: `1824478` corresponds to `ac256dfa`, `6e801f4` corresponds to `ff112229`, and the former carrier is the latter's direct parent.
- `v3.9.0` contains neither carrier; `v3.10.0` contains both. Therefore no released artifact contains the selected attempt without closure.

### 4. pypdf unterminated inline-image loop

- First-party advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/07/GHSA-g867-7843-wf8q/GHSA-g867-7843-wf8q.json` (`CVE-2026-59935`). Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/py-pdf__pypdf`.
- Claude-marked `4d8ebcec00d883eed81cd0aa88965217060d4eef` fixes stale cache entries for non-authoritative object streams in `pypdf/_reader.py`.
- `5a33a46416aa1ae6c025ff90a3cca57631fdafd2`, 139 commits later, adds EOF termination to ASCII85/ASCIIHex inline-image parsing in `pypdf/generic/_image_inline.py` and adjusts the related error type in `_data_structures.py`. There is no changed-file or mechanism overlap.
- `6.14.1` contains the prior without the final; `6.14.2` contains the final.

### 5. Prefect webhook SSRF

- First-party advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/05/GHSA-p3pq-hxmr-vqqr/GHSA-p3pq-hxmr-vqqr.json` (`CVE-2026-7724`). Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/PrefectHQ__prefect`.
- Claude-marked `34586366f0eed9112df75a4e683a4ef91fda8db6` changes `_UnpicklingFuture` in `src/prefect/task_runners.py` so deserialization errors reach callbacks.
- Its direct child, `7c70ac54a5e101431d83b9f2681ec88d5e0021ed`, changes `utilities/urls.py`, `blocks/webhook.py`, and `blocks/notifications.py` to validate and pin resolved addresses at connection time. The selected prior never touches the URL or webhook boundary.
- `3.6.28.dev1` contains neither commit; `3.6.28.dev2` contains both, so there is no released attempt-only interval.

### 6. CommonMark obfuscated-scheme XSS

- First-party advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/08/GHSA-29pj-957v-52mc/GHSA-29pj-957v-52mc.json` (`CVE-2026-71478`). Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/thephpleague__commonmark`.
- Claude-marked `51b529fd295ade2e641e8a6152e72c16ce9735ac` changes `FencedCodeParser.php` and `Cursor.php` to count tabs correctly in fenced code blocks.
- Three commits later, `493a5aa7d65754b73846006eaff9c2c4431a8e2c` changes `RegexHelper::isLinkPotentiallyUnsafe()` to remove ASCII tab/newline bytes and leading C0 controls before matching unsafe schemes. The prior neither attempted nor modified this guard.
- `2.8.3` contains the prior without the final; `2.9.0` contains the final.

### 7. Fickling invisible `OBJ` calls

- First-party advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/02/GHSA-mxhj-88fx-4pcv/GHSA-mxhj-88fx-4pcv.json` (no CVE alias). Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/trailofbits__fickling`.
- Claude-marked `a22a9a92fc07c4890b5ba7ec5222d660cc6945a7` handles cyclic structures in `ASTProperties` and the mutation opcodes `AddItems`, `SetItems`, `SetItem`, `Append`, and `Appends`.
- Sixteen commits later, `ff423dade2bb1f72b2b48586c022fac40cbd9a4a` changes `Obj`, `NewObj`, and `NewObjEx` to persist calls with `new_variable()`, preventing `POP` from erasing dangerous calls before analysis. Same file does not mean same boundary.
- `v0.1.7` predates the prior; `v0.1.8` contains both prior and final, so no released artifact contains only the selected attempt.

### 8. Hemmelig webhook SSRF

- First-party advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2025/12/GHSA-vvxf-wj5w-6gj5/GHSA-vvxf-wj5w-6gj5.json` (`CVE-2025-69206`). Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/HemmeligOrg__Hemmelig.app`.
- Copilot `de4cbe0303b72d34e2fd26d25195bf0b3801ad68` changes only `src/components/FileUpload.tsx`, replacing a non-functional sign-in button with a router link.
- Three commits later, `6c909e571d0797ee3bbd2c72e4eb767b57378228` changes `api/lib/utils.ts` to resolve and reject private IPs and changes webhook senders to reject redirects. The UI commit cannot be the incomplete SSRF guard.
- `v7.3.2` contains the prior without the final; `v7.3.3` points to the final.

### 9. LobeHub forgeable XOR auth header

- First-party advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/04/GHSA-5mwj-v5jw-5c97/GHSA-5mwj-v5jw-5c97.json` (`CVE-2026-39411`). Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/lobehub__lobehub`.
- Claude-marked `5b03f009eea81a9b44004f031ba021cb2db027bf` adds progressive loading to agent-document policy, database, runtime, and service code.
- Eight commits later, `3327b293d66c013f076cbc16cdbd05a61a3d0428` removes XOR auth utilities and the API-key truthiness fallback, and rewrites backend auth to require a validated OIDC identity or session. The prior changes no auth-header or webapi boundary.
- `v2.1.47` predates the prior; `v2.1.48` contains both prior and final. No vulnerable release contains the selected prior without closure.

### 10. Qinglong initialization-guard bypass

- First-party advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/03/GHSA-xj37-qjg2-xwv2/GHSA-xj37-qjg2-xwv2.json` (`CVE-2026-3965`). Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/whyour__qinglong`.
- Copilot `dc0b3f2eb29ee70311bba8e0c75bedf214acaccd` normalizes `QlBaseUrl` and installs an early rewrite middleware. The initialization guard and the later `/open/*` to `/api/*` rewrite already exist outside this hunk.
- Eight commits later, `6bec52dca158481258315ba0fc2f11206df7b719` adds `/open/user/init` and `/open/user/notification/init` to that guard's protected path set. Removing the base-path feature leaves the missing-sibling bypass unchanged.
- `v2.20.0` predates the prior; `v2.20.1` points to the final and therefore contains both. The advisory records `2.20.2` as fixed, creating a tag/ecosystem-version discrepancy, but neither source proves a released prior-only interval; release remains `FAIL`.

## Controls and disagreements

- All 10 selected commits are ancestors of their supplied final fixes; ancestry distance and patch-equivalent carriers were resolved without transferring authorship.
- All first-party advisory objects were read from the local `commit-gn` advisory-database clone at `a42c436870111aa3f221257c9d56126a93173ccc`. Input SHA-256 is `5bc8a8d97968bdf03329e650c2242fcee4703f81743f81f1514f6444ea80835d`; contract SHA-256 is `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
- The canonical84 ledger was searched by GHSA identity, aliases, repository, and mechanism. None of these cases collides; observed ledger SHA-256 is `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`.
- Locutus is genuinely a residual-bypass advisory, but the supplied docs-only prior is the wrong edge. Qinglong's advisory ecosystem version and Git tag disagree, but the causality rejection is independent of that release discrepancy.
- No row receives `AI_INCOMPLETE_REMEDIATION`, so no `original_vulnerability` block applies. Missing such a block is intentional, not an evidence omission.
- Commit messages, paths, ancestry, diffs, and tags came from the local bare pools. Missing promised objects for rows 6-10 were obtained only through Git smart-HTTP; no GitHub API was used.
