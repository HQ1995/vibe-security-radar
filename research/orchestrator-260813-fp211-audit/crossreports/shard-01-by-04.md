# Cross-review shard 01 by reviewer 04 (ordinals 1-36)

Coverage: **exactly ordinals 1-36** from `inputs/shard-01.jsonl` against `AUDIT_CONTRACT.md`.
Owned outputs: `crossreviews/shard-01-by-04.jsonl`, `crossreports/shard-01-by-04.md`.
JSONL is **36/36**, one compact 26-field row per ordinal in order 1–36.
No canonical ledger, first-pass shard, code, manifest, other shards, or caches were edited. No commit.
Independent clones (symlinks) and raw pages: `/tmp/fp211-cross-04`. First-pass citations were treated as routing only, not proof.

Rotation: reviewer 04 → first-pass shard 01.

## Verdict counts

| Verdict | n | ordinals |
|---|---:|---|
| CONFIRM | 9 | 2, 6, 12, 14, 19, 23, 26, 27, 32 |
| NARROW | 17 | 1, 3, 5, 8, 10, 18, 20, 21, 22, 24, 25, 28, 29, 30, 31, 33, 34 |
| FALSE_POSITIVE | 9 | 4, 7, 9, 11, 13, 15, 16, 17, 36 |
| UNKNOWN | 1 | 35 |
| BLOCKED | 0 | — |
| **total** | **36** | 1-36 |

None of the CONFIRM rows is a final HOLD case by itself. Contract still requires independent review of every non-CONFIRM/HIGH row before a rebuilt canonical ledger.

## Disagreements with first pass

First pass: `shards/shard-01.jsonl` / `reports/shard-01.md`. Compared after independent git+advisory inspection.

### Verdict disagreements (1)

1. **Ord 18 / GHSA-FPMV / CVE-2026-34218.** First pass `UNKNOWN`. This review `NARROW` / `AI_INCOMPLETE_REMEDIATION` / MEDIUM.
   - Parent `opfilter/main.swift` already did `adapter.start(initialRules: faaPolicy)` then applied updates only via GUI XPC `onPolicyUpdate`.
   - Candidate `5a887953` constructs `XPCServer` whose `init` calls `applyPolicyToFilter()` **before** `adapter.start(initialRules: server.mergedRules())`. That is an explicit attempt to push merged managed/user rules at boot; the nil-client guard no-ops it.
   - Fix `56d617b7` (tag `v4.2.14-56d617b`) moves apply after start. `v4.2.11-97eb073` contains the candidate without the fix.
   - Whole-advisory CONFIRM is refused: deleting the candidate restores the parent window (baseline-only until GUI), so the AI change is incomplete remediation of that window, not origin of it.
   - `but_for_gate` UNKNOWN → NARROW. Identity closed via repo advisory (global GHSA 404 preserved in evidence). UNKNOWN is not preserved here because parent/candidate ordering was recovered.

### Gate disagreements, same verdict (13 ordinals / 14 gates)

Identity NARROW-overuse: a global-or-repo 404 is recorded in `counterevidence`, but identity **PASS** when the other first-party object exists and aliases match.

| Ord | Gate | First pass | This review | Why |
|---|---|---|---|---|
| 7 | identity_gate | PASS | NARROW | GHSA-gxgq claims affected up to `3.4.0`; git `merge-base` shows origin `2b72d8a7` is **not** an ancestor of `3.4.0`. Polluted version mapping, not a 404. Verdict still FP (`unreleased_commit_only`). |
| 8 | identity_gate | NARROW | PASS | Global GHSA-j4xf aliases CVE-2026-32021; repo 404 preserved in evidence. |
| 10 | identity_gate | NARROW | PASS | Global GHSA-5wqv aliases CVE-2026-55197; repo 404 preserved. |
| 11 | identity_gate | NARROW | PASS | Repo GHSA-mg93 aliases CVE-2026-27627; global 404 preserved. |
| 17 | identity_gate | NARROW | PASS | Global GHSA-95f6 aliases CVE-2026-10291; repo 404 preserved. |
| 18 | identity_gate | NARROW | PASS | Repo GHSA-fpmv aliases CVE-2026-34218; global 404 preserved. |
| 18 | but_for_gate | UNKNOWN | NARROW | Parent/candidate ordering recovered (see verdict disagreement). |
| 22 | identity_gate | NARROW | PASS | Global GHSA-42m6 aliases CVE-2026-49949; repo 404 preserved. |
| 25 | identity_gate | NARROW | PASS | Repo GHSA-pqgx aliases CVE-2025-69288; global 404 preserved. |
| 30 | topology_gate | NARROW | PASS | Direct Copilot commit `66ff2a7c`; no squash/carrier rewrite. |
| 30 | release_gate | UNKNOWN | PASS | First pass queried `@dynatrace-oss/dynatrace-mcp` (404). GHSA package is `@dynatrace-oss/dynatrace-mcp-server`. npm `1.2.0` gitHead `1c192a04` contains candidate not fix; `2.1.1` gitHead `9a5f6f86` contains `15d3546c`. Verdict still NARROW (parent `additionalFilter`). Confidence MEDIUM → HIGH. |
| 34 | identity_gate | NARROW | PASS | Repo GHSA-q9j6 aliases CVE-2026-34599; global 404 preserved. |
| 35 | identity_gate | NARROW | PASS | Repo GHSA-4mpw aliases CVE-2026-34049; global 404 preserved. `ai_hunk_gate` remains UNKNOWN. |
| 36 | identity_gate | NARROW | PASS | Global GHSA-c7rr aliases CVE-2025-55526; repo 404 preserved. |

### Public-ID disagreements

**None.** For every ordinal, `public_ids_keep` = sorted input `public_ids` and `public_ids_remove` = `[]`. Shard 01 has no packed distinct GHSA pairs; GHSA+CVE rows are formal aliases. No keep/remove split.

No `public_ids_keep` collision with later first-pass shards.

## False-positive counterexamples (independent)

1. **Ord 4 / GHSA-GG5M / CVE-2026-32247 — `wrong_edge`.** Public IDs name `node_labels` Cypher injection already in parent `search_filters.py`. Candidate copies `group_ids` Lucene concat into `_build_neo4j_fulltext_query`; `v0.28.1` `search()` still uses `search_utils.fulltext_query`. Fix `7d65d5e` is primarily `validate_node_labels`. Identity FAIL + but-for FAIL + fix-reversal FAIL.
2. **Ord 7 / GHSA-GXGQ / CVE-2026-1979 — `unreleased_commit_only`.** JMPNOT→JMPIF origin `2b72d8a7` is not in `3.4.0`. `4.0.0-rc` contains origin **and** fix `e50f15c1`. Identity NARROW because the GHSA range does not match git.
3. **Ord 9 / GHSA-XWCJ — `wrong_edge`.** Parent `src/media/fetch.ts` already interpolates `${url}` into `MediaFetchError`. Sticker commit `506bed5a` is not but-for. Independently fetched npm `2026.3.13` gitHead `61d171ab` contains squash `7a53eb7e`, not member `724ca4c6`.
4. **Ord 11 / GHSA-MG93 / CVE-2026-27627 — `old_bug_preserving_refactor`.** `v0.30.0` `crawlerWorker` already passed `readableContentHtml`. Named `v0.30.0` is **not** an ancestor of `e193701d`.
5. **Ord 13 / GHSA-MHR7 / CVE-2026-41347 — `wrong_edge`.** GHSA is Origin/CSRF on trusted-proxy HTTP. `f4b03599` only adds `/v1/responses`. Fix `6b3f99a1` is a shared origin-check. Same SHA as 29/40, different invariants.
6. **Ord 15 / GHSA-2F7J / CVE-2026-41339 — `wrong_edge`.** Advisory is snapshot `configPath`/`stateDir` to non-admin clients (`676b748`). `079af0d0` only expands token-without-device connect.
7. **Ord 16 / GHSA-HXVM / CVE-2026-44114 — `wrong_edge`.** Parent already loads workspace dotenv and consumes `OPENCLAW_*`. `db67492a` only adds `launchctl kickstart`. Fix blocklists the prefix and does not reverse kickstart.
8. **Ord 17 / GHSA-95F6 / CVE-2026-10291 — `old_bug_preserving_refactor`.** Parent `edf0c0d6` already `new RegExp(pattern,'gi')`. `0a283f45` copies the same sink. Parent message names “Claude Code CLI” as a **product**; that is not an AI trailer.
9. **Ord 36 / GHSA-C7RR / CVE-2025-55526 — `unreleased_commit_only`.** Claude `ff958e` `os.path.join('workflows', filename)` is real, but the only tag `dmca-compliance-2025-08-14` already contains fix `64f9f86`.

## Narrow counterexamples (real AI mechanism, scope must shrink)

| Ord | Why NARROW |
|---|---|
| 1 | Squash member `aae7acba` adds `ha_url`→`/api/config`; **provider.py blob ≠ carrier** `39806871`. Primitive present in `v6.7.2`; fix in `v7.0.0`. |
| 3 | Copilot adds `prek-version` interpolation; parent already interpolates `extra_args`; GHSA-pwf7 names both; `v1.0.6` fixes both. |
| 5 | `bce0d2ba` **is** `v0.4.0`; no tag contains fix `c6daf910`/`6d709229`. GHSA-fwpr text contradicts (affected up to 0.4.0 **and** upgrade to 0.4.0). |
| 8 | Upstream Claude `4286755f` `senderName` grant; OpenClaw `2267d58a` is import carrier. Distinct from 31/58/65/66. |
| 10 | Parent already returned foreign sidecar transcripts; `ee672df4` additionally reads `state.db`. Distinct from ord 2. |
| 18 | AI attempted apply-before-start; parent already lacked managed/user enforcement until GUI. Incomplete remediation, not origin. |
| 20 | Both Claude SCA clients unbounded `resp.read()`; **`f08e6549` (osv.py) not in `v0.6.0`**. |
| 21 | Parent already `Path.Combine` extract; Copilot adds/renames async. Whole-advisory but-for fails. |
| 22 | Three Claude providers; human `ProviderHTTPClient` is later transport. Repo GHSA-42m6 404. |
| 24 | New `pdf_read.rs` copies parent filesystem validate-then-later-I/O. Distinct from 27. |
| 25 | Copilot replaces vm2 with native `vm`; parent already unsanitized `timeEntryRule`. |
| 28 | Member `78d08fc5` blob ≠ carrier `4b3e9c0f`; member **not** in npm `2026.2.1` (`ed4529e2`); gateway POSIX skip already existed. |
| 29 | Same `f4b03599` as 13/40. Adds `/v1/responses` onto captured `resolvedAuth`. Other HTTP/WS still captured. |
| 30 | Copilot `timeframe` interpolation; parent already interpolates `additionalFilter`. Release **does** close on `@dynatrace-oss/dynatrace-mcp-server` gitHeads. |
| 31 | Recovered OpenClaw Feishu local-path (`GHSA-8jpq` / CVE-2026-26321). Import carrier `2267d58a`. Fix `5b4121d6` still `createReadStream(string)`. Distinct from 58 SSRF. |
| 33 | Token-only no-device skip; not whole GHSA-3cvx. npm `2026.2.19-2`=`45d9b206`; npm `2026.2.21` gitHead `d9844c6a` ≠ git tag `5e34eb98`. Same SHA as 15. |
| 34 | `downloadAllLogs` copies parent `docker logs {$container}`. |

## Unknown (preserved)

- **Ord 35 / GHSA-4MPW / CVE-2026-34049.** Candidate `473c3227` message is only `Changes auto-committed by Conductor` (author Andras Bacsai). Parent already had `mongodump --excludeCollection` + `databases_to_backup`. Claude marker is on the **fix** member `99043600`. Sibling 68 is `update_backup`. `ai_hunk_gate` UNKNOWN. Do not infer PASS.

## Confirm (all required gates PASS)

Replay-checked independently:

- **2** additive dotenv (`d2b27f6f` ancestor of `v0.24`; `88dc8bbe` pops keys in `v0.50.12`).
- **6** Synology empty-allowlist (`security.ts` blob-equal; git tags `v2026.2.22`/`v2026.2.24`). Distinct from 96/122.
- **12** Budibase `bindings.oauth2` first add; parent `getUserContextBindings` has no oauth2; sanitizer in `3.39.25`.
- **14** filebrowser `ReplaceAll('\\','/')` added in `847d08bd` `http/raw.go`; reversed to `'_'` in `8503ba61` / `v2.63.17`.
- **19** ebay-mcp Claude author `updateEnvFile`; git tags equal npm gitHeads `v1.7.2`/`v1.7.3`.
- **23** Cursor trusted-proxy skip; `connect-policy.ts` blob-equal; npm `2026.2.24` gitHead `df9a4748` contains carrier not fix; **fix reversal is `role === "operator"` in `message-handler.ts`**, not a connect-policy.ts edit. Git tag `v2026.2.24` = `819cec3c` ≠ npm gitHead.
- **26** ruflo mcp-bridge first add; npm `3.16.2` gitHead `402b701a` / `3.16.3` gitHead `d00a0a40`. Git tags of those versions are different SHAs.
- **27** zeptoclaw webhook.rs first add; `v0.7.5`/`v0.7.6`.
- **32** claw-orchestrator `embedded-server.ts` first add with no `authToken`; `v3.5.5`/`v3.5.6`.

## Primary-source / replay notes

Git flags used: `git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false`.
Clones under `/tmp/fp211-cross-04/clones/` (symlinks into existing shard clones). Inspection used `git show SHA:path`, `git grep SHA`, `git diff A B -- path`, `git merge-base --is-ancestor`. `git tag --contains` was not used as release proof.

Independently fetched:

- Global GHSA pages: `/tmp/fp211-cross-04/pages/ghsa/`
- Repo security-advisories: `/tmp/fp211-cross-04/pages/repo-advisory/`
- npm packuments: `/tmp/fp211-cross-04/pages/npm/`

Global GHSA 404s (identity closed via repo object when present): GHSA-4mpw, c4hm, fpmv, mg93, pqgx, q9j6.
Repo GHSA 404s (identity closed via global when present): DeepMyst/Mysti fwpr, nesquena hermes vvfr/5wqv, mruby gxgq, m1heng clawdbot j4xf, steipete 42m6, enderfga 95f6/q6qc, zie619 c7rr.

OpenClaw SHAs resolved in `openclaw-v2`. Upstream Feishu root `4286755f` is in `clawdbot-feishu` and is **not** in `openclaw-v2`.

Independently fetched npm gitHeads (do not conflate with git tags):

| artifact | gitHead |
|---|---|
| openclaw@2026.2.1 | `ed4529e24673fb19ea506bb04b2c6d3deed6a451` |
| openclaw@2026.2.2 | `539a15e63fcc823256893ccde8bd421db14aba23` |
| openclaw@2026.2.19-2 | `45d9b2069264451d005ae612f2044e7deb8b44c0` |
| openclaw@2026.2.21 | `d9844c6afa2d6c6c8a7a4fb3b004b5c0456d184e` (git tag `v2026.2.21` = `5e34eb98`) |
| openclaw@2026.2.24 | `df9a474891d48084a452a2f809fb239dc751c323` (git tag `v2026.2.24` = `819cec3c`) |
| openclaw@2026.2.25 | `4b5d4a4c660d05e4bd73f0e11123e68fd9664432` |
| openclaw@2026.3.13 | `61d171ab0b2fe4abc9afe89c518586274b4b76c2` |
| ruflo@3.16.2 | `402b701a9d98700bc0dec823d2301df404f1f7d2` |
| ruflo@3.16.3 | `d00a0a40cd8bdbca877ac7f675f416bdc69accd1` |
| @dynatrace-oss/dynatrace-mcp-server@1.2.0 | `1c192a0427bb348b0843779207f556052d6c28e7` |
| @dynatrace-oss/dynatrace-mcp-server@2.1.1 | `9a5f6f86d186f1168645e24673c73bc56a94dda8` |

## Limitations

- Clones are symlinks into `/tmp/fp211-shard-01` / shard-04 caches, not fresh fetches. SHAs were re-inspected with `git show` / `merge-base`; blob contents were not assumed from first-pass notes.
- `f08e6549` `git show` of the full diff hit a missing blob in the shallow ciguard clone; ancestry vs `v0.6.0`/`v0.8.2` still resolved (`osv` not in `v0.6.0`).
- Uniqueness vs later-shard siblings used first-pass `public_ids_keep` plus mechanism keys, not a second hunk audit of those rows.
- Ord 35 Conductor provenance remains UNKNOWN; not upgraded.
- Identity 404s are preserved as evidence; they are not used to NARROW identity when the complementary first-party object exists.

## Reusable lessons

1. **Squash member ≠ carrier blob.** Ancestry `candidate_in_vuln_tag: no` is expected; prove the primitive on the carrier/tag blob, then NARROW topology if blobs differ (ords 1, 28). Blob-equal carriers can still CONFIRM (ords 6, 23).
2. **npm gitHead ≠ git tag of the same version string.** Ords 23/26/33. Ord 6 correctly used git tags; ord 23 must use packument gitHead.
3. **Fix reversal may live in the caller, not the policy blob.** Ord 23 `connect-policy.ts` is unchanged by `ec45c317`; `message-handler.ts` adds `role === "operator"`.
4. **Parent interpolation / parent helper is the default alternative to AI origin.** New call sites (sticker, `/v1/responses`, `downloadAllLogs`, `timeframe`, `prek-version`) fail whole-advisory but-for.
5. **Generic Conductor auto-commit is not hunk-level AI.** Preserve UNKNOWN (ord 35).
6. **Unreleased means no artifact with origin and without fix**, including RC tags that already contain the fix (ords 7, 36).
7. **Shared SHA/fix is not automatic duplicate.** Feishu `4286755f` and `f4b03599` fan out to distinct source/sink/invariants (8 vs 31 vs 58; 13 vs 29 vs 40). Synology `cc048a29` is empty-allowlist (6) vs webhook-path (96) vs rate-limit (122).
8. **404 is evidence, not a license to invent IDs or npm gitHeads, and not automatic identity NARROW** when the other first-party object exists.
9. **Use the GHSA package name for npm.** `@dynatrace-oss/dynatrace-mcp` 404 is not UNKNOWN if `@dynatrace-oss/dynatrace-mcp-server` packument exists (ord 30).
10. **Incomplete remediation is not origin.** An AI commit that attempts the advisory boundary and leaves the parent residual is NARROW `AI_INCOMPLETE_REMEDIATION`, not UNKNOWN and not CONFIRM (ord 18).
11. **A product name containing “Claude Code” is not an AI trailer** (ord 17 parent).
12. **A fix that does not reverse the candidate hunk is a failed fix-reversal gate** even if it patches the advisory (ords 4, 13, 15, 16).
