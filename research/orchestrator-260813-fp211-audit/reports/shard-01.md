# Shard 01 false-positive audit (ordinals 1-36)

Coverage: **exactly ordinals 1-36** from `inputs/shard-01.jsonl` against `AUDIT_CONTRACT.md`.
Owned outputs: `shards/shard-01.jsonl`, `reports/shard-01.md`.
JSONL is **36/36**, one compact row per ordinal in order 1–36 (rewritten as a whole file so order stays canonical). Incremental close is done; no further rows remain on this shard.
No canonical ledger, code, manifest, other shards, or caches were edited. No commit.
Temporary clones and raw pages: `/tmp/fp211-shard-01`.

Checkpoint: routing notes under `/tmp/fp211-shard-01/results/` proposed CONFIRM for ords **1, 18, 20, 31**. Those were **not** adopted (blob mismatch / unproven parent ordering / osv.py absent from `v0.6.0` / leftover `createReadStream(string)`). Rechecked CONFIRM 6 (security.ts blob-equal carrier; `v2026.2.22`/`v2026.2.24`) and CONFIRM 23 (connect-policy.ts blob-equal; npm `2026.2.24` gitHead contains carrier not fix; `2026.2.25` contains fix).

## Verdict counts

| Verdict | n | ordinals |
|---|---:|---|
| CONFIRM | 9 | 2, 6, 12, 14, 19, 23, 26, 27, 32 |
| NARROW | 16 | 1, 3, 5, 8, 10, 20, 21, 22, 24, 25, 28, 29, 30, 31, 33, 34 |
| FALSE_POSITIVE | 9 | 4, 7, 9, 11, 13, 15, 16, 17, 36 |
| UNKNOWN | 2 | 18, 35 |
| BLOCKED | 0 | — |
| **total** | **36** | 1-36 |

None of the CONFIRM rows is a final HOLD case by itself. Contract still requires independent review of every non-CONFIRM/HIGH row before a rebuilt canonical ledger.

## False-positive counterexamples

1. **Ord 4 / GHSA-GG5M / CVE-2026-32247 — `wrong_edge`.** Public IDs name `node_labels` Cypher injection already in parent `search_filters.py`. Candidate `1d94f7a3` copies `group_ids` Lucene concat into `_build_neo4j_fulltext_query`; production `search()` still uses `search_utils.fulltext_query`. Fix `7d65d5e` is primarily `validate_node_labels`. Identity FAIL + but-for FAIL.
2. **Ord 7 / GHSA-GXGQ / CVE-2026-1979 — `unreleased_commit_only`.** JMPNOT→JMPIF origin `2b72d8a7` is not in `3.4.0`. `4.0.0-rc` contains origin **and** fix `e50f15c1`. STRICT_RELEASED release FAIL.
3. **Ord 9 / GHSA-XWCJ — `wrong_edge`.** Parent `fetch.ts` already interpolates `${url}` (bot token) into `MediaFetchError`. Sticker commit `506bed5a` is not but-for. npm `2026.3.13` ships squash `7a53eb7e`, not member `724ca4c6`.
4. **Ord 11 / GHSA-MG93 / CVE-2026-27627 — `old_bug_preserving_refactor`.** Parent `crawlerWorker` already passed `readableContentHtml`. Named `v0.30.0` contains that parent path and is **not** an ancestor of `e193701d`.
5. **Ord 13 / GHSA-MHR7 / CVE-2026-41347 — `wrong_edge`.** Parent already serves `/v1/chat/completions` through `authorizeGatewayConnect`. `f4b03599` only adds `/v1/responses`. Trusted-proxy and Origin fix `6b3f99a1` are not this endpoint. Same SHA as ords 29/40 with different claimed invariants.
6. **Ord 15 / GHSA-2F7J / CVE-2026-41339 — `wrong_edge`.** Advisory is snapshot `configPath`/`stateDir` to non-admin clients (`676b748`). Parent already sent full snapshots. `079af0d0` only expands token-without-device connect. Ledger repo/ai/release were null; recovered from git+GHSA.
7. **Ord 16 / GHSA-HXVM / CVE-2026-44114 — `wrong_edge`.** Parent already `loadDotEnv` and consumes `OPENCLAW_*`. `db67492a` only adds `launchctl kickstart`. Fix blocklists the prefix and does not reverse kickstart.
8. **Ord 17 / GHSA-95F6 / CVE-2026-10291 — `old_bug_preserving_refactor`.** Human parent `edf0c0d6` (no AI marker) already `new RegExp(pattern,'gi')`. `0a283f45` copies the same sink. Repo GHSA 404 preserved.
9. **Ord 36 / GHSA-C7RR / CVE-2025-55526 — `unreleased_commit_only`.** Claude `ff958e` `os.path.join('workflows', filename)` is real, but the only tag `dmca-compliance-2025-08-14` already contains fix `64f9f86`.

## Narrow counterexamples (real AI mechanism, scope must shrink)

| Ord | Why NARROW |
|---|---|
| 1 | Squash member `aae7acba` adds `ha_url`→`/api/config`; **provider.py blob ≠ carrier** `39806871`. Primitive present in `v6.7.2`; fix in `v7.0.0`. |
| 3 | Copilot adds `prek-version` interpolation; parent already interpolates `extra_args`; GHSA-pwf7 names both; `v1.0.6` fixes both. |
| 5 | `bce0d2ba` **is** `v0.4.0`; no tag contains fix `c6daf910`/`6d709229`. GHSA-fwpr text contradicts (affected up to 0.4.0 **and** upgrade to 0.4.0). Repo GHSA 404. |
| 8 | Upstream Claude `4286755f` `senderName` grant; OpenClaw `2267d58a` is import carrier; parent `02842bef` ID-only. Not upstream origin. Distinct from 31/58/65/66. |
| 10 | Parent already returned foreign sidecar transcripts; `ee672df4` additionally reads `state.db`. Distinct from ord 2. |
| 20 | Both Claude SCA clients unbounded `resp.read()`; **`f08e6549` (osv.py) not in `v0.6.0`**. Harvest overwrote `d42195e1`. |
| 21 | Parent already `Path.Combine` extract; Copilot adds/renames async. Whole-advisory but-for fails. |
| 22 | Three Claude providers; human `f62bb8c8` later adds `ProviderHTTPClient`. Not origin of transport. Repo GHSA-42m6 404. |
| 24 | New `pdf_read.rs` copies parent filesystem validate-then-later-I/O. Distinct from 27. |
| 25 | Copilot replaces vm2 with native `vm`; parent already unsanitized `timeEntryRule`. Global GHSA-pqgx 404. |
| 28 | Member `78d08fc5` blob ≠ carrier `4b3e9c0f`; member **not** in npm `2026.2.1` (`ed4529e2`); gateway POSIX skip already existed. |
| 29 | Same `f4b03599` as 13/40. Adds `/v1/responses` onto captured `resolvedAuth`. Other HTTP/WS still captured. |
| 30 | Copilot `timeframe` interpolation; parent already interpolates `additionalFilter`. npm `@dynatrace-oss/dynatrace-mcp@1.2.0` and `2.1.1` **404**. Release UNKNOWN. |
| 31 | Recovered OpenClaw Feishu local-path (`GHSA-8jpq` / CVE-2026-26321). Import carrier `2267d58a`. Fix `5b4121d6` still `createReadStream(string)`. Distinct from 58 SSRF. Ledger fields were null. `v2026.2.13`/`v2026.2.14`. |
| 33 | Token-only no-device skip; not whole GHSA-3cvx. npm `2026.2.19-2`=`45d9b206`; npm `2026.2.21` gitHead `d9844c6a` ≠ git tag `5e34eb98`. Same SHA as 15. |
| 34 | `downloadAllLogs` copies parent `docker logs {$container}`. Global GHSA-q9j6 404. |

## Unknown (preserved, not inferred PASS)

- **Ord 18 / GHSA-FPMV / CVE-2026-34218.** Claude authored `5a887953`; fix `56d617b7` moves `applyPolicyToFilter` after `adapter.start`; tag `v4.2.14-56d617b` equals the fix. Parent apply-before-start ordering was **not** recovered as a decisive but-for counterexample (`18-cand-policy.txt` only shows `adapter.start`). Global GHSA 404. Verdict UNKNOWN.
- **Ord 35 / GHSA-4MPW / CVE-2026-34049.** Candidate `473c3227` message is only `Changes auto-committed by Conductor` (author Andras Bacsai). Parent already had `mongodump --excludeCollection` + `databases_to_backup`. Claude marker is on the **fix** member. Sibling 68 is `update_backup`. `ai_hunk_gate` UNKNOWN.

## Confirm (all required gates PASS)

Replay-checked: additive dotenv (2), Synology empty-allowlist (6), Budibase oauth2 broadcast (12), filebrowser backslash zip-slip (14), ebay-mcp env writeback (19), trusted-proxy Control UI skip vs **npm gitHead** (23), ruflo mcp-bridge (26), zeptoclaw webhook identity (27), claw-orchestrator embedded-server missing auth (32).

## Primary-source / replay notes

Git flags used throughout: `git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false`.
Clones under `/tmp/fp211-shard-01/clones/` are often `--no-checkout`; inspection used `git show SHA:path`, `git grep SHA`, `git diff A B -- path`, `git merge-base --is-ancestor`.

npm packument gitHeads (do not conflate with git tags of the same version string):

| artifact | gitHead |
|---|---|
| openclaw@2026.2.1 | `ed4529e24673fb19ea506bb04b2c6d3deed6a451` |
| openclaw@2026.2.2 | `539a15e63fcc823256893ccde8bd421db14aba23` |
| openclaw@2026.2.19-2 | `45d9b2069264451d005ae612f2044e7deb8b44c0` |
| openclaw@2026.2.21 | `d9844c6afa2d6c6c8a7a4fb3b004b5c0456d184e` (git tag `v2026.2.21` = `5e34eb98`) |
| openclaw@2026.2.24 | `df9a474891d48084a452a2f809fb239dc751c323` (git tag `v2026.2.24` is ordinal 6's **fixed** tag) |
| openclaw@2026.2.25 | `4b5d4a4c660d05e4bd73f0e11123e68fd9664432` |
| ruflo@3.16.2 | `402b701a9d98700bc0dec823d2301df404f1f7d2` |
| ruflo@3.16.3 | `d00a0a40cd8bdbca877ac7f675f416bdc69accd1` (the fix) |

Global GHSA 404s preserved (repo object used when present): GHSA-4mpw, c4hm, fpmv, mg93, pqgx, q9j6.
Repo GHSA 404s preserved (global used when present): DeepMyst/Mysti fwpr, nesquena hermes vvfr, mruby gxgq, m1heng clawdbot j4xf, steipete 42m6, enderfga 95f6/q6qc, zie619 c7rr.

OpenClaw SHAs resolved in `openclaw-v2`. Upstream Feishu root `4286755f` is in `clawdbot-feishu` and is **not** in `openclaw-v2`.

## Limitations

- Identity pages were cached under `/tmp/fp211-shard-01/advisories/` and `/tmp/fp211-shard-01/identity/`; live GitHub was not re-fetched in the finalize pass.
- Ord 18 parent daemon policy ordering remains unclosed; UNKNOWN preserved rather than inferred CONFIRM.
- Ord 30 scoped npm versions 404; no invented gitHead.
- Ord 31 leftover `createReadStream(string)` after `5b4121d6` prevents CONFIRM of full local-path reversal.
- Squash members are often not tag ancestors; blob identity was required (ords 1, 6, 23, 28).
- Uniqueness vs later-shard siblings (58, 65, 66, 68, 96, 165) used `all211-slim.json` mechanism keys, not a second hunk audit of those rows.

## Reusable lessons

1. **Squash member ≠ carrier blob.** Ancestry `candidate_in_vuln_tag: no` is expected; prove the primitive on the carrier/tag blob, then NARROW topology if blobs differ.
2. **npm gitHead ≠ git tag of the same version.** Ord 23/33/6 collide on `v2026.2.24` / `v2026.2.21` strings.
3. **Parent interpolation / parent helper is the default alternative to AI origin.** New call sites (sticker, `/v1/responses`, `downloadAllLogs`, `timeframe`, `prek-version`) fail whole-advisory but-for.
4. **Generic Conductor auto-commit is not hunk-level AI.** Preserve UNKNOWN (ord 35).
5. **Unreleased means no artifact with origin and without fix**, including RC tags that already contain the fix (ords 7, 36).
6. **Shared SHA/fix is not automatic duplicate.** Feishu `4286755f` and `f4b03599` fan out to distinct source/sink/invariants (8 vs 31 vs 58; 13 vs 29 vs 40).
7. **Do not trust harvest dicts.** Ord 20 overwrote `d42195e1` with `f08e6549`.
8. **404 is evidence, not a license to invent IDs or npm gitHeads.**
9. **A fix that does not reverse the candidate hunk is a failed fix-reversal gate** even if it patches the advisory (ords 4, 13, 15, 16).
10. **Null ledger repository/ai/release must be recovered or left UNKNOWN**, never copied from OSV `introduced` (ords 15, 31).
