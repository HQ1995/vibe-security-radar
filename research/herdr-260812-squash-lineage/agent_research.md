# Squash/compositional lineage tail: primary-source shard

Snapshot time: `2026-08-12T12:29:10-04:00` (`America/New_York`). Checkout `dev` was at `6c0d2084fd1240341d6d1b9f9096252490168f0b`; the intentionally dirty porcelain-v2 stream hashed to `e37fb8ed73d9c39c58cd4e33d591139e5f54289f0f3fd3025ed4ee4fa124162b`. Cached clones were read only. Their observed `HEAD`s are listed below; conclusions bind to the named commit objects, not to mutable branch names.

## Result

Ten previously undocumented advisory-specific member-to-carrier-to-fix edges were selected after excluding the current adjudicated corpus. Result: **0 PASS, 9 `REJECT_NONCAUSAL`, 1 `UNKNOWN`**. No selected member was proven erased before squash. Several survived exactly or semantically, but survival is topology rather than causality. The one `UNKNOWN` is a real new delegated authorization surface in Coder, but the advisory mechanism already existed in the parent and this shard did not close external reachability of the trusted in-process path for a suspended user.

This is a bounded tail audit, not a new positive-count claim.

## Frozen inputs and exclusions

Newest relevant documents were read first and excluded from candidate selection:

| Frozen source | SHA-256 | Exclusion applied |
|---|---|---|
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` | Current combined strict/incomplete-remediation report, including the six new strict components, OpenClaw 9/3, and post-135 batches. |
| `docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` | `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` | All 12 OpenClaw frontier rows: 9 PASS and 3 FAIL, including the known erased `d6338abe… -> 42164494…` row. No OpenClaw row was reconsidered. |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md` | `318912fbc789ef7f0708044d2041c24fa69198f878c2c668b04af86031d4616e` | All Batch B released and commit-only rows and controls. |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-C-2026-08-12.md` | `b1e03cb193003ebbba83b73b8d8bbcbcd72f02148ba00812967a2721e60a8ffd` | All Batch C rows and controls. |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md` | `3a8482a6badb0b8bff5dbf64adc18b37493c68dc56a25598be91ee3be7e727cd` | All Batch D rows and controls. |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md` | `f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad` | All Batch E rows and controls. |
| `docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md` / `strict-200-v3/ledger.jsonl` | `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` / `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` | The frozen 200 public IDs / 110 semantic components. |
| `docs/RESEARCH-SQUASH-SINGLE-MEMBER-2026-08-11.md` | `7d5902ace0d5f0431e8c9e14a7c1673a72f83c1f8f4807144b9630a9fd82e276` | The completed 10-class single-member batch: 4 PASS, 6 FAIL. |

The seed-time exact exclusion array `squash-assistant-multi-exact-seed-v1/excluded-public-ids.json` contains 301 IDs and hashes to `599892e76320613b624a50406cd32d4400d9759097f3abfa937d7ffcba3c6337`. Because it predates the newest documents, the document union above was also applied. In particular, the already adjudicated model-positive candidates `93f80ea4…`, `2db76f65…`, `0d851525…`, `257eb178…`, `cc048a29…`, `53764bbb…`, `d30b6175…`, and `924a11ee…` were excluded before this selection.

Relevant topology/routing snapshots:

| Artifact | SHA-256 | Boundary |
|---|---|---|
| `squash-assistant-single-relation-v2/summary.json` | `d0ade7a496c90847baf7350696f122e624c715b7cbcc9f032e0eee611e3cc9c7` | 3,198/3,198 single-member relation roots resolved; relations are topology only. |
| `squash-assistant-all-member-same-file-v2/summary.json` | `8af8c3219b43363b132bbb0e531a0945baac95fa0d8286375317723a4f09415e` | Direct-AI member/same-file screen; overlap is routing evidence only. |
| `squash-assistant-strict-v1/adjudications.json` | `fa164f42816630c202912c48883eab234849e46e78fe8ccfb73372919d97227a` | Completed 10-row patch-id adjudication, 4 PASS / 6 FAIL; excluded. |
| `squash-assistant-multi-relation-v1/summary.json` | `65467bf90bf20cab39b89bbfe78b0ede52637cb62fd3a8bf723ffcd37197eb2e` | Multi-member compositional relation closure. |
| `squash-assistant-multi-member-same-file-v1/summary.json` | `c170e8d7cc331abc62a8e506434646b0aa656d4fc84c2a61445ff3c9b16ef114` | 3,286 candidates / 472 alias classes; same-file only. |
| `squash-assistant-multi-fix-context-v5-no-actual/matches.jsonl` | `5b1f7331fc98ddeac540018d0179c2103799e2f49a360b16b8850f90472a79ae` | 288 routed matches, 164 exact-unambiguous candidates; positive routing only. |
| `squash-assistant-multi-fix-context-deepseek-v1/results.jsonl` | `da7b3267cfe305e23ab5fc62e4f7297de0d2ffcd3b562612cd39827016b06545` | 12 model-positive, 5 inconclusive, 106 negative reviews; all diagnostic. |

Selection priority was deterministic: remaining model-positive rows first; the same-fix sibling negative next; unresolved exact-context rows next; then the highest-confidence exact noncausal controls from distinct repositories. The selected public IDs are absent from the frozen documents and the 301-ID seed exclusion array.

## Row-level adjudication

`artifact fix` is the fix object recorded by the routing artifact. Where that object is an aggregate/release merge, `mechanism fix` names the actual advisory repair.

| # | Public identity and repo | Atomic member (parent) -> carrier -> fix | Squash survival | Parent baseline and same-mechanism result | Release/advisory witness | Verdict |
|---|---|---|---|---|---|---|
| 1 | [CVE-2026-55435 / GHSA-WQXV-W64V-5WH6](https://github.com/coder/coder/security/advisories/GHSA-wqxv-w64v-5wh6), `coder/coder`, PR 25625 | `2cda32c19f1fa6b832065aba8442f7172d4a763a` (`ef3f95a7af380e64e41717e978904db2ea30bc52`) -> `eddd4a8c2f8c4726cb4e5f81ac3111ef27d36f2e` -> `0d2c9f904a8b75b888140fcc8fbf4633660cc787` | **Semantic survival.** Carrier retains delegated `KeyId` authentication and secret-check bypass; only ambiguous-input error handling changes. Whole-patch IDs differ (`b8761267…` / `c9b4a9c4…`) because the squash includes review changes. | Parent already has the advisory's missing `user.Status` check on the ordinary token path. Member adds a distinct trusted in-process delegated path with the same omission, and the fix adds the common active-user check. What is unclosed is whether a suspended attacker can reach that trusted path independently of the already-vulnerable token path. | Carrier is in `v2.34.0`; repository advisory says fixes are `v2.32.7`, `v2.33.8`, `v2.34.2`. Cached tags show `v2.34.0`/`.1` contain the carrier before the main fix. | **UNKNOWN** — plausible new-surface contributor, not publication-grade without delegated-path reachability. |
| 2 | [CVE-2026-47090 / GHSA-F378-WF84-8J5H](https://github.com/jarrodwatts/claude-hud/issues/485), `jarrodwatts/claude-hud`, PR 76 | `c30a30a4ce3d52e98b1e5c1f2c50d34294612233` (`f4e2493863a3550794d47fe02f9e922801258fb1`) -> `1cffbdd57b4225ba79c8341b8f44800a210cc211` -> `234d9aad919b51326a43bcf90b45ae35c23afc30` | `src/render/lines/project.ts` blob is exactly identical at member/carrier: `2d52704a0520b257f95b72c993f1fe007d192ab9`. | Parent `src/render/session-line.ts` already emits raw cwd/branch. Member copies that behavior into a new expanded/default layout but contains no OSC-8 `hyperlink`, `branchUrl`, or URI construction. Those were added later by non-member history; fix repairs that later hyperlink code. Parent-baseline and same-mechanism gates fail. | Official CNA/GHSA snapshot says vulnerable through `0.0.12`; cached stable tags `v0.0.9`-`v0.0.12` contain the carrier and not the fix; `v0.1.0` contains the fix. | **REJECT_NONCAUSAL** — survived integration/layout surface, not the advisory mechanism. |
| 3 | [CVE-2026-47092 / GHSA-P5QQ-V9MC-39FF](https://github.com/jarrodwatts/claude-hud/issues/485), same repo/PR and same three SHAs as row 2 | Same exact member/carrier transfer. | Same as row 2. | Candidate does not touch `src/version.ts` or `COMSPEC`; the fix's independent `windowsCmdImpl` hunk replaces attacker-controlled `process.env.COMSPEC`. Same fix commit and chronology are not causal linkage. | Same released containment as row 2; advisory-specific mechanism is independent. | **REJECT_NONCAUSAL** — within-fix negative control. |
| 4 | [CVE-2026-39411 / GHSA-5MWJ-V5JW-5C97](https://github.com/lobehub/lobehub/security/advisories/GHSA-5mwj-v5jw-5c97), `lobehub/lobehub`, PR 12799 | `baa477352fb27b7856be4e4b55fa82fc5319a641` (`96916211b3204e0829a76c4a056a0bc996ab192f`) -> `e67bcb257138254a04adee6da8359e7737853eda` -> `3327b293d66c013f076cbc16cdbd05a61a3d0428` | Exact blobs at member/carrier: `apps/cli/src/api/http.ts` `fa967fcab85eb0acdc9ff1895fad76155b36e97e`; CLI test `2465f01adb1a901867fe1eb07a1821241648a1e8`. | Parent already contains `SECRET_XOR_KEY`, server XOR decoder, `X-lobe-chat-auth` trust, and `/webapi` auth decision. Member only makes the authenticated CLI send an empty XOR header; it creates no server route, bypass, or trust decision. Fix removes both the pre-existing server root and this incidental client integration. | Reviewed repo advisory fixes in `2.1.48`; stable `v2.1.41`-`v2.1.47` contain carrier but not fix. | **REJECT_NONCAUSAL** — exact integration-only transfer. |
| 5 | [CVE-2026-56121 / GHSA-Q63X-9PFM-MJX4](https://github.com/feast-dev/feast/commit/835cda8e2c1359f1f496ad72701dbd6a73bdb25a), `feast-dev/feast`, PR 5879 | `165d8c49ef72c48f62e90caf07f0a8d65b334629` (`6214d05963906f7c28b1ea7ea57af831879024b7`) -> `c1718b75522df978a33dd655050500c1fc71bb92` -> `835cda8e2c1359f1f496ad72701dbd6a73bdb25a` | Semantic refactor survives; carrier adds typing/formatting, so whole-patch IDs differ (`d7afc5f8…` / `86482a05…`). | Full parent proves `OnDemandFeatureView.from_proto(skip_udf=False)` already called `PandasTransformation.from_proto` / `PythonTransformation.from_proto` without honoring `skip_udf`. Member extracts the identical calls into `_parse_transformation_from_proto` and still ignores the existing parameter. Fix propagates `skip_udf`. This is preservation/movement of a pre-existing unsafe deserialization path. | Carrier ships in `v0.60.0`-`v0.62.0`; fix in `v0.63.0`, but released chronology cannot cure failed parent baseline. | **REJECT_NONCAUSAL** — refactor preservation. |
| 6 | [CVE-2026-60118 / GHSA-2H54-CPRV-VJ74](https://github.com/HiEventsDev/Hi.Events/security/advisories/GHSA-2h54-cprv-vj74), `HiEventsDev/Hi.Events`, PR 1104 | `72ad90ebe57aa595091fd1f3eb6f5e45c765779d` (`a0d09e514c24b223d8bb9511676fa466ca3ee865`) -> `48e75304e97e22b036dd6fdfb5a66ff69ff30028` -> artifact release merge `8da9feedc984ce8330e5c84f87c5654536b1e28f`; mechanism fix `9eec95e6176f500b71bf633986243045ca78cefb` | Delete/archive/admin UX lands in its squash; whole patches differ after review (`1e8da9fe…` / `bb136f3d…`). | Candidate touches deletion/archive actions and generated locales, not `OrderCreateRequestValidationService`. Its parent already accepts referenced product/price IDs without a visibility gate. Exact mechanism fix changes only that service and its test. Locale overlap in the aggregate release merge is incidental. | First-party advisory points to PR 1259 / `9eec95e…`; `8da9feed…` is the `v1.11.0-beta` merge containing both security fixes. | **REJECT_NONCAUSAL**. |
| 7 | [CVE-2026-60119 / GHSA-2GGX-79G6-2JMJ](https://github.com/HiEventsDev/Hi.Events/security/advisories/GHSA-2ggx-79g6-2jmj), same repo, PR 1166 | `0d44a961bf1a7686a6c9be4446bd8940e14d1456` (`fa8e2e55be7dbe04a72c38abeeaa7e0fc41c495e`) -> `3109cad047dcbc0000d6fd40d89e102977226619` -> artifact merge `8da9feedc984ce8330e5c84f87c5654536b1e28f`; mechanism fix `1e36b070771801ed7113255ef7b3a7f271a2a794` | Tracking-pixel/cookie-consent feature lands, with other PR members; whole patches differ (`a631fe87…` / `3da45b15…`). | Parent already has raw `JSON.stringify(dehydratedState)` in `frontend/server.js` and `JSON.stringify(schemaOrgJSONLD)` in `EventDocumentHead`. Candidate touches neither exact sink nor the later `safeScriptJson` helper. Exact mechanism fix changes those sinks plus title validation. | First-party advisory points to PR 1260 / `1e36b070…`; the aggregate merge is only release topology. | **REJECT_NONCAUSAL**. |
| 8 | [CVE-2026-45666 / GHSA-X3QM-P8HR-3C3H](https://github.com/open-webui/open-webui/security/advisories/GHSA-x3qm-p8hr-3c3h), `open-webui/open-webui`, PR 19296 | `00ef2399b20bdc574d06928ce58493183ba79a63` (`17389e1b66950f7e4ec938d4688f54cefbf835ca`) -> `902c6cfbeaa3c0c547598cd9f072cbe12077bcfd` -> `de3317e26bb67a2a7ea015a183bbd1d369880ebd` | Async embedding refactor lands with review follow-ups; whole-patch IDs differ (`5c6c7187…` / `71820702…`). | Candidate changes retrieval/embedding helpers. It does not change the per-ID notes router or ownership policy; `Notes` appears only as unchanged retrieval context. Fix adds note ownership/access-grant checks. Shared files and ancestry are incidental. | Reviewed repo advisory names exact fix and release `v0.8.11`. | **REJECT_NONCAUSAL**. |
| 9 | [CVE-2025-69255 / GHSA-GW2X-Q739-QHCR](https://github.com/rustfs/rustfs/security/advisories/GHSA-gw2x-q739-qhcr), `rustfs/rustfs`, PR 309 | `c676dd51741b1c763effc6ef6e71b802ff7f9e6c` (`6c37e1cb2aa083da80fa27cccb1f35e049070217`) -> `d5aef963f9bf1d1cfdbf505533d86129c6b2658f` -> `eb33e82b56ed11fd12bb39416359d8d60737dc7a` | Auth test-only member lands with formatting/script follow-ups; whole-patch IDs differ (`3b55cda2…` / `bc8b99f5…`). | Candidate adds only `#[cfg(test)]` authentication tests in `rustfs/src/auth.rs`. It does not touch production `GetMetrics`, `tonic_service.rs`, or rmp-serde `unwrap`; exact fix repairs that handler. | Reviewed repo advisory names the fix and patched alpha.78. | **REJECT_NONCAUSAL** — test-only negative control. |
| 10 | [CVE-2026-54686 / GHSA-9W2V-JHWW-VM85](https://github.com/warpdotdev/warp/security/advisories/GHSA-9w2v-jhww-vm85), `warpdotdev/warp`, PR 11465 | `c2f61d89af52679db3b4ba4d71af63f5f73aa51f` (`e23b5e9b418b1741cc0cb3b1dc9317b0229400a3`) -> `81d349656202acf639c9514591bae4c0afb61c6f` -> `32d21d15c9a3da1a923d1ed66226cf5cba081d16` | Import-order normalization is included in a large feature squash; whole-patch IDs differ (`4d37c321…` / `a8f33e66…`). | Commit explicitly says "No semantic changes" and only reorders imports. Fix adds client-generated session IDs, registers them, and rejects missing/unregistered DCS lifecycle hooks across bootstrap/parser/state paths. Exact-line import overlap is noncausal. | First-party CNA/repo advisory names `32d21d15…` and the fixed stable build. | **REJECT_NONCAUSAL** — formatting-only negative control. |

All nine carrier-to-fix ancestry checks returned `0` from `git merge-base --is-ancestor`; for Hi.Events the checks use the exact mechanism fixes (`9eec95e…`, `1e36b070…`), not merely the release merge. This proves chronology only.

## Clone snapshot heads

| Cache (read only) | Observed HEAD |
|---|---|
| `/home/hanqing/.cache/cve-analyzer/repos/coder_coder` | `119d436071cc88c004689cdd06c5c5b60f8a02b6` |
| `.ai-slop/cache/cve-analyzer/repos/v2_github.com_claude-hud_98984531a65e57f47c70f11b98df543b64612a9f55b5d3ee72fa1f4edc054066` | `e39bafc6d778d61f41592eced53f8aa58bf5239c` |
| `/home/hanqing/.cache/cve-analyzer/repos/lobehub_lobehub` | `f84a363b758bf0c745560a0e24c3ee645c29696e` |
| `/home/hanqing/.cache/cve-analyzer/repos/feast-dev_feast` | `6f5203ac50284c4fc5884740cbc3bbca7fd1c7d0` |
| `.ai-slop/cache/cve-analyzer/repos/v2_github.com_hi.events_6feabe7652f7ab96d8cadac84bb2164f1ac282fa36bd3f0e49c2cf91c4dff6d8` | `9de8863ae7db5cc8ab17a580df8bd6c5fe79c663` |
| `/home/hanqing/.cache/cve-analyzer/repos/open-webui_open-webui` | `1ac3dd4a893e13803e7b889611303c4a7a5cc470` |
| `/home/hanqing/.cache/cve-analyzer/repos/rustfs_rustfs` | `aac4a6c25f00684e00f467a380a41db10dccb2e2` |
| `.ai-slop/cache/cve-analyzer/repos/v2_github.com_warp_2489406195ce18af84e8d731f261c0c2e2ad89fb48760e5a13bd4e7b81bd5e7d` | `c16fd426d2ceaeed2f16217d7985dda324c38c9b` |

Selected first-party advisory packet hashes: repo 17 `a79b7c0f25b090d23e17b55b0bdcb1bb08bc13c2bbe99f415eae7c8d7da7fb64`; repo 25 `a44a391a51d0cbc92522398a1a6646b77178a5070abad5180972971dcf18928a`; repo 34 `c84cdcb58485e2757b3b41f82c9e289fa0bb46ac0eb2f7aca82edecb3a96a884`; repo 36 `9ac048eb7b076cd39902a52f3a62b72140ed7826c34037b48d37415da243cf00`; repo 44 `73f3279d04b3b58c0ef7350ec0b3ecab3aec7a6899babb91d38bbc83ec635794`; repo 65 `01d1ea788143ce2dc058fe650defe93438c4b4ea6816eadfce70f14c0d768fdb`; repo 75 `3d97c34a87e98c0fc9fea0e8a373faf4f2e4b73078b149c5cfa7c02a60561a93`; repo 97 `1e6f3402b18b3d729b44285c855bd8a92d06baf7c07f1187b337c8e47742273b`. Each selected packet reports `advisory_source_status: first_party`; live advisory state was not refreshed.

## Exact replay commands

The following commands are the minimal replay set used. Replace `$repo` only with the corresponding read-only cache path from the table above.

```sh
# Freeze checkout/document/artifact state.
git status --porcelain=v2 -z | sha256sum
sha256sum docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md \
  docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
  autoresearch/orchestrator-260811-atomic150/squash-assistant-multi-fix-context-v5-no-actual/matches.jsonl \
  autoresearch/orchestrator-260811-atomic150/squash-assistant-multi-fix-context-deepseek-v1/results.jsonl

# Verify objects, exact parent, carrier/fix chronology, and whole-patch diagnostics.
git -C "$repo" show -s --format='%H%n%P%n%s%n%b' "$member" "$carrier" "$fix"
git -C "$repo" merge-base --is-ancestor "$carrier" "$fix"
git -C "$repo" show --pretty=email --binary "$member" | git patch-id --stable
git -C "$repo" show --pretty=email --binary "$carrier" | git patch-id --stable

# Release containment (diagnostic unless advisory identity and mechanism also close).
git -C "$repo" tag --contains "$carrier" --no-contains "$fix" | sort -V

# Coder parent/member/carrier/fix authorization body.
git -C /home/hanqing/.cache/cve-analyzer/repos/coder_coder show \
  ef3f95a7af380e64e41717e978904db2ea30bc52:coderd/aibridgedserver/aibridgedserver.go
git -C /home/hanqing/.cache/cve-analyzer/repos/coder_coder show \
  eddd4a8c2f8c4726cb4e5f81ac3111ef27d36f2e:coderd/aibridgedserver/aibridgedserver.go
git -C /home/hanqing/.cache/cve-analyzer/repos/coder_coder show \
  0d2c9f904a8b75b888140fcc8fbf4633660cc787:coderd/aibridgedserver/aibridgedserver.go

# Exact transfer blobs.
git -C "$claude_hud_repo" rev-parse \
  c30a30a4ce3d52e98b1e5c1f2c50d34294612233:src/render/lines/project.ts \
  1cffbdd57b4225ba79c8341b8f44800a210cc211:src/render/lines/project.ts
git -C /home/hanqing/.cache/cve-analyzer/repos/lobehub_lobehub rev-parse \
  baa477352fb27b7856be4e4b55fa82fc5319a641:apps/cli/src/api/http.ts \
  e67bcb257138254a04adee6da8359e7737853eda:apps/cli/src/api/http.ts

# Parent-baseline controls.
git -C "$claude_hud_repo" show \
  f4e2493863a3550794d47fe02f9e922801258fb1:src/render/session-line.ts
git -C /home/hanqing/.cache/cve-analyzer/repos/lobehub_lobehub grep -n \
  -E 'LobeHub · LobeHub|X-lobe-chat-auth|LOBE_CHAT_AUTH_HEADER' \
  96916211b3204e0829a76c4a056a0bc996ab192f
git -C /home/hanqing/.cache/cve-analyzer/repos/feast-dev_feast show \
  6214d05963906f7c28b1ea7ea57af831879024b7:sdk/python/feast/on_demand_feature_view.py
git -C "$hi_events_repo" grep -n -E 'JSON.stringify|application/ld\\+json' \
  fa8e2e55be7dbe04a72c38abeeaa7e0fc41c495e -- frontend/server.js \
  frontend/src/components/common/EventDocumentHead/index.tsx

# Mechanism-file disjointness controls.
git -C "$hi_events_repo" diff-tree --no-commit-id --name-only -r \
  72ad90ebe57aa595091fd1f3eb6f5e45c765779d
git -C "$hi_events_repo" diff-tree --no-commit-id --name-only -r \
  9eec95e6176f500b71bf633986243045ca78cefb
git -C /home/hanqing/.cache/cve-analyzer/repos/rustfs_rustfs diff-tree \
  --no-commit-id --name-status -r c676dd51741b1c763effc6ef6e71b802ff7f9e6c
git -C "$warp_repo" show --format=fuller \
  c2f61d89af52679db3b4ba4d71af63f5f73aa51f
```

## Claim boundary and blockers

- Relation recovery, patch IDs, identical blobs, same-file/fix-context matches, model votes, ancestry, tags, and tests are diagnostic until the parent delta and advisory-specific reversal close.
- `REJECT_NONCAUSAL` rejects only the named AI-member causal edge. It does not dispute the advisory, fix, or released affected range.
- Whole-commit patch IDs normally differ for multi-member squashes. Exact security-file blobs or semantic hunk replay were used instead; patch-id mismatch alone was never treated as erasure.
- No selected edge earned `REJECT_ERASED`; the known OpenClaw erased control was excluded as already adjudicated.
- Coder remains `UNKNOWN` because the new delegated path is trusted/in-process and external suspended-user reachability was not closed from the frozen evidence. Promoting it requires a first-party call-chain or test proving a suspended user can invoke that path, not another same-file or ancestry match.
- The first-party advisory packets are frozen local extractions. This shard made no network/API call and therefore does not claim live-current advisory state.
