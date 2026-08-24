# Unadjudicated squash/compositional lineage tail

Started: `2026-08-12T12:17:44-04:00`

Evidence snapshot: `2026-08-12T12:37:40-04:00` (`America/New_York`)

Owned output: `autoresearch/herdr-260812-squash-lineage/`

## Result

The ten highest-priority remaining multi-member squash routes produced **0 PASS, 0 REJECT_ERASED, 9 REJECT_NONCAUSAL, and 1 UNKNOWN**.

The important negative control is that landing is not causality. Every selected member left some exact or semantic content in its carrier. Nine nevertheless fail the parent-baseline or advisory-specific same-mechanism test. Coder remains `UNKNOWN`: its member adds a real delegated authorization surface with the same missing active-user check repaired later, but the frozen evidence does not prove that a suspended attacker can reach that trusted in-process path independently of the pre-existing ordinary-token flaw.

This is a completed bounded tail adjudication, not a new positive-count or global-completeness claim.

| Verdict | Count |
|---|---:|
| `PASS` | 0 |
| `REJECT_ERASED` | 0 |
| `REJECT_NONCAUSAL` | 9 |
| `UNKNOWN` | 1 |

## Scope and immutable boundary

The shared checkout was read at branch `dev`, commit `6c0d2084fd1240341d6d1b9f9096252490168f0b`. It was intentionally dirty. `git status --porcelain=v2 -z | sha256sum` was `c2bdbe34a738ced16f7d20bc3ce46045cb1d1dc60db542cc80fc95ccdf2ad17d` at the evidence snapshot; this binds a volatile point in time and is not a clean-tree assertion. Other agents continued working, so conclusions bind to the named input hashes and Git objects, not current mutable paths or branch tips.

All cached clones were read only. No fetch, build, test suite, cache mutation, staging, commit, cleanup, or full-corpus rerun was performed. The eight observed clone `HEAD`s and all selected edge fields are frozen in [`snapshot.json`](snapshot.json). Each selected carrier is an ancestor of its exact fix (`git merge-base --is-ancestor` exit `0`); this proves chronology only.

An independent primary-source shard produced [`agent_research.md`](agent_research.md), SHA-256 `4156beadd468333143ee5d1bb361abc69eb3ad412070493b9b7eaf26c5ec00af`. It was used to cross-check advisory identities, release witnesses, and parent controls. Its alternative control-heavy ten-row draft is not the terminal ranking: the final selection below retains the ten unresolved positive/inconclusive routes after class-level exclusions.

## Inputs, exclusions, and priority rule

Newest current documents were read first. The following are the principal frozen exclusion sources; the complete 2026-08-11/12 top-level document union was also searched.

| Input | SHA-256 | Exclusion boundary |
|---|---|---|
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` | Current combined report and completed component batches. |
| `docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` | `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` | All 12 OpenClaw frontier rows; none were reconsidered. |
| `docs/RESEARCH-SQUASH-SINGLE-MEMBER-2026-08-11.md` | `7d5902ace0d5f0431e8c9e14a7c1673a72f83c1f8f4807144b9630a9fd82e276` | Completed 10-class single-member batch. |
| `docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md` | `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` | Frozen strict-200 public identities/components. |
| Post-135 batches B/C/D/E | `318912…` / `b1e03c…` / `3a8482…` / `f889a1…` | All completed post-135 rows and controls. |
| `strict-200-v3/ledger.jsonl` | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` | Machine-readable strict-200 exclusion. |
| `squash-assistant-multi-exact-seed-v1/excluded-public-ids.json` | `599892e76320613b624a50406cd32d4400d9759097f3abfa937d7ffcba3c6337` | Seed-time 301-ID exclusion, augmented by the newer document union. |

Rows were excluded at public-identity/class level, not merely by exact candidate SHA. This prevents redoing sibling members of an already completed advisory component. It excludes, among others, all OpenClaw rows, MLflow CVE-2026-8147, the two Actual CSV components sharing the already adjudicated carrier/fix, and the completed Ouroboros/Fission/registry rows. An exact selected-SHA and selected-public-ID search over `docs/*.md` returned no matches.

The remaining queue was ordered by maximum diagnostic model confidence: `AI_CAUSAL`/`INCONCLUSIVE` routes first, descending; duplicate member/carrier/fix routes were coalesced. Aggregate release merges were replaced with exact advisory mechanism fixes when the relation graph and first-party packet supplied them. The selected scores were `0.82, 0.82, 0.78, 0.76, 0.72, 0.65, 0.65, 0.60, 0.60, 0.55`. Scores only rank review work.

Key topology/routing snapshots:

| Artifact | SHA-256 | What it can establish |
|---|---|---|
| `squash-assistant-multi-relation-v1/summary.json` | `65467bf90bf20cab39b89bbfe78b0ede52637cb62fd3a8bf723ffcd37197eb2e` | 6,804/6,804 roots resolved; 357,518 conserved edges: 47,310 direct and 310,208 composite. Topology only. |
| `squash-assistant-multi-relation-v1/relations.jsonl` | `dbfb25f3b3643233acc4a2a4fff83c42f9bc9ea0e29bba5af1c1d1b84ec2b08b` | Exact PR member-to-landed-squash relations. |
| `squash-assistant-multi-member-same-file-v1/summary.json` | `c170e8d7cc331abc62a8e506434646b0aa656d4fc84c2a61445ff3c9b16ef114` | 3,286 candidates / 472 classes; same-file routing only. |
| `squash-assistant-multi-fix-context-v5-no-actual/matches.jsonl` | `5b1f7331fc98ddeac540018d0179c2103799e2f49a360b16b8850f90472a79ae` | 288 routed matches, 164 exact-unambiguous; positive routing only. |
| Three model result ledgers | `da7b3267…`, `b173c420…`, `fe9b9666…` | Diagnostic priority, never a verdict. |

## Decision tests

For each edge:

1. **Squash survival.** Compare stable whole-patch IDs, then count candidate-changed paths whose candidate/carrier blobs are identical, rewritten, or absent. Patch-ID mismatch in a multi-member squash is not erasure. A security-relevant exact blob or semantic hunk decides survival.
2. **Parent baseline.** Inspect `member^`. If the advisory behavior is already present, the member cannot be its direct origin. A genuinely new and independently reachable vulnerable surface may remain possible, but must be proven.
3. **Same mechanism.** Require the candidate delta, advisory behavior, and exact fix reversal to share the security mechanism. Same file, ancestry, fix context, shared helper, or broad feature family is insufficient.
4. **Identity and release.** Confirm the first-party advisory/PR/commit identity and a released containment witness. Tags alone do not repair a failed mechanism test. Missing identity or release prevents a positive claim.

`PASS` requires all four. `REJECT_ERASED` means the purported security-relevant member delta did not land. `REJECT_NONCAUSAL` means it landed but fails parent baseline or same mechanism. `UNKNOWN` preserves a plausible chain with an unclosed required fact.

## Row-level adjudication

### 1. LobeHub — `REJECT_NONCAUSAL`

- Identity: [CVE-2026-39411 / GHSA-5MWJ-V5JW-5C97](https://github.com/lobehub/lobehub/security/advisories/GHSA-5mwj-v5jw-5c97), PR 12799.
- Lineage: parent `96916211b3204e0829a76c4a056a0bc996ab192f` -> member `baa477352fb27b7856be4e4b55fa82fc5319a641` -> carrier `e67bcb257138254a04adee6da8359e7737853eda` -> fix `3327b293d66c013f076cbc16cdbd05a61a3d0428`.
- Survival: exact. All 7 member-changed blobs equal the carrier blobs. `apps/cli/src/api/http.ts` is `fa967fcab85eb0acdc9ff1895fad76155b36e97e` at both commits. Whole-patch IDs differ (`136d22a4…` vs `6259e77e…`) only because the carrier is the full squash.
- Control: the parent already contains the hard-coded XOR key, server decoder, `X-lobe-chat-auth` header trust, and truthy `apiKey` authorization decision. The member makes the authenticated CLI send an empty XOR header; it adds no server route, attacker-controlled decision, or trust primitive. The fix removes this client integration while also removing the pre-existing server root.
- Release: first-party packet names fixed `v2.1.48`; local tag containment agrees that the exact fix starts at `v2.1.48` while carrier-only stable/canary tags precede it.
- Boundary: exact removal by a fix is not enough when the parent already exposes the advisory bypass. This is an integration-only transfer.

### 2. Coder — `UNKNOWN`

- Identity: [CVE-2026-55435 / GHSA-WQXV-W64V-5WH6](https://github.com/coder/coder/security/advisories/GHSA-wqxv-w64v-5wh6), PR 25625.
- Lineage: parent `ef3f95a7af380e64e41717e978904db2ea30bc52` -> member `2cda32c19f1fa6b832065aba8442f7172d4a763a` -> carrier `eddd4a8c2f8c4726cb4e5f81ac3111ef27d36f2e` -> fix `0d2c9f904a8b75b888140fcc8fbf4633660cc787`.
- Survival: semantic with review rewrite: 5/9 candidate blobs exact and 4/9 rewritten; the delegated `KeyId` branch remains. Whole-patch IDs: `b8761267…` / `c9b4a9c4…`.
- Parent control: ordinary secret-bearing API-token authorization already fetches the user without checking `user.Status`, so suspended users' existing keys already satisfy the advisory behavior.
- Same-mechanism evidence: the member adds a distinct `KeyId`-only path, explicitly skips secret validation, and says trust is established at the in-process transport boundary. The fix adds the common `user.Status == Active` check and tests both ordinary and delegated paths.
- Missing fact: no frozen first-party call chain or test proves that a suspended external user can invoke the trusted delegated path independently of the already-vulnerable ordinary-token path. Rejecting it would discard a plausible same-mechanism new surface; passing it would infer attacker reachability.
- Release: the advisory names `v2.32.7`, `v2.33.8`, and `v2.34.2`. The cached mainline exact fix object first appears in `v2.35.0`; the earlier patched releases are backports with different commit identities.

### 3. Warp branch selector — `REJECT_NONCAUSAL`

- Identity: [CVE-2026-48719 / GHSA-HGVX-4XVM-39PW](https://github.com/warpdotdev/warp/security/advisories/GHSA-hgvx-4xvm-39pw), PR 10610.
- Lineage: parent `35cb40c31c7ae9707bfb3bf5f690973e19d4ea69` -> member `bfb1c83ffe80db83ff56a364398e041d804b6c12` -> carrier `b9a175372020bd5d6ce8e62f5fd881d927b3a9ad` -> fix `4295ec08d01912fe355351547e541277f29288cd`.
- Survival: all four member files are semantically present but rewritten by review/rustfmt; patch IDs `6fb16926…` / `875c1f19…`.
- Control: the advisory's attacker publishes a crafted **existing remote branch name** and the victim selects it. The parent already feeds that branch through `GitBranch::command()` and POSIX-only `shell_single_quote`. The member adds a sibling `CreateGitBranch` path from the victim's locally typed unmatched query. The fix converts both paths to typed, shell-specific rendering, but the member neither creates nor extends the advisory's remote-branch input route.
- Release: first-party packet names fixed `0.2026.05.06.15.42.stable_01`; cached object containment also shows a fix-containing dev tag. Chronology does not overcome the failed advisory-specific route test.

### 4. Claude HUD — `REJECT_NONCAUSAL`

- Identity: [CVE-2026-47090 / GHSA-F378-WF84-8J5H](https://github.com/jarrodwatts/claude-hud/issues/485), PR 76.
- Lineage: parent `f4e2493863a3550794d47fe02f9e922801258fb1` -> member `c30a30a4ce3d52e98b1e5c1f2c50d34294612233` -> carrier `1cffbdd57b4225ba79c8341b8f44800a210cc211` -> fix `234d9aad919b51326a43bcf90b45ae35c23afc30`.
- Survival: 13/15 exact blobs. The security-routed file `src/render/lines/project.ts` is exactly `2d52704a0520b257f95b72c993f1fe007d192ab9` at member and carrier. The full member patch ID is unavailable because cached blob `cd7a6d39…` is missing; a partial pipeline value was discarded. Target-blob evidence remains exact.
- Control: the parent already emits raw cwd/branch in `src/render/session-line.ts`. The member copies plain colored text into a new expanded-layout file but contains no OSC-8 `hyperlink`, `branchUrl`, or URI construction. Non-member commit `5869a69c251bdcb8ed1b262d038b067dcf26fb39` later introduces clickable OSC-8 links; the fix hardens that later path.
- Within-fix control: the same fix also repairs `COMSPEC` lookup (CVE-2026-47092), which the member never touches. This demonstrates why same fix and same file are insufficient.
- Release: carrier appears in `v0.0.10`-`v0.0.12`; fix begins at `v0.1.0` in the cached tags.

### 5. FrontMCP — `REJECT_NONCAUSAL`

- Identity: routed as `CVE-2026-67531`; the packet explicitly records `advisory_source_status: missing_first_party` and contains no advisory object.
- Lineage: parent `ab572fba54b4a37db49ee22c49fe8b1fa340282d` -> member `658f1ba788ac9527f5f50b9741ab8d9a4b7bee8a` -> carrier `e41227a223e482e4155380cda03cafc8decbf026` -> routed fix `209cddd19a8d4db0777f725b527818da7df6f67f`.
- Survival: mixed/reworked integration: 3/51 exact blobs, 16 rewritten, 32 absent at the original paths. `ToolSearch` interfaces survive semantically; the token and much Vectoria code are reworked. Patch IDs: `03d7ccb8…` / `cac3ea6b…`.
- Control: candidate/fix production-path intersection is empty; only `libs/sdk/package.json`, root `package.json`, and `yarn.lock` intersect. The parent already has the CodeCall execute skeleton and `getTool` contract/TODO. The member adds vector search and tool-search interfaces; it does not implement `execute.tool.ts`, expose raw Zod schemas, or create the constructor escape. Other carrier members/later history implement that boundary. The fix serializes schemas to plain JSON and blocks internal/meta tools.
- Release: cached tags contain the exact fix at `v1.5.7`, but without a recovered first-party advisory this is diagnostic release topology, not advisory-grade containment.
- Boundary: first-party absence independently forbids `PASS`; the code delta is affirmatively noncausal relative to the routed fix, so this is not `UNKNOWN`.

### 6. Feast — `REJECT_NONCAUSAL`

- Identity: [CVE-2026-56121 / GHSA-Q63X-9PFM-MJX4](https://github.com/feast-dev/feast/commit/835cda8e2c1359f1f496ad72701dbd6a73bdb25a), PR 5879.
- Lineage: parent `6214d05963906f7c28b1ea7ea57af831879024b7` -> member `165d8c49ef72c48f62e90caf07f0a8d65b334629` -> carrier `c1718b75522df978a33dd655050500c1fc71bb92` -> fix `835cda8e2c1359f1f496ad72701dbd6a73bdb25a`.
- Survival: the single changed file is semantically preserved with typing/formatting rewrite; patch IDs `d7afc5f8…` / `86482a05…`.
- Control: full parent source already calls `PandasTransformation.from_proto` / `PythonTransformation.from_proto` while `skip_udf=False` is ineffective. The member's own message says it preserves behavior and extracts those identical calls into `_parse_transformation_from_proto`. The fix propagates `skip_udf` to stop unsafe UDF deserialization. This is movement of a pre-existing sink, not its origin or extension.
- Release: carrier is contained by `v0.60.0`-`v0.62.0`; exact fix begins at `v0.63.0`.

### 7. Hi.Events PR 1104 member — `REJECT_NONCAUSAL`

- Identity: [CVE-2026-60119 / GHSA-2GGX-79G6-2JMJ](https://github.com/HiEventsDev/Hi.Events/security/advisories/GHSA-2ggx-79g6-2jmj).
- Lineage: parent `a0d09e514c24b223d8bb9511676fa466ca3ee865` -> member `72ad90ebe57aa595091fd1f3eb6f5e45c765779d` -> carrier `48e75304e97e22b036dd6fdfb5a66ff69ff30028` -> exact fix `1e36b070771801ed7113255ef7b3a7f271a2a794`.
- Survival: delete/archive/admin UX lands almost exactly: 65/68 blobs exact, 3 rewritten; patch IDs `1e8da9fe…` / `bb136f3d…`.
- Control: zero changed-path intersection with the nine exact XSS-fix paths. The parent already embeds `JSON.stringify(dehydratedState)` in `frontend/server.js` and `JSON.stringify(schemaOrgJSONLD)` in `EventDocumentHead`. The member neither changes those sinks nor adds `safeScriptJson`.

### 8. Hi.Events PR 1166 tracking member — `REJECT_NONCAUSAL`

- Lineage: parent `fa8e2e55be7dbe04a72c38abeeaa7e0fc41c495e` -> member `0d44a961bf1a7686a6c9be4446bd8940e14d1456` -> carrier `3109cad047dcbc0000d6fd40d89e102977226619` -> exact fix `1e36b070771801ed7113255ef7b3a7f271a2a794`.
- Survival: 17/61 exact blobs and 44 rewritten; patch IDs `a631fe87…` / `3da45b15…`.
- Control: the tracking-pixel/cookie-consent feature touches `EventHomepage` and tracking plugins, but has zero path intersection with the exact event-title repair. Its parent already contains both raw JSON sinks. Similar inline-script subject matter does not establish the event-title `</script>` mechanism.

### 9. Hi.Events PR 1166 follow-up member — `REJECT_NONCAUSAL`

- Lineage: parent `e6d8b7e4dfb384baf603eaf0783fb7248ff0a5e0` -> member `b8dbc37c37b7d3ef784665a02aa26998b22991f1` -> the same carrier `3109cad047dcbc0000d6fd40d89e102977226619` -> exact fix `1e36b070771801ed7113255ef7b3a7f271a2a794`.
- Survival: exact, 42/42 blobs; patch IDs `bc558715…` / `3da45b15…`.
- Control: cookie-consent/tracking audit follow-up, zero path intersection with the exact XSS fix, and both vulnerable JSON sinks already exist in the parent.
- Shared release control for rows 7-9: the model packet used aggregate release merge `8da9feedc984ce8330e5c84f87c5654536b1e28f`. First-party advisory recovery identifies `1e36b070…` as the XSS fix; local tags place it in `v.1.11.0-beta`. Aggregate locale overlap was discarded.

### 10. DeerFlow — `REJECT_NONCAUSAL`

- Identity: `CVE-2026-34430 / GHSA-GXX6-2VWG-3GC3`; first-party witnesses are [PR 1547](https://github.com/bytedance/deer-flow/pull/1547) and fix `92c7a20cb74addc3038d2131da78f2e239ef542e`.
- Lineage: parent `d664ae5a4b2e3ae34145f6dbdfc6908d955f6402` -> member `edfd0b25dc2e563f155dcd538298d342739231a7` -> carrier `75b7302000c066bf2ff1ba362ee6a6337d6bfc47` -> fix `92c7a20cb74addc3038d2131da78f2e239ef542e`.
- Survival: channel integration lands with rewrite: 6/19 exact and 13 rewritten; patch IDs `12b21ccb…` / `4fd8ea0d…`.
- Control: the parent already contains `LocalSandboxProvider` and the host `bash_tool`. The member adds Feishu/Slack/Telegram channel routing. Candidate/fix intersection is only `README.md` and `config.example.yaml`; it does not change sandbox validation, shell parsing, host execution, or tool registration. The fix disables host bash by default and hardens sandbox/tool policy.
- Release: the read-only clone has no tag containing either carrier or fix. PR/commit identity is first-party, but released containment is not recovered. This independently blocks a positive; the mechanism delta is already noncausal.

## Negative and unknown controls

- No selected member is `REJECT_ERASED`. Exact-file survival ranges from 3/51 to 42/42, with semantic survival in all other cases. The already adjudicated OpenClaw erased row was intentionally excluded.
- Hi.Events is a strong false-positive control: an aggregate release merge created locale overlap, while the recovered exact XSS fix has zero path intersection with all three members and all three parents already contain the sinks.
- Claude HUD is a chronology control: the member's target file is byte-identical in the squash, yet the advisory-specific OSC-8 mechanism is introduced by later non-member history.
- LobeHub and Feast are parent-baseline controls: the fix removes or rewrites member-touched code, but the security behavior predates the member.
- FrontMCP and DeerFlow are integration-surface controls: feature adjacency does not establish the sandbox mechanism.
- Coder is deliberately not forced negative. The trusted delegated path is new and receives the exact later active-user guard; only attacker reachability remains unclosed.

## Exact replay commands and sources

All commands were read-only and run against the frozen objects. `$repo`, `$member`, `$carrier`, and `$fix` are exactly the values in [`snapshot.json`](snapshot.json).

```sh
# Read-only cache locations used below.
warp_repo=.ai-slop/cache/cve-analyzer/repos/v2_github.com_warp_2489406195ce18af84e8d731f261c0c2e2ad89fb48760e5a13bd4e7b81bd5e7d
claude_hud_repo=.ai-slop/cache/cve-analyzer/repos/v2_github.com_claude-hud_98984531a65e57f47c70f11b98df543b64612a9f55b5d3ee72fa1f4edc054066
hi_events_repo=.ai-slop/cache/cve-analyzer/repos/v2_github.com_hi.events_6feabe7652f7ab96d8cadac84bb2164f1ac282fa36bd3f0e49c2cf91c4dff6d8

# Workspace and artifact boundary.
git rev-parse HEAD
git branch --show-current
git status --porcelain=v2 -z | sha256sum
sha256sum docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md \
  docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md \
  docs/RESEARCH-SQUASH-SINGLE-MEMBER-2026-08-11.md \
  autoresearch/orchestrator-260811-atomic150/squash-assistant-multi-relation-v1/relations.jsonl \
  autoresearch/orchestrator-260811-atomic150/squash-assistant-multi-fix-context-v5-no-actual/matches.jsonl

# Exact object, parent, chronology, and patch diagnostics.
git -C "$repo" cat-file -t "$member"
git -C "$repo" rev-parse "$member^"
git -C "$repo" merge-base --is-ancestor "$carrier" "$fix"
git -C "$repo" show --pretty=email --binary "$member" | git patch-id --stable
git -C "$repo" show --pretty=email --binary "$carrier" | git patch-id --stable
git -C "$repo" tag --contains "$carrier" --no-contains "$fix"
git -C "$repo" tag --contains "$fix"

# Changed-path and exact-blob survival.
git -C "$repo" diff-tree --no-commit-id --name-only -r "$member"
git -C "$repo" rev-parse "$member:$file" "$carrier:$file"

# Candidate/fix mechanism intersection.
comm -12 \
  <(git -C "$repo" diff-tree --no-commit-id --name-only -r "$member" | sort) \
  <(git -C "$repo" diff-tree --no-commit-id --name-only -r "$fix" | sort)

# Parent-baseline controls.
git -C /home/hanqing/.cache/cve-analyzer/repos/lobehub_lobehub grep -n \
  -E 'LobeHub · LobeHub|X-lobe-chat-auth|LOBE_CHAT_AUTH_HEADER' \
  96916211b3204e0829a76c4a056a0bc996ab192f
git -C /home/hanqing/.cache/cve-analyzer/repos/coder_coder show \
  ef3f95a7af380e64e41717e978904db2ea30bc52:coderd/aibridgedserver/aibridgedserver.go
git -C "$warp_repo" show \
  35cb40c31c7ae9707bfb3bf5f690973e19d4ea69:app/src/context_chips/display_chip.rs
git -C "$claude_hud_repo" show \
  f4e2493863a3550794d47fe02f9e922801258fb1:src/render/session-line.ts
git -C /home/hanqing/.cache/cve-analyzer/repos/feast-dev_feast show \
  6214d05963906f7c28b1ea7ea57af831879024b7:sdk/python/feast/on_demand_feature_view.py
git -C "$hi_events_repo" grep -n 'JSON.stringify' \
  a0d09e514c24b223d8bb9511676fa466ca3ee865 -- frontend/server.js \
  frontend/src/components/common/EventDocumentHead/index.tsx
git -C /home/hanqing/.cache/cve-analyzer/repos/github.com_bytedance_deer-flow grep -n \
  'class LocalSandboxProvider\|bash_tool' d664ae5a4b2e3ae34145f6dbdfc6908d955f6402 -- backend/src
```

Frozen first-party packet files and hashes used for identity recovery:

- Coder repo 17: `34dc635ae7cc08acf5ccb61e8be8d724d10458a29feb5d336070fb57ecd208be`
- Feast repo 25: `0bbf50731be1ba301355ca66c4785e6cfac810a3414f635e3cf3c5eccbe0bab1`
- Hi.Events repo 34: `4066508e8bbbd68f1d9940961a68485255703a9d759b6bedcaf768a4ae736a45`
- Claude HUD repo 36: `abd5632c189b9a17c82b6c79b00637a5977dfcb6c97e7bd8076b46ffacd1b832`
- LobeHub repo 44: `144a986fac53cc2b6e3bf7d2e7c31a0e6f8368a6cd00335595d1c75d24a3c8df`
- Warp repo 97: `5c29f691934d9883c058732f7b68a6ee7c52e4c2d6cd8f14250f6f75c53e6022`
- DeerFlow repo 10: `e0986a10effb8d9adca4d1621d129dffb950cddd1491a9f99e1e0c0d568c7278`
- FrontMCP repo 3: `4e7bcada1cad510a0d3ce11f0480137eb92c5499f7da268f0c60dca1afb91f70` (`missing_first_party`)

A bounded public GitHub lookup was attempted for the named advisory pages. GitHub rendering/search was incomplete, so no row was upgraded using live results; the frozen packet objects and exact Git history remain the evidence boundary. No credentials were used or exposed.

## Claim boundary and blockers

- Relation recovery, model votes, same-file/fix-context hits, patch IDs, exact blobs, tests already present in repositories, ancestry, and tag containment are diagnostic until candidate delta, parent baseline, advisory-specific reversal, identity, and release all close.
- `REJECT_NONCAUSAL` rejects only the named AI-member causal edge. It does not dispute the advisory, the fix, or the affected release range.
- No runtime test or exploit was executed. This audit establishes code lineage and falsifies nine routed causal claims; it does not independently reproduce the vulnerabilities.
- Coder can be promoted only with a first-party call chain or focused test proving a suspended user can reach the delegated `KeyId` path independently of the ordinary API-token path.
- FrontMCP lacks a recovered first-party advisory object. DeerFlow lacks a release-tag containment witness. Claude HUD's full member patch ID is unavailable due one missing cached blob; its security-target blob is exact.
- Therefore no selected edge supports a publication-grade AI-causality positive.
