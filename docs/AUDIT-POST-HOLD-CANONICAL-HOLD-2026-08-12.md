# Post-hold canonical ledger：199 source rows，结论仍为 HOLD

审计日期：2026-08-12（America/New_York）

## 结论

本轮把 Batch 2 的冻结账本、Batch F/G/H、OpenClaw sanitizer closure 与 residual 审计合并进一个 machine ledger。机械结果是：

| 口径 | 结果 |
|---|---:|
| Ledger records | 271 |
| Canonical source components | 211 |
| Strict released source rows | 132 |
| Incomplete-remediation released source rows | 67 |
| Broad released source envelope | **199** |
| Commit-only source rows | 12 |
| Widest source envelope | 211 |
| `integration_ready` | **false** |
| `final_count` | **null** |

不能发布“已确认 200”。这 199 条发布级 source rows 的真实状态分解是：

| 状态 | 发布级行数 | 是否可直接进入最终计数 |
|---|---:|---|
| PASS | 181 | 仅表示当前 ledger 的行级 PASS；继承的未抽样行仍受覆盖限制 |
| NARROW | 12 | 只能按写明的窄机制使用 |
| UNKNOWN | 2 | 否 |
| REJECT | 4 | 否 |

先前的 `200` 只是含重复 umbrella 的 source envelope；File Browser 终审后降为 `199`。账本按 fail-closed 规则输出 `HOLD`，没有把 REJECT、UNKNOWN 或 NARROW 偷换成 PASS。

## 本轮 28 个发布级候选的红队结果

本轮新增 28 个语义组件、39 个 public IDs：`STRICT_RELEASED=7`、`INCOMPLETE_RELEASED=21`。独立重放后为 `PASS=26`、`NARROW=2`、`REJECT=0`、`UNKNOWN=0`。

| 行 | 裁决 | 类别 | Public identity | Candidate → release fix | Vulnerable → fixed | Mechanism fingerprint label |
|---|---|---|---|---|---|---|
| F01 | PASS | STRICT | CVE-2026-44547 / GHSA-CWP8-RM8G-Q5C9 | `f9afc3c5` → `1bfc187a` | `7.2.2` → `7.3.1` | `churchcrm-public-api-login-removes-lockout-and-2fa` |
| F02 | PASS | STRICT | GHSA-MFMP-Q643-VJ39 | `0ea20d01` → `330d0d6a` | `7.4.2` → `7.4.3` | `churchcrm-groupview-role-listoption-label-xss` |
| F03 | PASS | STRICT | GHSA-M649-24Q9-Q6R4 | `0ea20d01` → `ae2b7355` | `7.5.1` → `7.6.0` | `churchcrm-group-member-url-attribute-xss` |
| F04 | PASS | STRICT | GHSA-HM7V-JRHM-FMFX | `6ef78813` → `ae2b7355` | `7.5.1` → `7.6.0` | `churchcrm-shared-person-action-attribute-xss` |
| F05 | PASS | INCOMPLETE | GHSA-F2FQ-4RMP-9X8C | `cbea916e` → `07be35d7` | `7.5.1` → `7.6.0` | `churchcrm-2fa-failure-counter-residual` |
| F06 | PASS | STRICT | CVE-2026-58409 / GHSA-37MF-VQ43-5QP9 | `095bf81b` → `1b4e2c70` | `7.3.3` → `7.4.0` | `churchcrm-community-plugin-webroot-php-rce` |
| F07 | PASS | INCOMPLETE | CVE-2026-57120 / GHSA-PV2J-RGHR-V5R9 | `179cab02` → `2adfe7e8` | `v4.6.58` → `v4.6.59` | `praisonai-python-sandbox-format-resolver-bypass` |
| F08 | PASS | INCOMPLETE | GHSA-3FP5-V549-9V66 | `8e41c118` → `55d1324c` | `v2026.6.8` → `v2026.6.9` | `openclaw-flock-wrapper-approval-binding-residual` |
| F09 | PASS | INCOMPLETE | GHSA-575V-8HFQ-M3MC | `3cc8b2a3` → `a90eb934` | `v2026.6.5` → `v2026.6.6` | `openclaw-sandbox-bind-ancestor-policy-residual` |
| F10 | PASS | INCOMPLETE | GHSA-X863-PQJW-HMGF | `3d93174c` → `78f3985c` | `v2026.5.18` → `v2026.5.19` | `openclaw-browser-act-current-tab-preflight-residual` |
| F11 | PASS | INCOMPLETE | GHSA-2X93-H3HG-2XFP | `b75ad800` → `06047005` | `v2026.5.22` → `v2026.5.26` | `openclaw-browser-snapshot-current-tab-preflight-residual` |
| F12 | PASS | INCOMPLETE | GHSA-8V95-QQCM-QP9H | `1c85eff9` → `517ce3df` | `v2026.5.26` → `v2026.5.27` | `openclaw-device-pair-approve-admin-gap` |
| F13 | PASS | INCOMPLETE | GHSA-QJPC-QF9M-XWMR | `0e702f10` → `96fba91b` | `v2026.5.12` → `v2026.5.18` | `openclaw-trusted-proxy-unpaired-scope-residual` |
| F14 | PASS | INCOMPLETE | GHSA-9C3V-684M-579C | `47eb2d48` → `3c6259eb` | `v2026.6.1` → `v2026.6.5` | `openclaw-mcp-sse-redirect-header-residual` |
| F15 | PASS | INCOMPLETE | GHSA-J4CX-JVQ7-79VM | `17ceca86` → `19fb9f12` | `v2026.5.28` → `v2026.6.1` | `openclaw-trajectory-export-redaction-residual` |
| F16 | PASS | INCOMPLETE | GHSA-WP73-F3GG-W4VR | `6c918ca8` → `797bcd5b` | `v2026.6.1` → `v2026.6.5` | `openclaw-clickclack-toolsallow-propagation-residual` |
| F17 | PASS | INCOMPLETE | GHSA-7JX6-764P-FGG9 | `6e498a1f` → `08a73dbe` | `v2026.5.26` → `v2026.5.27` | `openclaw-qqbot-same-chat-approval-fallback` |
| F18 | PASS | INCOMPLETE | GHSA-2HFG-4FH4-QP7F | `e0b8ddc1` → `3d93174c` | `v2026.5.12` → `v2026.5.18` | `openclaw-browser-action-kind-navigation-coverage-residual` |
| G01 | PASS | STRICT | CVE-2026-58407 / CVE-2026-58410 / GHSA-3J8Q-FWPJ-F8J5 / GHSA-JJCJ-H3CM-P7X7 | `b3edc225` → `83c19611` | `7.3.3` → `7.4.0` | `churchcrm-notes-object-scope-authorization` |
| G03 | PASS | STRICT | CVE-2026-44548 / GHSA-JX5R-P82P-2P8M | `6ef78813` → `f1c11f9f` | `7.4.0` → `7.4.3` | `churchcrm-fundraiser-destructive-get-csrf` |
| E01 | PASS | INCOMPLETE | CVE-2026-53864 / GHSA-CCWH-WWPP-6WG5 | `3affd5e8` → `91590132` | `v2026.5.22` → `v2026.5.27` | `openclaw-host-env-node-runtime-controls-residual` |
| E02 | PASS | INCOMPLETE | GHSA-HJR6-G723-HMFM | `3affd5e8` → `9f413acc` | `v2026.6.1` → `v2026.6.6` | `openclaw-host-env-interpreter-startup-residual` |
| E03 | PASS | INCOMPLETE | GHSA-9969-8G9H-RXWM | `3affd5e8` → `86bab969` | `v2026.6.1` → `v2026.6.6` | `openclaw-host-env-git-ext-transport-residual` |
| E04 | PASS | INCOMPLETE | GHSA-WXH3-G47H-Q3MC | `3affd5e8` → `7cdec287` | `v2026.6.1` → `v2026.6.6` | `openclaw-host-env-rustup-controls-residual` |
| R01 | PASS | INCOMPLETE | GHSA-4PQJ-3C56-5FQQ | `3affd5e8` → `85277c2d` | `v2026.5.27` → `v2026.5.28` | `openclaw-workspace-provider-credential-residual` |
| R02 | NARROW | INCOMPLETE | CVE-2026-53819 / GHSA-8WG3-5MCM-FJQ8 | `3affd5e8` → `f86953f3` | `v2026.4.29` → `v2026.5.2` | `openclaw-workspace-homebrew-executable-residual` |
| R03 | NARROW | INCOMPLETE | CVE-2026-53842 / GHSA-FQ9J-VW4W-FR6V | `3affd5e8` → `86251f43` | `v2026.4.29` → `v2026.5.2` | `openclaw-workspace-gcloud-python-residual` |
| R04 | PASS | INCOMPLETE | CVE-2026-45003 / GHSA-55CF-XX38-4P9P | `3affd5e8` → `0623079e` | `v2026.4.21` → `v2026.4.22` | `openclaw-workspace-connector-endpoint-residual` |

R02/R03 的 `NARROW` 是实质限制：PR #63277 的 Codex-generated、human-reviewed 广义修复与后续同边界 closure 成立，但 Homebrew/Cloud SDK sibling 行在 review chain 中被删。它们只能表述为 PR-level incomplete-remediation contribution，不能写成“发布 carrier 保留了对应 AI 原子 hunk”。

## 此前同步保留的 6 个 REJECT 控制

| Route | Public identity | 原因 |
|---|---|---|
| G02 | CVE-2026-40480 / GHSA-5W59-32C8-933V | AI 只重排已有 person GET/export 漏洞，回退 candidate 不消除漏洞 |
| 24vr | CVE-2026-53846 / GHSA-24VR-RPRV-67RF | `npm_execpath` sink 在 sanitizer candidate 之后才加入 |
| wc84 | CVE-2026-53858 / GHSA-WC84-J36W-PW4X | `STATE_DIRECTORY` sink 在 candidate 之后才加入 |
| 8f46 | GHSA-8F46-3XX3-8C9M | gateway/node env equivalence 是 approval-binding invariant，不是 denylist completeness |
| hxvm | CVE-2026-44114 / GHSA-HXVM-XJVF-93F3 | `OPENCLAW_*` 属于更早的独立 repair lineage |
| 7wv4 | CVE-2026-43531 / GHSA-7WV4-CC7P-JHXC | 对应 fix 已早于 sanitizer candidate |

这些记录是 non-counting controls，避免以后因同 SHA、同文件或“都是 env”重新抬回候选池。

## Batch H：24 个 OpenClaw / ChurchCRM route controls

[Batch H 逐行报告](RESEARCH-POST-HOLD-OPENCLAW-CHURCHCRM-BATCH-H-2026-08-12.md) 的结论是 `PASS=0 / REJECT=23 / UNKNOWN=1`。23 个 REJECT 分别由非 AI origin、remediation-only、format/refactor preservation 或不同机制反证；唯一 UNKNOWN 是 OpenClaw QQBot `GHSA-FWGR-FPV9-VF5X`：真实 regression 与发布区间成立，但精确 vulnerable PR member 没有 AI marker，Cursor trailer 只存在于同一 squash 的无关成员。

这 24 行全部作为 non-counting controls 写入同一 ledger；它们不增加 component、public-ID 或 mechanism-fingerprint 计数，也不改变 `132/199/211` source envelopes。

## 继承的 4 个发布级 UNKNOWN 终审

| Row | 终审 | 直接依据 |
|---|---|---|
| Gitea CVE-2026-58432 / GHSA-Q9PG-JJ6X-J9P6 | **PASS** | [仓库 advisory](https://github.com/go-gitea/gitea/security/advisories/GHSA-q9pg-jj6x-j9p6) 与 global reviewed advisory 直接声明 formal alias；Copilot `1eced4a7...` 给 API draft release/attachment 加 write gate，`f7fd5102...` 给遗漏的 web `ServeAttachment` 加同一 gate。发布分支见证为 `e7fca90a...` in `v1.25.5`、`ab10e37a...` in `v1.27.0`。 |
| PraisonAI CVE-2026-57148 / GHSA-F38V-77QJ-H4JQ | **PASS** | [仓库 advisory](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-f38v-77qj-h4jq) 与 global reviewed advisory 直接声明 formal alias；Cursor `179cab02...` 的 guard 把 unset `PLATFORM_ENV` 当 dev，`e0fb8e7d...` 关闭 default-open。PyPI `0.1.4` sdist 保留公开默认 key；`0.1.6` 已改用 resolved secret。 |
| File Browser CVE-2026-54094 / GHSA-239W-M3H6-CH8V | **REJECT / non-counting** | [原 advisory](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-239w-m3h6-ch8v) 在 `2.63.14` 已修；AI `847d08bd...` 是 remediation，不是该 CVE origin。主行列出的后续 dangling-write 与 unguarded-delete 已分别由 CVE-2026-55668、CVE-2026-55667 计数，没有第三个独立机制。 |
| Coolify CVE-2026-34198 / GHSA-CGJ8-7M5Q-X5GV | **UNKNOWN** | `e1fe5863...` 的 cold-cache early return 确实延续到 fix，且发布区间成立；但唯一 atomic marker 是 generic `Changes auto-committed by Conductor`。Conductor [官方文档](https://www.conductor.build/docs/reference/checkpoints) 明确 checkpoint 可同时包含 user 与 AI changes，因此该 subject 不能证明具体 hunk 为 AI 生成。 |

PraisonAI 的发布口径同时纠正：repo advisory 写 `>=0.1.5`，但 PyPI 没有 `0.1.5`；global reviewed advisory 与实际 sdist 均支持首次可用修复版 `0.1.6`。本账本使用 `0.1.4 → 0.1.6`，不沿用旧报告的 `0.1.5`。

GitHub repo/global advisory 已直接声明 Gitea 与 PraisonAI 的 CVE/GHSA alias。CVE Services 在本次重放仍返回 404；这被记录为同步状态，而不是反向否定一方正式分配。

## Strict U052 fix edge 校正（计数不变）

`CVE-2026-27695 / GHSA-76RV-2R9V-C5M6` 仍为 **PASS**，但旧 edge `3902c8c2 → 94a129ae` 不完整，不能继续作为单提交 reversal：

- Claude Opus 4.5 co-authored 的 root commit `3902c8c22868832db6d9f54046e76d5be226f607` 创建了 `PK=ENTITY#{id}` 的 bucket 布局；它没有 parent，并完整包含于 vulnerable `v0.10.0`。
- `94a129ae55acc3b034662045296e288279cbef2e` 只把 bucket 搬到 per-shard key 并注入 `wcu` 元数据。对该 commit 做 `git grep`，`bump_shard_count`、`random.randrange`、`MAX_SHARD_RETRIES`、`_is_wcu_exhausted` 均为零命中；单独移除/应用它不能证明热分区路径已关闭。
- 最小实际安全闭合点是 `9f66c42f06f3b87107ce327bede6416a582f0e60`。账本记录六个有序原子成员：`2d8cdd8`（bucket/shard key builders）、`abd6a8a9`（保留 `wcu` 名，防用户配置覆盖内部 guard）、`8fba24d1`（WCU 常量）、`94a129ae`（per-shard item layout）、`6e64d5b2`（每次 speculative write 消耗 WCU 并缓存 shard count）、`9f66c42f`（随机选 shard、跨 shard retry、WCU 耗尽后 conditional doubling）。
- 在 detached `9f66c42f` 上，async/sync repository 与 limiter 的 20 个定向 pre-shard/shard-retry tests 实跑为 `20 passed`。这包括 1,000 次 WCU 消耗后的 doubling、slow-path 新 shard 创建和跨 shard retry，不是仅靠 commit message 判定。
- 一方 [repository advisory](https://github.com/zeroae/zae-limiter/security/advisories/GHSA-76rv-2r9v-c5m6) 与 global reviewed advisory 都声明 formal alias、`<=0.10.0` vulnerable、`0.10.1` patched。正式发布 carrier 是 merge `481ce44d818d66e31d8837bc48519660ce4c267f`，恰为 tag `v0.10.1`；六个原子成员均不在 `v0.10.0`、均在该 carrier。

后续 aggregator commits 提供 proactive sharding、stream propagation 与 review 修补；它们增强修复，但不是 client-side minimum closure 的必要成员，因此没有为了把 fix-set 做大而收入 `atomic_fix_members`。这次校正只替换错误 fix edge，不新增 component/public ID，也不改变 `132/199/211` source envelopes。

定向重放：

```zsh
git -C ~/.cache/cve-analyzer/repos/zeroae_zae-limiter worktree add --detach /tmp/zae-u052-replay 9f66c42f06f3b87107ce327bede6416a582f0e60
uv run --project /tmp/zae-u052-replay --extra dev pytest -n 0 \
  /tmp/zae-u052-replay/tests/unit/test_repository.py::TestPreShardBuckets \
  /tmp/zae-u052-replay/tests/unit/test_limiter.py::TestShardRetry \
  /tmp/zae-u052-replay/tests/unit/test_sync_repository.py::TestPreShardBuckets \
  /tmp/zae-u052-replay/tests/unit/test_sync_limiter.py::TestShardRetry -q
```

## Strict U001 fix squash 拆分（计数不变）

`CVE-2026-32111 / GHSA-FMFG-9G7C-3VQ7` 的 AI origin 与发布因果均成立；缺口只在旧账本没有拆 fix squash：

- PR #368 的原子 member `aae7acba91dc21fc897ef6b78989b1f548c4083e` 带明确 Claude Code marker，新增 OAuth consent `ha_url`、`form.get("ha_url")`，并在 `_validate_ha_credentials` 对 `f"{ha_url}/api/config"` 发出 unauthenticated server-side request。squash carrier `39806871c9720bf8afdcf3e061095c0dd63dea7f` 保留这三个关键点，并进入 vulnerable `v6.7.2`。
- PR #748 的第一个原子 member `0ca572a1452cbabc9004993d6a649afa3c0f435d` 已完整关闭同一边界：移除表单与 token claims 中的 `ha_url`、删除 `_validate_ha_credentials`，改为启动时读取 server-side `HOMEASSISTANT_URL`。后续六个 members 只做文档、redirect-domain UI、merge conflict 与 lint/type 修正，没有重新引入该输入到 sink。
- fix member 自身不是主线祖先，因为 PR 以 `dc8eaa16a8550f885614655f14b6fd9fe429b278` squash；因此 release edge 保留 `39806871 → dc8eaa16`，同时 `atomic_fix_members=[0ca572a1...]`，不再把整个 squash carrier 冒充原子修复。
- 在 detached `0ca572a1` 上，`tests/src/unit/test_oauth.py` 实跑 `46 passed`；其中包括 consent POST、server URL/per-user token、REST/WebSocket proxy 路径。
- 一方 [repository advisory](https://github.com/homeassistant-ai/ha-mcp/security/advisories/GHSA-fmfg-9g7c-3vq7) 与 global reviewed advisory 均 published、未撤回，直接声明 CVE/GHSA formal alias；前者给出 `<=6.7.2 → 7.0.0`，后者给出 `<7.0.0 → 7.0.0`。fix carrier 在 `v7.0.0`、不在 `v6.7.2`。

定向重放：

```zsh
git -C ~/.cache/cve-analyzer/repos/homeassistant-ai_ha-mcp worktree add --detach /tmp/ha-mcp-u001-replay 0ca572a1452cbabc9004993d6a649afa3c0f435d
uv run --project /tmp/ha-mcp-u001-replay pytest -n 0 \
  /tmp/ha-mcp-u001-replay/tests/src/unit/test_oauth.py -q
```

## Strict U005 fix squash 拆分（计数不变）

`CVE-2026-14611 / GHSA-FWPR-59HH-GR98` 的现有 origin `bce0d2ba7904c056c576cf94db817635421d1f41` 是真实 AI 因果点，不是邻近提交误绑；需要修正的是 fix 的原子性和发布口径：

- Claude Opus 4.6 co-authored 的 `bce0d2ba` 在 parent 没有 per-project memory 的前提下，新增 `initProjectMemory(workspacePath)`，并用 `sha256(literal workspacePath)[0:12]` 直接构造持久化目录。它恰为 tag `v0.4.0`。一方 issue #46 用同一 lexical symlink 先指向 victim、再指向 attacker workspace，复现了共享 `$HOME` 下跨项目加载 `MEMORY.md`。
- PR #49 是 squash；其第一个 member `c6daf9107a8dc14088feff4671657e6319e36628` 已完整关闭该身份边界：对 workspace 做 `realpathSync.native()`（失败时 `path.resolve()`），再以 schema-domain-separated payload 计算 full SHA-256。第二个 member `40305cf3...` 只迁移 legacy 目录，不是消除泄漏所必需。
- 在 detached `c6daf910` 上，仓库新增的 symlink-isolation test 实跑 `1 passed`。账本因此保留发布 edge `bce0d2ba → 6d709229`，并记录 `atomic_fix_members=[c6daf910...]`，不再把整个 squash carrier 当作原子修复。
- global GHSA 为 published、未撤回，并正式列出 CVE/GHSA 两个 identifiers；它引用一方 issue #46、PR #49 和 exact fix。该 unreviewed 文本却同时说 `v0.4.0` affected 和“升级到 `v0.4.0` 即修复”，内部矛盾，故账本明确拒绝后一句作为 fixed-release evidence。当前可证明的是：AI origin 已进入 `v0.4.0`，fix 已在主线 commit，仓库尚无包含 fix 的 tag。

定向重放：

```zsh
git -C ~/.cache/cve-analyzer/repos/deepmyst_mysti worktree add --detach /tmp/mysti-u005-replay c6daf9107a8dc14088feff4671657e6319e36628
npm --prefix /tmp/mysti-u005-replay ci --ignore-scripts --no-audit --no-fund
npm --prefix /tmp/mysti-u005-replay exec -- vitest run tests/managers/memoryManager.test.ts --maxWorkers=1
```

## 仍阻断最终 200 的发布级行

### REJECT（4）

- Gitea OAuth reactivation：CVE-2026-55987 / GHSA-VRHC-JJFC-M3M3。
- GitPython positional `--file`：GHSA-3WXW-XV34-2FRG。
- Scriban lazy multiplication：GHSA-89CF-6HMV-8RXM。
- OpenClaw chat-attachment decode-before-limit：CVE-2026-29612 / GHSA-W2CG-VXX6-5XJG（Batch I row 22；AI 只复制了已有 `Buffer.from` 路径）。

### UNKNOWN（2）

- Coolify TrustHosts cold-cache attribution：CVE-2026-34198 / GHSA-CGJ8-7M5Q-X5GV。
- Quay org-mirror SSRF release containment：CVE-2026-2376 / GHSA-9W78-X9JW-9C7M（Batch I row 17；本地 clone 无 `v3.16.0`/`v3.17.0` tag，也没有未修复 origin 的已发布制品）。

### NARROW（12）

- Hermes cross-profile session search：CVE-2026-49956 / GHSA-MGXW-V6RH-WCV6。
- OpenClaw Feishu webhook scoped evidence：CVE-2026-32974 / CVE-2026-44109 / GHSA-G353-MGV3-8PCJ / GHSA-XH72-V6V9-MWHC。
- 本轮 R02 Homebrew。
- 本轮 R03 Cloud SDK Python。
- Batch I row 3 prek-version 新表面：GHSA-PWF7-47C3-MFHX。
- Batch I row 5 `/api/session` state.db 贡献者：CVE-2026-55197 / GHSA-5WQV-FHMR-PJGH。
- Batch I row 9 DQL timeframe：GHSA-PQH8-P93P-2RX7。
- Batch I row 10 `downloadAllLogs`：CVE-2026-34599 / GHSA-Q9J6-XCVX-PX63。
- Batch I row 11 create_backup API：CVE-2026-34049 / GHSA-4MPW-WCJ4-V9PP。
- Batch I row 16 Feishu webhook 新表面：CVE-2026-28478 / GHSA-Q447-RJ3R-2CGH。
- Batch I row 19 artifact `job_id` 新表面：CVE-2026-61462 / GHSA-5383-J2P9-QFG3 / GHSA-7C3W-FXGH-FRC7。
- Batch I row 24 suspended-process sweeper：CVE-2026-27486 / GHSA-JFV4-H8MC-JCP8。

即使把十二条 NARROW 全按其窄范围保留，当前也只有 193 个可接纳发布级 source rows；至少还要替换 4 个 REJECT、闭合 2 个 UNKNOWN，并新增无重复组件，才可能到 200。继承的 74 条 post-strict 中只有 20 条做过 Batch 1 adversarial sampling，这一 coverage blocker 也尚未消失。Batch I 审的是 strict-200-v3 的 24 行，不能拿来填那 74 行的覆盖缺口。

## Verifier 闸门

本轮 verifier 实际通过：

- 9 个 source artifacts 的 SHA-256 全匹配；
- builder 对 `ledger.jsonl` / `summary.json` byte-identical；
- 271 个 row keys 唯一，211 个 canonical components 守恒；
- 30 个 non-counting route controls 为 `29 REJECT / 1 UNKNOWN`；Batch H 的 public IDs 与 363 个 canonical public IDs 零交集。既有 `HXVM` control 与 canonical 组件共享两个正式 alias，但拒绝的是后出的 `3affd5e8` sanitizer route，canonical 接纳的是不同的早期 `db67492a → 018494fa` contributor edge；
- 363 个 canonical public-ID occurrences 全部唯一，无跨组件 alias collision；Batch I 补了 5 个同组件 alias（`GHSA-Q9J6-XCVX-PX63`、`GHSA-4MPW-WCJ4-V9PP`、`GHSA-X9QH-W4C4-54F9`、`CVE-2026-41345`、`GHSA-7C3W-FXGH-FRC7`），没有新增 component；
- 211 个 exact mechanism fingerprints 全部唯一；该机械检查不替代上面的 File Browser 语义终审；
- 新增 39 个 public IDs 内部唯一，且与 Batch 2 canonical public IDs 零交集；
- 28 个 mechanism fingerprints 唯一；
- 新增 77 个 candidate/carrier/fix Git objects 与 Batch 2 edge-object 集零交集；
- 共享 candidate/fix 的每一行都有显式 reuse justification；
- 新闭合的 PraisonAI JWT 行与 F07 Python sandbox 行共享 multi-purpose `179cab02...`，双方均登记不同 input/sink 的 reuse justification；
- live Git replay 为 28/28：candidate/carrier 在 vulnerable tag，fix 不在 vulnerable tag，fix 在 fixed tag；
- 29/29 一方 repo advisories 当前 `published` 且未撤回；有 CVE 的行经 repo/global identifiers 闭合；
- 追加重放 Gitea/PraisonAI 2/2：formal alias、candidate/fix 和 release/package containment 均闭合；
- U052 严格 edge 1/1：root AI marker、六成员 ancestry、旧 `94a` 缺失关键行为、`9f66` 最小闭合点、`v0.10.1` carrier 与正式 alias 均闭合；
- U001 严格 edge 1/1：origin/fix 两侧 PR member-to-squash 映射、最小 fix member、`v6.7.2 → v7.0.0` 与正式 alias 均闭合；
- U005 严格 edge 1/1：AI origin delta、`v0.4.0` containment、PR #49 两成员 squash、最小 fix member、一方 issue 与 global formal alias 均闭合；错误的“`v0.4.0` 已修复”元数据未被采用；
- Batch I 24/24：独立 packet 覆盖 rows 1–24 各一次；integrator 接纳 14 PASS / 8 NARROW / 1 UNKNOWN / 1 REJECT。Row 15 packet 标 NARROW 是因为提议 fix `e704323f` 不是首个语义修复；替换为 `f865a545` 后 origin 与 npm containment 仍成立，故保持 PASS。未把 NARROW/UNKNOWN 提升为 PASS，也未把 199 写成 200；
- 最终仍强制 `status=HOLD`、`integration_ready=false`、`final_count=null`。

闸门分级保持保守：发布级 public-ID alias 为 `PASS`，但含三条 commit-only UNKNOWN 的 widest alias 为 `PARTIAL`；exact fingerprint 为 `PASS`，全量语义复核仍为 `PARTIAL`；release containment 也为 `PARTIAL`，因为上述 33 条有本轮 live replay，其余继承行沿用冻结 Batch2 证据，没有在本轮把 199 条全部重新下载/构建。因此 `integration_ready` 不能翻成 true。

## Batch I：24 个 strict-200-v3 行的独立红队

四份只读 packet（`/tmp/herdr-ai-slop-b1a` rows 6–11、`b1b` 12–17、`b1c` 19–24、`b1d` 1–5 与 18）机械覆盖 Batch I rows 1–24 各一次。Packet JSON 的 SHA 均为 40-hex；b1c 的 GHSA 为小写，integrator 按账本合同升成大写后接纳。Routing、OSV `introduced`、同文件 overlap、ancestry-only、AI trailer 单独出现、commit subject 或模型投票都不当作因果。

| 行 | 终审 | 相对冻结 PASS 的变化 | 直接依据 |
|---:|---|---|---|
| 1 | PASS | 已有 squash 拆分，无新 mutation | ha-mcp `aae7acba` / `0ca572a1`，`v6.7.2 → v7.0.0` |
| 2 | PASS | 补 merge carrier 与最小 fix member | `d2b27f6f` → carrier `f21b088a`；fix member `abee926e`，squash `88dc8bbe` in `v0.50.12` |
| 3 | NARROW | PASS→NARROW | parent 已有 `extra_args`；Copilot 只新增 `prek-version` |
| 4 | PASS | 已有 squash 拆分，无新 mutation | Mysti `bce0d2ba` / `c6daf910`；`fixed_tag=null` |
| 5 | NARROW | PASS→NARROW | parent 已从全局 `SESSION_DIR` 读 sidecar；`ee672df4` 只加 foreign state.db |
| 6 | PASS | 记录 fix member | POSIX backslash zip-slip；`847d08bd → 8503ba61`；`v2.63.6 → v2.63.17` |
| 7 | PASS | 补同机制第二 origin | `d42195e1` + `f08e6549`；fix `17a119fe` |
| 8 | PASS | 记录 fix member | `4a7b813a` / carrier `20523b91`；fix `ec45c317` |
| 9 | NARROW | PASS→NARROW | parent 已插 `additionalFilter`；只把 timeframe 算 AI 新表面 |
| 10 | NARROW | PASS→NARROW；补 GHSA | parent 已有 `getLogs`；只算 `downloadAllLogs` |
| 11 | NARROW | PASS→NARROW；补 GHSA | parent 已有 `update_backup` 与 collection sink；只算 create_backup API |
| 12 | PASS | 补 GHSA | `buildHelperImage` 新 sink；`v4.0.0-beta.447 → beta.474` |
| 13 | PASS | merge fix 换成语义 member | `0c2ec967` 是双亲 merge；最小 member / npm `2.0.14` gitHead 是 `a0f9c2bf` |
| 14 | PASS | 记录 squash origin | Copilot `3e176213` 创建未转义 Swagger script sink |
| 15 | PASS | 纠正 fix SHA；补 CVE alias | packet 因 `e704323f` 标 NARROW；首个同 sink 修复是更早的 `f865a545`。Origin 成立，故不降为 NARROW |
| 16 | NARROW | PASS→NARROW | Feishu webhook 新表面，不是全家 webhook DoS 的 root |
| 17 | UNKNOWN | PASS→UNKNOWN | git 因果可复述，但缺少含 origin、不含 SSRF 修复的已发布 tag/package |
| 18 | PASS | 已有六成员 fix-set，无新 mutation | zae-limiter `3902c8c2` → `9f66c42f` / carrier `481ce44d` |
| 19 | NARROW | PASS→NARROW；补 repo GHSA | parent 已有 `/jobs/${jobId}/trace`；只算 artifact sinks |
| 20 | PASS | 记录 merge carrier | token-auth 跳过 device 且无 role gate；fix `ddcb2d79` |
| 21 | PASS | 记录 fix member | parent 无 attachment 模块；`v1.1.0 → 1.3.4` |
| 22 | REJECT | PASS→REJECT | parent `buildMessageWithAttachments` 已 `Buffer.from` 后再比 `maxBytes`；AI 只复制 |
| 23 | PASS | 记录 merge carrier | Galaxy.enabled-only query；prompt GHSA-3636-PP8Q-663Q 是 404 |
| 24 | NARROW | PASS→NARROW | parent 已有 `pkill -f`；只算 suspended-process sweeper。Member `bb6d608d` 不在本地 clone，从 GitHub commit API 回收 |

Replay 入口仍是同一组命令。Batch I 定向 live 检查：row 22 parent `Buffer.from`、row 3 `prek-version` 新表面、row 10 `downloadAllLogs`、row 15 `f865a545` 先于 `e704323f`、row 13 `a0f9c2bf` 是 merge 第二亲、row 17 本地无 3.16/3.17 tag。

## 可重放命令

```zsh
python3 autoresearch/orchestrator-260812-posthold-canonical/build.py --check
python3 autoresearch/orchestrator-260812-posthold-canonical/verify.py
python3 autoresearch/orchestrator-260812-posthold-canonical/verify.py --live
python3 autoresearch/orchestrator-260812-posthold-canonical/test_canonical.py
```

`--live` 只读取三个本地一方 Git clones，并通过 `gh api` 读取公开 advisory；命令不打印 credential。结构 verifier 与 test 不需要网络。

## Durable artifacts

- `autoresearch/orchestrator-260812-posthold-canonical/ledger.jsonl`
- `autoresearch/orchestrator-260812-posthold-canonical/summary.json`
- `autoresearch/orchestrator-260812-posthold-canonical/result.json`
- `autoresearch/orchestrator-260812-posthold-canonical/adjudications.json`
- `autoresearch/orchestrator-260812-posthold-canonical/inherited_corrections.json`
- `autoresearch/orchestrator-260812-posthold-canonical/source_manifest.json`
- `autoresearch/orchestrator-260812-posthold-canonical/build.py`
- `autoresearch/orchestrator-260812-posthold-canonical/verify.py`
- `autoresearch/orchestrator-260812-posthold-canonical/test_canonical.py`

本报告没有改写 Batch 2 的冻结 artifact。它在单一新账本中显式接纳、收窄或拒绝 post-hold 行与 Batch I 的 24 个 strict 行，并保留所有未闭合项。Batch H 没有提供补位项；Batch I 把发布级 PASS 从 191 降到 181，并增加 REJECT/UNKNOWN/NARROW。仍需替换 4 个 released REJECT、闭合 2 个 released UNKNOWN 并新增无重复组件；十二条 NARROW 仍只能按各自窄口径使用，不能作为“200 已完成”的依据。
