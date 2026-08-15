# 118 个 semantic component 的因果准确率复核

日期：2026-08-11
审计对象：`autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v1/ledger.jsonl`
对象 SHA-256：`996e81f5298bf695a7d91bc0b2646a314146aaad97aa417fbc4fa5b255ab078c`
冻结规模：118 个 semantic component、207 个唯一 public ID；其中 base 92、supplement 26。

## 结论

这次复核不继承旧 `PASS`，也不把 OSV `introduced`、模型投票、AI author/co-author marker 当作因果证明。每个 component 都重新检查了 candidate 的直接 parent、candidate delta、公开 advisory 指向的机制，以及最小 fix/revert。

| 互斥判定 | 数量 | 118-component 占比 |
|---|---:|---:|
| `DIRECT_ROOT` | 77 | 65.25% |
| `VALID_CONTRIBUTOR` | 31 | 26.27% |
| `FALSE_POSITIVE` | 10 | 8.47% |
| `NEEDS_REVIEW` | 0 | 0.00% |
| 合计 | 118 | 100.00% |

两套分母口径：

- **Actual causal contribution accuracy**：`(77 + 31) / 118 = 108 / 118 = 91.53%`。这里要求 candidate 实际新增、重开或实质扩大 advisory 所述可利用面；纯粹不完整但净减风险的 hardening 不算贡献。
- **Strict direct-root/reintroduction precision**：`77 / 118 = 65.25%`。这里要求 exact unsafe state 在 candidate 的直接 parent 中不存在，而由 candidate delta 首次建立或由真实 guard removal/revert 重新建立；仅把更早缺陷接到新 caller/route/provider 的列为 contributor。作为补充，在 108 个 causal-valid component 内，direct-root/reintroduction share 为 `77 / 108 = 71.30%`。这不是“历史上首次出现”的纯 first-origin 指标。

分母边界：用户问题和本报告的审计单位都是 118 个 semantic component。ledger 内另有 134 个 accepted-edge occurrence、131 个唯一 `(candidate, fix)` pair。若仅把 10 个 false component 所属 edge 机械剔除，会得到 `123/134 = 91.79%` 与 `122/131 = 93.13%`；但多 edge 的 valid component 并未被当作独立统计样本重新抽样，因此这两个数只用于账目对齐，**不外推为独立 edge-level precision**。

31 个 contributor rows 为：`3, 4, 10, 15, 17, 18, 23, 24, 26, 30, 32, 38, 40, 41, 43, 48, 53, 58, 64, 72, 75, 84, 86, 92, 94, 95, 99, 104, 106, 112, 113`。

10 个 false-positive rows 为：`8, 31, 62, 74, 76, 80, 98, 100, 109, 110`。

## 判定规则与证据边界

- `DIRECT_ROOT`：candidate 的最小 delta 创建 exact sink/policy failure，或从受保护 parent 明确移除 guard；fix 直接反转该 delta。安全修复主题并不自动排除回归，例如 row 16 把 POSIX 合法反斜线名改写成 `../`，确实制造了新的跨平台 traversal。
- `VALID_CONTRIBUTOR`：更早的共享缺陷仍在，但 candidate 新增了真实 caller、route、provider、模型配置、平台分支或生产 API；删除 candidate 会消除该新增攻击面，但不消除更广的旧根因。等价重构本身不算贡献；重写只有同时新增可达 surface 才成立。
- `FALSE_POSITIVE`：candidate 与机制无关、只是等价重构，或 candidate 是净减风险的不完整 hardening。尤其是：若删除 candidate 会回到同样或更严重的漏洞状态，则它不满足 actual but-for contribution。
- `NEEDS_REVIEW`：本地一方对象、parent 或最小 fix 不可读，无法闭合。此次 118 项所需对象均可读，因此为 0。
- AI marker 只用于回答“该 commit 是否可归入 AI-contributed 候选”，不用于回答“它是否导致漏洞”。完整 SHA、aliases 和原始 evidence 索引在 union ledger；base 的定位索引为 `autoresearch/orchestrator-260811-atomic150/strict-audit-20260811/class_adjudications_v4.json`，supplement 的一方 repo 路径、机制与 edge 为 `autoresearch/orchestrator-260811-atomic150/strict-supplement-v1/adjudications.json`。表内短 SHA 在冻结 repo 中唯一解析。

## 高风险边界的独立反证

### Rows 8/80：9Router edge 错绑，不是漏洞 root

`7648c3412b403a29f04967c4b4e9725e228791d4` 的主题和 delta 是 real-client-IP rate limiting、remote default-password guard、导出既有 `isLocalRequest` 以及 reset-password route；其 parent 已有 `/api/mcp/`、`/v1` gates，且 locality 当时只信 `Host`/`Origin`。把 `x-9r-real-ip` 当 locality anchor 的代码由后续 human `b282f055` 写入，`da667836cc7584bea0edd893de1d590c9ea279dc` 修的是该后续逻辑。CVE-2026-62312 的 MCP args 面也不是 candidate 创建。两个 component 都是 `FALSE_WRONG_EDGE`。

```bash
git -C /home/hanqing/.cache/cve-analyzer/repos/github.com_decolua_9router show 7648c3412b403a29f04967c4b4e9725e228791d4 -- src/dashboardGuard.js custom-server.js
git -C /home/hanqing/.cache/cve-analyzer/repos/github.com_decolua_9router blame -L 70,115 da667836cc7584bea0edd893de1d590c9ea279dc^ -- src/dashboardGuard.js
git -C /home/hanqing/.cache/cve-analyzer/repos/github.com_decolua_9router show da667836cc7584bea0edd893de1d590c9ea279dc -- src/dashboardGuard.js
```

第二条命令把危险 locality 行归到 `b282f055`，而非 `7648c341`。

### Row 31：Coolify 是等价抽取，不是新增 model/caller

链为 `a8aa4524751d1530031f6134d49474d254bbab72^ → a8aa4524751d1530031f6134d49474d254bbab72 → 096d4369e59b3db7ace2db3ca42588c41b9b6019`。parent 的 `Application`、`Server` 和每个 `Standalone*` model 已分别把 `sentinel_token` 插入 `docker exec ... sh -c 'curl ...'`。candidate 删除这些同名方法并集中到 `app/Traits/HasMetrics.php`；trait 的 10 个使用者正是被删除方法的同一 10 个 model，Livewire caller 未增加。`StartSentinel.php` 的另一处 token shell interpolation 也在 parent。删除 candidate 仍完整保留漏洞，故为 `FALSE_REFACTOR_PRESERVATION`。

```bash
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify diff a8aa4524751^ a8aa4524751 -- app/Models app/Traits/HasMetrics.php
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify grep -n 'sentinel_token' a8aa4524751^ -- app/Models app/Actions/Server/StartSentinel.php
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify show 096d4369e59b3db7ace2db3ca42588c41b9b6019 -- app/Traits/HasMetrics.php app/Actions/Server/StartSentinel.php app/Models/ServerSetting.php
```

### Rows 62/74：PraisonAI 两项都是不完整 hardening

链为 `3cd664bf7b7db5f774c1e7e3123a1a24c68ba700^ → 3cd664bf7b7db5f774c1e7e3123a1a24c68ba700 → 179cab02dbec0c1e9b601507a65908e079876004`。parent 已有 unrestricted `Session.get(url)` 和带完整 builtins 的 Python `exec`。candidate 主题就是修复严重安全问题，只加入可绕过的字符串 SSRF blacklist 和弱伪 sandbox；fix 再覆盖 alternate loopback encodings 与 AST/builtins。删除 candidate 会回到更宽的同类漏洞，不会消除 advisory 机制，故两项均为 `FALSE_INCOMPLETE_HARDENING`。

```bash
git -C /home/hanqing/.cache/cve-analyzer/repos/github.com_mervinpraison_praisonai show 3cd664bf7b7db5f774c1e7e3123a1a24c68ba700^:src/praisonai-agents/praisonaiagents/tools/spider_tools.py
git -C /home/hanqing/.cache/cve-analyzer/repos/github.com_mervinpraison_praisonai show 3cd664bf7b7db5f774c1e7e3123a1a24c68ba700 -- src/praisonai-agents/praisonaiagents/tools/spider_tools.py src/praisonai-agents/praisonaiagents/tools/python_tools.py
git -C /home/hanqing/.cache/cve-analyzer/repos/github.com_mervinpraison_praisonai show 179cab02dbec0c1e9b601507a65908e079876004 -- src/praisonai-agents/praisonaiagents/tools/spider_tools.py src/praisonai-agents/praisonaiagents/tools/python_tools.py
```

### Row 76：Argo allowlist 减少风险，但整体放行 ArtifactGC

两条是分支复制：`251bb231d6^ → 251bb231d6 → 358cc3968c` 与 `2727f3f701^ → 2727f3f701 → 277e9cef0a`。parent 在 `MustUseReference` 下仅阻止顶层 `PodSpecPatch`，其余敏感 `WorkflowSpec` 可 merge。candidate 新增 `ValidateUserOverrides`/`SanitizeUserWorkflowSpec`，阻止多数敏感字段，但 allowlist 整体放行 `ArtifactGC`；fix 只补 `ArtifactGC.ServiceAccountName`、`PodSpecPatch`、`PodMetadata`。删除 candidate 会恢复更广泛越权，故是 `FALSE_INCOMPLETE_HARDENING`，不是新攻击面。

```bash
git -C /home/hanqing/.cache/cve-analyzer/repos/argoproj_argo-workflows show 251bb231d62a0f4e5e03dcc13c3f2ae456b2fa34 -- workflow/controller/operator.go workflow/util/merge.go
git -C /home/hanqing/.cache/cve-analyzer/repos/argoproj_argo-workflows show 358cc3968c8f06f1be0967e41df191088db0b662 -- workflow/util/merge.go
git -C /home/hanqing/.cache/cve-analyzer/repos/argoproj_argo-workflows show 251bb231d62a0f4e5e03dcc13c3f2ae456b2fa34^:workflow/controller/operator.go
```

### Rows 98/100/109/110：supplement 的四个“incomplete hardening”均不满足 but-for

- Fission `2db76f65db...` 的主题是拒绝危险 PodSpec 字段，并新建 denylist/validator；`2569b42bfa...` 只补 `SYS_TIME`，`695d3e97e3...` 只补遗漏的 Runtime/Builder standalone container。parent 更宽泛地允许危险字段。
- Registry `257eb178cf...` 的主题是阻止 SSRF，已把 unrestricted client 换成 `safeDialContext`；`f5f40bd980...` 只补 6to4、NAT64、site-local IPv6 CIDR。
- Fission `0d851525a3...` 的 commit message 明说 harden Builder Clean：把 raw `filepath.Join` 改成旧 `SanitizeFilePath`；`8298e33ea7...` 再以 `RootJoin` 替代有 sibling-prefix 缺陷的 helper。

共同点是 candidate 净减风险、删除 candidate 会更糟。因此四项均为 false positive，而不是 causal contributor。

```bash
git -C /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_fission_4d88e44809c5e5f15bf7f3dd33b6092f06b4eeb19114e21ba2df793b6177b725 show 2db76f65db --
git -C /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_fission_4d88e44809c5e5f15bf7f3dd33b6092f06b4eeb19114e21ba2df793b6177b725 show 2569b42bfa --
git -C /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_fission_4d88e44809c5e5f15bf7f3dd33b6092f06b4eeb19114e21ba2df793b6177b725 show 695d3e97e3 --
git -C /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_fission_4d88e44809c5e5f15bf7f3dd33b6092f06b4eeb19114e21ba2df793b6177b725 show 0d851525a3 --
git -C /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_registry_29b2997ea8cfaf7ac0827767387398565017ee92e1678eef1fd86a2417fb2402 show 257eb178cf --
git -C /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_registry_29b2997ea8cfaf7ac0827767387398565017ee92e1678eef1fd86a2417fb2402 show f5f40bd980 --
```

### Row 16：安全修复主题下的真实回归

`847d08bdd135e5c3659f2e6dea2f0cd36617af9b` 不是因为“security fix”主题就被排除。它把 POSIX 上合法的反斜线文件名 `..\\..\\x` 规范化成 `../../x`，把原先 Windows-only 的问题制造成跨平台 traversal；`8503ba61ff51d48a7313896483d130eb6a5abfe0` 把反斜线中和为 `_` 并补 normalized-root containment。因此本项是 `DIRECT_ROOT`。

```bash
git -C /home/hanqing/.cache/cve-analyzer/repos/filebrowser_filebrowser show 847d08bdd135e5c3659f2e6dea2f0cd36617af9b --
git -C /home/hanqing/.cache/cve-analyzer/repos/filebrowser_filebrowser show 8503ba61ff51d48a7313896483d130eb6a5abfe0 --
```

## 118/118 逐项判定表

表中 `R` 表示 `DIRECT_ROOT`，`C` 表示 `VALID_CONTRIBUTOR`，`F` 表示 `FALSE_POSITIVE`。每一行的 candidate/fix 来自 union ledger 的 full-SHA edge；`carrier:` 只表示 import/squash carrier，不把 carrier 当 atomic origin。

| audit_row | component | verdict | causal_role | candidate → fix | parent/delta/fix 机制证据 |
|---|---|---|---|---|---|
| U001 | CVE-2026-32111 | VALID | R_DIRECT_ROOT | `aae7acba91 (carrier:39806871) → dc8eaa16a8` | Home Assistant OAuth URL fetch/redirect SSRF 在 candidate atomic delta 建立，fix 在同 fetch boundary 收口。 |
| U002 | CVE-2026-6830 | VALID | R_DIRECT_ROOT | `d2b27f6f1e → 88dc8bbe26` | Hermes profile/env trust-boundary leak 由 candidate 建立，fix 直接约束 profile-derived environment。 |
| U003 | GHSA-PWF7-47C3-MFHX | VALID | C_NEW_SURFACE | `070aae8e53 (carrier:a7c5a005) → 6b7c6ef5c3` | candidate 新增 `prek-version` action/vector 并接入既有 shell/extra-args 缺陷；删除它仅移除新增表面。 |
| U004 | CVE-2026-32247 | VALID | C_NEW_SURFACE | `99923c0352 → 7d65d5e77e` | candidate 新增 `graphiti.nodes`/driver-operations 生产 API，并在新 Neo4j search path 重写未校验的 `group_ids` Lucene 拼接；旧 search API 根因更早，fix 加 `validate_group_ids`。 |
| U005 | CVE-2026-14611 | VALID | R_DIRECT_ROOT | `bce0d2ba79 → 6d709229b5` | Mysti project-memory identity/key collision 在 candidate delta 出现，fix 改为稳定隔离键。 |
| U006 | CVE-2026-31998 | VALID | R_DIRECT_ROOT | `cc048a295e (carrier:03586e3d) → 0ee30361b8` | Synology channel 的 empty-allowlist fail-open 由 atomic candidate 创建；fix fail closed。 |
| U007 | CVE-2026-1979 | VALID | R_DIRECT_ROOT | `1de6340f1b,2b72d8a7c1 → e50f15c1c6` | 两个 mruby commits 组合出 pinned-variable trigger 和错误 opcode rewrite；fix 在优化前校验 opcode。 |
| U008 | CVE-2026-62312 | FALSE | F_WRONG_EDGE | `7648c3412b → da667836cc` | parent 已有 MCP/v1 gate；危险 `x-9r-real-ip` locality 由后续 human `b282f055` 创建。 |
| U009 | CVE-2026-32021 | VALID | R_DIRECT_ROOT | `4286755f26 (carrier:2267d58a) → 4ed87a6672` | 上游 atomic 以 mutable Feishu `senderName` 命中 allowlist；fix 仅接受稳定 ID。 |
| U010 | GHSA-XWCJ-HWHF-H378 | VALID | C_NEW_SURFACE | `506bed5aed → 7a53eb7ea8` | candidate 新增 Telegram sticker 下载和含 bot token URL；共享 media error logging 更早，fix 做 URL/secret redaction。 |
| U011 | GHSA-5WP8-Q9MX-8JX8 | VALID | R_DIRECT_ROOT | `91f6c2bf98,d3480ca940,3c4368da0a → 68916c3e4f` | candidate commits 创建/重写 literal/regex blocklist 与 empty-list policy；fix 封堵 exact bypasses。 |
| U012 | CVE-2026-55197 | VALID | R_DIRECT_ROOT | `ee672df463 → 2a3baa71b8` | `/api/session` 改为按目标 session.profile 读 state DB，首次允许跨 profile transcript；fix 绑定 active profile。 |
| U013 | CVE-2026-27627 | VALID | R_DIRECT_ROOT | `e193701def (carrier:7a100672) → ba3db953c0` | Reddit `meta.readableContentHtml` 直通分支由 atomic candidate 新建；fix DOMPurify。 |
| U014 | GHSA-GH4H-34GR-87R7 | VALID | R_DIRECT_ROOT | `700ff33db7 → bca426de7d` | candidate 首次把 OAuth2 credentials 放入共享 test-result bindings；fix 清洗并按 user 隔离 polling。 |
| U015 | CVE-2026-41347 | VALID | C_NEW_SURFACE | `f4b03599f0 → 6b3f99a11f` | candidate 新增 `/v1/responses` 并复用既有 trusted-proxy auth；fix 增加 browser-Origin policy。 |
| U016 | CVE-2026-62843 | VALID | R_DIRECT_ROOT | `847d08bdd1 → 8503ba61ff` | candidate 把 POSIX 反斜线名改写成 traversal；fix 中和 `\\` 并校验 normalized root。 |
| U017 | CVE-2026-41339 | VALID | C_NEW_SURFACE | `079af0d0b0 → 676b748056` | candidate 新增 token-only/no-device WS clients，使更多客户端收到 full snapshot；共享 snapshot policy 更早。 |
| U018 | CVE-2026-44114 | VALID | C_NEW_SURFACE | `db67492a00 → 018494fa3e` | candidate 新增 `OPENCLAW_LAUNCHD_LABEL` 特权 consumer；workspace dotenv loader 更早，fix 拒绝 namespace。 |
| U019 | CVE-2026-10291 | VALID | R_DIRECT_ROOT | `0a283f454b → 3f970a974c` | candidate 创建 `/session/grep` attacker-regex path；fix 约束/转义 regex。 |
| U020 | CVE-2026-34218 | VALID | R_DIRECT_ROOT | `31c617c828,5a887953c4,614a7946ae → ddfdacb263,56d617b778` | startup ordering 使 nil client 时 policy 不应用；fix 把 apply 移到 adapter start 后并清 cache。 |
| U021 | CVE-2026-27203 | VALID | R_DIRECT_ROOT | `4c9c826c6f,8c1989e36a → aab0bda75e` | candidate 首次把未拒绝换行的 eBay MCP token 写回 `.env`；fix 校验/转义输入。 |
| U022 | CVE-2026-44219 | VALID | R_DIRECT_ROOT | `d42195e10b → 17a119fe43` | Ciguard 对远端 response 无大小上限的 read path 由 candidate 创建；fix 加 bounded read。 |
| U023 | CVE-2026-44788 | VALID | C_NEW_SURFACE | `8b95e0a76d → 2021a06626` | SharpCompress candidate 重写 sync 并新增 async extraction；只有新增 async surface 构成贡献，旧 sync traversal 更早，fix 两路做 full-path containment。 |
| U024 | CVE-2026-49949 | VALID | C_NEW_SURFACE | `b6b77b4b8e,8348c85cd8,c3a0304298 → 08c171b6b4` | 三个 commits 新增 credentialed providers；共享 HTTP redirect transport 更早，fix 加 same-origin guard。 |
| U025 | CVE-2026-32057 | VALID | R_DIRECT_ROOT | `4a7b813a4f (carrier:20523b91) → ec45c317f5` | candidate 的 trusted-proxy node role/pairing policy omission 建立 exact privilege path；fix 恢复 role restriction。 |
| U026 | CVE-2026-32232 | VALID | C_NEW_SURFACE | `fe70dcd422 (carrier:51bc07a0) → f50c17e11a` | atomic candidate 新建 PDF validate-then-later-I/O seam；共享 revalidation 缺陷更早，fix 在 PDF I/O 前重验。 |
| U027 | CVE-2025-69288 | VALID | R_DIRECT_ROOT | `40331e6100 (carrier:67c7b766) → 2e2ac5cbee` | candidate 以允许 `fs/net` 的自制 Node `vm` 替换 vm2；fix 加 sandbox-code validation。 |
| U028 | CVE-2026-59726 | VALID | R_DIRECT_ROOT | `29d52dfc22 → d00a0a40cd` | candidate 创建公网 3001 和无认证 `/mcp*` 到 terminal bridge；fix 加认证与 bind restriction。 |
| U029 | CVE-2026-32231 | VALID | R_DIRECT_ROOT | `2c9deefbf7 → bf004a20d3` | webhook channel 直接信任 request `sender/chat_id`；fix 使用 server-controlled identity/HMAC。 |
| U030 | CVE-2026-28391 | VALID | C_NEW_SURFACE | `78d08fc574 (carrier:4b3e9c0f) → a7f4a53ce8` | candidate 新增 node-host Windows surface 却复用 POSIX parser；gateway 根因更早，fix 传 platform 并 reject-first。 |
| U031 | CVE-2026-34034 | FALSE | F_REFACTOR_PRESERVATION | `a8aa452475 → 096d4369e5` | candidate 仅把同一 10 个 model 的既有 token shell interpolation 抽成 `HasMetrics`; caller/surface 未增加。 |
| U032 | CVE-2026-43585 | VALID | C_NEW_SURFACE | `f4b03599f0 → acd4e0a32f` | candidate 新 `/v1/responses` 捕获 startup resolvedAuth，扩大既有 stale SecretRef auth；fix 逐请求解析。 |
| U033 | GHSA-PQH8-P93P-2RX7 | VALID | R_DIRECT_ROOT | `66ff2a7c8b → 15d3546c06` | Dynatrace timeframe 进入 DQL 字符串的 injection 由 candidate 建立；fix 约束输入。 |
| U034 | CVE-2026-26321 | VALID | R_DIRECT_ROOT | `4286755f26 (carrier:2267d58a) → 5b4121d601` | 上游 atomic 创建 Feishu media 任意本地路径读取；fix 删除 raw local branch。 |
| U035 | CVE-2026-10281 | VALID | R_DIRECT_ROOT | `f82c783607 → d0b02a800a` | candidate 建立 embedded HTTP server 的无认证访问；fix 加认证 boundary。 |
| U036 | CVE-2026-32034 | VALID | R_DIRECT_ROOT | `079af0d0b0 → 40a292619e` | candidate 把 no-device reject 改成 token 即允许，创建 plaintext insecure-auth path；fix 限回显式 opt-out。 |
| U037 | CVE-2026-34599 | VALID | R_DIRECT_ROOT | `bbb2aa9ad4 → f267a28cb2` | Coolify Livewire `GetLogs` public properties/target selection 由 candidate 暴露；fix 约束 server/resource ownership。 |
| U038 | CVE-2026-34049 | VALID | C_NEW_SURFACE | `473c32270d → b1de75a7c6` | candidate 新增 backup create/update API 把未校验 Mongo collection 输入送入既有 job/shell sink。 |
| U039 | CVE-2025-55526 | VALID | R_DIRECT_ROOT | `ff958e486e → 64f9f86f87` | Prompty `api_server.py` 三条 route 直接 `join` URL filename；fix basename/canonical containment。 |
| U040 | CVE-2026-25505 | VALID | C_NEW_SURFACE | `a7319f0e70 → c31f296888` | candidate 新增无认证 OpenC3 debug endpoint；更广 auth 根因是 human，fix 关闭新增 endpoint。 |
| U041 | CVE-2026-44937 | VALID | C_NEW_SURFACE | `b611530214 → c967a3c184` | Fleet candidate 新增 Azure `visualstudio.com` → `dev.azure.com` URL 归一化表面，并继续把 webhook URL/path 拼进 regex；其他 provider 根因更早，fix QuoteMeta/anchors。 |
| U042 | CVE-2026-42148 | VALID | R_DIRECT_ROOT | `18f30b7fab → dc9322b11f` | Coolify `buildHelperImage()` 首次把 `dev_helper_version` 插入 shell；fix 校验 Docker tag 并 shell-escape。 |
| U043 | CVE-2026-32045 | VALID | C_NEW_SURFACE | `f4b03599f0 → 356d61aacf` | 新 `/v1/responses` 复用未区分 HTTP/WS 的 Tailscale header auth；fix 将 HTTP 设为 false。 |
| U044 | CVE-2026-33890 | VALID | R_DIRECT_ROOT | `b7bf9b7960 → d6c1275a7f` | candidate 重写 middleware 并把 `/passkeys/register` 加回 public prefix，直接重开受保护 route；fix 从 public arrays 删除并强制 admin。 |
| U045 | CVE-2026-22171 | VALID | R_DIRECT_ROOT | `a604df8c83 (carrier:2267d58a) → c821099157` | 上游 atomic 创建 key-derived predictable temp paths；fix 改 UUID。 |
| U046 | CVE-2026-58195 | VALID | R_DIRECT_ROOT | `2a1e2777dd,319c98616b → 0c2ec96773` | agentic-flow MCP tool 把 model-controlled command 送入 `execSync`；fix 移除/约束 shell execution。 |
| U047 | CVE-2026-33331 | VALID | R_DIRECT_ROOT | `3e17621325 (carrier:4f28b695) → 4f0efa8a1d` | oRPC OpenAPI UI 首次内联未转义 attacker data；fix 安全编码/DOM rendering。 |
| U048 | CVE-2026-41394 | VALID | C_NEW_SURFACE | `3e9c8721fb → 2a1db0c0f1` | configured Control UI basePath 的 non-GET fallthrough 新增 unauth plugin route surface；empty-basePath 缺陷更早。 |
| U049 | GHSA-68V4-HMWV-F43H | VALID | R_DIRECT_ROOT | `06dd9b8ed8 → e704323ff3` | Twilio media redirect 跨 origin 转发 auth header 的 transport 由 candidate 建立；fix 限制 redirect credential forwarding。 |
| U050 | CVE-2026-28478 | VALID | R_DIRECT_ROOT | `b0c67ea0b5 (carrier:5c2cb6c5) → 3cbcba10cf` | Feishu webhook body 无界读取 path 由 atomic candidate 建立；fix 加请求大小限制。 |
| U051 | CVE-2026-2376 | VALID | R_DIRECT_ROOT | `24d6083f5a,bb7c06aec0,a6d759cd01 → 9afe28a53b` | Quay registry URL/redirect fetch 允许 internal targets；candidate origins 与 fix 的 SSRF guard 逐项闭合。 |
| U052 | CVE-2026-27695 | VALID | R_DIRECT_ROOT | `3902c8c228 → 94a129ae55` | ZAE rate limiter 的 attacker-controlled partition key/hot partition 由 candidate 创建；fix 规范化 key。 |
| U053 | CVE-2026-10860 | VALID | C_NEW_SURFACE | `687291e596 → a5877559dc` | candidate 新增 MISP EventTemplates delete endpoint 并调用既有 CRUD precedence bug；fix 修 `(POST or DELETE)` 检查。 |
| U054 | CVE-2026-32067 | VALID | R_DIRECT_ROOT | `f05553413d → a0c5e28f3b` | candidate 把全局 Feishu pairing-store read 接入多账号 handler；fix 按 accountId scoped read。 |
| U055 | CVE-2026-61462 | VALID | R_DIRECT_ROOT | `c156ac7675 → e2a81a047a` | GitLab artifact job/pipeline ID 进入路径/请求的 injection 由 candidate 建立；fix 校验 identifiers。 |
| U056 | CVE-2026-67530 | VALID | R_DIRECT_ROOT | `b7b362ae42 → 23838a9959` | automation webhook fetch 接受任意 internal URL；fix 对同一 sink 加 SSRF policy。 |
| U057 | CVE-2026-32001 | VALID | R_DIRECT_ROOT | `079af0d0b0 → ddcb2d79b1` | candidate 的 token/no-device policy 让 node role 绕过绑定；fix 恢复 device/role requirement。 |
| U058 | CVE-2026-34050 | VALID | C_NEW_SURFACE | `acff543e09 → 0fed553207` | candidate 修 cloud 404 后首次让缺 admin gate 的 Settings/Updates 在 cloud 可达；self-hosted 缺陷更早。 |
| U059 | GHSA-8G98-M4J9-QWW5 | VALID | R_DIRECT_ROOT | `c139c021f6 → 57b7634391` | Backend-in-a-Box candidate 直接信任 PayPal webhook body 发 token；fix 验签和 webhook ID。 |
| U060 | CVE-2026-7386 | VALID | R_DIRECT_ROOT | `26be5ccbf1 → 638b162b26` | mail attachment filename traversal 写盘路径由 candidate 创建；fix canonical containment。 |
| U061 | CVE-2026-28451 | VALID | R_DIRECT_ROOT | `4286755f26,822b5f37b7 (carrier:2267d58a) → 5b4121d601` | 上游 Feishu raw/local fetch origins 创建 SSRF/file-read paths；import 仅 carrier，fix 统一 hardened loader。 |
| U062 | CVE-2026-47390 | FALSE | F_INCOMPLETE_HARDENING | `3cd664bf7b → 179cab02db` | parent 已 unrestricted spider fetch；candidate 的 weak URL blacklist 净减风险，fix 只补 alternate loopback encodings。 |
| U063 | CVE-2026-29612 | VALID | R_DIRECT_ROOT | `c4e76eb635 → 31791233d6` | image attachment base64 无大小上限的 request/memory path 由 candidate 创建；fix bounded decode。 |
| U064 | CVE-2026-32002 | VALID | C_NEW_SURFACE | `8d74578ceb → dd9d9c1c60` | candidate 移除 primarySupportsImages gate，使更多 model 配置进入旧 image-tool fsPolicy gap；fix 传 workspaceOnly。 |
| U065 | CVE-2026-10854 | VALID | R_DIRECT_ROOT | `47bf71cc78 → d3adfe1a09` | MISP event-template builder 未按 org/distribution 限制 galaxies 的 query 由 candidate 建立；fix 加 visibility condition。 |
| U066 | CVE-2026-27486 | VALID | R_DIRECT_ROOT | `8befe7f8a7 → 6084d13b95` | OpenClaw cleanup 以全系统 process pattern kill、无 ownership 校验；fix 绑定 child ownership。 |
| U067 | CVE-2026-27487 | VALID | R_DIRECT_ROOT | `a39951d463 → 9dce3d8bf8` | macOS OAuth refresh 把 token JSON 插入 `execSync security`；fix 改 `execFileSync` argv。 |
| U068 | CVE-2026-56678 | VALID | R_DIRECT_ROOT | `706e6513c9 → 126aa244c5` | 9Router Kiro region 拼 upstream URL 并转发 API key；fix allowlist/URL validation。 |
| U069 | CVE-2026-22178 | VALID | R_DIRECT_ROOT | `4286755f26 (carrier:2267d58a) → 7e67ab75cc` | 上游 atomic 直接从 unescaped Feishu mention metadata 构造 RegExp；fix escape 两个 values。 |
| U070 | CVE-2026-41406 | VALID | R_DIRECT_ROOT | `4286755f26 (carrier:2267d58a) → f45e5a6569` | 上游 atomic 把 fetched quoted/root/thread body 注入 context 而不验 fetched sender；fix 过 sender allowlist。 |
| U071 | CVE-2026-54362 | VALID | R_DIRECT_ROOT | `47bf71cc78 → 8aa2bb6d1a` | MISP galaxy visibility condition 误写 PHP comparison 而非 query predicate；fix 精确改查询条件。 |
| U072 | CVE-2026-34149 | VALID | C_NEW_SURFACE | `473c32270d → 99043600ee` | candidate 新增 authenticated create_backup API，把未校验 DB/collection 输入送入既有 backup job；fix API+job 双重校验。 |
| U073 | CVE-2025-13120 | VALID | R_DIRECT_ROOT | `cf8faed585 → eb398971bf` | mruby sort/optimizer UAF trigger 由 candidate delta 创建；fix 反转 unsafe lifetime/opcode handling。 |
| U074 | CVE-2026-47392 | FALSE | F_INCOMPLETE_HARDENING | `3cd664bf7b → 179cab02db` | parent 已 full-builtins Python `exec`；candidate weak pseudo-sandbox 净减风险，移除不会消除 RCE。 |
| U075 | CVE-2026-45539 | VALID | C_NEW_SURFACE | `810d87b2af → f85b9f54ad` | candidate 新增 Claude agents deploy target，复用旧 symlink-dereference helper；fix safe finder/拒绝 symlink。 |
| U076 | CVE-2026-54526 | FALSE | F_INCOMPLETE_HARDENING | `251bb231d6,2727f3f701 → 358cc3968c,277e9cef0a` | parent 更宽泛 unrestricted overrides；candidate allowlist 净收紧但漏 nested ArtifactGC，fix 只补该漏项。 |
| U077 | CVE-2026-41374 | VALID | R_DIRECT_ROOT | `b9b47f5002 → ee52f64226` | candidate 把 Discord audio property 改为真实 `content_type`，激活 auth 前 transcription；fix 把 member access gate 移到 preflight 前。 |
| U078 | CVE-2026-9806 | VALID | R_DIRECT_ROOT | `5a4344884f → cf42409bad` | website notification UI 首次用 `innerHTML` 渲染 `${n.message}`；fix `createElement/textContent`。 |
| U079 | CVE-2026-10855 | VALID | R_DIRECT_ROOT | `41450bdb5d → 7c2200d143` | MISP event-template importer 的 ownership/authorization gap 由 candidate 建立；fix 校验 owner/org。 |
| U080 | CVE-2026-56675 | FALSE | F_WRONG_EDGE | `7648c3412b → da667836cc` | candidate 未创建 real-IP locality trust；危险行来自后续 human `b282f055`，fix 反转后续行。 |
| U081 | CVE-2026-47091 | VALID | R_DIRECT_ROOT | `26a3e984e4 → 234d9aad91` | Claude HUD 信任 stdin `transcript_path` 并读取/缓存任意文件；fix canonical allowed-root validation。 |
| U082 | CVE-2026-32302 | VALID | R_DIRECT_ROOT | `20523b918a → ebed3bbde1` | trusted-proxy WebSocket path 跳过 browser Origin validation，直接建立 privileged operator session；fix 强制 Origin policy。 |
| U083 | CVE-2026-32890 | VALID | R_DIRECT_ROOT | `403ccf079b → d5ae67e5b4` | Anchorr user-mapping dropdown 把 Discord-controlled name 渲染为 HTML；fix safe text rendering。 |
| U084 | CVE-2026-34510 | VALID | C_NEW_SURFACE | `8d74578ceb → 93880717f1` | candidate 新增 native image/UNC media seam 并接到旧 path-policy gap；fix 对该新 surface 做 containment。 |
| U085 | CVE-2026-43576 | VALID | R_DIRECT_ROOT | `75602014db → bc356cc8c2` | candidate 新增 direct WS/WSS CDP URL branch 而跳过 endpoint SSRF validation；fix 在该 branch 调 `assertCdpEndpointAllowed`。 |
| U086 | CVE-2026-45288 | VALID | C_NEW_SURFACE | `18c8d9b463 → 6262496568` | candidate 新增 public PrefixSearch API，把 regConfig 送入既有 flawed SQL fragment；fix shared-entry validation。 |
| U087 | CVE-2026-22172 | VALID | R_DIRECT_ROOT | `079af0d0b0 → 5e389d5e7c` | token-auth/no-device path 保留未绑定 scopes 的 policy 由 candidate 建立；fix 清除/绑定 scopes。 |
| U088 | CVE-2026-28472 | VALID | R_DIRECT_ROOT | `079af0d0b0 → fe81b1d712` | shared-token auth 对缺 device client 的 bypass 由 candidate 建立；fix 恢复 device authentication。 |
| U089 | CVE-2026-13591 | VALID | R_DIRECT_ROOT | `94e14d9d30 → 9b4aff0f10` | Mysti `_isTrackedConversation` 以不充分 channel/contact identity 判定，candidate 创建 collision；fix 稳定复合键。 |
| U090 | CVE-2026-32718 | VALID | R_DIRECT_ROOT | `62c394d3a1 → c15bcd5634` | Coolify mutating Hetzner/cloud validation endpoints 只要求 read permission；fix 要求 write。 |
| U091 | GHSA-VH5J-5FHQ-9XWG | VALID | R_DIRECT_ROOT | `57b7634391 → fdf67a6fba` | Taylor `/get-patch` 以 SELECT 后 UPDATE 消耗 token，candidate 创建 replay race；fix atomic UPDATE RETURNING。 |
| U092 | CVE-2026-32049 | VALID | C_NEW_SURFACE | `506bed5aed → 73d93dee64` | candidate 新增 Telegram static sticker media path，复用 shared max-bytes gap；fix 对该 body 加 size cap。 |
| U093 | CVE-2026-58138 | VALID | R_DIRECT_ROOT | `840ec19c1f → c691e35e76` | Conductor 以 GraalJS `HostAccess.ALL` 替换 Nashorn `--no-java`；fix 禁 host/native/thread/process access。 |
| U094 | CVE-2026-63102 | VALID | C_NEW_SURFACE | `4b0938dd50 → 84822f4051` | candidate 暴露 token-auth Users API，接到既有弱 role validation；fix allowlist roles 且仅 Admin 可授 Admin。 |
| U095 | CVE-2026-10108 | VALID | C_NEW_SURFACE | `ac32a09a6a (carrier:fa0511f4) → 88404da7a2` | candidate 新增 `/music/temp/` 并复用 separator-free prefix check；旧 music path 同缺陷。 |
| U096 | CVE-2026-45796 | VALID | R_DIRECT_ROOT | `f2b9ec2b4b (carrier:9400eaa9) → 57b11d405f` | AI-attributed revert 删除 Azure host allowlist/private-IP client/size cap；fix 恢复同 controls。 |
| U097 | CVE-2026-50569 | VALID | R_DIRECT_ROOT | `c6cd334f00 (carrier:6104e1fd) → 0deed6bf3f` | candidate 退役 HTTPTrigger webhook，但 CEL 漏 RelativeURL/Prefix，重开 direct-API bypass；fix CEL+Go validation。 |
| U098 | CVE-2026-50570 | FALSE | F_INCOMPLETE_HARDENING | `2db76f65db (carrier:e484df84) → 2569b42bfa` | candidate 新 denylist 阻止六项 capability 但漏 SYS_TIME；相对 unrestricted parent 是净 hardening。 |
| U099 | CVE-2026-32885 | VALID | C_NEW_SURFACE | `93f80ea447 (carrier:5f988451) → 05cbe29977` | candidate 新增 DDEV Untar symlink extraction；旧 regular-file ZipSlip 根因更早，fix 校验 entry/link targets。 |
| U100 | CVE-2026-44430 | FALSE | F_INCOMPLETE_HARDENING | `257eb178cf (carrier:1201cbd8) → f5f40bd980` | candidate 已用 `safeDialContext` 阻 SSRF，仅漏 IPv6 6to4/NAT64/site-local；删除会恢复 unrestricted client。 |
| U101 | CVE-2026-35670 | VALID | R_DIRECT_ROOT | `ce12b9092f (carrier:9a3800d8) → 7ade3553b7` | Synology reply recipient 用 mutable username/nickname 映射；fix 默认稳定 webhook numeric user_id。 |
| U102 | CVE-2026-41376 | VALID | R_DIRECT_ROOT | `fbfe2f15fc (carrier:49c60e90) → 8a563d603b` | candidate 把 Matrix thread-root body 加入 context 却不验 root sender；fix 记录 sender 并过 allowlist。 |
| U103 | CVE-2026-45001 | VALID | R_DIRECT_ROOT | `53764bbb4c (carrier:29f20624) → fe30b31a97` | candidate 删除 richer plugin/hook/remote-gateway guards，换成不完整 set-diff denylist；fix 恢复并扩展 protections。 |
| U104 | CVE-2026-41329 | VALID | C_NEW_SURFACE | `01d568c9f5 (carrier:483fba41) → a30214a624` | candidate 新增 exec-event system context，继承旧 `senderIsOwner` semantics；fix 强制 false 并让 auth honor。 |
| U105 | CVE-2026-35635 | VALID | R_DIRECT_ROOT | `cc048a295e (carrier:03586e3d) → 980940aa58` | Synology channel 的默认 webhook path/replaceExisting 造成多账号 route ownership collapse；fix 唯一路径且不 replace。 |
| U106 | GHSA-WXW3-Q3M9-C3JR | VALID | C_NEW_SURFACE | `3d3435b32d (carrier:0deaaa4e) → 9deb7936ab` | candidate 扩 generic OAuth callbacks，复用未绑定 nonce 的 `parseGenericState`；fix 每个 caller 存取比对 oauthState。 |
| U107 | CVE-2026-11330 | VALID | R_DIRECT_ROOT | `924a11eeca (carrier:c6f93298) → f32fda8b35` | claude-mem 以截断 16 hex SHA-256 作 observation identity；fix 替换弱 truncated hash。 |
| U108 | CVE-2026-46672 | VALID | R_DIRECT_ROOT | `c4de834f98 (carrier:a43b6f5c) → 068185751c` | Actual CLI 新 CSV exporter 只做 RFC4180 quoting，未防 formula cells；fix 对 triggers 加前缀。 |
| U109 | CVE-2026-50566 | FALSE | F_INCOMPLETE_HARDENING | `2db76f65db (carrier:e484df84) → 695d3e97e3` | candidate 安全 validator 已减少 PodSpec 风险，仅漏 standalone Runtime/Builder containers；fix 补漏。 |
| U110 | CVE-2026-50568 | FALSE | F_INCOMPLETE_HARDENING | `0d851525a3 (carrier:5a3d68a3) → 8298e33ea7` | candidate 把 raw Join 改成旧 `SanitizeFilePath`，净 hardening；fix 再用 RootJoin 修 sibling-prefix 缺陷。 |
| U111 | CVE-2026-47211 | VALID | R_DIRECT_ROOT | `d30b61759b (carrier:4aaf9147) → 4e70b760b4` | candidate 新增执行相关 `OUROBOROS_CLI_PATH` env override；project `.env` 可指向 attacker code，fix 阻 privileged selectors。 |
| U112 | CVE-2026-25580 | VALID | C_NEW_SURFACE | `6bba553f19 (carrier:afde1c43) → d398bc9d39` | candidate 新增 `force_download`，使 message URL 进入 server fetch；共享 network policy 更早，fix redirect-aware SSRF guard。 |
| U113 | CVE-2025-32425 | VALID | C_NEW_SURFACE | `a75c1af2e4 (carrier:f172b314) → 57a06f7088` | candidate 新增长期 frontend Compose service 而无 log rotation；旧 services 同 advisory，fix 给平台 containers bounded logging。 |
| U114 | CVE-2026-8147 | VALID | R_DIRECT_ROOT | `3e590361e0,f685d19b59 → f9b1eb5104` | MLflow 新 `BatchGetTraceInfos` handler 接受任意 trace IDs 而无 validator；fix 注册 batch/trace auth validators。 |
| U115 | CVE-2026-53598 | VALID | R_DIRECT_ROOT | `19137b339d,a0e6108842,bd50f65d67 → 88ac9948d7` | Prompty TS/C#/Rust `${file:...}` resolver 无 allowed-root；fix 跨 runtime 加 traversal/symlink containment。 |
| U116 | GHSA-W28W-GP39-M4P6 | VALID | R_DIRECT_ROOT | `a0e6108842 → 047756f4c8` | TS v2 unrestricted Nunjucks Environment 渲染 attacker template+host objects；fix 阻 constructor/prototype/calls。 |
| U117 | CVE-2026-53597 | VALID | R_DIRECT_ROOT | `a0e6108842 → c27402da24` | TS v2 loader 启用 executable js/javascript frontmatter engines；fix parse 前拒绝。 |
| U118 | CVE-2026-18980 | VALID | R_DIRECT_ROOT | `ca8b28ad23 (carrier:b58b4215) → a1d7c3ba42` | Ironclaw 把 Low shell risk 映射为无需审批，`env`/`sort` wrapper 可注入；fix 解析 nested wrappers。 |

## 机器校验约束

本报告的逐项表以 `U001` 到 `U118` 为唯一主键；应满足：118 行、118 个唯一 key、连续无缺号，且四类互斥计数为 `77 + 31 + 10 + 0 = 118`。`VALID` 行应为 108，`FALSE` 行应为 10；表中不得出现未裁决 row。
