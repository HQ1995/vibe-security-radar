# NEEDS_REVIEW Batch 1 一手证据复核（2026-08-11）

## 结论

固定抽取的 20 行中，**PASS 16、FAIL 4、NEEDS_REVIEW 0、BLOCKED 0**。

| 状态 | 行号 |
|---|---|
| PASS | 8, 12, 14, 16, 20, 23, 31, 32, 34, 42, 43, 46, 48, 62, 73, 102 |
| FAIL | 37, 70, 74, 75 |
| NEEDS_REVIEW | 无 |
| BLOCKED | 无 |

这里的 PASS 是 class-level 的“AI causal contributor”结论，不等于 AI 是唯一根因，也不表示同一 class 的每条旧 edge 都正确。row 8、34、42、48、73 属于重写或新增 surface 的贡献型 PASS；报告明确保留其人类前因。row 37 的媒体 edge 本身可对应另一个 CVE，但当前 ledger 行把它投影到了错误的 primary/public component，因此该行 FAIL。

## 选择与裁决规则

- 样本由主审预先固定为 rows `8,12,14,16,20,23,31,32,34,37,42,43,46,48,62,70,73,74,75,102`：18 行已有人工 audit record，另加两行 exact packet（34、37）。发现反证后不换样本。
- 四项同时闭合才 PASS：candidate parent→delta；first-party advisory 的精确机制；真实 fix 的直接 reversal 或最小 ancestry；AI metadata 绑定真正 causal atomic/member。
- squash、merge、import 只作 carrier；必须回到 atomic/member。模型 verdict、重复采样票、`exact_blame_hit` 和 OSV `introduced` 都不作为结论证据。
- **OSV `introduced` 只用于 recall/routing**。它不能证明漏洞起源、更不能证明 AI 因果。本报告的 PASS 只依赖 CVEList/GHSA 一方记录、上游 git/PR 对象、commit author/trailer，以及 candidate/fix 代码反事实。
- “新 surface”只有在 candidate 新增 advisory 覆盖、此前不存在且可利用的入口，并由 fix 关闭该入口时才算 contributor；仅调用旧 sink、同文件或同 omnibus fix 不够。

## 证据与快照边界

- 选择源：`docs/AUDIT-STRICT-LEDGER-156-2026-08-11.md`，SHA-256 `e95059199f35756a0c95970c5c2950e9c846ffd701c810126a58ff808baf98bb`。
- CVEList checkout：`/home/hanqing/.cache/cve-analyzer/cvelistV5`，HEAD `8ca64b5ad6b84d3cd5741b023610b8494800f174`。
- GitHub Advisory Database checkout：`/home/hanqing/.cache/cve-analyzer/advisory-database`，HEAD `39d8887723797efc1804585dd06585c9fd751226`。
- 固定来源 tar：`autoresearch/orchestrator-260809-0539/current-source-snapshots/cvelistV5-11ff8d6bde24923d36a0f18758aa2ffaaac220d6.tar.gz` 与 `advisory-database-71ca7b6916b1fb164168b4bb6050d2676e5a8d6a.tar.gz`。tar 仅用于重放一方快照，不提供 AI 因果。
- 本轮未实时联网；结论限于当前本地一方 JSON、完整 git objects 和缓存的 `mcp-go@v0.31.0` 源码。后续 advisory 撤回、alias 修订、强推或新披露不在本轮覆盖内。

冻结快照可先这样查；下面逐案命令则读取当前本地 checkout：

```zsh
W=/home/hanqing/agents/ai-slop
tar -tzf "$W/autoresearch/orchestrator-260809-0539/current-source-snapshots/cvelistV5-11ff8d6bde24923d36a0f18758aa2ffaaac220d6.tar.gz" | rg 'CVE-2026-32247.json|CVE-2025-59829.json'
tar -tzf "$W/autoresearch/orchestrator-260809-0539/current-source-snapshots/advisory-database-71ca7b6916b1fb164168b4bb6050d2676e5a8d6a.tar.gz" | rg 'GHSA-gg5m-55jj-8m5g|GHSA-66m2-gx93-v996'
```

## 20 行裁决

| row | primary / class | 状态 | candidate / true member → fix | 一手闭环或反证 | 本地证据 |
|---:|---|---|---|---|---|
| 8 | CVE-2026-32247 / `alias-081a549b9da97e4d5e1e54c4` | **PASS** | `99923c0352a4679c373b16f0ce45f1391fd589c9` → `7d65d5e77e89a199a62d737634eaa26dbb04d037` | Claude trailer 的 driver-ops 重写重新实现了未校验 `group_ids` 的 Lucene 拼接；GHSA 明列该独立窄路径，fix 加 `validate_group_ids`。旧记录中的 `dcc9da3f6887b84830758d7e89974eb4f2af8f92` 未引入 `node_labels` 拼接，不能承载主 label-injection origin；class PASS 只靠 `99923c0` 的附属 advisory path。 | `scripts/audit_results/CVE-2026-32247.json`; `$GH/github-reviewed/2026/03/GHSA-gg5m-55jj-8m5g/GHSA-gg5m-55jj-8m5g.json`; `$R/getzep_graphiti` |
| 12 | CVE-2026-31998 / `alias-0c1856ecc9f259fe50edd5af` | **PASS** | atomic `cc048a295e7e70684ca24654257e0ecf38e49153` → squash `03586e3d0057b5975090d50dadcc5bc95b51f977` → `0ee30361b8f6ef3f110f3a7b001da6dd3df96bb5` | Atomic Claude commit 新建 Synology channel 的 empty-allowlist fail-open；三个安全关键文件在 squash 中 blob 完全相同；fix 改为 fail closed。 | `scripts/audit_results/CVE-2026-31998.json`; `$CV/2026/31xxx/CVE-2026-31998.json`; `$V/v2_github.com_openclaw_c2e21135e2e4d103a91f04425616aa5d7d8c5dd28582aa10a12b6898fde51b0f` |
| 14 | CVE-2026-1979 / `alias-0c32bc35f9b2dfd939667e3` | **PASS** | `1de6340f1bc81564274890660f66444e48d660b0` + `2b72d8a7c153e2afb22245ad9e40e0c7d5b1aa70` → `e50f15c1c6e131fa7934355eb02b8173b13df415` | 两个 Claude-coauthored commits 分别加入 pinned-variable trigger 与错误的 JMPNOT→JMPIF optimizer；fix 在改写前验证 opcode，直接关闭 bytecode corruption/UAF 链。 | `scripts/audit_results/CVE-2026-1979.json`; `$CV/2026/1xxx/CVE-2026-1979.json`; `$R/mruby_mruby` |
| 16 | CVE-2026-32021 / `alias-12debd2395456ef3aa1dd946` | **PASS** | upstream atomic `4286755f26bcfdd5c704cc4eb0cabfdc1b314e68` → import `2267d58afcc70fe19408b8f0dce108c340f3426d` → `4ed87a667263ed2d422b9d5d5a5d326e099f92c7` | 上游 Claude 初始提交直接允许 mutable `senderName` 命中 allowlist；该函数的 27 行在 OpenClaw import 中逐字相同；fix 删除 name grant，只接受规范化 ID。AI 归因落在 upstream atomic，不转移给 import carrier。 | `scripts/audit_results/CVE-2026-32021.json`; `$CV/2026/32xxx/CVE-2026-32021.json`; upstream `$V/v2_github.com_clawdbot-feishu_f25c435dc88d86d445a87247b170272688547b364c53338716dbbc464a40122d`; `$R/openclaw_openclaw` |
| 20 | GHSA-5WP8-Q9MX-8JX8 / `alias-1a8156c9b0ac4e49d726cdc4` | **PASS** | `91f6c2bf98e40238ad4d175513f0ee400fd62068`, `d3480ca94087b74f110bb5b80fc8219b32c8b8b5`, `3c4368da0ab48c1091858d3f9503c378a209997f` → `68916c3e4f3af107f11940b27854fc7ef517058b` | 三个 Claude commits 直接创建/重写 advisory 点名的 literal/regex blocklist 与 first-token/empty allowlist；fix 分别封堵 metacharacter、combined flags、glob 和 empty strict list。 | `scripts/audit_results/GHSA-5wp8-q9mx-8jx8.json`; `$GH/github-reviewed/2026/03/GHSA-5wp8-q9mx-8jx8/GHSA-5wp8-q9mx-8jx8.json`; `$R/qhkm_zeptoclaw` |
| 23 | CVE-2026-27627 / `alias-21d75c6b2298811581b2259d` | **PASS** | atomic `e193701defac96a4403470971363faf0e32a84d6` → squash `7a10067234b19c2c35fb51670173cd82c97cc807` → `ba3db953c0d8675e2e3ecc29113a332b570b2cb9` | Atomic Claude commit 新建 Reddit `meta.readableContentHtml` 直通分支；squash 只改 IPC/日志等周边，危险三元分支保留；fix 对该分支调用 DOMPurify。 | `scripts/audit_results/CVE-2026-27627.json`; `$CV/2026/27xxx/CVE-2026-27627.json`; `$R/karakeep-app_karakeep` |
| 31 | CVE-2026-34218 / `alias-2d420fc19cb5fabda6edbe92` | **PASS** | `31c617c8286a0707e1c7e65ec6469013d40b3ff1` + `5a887953c45551879797fd9e11a2055cf9386d7e` + preserving refactor `614a7946aecf2456893498f24ac18be5ed57f196` → `ddfdacb2633681bbd9c2f41dbd536ea039386628` + `56d617b778c571e3c29b803636d9807940992daa` | Claude commits 组合出确定性 startup ordering bug：`updatePolicy` 在 nil client 时返回，而 policy apply 发生在 `adapter.start()` 前；fix 把 apply 移到 start 后并清 cache。ledger 的 `d068148a`/`9af5bb43` 模型 edges 不用于本 PASS。 | `scripts/audit_results/CVE-2026-34218.json`; `$CV/2026/34xxx/CVE-2026-34218.json`; `$R/github.com_craigjbass_clearancekit` |
| 32 | CVE-2026-27203 / `alias-2e4283d234c17809cb8d3294` | **PASS** | `4c9c826c6fc8b64a20e948cb46fefdda42d5244d` + reimplementation `8c1989e36ad2950fcf4c8f9f95027ebf487e0f61` → `aab0bda75ea9dd27aa37d0d8524d7cf41b3c4a9a` | Claude author首次加入 `.env` token 写回且不拒绝换行；后续 Claude quoting 仍允许换行注入；fix 校验/转义 trust-boundary 输入。 | `scripts/audit_results/CVE-2026-27203.json`; `$CV/2026/27xxx/CVE-2026-27203.json`; `$R/yosefhayim_ebay-mcp` |
| 34 | CVE-2026-44788 / `alias-32624290ded12d479653d429` | **PASS** | `8b95e0a76d6b387533175730e2895ccd16772d07` → `2021a06626d0555a4d69471386e763ca5f5d5dfb` | Copilot commit 重写/更名同步 extraction，并新建 async `WriteToDirectoryAsync`，两路都用 archive entry 构造目录而无 root containment；fix 在同步/异步实现加入 `GetFullPath`+prefix check。同步旧实现已有同缺陷，因此只声明 reimplementation/new-async contributor，不声明 sole origin。 | `$CV/2026/44xxx/CVE-2026-44788.json`; `$GH/github-reviewed/2026/05/GHSA-6c8g-7p36-r338/GHSA-6c8g-7p36-r338.json`; `$V/v2_github.com_sharpcompress_772dfee2eaf91a5bccdc35913a4fce1142f2597f42591d455bb5ed9709f810ba` |
| 37 | CVE-2026-34426 / `alias-39623f401c4ed1875acfdda0` | **FAIL** | ledger edge `8d74578ceb0c3b913555dff6265821eb0fc09749` → `93880717f1cd34feaa45e74e939b7a5256288901` | edge 对 Windows media/UNC 机制成立，但 public component 错绑：当前 CVEList 的 `/cves/2026/34xxx/CVE-2026-34426.json` 明确是 environment-normalization approval bypass、fix `b57b680c...`；正确的 media CVE 是同目录 `CVE-2026-34510.json`，fix `4fd7feb0...`/`93880717...`。GHSA-h3x4 缓存的 `aliases:["CVE-2026-34426"]` 与这两个 first-party CVE records 冲突。row 37 primary/public_exact 失败。 | `$CV/2026/34xxx/CVE-2026-34426.json`; `$CV/2026/34xxx/CVE-2026-34510.json`; `$GH/github-reviewed/2026/03/GHSA-h3x4-hc5v-v2gm/GHSA-h3x4-hc5v-v2gm.json`; `$R/openclaw_openclaw` |
| 42 | CVE-2026-32232 / `alias-444d166bd62f8714937b931d` | **PASS** | atomic `fe70dcd422adbd1e95c90b097489380bf84c4c55` → squash `51bc07a02484ddfd2ec9c7f382dc43f829a9df86` → `f50c17e11ae3e2d40c96730abac41974ef2ee2a8` | Claude atomic 新建 PDF read 的 validate→later-I/O seam；squash 的变化是安全 hunk 外格式/UTF 修正，仍保留 seam；fix 在 PDF I/O 前加入 `revalidate_path`。共享 validator 缺陷更早存在，故只声明新增 PDF surface contributor。 | `scripts/audit_results/CVE-2026-32232.json`; `$CV/2026/32xxx/CVE-2026-32232.json`; `$R/qhkm_zeptoclaw` |
| 43 | CVE-2025-69288 / `alias-470d0cf2ef6e3a7cf2d1be73` | **PASS** | atomic `40331e610075e7c9a076873cc5b3655362d136db` → squash `67c7b7663219c9e28fce487b1803706b333c2a4f` → `2e2ac5cbeed47a76720b21c7fde0214a242e065e` | Copilot atomic 将 `vm2` 换成自制 Node `vm` sandbox，且允许 `fs/net/...`、无输入 validation；squash 保留该安全边界降级；fix 首次在执行前调用 `validateSandboxCode`。 | `scripts/audit_results/CVE-2025-69288.json`; `$CV/2025/69xxx/CVE-2025-69288.json`; `$R/kromitgmbh_titra` |
| 46 | CVE-2026-32231 / `alias-48acec3eadce8bee986a75d3` | **PASS** | `2c9deefbf744089c3041885717b92c6f2fc0bf8c` → `bf004a20d3687a0c1a9e052ec79536e30d6de134` | Claude commit 首次创建 webhook channel，直接把 request JSON 的 `sender/chat_id` 用于 allowlist 与 routing；fix 改为 server-controlled identity 并加可选 HMAC。 | `scripts/audit_results/CVE-2026-32231.json`; `$CV/2026/32xxx/CVE-2026-32231.json`; `$R/qhkm_zeptoclaw` |
| 48 | CVE-2026-28391 / `alias-4f3fe99f85fab6a063ea6784` | **PASS** | atomic `78d08fc574af8742c674cd6b986cd61a46d811e6` → squash `4b3e9c0f339d3b0af21dbbd699b378899ec6e193` → `a7f4a53ce80c98ba1452eb90802d447fca9bf3d6` | Claude atomic 首次让 node host 的 on-miss 请求通过 POSIX parser/allowlist 命中而跳过 prompt；squash 保留该效果；fix 把 node platform 传入 evaluator 并新增 Windows reject-first parser。gateway 有更早人类前因，故只声明新增 node-host contributor。 | `scripts/audit_results/CVE-2026-28391.json`; `$CV/2026/28xxx/CVE-2026-28391.json`; `$V/v2_github.com_openclaw_c2e21135e2e4d103a91f04425616aa5d7d8c5dd28582aa10a12b6898fde51b0f` |
| 62 | CVE-2025-55526 / `alias-6cc43b070d8c0d98ab41f2c2` | **PASS** | `ff958e486e1f8de4f7fd43c70ef357b8d6eaf433` → first removal `64f9f86f87c23705fda6faa9947a947bf48b12c2`；later hardening `5ffee225b7c9e314cacefd7f0a46a1c10ae3d20e` | Claude-generated commit 首次创建 `api_server.py`，三条路由把 URL filename 直接传给 `os.path.join("workflows", filename)`；`64f9f86f` 先以 basename 搜索移除直接 traversal，`5ffee225` 再做显式 canonical containment。 | `scripts/audit_results/CVE-2025-55526.json`; `$CV/2025/55xxx/CVE-2025-55526.json`; `$R/zie619_n8n-workflows` |
| 70 | CVE-2026-21882 / `alias-7fd746400e61bcd63065c0f5` | **FAIL** | rejected `0fc1b4f701171346848fd4f3b3faa967442108fb`; true fix member `e24169064d77e51788b496ca13f18d96cbbbbb0c` → merge carrier `5293957b119e55212dce2c6dcbaf1d7eb794602a` | candidate parent 已以 `Command::new(...).output()` 在当前特权下完整执行用户命令；Copilot candidate 只换成 `.spawn()`+timeout，未新增未降权机制。真正首次加入 `PermissionIssue` 与 `pre_exec(initgroups/setgid/setuid)` 的是 second-parent chain member `e241690...`；5293957 是 merge carrier。 | `scripts/audit_results/CVE-2026-21882.json`; `$CV/2026/21xxx/CVE-2026-21882.json`; `$R/asfhtgkdavid_theshit` |
| 73 | CVE-2026-33890 / `alias-8215494358ad2dbd50e4323c` | **PASS** | human roots `6fdfa90d0190488e263bf49e6f477572a7c30538`/`f85ae9b0d6e4a6480c6af5b675a99069d08d496e`; AI reimplementation `b7bf9b7960958c6c51f85fe50a2fc041a086c466` → `d6c1275a7ff7ffd3d51b53c333237f4d572580ac` | AI commit 重写两个 auth middleware，并在新 `PUBLIC_PREFIX_PATHS` 中明确重新放行 `/passkeys/register`；fix 从两数组删除并在 controller 强制 admin。结论是 AI reimplementation contributor，非人类 root 的替代。 | `scripts/audit_results/CVE-2026-33890.json`; `$CV/2026/33xxx/CVE-2026-33890.json`; `$R/franklioxygen_mytube` |
| 74 | CVE-2025-59163 / `alias-84fe44b018f673f30819b921` | **FAIL** | rejected `cd7caffb4aa568d07edc0d21bbd7dabd38ef7e2c`; fix `0ae3560ba11846375812377299fe078d45cc3d48` | parent 已用 first-party dependency `mcp-go v0.31.0` 的 `SSEServer.Start` 启动 `http.Server{Handler:s}`；该 handler 的 GET/message path 已无 Host/Origin guard 且 GET SSE 已给 `Access-Control-Allow-Origin:*`。Copilot candidate 只是等价展开 Start，并为 HEAD 加 wrapper；所有可读取数据库的 GET/message 仍 delegate 给同一 `s`。fix 即使没有 candidate 也完整必要。 | `scripts/audit_results/CVE-2025-59163.json`; `$CV/2025/59xxx/CVE-2025-59163.json`; `$R/safedep_vet`; `/home/hanqing/go/pkg/mod/github.com/mark3labs/mcp-go@v0.31.0/server/sse.go` |
| 75 | CVE-2025-59829 / `alias-856cb7c398fc0d039859caa3` | **FAIL** | rejected `59372c0921b0170e81f9c63777962d02347411d5`; later plugin remediation `ff0fdc06760d9d8d94cf45549908e06e2ffe36d6` | GHSA 于 `2025-10-03` 发布，affected package 是 `@anthropic-ai/claude-code <1.0.120`；candidate 到 `2025-11-17` 才加入 public marketplace 的 Hookify plugin，时间上不可能是已披露 package 漏洞 origin，组件也不同。`ff0fdc0` 是 2026-01 的 post-advisory plugin remediation。 | `scripts/audit_results/CVE-2025-59829.json`; `$GH/github-reviewed/2025/10/GHSA-66m2-gx93-v996/GHSA-66m2-gx93-v996.json`; `$R/anthropics_claude-code` |
| 102 | GHSA-8G98-M4J9-QWW5 / `alias-a57df415a930e4db1ef3b6f7` | **PASS** | `c139c021f68a09d22c2af88641b61c00f67f2af4` → `57b7634391959dbbdb39b387ac4dc68157cd58a1` | Jules bot candidate 首次创建 Backend-in-a-Box，并直接信任 PayPal webhook body 来发放 purchase token；其直接子提交验证 PayPal signature/`PAYPAL_WEBHOOK_ID`。GHSA 的四项 omnibus 中该 webhook path 精确闭合。 | `scripts/audit_results/GHSA-8g98-m4j9-qww5.json`; `$GH/github-reviewed/2025/06/GHSA-8g98-m4j9-qww5/GHSA-8g98-m4j9-qww5.json`; `$R/tailot_taylored` |

## 逐案可复现命令

以下命令假定 zsh；先定义只读路径：

```zsh
W=/home/hanqing/agents/ai-slop
CV=/home/hanqing/.cache/cve-analyzer/cvelistV5/cves
GH=/home/hanqing/.cache/cve-analyzer/advisory-database/advisories
R=/home/hanqing/.cache/cve-analyzer/repos
V="$W/.ai-slop/cache/cve-analyzer/repos"
OCV2="$V/v2_github.com_openclaw_c2e21135e2e4d103a91f04425616aa5d7d8c5dd28582aa10a12b6898fde51b0f"
```

### row 8

```zsh
jq -r '.summary,.details' "$GH/github-reviewed/2026/03/GHSA-gg5m-55jj-8m5g/GHSA-gg5m-55jj-8m5g.json"
git -C "$R/getzep_graphiti" show --format=fuller 99923c0352a4679c373b16f0ce45f1391fd589c9 -- graphiti_core/driver/neo4j/operations/search_ops.py
git -C "$R/getzep_graphiti" show --format=fuller 7d65d5e77e89a199a62d737634eaa26dbb04d037 -- graphiti_core/driver/neo4j/operations/search_ops.py graphiti_core/helpers.py
git -C "$R/getzep_graphiti" diff dcc9da3f6887b84830758d7e89974eb4f2af8f92^ dcc9da3f6887b84830758d7e89974eb4f2af8f92 -- graphiti_core/search/search_filters.py
```

### row 12

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/31xxx/CVE-2026-31998.json"
for p in extensions/synology-chat/src/security.ts extensions/synology-chat/src/security.test.ts extensions/synology-chat/src/webhook-handler.ts; do git -C "$OCV2" rev-parse "cc048a295e7e70684ca24654257e0ecf38e49153:$p" "03586e3d0057b5975090d50dadcc5bc95b51f977:$p"; done
git -C "$OCV2" show --format=fuller 0ee30361b8f6ef3f110f3a7b001da6dd3df96bb5 -- extensions/synology-chat/src/security.ts extensions/synology-chat/src/webhook-handler.ts
```

### row 14

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value,([.references[].url]|join(" "))' "$CV/2026/1xxx/CVE-2026-1979.json"
git -C "$R/mruby_mruby" show --format=fuller 1de6340f1bc81564274890660f66444e48d660b0 2b72d8a7c153e2afb22245ad9e40e0c7d5b1aa70 e50f15c1c6e131fa7934355eb02b8173b13df415 -- mrbgems/mruby-compiler/core/codegen.c
```

### row 16

```zsh
UP="$V/v2_github.com_clawdbot-feishu_f25c435dc88d86d445a87247b170272688547b364c53338716dbbc464a40122d"
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/32xxx/CVE-2026-32021.json"
diff -u <(git -C "$UP" show 4286755f26bcfdd5c704cc4eb0cabfdc1b314e68:src/policy.ts | sed -n '8,34p') <(git -C "$R/openclaw_openclaw" show 2267d58afcc70fe19408b8f0dce108c340f3426d:extensions/feishu/src/policy.ts | sed -n '8,34p')
git -C "$R/openclaw_openclaw" show --format=fuller 4ed87a667263ed2d422b9d5d5a5d326e099f92c7 -- extensions/feishu/src/policy.ts extensions/feishu/src/bot.ts
```

### row 20

```zsh
jq -r '.summary,.details' "$GH/github-reviewed/2026/03/GHSA-5wp8-q9mx-8jx8/GHSA-5wp8-q9mx-8jx8.json"
git -C "$R/qhkm_zeptoclaw" show --format=fuller 91f6c2bf98e40238ad4d175513f0ee400fd62068 d3480ca94087b74f110bb5b80fc8219b32c8b8b5 3c4368da0ab48c1091858d3f9503c378a209997f 68916c3e4f3af107f11940b27854fc7ef517058b -- src/security/shell.rs
```

### row 23

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/27xxx/CVE-2026-27627.json"
for s in e193701defac96a4403470971363faf0e32a84d6 7a10067234b19c2c35fb51670173cd82c97cc807; do git -C "$R/karakeep-app_karakeep" show "$s":apps/workers/scripts/parseHtmlSubprocess.ts | rg -n -C 4 'readableContentHtml'; done
git -C "$R/karakeep-app_karakeep" show --format=fuller ba3db953c0d8675e2e3ecc29113a332b570b2cb9 -- apps/workers/scripts/parseHtmlSubprocess.ts
```

### row 31

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/34xxx/CVE-2026-34218.json"
git -C "$R/github.com_craigjbass_clearancekit" show --format=fuller 31c617c8286a0707e1c7e65ec6469013d40b3ff1 5a887953c45551879797fd9e11a2055cf9386d7e 614a7946aecf2456893498f24ac18be5ed57f196 56d617b778c571e3c29b803636d9807940992daa ddfdacb2633681bbd9c2f41dbd536ea039386628 -- opfilter/ESInboundAdapter.swift opfilter/XPCServer.swift opfilter/main.swift
```

### row 32

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/27xxx/CVE-2026-27203.json"
git -C "$R/yosefhayim_ebay-mcp" show --format=fuller 4c9c826c6fc8b64a20e948cb46fefdda42d5244d 8c1989e36ad2950fcf4c8f9f95027ebf487e0f61 aab0bda75ea9dd27aa37d0d8524d7cf41b3c4a9a -- src/auth/oauth.ts
```

### row 34

```zsh
SC="$V/v2_github.com_sharpcompress_772dfee2eaf91a5bccdc35913a4fce1142f2597f42591d455bb5ed9709f810ba"
jq -r '.summary,.details' "$GH/github-reviewed/2026/05/GHSA-6c8g-7p36-r338/GHSA-6c8g-7p36-r338.json"
git -C "$SC" show --format=fuller 8b95e0a76d6b387533175730e2895ccd16772d07 2021a06626d0555a4d69471386e763ca5f5d5dfb -- src/SharpCompress/Archives/IArchiveExtensions.cs src/SharpCompress/Archives/IAsyncArchiveExtensions.cs
```

### row 37

```zsh
jq -r '.cveMetadata.cveId,.containers.cna.title,.containers.cna.descriptions[0].value,([.containers.cna.references[].url]|join(" "))' "$CV/2026/34xxx/CVE-2026-34426.json" "$CV/2026/34xxx/CVE-2026-34510.json"
jq -r '.id,.aliases,.summary,.details,([.references[].url]|join(" "))' "$GH/github-reviewed/2026/03/GHSA-h3x4-hc5v-v2gm/GHSA-h3x4-hc5v-v2gm.json"
git -C "$R/openclaw_openclaw" show -s --format=fuller 8d74578ceb0c3b913555dff6265821eb0fc09749 93880717f1cd34feaa45e74e939b7a5256288901 b57b680c0c34de907d57f60c38fb358e82aef8f7
```

### row 42

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/32xxx/CVE-2026-32232.json"
for s in fe70dcd422adbd1e95c90b097489380bf84c4c55 51bc07a02484ddfd2ec9c7f382dc43f829a9df86; do git -C "$R/qhkm_zeptoclaw" show "$s":src/tools/pdf_read.rs | rg -n -C 5 'validate_path_in_workspace|metadata\(&resolved\)'; done
git -C "$R/qhkm_zeptoclaw" show --format=fuller f50c17e11ae3e2d40c96730abac41974ef2ee2a8 -- src/tools/pdf_read.rs
```

### row 43

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2025/69xxx/CVE-2025-69288.json"
git -C "$R/kromitgmbh_titra" show --format=fuller 40331e610075e7c9a076873cc5b3655362d136db 67c7b7663219c9e28fce487b1803706b333c2a4f 2e2ac5cbeed47a76720b21c7fde0214a242e065e -- imports/utils/vm_sandbox.js imports/api/timecards/server/methods.js package.json
```

### row 46

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/32xxx/CVE-2026-32231.json"
git -C "$R/qhkm_zeptoclaw" show --format=fuller 2c9deefbf744089c3041885717b92c6f2fc0bf8c bf004a20d3687a0c1a9e052ec79536e30d6de134 -- src/channels/webhook.rs src/config/schema.rs
```

### row 48

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/28xxx/CVE-2026-28391.json"
git -C "$OCV2" show --format=fuller 78d08fc574af8742c674cd6b986cd61a46d811e6 4b3e9c0f339d3b0af21dbbd699b378899ec6e193 a7f4a53ce80c98ba1452eb90802d447fca9bf3d6 -- src/agents/bash-tools.exec.ts src/infra/exec-approvals.ts
```

### row 62

```zsh
jq -r '.containers.cna | .descriptions[0].value,([.references[].url]|join(" "))' "$CV/2025/55xxx/CVE-2025-55526.json"
git -C "$R/zie619_n8n-workflows" show --format=fuller ff958e486e1f8de4f7fd43c70ef357b8d6eaf433 64f9f86f87c23705fda6faa9947a947bf48b12c2 5ffee225b7c9e314cacefd7f0a46a1c10ae3d20e -- api_server.py
```

### row 70

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/21xxx/CVE-2026-21882.json"
git -C "$R/asfhtgkdavid_theshit" show 0fc1b4f701171346848fd4f3b3faa967442108fb^:src/fix.rs | rg -n -C 8 'Command::new|\.output'
git -C "$R/asfhtgkdavid_theshit" show --format=fuller 0fc1b4f701171346848fd4f3b3faa967442108fb e24169064d77e51788b496ca13f18d96cbbbbb0c -- src/fix.rs src/fix/output.rs
git -C "$R/asfhtgkdavid_theshit" show -s --format='%H %P' 5293957b119e55212dce2c6dcbaf1d7eb794602a && git -C "$R/asfhtgkdavid_theshit" merge-base --is-ancestor e24169064d77e51788b496ca13f18d96cbbbbb0c 5293957b119e55212dce2c6dcbaf1d7eb794602a
```

### row 73

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/33xxx/CVE-2026-33890.json"
git -C "$R/franklioxygen_mytube" show --format=fuller 6fdfa90d0190488e263bf49e6f477572a7c30538 f85ae9b0d6e4a6480c6af5b675a99069d08d496e b7bf9b7960958c6c51f85fe50a2fc041a086c466 d6c1275a7ff7ffd3d51b53c333237f4d572580ac -- backend/src/middleware/roleBasedAuthMiddleware.ts backend/src/middleware/roleBasedSettingsMiddleware.ts backend/src/controllers/passkeyController.ts
```

### row 74

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2025/59xxx/CVE-2025-59163.json"
git -C "$R/safedep_vet" show cd7caffb4aa568d07edc0d21bbd7dabd38ef7e2c^:go.mod | rg 'github.com/mark3labs/mcp-go'
sed -n '285,315p;690,720p' /home/hanqing/go/pkg/mod/github.com/mark3labs/mcp-go@v0.31.0/server/sse.go
git -C "$R/safedep_vet" show --format=fuller cd7caffb4aa568d07edc0d21bbd7dabd38ef7e2c 0ae3560ba11846375812377299fe078d45cc3d48 -- mcp/server/sse.go
```

### row 75

```zsh
jq -r '.published,.modified,.affected,.summary,.details' "$GH/github-reviewed/2025/10/GHSA-66m2-gx93-v996/GHSA-66m2-gx93-v996.json"
git -C "$R/anthropics_claude-code" show -s --format='%H %aI %an <%ae>%n%s%n%b' 59372c0921b0170e81f9c63777962d02347411d5 ff0fdc06760d9d8d94cf45549908e06e2ffe36d6
git -C "$R/anthropics_claude-code" show --stat ff0fdc06760d9d8d94cf45549908e06e2ffe36d6
```

### row 102

```zsh
jq -r '.summary,.details' "$GH/github-reviewed/2025/06/GHSA-8g98-m4j9-qww5/GHSA-8g98-m4j9-qww5.json"
git -C "$R/tailot_taylored" show --format=fuller c139c021f68a09d22c2af88641b61c00f67f2af4 57b7634391959dbbdb39b387ac4dc68157cd58a1 -- templates/backend-in-a-box/index.js lib/handlers/setup-backend-handler.ts
git -C "$R/tailot_taylored" rev-parse 57b7634391959dbbdb39b387ac4dc68157cd58a1^
```

## 对主 ledger 的直接影响

- 这批 20 行可把 16 行从 NEEDS_REVIEW 收紧为 PASS，把 4 行收紧为 FAIL。
- row 37 暴露的是 stale GHSA alias 与当前 CVEList 的冲突：`CVE-2026-34510` 才是 media/UNC advisory。它不应再被当作 `CVE-2026-34426` 的 duplicate；主 ledger 的 row 139 需要按正确 CVE component 独立保留和计数。
- row 70 必须记录真实 fix member `e24169064d77e51788b496ca13f18d96cbbbbb0c`，不能把 merge carrier `5293957b...` 当 semantic member。
- rows 8、31 中旧 audit/model evidence 含有不承担最终结论的边；后续聚合必须保存 class/edge 分离，而不是因为 class PASS 就把所有 edge 设为真。
