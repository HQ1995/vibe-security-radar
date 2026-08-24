# NEEDS_REVIEW Batch 2 一手证据复核（2026-08-11）

## 结论

固定的 20 行中，**PASS 10、FAIL 9、NEEDS_REVIEW 1、BLOCKED 0**。

| 状态 | 行号 |
|---|---|
| PASS | 24, 29, 35, 56, 87, 92, 101, 106, 112, 116 |
| FAIL | 36, 39, 59, 61, 67, 97, 99, 107, 153 |
| NEEDS_REVIEW | 44 |
| BLOCKED | 无 |

这里的 PASS 是 class-level 的“AI causal contributor”，不等于 AI 是唯一根因，也不代表旧 ledger 中该 class 的每条 edge 都成立。rows 24、101、106、116 必须使用校正后的 atomic/member edge；rows 29、35、87、92、101、106 是新增 surface 或重实现贡献，报告保留其更早的人类前因。FAIL 是已经找到足以推翻旧 edge 的一手反证；NEEDS_REVIEW 不是肯定项。

## 裁决规则

- 样本固定为 rows `24,29,35,36,39,44,56,59,61,67,87,92,97,99,101,106,107,112,116,153`，发现反证后没有换样本。
- 四项同时闭合才 PASS：candidate parent→delta；first-party advisory 的精确 component/mechanism；真实最小 fix member 的 reversal；AI metadata 绑定真正 causal atomic/member。
- squash、merge、import 和批量安全提交只是 carrier，不能承接 atomic/member 的语义或 AI 归因。
- **OSV `introduced` 和 alias 只用于 recall/routing**，不证明漏洞起源，也不证明 AI 因果。模型 verdict、重复模型票、subject/chronology、same-file 和 `exact_blame_hit` 也都不单独定案。
- 新 surface 只有在 candidate 新增 advisory 覆盖、此前不存在且可利用的入口/配置路径，fix 又关闭该路径时，才计 contributor。只增加旁路 caller、重复已有攻击能力或继承共享 sink 不够。
- 对“重实现”采用同一项目口径：AI 在活跃生产路径中重新写出 advisory 点名的脆弱安全边界，可以是 contributor；必须明确其不是 sole origin，且不得掩盖 parent 中更宽泛的旧漏洞。

## 证据与快照边界

- 选择源：`AUDIT-STRICT-LEDGER-156-2026-08-11.md`，SHA-256 `e95059199f35756a0c95970c5c2950e9c846ffd701c810126a58ff808baf98bb`。
- CVEList checkout：`/home/hanqing/.cache/cve-analyzer/cvelistV5`，HEAD `8ca64b5ad6b84d3cd5741b023610b8494800f174`。
- GitHub Advisory Database checkout：`/home/hanqing/.cache/cve-analyzer/advisory-database`，HEAD `39d8887723797efc1804585dd06585c9fd751226`。
- row 24 的 reviewed GHSA 已不在当前 advisory checkout，但存在于冻结的一方 tar：`research/orchestrator-260809-0539/current-source-snapshots/advisory-database-71ca7b6916b1fb164168b4bb6050d2676e5a8d6a.tar.gz`。
- 本轮未以实时网页内容定案。结论限于当前本地 CVEList/GHSA 一方 JSON、冻结一方 tar 和本地完整 git objects；未来 advisory 撤回、alias 修订、强推或新披露不在覆盖内。

## 20 行裁决

| row | primary / class | 状态 | accepted atomic/member → fix | 一手闭环或反证；旧 edge 处理 |
|---:|---|---|---|---|
| 24 | GHSA-GH4H-34GR-87R7 / `alias-226bc664b77d22042b6f4336` | **PASS** | `700ff33db7470d4d2dd9674e9e29dc5e6392daa4` → `bca426de7dc36d680285295655dc640dea2aab21` | 冻结 reviewed GHSA 点名 automation test result 把 OAuth2 access/refresh token 广播给其他 builders。Claude-coauthored `700ff33d` 首次把 OAuth2 credentials 放入 user-context bindings；fix 对 test result 清洗并按 user 隔离 polling。**拒绝旧 ledger `1e6bf7f4→bca426de`**：`1e6bf7f4` 的直接 parent 已含 token 注入，它只保留/测试该行为。 |
| 29 | CVE-2026-44114 / `alias-2b012541da0847fedc6f6867` | **PASS** | `db67492a00b4520edc459efd3745ce35d7d912ee` → `018494fa3ebb9145112e68b56fe1cb2e9f9a9ed6` | CVEList/GHSA 明列 workspace `.env` 不应覆盖 `OPENCLAW_*` runtime namespace。Claude candidate 新增从 `OPENCLAW_LAUNCHD_LABEL` 驱动 `launchctl kickstart` 的特权 consumer；fix 在 workspace dotenv 边界拒绝整个 namespace。它是新增内部变量 surface contributor，不是 dotenv loader 的 sole origin。旧 edge 可保留。 |
| 35 | CVE-2026-49949 / `alias-3292147318b72b8ffb0807cc` | **PASS** | `b6b77b4b8ea803b671dea666bc76135e6af0c057`, `8348c85cd8d43affa0c9d83be20ff42d895fe1dc`, `c3a0304298597ace4026a9778cb0025309b628a3` → `08c171b6b487654a0eb188494fa24bd1c4272a2e` | 一方 component 是 CodexBar `ProviderHTTPClient` 在 cross-origin/downgrade redirect 上转发 cookies、bearer token、API keys。三个 Claude commits 分别加入 DeepSeek、OpenRouter、Kimi 的 credentialed production callers；fix 在共享 transport 加 same-origin redirect guard。共享 transport 缺陷更早存在，故只声明三个 provider surface contributor；三条旧 edge 均可保留。 |
| 36 | GHSA-48VW-M3QC-WR99 / `alias-345122df586cc319a86cf00a` | **FAIL** | 无 | candidate tree 中，无 device 的 scopes 仍会被 `clearUnboundScopes()` 清除；后续**人工** `7dc447f79f83908c06d9220723881e2047d1278c` 才把 Control UI allow decision 排除在清除条件外，制造 advisory 所述 trusted-proxy scope retention。`ccf16cd8` 增加 `trustedProxyAuthOk` 限制，反转的是后续人工条件。**拒绝 `20523b91→ccf16cd8`**。 |
| 39 | CVE-2026-53871 / `alias-3f21c5b90654e0fdc6c69317` | **FAIL** | 无 | advisory 是 unsigned `hermes_profile` cookie 决定 profile。ledger candidate `b8b62722` 只加 password auth；备选 AI `d2b27f6f` 加 multi-profile 但也没有 cookie。危险 cookie 由后续人工 `3246b263d9600d885d12ecacf0d661e0cfcd5fad` 创建。真实 production fix member 是 `4dca506858651d5424842f166b47f7ca40b031c7`，`9e96f5f6` 只是 merge carrier。**拒绝 `b8b62722→9e96f5f6`**。 |
| 44 | CVE-2026-59726 / `alias-4746e8151755cf3b6ee6d14d` | **NEEDS_REVIEW** | 暂无 claim-grade accepted edge | CVEList 点名 `ruflo/docker-compose.yml` 的公网 `3001:3001` 和 `ruflo/src/{,ruvocal/}mcp-bridge/index.js` 的无认证 `/mcp*`→`terminal_execute`。这些路径在 ledger candidate `dba545f0` 中不存在；真正 file-creation commit 是九个月后的 `29d52dfc22842b80928d058c88f446993ec4975c`，fix 是 `d00a0a40cd8bdbca877ac7f675f416bdc69accd1`。`29d52dfc` 只有 `Co-Authored-By: claude-flow <ruv@ruv.net>`，缺少可把它 fail-closed 绑定到具体 AI 模型/bot 的独立一方 metadata。**拒绝旧 `dba545f0→d00a0a40`；候选 corrected edge `29d52dfc→d00a0a40` 暂不晋级**。 |
| 56 | CVE-2026-32034 / `alias-62042a3acb09a9a9ad48ae77` | **PASS** | `079af0d0b02ca2c722f90b6c4e38e27ba16227b4` → `40a292619e1f2be3a3b1db663d7494c9c2dc0abf` | Claude candidate 把“无 device 一律拒绝”改成“只要有 token 就允许”，并跳过缺失 device 的 token verify；这直接创建 plaintext `allowInsecureAuth` 下 token-only/no-device path。fix 将 Control UI bypass 限回明确 dangerous opt-out，直接关闭该 path。旧 edge 可保留。 |
| 59 | CVE-2026-28467 / `alias-65440601a2765bf3af347327` | **FAIL** | 无 | advisory 是模型控制任意 attachment/media URL 的 SSRF/exfiltration。Claude `506bed5a` 的 Telegram sticker URL 固定为 `api.telegram.org/file/bot.../<Telegram file_path>`，攻击者不能选择 arbitrary host；它不是 advisory 的 URL trust boundary。`81c68f58`/`9bd64c8a` 修共享任意 URL callers，即使没有 sticker candidate 也完整必要。**拒绝 `506bed5a→9bd64c8a`**。 |
| 61 | CVE-2026-34167 / `alias-6a88b736c4383ca31560be8f` | **FAIL** | 无 | candidate parent 已有 public `$activityId` 和无 team scope 的 `Activity::find($this->activityId)`；Claude `30d206e7` 只改 UI/header、事件 flag，并把一个 boarding activity 接到既有组件。真实 fix member `3e0d48faeaab950bfd063dfca908f1d140316ede` 才加 `#[Locked]` 和 team/server ownership，`2729dffb` 是 merge carrier。**拒绝 `30d206e7→2729dffb`**。 |
| 67 | CVE-2026-30246 / `alias-7be28b97d88767f90bbbd437` | **FAIL** | 无 | Fiber cache 的 path-only key 是更早的人类 root；人工 `07589425317d13c107a840d3f1527b89cf2671e7` 已在 ledger candidate 前把默认 key 改成 path+canonical query。Claude `047de649` 自身是 delimiter/DoS 安全加固，其 parent 已 query-aware；`9a0d12c0` 是后续 method/delimiter hardening。**拒绝 `047de649→9a0d12c0`**：候选是 remediation，不是 origin/contributor。 |
| 87 | CVE-2026-41394 / `alias-93fa45f75fcf8a90730ee3e9` | **PASS** | `3e9c8721fb7fea9d890774d4141b3f6faaec438d` → `2a1db0c0f1fa375004a95ba0ef030534790a6d47` | GHSA 点名 unauthenticated `auth:"plugin"` HTTP routes 获得 operator write scope。Claude candidate 让 configured Control UI basePath 的非 GET 请求从 405 改为 fallthrough 到 plugin webhooks，首次让该配置下的未认证 plugin path 可达；fix 对 plugin-auth routes 返回空 scopes。空 basePath 的旧 surface 仍是人类前因，故仅为配置特定 contributor。旧 edge可保留。 |
| 92 | CVE-2026-10860 / `alias-9b86599ed7002e4df341ef1d` | **PASS** | `687291e596674d0dd6055dc461df183a0364599c` → `a5877559dc88ad7a0c935910a652c130489ae2bd` | MISP 一方记录点名 CRUD delete precedence 使 DELETE 绕过 validation。Claude candidate 新建 `EventTemplatesController::delete` 并调用既有 `$this->CRUD->delete`，形成此前不存在的 advisory-covered endpoint；fix 给 `(POST || DELETE)` 加括号并关闭该新 endpoint 的 bypass。共享 CRUD bug 和其他 callers 更早存在，故仅为新 surface contributor。旧 edge 可保留。 |
| 97 | CVE-2026-27964 / `alias-9ece3506614492e6056b3b7a` | **FAIL** | 无 | advisory 是 attacker-controlled `fsNick` cookie 被写入 HTML/log message 的 reflected XSS。`73dd9f06` 的 parent 已读取 raw cookie 并调用同一 `login-user-not-found` message；candidate 只拆分 auth/disabled-user checks。`9066e103` 对这些旧 log calls 加 `htmlspecialchars`，没有反转 candidate delta。**拒绝 `73dd9f06→9066e103`**。 |
| 99 | CVE-2026-35214 / `alias-a0de6e3709572c1f7a3cf526` | **FAIL** | 无 | Budibase advisory 是 multipart filename→`createTempFolder`→remove/extract 的 temp path traversal。Claude `30caf1da` 更换 TAR 库并重写 backup extraction，但 raw plugin filename caller 和 unsafe temp-folder construction 都在 parent 中；旧 `tar` 实现同样可达漏洞。真实最小 fix member `2a09d808f99620d0049ac5df9ad35f8fc18b71a2` 改 plugin upload temp path；`6344d06d` 是含多次 merge/hardening 的 PR carrier。**拒绝 `30caf1da→6344d06d`**。 |
| 101 | CVE-2026-34050 / `alias-a45f374601ed322c071603fe` | **PASS** | `acff543e09ae5c7f8da78e5a092ebb1e57f24dc0` → `0fed553207383f384b93cba24d28122065fa67d5` | Settings/Updates 的 auth omission 在 self-hosted parent 已存在；但 parent 在 cloud 无条件 `Server::findOrFail(0)` 而 404。Claude candidate 明确修 cloud 404，改为 `if (!isCloud())` 后首次让 cloud 上缺少 admin gate 的组件和 mutators 可达。fix 在 `mount()` 增加 `isInstanceAdmin()`，直接关闭该新增配置 path。仅声明 cloud-surface contributor，不声明 sole origin。 |
| 106 | CVE-2026-47390 / `alias-adaf8ed9e0a157cba9b63805` | **PASS** | `3cd664bf7b7db5f774c1e7e3123a1a24c68ba700` → `179cab02dbec0c1e9b601507a65908e079876004` | CVEList 把问题定义为 `spider_tools` SSRF protection 可被 alternate loopback encodings 绕过。AI bot candidate 首次写出 `_validate_url` exact-string blacklist，并把它接到 `Session.get` 前；真实 fix member `179cab02` 加 numeric/hex/`inet_aton`/backslash/control parsing。parent 有更宽泛的 unrestricted SSRF，所以这里只是 advisory-specific weak-protection reimplementation contributor。**拒绝以 merge carrier `b0d8f777` 作为 semantic fix 的旧 edge，改用 member**。 |
| 107 | CVE-2026-32030 / `alias-b18b508dfcd7c43d53c9570f` | **FAIL** | 无 | advisory 是 iMessage remote attachment path→`stageSandboxMedia`→SCP arbitrary absolute path。`8d74578c` 的 parent 已把 first attachment 的 `original_path` 和 `MediaRemoteHost` 送入相同 staging flow，攻击者把任意 path 放第一项即可利用；candidate 只扩为 `MediaPaths` 多附件。packet 的 `fdecf5c5` 只跳过 vision understanding，也不创建 SCP trust boundary。`1316e574` 修共享 root policy。**拒绝 `8d74578c→1316e574`，也拒绝备选 `fdecf5c5→1316e574`**。 |
| 112 | CVE-2026-27487 / `alias-b9a5a8da5751392a45949620` | **PASS** | `a39951d463b9c5377cbe7e08d6953899dca708d8` → `9dce3d8bf83f13c067bc3c32291643d2f1f10a06` | Claude candidate 首次实现 macOS Claude CLI OAuth refresh 写回，并把 token JSON 插入 `execSync("security ... -w ...")` shell command。一方 advisory 精确点名该路径；最早 production reversal `9dce3d8b` 用 `execFileSync("security", argv)`。**拒绝旧 `a39951d4→66d7178f` 作为最小 edge**：`66d7178f` 位于已经含 `9dce3d8b` 的 ancestry 上并继续清除剩余 shell use；`b908388` 只是测试清理。 |
| 116 | CVE-2026-41406 / `alias-bea67a3b6bb5fe42289b5787` | **PASS** | upstream `4286755f26bcfdd5c704cc4eb0cabfdc1b314e68` → import `2267d58afcc70fe19408b8f0dce108c340f3426d` → `f45e5a6569aab1d58cc6de25b19f1dc4c8779b85` | upstream `m1heng/clawdbot-feishu` 的 Claude-coauthored root commit 原子创建 `parentId→getMessageFeishu→quotedContent→agent context`，仅校验触发者而不校验 fetched sender；OpenClaw import 保留该 path。fix 将 quoted/root/thread fetched context 全部过 group sender allowlist。**旧 ledger 的 `2267d58a` 是 import carrier，`5f6e1c19` 是 multi-account sync，均不承接 AI origin；accepted atomic 是 `4286755f`**。 |
| 153 | CVE-2026-44109 / `alias-f4ab3ab628d3387b104d0a46` | **FAIL** | 无 | `2267d58a` 导入时 monitor 明确写着 webhook mode “not implemented”，也尚无后来受影响的 structured card-action lifecycle。missing `encryptKey` 时 `return true` 由后续**人工** `496ca3a6373a3c1203b7a0b82ed8c93acfbb22e0` 写入；blank callback token fail-open 由后续**人工** `fa62231afca31a614d2494a4148e08b130a1601a` 写入。`c8003f1b` 反转这两条后续人工机制。**拒绝 `2267d58a→c8003f1b`**。 |

## 逐案可复现命令

下面均为只读命令。先定义路径：

```zsh
W=/home/hanqing/agents/ai-slop
CV=/home/hanqing/.cache/cve-analyzer/cvelistV5/cves
GH=/home/hanqing/.cache/cve-analyzer/advisory-database/advisories
R=/home/hanqing/.cache/cve-analyzer/repos
V="$W/.ai-slop/cache/cve-analyzer/repos"
OC="$R/openclaw_openclaw"
UPF="$V/v2_github.com_clawdbot-feishu_f25c435dc88d86d445a87247b170272688547b364c53338716dbbc464a40122d"
CB="$V/v2_github.com_codexbar_33118aaca129ca3c666f8cce2b0c2f27fef12501e76700a9e2ddb94277e54115"
```

### row 24

```zsh
TAR="$W/research/orchestrator-260809-0539/current-source-snapshots/advisory-database-71ca7b6916b1fb164168b4bb6050d2676e5a8d6a.tar.gz"
tar -xOzf "$TAR" 'advisory-database-71ca7b6916b1fb164168b4bb6050d2676e5a8d6a/advisories/github-reviewed/2026/07/GHSA-gh4h-34gr-87r7/GHSA-gh4h-34gr-87r7.json' | jq -r '.summary,.details'
git -C "$R/budibase_budibase" show -s --format=fuller 700ff33db7470d4d2dd9674e9e29dc5e6392daa4 1e6bf7f4 bca426de7dc36d680285295655dc640dea2aab21
git -C "$R/budibase_budibase" diff 700ff33d^ 700ff33d -- packages/server/src/sdk/users/utils.ts packages/server/src/automations
git -C "$R/budibase_budibase" diff bca426de^ bca426de -- packages/server/src/automations packages/server/src/api/controllers/automation.ts
```

### row 29

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value,([.references[].url]|join(" "))' "$CV/2026/44xxx/CVE-2026-44114.json"
git -C "$OC" show --format=fuller db67492a00b4520edc459efd3745ce35d7d912ee 018494fa3ebb9145112e68b56fe1cb2e9f9a9ed6
git -C "$OC" diff db67492a^ db67492a | rg -n -C 8 'OPENCLAW_LAUNCHD_LABEL|launchctl|kickstart'
git -C "$OC" diff 018494fa^ 018494fa | rg -n -C 8 'OPENCLAW_|dotenv|workspace'
```

### row 35

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/49xxx/CVE-2026-49949.json"
git -C "$CB" show -s --format=fuller b6b77b4b8ea803b671dea666bc76135e6af0c057 8348c85cd8d43affa0c9d83be20ff42d895fe1dc c3a0304298597ace4026a9778cb0025309b628a3 08c171b6b487654a0eb188494fa24bd1c4272a2e
for s in b6b77b4b 8348c85c c3a03042; do git -C "$CB" diff "$s^" "$s" | rg -n -C 6 'ProviderHTTPClient|Authorization|Cookie|api.?key|bearer'; done
git -C "$CB" diff 08c171b6^ 08c171b6 | rg -n -C 10 'redirect|origin|Authorization|Cookie'
```

### row 36

```zsh
git -C "$OC" show -s --format=fuller 20523b918adff4feae378ac9965e204c56b6e3d8 7dc447f79f83908c06d9220723881e2047d1278c ccf16cd8892402022439346ae1d23352e3707e9e
git -C "$OC" show 20523b91:src/gateway/server/ws-connection/message-handler.ts | rg -n -C 12 'clearUnboundScopes|device|decision.kind'
git -C "$OC" blame ccf16cd8^ -L 509,540 -- src/gateway/server/ws-connection/message-handler.ts
git -C "$OC" diff ccf16cd8^ ccf16cd8 -- src/gateway/server/ws-connection/message-handler.ts
```

### row 39

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/53xxx/CVE-2026-53871.json"
git -C "$R/github.com_nesquena_hermes-webui" show -s --format=fuller b8b62722 d2b27f6f 3246b263d9600d885d12ecacf0d661e0cfcd5fad 4dca506858651d5424842f166b47f7ca40b031c7 9e96f5f6
git -C "$R/github.com_nesquena_hermes-webui" show 3246b263 -- api/helpers.py api/routes.py
git -C "$R/github.com_nesquena_hermes-webui" log --oneline --graph 9e96f5f6^1..9e96f5f6^2
```

### row 44

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value,([.references[].url]|join(" "))' "$CV/2026/59xxx/CVE-2026-59726.json"
git -C "$R/github.com_ruvnet_ruflo" ls-tree -r --name-only dba545f0 | rg '^ruflo/(docker-compose.yml|src/.*/mcp-bridge/index.js)$' || true
git -C "$R/github.com_ruvnet_ruflo" log --all --diff-filter=A --format='%H %P %aI %an <%ae>%n%B%n---' -- ruflo/docker-compose.yml ruflo/src/mcp-bridge/index.js ruflo/src/ruvocal/mcp-bridge/index.js
git -C "$R/github.com_ruvnet_ruflo" show --format=fuller 29d52dfc22842b80928d058c88f446993ec4975c d00a0a40cd8bdbca877ac7f675f416bdc69accd1 -- ruflo/docker-compose.yml ruflo/src/mcp-bridge/index.js ruflo/src/ruvocal/mcp-bridge/index.js
```

### row 56

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/32xxx/CVE-2026-32034.json"
git -C "$OC" show -s --format=fuller 079af0d0b02ca2c722f90b6c4e38e27ba16227b4 40a292619e1f2be3a3b1db663d7494c9c2dc0abf
git -C "$OC" diff 079af0d0^ 079af0d0 -- src/gateway/server/ws-connection/message-handler.ts
git -C "$OC" diff 40a29261^ 40a29261 -- src/gateway/server/ws-connection/message-handler.ts
```

### row 59

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/28xxx/CVE-2026-28467.json"
git -C "$OC" show -s --format=fuller 506bed5aed40820565b7db66a963b8163968208f 81c68f582d4a9a20d9cca9f367d2da9edc5a65ae 9bd64c8a1f91dda602afc1d5246a2ff2be164647
git -C "$OC" show 506bed5a:src/telegram/bot/delivery.ts | rg -n -C 8 'api.telegram.org|fetchRemoteMedia|file_path'
git -C "$OC" show --stat 81c68f58 9bd64c8a
```

### row 61

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/34xxx/CVE-2026-34167.json"
git -C "$R/coollabsio_coolify" show 30d206e7^:app/Livewire/ActivityMonitor.php | rg -n -C 8 'activityId|Activity::find'
git -C "$R/coollabsio_coolify" show --format=fuller 30d206e7b9ed1501c7726d6e30fec22f49969228 3e0d48faeaab950bfd063dfca908f1d140316ede 2729dffb3e30167c1ffd642357b7e0bb99b7d180
git -C "$R/coollabsio_coolify" log --oneline --graph 2729dffb^1..2729dffb^2
```

### row 67

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/30xxx/CVE-2026-30246.json"
git -C "$R/gofiber_fiber" show -s --format=fuller 07589425317d13c107a840d3f1527b89cf2671e7 047de6498f7e8a7a236f70b2994dc66f7231a704 9a0d12c07ed895b84c72987f9288b04137afe5de
git -C "$R/gofiber_fiber" show 047de649^:middleware/cache/cache.go | rg -n -C 10 'canonicalQueryString|DisableQueryKeys|KeyGenerator'
git -C "$R/gofiber_fiber" diff 047de649^ 047de649 -- middleware/cache
```

### row 87

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/41xxx/CVE-2026-41394.json"
git -C "$OC" show -s --format=fuller 3e9c8721fb7fea9d890774d4141b3f6faaec438d 2a1db0c0f1fa375004a95ba0ef030534790a6d47
git -C "$OC" diff 3e9c8721^ 3e9c8721 | rg -n -C 10 'basePath|plugin|405|fallthrough|webhook'
git -C "$OC" diff 2a1db0c0^ 2a1db0c0 | rg -n -C 10 'auth.*plugin|scope|WRITE|operator'
```

### row 92

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/10xxx/CVE-2026-10860.json"
git -C "$R/misp_misp" show -s --format=fuller 687291e596674d0dd6055dc461df183a0364599c a5877559dc88ad7a0c935910a652c130489ae2bd
git -C "$R/misp_misp" diff 687291e5^ 687291e5 | rg -n -C 8 'EventTemplatesController|CRUD.*delete|function delete'
git -C "$R/misp_misp" diff a5877559^ a5877559 | rg -n -C 8 'validationError|POST|DELETE'
```

### row 97

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/27xxx/CVE-2026-27964.json"
git -C "$R/neorazorx_facturascripts" show -s --format=fuller 73dd9f0600c46219fd14bcfba80ca9724b54c2cd 9066e10326029adf012114e27eb5f3f33f78ecfd
git -C "$R/neorazorx_facturascripts" show 73dd9f06^ | rg -n -C 8 'fsNick|login-user-not-found'
git -C "$R/neorazorx_facturascripts" diff 9066e103^ 9066e103 | rg -n -C 8 'htmlspecialchars|fsNick|login-user-not-found'
```

### row 99

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/35xxx/CVE-2026-35214.json"
git -C "$R/budibase_budibase" show -s --format=fuller 30caf1da9024bae688e8d547d04f5a60b0b38e6e 2a09d808f99620d0049ac5df9ad35f8fc18b71a2 6344d06d703660fd05995e61d581593c2349c879
git -C "$R/budibase_budibase" show 30caf1da^ | rg -n -C 8 'createTempFolder|originalname|filename'
git -C "$R/budibase_budibase" log --oneline --graph 6344d06d^1..6344d06d^2
git -C "$R/budibase_budibase" show 2a09d808 -- packages/server/src/api/controllers/plugin
```

### row 101

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/34xxx/CVE-2026-34050.json"
git -C "$R/coollabsio_coolify" show -s --format=fuller acff543e09ae5c7f8da78e5a092ebb1e57f24dc0 0fed553207383f384b93cba24d28122065fa67d5
git -C "$R/coollabsio_coolify" diff acff543e^ acff543e -- app/Livewire/Settings/Updates.php
git -C "$R/coollabsio_coolify" diff 0fed5532^ 0fed5532 -- app/Livewire/Settings/Updates.php
```

### row 106

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value,([.references[].url]|join(" "))' "$CV/2026/47xxx/CVE-2026-47390.json"
git -C "$R/github.com_mervinpraison_praisonai" show -s --format=fuller 3cd664bf7b7db5f774c1e7e3123a1a24c68ba700 179cab02dbec0c1e9b601507a65908e079876004 b0d8f777528f3253a0cfb0a3ef65455da6ae32f6
git -C "$R/github.com_mervinpraison_praisonai" diff 3cd664bf^ 3cd664bf | rg -n -C 10 '_validate_url|localhost|127\.0\.0\.1|Session\.get'
git -C "$R/github.com_mervinpraison_praisonai" diff 179cab02^ 179cab02 | rg -n -C 10 'inet_aton|numeric|backslash|loopback|validate_url'
```

### row 107

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/32xxx/CVE-2026-32030.json"
git -C "$OC" show -s --format=fuller 8d74578ceb0c3b913555dff6265821eb0fc09749 fdecf5c59a40c86459bf6528666566631bfbbd73 1316e5740382926e45a42097b4bfe0aef7d63e8e
git -C "$OC" diff 8d74578c^ 8d74578c -- src/imessage/monitor/monitor-provider.ts
git -C "$OC" show 8d74578c^:src/imessage/monitor/monitor-provider.ts | rg -n -C 10 'original_path|MediaPath|MediaRemoteHost'
git -C "$OC" diff 1316e574^ 1316e574 -- src/auto-reply/reply/stage-sandbox-media.ts src/imessage/monitor/monitor-provider.ts
```

### row 112

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value,([.references[].url]|join(" "))' "$CV/2026/27xxx/CVE-2026-27487.json"
git -C "$OC" show -s --format=fuller a39951d463b9c5377cbe7e08d6953899dca708d8 9dce3d8bf83f13c067bc3c32291643d2f1f10a06 66d7178f2d6f9d60abad35797f97f3e61389b70c b908388245764fb3586859f44d1dff5372b19caf
git -C "$OC" diff a39951d4^ a39951d4 | rg -n -C 12 'security add-generic-password|newValue|execSync'
git -C "$OC" diff 9dce3d8b^ 9dce3d8b -- src/agents/cli-credentials.ts
git -C "$OC" merge-base --is-ancestor 9dce3d8b 66d7178f
```

### row 116

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/41xxx/CVE-2026-41406.json"
git -C "$UPF" show -s --format=fuller 4286755f26bcfdd5c704cc4eb0cabfdc1b314e68
git -C "$UPF" show 4286755f:src/bot.ts | rg -n -C 12 'parentId|getMessageFeishu|quotedContent|allowFrom'
git -C "$OC" show 2267d58a:extensions/feishu/src/bot.ts | rg -n -C 12 'parentId|getMessageFeishu|quotedContent|allowFrom'
git -C "$OC" show --format=fuller f45e5a6569aab1d58cc6de25b19f1dc4c8779b85 -- extensions/feishu/src/bot.ts
git -C "$OC" show -s --format=fuller 2267d58afcc70fe19408b8f0dce108c340f3426d 5f6e1c19bd18ea45addd3afedf2f88cc3064f3f6
```

### row 153

```zsh
jq -r '.containers.cna | .title,.descriptions[0].value' "$CV/2026/44xxx/CVE-2026-44109.json"
git -C "$OC" show 2267d58a:extensions/feishu/src/monitor.ts | rg -n -C 8 'webhook mode|connectionMode'
git -C "$OC" blame c8003f1b^ -L 52,70 -- extensions/feishu/src/monitor.transport.ts
git -C "$OC" blame c8003f1b^ -L 180,205 -- extensions/feishu/src/card-action.ts
git -C "$OC" show -s --format=fuller 496ca3a6373a3c1203b7a0b82ed8c93acfbb22e0 fa62231afca31a614d2494a4148e08b130a1601a c8003f1b33ed2924be5f62131bd28742c5a41aae
git -C "$OC" diff c8003f1b^ c8003f1b -- extensions/feishu/src/monitor.transport.ts extensions/feishu/src/card-action.ts
```

## 对 ledger 的直接影响

- 10 行可以从 NEEDS_REVIEW 收紧为 contributor-PASS；其中 rows 24、106、116 必须替换为 atomic/member edge，row 112 只能保留最小 production reversal。
- 9 行存在明确因果反证，应从 causal ledger 移除旧 edge。
- row 44 的旧 edge 已确定错误，但 corrected origin 的 AI 身份尚不够 claim-grade，所以 class 保留 NEEDS_REVIEW；不能因为 subject 含 “MCP/terminal” 就把九个月前的无关基础系统提交算作 origin。
- 这一批再次证明 class 与 edge 必须分层：class PASS 不会自动使同类的 import、merge、later-hardening 或同文件 edge 有效。
