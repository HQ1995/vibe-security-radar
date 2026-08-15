# OpenClaw 12 个 `FRONTIER_PASS` 最终冻结审计

日期：2026-08-12

仓库：`openclaw/openclaw`

本地 first-party Git：`/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw`
取证时 `origin/main`：`fb9a62e9956883c1b0aed5fa742d6e527cb9e86d`

## 冻结结论

对主报告列出的 12 行逐项重放后，最终是：

- **PASS：9 个语义组件**；其中 4 个是直接 origin，5 个是有明确调用链/策略维度的 causal contributor；
- **FAIL：3 个**；分别是 squash 中 AI hunk 被擦除、ghost-blame、以及无机制连接；
- **NR：0 个行级裁决**；但第 9 行必须缩窄，`GHSA-XH72-V6V9-MWHC` 中独立的 blank card-action token 分支不属于已接受 webhook 组件，也不计数。

所以，原来的 12 个 provisional frontier **不能 12/12 晋升**。可冻结的 accepted atomic edges 是 9 条；按语义组件计数而不是按 GHSA/CVE 数量计数。

| # | 冻结状态 | 类型 | 语义组件 | 最小 AI commit / 主线 carrier | reversal | 发布见证 | 核心裁决 |
|---:|---|---|---|---|---|---|---|
| 1 | **PASS** | contributor / 新 credentialed surface | MiniMax workspace dotenv endpoint redirect | `7d7f5d85…` | `2f066965…` | `v2026.4.5` vulnerable；`v2026.4.20` fixed | AI commit 新增 TTS provider，从 `MINIMAX_API_HOST` 取 `baseUrl` 并向该 origin 发送 Bearer key；不宣称它是更早共享 dotenv loader 的 sole origin。 |
| 2 | **PASS** | direct origin | Control UI `gatewayUrl` token exfiltration | `c74551c2…` | `a7534dc2…` | `v2026.1.20` 起含 candidate；`v2026.1.29` fixed | candidate 直接把 query 参数写入 active settings；fix 改为 pending confirmation。 |
| 3 | **PASS** | direct origin | native prompt image 绕过 `tools.fs.workspaceOnly` | `8d74578c…` | `370d1155…` | `v2026.1.20` 起含 candidate；`v2026.2.24` fixed | candidate 首次创建 prompt/history image loader，但只检查 sandbox root，未执行 workspace-only assertion；fix 在同一路径补齐。 |
| 4 | **PASS** | contributor / new Browserbase surface | strict browser navigation 的 Node/Chromium DNS split | `75602014…` | `121c452d…` | `v2026.3.8` 起含 candidate；`v2026.4.10` fixed | candidate 新增 direct `ws/wss` remote CDP/Browserbase 路径并把 target URL送入既有 navigation guard；pre-fix guard 在 Node 解析，而 Chromium/remote browser 再解析。共享 guard 更早存在，故只计 surface contributor。 |
| 5 | **PASS** | contributor / new image-ingest surface | sips fail-open pixel/decompression DoS | `8d74578c…` | `0ed4f8a7…` | `v2026.1.20` 起含 candidate；`v2026.3.31` fixed | parent 已有无 pixel cap 的 shared decoder；candidate 新增 prompt/history local-image → `loadWebMedia` → `resizeToJpeg` 路径，并新增 pre-resize sips EXIF 操作。只计新输入面贡献，不计 shared decoder sole origin。 |
| 6 | **PASS** | direct origin | Synology webhook pre-auth token-guess rate limit | member `cc048a29…`；carrier `03586e3d…` | `0b4d0733…` | `v2026.2.22` 起 vulnerable；首个实际 fixed release 是 `v2026.3.28` | AI member 新建 handler，先验 token、后做按 authenticated `user_id` 的 rate limit；carrier 中安全相关文件 byte-identical；fix 新增按 remote IP 的 pre-auth failure limiter。 |
| 7 | **PASS** | direct origin / incomplete-fix residual series | untrusted workspace channel shadow during setup | member `fc1b156d…`；carrier `f4cc93dc…` | `53c29df2…` + `1fede43b…` | `v2026.3.22` 起；`v2026.4.2` 首修；`v2026.4.10` 关 residual | member 新增 scoped, non-activating setup snapshot；carrier 保留 `onlyPluginIds`/`activate:false` 的核心语义。两条 GHSA 是同一 trust invariant 的首修与 residual，不是正式 alias，只计一个组件。 |
| 8 | **FAIL** | erased squash member | CWD path prompt injection | member `d6338abe…`；carrier `42164494…` | `6254e96a…` | carrier 在 `v2026.2.6`；fix 在 `v2026.2.15` | AI member 只给 `resolveUserPath(undefined)` 加 `process.cwd()` fallback；六提交 PR 的 human follow-ups 在 squash 前移除了这三行，并用 `workspace-run.ts` 重写。进入主线的未清理 prompt path 不是该 AI hunk 的 patch-equivalent descendant。 |
| 9 | **PASS（缩窄）** | contributor / integration + incomplete-fix residual | Feishu webhook missing-`encryptKey` fail-open | member `b0c67ea0…`；carrier `5c2cb6c5…` | `7844bc89…` + `c8003f1b…` 的 webhook 半边 | `v2026.2.12` 起；`v2026.3.12` 首修；`v2026.4.15` 关 webhook residual | member 把 webhook HTTP server/dispatcher 引入 OpenClaw；carrier 的 `monitor.ts` 与 member byte-identical。它是 AI-assisted upstream integration contributor，不是上游文本 sole origin。XH72 的 blank card-action token 是后出的人类组件，排除。 |
| 10 | **PASS** | compositional contributor | Feishu per-account tool-family gate | `5f6e1c19…` | `d4f11d30…` | `v2026.2.6` 起含 policy scaffold；`v2026.6.9` fixed | candidate 首次加入 per-account `tools` 配置及按 first account 注册的 gate；后续 human commit 加 per-call account routing 后形成完整绕过。fix 在选定 account 后执行 centralized `requiredTool` gate。只宣称组合贡献。 |
| 11 | **FAIL** | ghost-blame | `system.run` displayed command / raw argv mismatch | member `01d568c9…`；carrier `483fba…` | `03e689fc…` | carrier 在 `v2026.1.24-1`；fix 在 `v2026.2.25` | AI member 只加 Discord approval forwarding/heartbeat；与 fix 的 12 个实现路径零交集，也没有 argv identity。generic approval core 来自 PR 的后续 human member；新增审批 UI 不制造 command-source 或 display/raw identity mismatch。 |
| 12 | **FAIL** | unrelated ancestor | message tool `mediaUrl`/`fileUrl` sandbox bypass | `33e2d53…` | `1d7cb6fc…` | candidate 在 `v2026.1.8`；fix 在 `v2026.3.24` | candidate 是 Telegram threading、send action 和 duplicate suppression，未改 advisory 的 `message-action-params.ts` / `message-action-runner.ts`，candidate 与 fix 路径交集为零；只有 ancestry，无因果 delta。 |

`PASS` 不是“advisory 真实”的同义词。第 8、11、12 条 advisory 本身都是真实、已发布、未撤回；失败的是所列 **AI candidate → vulnerability** 归因边。

## 判定合同

本报告采用以下 fail-closed 合同：

1. **公开身份**：repo security advisory 必须 `published` 且 `withdrawn_at=null`；若已有 CVE，CVEList v5 CNA record 必须为 `PUBLISHED`。
2. **原子 AI signal**：必须出现在最小 source-changing candidate/member commit 本身；merge/squash carrier 的 trailer 不能代替 member 证据。
3. **candidate^ delta**：candidate 相对其第一父提交必须新增缺陷、不完整修复，或新增一条真实到达既有脆弱 sink 的攻击面/策略维度。仅同仓库、同文件、时间靠近或 ancestor 不够。
4. **fix reversal**：fix 必须关闭 candidate delta 所对应的同一 predicate、sink 或 reachability；共享 fix 允许支持 contributor，但报告必须降格为“非 sole origin”。
5. **squash transfer**：member 不在 main 时，必须证明其 causal hunk 在 carrier 中 byte-identical 或语义 patch-equivalent；若在 PR 内被后续提交擦掉，判 FAIL。
6. **发布进入**：至少一个稳定 tag 必须包含 candidate/carrier 且不包含 fix；不能把只在 PR branch 的代码称为 released vulnerability。
7. **组件去重**：按攻击输入、信任边界、sink/reversal invariant 计数；多个 GHSA/CVE 可以属于一个 residual series，但不能把一个 advisory 中不同机制的分支硬并。

本合同接受用户指定的广义贡献口径：**AI 不完整修复**和**有具体调用链的新 surface contributor**可以 PASS；但两者都必须有原子 delta 和 shipped-code transfer，不能只靠模型路由或 fix 邻近性。

## 一方公开身份与语义去重

审计到的 15 条 repo advisories 全部为 `state=published`、`withdrawn_at=null`。其中 14 条已有 `PUBLISHED` CNA record；`GHSA-9F72-QCPW-2HXC` 仍为 GHSA-only。

| 行 | Repo advisory / CVEList CNA | 公共身份结果 | 组件归并 |
|---:|---|---|---|
| 1 | [GHSA-H2VW-PH2C-JVWF](https://github.com/openclaw/openclaw/security/advisories/GHSA-h2vw-ph2c-jvwf) / [CVE-2026-44992](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/44xxx/CVE-2026-44992.json) | published / PUBLISHED | 独立组件 |
| 2 | [GHSA-G8P2-7WF7-98MQ](https://github.com/openclaw/openclaw/security/advisories/GHSA-g8p2-7wf7-98mq) / [CVE-2026-25253](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/25xxx/CVE-2026-25253.json) | published / PUBLISHED | 独立组件；advisory 的旧 `clawdbot` package name 与实际 `openclaw@2026.1.29` rename artifact 有元数据偏差，不影响 tag 中 fix 存在 |
| 3 | [GHSA-9F72-QCPW-2HXC](https://github.com/openclaw/openclaw/security/advisories/GHSA-9f72-qcpw-2hxc) | published；无 CVEList record | 独立组件 |
| 4 | [GHSA-XQ94-R468-QWGJ](https://github.com/openclaw/openclaw/security/advisories/GHSA-xq94-r468-qwgj) / [CVE-2026-43582](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/43xxx/CVE-2026-43582.json) | published / PUBLISHED | 独立组件 |
| 5 | [GHSA-W85G-3H6X-4XH2](https://github.com/openclaw/openclaw/security/advisories/GHSA-w85g-3h6x-4xh2) / [CVE-2026-41334](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/41xxx/CVE-2026-41334.json) | published / PUBLISHED | 主报告只计一次；旧 ledger 中 GHSA/CVE 双行不得再计第二组件 |
| 6 | [GHSA-MF5G-6R6F-GHHM](https://github.com/openclaw/openclaw/security/advisories/GHSA-mf5g-6r6f-ghhm) / [CVE-2026-35646](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/35xxx/CVE-2026-35646.json) | published / PUBLISHED | 独立组件；patched-release 元数据需校正，见下 |
| 7 | [GHSA-2QRV-RC5X-2G2H](https://github.com/openclaw/openclaw/security/advisories/GHSA-2qrv-rc5x-2g2h) / [CVE-2026-41295](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/41xxx/CVE-2026-41295.json)；[GHSA-82QX-6VJ7-P8M2](https://github.com/openclaw/openclaw/security/advisories/GHSA-82qx-6vj7-p8m2) / [CVE-2026-43571](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/43xxx/CVE-2026-43571.json) | 全部 published / PUBLISHED | **不是正式 aliases**；同一 workspace-shadow trust invariant 的 first fix + residual，只计一个组件 |
| 8 | [GHSA-2QJ5-GWG2-XWC4](https://github.com/openclaw/openclaw/security/advisories/GHSA-2qj5-gwg2-xwc4) / [CVE-2026-27001](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/27xxx/CVE-2026-27001.json) | published / PUBLISHED | advisory 真实；所列 AI edge FAIL |
| 9 | [GHSA-G353-MGV3-8PCJ](https://github.com/openclaw/openclaw/security/advisories/GHSA-g353-mgv3-8pcj) / [CVE-2026-32974](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/32xxx/CVE-2026-32974.json)；[GHSA-XH72-V6V9-MWHC](https://github.com/openclaw/openclaw/security/advisories/GHSA-xh72-v6v9-mwhc) / [CVE-2026-44109](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/44xxx/CVE-2026-44109.json) | 全部 published / PUBLISHED | 只把 XH72 的 webhook residual 并入 G353；blank card-action token 是另一组件，不能借本 edge 计数 |
| 10 | [GHSA-2Q7J-2VHX-56G8](https://github.com/openclaw/openclaw/security/advisories/GHSA-2q7j-2vhx-56g8) / [CVE-2026-62187](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/62xxx/CVE-2026-62187.json)；[GHSA-W8WF-3QVJ-6XQF](https://github.com/openclaw/openclaw/security/advisories/GHSA-w8wf-3qvj-6xqf) / [CVE-2026-62188](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/62xxx/CVE-2026-62188.json) | 全部 published / PUBLISHED | **不是正式 aliases**；同一 centralized `requiredTool` account-family gate，permission 是子集，只计一个组件 |
| 11 | [GHSA-HWPQ-RRPF-PGCQ](https://github.com/openclaw/openclaw/security/advisories/GHSA-hwpq-rrpf-pgcq) / [CVE-2026-32065](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/32xxx/CVE-2026-32065.json) | published / PUBLISHED | advisory 真实；所列 AI edge FAIL |
| 12 | [GHSA-V8WV-JG3Q-QWPQ](https://github.com/openclaw/openclaw/security/advisories/GHSA-v8wv-jg3q-qwpq) / [CVE-2026-33581](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/33xxx/CVE-2026-33581.json) | published / PUBLISHED | advisory 真实；所列 AI edge FAIL |

### 第 6 行的发布元数据校正

`GHSA-MF5G-6R6F-GHHM` 和 CNA 把 planned `2026.3.25` 写成 patched version，但审计日的 first-party tags、GitHub releases 和 npm artifact 均不存在该版本。`0b4d0733…` 不在 `v2026.3.24`，首个包含它的稳定 tag/release 是 [v2026.3.28](https://github.com/openclaw/openclaw/releases/tag/v2026.3.28)。因此：

- 组件真实性与 causal edge：PASS；
- “first patched release = 2026.3.25”：FAIL；
- 本报告冻结的真实 release closure：`v2026.3.24` vulnerable → `v2026.3.28` fixed。

## 逐项因果证据

### 1. MiniMax dotenv redirect — PASS contributor

- [candidate `7d7f5d85…`](https://github.com/openclaw/openclaw/commit/7d7f5d85b4ff0bf9a135ced8022d8860a1979a06) 自带 `Co-Authored-By: Claude Opus 4.6`；相对 parent `49d962a8…` 新增 native MiniMax TTS provider。
- 新代码用 `process.env.MINIMAX_API_HOST` 解析 `baseUrl`，并用同一 provider 的 API key 形成 credentialed request。candidate^ 不含这条 TTS sink。
- [fix `2f066965…`](https://github.com/openclaw/openclaw/commit/2f06696579a1ab0cb5bbbbb6a900414a6b2e3cd1) 明确阻断 workspace dotenv 的 `MINIMAX_API_HOST`，并收紧 affected MiniMax URL routing。
- `v2026.4.5` 首次稳定包含 candidate；`v2026.4.15` 仍不含 fix；`v2026.4.20` 包含 fix，和 advisory/CNA 的下界一致。
- 边界：更早代码已有共享 dotenv 行为和其他 MiniMax consumer；因此本 PASS 是新增 credentialed TTS surface 的因果贡献，不扩大成 shared loader sole-origin claim。

### 2. `gatewayUrl` token exfiltration — PASS direct origin

- [candidate `c74551c2…`](https://github.com/openclaw/openclaw/commit/c74551c2ae0611f3ef0e691dc93a38372f366765) 自带 Claude 4.5 trailer；candidate^ 首次读取 query `gatewayUrl` 并立即 `applySettings`。
- Control UI 随后自动连接并发送已存 gateway token；这就是 advisory 所述一键 token exfiltration/RCE 链。
- [fix `a7534dc2…`](https://github.com/openclaw/openclaw/commit/a7534dc22382c42465f3676724536a014ce0cbf7) 把同一赋值反转为 `pendingGatewayUrl`，要求用户确认后才连接。
- candidate 和 fix 均在 main ancestry；`v2026.1.20` 是稳定 vulnerable witness，`v2026.1.29` 是 fixed witness。

### 3. native prompt image `workspaceOnly` — PASS direct origin

- [candidate `8d74578c…`](https://github.com/openclaw/openclaw/commit/8d74578ceb0c3b913555dff6265821eb0fc09749) 自带 Claude 4.5 trailer，并首次创建 `detectAndLoadPromptImages` / `loadImageFromRef`。
- candidate 只在 sandbox enabled 时对 `sandboxRoot` 执行 path assertion；它没有读取或传递 `tools.fs.workspaceOnly`。因此 mounted `/agent/secret.png` 可进入 vision prompt。
- [fix `370d1155…`](https://github.com/openclaw/openclaw/commit/370d115549c0dadace0902775eea0d5094aedfdc) 在 `attempt.ts` 解析 effective workspace-only policy，并在 `images.ts` 对 prompt/history refs 执行 workspace assertion；tests 直接覆盖 `/agent/secret.png`。
- candidate 从 `v2026.1.20` 已发布，fix 首见 `v2026.2.24`。

### 4. Browserbase direct-WS CDP / DNS rebinding — PASS contributor

- [candidate `75602014…`](https://github.com/openclaw/openclaw/commit/75602014dbc5088b80e9b236146dfe5fdcc59e20) 自带 Claude 4.6 trailer；candidate^ 从只接受 HTTP(S) CDP 扩展到 `ws/wss`，并为 Browserbase 直接向 remote CDP `Target.createTarget({url})`。
- candidate 新路径在发送 target 前调用共享 `assertBrowserNavigationAllowed`。pre-fix guard 在 OpenClaw/Node 一侧解析 hostname，而 Chromium（尤其 remote Browserbase）实际再次解析，具备 advisory 的 resolver split。
- [fix `121c452d…`](https://github.com/openclaw/openclaw/commit/121c452d666d4749744dc2089287d0227aae2ed3) 在 strict policy 下拒绝非 IP literal 且未显式 allowlist 的 hostname navigation，并在 CDP/Playwright paths 复用该 gate。
- `8eeb7f082975…` 仅把 browser ownership 搬进 bundled extension；pre-fix tree `4164d6fc…` 仍保留 `isWebSocketUrl`、direct `wsUrl = opts.cdpUrl` 和 Browserbase tests，属于语义 transfer。
- `v2026.3.8` 已含 candidate surface，`v2026.4.9` 仍无 fix，`v2026.4.10` fixed。共享 DNS guard 的早期缺陷不归因给 candidate；只接受 remote direct-WS surface contribution。

### 5. sips pixel DoS — PASS contributor

- 同一 [candidate `8d74578c…`](https://github.com/openclaw/openclaw/commit/8d74578ceb0c3b913555dff6265821eb0fc09749) 新增从 prompt/history local path 到 `loadWebMedia` 的自动 image ingest；`loadWebMedia` 对 image 调用 `resizeToJpeg`。candidate 还在 `image-ops.ts` 增加 pre-resize sips EXIF normalization。
- candidate parent `f7123ec3…` 已有 `sipsMetadataFromBuffer(...).catch(() => null)` 和无 pixel cap 的 `sipsResizeToJpeg`/Sharp path，所以不能宣称缺陷 sole origin。
- 但 candidate^ 确实新增一条攻击者可控 prompt path 到该 decoder；pre-fix blame 仍能在 `attempt.ts`/`images.ts` 找到 `8d74578c…` 的 loader symbols，证明该 surface 进入受影响 release。
- [fix `0ed4f8a7…`](https://github.com/openclaw/openclaw/commit/0ed4f8a72bb140045962e97ab01c94c076b758a4) 加 25M pixel cap、header parser、sips unknown-dimension fail-closed 和 Sharp `limitInputPixels`。
- `v2026.3.28` 是 pre-fix stable witness；`v2026.3.31` fixed。该 PASS 只贡献一个新的 image-ingest surface，且与第 3 行的 filesystem-policy bypass 是两个不同 security invariants/fixes，不是重复计数。

### 6. Synology pre-auth rate limit — PASS direct origin

- PR [#23012](https://github.com/openclaw/openclaw/pull/23012) 的 first member [ `cc048a29…`](https://github.com/openclaw/openclaw/commit/cc048a295e7e70684ca24654257e0ecf38e49153) 自带 Claude 4.6 trailer并新建整个 Synology Chat webhook handler。
- member 明确顺序为：parse → `validateToken` → allowlist → `rateLimiter.check(payload.user_id)`。无效 token 在 limiter 前返回 401，所以弱 token 可被反复猜测。
- squash carrier [ `03586e3d…`](https://github.com/openclaw/openclaw/commit/03586e3d0057b5975090d50dadcc5bc95b51f977) 的 `webhook-handler.ts` 和对应 test 与 member byte-identical；第二 member 只调整 channel metadata/messaging。
- [fix `0b4d0733…`](https://github.com/openclaw/openclaw/commit/0b4d07337467f4d40a0cc1ced83d45ceaec0863c) 在 token check 前增加 remote-IP failure budget/lockout，并保留 post-auth sender budget。
- 实际 release closure 是 `v2026.2.22` 起含 carrier、`v2026.3.24` 仍 vulnerable、`v2026.3.28` fixed；不存在 `2026.3.25` artifact。

### 7. workspace channel shadow — PASS direct origin，两个 CVE 一个 residual series

- PR [#46763](https://github.com/openclaw/openclaw/pull/46763) first member [ `fc1b156d…`](https://github.com/openclaw/openclaw/commit/fc1b156dc4105bdbcdc24d4c25d4f5af25cfd7bb) 自带 Claude 4.6 trailer；candidate^ 为 setup/channel-add 新增 `onlyPluginIds`、`activate:false` 的 scoped snapshot。
- 该 snapshot 按 channel/plugin id 做 discovery/import；untrusted workspace plugin 可 shadow bundled channel id，并在尚未通过 intended trust gate 时以 setup-only 路径执行。
- squash carrier [ `f4cc93dc…`](https://github.com/openclaw/openclaw/commit/f4cc93dc7da7359c35130bbbb244d3fac695740f) 吸收 8 个 PR members。后续 members 对路径/manifest mapping 做了调整，但仍保留 scoped snapshot、non-activating load 和 selected-id import 的安全相关语义，因此不是被擦除的 member。
- [first fix `53c29df2…`](https://github.com/openclaw/openclaw/commit/53c29df2a9eb242a70d0ff29f3d1e67c8d6801f0) 在 setup resolution 排除未受信 workspace shadows；[residual fix `1fede43b…`](https://github.com/openclaw/openclaw/commit/1fede43b948df40ca8674511d4bd08d39f6c5837) 把剩余 catalog/plugin-install call sites 路由到 trusted catalog。
- 第一 advisory 在 `v2026.4.2` 修，第二 residual 在 `v2026.4.10` 修。两条 CNA 是不同 CVE，不是假称 alias；按同一 trust-boundary residual series 只计一个组件。

### 8. CWD prompt injection — FAIL，AI member 未进入主线机制

- PR [#10176](https://github.com/openclaw/openclaw/pull/10176) first member [ `d6338abe…`](https://github.com/openclaw/openclaw/commit/d6338abe1f07077c1afb38e0f816d130eb4b18db) 自带 Claude 4.6 trailer，只在 `src/utils.ts` 加三行：空 input 返回 `process.cwd()`。
- PR 随后有 5 个 human-authored hardening/refactor members。squash carrier [ `42164494…`](https://github.com/openclaw/openclaw/commit/421644940517ae1857281bddf8603aeef9cebf1c) 不再含这三行，而由 human `workspace-run.ts` 根据 explicit/config/session state 解析 workspace。
- advisory 的 exploit primitive 是攻击者可控 path 中的 newline/control chars 被插入 system prompt；AI 的 missing-input fallback 不创建或扩展该 primitive。
- [fix `6254e96a…`](https://github.com/openclaw/openclaw/commit/6254e96acf16e70ceccc8f9b2abecee44d606f79) 新增 `sanitizeForPromptLiteral` 并在 system prompt/workspace path 上调用。它反转的是 carrier 中 human rewrite 的 prompt path，不是 AI member 的 fallback。
- 所以即便 carrier 和 fix 都进入 release，也不能用 squash commit 的 Claude trailer把 human final code 归给 AI。

### 9. Feishu webhook fail-open — PASS contributor，但必须缩窄 XH72

- PR [#12662](https://github.com/openclaw/openclaw/pull/12662) 只有一个 source member [ `b0c67ea0…`](https://github.com/openclaw/openclaw/commit/b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517)，自带 Claude 4.6 trailer；它把 independent `clawdbot-feishu` 的 webhook mode 集成到 OpenClaw。
- candidate^ 新增 bare `http.createServer`、`Lark.adaptDefault(...)` 和 webhook dispatcher，但没有强制 `encryptKey`。主线 squash carrier 是 [ `5c2cb6c5…`](https://github.com/openclaw/openclaw/commit/5c2cb6c591e4b63c2df0549ad2202403256e2a96)，不是 `b0c67ea…`；carrier 的 `extensions/feishu/src/monitor.ts` 与 member byte-identical。
- [fix `7844bc89…`](https://github.com/openclaw/openclaw/commit/7844bc89a1612800810617c823eb0c76ef945804) 要求 webhook `encryptKey`，对应 G353；[fix `c8003f1b…`](https://github.com/openclaw/openclaw/commit/c8003f1b33ed2924be5f62131bd28742c5a41aae) 又把 direct transport 的 missing/invalid signing config 改成 fail-closed，对应 XH72 的 webhook residual。
- `v2026.2.12` 已含 carrier，`v2026.3.11` 是 G353 pre-fix witness，`v2026.3.12` 含首修；`v2026.4.14` 仍缺 residual fix，`v2026.4.15` fixed。
- 限定：candidate 是 AI-assisted integration commit，提交说明明确是 sync community contributions；本报告不把上游 human code 原创归给 Claude，只计 AI 参与把 vulnerable webhook surface 带入 OpenClaw release。
- XH72 同时修了 `card-action.ts` 的 blank callback token。candidate 未触碰该文件；它由 human commit `49cf2bce…` 后出创建。因此 card-action 是独立、对本 candidate 为 FAIL 的子机制，不作为第 9 行的第二计数。

### 10. Feishu account tool gate — PASS compositional contributor

- [candidate `5f6e1c19…`](https://github.com/openclaw/openclaw/commit/5f6e1c19bd18ea45addd3afedf2f88cc3064f3f6) 自带 Claude 4.5 trailer；candidate^ 首次加入 `accounts`、account-level `tools` config，并以 first enabled account 的 config 决定 doc/drive/wiki/perm tool registration。
- 后续 human commit `39b5ffda…` 加 per-call/agent account routing，才使“注册时看 A account、执行时使用 B account”完整可利用。因此 candidate 不是 sole origin，但它提供了必要的 per-account policy dimension 和 first-account gate scaffold，且这些配置/registration hunks进入受影响 releases。
- [fix `d4f11d30…`](https://github.com/openclaw/openclaw/commit/d4f11d3005a56abc709ebc8e715972593ebed96e) 在 runtime selected account 后执行 centralized `requiredTool` family check，并覆盖 permission path。
- 2Q7J 和 W8WF 有两个 CVE，但相同版本、相同 central fix、permission 是 broad tool-family bug 的子集；只计一个 semantic component。
- candidate 从 `v2026.2.6` 已发布；`v2026.6.6` 仍 vulnerable；`v2026.6.9` fixed。

### 11. `system.run` approval identity — FAIL ghost-blame

- PR [#1621](https://github.com/openclaw/openclaw/pull/1621) first member [ `01d568c9…`](https://github.com/openclaw/openclaw/commit/01d568c9f54585d2df3002e1090067c9dd621e43) 自带 Claude 4.5 trailer，只改 Discord forwarding、Discord config 与 heartbeat。
- PR 的 second member `e3bfdee1…` 由 human 添加 generic approval core；squash carrier [ `483fba41…`](https://github.com/openclaw/openclaw/commit/483fba41b9f9fb57964f31b90a2ddacb185d54d7) 因此带有 Claude trailer和大量 core files，但 trailer 不能回灌到 human member。
- candidate 的 6 个路径与 [fix `03e689fc…`](https://github.com/openclaw/openclaw/commit/03e689fc89bbecbcd02876a95957ef1ad9caa176) 的 12 个实现路径交集为空；candidate 无 `commandArgv`、raw argv binding 或 rendered identity delta。
- Discord approval forwarding 只是另一 trusted approval UI；它不新增攻击者控制 command argv 的来源，也不制造 displayed/raw mismatch。故不能套用“new surface contributor”规则。

### 12. media alias sandbox bypass — FAIL unrelated ancestor

- [candidate `33e2d53…`](https://github.com/openclaw/openclaw/commit/33e2d53be308a9c318875d752da9dccbc1580751) 有 `Generated with Claude Code` 和 Claude 4.5 trailer，但其 delta 是 Telegram threading/forum、Telegram `sendMessage` 和 messaging duplicate suppression。
- advisory 明列 affected component 为 `src/infra/outbound/message-action-params.ts` 与 `message-action-runner.ts`；candidate 没有触碰这两个文件，也没有添加 generic `mediaUrl`/`fileUrl` sandbox-normalization logic。
- [fix `1d7cb6fc…`](https://github.com/openclaw/openclaw/commit/1d7cb6fc03552bbba00e7cffb3aa9741f5556416) 把 aliases 纳入 sandbox media key normalization/hydration，并传递 `mediaLocalRoots`。candidate 与 fix 的 changed-path intersection 为零。
- candidate 在 fix 祖先中且进入早期 tags，只能证明 chronology；不能证明机制归因，故 FAIL。

## Accepted atomic edges

以下 9 条是本报告唯一接受的边；`member => carrier` 表示 topology/transfer，不把 carrier 当 AI origin：

```text
1  7d7f5d85b4ff0bf9a135ced8022d8860a1979a06
   -> 2f06696579a1ab0cb5bbbbb6a900414a6b2e3cd1

2  c74551c2ae0611f3ef0e691dc93a38372f366765
   -> a7534dc22382c42465f3676724536a014ce0cbf7

3  8d74578ceb0c3b913555dff6265821eb0fc09749
   -> 370d115549c0dadace0902775eea0d5094aedfdc

4  75602014dbc5088b80e9b236146dfe5fdcc59e20
   -> 121c452d666d4749744dc2089287d0227aae2ed3

5  8d74578ceb0c3b913555dff6265821eb0fc09749
   -> 0ed4f8a72bb140045962e97ab01c94c076b758a4

6  cc048a295e7e70684ca24654257e0ecf38e49153
   => 03586e3d0057b5975090d50dadcc5bc95b51f977
   -> 0b4d07337467f4d40a0cc1ced83d45ceaec0863c

7  fc1b156dc4105bdbcdc24d4c25d4f5af25cfd7bb
   => f4cc93dc7da7359c35130bbbb244d3fac695740f
   -> 53c29df2a9eb242a70d0ff29f3d1e67c8d6801f0
   -> 1fede43b948df40ca8674511d4bd08d39f6c5837

9  b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517
   => 5c2cb6c591e4b63c2df0549ad2202403256e2a96
   -> 7844bc89a1612800810617c823eb0c76ef945804
   -> c8003f1b33ed2924be5f62131bd28742c5a41aae  [webhook residual only]

10 5f6e1c19bd18ea45addd3afedf2f88cc3064f3f6
   -> d4f11d3005a56abc709ebc8e715972593ebed96e
```

Rejected edges：

```text
8  d6338abe… => 42164494… -> 6254e96a…   FAIL: AI hunk erased before squash
11 01d568c9… => 483fba41… -> 03e689fc…   FAIL: ghost-blame / no argv-identity delta
12 33e2d53b… -> 1d7cb6fc…                FAIL: unrelated ancestor / zero path overlap
```

## Release/tag matrix

“first candidate tag”是代码进入稳定 tag 的下界；它不覆盖 advisory 可能更早存在的 shared-root 缺陷。`pre-fix witness` 均同时包含 candidate/carrier且不包含对应 fix。

| # | first candidate/carrier stable tag | pre-fix stable witness | first stable fix tag | 结果 |
|---:|---|---|---|---|
| 1 | `v2026.4.5` | `v2026.4.15` | `v2026.4.20` | closed |
| 2 | `v2026.1.20` | `v2026.1.24-1` | `v2026.1.29` | closed |
| 3 | `v2026.1.20` | `v2026.2.23` | `v2026.2.24` | closed |
| 4 | `v2026.3.8` | `v2026.4.9` | `v2026.4.10` | closed |
| 5 | `v2026.1.20` | `v2026.3.28` | `v2026.3.31` | closed |
| 6 | `v2026.2.22` | `v2026.3.24` | `v2026.3.28` | closed；纠正 planned `3.25` |
| 7 | `v2026.3.22` | `v2026.4.1` / `v2026.4.9` | `v2026.4.2` / `v2026.4.10` | first fix + residual closed |
| 8 | carrier `v2026.2.6` | `v2026.2.14` | `v2026.2.15` | release exists；AI edge FAIL |
| 9 | carrier `v2026.2.12` | `v2026.3.11` / `v2026.4.14` | `v2026.3.12` / `v2026.4.15` | webhook first fix + residual closed |
| 10 | `v2026.2.6` | `v2026.6.6` | `v2026.6.9` | closed |
| 11 | carrier `v2026.1.24-1` | `v2026.2.24` | `v2026.2.25` | release exists；AI edge FAIL |
| 12 | `v2026.1.8` | `v2026.3.23` | `v2026.3.24` | release exists；AI edge FAIL |

## 可复现命令

以下命令只读 first-party Git/GitHub/CVEList/release metadata；OSV 和模型输出未参与裁决。

```zsh
R=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw

# repo advisory：逐条确认 published/non-withdrawn
for g in \
  GHSA-H2VW-PH2C-JVWF GHSA-G8P2-7WF7-98MQ GHSA-9F72-QCPW-2HXC \
  GHSA-XQ94-R468-QWGJ GHSA-W85G-3H6X-4XH2 GHSA-MF5G-6R6F-GHHM \
  GHSA-2QRV-RC5X-2G2H GHSA-82QX-6VJ7-P8M2 GHSA-2QJ5-GWG2-XWC4 \
  GHSA-XH72-V6V9-MWHC GHSA-G353-MGV3-8PCJ GHSA-2Q7J-2VHX-56G8 \
  GHSA-W8WF-3QVJ-6XQF GHSA-HWPQ-RRPF-PGCQ GHSA-V8WV-JG3Q-QWPQ
do
  gh api "repos/openclaw/openclaw/security-advisories/$g" \
    --jq '[.ghsa_id,.state,.published_at,.withdrawn_at,.summary,.vulnerabilities]'
done

# CVEList CNA：示例；其余记录使用同样路径规则
gh api repos/CVEProject/cvelistV5/contents/cves/2026/44xxx/CVE-2026-44992.json \
  --jq .content | base64 -d | jq '.cveMetadata,.containers.cna'
gh api repos/CVEProject/cvelistV5/contents/cves/2026/27xxx/CVE-2026-27001.json \
  --jq .content | base64 -d | jq '.cveMetadata,.containers.cna'

# candidate^ / fix reversal / AI marker
git -C "$R" show --format=fuller 7d7f5d85^..7d7f5d85
git -C "$R" show --format=fuller 2f066965
git -C "$R" show --format=fuller 8d74578c^..8d74578c
git -C "$R" show --format=fuller 370d1155
git -C "$R" show --format=fuller 0ed4f8a7

# ancestry 与“candidate 已发布、fix 尚未发布”的 tag witness
git -C "$R" merge-base --is-ancestor 7d7f5d85 origin/main
git -C "$R" tag --contains 7d7f5d85 --no-contains 2f066965 --sort=creatordate
git -C "$R" tag --contains 2f066965 --sort=creatordate

# squash members 来自一方 PR API
for p in 23012 46763 10176 12662 1621; do
  gh api --paginate "repos/openclaw/openclaw/pulls/$p/commits?per_page=100" \
    --jq '.[] | [.sha,.commit.author.date,.commit.author.name,.commit.message] | @tsv'
done

# byte-identical transfer
git -C "$R" diff --exit-code cc048a29 03586e3d -- \
  extensions/synology-chat/src/webhook-handler.ts \
  extensions/synology-chat/src/webhook-handler.test.ts
git -C "$R" diff --exit-code b0c67ea0 5c2cb6c5 -- \
  extensions/feishu/src/monitor.ts

# 被擦除 member / ghost blame / unrelated edge
git -C "$R" diff d6338abe 42164494 -- src/utils.ts src/agents/workspace-run.ts
comm -12 \
  <(git -C "$R" diff-tree --no-commit-id --name-only -r 01d568c9 | sort) \
  <(git -C "$R" diff-tree --no-commit-id --name-only -r 03e689fc | sort)
comm -12 \
  <(git -C "$R" diff-tree --no-commit-id --name-only -r 33e2d53b | sort) \
  <(git -C "$R" diff-tree --no-commit-id --name-only -r 1d7cb6fc | sort)

# XH72 card-action split：candidate 无该路径，human commit 后出创建
git -C "$R" diff-tree --no-commit-id --name-only -r b0c67ea0 | rg card-action
git -C "$R" log --all --diff-filter=A --format=fuller -- \
  extensions/feishu/src/card-action.ts

# planned 3.25 不存在；0b4d 的首个 stable tag 是 3.28
git -C "$R" tag -l 'v2026.3.25*'
gh api repos/openclaw/openclaw/releases --paginate --jq '.[].tag_name' | rg '^v?2026\.3\.25'
npm view openclaw@2026.3.25 version
git -C "$R" tag --contains 0b4d0733 --sort=creatordate | rg '^v2026\.[0-9]+\.[0-9]+$'
```

## Claim boundary

- 这是 source/history/release 因果审计，不是 exploitability benchmark，也没有声称所有配置下都可利用。
- commit trailer 证明 AI 被 first-party commit metadata 署名为参与者；它不能逐行证明模型生成比例。故 import/compositional cases 均明确降格为 contributor。
- 本报告没有用 OSV、模型分类、时间相邻或 fix-file overlap 作为最终证据；这些最多是 routing。
- 本报告不修改 ledger、主报告、代码或既有证据。最终计数只能由主线维护者显式吸收：建议将确认下界增加 **9 个组件**，而不是 12 个，也不能把第 9 行 XH72 的 card-action 半边顺带计入。

## Artifact integrity

- 正文前缀 SHA-256（`sed '/^## Artifact integrity$/,$d' <file> | sha256sum`）：`f7c36abc2f9628a0bfcc1ec1302f4f3484d39cc6a1c6cd6995f76d37a0ff3c26`
- 完整文件 SHA-256 无法无悖论地自嵌；在交接消息中另行给出并由 `sha256sum` 复算。
- whitespace gate：`git diff --no-index --check /dev/null docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md`（最终运行无诊断）。
