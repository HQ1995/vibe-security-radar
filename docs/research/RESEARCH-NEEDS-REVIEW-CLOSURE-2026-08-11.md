# 剩余 NEEDS_REVIEW 严格收口（2026-08-11）

## 结论

本轮重新核验 `class_adjudications_v3.json` 的 21 个剩余 `NEEDS_REVIEW`，结果为：

- **PASS 10**：rows **19, 25, 28, 44, 50, 72, 109, 120, 124, 141**；
- **FAIL 10**：rows **3, 7, 45, 57, 76, 77, 113, 117, 127, 147**；
- **NEEDS_REVIEW 1**：row **125**；
- **BLOCKED 0**。

判定只使用一方 advisory、Git commit parent/delta、历史 blame/`-S`、公开 PR/commit metadata。OSV 的 `introduced`/`fixed` 仅用于找到候选，不进入因果证明。

## 统一判定边界

“AI contributed” 不要求 AI commit 是整个漏洞的唯一历史起点，但新表面必须同时满足：

1. parent 中没有该具体公开 route、输入类型、客户端类型或模型可达面；
2. AI commit 使该表面进入 advisory 明列的受影响机制；
3. 一方 security fix 对该表面或其共享安全不变量作了反转；
4. commit/PR 有明确 AI signal。

仅同仓库、同模型、同文件、同一后续 fix，或在已有漏洞上做无关重构，均判 `FAIL`。

## 逐行结论

| Row | Component | 结论 | 最小因果边 / 反证 | AI 证据与边界 |
|---:|---|---|---|---|
| 3 | CVE-2026-41334 | **FAIL** | `8d74578c` 增加 EXIF normalization，但 parent 的 `resizeToJpeg` 已经通过 `sips` 解码且没有像素上限；`0ed4f8a7` 是覆盖所有 image operations 的全局 pixel guard，不是对候选所创缺陷的反转。 | Claude trailer 真实，但因果不成立。row142 是同一 advisory component 的重复行。 |
| 7 | CVE-2026-31991 | **FAIL** | `5a3a448b` 只改 `/subagents spawn`/command context；`64de4b6d` 修的是 Signal DM pairing-store 泄入 group allowlist 的 shared policy。候选未改 Signal、pairing store 或 allowlist。 | Claude trailer 真实，但 edge 错绑。 |
| 19 | GHSA-xwcj-hwhf-h378 | **PASS** | `506bed5a` 首次加入 static Telegram sticker 下载，构造含 bot token 的 file URL，`fetchRemoteMedia()` 失败后又在 `catch` 中 `logVerbose(... ${err})`；`7a53eb7e` 在共享 media fetch error 路径加入 `redactMediaUrl()`/`redactSensitiveText()`。 | commit 明写 `AI-assisted: Built with Claude Code (claude-opus-4-5)` 及 Claude trailer。它是新增 sticker 泄露表面，不宣称是既有 photo/video 泄露的唯一 origin。 |
| 25 | CVE-2026-41347 | **PASS** | `f4b03599` 首次增加 HTTP `/v1/responses` 并把 startup `resolvedAuth` 送入 handler；`6b3f99a1` 为 trusted-proxy HTTP auth 增加 browser-Origin policy。 | Claude Opus 4.5 trailer。只认新 HTTP endpoint contributor。 |
| 28 | CVE-2026-41339 | **PASS** | `079af0d0` 首次允许 token-auth WebSocket 在无 device identity 时连接，从而新增会收到 full connect snapshot 的非设备客户端群；`676b7480` 把敏感 snapshot 字段限制为 admin scopes。 | Claude Opus 4.5 trailer。既有 paired non-admin clients 仍是更早风险，本边只认新增客户端表面。 |
| 44 | CVE-2026-59726 | **PASS** | 拒绝旧 `dba545f0`。修正后的 `29d52dfc` 首次创建 `ruflo/docker-compose.yml` 的公网 `3001:3001` 以及无认证 `/mcp* -> terminal_execute` bridge；`d00a0a40` 加认证/绑定限制。 | commit 明写 `Co-Authored-By: claude-flow <ruv@ruv.net>`；[一方仓库](https://github.com/ruvnet/ruflo)把 claude-flow/Ruflo 定义为 Claude agent orchestration platform。只主张 AI 工具共著，不推断具体模型。 |
| 45 | CVE-2026-55198 | **FAIL** | 一方 CVE 明确点名 `_handle_session_export` 缺少 active-profile ownership check。`ee672df4` 只让普通 session detail 的 state.db reader 按 session profile 读取，未改 export handler；`2a3baa71` 才同时给 detail/export 加 `_profiles_match -> 404`。 | Claude trailer 真实，但不创建 CVE 点名的 export authorization flaw。 |
| 50 | CVE-2026-43585 | **PASS** | `f4b03599` 新增 `/v1/responses`，使用启动时捕获的 `resolvedAuth`，使该新 endpoint 继承 revoked SecretRef bearer token 仍有效的问题；`acd4e0a3` 改为每次请求 `getResolvedAuth()`。 | Claude Opus 4.5 trailer；只认新 endpoint contributor。 |
| 57 | CVE-2026-42438 | **FAIL** | `df09e583` 加 message-sending hook，最多把 hook 输出的 `MEDIA:` 转成已有 `mediaUrls`；parent 已有 host-media outbound loader。`c949af9f` 修的是 follow-up runner 到 outbound loader 缺少 requester identity。 | Claude trailer 真实，但未创建共享 host-file read 或缺失 sender context。 |
| 72 | CVE-2026-32045 | **PASS** | `f4b03599` 新增 `/v1/responses`，handler 复用未区分 HTTP/WS 的 `authorizeGatewayConnect`，从而新增 tokenless Tailscale-header HTTP 表面；`356d61aa` 引入 `allowTailscaleHeaderAuth`，HTTP=false、WS=true。 | Claude Opus 4.5 trailer；只认新 endpoint contributor。 |
| 76 | CVE-2026-41378 | **FAIL** | `5a3a448b` 是 subagent command refactor；`a77928b1` 修的是 paired node 的 `node.event -> agent.request` unrestricted dispatch。候选不触及 node event handler 或 gateway tool authorization。 | Claude trailer 真实，但 edge 错绑。 |
| 77 | CVE-2026-14534 | **FAIL** | `87146271` 只改 `fickling/hook.py` 的 PyTorch Unpickler hook；`e8408615` 在 `fickling/fickle.py` 的 `UNSAFE_IMPORTS` 加 `_posixsubprocess`、`site`、`atexit`。 | Claude trailer 真实，但机制/文件均不相干。 |
| 109 | CVE-2026-32002 | **PASS** | `8d74578c` 移除 `primarySupportsImages` gate，使 image tool 对 vision-capable primary models 也保持可达，却未传 `tools.fs.workspaceOnly`；`dd9d9c1c` 将 workspaceOnly 送入 image tool 并用 `assertSandboxPath` 约束 sandbox path。 | Claude Opus 4.5 trailer；只认新增模型配置表面。 |
| 113 | CVE-2026-28456 | **FAIL** | `079af0d0` 改 token auth/device identity；`35c0e66e` 修 configured hook module path 进入 `dynamic import()` 的任意本地模块执行。 | Claude trailer 真实，但 auth client 与 hook loader 无因果关系。 |
| 117 | CVE-2026-34057 | **FAIL** | `94560ea6`/`a9f42b94` 重构既有 S3 restore。它们的 parent 已有 public Livewire `container/serverId`、`runImport()` 以及 `downloadFromS3()`/`restoreFromS3()`，并已把 `$this->container` 拼入 `docker cp/exec`。`d486bf09` 的真实缺陷行 blame 到 2024/2025 human commits。 | Claude trailers 真实，但没有新增 route/surface，且危险属性和 sink 均先验存在。 |
| 120 | CVE-2026-34149 | **PASS** | `473c3227` 首次新增 authenticated `create_backup` API，把未校验 `databases_to_backup` 写入 backup config；`99043600` 正是在 create/update API 加 `validateDatabasesBackupInput()`，并在 job 中逐个校验/escape Mongo collection names。 | subject `Changes auto-committed by Conductor`；冻结的 atomic-AI inventory 标为 `explicit_attribution_line`、tool=`claude_code`。只认新增 API 输入表面。 |
| 124 | CVE-2026-45539 | **PASS** | `810d87b2` 首次加入 Claude agent package integration，复用会 dereference symlink 的 `find_agent_files`/`copy_agent`，把内容部署进 `.claude/agents`；`f85b9f54` 把 prompt/agent finders 路由到 safe helper 并显式拒绝 symlink。 | author 为 `copilot-swe-agent[bot]`。只认新 Claude-agents deploy target contributor。 |
| 125 | CVE-2026-59101 | **NEEDS_REVIEW** | `5382aec8` 的确以 Claude Code 创建整个 setup wizard 和任意 host `httpx.get` endpoint；`c7c709fa` 曾完整阻断 private/reserved/loopback，随后 AI commit `61ff20fe` 又为允许 private IP 明确移除该 guard。公开 `487bdfec` 只限制 scheme、去掉 raw exception，仍允许 internal HTTP SSRF。 | AI 起点/重引入很强，但公开“fix”没有反转 advisory 所述 arbitrary-host/internal probing，严格 fix-reversal gate 不能闭合。 |
| 127 | CVE-2026-49987 | **FAIL** | `a2edd58e` 只保留 Azure DevOps URL parsing，且写入 `remoteBranch: undefined`；不安全 branch 进入 subprocess 的路径来自更早 human commits。Devin commit `70bbaa1` 也只是重构既有 URL validation，parent 已有同一 branch weakness；`92bfa319` 才加 `validateGitRef` 与 `--end-of-options`。 | AI signals 真实，但候选都不是 branch injection contributor。 |
| 141 | CVE-2026-45288 | **PASS** | `18c8d9b4` 首次加入 public `PrefixSearchAsync`/LINQ `PrefixSearch(..., regConfig)`，把未校验 `regConfig` 送入既有 `FullTextWhereFragment`；`62624965` 在共享入口校验 regConfig，并回归覆盖包括 PrefixSearch 的全部 API。 | Claude Opus 4.6 trailer；只认新增 PrefixSearch API contributor。 |
| 147 | CVE-2026-49353 | **FAIL** | `bd23ab41` 只新增 IFlow provider executor，与 `src/dashboardGuard.js` 的 Host/Origin local-only gate 无关。`git log -S 'function isLocalRequest'` 将 gate 历史指向 human commits；`5e1c1261` 是后续 gate hardening，不会把 IFlow feature 变成 origin。 | Cursor trailer 真实，但候选/修复错配。 |

## 关键一方证据

- [OpenClaw GHSA-xwcj-hwhf-h378](https://github.com/advisories/GHSA-xwcj-hwhf-h378) 明确点名 `src/media/fetch.ts` 的 Telegram token-bearing URL error 与 fix `7a53eb7e`。
- [9router GHSA-6g2f-w7g3-77vf](https://github.com/decolua/9router/security/advisories/GHSA-6g2f-w7g3-77vf) 明确点名 `src/dashboardGuard.js` 的 Host/Origin trust 与 fix references；这反证 IFlow candidate。
- 其余一方 advisory 文本冻结在 `research/orchestrator-260811-atomic150/*review-packets*/packets.jsonl`，alias membership 冻结在 `research/orchestrator-260809-0539/current-official-census/alias_classes.jsonl`。

## 可复核命令

```bash
git show -s --format='%H%n%P%n%ad%n%an <%ae>%n%B' --date=iso-strict <sha>
git diff <candidate>^ <candidate> -- <production-path>
git diff <fix>^ <fix> -- <production-path>
git blame -l <fix>^ -- <production-path>
git log --all --reverse -S '<security-symbol>' -- <production-path>
```

下一层机器可读判定为 `class_adjudications_v4.json`；旧 v2/v3 保持不变。
