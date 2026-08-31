# “How AI contributed” 摘要可读性优先改写样本

## 结论

当前摘要的通用问题不是“信息太少”，而是把审计过程直接暴露给读者：SHA、PR 拆分、函数名、BIC/carrier 等内部术语挤掉了漏洞本身，12 条摘要还被硬截断在 280 字中间。公开摘要应固定为两步：

1. 先说攻击者能做什么、造成什么影响。
2. 再说 AI 改动在因果链中的作用；直接引入与不完整修复必须分开。

以下 28 条是优先改写样本。原文逐字取自当前 `web/src/generated/research-data.json`；事实只取当前总账、本地 Git 对象和项目方代码/advisory。这里的“不能声称”不是页面文案，而是生成摘要时必须守住的证据边界。

## JSON-ready 优先发布映射

下面覆盖审计列出的全部 12 条截断 fallback、19 条缺少 AI 作用、13 条过长摘要，并额外修复 CVE-2026-55828 的陈旧缓存文案。每条均为一到两句、不超过 200 个字符、无 SHA/PR。

```json
{
  "GHSA-Q8HH-M6V5-4F3X": "Cursor-assisted scope logic let session tokens skip admin checks, exposing user and log data to signed-in non-admins. The AI commit covers only one branch of the advisory.",
  "GHSA-HW36-J4Q7-VJXX": "Claude-assisted code let requests select DeepStream GPU decoding and control a shared pool without the normal frame-size limit. An unauthenticated client could starve other requests.",
  "GHSA-H5RM-9FHH-5PHJ": "Claude-coauthored schema loading used an untrusted node type as a module path. An authenticated n8n member could traverse directories and execute code in the main process.",
  "GHSA-2664-HR5V-554W": "A Claude-marked n8n squash stopped freezing function-valued prototypes, letting authenticated workflow authors escape the JavaScript sandbox with an allowed import gadget.",
  "GHSA-JJ45-W38G-GFRJ": "Copilot SWE-agent changed wildcard escaping without matching native PostgreSQL SQL, so unauthenticated searches could force broad scans and degrade availability.",
  "GHSA-GVQ9-CMXR-844M": "Claude-coauthored key-server code accepted any non-empty bearer token, allowing unauthenticated upload of attacker-controlled, self-signed key bundles.",
  "GHSA-C7VW-VFXJ-3MVH": "Claude-generated plugin guards omitted dangerous Python modules. A plugin that bypassed the static scan could import them and escape the sandbox.",
  "GHSA-723W-CRW6-P9HX": "Claude-coauthored key-bundle code allowed conversion without signature verification, which could make callers encrypt data to an attacker-controlled key.",
  "GHSA-Q6QC-XP4Q-RJQ5": "Claude-coauthored code created an embedded control server with no authentication. Anyone who could reach it could invoke non-health command routes.",
  "GHSA-G8P2-7WF7-98MQ": "Claude-coauthored Control UI code auto-connected to a gateway URL from a crafted link, sending the user's stored gateway token to an attacker.",
  "GHSA-QGP8-V765-QXX9": "Claude-implemented PKCE checked a verifier only when a challenge was already stored. Removing the challenge could downgrade the authorization flow and bypass PKCE.",
  "GHSA-4PC9-X2FX-P7VJ": "Claude-generated OAuth code accepted unregistered callback URLs, so an auto-approved authorization flow could send a live code to an attacker's site.",
  "GHSA-GWMJ-HF32-5V8V": "Claude-coauthored local-trust code omitted Host validation, so DNS rebinding could give an attacker admin context and arbitrary command execution.",
  "GHSA-P5RM-JG5C-8C77": "Copilot-assisted path validation still accepted encoded traversal in OpenAPI file references, allowing generated plugin manifests to read arbitrary files.",
  "GHSA-FRVJ-C5QP-XJ4W": "Claude-assisted path sanitization stopped decoding after eight passes instead of failing closed. A deeply encoded traversal path could survive the check.",
  "GHSA-GF29-4F56-R2JF": "Cursor-assisted Git operations omitted sandbox path checks on fetch, pull, and tag pushes, letting authenticated workflow users read arbitrary local repositories.",
  "GHSA-WV26-J37Q-2G7P": "Claude-coauthored Slack approval code reused an exec-only approver check for plugin approvals, letting exec approvers bypass channel rules.",
  "GHSA-Q6RR-FM2G-G5X8": "Copilot-assisted limits still skipped array multiplication, so a tiny Scriban template could allocate gigabytes and deny service.",
  "GHSA-VXGJ-XG5C-P4H7": "Claude-bot code checked SSRF targets without DNS resolution, so hostnames resolving to private, loopback, or metadata addresses could bypass the guard.",
  "GHSA-FC26-M9PF-V56Q": "Claude-generated Linear webhook code skipped signature checks when the secret was unset, letting unauthenticated callers trigger agents and post comments.",
  "GHSA-2C85-RFCC-G74J": "Claude-generated mock-server code evaluated attacker-controlled request expressions with the full Java bridge, enabling remote code execution.",
  "GHSA-5C6W-WWFQ-7QQM": "Cursor-assisted SSRF validation blocked only literal loopback names, so alternate IP encodings could reach internal services.",
  "GHSA-WXW3-Q3M9-C3JR": "Copilot-coauthored OAuth cookie handling decrypted state but never compared it with the callback value, allowing state mismatch and OAuth CSRF.",
  "GHSA-WRWR-H859-XH2R": "Cursor-assisted XML validation checked a string view but forwarded the raw object. Stateful coercion could bypass the patch and restore prototype-pollution RCE.",
  "GHSA-8CXW-CC62-Q28V": "Claude-coauthored pipeline discovery followed symlinks outside the scan root, allowing a planted link to expose external files and their contents.",
  "GHSA-P7MM-R948-4Q3Q": "Claude-coauthored approval endpoints trusted a caller-supplied actor ID, letting users forge who approved a governance decision in the audit trail.",
  "GHSA-G5CG-8X5W-7JPM": "Claude-coauthored heartbeat code inherited owner status across a sandbox boundary, allowing an untrusted sender to gain owner-level privileges.",
  "GHSA-QPMQ-6WJC-W28Q": "Claude-generated UI code rendered user-controlled names as HTML. A guild user could run script in an admin's browser and steal exposed service secrets.",
  "GHSA-5WP8-Q9MX-8JX8": "Claude-coauthored shell restrictions were incomplete, so command arguments and filename wildcards could still execute blocked commands in Strict mode.",
  "GHSA-HFF7-CCV5-52F8": "Claude-coauthored HTTP gateway code reused tokenless Tailscale UI trust, letting attackers on trusted networks bypass token or password checks.",
  "GHSA-VH5J-5FHQ-9XWG": "Jules AI code checked and consumed purchase tokens in separate queries, so simultaneous requests could reuse one token and download a paid patch twice.",
  "GHSA-9J5F-PJWJ-62R3": "Claude-generated plugin code logged false restoration counts and installed import guards non-atomically, allowing a concurrent blocked-module re-import.",
  "GHSA-8359-H9FX-J6V9": "Human code introduced unsafe local references; a Claude-coauthored remediation still allowed traversal, so crafted schemas could read arbitrary files.",
  "GHSA-6MWV-4MRM-5P3M": "Claude-coauthored code put an unvalidated region into an upstream hostname, letting an authenticated caller send a Kiro API key to an attacker-controlled server.",
  "CVE-2026-32718": "Claude-generated validation endpoints accepted read-only API tokens but performed write-scoped provider actions, letting those tokens trigger changes.",
  "GHSA-PMCH-G965-GRMR": "Claude-authored SQL validation used an incomplete function denylist, allowing database users with sufficient privileges to read server files.",
  "GHSA-8CCJ-P46R-JWQQ": "Cursor-coauthored sandbox code silently fell back to a weaker subprocess sandbox, allowing code to access files or networks outside configured limits.",
  "GHSA-PGP4-XR4J-H5CG": "Claude-coauthored prompt scanning matched only simple phrases, so multi-word injections in auto-loaded project files could alter the agent's system prompt.",
  "GHSA-6C8G-7P36-R338": "Copilot SWE-agent added archive extraction without validating directory-entry paths, allowing traversal and, with symlinks, writes outside the target root.",
  "GHSA-FVXX-GGMX-3CJG": "Claude-bot deployment code let commas in settings become extra Cloud Run environment variables, allowing configuration injection during deployment.",
  "GHSA-CHFM-XGC4-47RJ": "Claude-coauthored Teams reply code copied unfiltered thread history into the model context, letting blocked senders influence channel replies.",
  "GHSA-GJXX-92W9-8V8F": "Claude-coauthored proxy code could treat a crafted path as a new host and forward the application's Clerk secret key to that host.",
  "GHSA-76RV-2R9V-C5M6": "Claude-coauthored rate limiting put one customer's writes on one DynamoDB partition, so heavy traffic could throttle that customer and nearby tenants.",
  "CVE-2026-28473": "Claude-coauthored approval code used a privileged internal client, letting users limited to operator.write approve or deny command executions.",
  "GHSA-F9M7-VC86-P6JJ": "Claude-coauthored tar extraction failed to exclude link-based targets before truncating files, allowing a crafted archive to overwrite arbitrary files."
}
```

## 1. GHSA-HW36-J4Q7-VJXX — vllm-project/vllm

**原摘要**

> The DeepStream inner-codec design, request-controlled DecodePool singleton, and decode path that discards probed frame dimensions were first written in PR #42424 member 9dbcf8c3d5de23925195bac6217fc85df6e8bb71 (author Viranjan Pagar, Co-Authored-By Claude Opus 4.8). Later PR memb

**面向读者的改写**

> An unauthenticated request could select vLLM’s GPU video decoder without the normal GPU-backend and frame-size safeguards, allowing oversized videos or attacker-chosen pool settings to exhaust shared resources. The commit that first added this unsafe DeepStream path is explicitly marked as co-authored by Claude Opus 4.8.

**保留的事实锚点**：请求可选择 DeepStream；该路径漏掉 GPU 后端限制和像素上限；进程级解码池受首次请求影响；[引入提交](https://github.com/vllm-project/vllm/commit/9dbcf8c3d5de23925195bac6217fc85df6e8bb71)、[修复提交](https://github.com/vllm-project/vllm/commit/d83eb0b36bfbe26fc856ffdb60f05c8bd460f2fd)、[项目方 advisory](https://github.com/vllm-project/vllm/security/advisories/GHSA-cqm8-jxg6-fqfq)。

**不能声称的边界**：证据支持资源耗尽/拒绝服务，不支持 RCE；项目方 advisory 的版本边界与 Git 标签包含关系有冲突，不能在摘要里直接写成“0.27.0 已修复”。

## 2. GHSA-4PC9-X2FX-P7VJ — cloudflare/workers-oauth-provider

**原摘要**

> Root commit 3b2ae809e9256d292079bb15ea9fe49439a0779c first wrote oauth-provider.ts. parseAuthRequest (lines 661-676) copied redirect_uri from the query and returned it with no client lookup or allowlist check; completeAuthorization (line 711) redirected to options.request.redirec

**面向读者的改写**

> The OAuth provider accepted a callback URL without checking it against the client’s registered URLs, so an auto-approved authorization flow could send a live authorization code to an attacker’s site. This behavior came from the initial provider implementation, whose commit message says Claude was asked to write the provider.

**保留的事实锚点**：授权端点未校验注册回调地址；重定向携带授权码；[引入提交](https://github.com/cloudflare/workers-oauth-provider/commit/3b2ae809e9256d292079bb15ea9fe49439a0779c)、[两步修复](https://github.com/cloudflare/workers-oauth-provider/commit/66de8d802c1d7c468887906ea1a0769a975ff1e3)。

**不能声称的边界**：利用依赖应用自动批准先前授权的客户端；授权码泄漏不等于攻击者必然兑换到访问令牌。

## 3. GHSA-QGP8-V765-QXX9 — cloudflare/workers-oauth-provider

**原摘要**

> First public write of PKCE is b1079e7beb5f4821a0ffc7ae07670c417b66d07d ('Ask Claude to implement PKCE support (for OAuth 2.1).'). That commit added oauth-provider.ts parseAuthRequest optional code_challenge capture (lines 1226-1236), grant persistence of those fields (1275-1277),

**面向读者的改写**

> An attacker who removed the PKCE challenge from an authorization request could downgrade the grant, because the token endpoint checked the verifier only when a challenge had already been stored. The commit that introduced this optional, bypassable PKCE flow explicitly says Claude was asked to implement PKCE support.

**保留的事实锚点**：challenge 缺失时不验证 verifier；形成 PKCE 降级；[引入提交](https://github.com/cloudflare/workers-oauth-provider/commit/b1079e7beb5f4821a0ffc7ae07670c417b66d07d)、[直接修复](https://github.com/cloudflare/workers-oauth-provider/commit/d954473f066f0daa3949717fd4d6e805d2ac618b)。

**不能声称的边界**：攻击者必须能干预授权请求；这不是所有 OAuth 流程都能被无条件绕过。

## 4. GHSA-G8P2-7WF7-98MQ — openclaw/openclaw

**原摘要**

> c74551c2 first applied attacker-controlled gatewayUrl query data to the connection path; parent 51dfd6ef had gateway URL settings but not this query application. The Control UI accepted gatewayUrl and token from query parameters and auto-connected, sending the stored gateway toke

**面向读者的改写**

> A crafted Control UI link could make the browser connect to an attacker-controlled gateway and send it the user’s stored gateway token. The Claude-coauthored commit introduced this query-driven auto-connect path; the fix added an explicit confirmation before changing gateways.

**保留的事实锚点**：攻击者控制 URL 中的 gateway 地址；页面自动连接并带出已存 token；[引入提交](https://github.com/openclaw/openclaw/commit/c74551c2ae0611f3ef0e691dc93a38372f366765)、[修复提交](https://github.com/openclaw/openclaw/commit/a7534dc22382c42465f3676724536a014ce0cbf7)。

**不能声称的边界**：证据直接证明 token 外泄；后续 RCE 取决于 token 权限和网关暴露面，不能写成访问链接即无条件 RCE。

## 5. GHSA-Q6QC-XP4Q-RJQ5 — enderfga/claw-orchestrator

**原摘要**

> f82c7836 first created the unauthenticated embedded server; parent 0a283f45 has no src/embedded-server.ts. The embedded HTTP server exposed every non-health command route without authentication and allowed broad browser origins. The AI-marked atomic commit creates the named surfa

**面向读者的改写**

> The embedded control server exposed command routes without authentication, allowing anyone who could reach it to invoke privileged operations. The commit that created this server is marked as co-authored by Claude Opus 4.6; the fix added a generated token to every non-health route.

**保留的事实锚点**：新服务器的非健康检查路由没有认证；修复增加 token；[引入提交](https://github.com/enderfga/claw-orchestrator/commit/f82c783607ae0129386cc072160dfcfb151a31fe)、[修复提交](https://github.com/enderfga/claw-orchestrator/commit/d0b02a800aa0689d9428cc4cc170e0b6589fb2c3)。

**不能声称的边界**：初始默认监听回环地址；远程可利用性取决于监听配置、代理或同机浏览器访问，不能笼统写成互联网任意攻击者可达。

## 6. GHSA-723W-CRW6-P9HX — jahlives/openssl_encrypt

**原摘要**

> The unguarded deserialization path was first written in fafdfeed1b279cfe61e86cd8adc132b206eef8d4 (2025-12-30), which added openssl_encrypt/modules/key_bundle.py with from_dict() returning an unverified PublicKeyBundle (docstring: 'SECURITY: Does NOT verify signature. Call verify_

**面向读者的改写**

> An untrusted public-key bundle could be converted into a usable identity without verifying its signature, causing callers to encrypt data to an attacker-controlled key. The Claude-coauthored commit introduced this unsafe conversion path, and the fix made verification mandatory before conversion.

**保留的事实锚点**：反序列化不验签；未验证对象可转为 identity；[引入提交](https://github.com/jahlives/openssl_encrypt/commit/fafdfeed1b279cfe61e86cd8adc132b206eef8d4)、[修复提交](https://github.com/jahlives/openssl_encrypt/commit/f4a1ba660063cd9e17883829e5272a248525a16b)。

**不能声称的边界**：默认 key resolver 已有验签；风险位于直接 API 调用及未验签的插件/缓存路径，不能说所有密钥解析都会泄露明文。

## 7. GHSA-C7VW-VFXJ-3MVH — jahlives/openssl_encrypt

**原摘要**

> 8a5ed7e62417441ed98b39481ac1a47510c1a9ef first added plugin validation plus normal module execution. Later import/AST guards were incomplete remediation, not the BIC. PluginImportGuard is a sys.meta_path hook plus a sys.modules hider that is supposed to block dangerous imports at

**面向读者的改写**

> The plugin sandbox’s runtime denylist omitted several Python modules that can lead to code execution, so a plugin that bypassed the static scan could import them and escape the sandbox. A Claude-generated commit introduced the original plugin execution boundary, while later guards failed to close it completely.

**保留的事实锚点**：运行时 denylist 与静态扫描名单不一致；绕过静态层后可导入危险模块；[引入提交](https://github.com/jahlives/openssl_encrypt/commit/8a5ed7e62417441ed98b39481ac1a47510c1a9ef)、[修复提交](https://github.com/jahlives/openssl_encrypt/commit/e0c999ea44429e8de00b4acb3ba570efdc733092)。

**不能声称的边界**：利用需要先绕过静态 AST 扫描；不能把“某个危险模块存在”写成任意插件都能直接 RCE。

## 8. GHSA-GVQ9-CMXR-844M — jahlives/openssl_encrypt

**原摘要**

> The stub was the original production implementation, not a later regression. fafdfeed1b279cfe61e86cd8adc132b206eef8d4 first added server/key-server/app/api/v1/keys.py with comments 'In production, validate token against database or JWT' / 'For now, simple token check (replace wit

**面向读者的改写**

> The key server treated any non-empty bearer token as valid, allowing an unauthenticated attacker to upload an attacker-controlled, self-signed key bundle. The Claude-coauthored initial implementation shipped this placeholder check as production behavior.

**保留的事实锚点**：任意非空 token 被接受；可上传合法自签但由攻击者控制的 bundle；[引入提交](https://github.com/jahlives/openssl_encrypt/commit/fafdfeed1b279cfe61e86cd8adc132b206eef8d4)、[修复提交](https://github.com/jahlives/openssl_encrypt/commit/1d519a1eb1a29936d087fc7d98dc84a4718098c9)。

**不能声称的边界**：公开搜索是有意设计，撤销仍要求所有权签名；不能把这些路径也描述成认证绕过。

## 9. GHSA-JJ45-W38G-GFRJ — thorsten/phpMyFAQ

**原摘要**

> The flawed mechanism was first written by Copilot SWE-agent commit 086c8ad58f91a8e34ea27fabd1ba9ca0b2487f42 (GitHub PR 4180 rebase onto main), which changed `escapeLikeWildcards()` and the PDO/generic LIKE clauses from backslash to `|` “to work across all databases” but left nati

**面向读者的改写**

> Public FAQ searches on phpMyFAQ’s native PostgreSQL backend failed to neutralize `%` and `_` wildcards, allowing unauthenticated users to force broad, expensive scans and degrade availability. A Copilot SWE-agent change introduced the mismatched escaping rule.

**保留的事实锚点**：仅 native pgsql 路径缺少匹配的 `ESCAPE '|'`；通配符仍生效；[引入提交](https://github.com/thorsten/phpMyFAQ/commit/086c8ad58f91a8e34ea27fabd1ba9ca0b2487f42)、[修复提交](https://github.com/thorsten/phpMyFAQ/commit/17b7f5b0e181c6ced34887acc5f836eec7f6d0f8)。

**不能声称的边界**：PDO PostgreSQL 路径不受影响；引号仍被转义，因此这是可用性问题，不是可破坏 SQL 结构的注入。

## 10. GHSA-2664-HR5V-554W — n8n-io/n8n

**原摘要**

> Not an original omission of all prototype freezing. Commit bdf266cf55032d05641b20dce8804412dc93b6d5 (2025-01-15, #12588) froze every globalThis function's `.prototype` unconditionally, which does freeze Function.prototype (Function is the second function-valued global). The first

**面向读者的改写**

> An n8n sandbox change stopped freezing function-valued prototypes, allowing an authenticated workflow author to modify `Function.prototype` and, with a permitted import gadget, escape the JavaScript sandbox. The public squash carries a Claude co-author marker, but its unavailable private members do not prove that Claude authored this exact hunk.

**保留的事实锚点**：函数类型 prototype 未被冻结；需要已认证的 workflow 执行能力和可用 gadget；[候选 squash](https://github.com/n8n-io/n8n/commit/562d867483e871b0f1e31776252e23bd721df75b)、[修复提交](https://github.com/n8n-io/n8n/commit/ca3d42d8386515cd9f044377a15a632cd09b62f0)。

**不能声称的边界**：不能把它写成未认证远程 RCE；也不能声称 Claude 确定写了具体冻结逻辑，只能说 AI 标记存在于包含该改动的公开 squash。

## 11. GHSA-H5RM-9FHH-5PHJ — n8n-io/n8n

**原摘要**

> The unsafe mapping was first written in reconstructable PR #24535 member 6d88b9e1e9f24901985b1fb4e4200f18bd550e1b (2026-01-28), feat(workflow-sdk): integrate Zod schema validation into validate(), which added packages/@n8n/workflow-sdk/src/validation/schema-validator.ts. That com

**面向读者的改写**

> An authenticated n8n MCP member could place path-traversal components in a node type, causing the schema loader to execute a module outside its intended directory in the main process. A Claude-coauthored PR commit first added the unsafe path construction and dynamic module load.

**保留的事实锚点**：攻击输入是 node type；未校验的路径进入动态 `require`；[原子引入提交](https://github.com/n8n-io/n8n/commit/6d88b9e1e9f24901985b1fb4e4200f18bd550e1b)、[修复提交](https://github.com/n8n-io/n8n/commit/ca3d42d8386515cd9f044377a15a632cd09b62f0)、[项目方 advisory](https://github.com/n8n-io/n8n/security/advisories/GHSA-6h4x-896x-fw5m)。

**不能声称的边界**：需要已认证的 global member；CNA 所写 2.0.0 起始版本未被 Git 证明，当前代码证据最早只闭合到 2.9.0 carrier。

## 12. GHSA-Q8HH-M6V5-4F3X — lin-snow/ech0

**原摘要**

> b47fa1c75d890cd080e3f6699bbfca8cd8d4b939 is the atomic BIC only for the RequireScopes session-token early-return constituent. The advisory also joins independently introduced missing-handler and middleware-free sink defects, including user-list BIC f85756b51d5aa4f8629d4e247eaffdf

**面向读者的改写**

> Logged-in non-admins could reach several admin-only user and log endpoints because session tokens skipped the scope check; a separate log WebSocket path also lacked an admin check. The Cursor-marked commit introduced only the session-token bypass, not every flaw bundled into the advisory.

**保留的事实锚点**：session token 触发提前放行；若干 admin endpoint 缺少后置 `IsAdmin`；[AI 标记候选提交](https://github.com/lin-snow/ech0/commit/b47fa1c75d890cd080e3f6699bbfca8cd8d4b939)。

**不能声称的边界**：当前最小修复集合为空，advisory 又合并了多个独立 origin；不能称整条 advisory 均由 AI 引入，也不能把归因写成已经最终闭合。

## 13. GHSA-8359-H9FX-J6V9 — koxudaxi/datamodel-code-generator

**原摘要**

> The AI-written code resolved JSON-Schema `$ref` targets without restricting them to the input directory or honoring `--no-allow-remote-refs`, enabling arbitrary local file reads and host filesystem mapping from attacker-controlled schemas.

**面向读者的改写**

> An attacker-controlled JSON Schema could use local `$ref` paths to read files outside the input directory, even when remote references were disabled. Human-written code introduced local-file references; a later Claude-coauthored remediation still left traversal possible, so AI prolonged the flaw rather than originating it.

**保留的事实锚点**：初始 `file://` 支持提交无 AI 标记；Claude 只出现在未完全修好的 remediation；[AI 参与的未完整修复](https://github.com/koxudaxi/datamodel-code-generator/commit/f6d4cbd3440a84e801566fa758ab2bf483322082)、[最终修复](https://github.com/koxudaxi/datamodel-code-generator/commit/2ff4a72b4550a2b2069754c5b075b1655067e5fb)、[项目方 advisory](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-8359-h9fx-j6v9)。

**不能声称的边界**：不能再写“AI-written code introduced arbitrary file read”；AI 的证据角色是不完整修复，不是原始漏洞 introducer。

## 14. CVE-2026-28473 — openclaw/openclaw

**原摘要**

> The AI-written /approve command invoked exec.approval.resolve through a privileged internal client that only checked isAuthorizedSender, letting operator.write-only users bypass authorization and approve or deny pending exec approvals.

**面向读者的改写**

> A user limited to `operator.write` could use the chat approval command to approve or deny pending command executions that required stronger privileges. The Claude-coauthored command routed the request through a privileged internal client without preserving the caller’s authorization scope.

**保留的事实锚点**：低权限写用户可越权处理 exec approval；直接 RPC 本身有正确权限；[引入提交](https://github.com/openclaw/openclaw/commit/483fba41b9f9fb57964f31b90a2ddacb185d54d7)、[修复提交](https://github.com/openclaw/openclaw/commit/efe2a464af9fcaa2da13873742003d21408a3f9d)。

**不能声称的边界**：攻击者仍需是获准发送者并持有 `operator.write`；这不是未认证绕过。

## 15. GHSA-76RV-2R9V-C5M6 — zeroae/zae-limiter

**原摘要**

> AI-written code keyed all rate limit buckets for one entity under a single DynamoDB partition, allowing high-traffic entities to hit per-partition throughput limits and throttle service for that entity and co-located tenants.

**面向读者的改写**

> All rate-limit writes for one customer were placed on the same DynamoDB partition, so a sufficiently busy customer could exhaust that partition and slow or reject requests for itself and nearby tenants. The partition-key design was introduced in a commit marked as co-authored by Claude Opus 4.5.

**保留的事实锚点**：单 entity 的 buckets 共享 partition key；高写入率形成热点；[引入提交](https://github.com/zeroae/zae-limiter/commit/3902c8c22868832db6d9f54046e76d5be226f607)、[修复提交](https://github.com/zeroae/zae-limiter/commit/9f66c42f06f3b87107ce327bede6416a582f0e60)、[项目方 advisory](https://github.com/zeroae/zae-limiter/security/advisories/GHSA-76rv-2r9v-c5m6)。

**不能声称的边界**：触发阈值受 DynamoDB 自适应容量和部署流量影响；证据是可用性/公平性风险，不是数据泄露或权限提升。

## 16. GHSA-CHFM-XGC4-47RJ — openclaw/openclaw

**原摘要**

> The AI-written code fetched full thread history via Graph API and injected all parent and reply messages into the model context without sender allowlist enforcement, allowing unauthorized senders to influence channel replies.

**面向读者的改写**

> When replying in Microsoft Teams, OpenClaw copied the entire thread into the model context without filtering each message by the sender allowlist, so blocked users could influence the agent’s reply. The Claude-coauthored commit introduced this unfiltered thread-history path.

**保留的事实锚点**：直接消息有 allowlist，而 thread history 没有；未获准发送者内容进入模型上下文；[引入提交](https://github.com/openclaw/openclaw/commit/8c852d86f759bc769dfdb070ce568b91c30f2b67)、[修复提交](https://github.com/openclaw/openclaw/commit/5cca38084074fb5095aa11b6a59820d63e4937c9)。

**不能声称的边界**：证据证明上下文污染和回复影响，不自动证明下游工具执行或主机接管。

## 17. GHSA-PMCH-G965-GRMR — langroid/langroid

**原摘要**

> AI-written SQL validation blocklisted only specific function names, missing pg_read_file/pg_stat_file/pg_ls_logdir/pg_ls_waldir/pg_current_logfile, OPENDATASOURCE, and SQLite ATTACH variants, enabling filesystem disclosure.

**面向读者的改写**

> Langroid tried to block file-reading SQL with a short list of function names, but attackers could use unlisted PostgreSQL, SQL Server, or SQLite features to read files available to the database account. The Claude-marked validation change was an incomplete security repair, not the original decision to execute model-generated SQL.

**保留的事实锚点**：denylist 漏掉多种同族文件访问语句；风险受数据库权限约束；[AI 参与的候选修复](https://github.com/langroid/langroid/commit/60933b4860a8952894b31caa0dd3f9dcba512c8e)、[完整同族修复](https://github.com/langroid/langroid/commit/00b7dd7b79c5d03c94be284cf3459d98195ebfba)、[项目方 advisory](https://github.com/langroid/langroid/security/advisories/GHSA-pmch-g965-grmr)。

**不能声称的边界**：文件访问能力取决于数据库方言和服务账号权限；不能概括成无条件主机 RCE，也不能把原始 SQL 执行面归因给 AI。

## 18. GHSA-9J5F-PJWJ-62R3 — jahlives/openssl_encrypt

**原摘要**

> AI-written code in openssl_encrypt logged restored module counts after clearing them and installed import hooks non-atomically, corrupting audit trails and allowing blocked module re-imports in multi-threaded use.

**面向读者的改写**

> The plugin guard always logged that zero modules had been restored, and a race during guard installation could let another thread re-import a blocked module before protection was active. The commit that introduced both errors is explicitly marked as generated with Claude Code and co-authored by Claude Sonnet 4.5.

**保留的事实锚点**：清空集合后才计数；先隐藏模块、后安装 import hook；[引入提交](https://github.com/jahlives/openssl_encrypt/commit/e588aaa3a53ef291406b02745c20fdea8cea7f7c)、[修复提交](https://github.com/jahlives/openssl_encrypt/commit/85cdb6bedf3a0fbfb49e2f2e29cd66f1f36f3101)、[项目方 advisory](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-43r4-3hf9-m84q)。

**不能声称的边界**：重导入绕过需要多线程和竞态时机；错误日志本身只破坏审计可信度，不能单独描述成 sandbox escape。

## 19. GHSA-FVXX-GGMX-3CJG — mervinpraison/praisonai

**原摘要**

> AI-written deploy.py concatenates user-controlled env values into a gcloud --set-env-vars argument without validating commas, allowing arbitrary environment variable injection into the deployed Cloud Run service.

**面向读者的改写**

> A comma inside a deployment setting was interpreted by `gcloud` as another environment variable, allowing someone who controlled the setting to inject configuration into the deployed Cloud Run service. A commit authored by the Claude bot introduced this unsafe argument construction.

**保留的事实锚点**：多项环境值被拼成一个逗号分隔参数；逗号可注入额外 `KEY=VALUE`；[引入提交](https://github.com/MervinPraison/PraisonAI/commit/eb0a5d19347e979519b99fbe7ba12cfc22276dca)、[修复提交](https://github.com/MervinPraison/PraisonAI/commit/9d9a9a7ad8f94e62dc025fd55b60a7945c50f2e9)。

**不能声称的边界**：攻击者需要控制部署输入并触发部署；这是 gcloud 参数语义导致的环境变量注入，不是已经证明的 shell 命令注入。

## 20. GHSA-6MWV-4MRM-5P3M — decolua/9router

**原摘要**

> AI-written code interpolated a user-controlled region into an upstream URL without validation, allowing an authenticated attacker to redirect a request carrying a Kiro API key to an attacker-controlled host.

**面向读者的改写**

> An authenticated caller could choose a “region” that changed the upstream hostname, causing 9router to send a submitted Kiro API key to an attacker-controlled server. The Claude-coauthored commit added this route and built the hostname from the unvalidated value.

**保留的事实锚点**：region 直接进入 `codewhisperer.${region}.amazonaws.com`；请求携带 Kiro API key；[引入提交](https://github.com/decolua/9router/commit/706e6513c94803ac46a8c1c21ca8ac6775912e3a)、[修复提交](https://github.com/decolua/9router/commit/126aa244c5b51b74ab8c7594e3418fcf4437bf6f)、[项目方 advisory](https://github.com/decolua/9router/security/advisories/GHSA-6mwv-4mrm-5p3m)。

**不能声称的边界**：需要已认证调用和该 Kiro 验证路径；证据是凭据外泄，不是任意代码执行。

## 21. GHSA-GJXX-92W9-8V8F — clerk/javascript

**原摘要**

> The AI-written code built a proxy URL with `new URL(targetPath, fapiBaseUrl)`, allowing paths like `/__clerk//evil.com/steal` to resolve to an attacker-controlled host and leak the `Clerk-Secret-Key` header.

**面向读者的改写**

> Clerk’s optional frontend API proxy could interpret a crafted path as a new host and forward the application’s secret key to that host. The vulnerable URL construction was introduced in a commit marked as co-authored by Claude Haiku 4.5.

**保留的事实锚点**：协议相对路径可覆盖目标主机；代理继续附带 `Clerk-Secret-Key`；[引入提交](https://github.com/clerk/javascript/commit/7772f45ee601787373cf3c9a24eddf3f76c26bee)、[修复提交](https://github.com/clerk/javascript/commit/486545c17db652e003f56ffdecf6f31dd77a1b02)。

**不能声称的边界**：只影响启用该代理的部署；直接后果是 secret 泄漏，不能跳写成应用必然 RCE。

## 22. GHSA-6Q7J-XR26-3H2C — scriban/scriban

**原摘要**

> Scriban’s AI-written parser guard only logged a non-fatal error instead of stopping recursion, so deeply nested expressions cause an uncatchable StackOverflowException that crashes the host process.

**面向读者的改写**

> Deeply nested template expressions could crash the host because the parser recorded a depth error but continued recursing until the stack overflowed. The faulty lines predated Copilot; later Copilot-assisted parser changes failed to close the issue, so AI’s role was incomplete remediation rather than original introduction.

**保留的事实锚点**：深度错误不是终止条件；最终为不可捕获的栈溢出；[AI 参与但未闭合的修改](https://github.com/scriban/scriban/commit/f55280a09575e577fcf7f5629007e0814594e3ac)、[最终修复](https://github.com/scriban/scriban/commit/8fdbd687bbe8f00085c4c4c5b2b3b8d529933949)、[项目方 advisory](https://github.com/scriban/scriban/security/advisories/GHSA-6q7j-xr26-3h2c)。

**不能声称的边界**：不能说 AI 写了原始漏洞行；影响是进程崩溃/拒绝服务，不是 RCE。

## 23. GHSA-J6R7-6FHX-77WX — czlonkowski/n8n-mcp

**原摘要**

> AI-written multi-tenant workflow version endpoints used workflowId/versionId without instance scope checks, letting attackers access or delete other tenants' workflow versions and node credentials.

**面向读者的改写**

> In multi-tenant mode, workflow-version records were looked up without tying them to the caller’s n8n instance, allowing an authenticated tenant to read or delete another tenant’s versions and exposed node credentials. The endpoints were introduced in a commit marked as generated with Claude Code and co-authored by Claude.

**保留的事实锚点**：lookup 缺少 instance scope；读、删、回滚等路径共享问题；[引入提交](https://github.com/czlonkowski/n8n-mcp/commit/04e7c53b59a49a4019b56a25799bf9a26e50912d)、[修复提交](https://github.com/czlonkowski/n8n-mcp/commit/ed0447d8a0a87ad45436ff5ee1af49a76667c965)。

**不能声称的边界**：需要启用 multi-tenant HTTP 模式且攻击者已经认证；单租户部署不属于这条跨租户链。

## 24. GHSA-2JCC-MXV7-P3F9 — oasdiff/oasdiff

**原摘要**

> The AI-written code installed a custom ReadFromURIFunc in loadFromGitRevision that bypassed kin-openapi's external-ref policy, allowing SSRF and local file reads when --allow-external-refs=false.

**面向读者的改写**

> When loading an OpenAPI document from a Git revision, oasdiff bypassed its “no external references” setting, so a malicious specification could still fetch internal URLs or local files. The custom reader that bypassed the shared policy was introduced in a Claude-coauthored change.

**保留的事实锚点**：只在 Git revision loader 安装 custom reader；`--allow-external-refs=false` 失效；[引入提交](https://github.com/oasdiff/oasdiff/commit/58adc823453286a8f6edb19572d59a73b73db292)、[修复提交](https://github.com/oasdiff/oasdiff/commit/c01d48dae4806e11f2041163c92d9ad7d34632bd)。

**不能声称的边界**：需要处理攻击者可控的 OpenAPI `$ref`；普通非 Git-revision 加载路径不能自动归入该漏洞。

## 25. GHSA-8G7G-HMWM-6RV2 — czlonkowski/n8n-mcp

**原摘要**

> AI-generated code failed to validate caller-supplied IDs before using them in URL paths and followed redirects, letting authenticated callers exfiltrate the n8n API key to unintended endpoints.

**面向读者的改写**

> Authenticated MCP callers could use crafted identifiers or redirects to send n8n API requests and credentials to unintended routes or hosts; the same affected release could also upload unredacted workflow values in telemetry. Separate Claude-attributed commits introduced these three paths, rather than one commit causing one uniform flaw.

**保留的事实锚点**：ID path、redirect SSRF、telemetry 泄漏是三个独立机制；[公开候选提交](https://github.com/czlonkowski/n8n-mcp/commit/74f05e937fa7d94babe3507510caa17ce17a698c)、[聚合修复](https://github.com/czlonkowski/n8n-mcp/commit/1cfe9c6bddb4b1634e6e23323c18ea35fd196999)、[项目方 advisory](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-8g7g-hmwm-6rv2)。

**不能声称的边界**：前两条需要已认证 MCP 调用和已配置 n8n API key；telemetry 泄漏只影响启用 telemetry 的实例；不能把三条归因给同一个 SHA。

## 26. GHSA-4PQR-V6C3-X77J — deepmyst/mysti

**原摘要**

> AI-written ChannelBridge.ts misclassifies tracked conversations via _channelType, permitting remote improper authorization on contact tracking under complex attack conditions.

**面向读者的改写**

> Mysti tracked a contacted person by name without binding that identity to the specific messaging account, so a matching sender on another connected channel could be treated as an expected reply and routed into the agent. The unscoped tracking logic was introduced in a commit marked as co-authored by Claude Opus 4.6.

**保留的事实锚点**：旧 tracking record 只有 identifier 和 channel type；修复加入具体 channel ID 和 type；[引入提交](https://github.com/DeepMyst/Mysti/commit/94e14d9d30e2b9bf0b9d67ae6d459dbf263b9d99)、[修复提交](https://github.com/DeepMyst/Mysti/commit/9b4aff0f106db424aa45a35aa89dd0b8f2eb9a48)。

**不能声称的边界**：利用需要多个连接渠道/账号和能匹配的发送者标识；不能写成任意远程用户都可直接取得主机权限。

## 27. GHSA-WVPP-8HX9-P66J — gitpython-developers/GitPython

**原摘要**

> AI-written code allowed a single-character kwarg with split_single_char_options=False to smuggle joined git options, bypassing the guard and enabling arbitrary command execution.

**面向读者的改写**

> GitPython’s unsafe-option check could miss a joined short option when option splitting was disabled, allowing attacker-controlled input to reach Git as a command-executing option. The bypass was introduced by an earlier guard change whose commit author is recorded as GPT 5.6.

**保留的事实锚点**：guard 看到的候选参数与最终传给 Git 的 joined 参数不一致；可形成 `--upload-pack`；[引入提交](https://github.com/gitpython-developers/GitPython/commit/e8d0fbf774d1f6baa3b481adfe48bd262e43b453)、[修复提交](https://github.com/gitpython-developers/GitPython/commit/96a888f4d782cb2f80452148e48e60ce4af6d541)、[项目方 advisory](https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-wvpp-8hx9-p66j)。

**不能声称的边界**：调用方必须让攻击者影响相关 kwargs/value；这不是使用任意 GitPython API 就自动获得 RCE。

## 28. GHSA-539M-9XH6-Q6RR — gitpython-developers/GitPython

**原摘要**

> GitPython’s AI-written `Repo.archive()` option guard uses an incomplete denylist, allowing `--add-file` and `--bundle` options to write to attacker-controlled filesystem paths.

**面向读者的改写**

> `Repo.archive()` still accepted Git options that write additional files to attacker-chosen paths, even when unsafe options were supposed to be blocked. The AI-authored safety guard omitted `--add-file` and `--bundle`, so AI’s causal role was an incomplete remediation.

**保留的事实锚点**：两个写文件选项未进入 denylist；安全默认值仍可绕过；[AI 写的未完整 guard](https://github.com/gitpython-developers/GitPython/commit/701ce32fe5ba8cb622c0e0342a376a6beb47d738)、[最终修复](https://github.com/gitpython-developers/GitPython/commit/7a4f5dcb7bf3cbcbf6e438017efcdfe0bc0d36ca)、[项目方 advisory](https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-539m-9xh6-q6rr)。

**不能声称的边界**：需要攻击者能影响 archive options，且写入仍受进程文件权限约束；证据不等于任意文件读取或无条件代码执行。

## 29. CVE-2026-55828 / GHSA-F9M7-VC86-P6JJ — qbee-io/transport

**原摘要**

> The qbee transport release contains the advisory-described security flaw, but with no auditable source history available to determine the exact faulty AI-written code or its full impact.

**面向读者的改写**

> Claude-coauthored tar extraction failed to exclude link-based targets before truncating files, allowing a crafted archive to overwrite arbitrary files.

**保留的事实锚点**：当前权威 `blocked_deepwave_research` 已闭合原子 introducer、存在的直接 parent、Claude Opus 4.6 trailer 和独立 fix；[引入提交](https://github.com/qbee-io/transport/commit/6a3afbcf335ea2cb22e50fd0563ede611e3ec8c7)、[修复提交](https://github.com/qbee-io/transport/commit/43947671ba9be8fb08b105f3539a112ee7a57ddc)。

**不能声称的边界**：任意覆盖仍受解压进程权限和可构造链接/目标路径约束；不能扩展为读取文件或执行代码。

**数据结论**：页面上的 “no auditable source history” 是过期缓存文案，不是真实证据缺口；publisher 应优先读取当前权威研究字段并覆盖该缓存。

## 可直接落到生成器的最小规则

- 第一字句必须是“攻击入口 → 安全后果”，不能以 SHA、PR、BIC、函数名或审计过程开头。
- 第二句只描述 AI 的证据角色：`introduced`、`copied into a new surface` 或 `left incomplete by remediation` 三选一；没有原子证据时写 “the commit is marked …”，不要写 “AI wrote this hunk”。
- 公开摘要不放 SHA；SHA、parent、carrier 和 fix 留在下面的 evidence chain。
- 句子必须自然结束；禁止按字符数截断。若需限制长度，按完整句保留一到两句。
- 若最小修复集合为空、一个 advisory 混合多个 origin，或具体 hunk 的 AI 归属只能落到不可拆 squash，页面不能用 “attribution is final”。
