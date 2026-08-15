# 135 后续：AI 不完整修复 Batch B（2026-08-12）

## 结论

本批按用户确认的宽口径审计，但不把“同 CWE、同仓库或时间相邻”当因果证据。最终闭合：

| 层级 | PASS | Public components |
|---|---:|---|
| 发布级 `AI_INCOMPLETE_REMEDIATION` | 4 | n8n-mcp 1；Prospero Flow CRM 3 |
| commit-only partial remediation | 4 | Dynatrace MCP、WACRM、MISP、OmniFaces |
| commit-only `STRICT_CAUSAL` | 1 | Prospero Order/OrderItem API |

这 9 个组件均未出现在 frozen `strict-200-v3` 的 public-ID 集合中。发布级正例要求存在一个 tag 同时包含 partial candidate 且不包含 closure；commit-only 只说明 Git 因果成立，不能写成“残缺版本已发布”。

## 发布级 PASS

### 1. n8n-mcp：CVE-2026-42449 / GHSA-56C3-VFP2-5QQJ

裁决：`PASS AI_INCOMPLETE_REMEDIATION_RELEASED`。

- AI candidate：`d9d847f230923d96e0857ccecf3a4dedcc9b0096`，parent `643c98bcf7663fe8f08f6dfd21d2ddeb56634387`。提交自身是单父 mainline object，并带 `Co-authored-by: Claude Opus 4.6`，不是需要反投影的 squash carrier。
- candidate 明确关闭更早 SSRF advisory，并新增同步 `SSRFProtection.validateUrlSync()`；但实现只覆盖 IPv4/private-host checks，没有 IPv6 family checks。
- 一方 [GHSA-56C3-VFP2-5QQJ](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-56c3-vfp2-5qqj) 明确把受影响范围限定为 `>=2.47.4,<2.47.14`，并复述 SDK embedder 可用 IPv4-mapped IPv6 绕过同步 validator、读取响应且转发 `x-n8n-api-key`。
- closure：`9639f757853149f0cb16663cc8b6b6468f27a25f`，补 `::ffff:`、IPv4-compatible IPv6、6to4、NAT64、ULA 和 site-local checks。
- 发布见证：`v2.47.4` 至 `v2.47.13` 含 candidate 不含 closure；`v2.47.14` 首含 closure。

旧主报告把它列为 NR 的理由是“28 文件 fork bundle，最小 member 未恢复”。这条理由不成立：candidate commit object 本身只有一个 parent，AI trailer 也在该 object 上；无需再发明一个 member。

### 2. Prospero Flow CRM：CVE-2026-59233

裁决：`PASS AI_INCOMPLETE_REMEDIATION_RELEASED`。

- AI candidate：`52e5e1938ba7db9191ab75fc6f81d92cf667dd4d`，带 Claude Sonnet 4.6 trailer，主题明确是修 permission endpoint 等安全问题。
- 它把 `PermissionSaveController` 从裸 `Controller` 改成 `MainController`，阻断未登录请求；但保存逻辑仍对 caller 提交的任意 role 执行 `syncPermissions()`。candidate 的正向测试还明确允许任意已认证用户保存权限。
- 一方 [CVE-2026-59233](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/59xxx/CVE-2026-59233.json) 描述的正是“任意 authenticated user 可给任意 role 授权”的剩余 privilege escalation。
- closure：`86a7d6557bd111518a221f4575ad6e36087e19d3` 新增 `PermissionSaveRequest::authorize()`，只允许 `SuperAdmin`，并校验 roles/permissions。
- 发布见证：`v4.6.0` 含 candidate 不含 closure；closure 首见 `v5.5.3` tag。

这是典型的“pre-auth 变 post-auth，但 authorization 仍缺失”，不标 origin。

### 3. Prospero Flow CRM：CVE-2026-59234

裁决：`PASS AI_INCOMPLETE_REMEDIATION_RELEASED`。

- AI candidate：`a3a2f9f5dd2010dc1f3b3c3c723bea52aa5c77c1`，每个安全 member 及 mainline squash object 都带 Claude Sonnet 4.6 trailer。
- candidate 明确执行 web-controller authentication / cross-tenant ownership sweep，并在 Calendar sibling `CalendarExportController` 上把 `find(id)` 改为 `id + Auth::id()` scope；但漏掉 `CalendarDeleteEventController`。
- 一方 [CVE-2026-59234](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/59xxx/CVE-2026-59234.json) 精确描述任意 authenticated user 可按顺序 ID 删除其他用户 calendar event。
- closure：`8c26eed4d80544c30e55448e12a8e999af6d2b70` 在 Calendar delete 上加入 `user_id` ownership filter，并补回归测试。
- 发布见证：`v4.6.0` 含 candidate 不含 closure；closure 首见 `v5.5.3`。

### 4. Prospero Flow CRM：CVE-2026-59240

裁决：`PASS AI_INCOMPLETE_REMEDIATION_RELEASED`。

- 同一 AI candidate `a3a2f9f5…` 在 Notification sibling `SetNotificationReadAjaxController` 上加入 `user_id = Auth::id()`，且给 notification module 增加 ownership tests；但漏掉 `DeleteNotificationController`。
- 一方 [CVE-2026-59240](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/59xxx/CVE-2026-59240.json) 明确指出 delete path 仍使用裸 `Notification::findOrFail($id)`，可删除其他用户通知。
- closure：`eaee2ae018701d116164976cbfa37fa9294ab4cc` 在同一 resource/invariant 上补 `user_id` filter。
- 发布见证同上：`v4.6.0` 是 partial-only tag，`v5.5.3` 含 closure。

这两条 Prospero CVE 是不同 endpoint、不同数据对象和不同一方 CVE；共享 broad hardening candidate 不构成 alias。candidate 的 delta 分别触达 Calendar 和 Notification 的 sibling ownership path，因此也不是仅靠同 CWE 关联。

## Commit-only PASS

### Dynatrace MCP：GHSA-P7W7-4929-VPJ5

- AI partial：`aab80e1652bde1028d84ded3e23855dd0a9a86b7` 把默认 HTTP bind 从 `0.0.0.0` 改为 `127.0.0.1`，提交明确说在收窄 unauthenticated MCP exposure，并带 Claude Sonnet 4.6 trailer。
- residual：显式 `--host 0.0.0.0` 仍完全无认证；一方 [GHSA-P7W7-4929-VPJ5](https://github.com/dynatrace-oss/dynatrace-mcp/security/advisories/GHSA-p7w7-4929-vpj5) 的 PoC 正是显式外部 bind 后直接调用 tools。
- closure：`8f12972481e9165e8bd24d63b0a9e71976f85a43` 加 bearer-token gate、body limit 和 connection cap。
- candidate 与 closure 都只在最终 `v2.0.0` 发布闭包中可见；不进入发布级计数。

### WACRM：CVE-2026-49141

- AI partial：`4afa9bea32cd4538af19cbba45a874dbb614be8d` 在同一个 public automation-engine endpoint 的 Meta send sink 上，将 caller-supplied `contact_id` lookup scope 到 `user_id`；提交正文逐字识别 service-role bypass-RLS 风险，并带 Claude Opus 4.7 trailer。
- residual：其他 automation steps 仍以 service-role client 对同一个 caller-supplied contact ID 读、改字段及增删 tag。
- 一方 [CVE-2026-49141](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/49xxx/CVE-2026-49141.json) 描述的正是该 endpoint 的跨 tenant contact read/write。
- 原子 closure member：`b4f18537bbf6787d18a9abafce53c557ac36f475`；merge carrier：`73041bfa6420f5e1ecbfa1dd4fa847d8529320f5`。closure 在 dispatcher 前做 account ownership check，并给 read/write sinks 加 account scope。
- repo 没有可证明 candidate-only 的 release tag；只计 commit-level。

### MISP：CVE-2026-56422

- 一方 [CVE-2026-56422](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/56xxx/CVE-2026-56422.json) 将多个 controller/model capture path 的 client-controlled primary/ownership keys 合并为一个 mass-assignment advisory，并把 Claude 列为 remediation tool。
- AI patch `bc182d55dde5686a36ca2eb88fe6c2adabb9fad9` 带 Claude Opus 4.8 trailer，关闭 Event freetext/module-result nested `id` overwrite；它也是 CNA 明列的一方 patch。
- 同一 advisory 的其他路径由 `7acf8220…`、`58f637aa…`、`05aad418…`、`63aebc27…`、`00b2e3da…`、`025f7115…` 等后续/并列 patch 才闭合。
- partial 与完整 fix-set 都首次进入 `v2.5.42`，所以这是 AI 对公开漏洞修复的真实部分贡献，但不是发布过的残缺版本。

### OmniFaces：GHSA-FP43-VJ7G-PG92

- 一方 [GHSA-FP43-VJ7G-PG92](https://github.com/omnifaces/omnifaces/security/advisories/GHSA-fp43-vj7g-pg92) 明列 forged combined-resource ID、source-map cache、HashParam、push 等多个修复边界，并引用全部 first-party patches。
- AI patch `aa42da361821ddfbb85b126564e71587347d2786` 带 Claude Opus 4.8 trailer，给 combined-resource inflate 加 64 KiB cap、阻断 serve-path cache growth 并限制 inner resource types。
- 同一 advisory 的 source-map cache 仍由后续 AI patch `a52b92461cf39d983f51ce8724fe7e6b944073e4` 才停止缓存 arbitrary misses；其他边界也有独立 patch。
- 没有 candidate-only release witness；一个 GHSA 只计一个 commit-only component。

## Commit-only strict origin

### Prospero Flow CRM：CVE-2026-59237

- `56ea64c80fd36840fe3c84d0c6a6a38296a8f111`（Claude Haiku 4.5 trailer）首次创建 Order read/update API，直接使用 `Order::find($id)`。
- `86f406519fd208f9be09cd7cf32cd24d292779fd`（同样带 Claude trailer）首次创建 OrderItem read/update/delete API，直接使用 `Item::find($id)`。
- 一方 [CVE-2026-59237](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/59xxx/CVE-2026-59237.json) 逐项列出这些 endpoint 和裸 ID lookup。
- closure `9a859c4de3d49674916773d346c60d89ad7febe0` 用 authenticated company scope 或 parent-order company scope 精确反转。
- `git tag --contains origin --no-contains closure` 为空；origin 与 closure 都首次在 `v5.5.3` tag 中，因此只计 commit-level strict，不进入发布级下界。

## 关键 FAIL / 防膨胀控制

| Candidate / public ID | 结果 | 原因 |
|---|---|---|
| melange `e51ca30…` -> CVE-2026-25143 | FAIL | candidate 精确修 GHSA-VQQR 的 working-directory/setfattr shell quoting；CVE-25143 的 `patch.yaml` series/patch/fuzz sinks 是另一 advisory、另一 input 和另一 fix `bd132535…`。同为 CWE-78 不等于 incomplete fix。 |
| Prospero CVE-2026-59235 | FAIL strict | vulnerable BankAccount API 由无 AI marker 的 human `37c541be…` 首次创建；早期 AI web-controller sweep 发生在该 surface 出现之前。 |
| Prospero CVE-2026-59236 | FAIL | Excel import 的 caller-supplied `company_id` 由 `bdd6c977…` 修；候选 Company API/profile authorization 没触达 import mapper，不能按“cross-tenant”四字硬连。 |
| Vulnogram CVE-2026-32774 | FAIL | Copilot `47d1464…` 是 client-side display autofix；server-side stored-XSS sink 从 2022 human `06fedea…` 已存在，`2f0e21b…` 才在写入前 sanitize。 |
| ChurchCRM CVE-2025-67751 | FAIL AI attribution | `b41692a1…` 修另一个 `EditEventTypes.php` SQLi，但其 trailer 是 human `DawoudIO`，没有 AI marker；`2d6cf7…` 修 `EventEditor.php` 的 CVE-67751。旧 CVE-67874 pairing 还把 plaintext-password advisory 错绑到 SQLi。 |

## 计数影响

以前一方冻结报告为起点：

- strict release-grade：`116 + 9 OpenClaw = 125`；
- incomplete-remediation release-grade：`19 + 1 n8n + 3 Prospero = 23`；
- **宽口径发布级确认下界：148**；
- commit-only：原 3 + 本批 5 = 8；
- **最宽 commit-level 工作数：156**。

其中 OpenClaw 不是 12/12：独立报告冻结为 9 PASS / 3 FAIL。`156` 不能写成发布级样本数。

## 可重放检查

```zsh
cd /home/hanqing/agents/ai-slop

prospero_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_prospero-flow-crm_74adca6f21ff5f432fddd961e722287ea558c796a12c75c2e95338500ab31ef2
n8n_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_n8n-mcp_7f3ec1dcf0d7cdaa7f65f6c0aed32341a5c14c9c95b456fff2c6e355a78931a1
wacrm_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_wacrm_4e2c44937684865531ea35e48b265b4c1fc620b74b3ae03bce6efc1b56232c69
misp_repo=/home/hanqing/.cache/cve-analyzer/repos/misp_misp

# 发布级 partial-only witnesses。
git -C "$n8n_repo" tag --contains d9d847f230923d96e0857ccecf3a4dedcc9b0096 --no-contains 9639f757853149f0cb16663cc8b6b6468f27a25f
git -C "$prospero_repo" tag --contains 52e5e1938ba7db9191ab75fc6f81d92cf667dd4d --no-contains 86a7d6557bd111518a221f4575ad6e36087e19d3
git -C "$prospero_repo" tag --contains a3a2f9f5dd2010dc1f3b3c3c723bea52aa5c77c1 --no-contains 8c26eed4d80544c30e55448e12a8e999af6d2b70
git -C "$prospero_repo" tag --contains a3a2f9f5dd2010dc1f3b3c3c723bea52aa5c77c1 --no-contains eaee2ae018701d116164976cbfa37fa9294ab4cc

# WACRM member/carrier topology。
git -C "$wacrm_repo" rev-list --parents -n 1 73041bfa6420f5e1ecbfa1dd4fa847d8529320f5
git -C "$wacrm_repo" diff 19a1df275a1006b153568d576c5356ed284eebe3 73041bfa6420f5e1ecbfa1dd4fa847d8529320f5 -- src/lib/automations

# MISP partial 和 fix-set 同一首发 tag。
git -C "$misp_repo" tag --contains bc182d55dde5686a36ca2eb88fe6c2adabb9fad9 --sort=version:refname | head
git -C "$misp_repo" tag --contains 025f711506850aadb69cde1b57e5e5d57628c87f --sort=version:refname | head

# Prospero strict commit-only release gate：应为空。
git -C "$prospero_repo" tag --contains 56ea64c80fd36840fe3c84d0c6a6a38296a8f111 --no-contains 9a859c4de3d49674916773d346c60d89ad7febe0
git -C "$prospero_repo" tag --contains 86f406519fd208f9be09cd7cf32cd24d292779fd --no-contains 9a859c4de3d49674916773d346c60d89ad7febe0
```
