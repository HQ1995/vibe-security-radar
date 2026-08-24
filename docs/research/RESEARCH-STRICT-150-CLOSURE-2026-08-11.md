# AI 贡献漏洞严格闭包：118 个语义组件 / 207 个 CVE/GHSA 标识（2026-08-11）

## 结论

本轮达到“至少 150 个 CVE 或 GHSA”的**公开标识口径**，并保留去重后的真实语义口径：

| 口径 | 数量 | 含义 |
|---|---:|---|
| 严格语义组件 | **118** | CVE/GHSA alias、重复 advisory component 与相同机制只算一次 |
| 不重复公开标识 | **207** | **108 CVE + 99 GHSA**；满足 `>=150` 标识门槛 |
| 冻结基线 | 92 组件 / 157 标识 | `strict-ledger-audited-v4` |
| 本轮严格补充 | 26 组件 / 50 标识 | 12 direct origin、1 dangerous revert、2 guard weakening、4 incomplete-hardening contributor、7 new-surface contributor |

因此可以说：**已严格确认 207 个公开 CVE/GHSA 标识存在 commit-level AI 贡献证据**。不能说“确认了 207 个彼此独立漏洞”；去掉 alias 和同机制重复后是 **118 个独立语义组件**。如果目标被解释为“150 个独立漏洞组件”，本结果还差 32 个，不能用 CVE/GHSA 双计数补足。

## 严格门禁

每个 PASS 同时满足：

1. **明确 AI 信号**：候选 commit 自身的 author identity、`Co-Authored-By`、`Generated with` 或 `[AI]` 标记；carrier 的 AI 标签不能传递给无标记 member。
2. **最小归因单元**：direct commit 直接归因；squash 只接受已恢复的 atomic/member SHA，并另记 mainline carrier。
3. **候选自己的 delta**：必须由 parent→candidate 新增、削弱或扩展 advisory 覆盖的危险路径；祖先关系、同文件、blame 命中都不够。
4. **advisory 机制 + fix reversal**：优先使用项目一方 advisory；仅有注册记录时，必须由其引用的项目 commit/PR 与本地 Git diff 独立闭合。真实 fix 必须反转候选 delta；修复旧漏洞、无关重构和 omnibus-fix 邻近全部拒绝。
5. **保守贡献分型**：旧根因上的新入口只叫 `new_surface_contributor`；失败的安全加固只叫 `incomplete_hardening_contributor`，不冒充首次 origin。

OSV `introduced`、模型票、same-file、subject/token overlap 只用于 recall/routing，没有进入 PASS 的 claim-grade 证据。DeepSeek 只做候选排序；Prompty 等模型漏报由完整 Git history 人工复核纠正。

## 可复核产物

| 产物 | 作用 | 校验值 |
|---|---|---|
| `research/orchestrator-260811-atomic150/strict-ledger-audited-v4/ledger.jsonl` | 冻结 92 组件基线 | byte SHA-256 `437cec14c55e1ba0dfde0492c0952497bfea306194c2b2e184f63d247b7d421b` |
| `research/orchestrator-260811-atomic150/strict-supplement-v1/adjudications.json` | 26 个补充组件、50 个标识、全部 accepted edges | SHA-256 `7a196290fcd0a8d81f347c2172d13d8e842cd4e5df9e1a536e1a0ae259035fa9` |
| `research/orchestrator-260811-atomic150/strict-ledger-union-v1/ledger.jsonl` | 118 行合并账本 | canonical SHA-256 `990974f2446c8f4a617f439d2f99e53ac08baa8e9ef9310fb9d64e132ce5c8fe` |
| `research/orchestrator-260811-atomic150/strict-ledger-union-v1/summary.json` | 118 / 207 / 108 / 99 计数与输入绑定 | `minimum_met=true` |
| `scripts/merge_strict_ai_causal_supplement.py` | fail-closed 合并/校验 | 检查格式、去重、Git 对象、候选 AI marker 与 ancestry |

合并器实际对 26/26 行检查了 candidate、carrier、fix 是否为本地真实 commit；对 direct edge 检查 candidate→fix ancestry，对 squash edge 检查 carrier→fix ancestry；还检查补充 50 个公开标识与基线 157 个标识零重叠。

## 新增 26 个严格组件

| # | 公开标识 | 仓库 | 贡献类型 | 最小 edge | parent→delta→fix 闭环 |
|---:|---|---|---|---|---|
| 1 | CVE-2026-58138 / GHSA-7X5Q-8F6H-RJRC | conductor-oss/conductor | direct origin | `840ec19c` → `c691e35e` | Nashorn `--no-java` 被 AI 改成 GraalJS `HostAccess.ALL`；fix 禁 host class/native/thread/process。 |
| 2 | CVE-2026-63102 / GHSA-H4RQ-P45C-642R | rconfig/rconfig | new surface | `4b0938dd` → `84822f40` | AI 新增 token-auth v1/v2 Users API 并继承任意 `role` 写入；fix allowlist 角色且仅 Admin 可授予 Admin。 |
| 3 | CVE-2026-10108 / GHSA-5J8P-5RRJ-8WJG | hanxi/xiaomusic | new surface | `ac32a09a` → carrier `fa0511f4` → `88404da7` | AI 新增 `/music/temp/` 并复用无 separator 的 `startswith`；旧 music path 同样有 bug，故只归因新 temp path。 |
| 4 | CVE-2026-45796 / GHSA-686C-7VGV-V3FX | coder/coder | dangerous revert | `f2b9ec2b` → carrier `9400eaa9` → `57b11d40` | AI revert 删除 Azure host allowlist、private-IP client、size cap 与通用错误；fix 全部恢复。 |
| 5 | CVE-2026-50569 / GHSA-VCHH-R53J-8MPW | fission/fission | guard weakening | `c6cd334f` → carrier `6104e1fd` → `0deed6bf` | AI 在 CEL 未覆盖 RelativeURL/Prefix 时移除 HTTPTrigger webhook；fix 恢复 CEL + Go validation。 |
| 6 | CVE-2026-50570 / GHSA-QF5V-M7P4-95RP | fission/fission | incomplete hardening | `2db76f65` → carrier `e484df84` → `2569b42b` | AI 建六项 capability denylist 但漏 `SYS_TIME`；fix 改 allowlist。 |
| 7 | CVE-2026-32885 / GHSA-X2XQ-QHJF-5MVG | ddev/ddev | new surface | `93f80ea4` → carrier `5f988451` → `05cbe299` | AI 新增 Untar symlink extraction，不校验 entry/target containment；fix 同时验证两者。旧 regular-file ZipSlip 不归给 AI。 |
| 8 | CVE-2026-44430 / GHSA-R48C-V28R-PF6V | modelcontextprotocol/registry | incomplete hardening | `257eb178` → carrier `1201cbd8` → `f5f40bd9` | AI 建 `safeDialContext` blocklist 但漏 6to4/NAT64/site-local IPv6；fix 添加精确 CIDR。 |
| 9 | CVE-2026-35670 / GHSA-WV46-V6XC-2QHF | openclaw/openclaw | direct origin | `ce12b909` → carrier `9a3800d8` → `7ade3553` | AI 用可变 username/nickname 解析 reply recipient；fix 默认稳定 numeric user_id，name matching 需危险 opt-in。 |
| 10 | CVE-2026-41376 / GHSA-RG8M-3943-VM6Q | openclaw/openclaw | direct origin | `fbfe2f15` → carrier `49c60e90` → `8a563d60` | AI 把 Matrix thread root 注入上下文却不校验 sender；fix 按 room sender allowlist 过滤 root/reply。 |
| 11 | CVE-2026-45001 / GHSA-9FC9-8V4X-F5CP / GHSA-7JM2-G593-4QRC | openclaw/openclaw | guard weakening | `53764bbb` → carrier `29f20624` → `fe30b31a` | AI 把复杂 config guard 简化为不完整 set-diff/denylist；fix 扩大 protected paths 并封住 per-agent array edits。两个 advisory 是同一 edge，只算一个组件。 |
| 12 | CVE-2026-41329 / GHSA-G5CG-8X5W-7JPM | openclaw/openclaw | new surface | `01d568c9` → carrier `483fba41` → `a30214a6` | AI 新增 exec-event heartbeat delivery，系统事件继承 owner auth；fix 传 `ForceSenderIsOwnerFalse`。 |
| 13 | CVE-2026-35635 / GHSA-RQP8-Q22P-5J9Q | openclaw/openclaw | direct origin | `cc048a29` → carrier `03586e3d` → `980940aa` | AI 新增 Synology channel，继承共享 webhookPath 且 `replaceExisting`；fix 要求显式唯一路径并禁止 replacement。 |
| 14 | GHSA-WXW3-Q3M9-C3JR | better-auth/better-auth | new surface | `3d3435b3` → carrier `0deaaa4e` → `9deb7936` | Cursor member 扩展 generic OAuth proxy callback，cookie state 未绑定 nonce；fix 为所有 caller 存储并比较 `oauthState`。GitHub 明确列为 **No known CVE**。 |
| 15 | CVE-2026-11330 / GHSA-5GVR-V6QV-H5MM | thedotmack/claude-mem | direct origin | `924a11ee` → carrier `c6f93298` → `f32fda8b` | AI 新增 observation dedup，把 SHA-256 截为 16 hex 并当 identity；fix 替换弱 hash。 |
| 16 | CVE-2026-46672 / GHSA-7GH7-258J-4MPQ | actualbudget/actual | direct origin | `c4de834f` → carrier `a43b6f5c` → `06818575` | Author 为 Claude 且主题 `[AI]`；新 CLI `escapeCsv` 只做 RFC 4180 quoting；fix 中和公式触发字符。 |
| 17 | CVE-2026-50566 / GHSA-M63V-2G9W-2W6V | fission/fission | incomplete hardening | `2db76f65` → carrier `e484df84` → `695d3e97` | AI 只校验 PodSpec containers，漏 Runtime.Container/Builder.Container；fix 抽取共同验证并接入两条路径。 |
| 18 | CVE-2026-50568 / GHSA-R5JH-Q2MW-GCX4 | fission/fission | incomplete hardening | `0d851525` → carrier `5a3d68a3` → `8298e33e` | AI 把 Builder.Clean 接到旧 lexical `HasPrefix` helper；fix 用 `os.Root` 风格 confinement 替换 builder/fetcher 调用。 |
| 19 | CVE-2026-47211 / GHSA-C4M7-2GWP-VW76 | Q00/ouroboros | direct origin | `d30b6175` → carrier `4aaf9147` → `4e70b760` | AI 新增 `OUROBOROS_CLI_PATH` 执行覆盖；project-local `.env` 可指向恶意脚本；fix 禁本地 `.env` 写 execution selectors。 |
| 20 | CVE-2026-25580 / GHSA-2JRP-274C-JHV3 | pydantic/pydantic-ai | new surface | `6bba553f` → carrier `afde1c43` → `d398bc9d` | AI 为 Anthropic PDF `DocumentUrl` 新增 `force_download` server fetch；fix 添加 redirect-aware private/metadata SSRF 阻断。 |
| 21 | CVE-2025-32425 | Significant-Gravitas/AutoGPT | new surface | `a75c1af2` → carrier `f172b314` → `57a06f70` | AI 新增长期运行 frontend Compose service 却无 log rotation；fix 为平台容器加 bounded logging。旧 services 不归 AI。 |
| 22 | CVE-2026-8147 / GHSA-2CM6-R77W-6G96 | mlflow/mlflow | direct origin | `f685d19b` + `3e590361` → `f9b1eb51` | 两条 Claude commits 新增 BatchGetTraceInfos proto/handler/client；handler 无 trace auth validator；fix 注册 validator。 |
| 23 | CVE-2026-53598 / GHSA-WXHM-2MQ7-7697 | microsoft/prompty | direct origin | `a0e61088` + `bd50f65d` + `19137b33` → `88ac9948` | Copilot TypeScript/C#/Rust loaders 都新增无 allowed-root 的 `${file:...}`；fix 跨语言限制 roots 与 symlink/traversal。 |
| 24 | GHSA-W28W-GP39-M4P6 | microsoft/prompty | direct origin | `a0e61088` → `047756f4` | Copilot TypeScript runtime 建 unrestricted Nunjucks renderer；fix 禁 constructor/prototype traversal、function calls 与非 own data。GitHub 明确列为 **No known CVE**。 |
| 25 | CVE-2026-53597 / GHSA-C4GH-RV8H-Q9VW | microsoft/prompty | direct origin | `a0e61088` → `c27402da` | Copilot TypeScript loader 直接调用 gray-matter，允许 executable js/javascript frontmatter；fix 解析前拒绝 engine。 |
| 26 | CVE-2026-18980 / GHSA-CW23-QWR7-C655 | nearai/ironclaw | direct origin | `ca8b28ad` → carrier `b58b4215` → `a1d7c3ba` | AI 新增 Low/Medium/High shell risk，把 Low 映射为永不审批；`env sh -c`、`time rm`、`sort --compress-program` 可绕过；fix 递归拆 wrappers。 |

公开 advisory 记录补足了本地快照缺口：[Ouroboros 项目 advisory](https://github.com/advisories/GHSA-c4m7-2gwp-vw76) 明确把 RCE 归因于 project-local `.env` 接受 `OUROBOROS_CLI_PATH` 等执行选择器；[Ironclaw 注册记录](https://github.com/advisories/GHSA-cw23-qwr7-c655) 是 unreviewed，因此只用来确认 ID、函数与 fix 引用，因果结论另由本地 candidate/fix diff 闭合。[Better Auth](https://github.com/advisories/GHSA-wxw3-q3m9-c3jr) 与 [Prompty Nunjucks](https://github.com/advisories/GHSA-w28w-gp39-m4p6) 页面都明确没有 CVE，因此各只计一个 GHSA，没有使用猜测或尚未发布的 CVE 号。

## 本轮消除的误报

以下候选曾被结构/模型路由提升，但均未进入账本：

| 对象 | 误报原因 |
|---|---|
| PJProject CVE-2026-34235 | AI candidate 改 SIP event subscription lifetime；真实 fix `f4c7d082...` 修 VP9 packetizer bounds，机制不相交。 |
| MoviePilot CVE-2026-16224 | AI candidates 增 workflow share/fork；fix 改 system/dashboard/plugin/user auth，没有 workflow delta。 |
| Tekton CVE-2026-33022 / GHSA-CV4X-* | AI candidate 加 resolver cache；panic 函数与调用早已存在，fix 是 long resolver name 的 deterministic-name 修复。 |
| OpenClaw CVE-2026-45006 | denylist routing edge 没有 candidate→advisory reversal，已剔除；不能因为与 CVE-2026-45001 同仓同 fix 邻近就合并。 |
| Better Auth `CVE-2026-67335` | GitHub 一方 advisory 当前显示 No known CVE；只保留 GHSA-WXW3-Q3M9-C3JR。 |
| OpenClaw gateway 双 advisory | GHSA-9FC9-* 与 GHSA-7JM2-* 共用同一 guard edge/fix，合并为一个语义组件，保留三个公开标识。 |

早期 V12 报告对 DDEV 的 `0c26d82f...` 测试清理 edge 判 FAIL；本轮 PASS 是后来从 squash 历史恢复出的不同 member `93f80ea4...`，它原子新增 symlink extraction。这里是“旧 edge 继续拒绝、新 edge 另行闭合”，不是把同一反证翻成正例。

此外，前序分批审计已系统拒绝“AI 修复旧漏洞”“later-human origin 反投影”“同文件无关修改”“merge/squash carrier 代替 member”“新 surface 仅继承旧 sink”以及 alias 重复行。负例和 `NEEDS_REVIEW` 没有为了达到 150 而丢弃。

## 复现

```zsh
cd /home/hanqing/agents/ai-slop

uv run --project cve-analyzer python scripts/merge_strict_ai_causal_supplement.py \
  --supplement research/orchestrator-260811-atomic150/strict-supplement-v1/adjudications.json \
  --output-dir research/orchestrator-260811-atomic150/strict-ledger-union-v1

jq '{semantic_component_count,public_id_count,cve_count,ghsa_count,minimum_met,ledger_sha256}' \
  research/orchestrator-260811-atomic150/strict-ledger-union-v1/summary.json

wc -l research/orchestrator-260811-atomic150/strict-ledger-union-v1/ledger.jsonl
sha256sum research/orchestrator-260811-atomic150/strict-supplement-v1/adjudications.json
```

预期核心输出：

```json
{
  "semantic_component_count": 118,
  "public_id_count": 207,
  "cve_count": 108,
  "ghsa_count": 99,
  "minimum_met": true,
  "ledger_sha256": "990974f2446c8f4a617f439d2f99e53ac08baa8e9ef9310fb9d64e132ce5c8fe"
}
```
