# Batch F：冻结总数后的 public-ID / mechanism / release 闭合

审计日期：2026-08-12（America/New_York）
读者：技术审计与后续统一 ledger 集成人员

## 技术摘要

本批得到 **18 个待整合的发布级语义组件**：`STRICT_CAUSAL=5`，`AI_INCOMPLETE_REMEDIATION=13`，`COMMIT_ONLY=0`，覆盖 **21 个当前已发布且未撤回的一方 public IDs**。这里的 18 是本批提案数，不是新总数；它们没有写入 Batch 2 snapshot-only unified ledger，也没有改变其 `integration_ready=false` 状态。Batch 2 的机械验收只冻结 `strict/broad/widest=125/172/184` 的 source envelopes；12 个 shard 虽通过路径、哈希、JSON/JSONL 与 unified verifier 检查，acceptance matrix 仍为 `4 ACCEPT + 8 ACCEPT_WITH_LIMITS`，五条早先 proposal 仍未整合。

五个 strict 组件均由最小 AI-attributed member 引入对应 input/sink/invariant，随后在受影响发布版中存在，并由一方 advisory 的 exact fix 反转。十三个 incomplete-remediation 组件均是 AI 明确实施安全收紧、残缺状态真实发布、后续同机制修复精确补洞；它们不得改写成 AI 首次制造旧漏洞。

本批没有按 public ID 数量或提交 SHA 数量计数组件。三组容易误判的复用被保留为显式关系：

- ChurchCRM `cbea916e…` 是 CVE-2026-44547 的 closure，同时是 GHSA-F2FQ 的残缺 2FA 修复；两条分别是“完全绕过 2FA/lockout”与“错误 OTP 不累计失败次数”。
- PraisonAI `179cab02…` 已在旧账本用于别的 SSRF/Python-sandbox hunks；本批只使用其 `str.format` 未覆盖的 C-level attribute-resolution residual。该 advisory 明确称其与 GHSA-4MR5 是同一 defense surface、不同 bypass mechanism。
- OpenClaw `3d93174c…` 关闭 action-triggered post-navigation residual，却仍漏 current-tab route preflight；前者与后者有不同输入时点、检查位置和 final fix。

因此，本批可以进入下一版统一 mechanism ledger 的 red-team 输入；在跨批去重、负控抽样和统一 verifier 重放前，不应加入“200”或任何新下界。

## 18 个待整合组件

| # | 分类 | Public identity | Repo | AI member / released carrier | Exact closure | 发布见证 | 语义机制 |
|---:|---|---|---|---|---|---|---|
| F01 | STRICT | CVE-2026-44547 / GHSA-CWP8-RM8G-Q5C9 | ChurchCRM/CRM | `f9afc3c5…` / `18b21153…` | member `cbea916e…`, carrier `1bfc187a…` | `7.2.0`–`7.2.2`; fixed `7.3.1` | public API login 删除既有 lockout 与 2FA gate |
| F02 | STRICT | GHSA-MFMP-Q643-VJ39 | ChurchCRM/CRM | `0ea20d01…` / `80a3e620…` | members `3b8b4745…` + `367dd18e…`, carrier `330d0d6a…` | candidate in `7.1.0`; advisory witness through `7.4.2`; fixed `7.4.3` | group role/ListOption names written into HTML label sinks |
| F03 | STRICT | GHSA-M649-24Q9-Q6R4 | ChurchCRM/CRM | `0ea20d01…` / `80a3e620…` | member `5631bb08…`, carrier `ae2b7355…` | advisory witness `7.5.1`; fixed `7.6.0` | member phone/email/name enter URL and quoted attribute sinks |
| F04 | STRICT | GHSA-HM7V-JRHM-FMFX | ChurchCRM/CRM | `6ef78813…` / `ede1bfb0…` | member `5631bb08…`, carrier `ae2b7355…` | candidate in `7.1.0`; advisory witness `7.5.1`; fixed `7.6.0` | shared person action menu uses HTML escaping in quoted `data-person_name` |
| F05 | INCOMPLETE | GHSA-F2FQ-4RMP-9X8C | ChurchCRM/CRM | member `cbea916e…`, carrier `1bfc187a…` | member `32599b3d…`, carrier `07be35d7…` | partial from `7.3.1`, advisory witness `7.5.1`; fixed `7.6.0` | restored 2FA checks reject bad OTP but do not increment lockout counter |
| F06 | STRICT | CVE-2026-58409 / GHSA-37MF-VQ43-5QP9 | ChurchCRM/CRM | `095bf81b…` / `de417ffa…` | members `682084ed…` + `4ba62f43…`, carrier `1b4e2c70…` | `7.3.0`–`7.3.3`; fixed `7.4.0` | new plugin installer extracts executable PHP below web root |
| F07 | INCOMPLETE | CVE-2026-57120 / GHSA-PV2J-RGHR-V5R9 | MervinPraison/PraisonAI | `179cab02…` | `2adfe7e8…` | repo tags `v4.6.40`–`v4.6.58`; fixed `v4.6.59` | AST denylist misses `str.format` / `format_map` C-level attribute resolution |
| F08 | INCOMPLETE | GHSA-3FP5-V549-9V66 | openclaw/openclaw | `8e41c118…` | `55d1324c…` | witness `v2026.6.8`; fixed `v2026.6.9` | wrapper hardening misses durable approval binding through `flock` |
| F09 | INCOMPLETE | GHSA-575V-8HFQ-M3MC | openclaw/openclaw | `3cc8b2a3…` | `a90eb934…` | witness `v2026.6.5`; fixed `v2026.6.6` | absolute bind-source validation misses allowed-parent covering denied descendant |
| F10 | INCOMPLETE | GHSA-X863-PQJW-HMGF | openclaw/openclaw | `3d93174c…` | `78f3985c…` | witness `v2026.5.18`; fixed `v2026.5.19` | act route lacks current-tab URL preflight before operating on an existing session |
| F11 | INCOMPLETE | GHSA-2X93-H3HG-2XFP | openclaw/openclaw | `b75ad800…` | `06047005…` | witness `v2026.5.22`; fixed `v2026.5.26` | snapshot hardening misses current-tab validation before snapshot read |
| F12 | INCOMPLETE | GHSA-8V95-QQCM-QP9H | openclaw/openclaw | `1c85eff9…` | `517ce3df…` | witness `v2026.5.26`; fixed `v2026.5.27` | admin scope added for device-token methods but omitted `device.pair.approve` |
| F13 | INCOMPLETE | GHSA-QJPC-QF9M-XWMR | openclaw/openclaw | `0e702f10…` | `96fba91b…` | witness `v2026.5.12`; fixed `v2026.5.18` | unbound-scope clamp still accepts trusted-proxy Control UI scope before pairing |
| F14 | INCOMPLETE | GHSA-9C3V-684M-579C | openclaw/openclaw | `47eb2d48…` | `3c6259eb…` | witness `v2026.6.1`; fixed `v2026.6.5` | redirect-header scrub covers Streamable HTTP but not MCP SSE transport |
| F15 | INCOMPLETE | GHSA-J4CX-JVQ7-79VM | openclaw/openclaw | `17ceca86…` | `19fb9f12…` | witness `v2026.5.28`; fixed `v2026.6.1` | broad persisted-secret redaction misses trajectory-export bundle traversal |
| F16 | INCOMPLETE | GHSA-WP73-F3GG-W4VR | openclaw/openclaw | `6c918ca8…` | `797bcd5b…` | witness `v2026.6.1`; fixed `v2026.6.5` | delegated-session `toolsAllow` propagation stops before ClickClack reply dispatch |
| F17 | INCOMPLETE | GHSA-7JX6-764P-FGG9 | openclaw/openclaw | `6e498a1f…` | `08a73dbe…` | witness `v2026.5.26`; fixed `v2026.5.27` | approval callback authorization retains same-chat fallback for non-allowlisted sender |
| F18 | INCOMPLETE | GHSA-2HFG-4FH4-QP7F | openclaw/openclaw | `e0b8ddc1…` | `3d93174c…` | witness `v2026.5.12`; fixed `v2026.5.18` | three-phase navigation guard covers press/type-submit but misses other navigation-capable acts |

## 五个 strict 组件的 direct-parent 因果证据

### F01：AI 原子提交删除既有认证边界

`f9afc3c5a961efbf600ac8f71ecc3da54ddef1b1` 的 parent `43d5d7c6660a527efd87999241229db840eb4a00` 已在 `public-user.php` 检查 `isLocked()`、递增 `FailedLogins`、要求 OTP/recovery code，并仅在完整认证后返回 API key。该 Claude-authored member 将整段 gate 删除，只保留用户名/密码校验。其 squash carrier `18b211535fec3b09d1ab613af923e28080605101` 首次进入 `7.2.0`；删除 candidate 会恢复原有 2FA/lockout，不是旧漏洞的偶然邻接。

`cbea916e77e2d8cbe34f04efdd00792e3af27e2c` 原样恢复这些检查，mainline carrier `1bfc187ac41238a2488d58f06361d7377d3cdf11` 首次进入 `7.3.1`。一方 advisory 的受影响范围恰为 `>=7.2.0,<=7.2.2`。

这条与先前的 CVE-2026-40582 / GHSA-8CWR-X83M-MH9X 是同一认证机制的复发链，不是一个可再拆分的第二机制：人工提交 `214694eb…` 曾在发版前完整加回 gate，随后 Claude member `f9afc3c5…` 删除该 gate；其 route hunk 与 mainline carrier `18b21153…` 的 stable patch-id 同为 `1c48deba…`。旧 advisory 只描述 `<=7.1.2` 的原始人类漏洞，故不计入本批 AI-attributed public-ID 数；F01 只以专门描述 7.2.x 回归的 CVE-2026-44547 / GHSA-CWP8 作为 public identity。未来 unified ledger 必须保留 `related_prior_advisory` 关系，禁止把新旧 advisory 再计成两个语义组件。

### F02–F04：同一 UI 改造中的三个独立 XSS sink

`0ea20d01050cd25b30bca1418bb821fbd3bcb7ab` 新建/重写 GroupView，并把 `OptionName` 直接拼入 role pill、dropdown 与 option-label HTML；`3b8b4745…` 和 `367dd18e…` 对相同四个 sink 加 `escapeHtml`。这是 F02。

同一 AI member 还新增 member-table 的 `tel:`、`mailto:` 和 quoted `data-name` 构造；`5631bb08…` 改用 `encodeURIComponent` 与 `escapeAttribute`。这是 F03，输入与 sink 均不同于 role label。

`6ef78813e04987da217bbb081706715c1ecb19e9` 则在共享 `CRMJSOM.js` person action renderer 新增 `data-person_name` attribute；`5631bb08…` 将其从不编码引号的 HTML escape 改成 attribute escape。它影响 dashboard 等共享调用方，不是 F03 member-table 的第二个 public ID。

三个 advisory、三个输入/sink 元组和两个独立 origin members 均不同；共享 bulk carrier 或共享 final fix 不等于同一组件。

### F06：AI 新增可下载、可解压到 web root 的 PHP plugin surface

`095bf81b318c892258a9874e63ebb017b971443d` 的 parent 不存在 URL community-plugin installer。该 Claude-authored member 创建 `PluginInstaller`、下载/校验/解压流程与 admin API，并允许普通 `.php` 作为 plugin code 落入 `src/plugins/community/`。carrier `de417ffa845a8f6c68905740b34478537543bc05` 首次进入 `7.3.0`。

`682084ed6e108ae32c16dff27dd29bdeb453b788` 添加 Apache deny、installer refresh 和 nginx guard；`4ba62f4343079512171109d639c1f0f06c2dd64b` 修正 nginx `^~` precedence 并补 Caddy。carrier `1b4e2c708f9f4d8afd458febc6958cec21da2922` 首次进入 `7.4.0`。这不是把“安全修复提交”误当 origin：candidate 首次创建了可利用的安装与 HTTP-execution surface。

## 十三个 incomplete-remediation 组件的残缺链

### F05 与 F07：修复确实减风险，但遗漏 later advisory 的精确绕过

F05 的 `cbea916e…` 恢复 password failure 计数、lockout 和 OTP 校验，但错误 OTP 分支只返回 401，既不递增 `FailedLogins` 也不触发 lock。`32599b3d…` 在 API 与 browser 两条 2FA path 同时补计数、锁定和 fail-closed redirect。删除 partial 会恢复更严重的完全 2FA bypass；因此只能标 `AI_INCOMPLETE_REMEDIATION`。

F07 的 `179cab02…` 明确将 AST blocked attrs/calls 提取成共享集合，并把 attribute-call 校验接入 parent 的弱 sandbox；它却未把 `format`/`format_map` 放入 blocked calls。`str.format` 的 C-level field resolution 不经过 Python-level `_safe_getattr`，所以可读取任意被 blocklist 命名的 dunder。`2adfe7e8…` 精确加入这两个 call 名称。

GHSA-PV2J 的一方说明主动区分它与 GHSA-4MR5：前者绕过整个 blocklist 的 C-level resolver，后者是直接 `print.__self__`/`vars` object-graph path。共享 defense surface 和 commit 不足以合并两个输入/解析机制；本批也不声称 `179cab02…` 只服务于这一条 hunk。

### F08–F18：一方 advisory 与 commit 主题都明确指向未完成的安全收紧

- F08：`8e41c118…` 标题即 “block side-effecting command wrappers [AI]”，但 durable allow-always 仍绑定 wrapper；`55d1324c…` 解包 `flock` 后绑定真实命令。
- F09：`3cc8b2a3…` 验证 bind source 为绝对路径；runtime policy 仍允许一个已允许 parent 覆盖 denied descendant；`a90eb934…` 在最终 mount set 上做 ancestor/descendant policy check。
- F10：`3d93174c…` 给 interaction 本身加 navigation checks；existing-session act route 仍可在 action 前位于 private current tab；`78f3985c…` 增加 route-entry current-tab guard。
- F11：`b75ad800…` 扩展 snapshot/screenshot/tab SSRF policy；current-tab snapshot path 仍缺 read 前 validation；`06047005…` 补该 pre-snapshot gate。
- F12：`1c85eff9…` 给 node device-token management 加 admin scope，却没覆盖 `device.pair.approve`；`517ce3df…` 把 approve 纳入同一 role-management gate。
- F13：`0e702f10…` 收窄未绑定 WebSocket scopes，但 trusted-proxy Control UI 仍可在 pairing 前提交 proxy scopes；`96fba91b…` 强制 pairing/baseline binding。
- F14：`47eb2d48…` 对 Streamable HTTP redirect 跨 origin 清 Authorization；SSE transport 仍走未保护 redirect；`3c6259eb…` 将 guard 接到共享 MCP fetch/两种 transport。
- F15：`17ceca86…` 广泛加入 persisted-secret redaction 并创建 trajectory runtime；export bundle walker 仍可输出未统一清洗的 credential-shaped values；`19fb9f12…` 对每个 exported file/object 应用统一 redactor。
- F16：`6c918ca8…` 让 delegated session 继承 tool restrictions，并触及中央 dispatch；ClickClack reply adapter 未携带 `toolsAllow`；`797bcd5b…` 将约束贯穿 provider/reply dispatch。
- F17：`6e498a1f…` 给 QQBot approval callback 加 sender authorization，但保留同 chat fallback；`08a73dbe…` 用 command-auth/allowlist 结果替代该 fallback。
- F18：`e0b8ddc1…` 给 pressKey 与 type-submit 加 before/after/settled 三阶段 URL guard；select/fill/evaluate 等 navigation-capable acts 仍漏检；`3d93174c…` 扩大 interaction coverage。

每一条 candidate 都在上表的 vulnerable witness tag 中，且对应 final fix 不在该 tag；final fix 首次进入右侧 fixed tag。故没有把“partial 与 final 同版落地”的 commit-only 行伪装成发布级行。

## 组件粒度、去重与计数边界

组件键采用 `(repository, public identity set, attacker input, security sink, violated invariant, exact closure)`。以下信号只作 routing，不能单独拆分组件：不同 GHSA、不同 CWE、相同大提交中的不同文件、相同 fix SHA、相同 release range。

本批的有意 SHA 复用关系是：

| SHA | 关系 | 为什么没有按 SHA 合并 |
|---|---|---|
| `0ea20d01…` | F02 与 F03 的共同 origin member | role labels 与 member URL/attribute 是不同 attacker-controlled fields、DOM contexts 和 closure lines |
| `5631bb08…` | F03 与 F04 的共同 final member | group member table 与跨页面 shared person action renderer 是不同 sink families |
| `cbea916e…` | F01 closure / F05 partial | 前者恢复 gate，后者只描述恢复后 bad-OTP counter residual；前后相邻而非重复计数同一状态 |
| `179cab02…` | 旧账本多 hunk + F07 partial | F07 advisory 明确限定 C-level `format` resolver；不复用旧 SSRF/JWT/直接 AST-attribute机制 |
| `3d93174c…` | F18 closure / F10 partial | F18 是 action 后导航检查覆盖；F10 是 route 进入时 current-tab preflight |

Public IDs 在 frozen strict ledger、Batch 2 unified snapshot ledger 以及现有 post-strict 报告中均无重复；唯一文本命中是 `179cab02…` 的多 hunk历史，已在上表收窄。Public-ID 零交集并不证明组件独立，故最终仍需 unified mechanism fingerprint verifier。

## 方法与可重放检查

证据只使用一方 Git history/tag、repository security advisory API 和现有 frozen ledger。未把 OSV `introduced`、模型判断、commit message、ancestry 或测试单独当因果证明。

代表性重放命令如下；所有 shared clones 均以只读 Git 配置访问：

```zsh
church=/home/hanqing/.cache/cve-analyzer/repos/churchcrm_crm
praison=/home/hanqing/.cache/cve-analyzer/repos/github.com_mervinpraison_praisonai
openclaw=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw

# Direct member metadata and parent delta.
git -c gc.auto=0 -c maintenance.auto=false -C "$church" \
  show -s --format=fuller f9afc3c5 0ea20d01 6ef78813 095bf81b cbea916e
git -c gc.auto=0 -c maintenance.auto=false -C "$church" \
  show f9afc3c5 -- src/api/routes/public/public-user.php
git -c gc.auto=0 -c maintenance.auto=false -C "$praison" \
  show 179cab02 2adfe7e8 -- \
  src/praisonai-agents/praisonaiagents/tools/python_tools.py

# Released candidate-only witnesses: each candidate/carrier must be in the
# vulnerable tag, exact closure absent, and closure present in fixed tag.
git -c gc.auto=0 -c maintenance.auto=false -C "$church" \
  merge-base --is-ancestor 18b211535fec3b09d1ab613af923e28080605101 7.2.0
! git -c gc.auto=0 -c maintenance.auto=false -C "$church" \
  merge-base --is-ancestor 1bfc187ac41238a2488d58f06361d7377d3cdf11 7.2.2
git -c gc.auto=0 -c maintenance.auto=false -C "$church" \
  merge-base --is-ancestor 1bfc187ac41238a2488d58f06361d7377d3cdf11 7.3.1

git -c gc.auto=0 -c maintenance.auto=false -C "$openclaw" \
  merge-base --is-ancestor e0b8ddc1a55185aff1cf9e0e095014d2e4f1d894 v2026.5.12
! git -c gc.auto=0 -c maintenance.auto=false -C "$openclaw" \
  merge-base --is-ancestor 3d93174c4398088066a1de9372ea1103cd713df1 v2026.5.12
git -c gc.auto=0 -c maintenance.auto=false -C "$openclaw" \
  merge-base --is-ancestor 3d93174c4398088066a1de9372ea1103cd713df1 v2026.5.18

# First-party advisory status; gh uses existing auth without printing it.
gh api repos/ChurchCRM/CRM/security-advisories/GHSA-cwp8-rm8g-q5c9 \
  --jq '{ghsa_id,cve_id,state,published_at,withdrawn_at,vulnerabilities}'
gh api repos/openclaw/openclaw/security-advisories/GHSA-2hfg-4fh4-qp7f \
  --jq '{ghsa_id,cve_id,state,published_at,withdrawn_at,vulnerabilities}'

# Frozen-ledger public-ID and candidate collision screen.
rg -i 'CVE-2026-44547|GHSA-CWP8-RM8G-Q5C9|GHSA-2HFG-4FH4-QP7F' \
  research/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
  research/herdr-260812-b2-unified-ledger/ledger.jsonl
```

批量重放结果：18/18 candidate/carrier 均被各自 vulnerable witness 包含；18/18 exact closure 均不在该 witness；18/18 closure 均被 fixed witness 包含。18/18 repository advisories 当前均 `published` 且 `withdrawn_at=null`；其中的 CVE/GHSA 映射合计为 21 个 public IDs。

## 局限、稳健性与当前 hold

- 本批验证的是 source/tag containment，没有安装 18 个历史版本或重跑 exploit。测试与 advisory PoC 只作支持证据。
- ChurchCRM 的 atomic member 与 squash carrier 分开记录；carrier 只证明发布 topology，不替代 member-level AI/hunk 归因。
- PraisonAI 一方 advisory 使用 `praisonaiagents 1.6.x` package range，本地 monorepo release witness 使用 `v4.6.x` repo tag；两套版本名必须同时保留，不能伪装成数值一致。
- OpenClaw 11 条当前是 GHSA-only；它们是真实一方 public identities，但不是 11 个 CVE，也不能用来增加 CVE 数。
- Batch 2 snapshot unified ledger 尚未采纳本批，且只对 74 个 post-strict rows 中的 20 个做过 adversarial causal-control sampling。其 `125/172/184` 是 source envelopes，不是确认总数；负控后的 `<=168/<=180` 也只是一项保守投影。现阶段总数继续 hold。

## 下一步

1. 把 F01–F18 以一行一机制写入下一版 unified ledger，并保存上述五组 SHA 复用关系。
2. 对 18 行做独立负控：至少检查 direct parent、candidate 删除后的风险方向、same-mechanism closure 与 candidate-only release。
3. 与正在进行的 OpenClaw sanitizer residual 审计合并后，再跑 public-ID alias、mechanism fingerprint、release containment 与 conservation verifier。
4. 只有 verifier 对最终 canonical ledger 给出 `integration_ready=true` 且 canonical released components 达到 200，才更新总报告。

## 仍需回答的问题

- OpenClaw host-environment 后续 advisories 中，哪些是 `3affd5e8…` 同一安全边界的独立 residual，哪些只是后来新增的 provider/tool surface？
- Batch 2 alias-QA 的六个 UNKNOWN 是否会继续降低旧基线？
- F07 与旧 PraisonAI sandbox row 的机制 fingerprint 能否在统一 ledger 中稳定表达“同 defense surface、不同 parser path”，避免未来被仅按文件/SHA 合并？

在这些问题闭合前，本报告只提供 18 条行级提案，不发布新总数。
