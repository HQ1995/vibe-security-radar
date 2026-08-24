# Work state checkpoint — 2026-08-18 (updated after squash-audit)

## 核心原则（最高优先级）
每个漏洞先理解明白 -> 分析成因（谁在哪个 commit 写了缺陷行）-> 再判 AI 角色。
禁止机械 gate 翻转；判定必须带三件套证据：候选文件清单、成因 commit
作者+marker、fix 文件清单。

## Canonical book
artifacts/funnel-account-20260817.jsonl（23,868 类，一行一类，状态用
自解释英文代码）。

## 当前桶（2026-08-18）
AI_ROOT_CAUSE 133 | AI_CODE_FLAWED 11 | NOT_AI 2,013 | BLOCKED 1 |
PARTIALLY_ANALYZED 4,280 | UNANALYZED 17,430 -> TP = 144

## 已完成的战役
- narrow70（70 条）：理解式裁决 + grok4.6/gemini 双重评审 + 政策裁决框架
- legacy87（87 条）：gemini-3.7-flash 重审 + 全员三件套补验；59 条误报翻案
- blocked535 复活（535 条）：11 条翻出真 TP，其余 NOT_AI
- blocked106（106 条）：104 NOT_AI + 1 复核后翻回 NOT_AI + 1 闭源 BLOCKED
- squash-audit（182 条 TP 全量拆解）：171 条审计完，133 CONFIRM / 38 OVERTURN
  -> TP 182 -> 144；52 条 squash 拆解到写缺陷行的 commit，全部记录
- chromium 旁账：214 条记录 / 21 仓库（artifacts/chromium-ai-scan-20260817.jsonl）

## 裁决框架（已沉淀）
1. AI 直接写缺陷行（含照抄惯例）-> AI_ROOT_CAUSE / AI_CODE_FLAWED
2. 触发路径必查 introduced 版本 vs AI commit（之前 live = 无关/有缺陷；首次 live = 根源）
3. 删防线/弱化 -> AI_ROOT_CAUSE
4. 激活休眠漏洞（enablement）-> AI_ROOT_CAUSE
5. 新面暴露旧缺陷 -> AI_CODE_FLAWED
6. 人类在 AI 代码之后引入缺陷 -> NOT_AI
7. co-authored/assisted-by = AI 写的，不讨论主笔

## 下一步（按顺序）
1. 4,280 PARTIALLY_ANALYZED 补成因分析（已找回 fix 的 2,976 优先）
2. 17,430 UNANALYZED 按仓库分片主攻
3. 45,374 无仓库类：GHSA 确定性仓库匹配（下一大矿）
