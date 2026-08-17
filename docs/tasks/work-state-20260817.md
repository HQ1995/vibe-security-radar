# Work state checkpoint — 2026-08-17 (updated after narrow70 + legacy87)

## 核心原则（最高优先级）
每个漏洞先理解明白 -> 分析成因（谁在哪个 commit 写了缺陷行）-> 再判 AI 角色。
禁止机械 gate 翻转；判定必须带三件套证据：候选文件清单、成因 commit
作者+marker、fix 文件清单。

## Canonical book
artifacts/funnel-account-20260817.jsonl（23,868 类，一行一类，状态用
自解释英文代码）。旧账冻结于 649505a，工作区已移除。

## 当前桶
AI_ROOT_CAUSE 146 | AI_CODE_FLAWED 25 | NOT_AI 1,452 | BLOCKED 535 |
PARTIALLY_ANALYZED 4,280 | UNANALYZED 17,430 -> TP = 171

## 已完成的战役
- narrow70（70 条）：理解式裁决 + grok4.6/gemini 双重评审 + 政策裁决框架
  （docs/tasks/ai-pattern-methods-20260817.md）
- legacy87（87 条）：gemini-3.7-flash 重审 + 全员三件套补验；59 条启发式
  误报翻案，4 条 fix 目标验证后翻回 AI_CODE_FLAWED
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
1. 535 BLOCKED 复活（成因分析受阻的重试）
2. 4,280 PARTIALLY_ANALYZED 补成因分析
3. 17,430 UNANALYZED 按仓库分片主攻
4. 45,374 无仓库类：GHSA 确定性仓库匹配（下一大矿）
