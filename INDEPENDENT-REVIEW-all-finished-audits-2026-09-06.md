# 独立复核报告 — all-finished-audits.zip

复核日期 2026-09-06 复核人 hanqing 依据 docs/AUDIT-PROTOCOL.md

## 范围与实际覆盖

- 档案: /home/hanqing/all-finished-audits.zip -> 447 条 unique class_id
- 判定: NOT_AI 410 | AI_ROOT_CAUSE 21 | AI_CODE_FLAWED 2 | FALSE_POSITIVE 7 | EVIDENCE_GAP 7
- 本地克隆 18 个仓库逐条 git 验证; OSV/cveawg 状态在沙箱网络切换前抓取, 之后网络不可达(标签级核对受限, 有本地 pickaxe/HEAD 证据支撑)

## 23 个 AI TP 逐一判定 (主要证据为 clone 内 git)

- CVE-2026-19744 ccyl13/pentestify 准确: BIC e421fcc 引入 markdownToHtml(父无), Claude Sonnet 4.6 标记; fix 272f7d6 加引号转义
- CVE-2026-74896 openssl 准确: BIC 50bec5d 新建 plugin_ast_analyzer.py 与 DangerousPatternVisitor(父无); fix 993cd13 加 dunder 检测; OSV fixed=768df5cd 为 docs 提交
- GHSA-pfvm-w89x-94jw sipsorcery 准确: BIC dd767827 新建 TurnServer.cs(1096 行, 父无), Claude Opus 4.6; fix ccb0b5a per-datagram try/log-and-continue
- CVE-2026-74880 openssl 准确(INCOMPLETE_REMEDIATION): fix 4b2adb05 仅改 telemetry/routes.py; v1.4.0 keyserver 仍 refresh_token Query, 修复不完整成立
- CVE-2026-74892 openssl 准确: BIC 4c7ae852 首写 CHANGE_THIS_IN_PRODUCTION(pickaxe, 父无), fix 9982c0c9 移除硬编码密钥
- CVE-2026-74891 openssl 准确: 同 BIC 首写默认 DB URL; fix 57e618d 移除
- CVE-2026-77759 prospero-flow-crm 准确: BIC e3c6897d CRUD, Claude Haiku 4.5; fix 980c35a IDOR 保护+权限检查
- CVE-2026-76220 GitPython 准确: BIC e8d0fbf7 author=GPT 5.6 codex@openai.com, 含 agent 标记; fix 96a888f 校验 joined options
- CVE-2026-73560 vllm 准确: BIC c245d35f 新建 mimo_v2_omni.py(父无), Claude Opus 4.6+Copilot; fix 54503ec 改走 MediaConnector
- CVE-2026-32031 openclaw 有条件准确(AI_CODE_FLAWED 自标 medium): fixes da0ba1/0ed675/258d61 均在; AI 标记仅 staged-fix-workflow 文字
- CVE-2026-73155/73162/72760 cti-transmute 准确: BIC 4fa058f 为 react/toggle_reaction/get_following/GET-mutators 首写(父无); fixes a18c07c/c352c23/4bad9f1 均存在且机制吻合
- CVE-2026-67530 wacrm 准确: BIC b7b362ae automations engine 首写, Claude Opus 4.7; fix 7d1ddbf SSRF guard + merge 23838a9
- CVE-2026-34507 openclaw 准确: BIC 5e72e39 Made-with Cursor; fix 62fb876 统一 auth
- CVE-2026-72769/77085 n8n 准确: BIC 0ed9f35(IsolatedVmBridge, Claude)/b415544(Cursor); fixes 2222fe3 f69dfc6 ff05cd3 / ca3d42d 均存在
- CVE-2026-74875 openssl 准确: BIC a3d7f41 首写含 fail-open(print+return) 的 validate_against_schema; fix 6e7f938 改为 raise
- CVE-2026-74889 openssl 准确: BIC 1dfb5f15 HKDF salt=None; fix c2692d7 加随机 salt
- CVE-2026-74870 openssl 准确: BIC 058df1 新建 FIDO2 CLI; fix 35c4dd5 停止打印 pepper
- CVE-2026-74874 openssl 准确: BIC 5f60678 首写 stego 随机选择; fix 09e96e0 换 HMAC-SHA256 CSPRNG
- CVE-2026-74882 openssl 准确: BIC f6f2e48 Integrity RFC1918 默认 trusted_proxies; fix 746ad01 收窄到 localhost; 父 9872c84(Pepper) 为复制源而非 move
- CVE-2026-73299 microsoft/prompty 准确: BIC a0e61088 新建 nunjucks.ts, Copilot co-author, 父无; fixes e4a0ebf/f5c57c94 限制模板执行

## FALSE_POSITIVE (7)

- 权威撤销类(cveawg REJECTED, 复核通过):
  - CVE-2026-72540 photoprism REJECTED 2026-08-17
  - CVE-2026-1518 keycloak REJECTED 2026-07-24
  - CVE-2026-3260 undertow REJECTED 2026-07-07
- 机制分析类(CVE.org 仍 PUBLISHED, 逐条再验证成立):
  - CVE-2026-36341 krayin: OSV fixed 68140c0 为 CHANGELOG merge(PR #2410), 无关 comment 渲染; DOMPurify/v-safe-html 早于 4848b68a(2024-11) 已就位, affected/fixed 配对错误, FP 成立
  - CVE-2023-53957 kimai: cookie_samesite: lax 由 84e25851(2021-10-07)引入且 HEAD 仍生效; EDB 利用为同源 webroot 文件写入, 非 SameSite 缺失, FP 成立
  - CVE-2026-39890 praisonai: 仓库内无 js-yaml 实际使用(仅一段迁移安全注释), 无 loadAgentFromFile; fix b1048da6 为通用加固, 构造不存在, FP 成立
  - CVE-2026-74887 openssl: BIC 5e310448 仅新增孤立 import random; HEAD pqc.py 无 random.* 调用点(仅注释提及 nonce), CWE-338 机制不存在, FP 成立

## EVIDENCE_GAP (7)

全部 7 条(openclaw CVE-2026-53857/CVE-2026-32035、wso2/docs-security CVE-2024-7096、bagisto CVE-2025-62417/CVE-2025-60880、magento CVE-2025-49556/CVE-2025-47110) 均明确声明未定位 BIC 链/缺父代/OSV 发布标记不可当 BIC, 未臆造 NOT_AI —— 符合协议缺失事实保持显式 gap 原则, 处理质量高。

## NOT_AI 中 bic.ai_on_bic=True 的 5 条(逐一排除误报)

- gitea CVE-2026-58508: BIC 2020 人工 maintainer squash(6543), co-author lunny/zeripath/techknowlogick 均人工; AI 标记只在 2026 修复 PR, 审计正确忽略 → NOT_AI 正确
- vllm CVE-2026-73558: BIC 人工 kernel squash(Дзержинский), gemini-code-assist 仅为 reviewer → NOT_AI 正确
- traefik CVE-2026-44774: BIC 人工 jbdoumenjou, AI 仅修复侧 → NOT_AI 正确
- n8n CVE-2026-21858: BIC 人工 n8n 员工(Michael Kret), 修复来自 fork 无声合并 → NOT_AI 正确
- n8n CVE-2026-77071: BIC 人工(RicardoE105), 创始人 co-author → NOT_AI 正确

## 标注级小问题 (不影响主判定)

1. CVE-2026-73155 status=AI_ROOT_CAUSE 但 contribution_class=AI_INCOMPLETE_REMEDIATION, 其 causality 自述新功能面非 incomplete — 类别字段内部矛盾(建议修正为 AI_DIRECT_ROOT 或统一说明)
2. CVE-2026-74880 bic.ai_on_bic=None 为保守处理, 可接受
3. traefik CVE-2026-44774 单记录同时存在 EVIDENCE_GAP 与 NOT_AI 两审计员票并取 NOT_AI(0.84), reconcile_notes 为空, 建议记录分歧
4. 3 条 PUBLISHED 类 FP 依赖机制分析而非 CVE.org 撤销 — 不违反协议(权威撤销仅对已撤销 CVE 是唯一路径; 对未撤销但机制错误的 CVE, 机制证明是可接受的 FP 依据), 但公开发布建议标 provisional
5. 其余 NOT_AI 大量存在 bic.sha 与 fix.sha (举例 pentestify 636fb984、openssl 各 BIC) 与本地 git 一致, 未见幻觉 SHA

## 结论

复核未发现会翻转结论的事实错误。23 个 AI TP 的 BIC 归属、first-write、fix 闭合均与克隆内 git primary evidence 一致; 7 个 FP 中 3 个有 cveawg REJECTED 背书, 4 个机制分析经我再验证成立; EVIDENCE_GAP 处理严格合规; NOT_AI 中 BIC 带 AI 标记的潜在误报已逐一排除。整体判定: 该批次审计准确、可信, 仅有少量标注级瑕疵与 1 处类别字段内部不一致, 不影响数据可用性。

限制说明: 复核依赖本地克隆与网络切换前抓取的 OSV/cveawg 状态; 切换后网络不可达, kimai 1.30.10 标签内容与 praisonai 上游 tag 未在线复核(有本地 pickaxe/HEAD 证据支撑)。审计来源文件(/home/box/...)不存在于本机, 无法逐一比对原始 markdown; schema.jsonl 与 MEGA.md 内部一致(447 条、verdict 分布、审计员计数吻合)。

