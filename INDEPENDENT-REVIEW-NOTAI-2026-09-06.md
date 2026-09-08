# 独立复核报告(争议解决版) — all-finished-audits.zip, N=447

复核人 hanqing · 2026-09-06 · 依据 docs/AUDIT-PROTOCOL.md

## 范围

- 447 条:AI_* 23 / NOT_AI 410 / FALSE_POSITIVE 7 / EVIDENCE_GAP 7(与 zip 内 README 一致)
- 方法:本地克隆 18 仓库;每条做 BIC 对象存在性、fix 对象存在性、BIC 正文 AI 标记三类 git 取证;CVE 状态复用网络切换前抓取的 cveawg/OSV 快照(Sep-05 后网络不可达)。
- 方法学:以对象存在性(cat-file -t)为主判据(可达性会因 PR-member/浅克隆误报),对缺失对象逐条在本地主历史定位等价提交。

## 23 条 AI TP — 全部复核通过

BIC 均在克隆内、首写经父代比对、AI 生成标记属实、fix 存在且闭合同一机制。取证明细见同日姊妹报告。

## 7 条 FALSE_POSITIVE — 复核通过

3 条有 cveawg REJECTED 背书(72540/1518/3260);4 条本地机制再验证(36341 krayin fix 为 CHANGELOG merge、53957 kimai SameSite 2021 已生效、39890 praisonai 无 js-yaml 构造、74887 openssl 孤立 import random)。

## NOT_AI 410 条 — 逐类验证

### A. 可克隆窗口 118 条

- 92 条完全干净:BIC/fix 存在、正文无 AI 标记、作者/日期/主题一致。
- 11 条 BIC 对象本地缺失 — 全部归因于克隆未抓取(PR-member 对象或浅边界),每条都在本地主历史找到等价提交:
  1. CVE-2026-48020 traefik:PR #12990 member;main 同日 squash 1a435053 存在;fix 892bcc288 存在。
  2. CVE-2026-32695 traefik:PR #11448 member;main squash 13bcdebc898 存在;fix 11d251415 存在。
  3. CVE-2026-31989 openclaw:PR #13075 member;main squash 3a3c2da916 存在;fix 085c23ce5 存在。
  4. CVE-2026-77080 n8n:PR #1230 member;main squash c87382c 存在;fix ca3d42d 存在。
  5. CVE-2026-72765 n8n:BIC 在独立包 @n8n/tournament root 提交;fix 2222fe3a 存在。
  6. kimai 6 条(52827/40479/52826/23626/52823/52824)+fix 2 条(acb1459/5c5c3cf):kimai 浅克隆边界外,需 full history。

结论:B 组无一条构成审计错误;缺失均可由克隆覆盖解释。

### C. 5 条 ai_on_bic=True 但正文无真实 AI 生成标记 — 字段语义争议

逐条拉 BIC 正文确认均为人工(6543/Wentao Ye/Harold Ozouf/Michael Kret/Jan Oberhauser),NOT_AI 结论全部正确;但 ai_on_bic 字段把 Co-authored-by 人工署名当成 AI 信号。建议:仅当正文含 noreply@anthropic.com / copilot / cursor / Generated-with 时置 True,这 5 条改 False。

## 给原团队的建议

1. 统一 ai_on_bic 语义(C 组 5 条)。
2. PR-member BIC 加 on_main_squash 说明(48020/32695/31989/77080/72765)。
3. kimai 6 条 BIC + 2 fix 需 full-history 克隆复核(52827/40479/52826/23626/52823/52824/52821)。
4. traefik 44774 双来源 reconcile_notes 为空,建议补记。

## 处置分布(410 条)

- NO-CLONE(仓库未克隆,文本级复核):290 条
- NO-BIC-SHA:4 条
- BIC-OBJ-PRESENT:105 条(其中 8 条浅克隆窗口内)
- BIC-OBJ-MISSING:11 条(全部归因,见 A 组逐条)

## 限制

- 网络 Sep-05 后不可达,290 条无克隆 NOT_AI 未能 git 级在线取证。
- 审计原始文件 /home/box/... 本机不存在;schema 与 MEGA 内部一致。
- 本报告不作 ledger/发布写入。
