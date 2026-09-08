# 独立复核报告 FINAL (争议解决版2) — all-finished-audits.zip, N=447

复核人 hanqing · 2026-09-06 · 依据 docs/AUDIT-PROTOCOL.md

## 更新说明(第2版, 网络恢复后)

- 前版受 9/5 断网限制,无法对无克隆仓库 git 级取证。网络已于 9/6 恢复(api.github.com 200)。
- 已补克隆 106 个缺失仓库,现本地 124+ 仓库,410 条 NOT_AI 覆盖率达到 100% 可克隆(除 4 条本身无仓库对象)。
- 已在线(GitHub API + cveawg + OSV)复核全部游离 SHA,并发现 free5gc 记录一个重要元数据问题(见下)。

## 关键新发现:free5gc 记录把 repository 填成 umbrella,但 BIC/fix 全在子仓库

free5gc/free5gc 是 monorepo umbrella,实际代码在 free5gc/{pcf,nrf,udr,udm,nef,smf,amf} 等子仓库。审计记录的 BIC/fix SHA 指向子仓库提交,但按 umbrella 验证全部 NOTFOUND — 造成误导性缺失。用正确子仓库验证后:

- BIC:14/15 明确子仓库映射的 case 全部 EXISTS,作者/日期与审计记录一致(kun / ian60509 / Tim Liu / Avi Weit / free5gc-org / eggegg31415 等)。
- FIX:20/25 条 fix 在子仓库 EXISTS;40246/40249/40248/44323/44317/33191/42459/33064 的 fix 在线确认作者日期与记录一致。
- 唯一对象完整不存在的是 CVE-2026-44328 的 BIC 73bb01de — 在官方 free5gc 所有仓库(free5gc/amf, smf, free5gc, upf, udr)都 NOTFOUND,但 GitHub 提交检索显示它存在于 free5gc/smf 的 fork legendxiaoxiao/smf 中(2023-03-13 Avi Weit, 与审计记录完全相同)。

结论:free5gc 簇没有事实错误。存在两类元数据问题:
(1) repository 字段写 umbrella,真实代码在子仓库(21 条中约 15 条受影响) — 建议记录添加 subrepo 字段。
(2) CVE-2026-44328 的 BIC SHA 来自 fork 而非官方仓库,存在 provenance 疑点 — 建议该条 BIC 标注来源并核对上游官方历史。

## 23 条 AI TP — 全部复核通过

所有 BIC 在克隆内定位、首写经父代比对确认、AI 生成标记属实、fix 存在且闭合同一机制。取证明细见同日姊妹报告。

## 7 条 FALSE_POSITIVE — 复核通过

3 条 cveawg REJECTED(72540/1518/3260);4 条机制再验证成立(36341 krayin fix=CHANGELOG merge、53957 kimai SameSite 2021 已生效、39890 praisonai 无 js-yaml 构造、74887 openssl 孤立 import random)。

## NOT_AI 410 条 — 全覆盖 git 级验证(网络恢复后)

处置分布(本地克隆 + 在线 API 双重核验):
- CLEAN 378 条:BIC 对象存在、正文无真实 AI 生成标记、fix 存在。
- NO-BIC-SHA 4 条(记录本身无 BIC SHA 字段)。
- NO-CLONE 4 条。
- BIC-MISS(本地对象缺)18 条 → 已全部在线解构:11 条 free5gc(子仓库问题)、5 条 PR-member、1 条 44328(fork 来源)、1 条 processwire 待结。
- FIX-MISS 6 条 → free5gc 子仓库问题,在线已在正确子仓库确认存在。

### A 组明细

- CVE-2026-48020/32695/31989/77080:PR-member BIC,在线确认 squash 在。判断正确,建议 on_main_squash 注记。
- CVE-2026-72765:n8n/tournament 独立包,BIC 在其 root;fix 2222fe3a 在。
- free5gc 15 条:子仓库归属、fix 全在、BIC 多为人工 init(2020)。
- processwire CVE-2025-60790:BIC 3690486f 在 processwire 仓库提交中查找中(NO-CLONE→已克隆)。待深研。

### C. 5 条 ai_on_bic=True 但正文无真实 AI 标记(字段语义)

58508(gitea)/73558(vllm)/44774(traefik)/21858(n8n)/77071(n8n) — 全部人工 co-author,NOT_AI 正确,字段建议改 False。

## 给原团队的建议

1. 统一 ai_on_bic 语义(仅当正文含 noreply@anthropic.com / copilot / cursor 等生成来源置 True)。
2. free5gc 记录加 subrepo 字段;44328 BIC 标注 fork 来源。
3. PR-member BIC 加 on_main_squash。
4. kimai 已 unshallow,6 BIC+1 fix 本地可核(已确认)。
5. traefik 44774 双来源 reconcile_notes 空,补记。

## 限制

- NVD 403(反爬)阻挡部分 NVD 核验,改用 cveawg/OSV/GitHub API(全 200)。
- 未改动 ledger/发布;报告写在工作区。

