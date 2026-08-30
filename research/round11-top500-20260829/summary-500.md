# Round11 Top-500 总结

生成于 2026-08-30。本文总结已完成二审 reconciliation 并落入 canonical ledger 的最终状态。

## 结论

500 份 primary 已全部完成并通过结构校验：500 个唯一 class，无缺失、无重复、无 Round10 重叠。当前 canonical verdict 为：

| Verdict | 数量 | 占 500 比例 | 解释 |
|---|---:|---:|---|
| `NOT_AI` | 477 | 95.4% | 终局非 TP |
| `AI_ROOT_CAUSE` | 9 | 1.8% | AI 因果 TP |
| `AI_CODE_FLAWED` | 1 | 0.2% | AI 代码有缺陷 |
| `FALSE_POSITIVE` | 7 | 1.4% | 漏洞或受影响发布主张不成立 |
| `EVIDENCE_GAP` | 6 | 1.2% | 证据边界尚未闭合 |

因此：

- AI TP：10/500（2.0%）。
- 终局非 TP：484/500（96.8%）。
- 尚未闭合：6/500（1.2%）。

这 2.0% 只描述这批按 TP-likelihood 排序的 remaining-open 样本，不是全部 advisory 的总体发生率。

## 10 个 AI TP

| Verdict | Repo | Advisory |
|---|---|---|
| `AI_ROOT_CAUSE` | jahlives/openssl_encrypt | GHSA-723w-crw6-p9hx |
| `AI_CODE_FLAWED` | n8n-io/n8n | GHSA-2664-hr5v-554w |
| `AI_ROOT_CAUSE` | jahlives/openssl_encrypt | GHSA-c7vw-vfxj-3mvh |
| `AI_ROOT_CAUSE` | n8n-io/n8n | GHSA-h5rm-9fhh-5phj |
| `AI_ROOT_CAUSE` | jahlives/openssl_encrypt | GHSA-gvq9-cmxr-844m |
| `AI_ROOT_CAUSE` | lin-snow/ech0 | GHSA-q8hh-m6v5-4f3x |
| `AI_ROOT_CAUSE` | thorsten/phpmyfaq | GHSA-jj45-w38g-gfrj |
| `AI_ROOT_CAUSE` | vllm-project/vllm | GHSA-hw36-j4q7-vjxx |
| `AI_ROOT_CAUSE` | cloudflare/workers-oauth-provider | GHSA-qgp8-v765-qxx9 |
| `AI_ROOT_CAUSE` | cloudflare/workers-oauth-provider | GHSA-4pc9-x2fx-p7vj |

主要信号不是“仓库里出现过 AI commit”，而是 advisory mechanism、source-to-sink、原子 introducer、direct fix 与因果 AI marker 同时闭合。仅有 PR 标签、changelog、`Co-Authored-By` 或仓库级 AI 活动不够。

## 二审覆盖与已落地纠错

500 个 case 现在都有独立二审：原始批次 389 个，后来 Grok 二审 111 个。

原始 389 二审的历史结果为 `CONFIRMED` 280、`CORRECTION_REQUIRED` 94、`EVIDENCE_GAP` 15。其中 33 个争议 case 已重新研究并完成 canonical reconciliation：

- 18 个 `CORRECTION_REQUIRED`
- 7 个 field erratum
- 6 个确认无需 canonical 修改
- 2 个 `EVIDENCE_GAP`
- 合计 27 个 primary 有字段变化，其中 8 个发生 verdict flip

当前 477/9/1/7/6 histogram 已包含这些修改。

## Grok 后 111 二审：当前状态

物理文件、schema、identity 与 frozen hash 均完整：111/111。Grok 的 review histogram 是：

- `CONFIRMED` 92
- `CORRECTION_REQUIRED` 17
- `EVIDENCE_GAP` 2
- 没有提出任何 AI TP flip

这 111 份二审已经完成 substantive reconciliation：

1. 接受 w350：`NOT_AI → EVIDENCE_GAP`。
2. 接受 w434：`EVIDENCE_GAP → NOT_AI`。
3. 拒绝 w440：保留 `FALSE_POSITIVE`；发布拓扑仍支持该结论。
4. w454 保留证据缺口；w496 保留 fixed-release caveat。
5. 16 份字段纠错和 7 个缺失 `ai_marker` 已按统一字段语义写回 canonical primary。

## 最终状态判断

- primary 数据集：完成。
- 500/500 独立二审覆盖：完成。
- 原始 33 个争议项的 canonical reconciliation：完成。
- Grok-111 的 substantive reconciliation：完成（25 份 reconciliation 记录）。
- ledger 落地：完成；500 份 assessment 通过单一 change set 写入 Neon，并导出为本地 canonical JSONL。
- 发布门禁：完成；260 份发布记录通过 preflight、advisory-link、identity 与完整 Next.js build/test。

所以这 500 个可以概括为：**审计、独立二审、争议复核、canonical 落账和发布门禁均已完成；最终为 10 个 AI TP、484 个终局非 TP、6 个证据缺口。证据缺口按协议保留为 `PARTIALLY_ANALYZED`，没有强行闭合。**

## 落账与发布凭据

- scan run：`a5427fbc-7520-575e-be07-b56ecfdc51d0`
- change set：`829910c2-b608-4125-ac18-54b21357358b`
- canonical export sha256：`cb2d41daa464c00f81a59e46c9810273c352a60c8397d19828f5fb5d0c2be617`
- 500/500 数据库行与 landing plan 一致；本地 JSONL 与数据库导出一致。

## 来源

- `research/round11-top500-20260829/records.jsonl`
- `research/round11-top500-20260829/coverage.json`
- `research/round11-top500-20260829/report.md`
- `research/round11-top500-20260829/disagreement-rereview/report.md`
- `research/round11-top500-20260829/independent-review-111/report.md`
- `research/round11-top500-20260829/review-111-reconciliation.jsonl`
- `research/round11-top500-20260829/ledger-landing-result.json`
