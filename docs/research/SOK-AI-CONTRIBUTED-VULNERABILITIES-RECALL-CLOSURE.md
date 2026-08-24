# AI-Contributed CVE/GHSA SoK：Recall Closure 审计

Status: RECALL_UNESTABLISHED  
Pipeline complete: **false**  
研究窗口：2025-05-01 至 2026-08-09（UTC）  
总体单位：CVE/GHSA alias class

> 本报告取代 `research/orchestrator-260809-1127` 的 `CONVERGED` 结论。旧结论只证明既有工件生成完毕，未证明候选总体被覆盖、阻塞项被界定或召回率达到停止阈值。本轮只研究已经公开编号漏洞的 advisory、patch 与历史，不进行新漏洞挖掘。

## 1. 可证伪的结束条件

只有独立验证器同时通过以下门，才可写 `recall_status=ESTABLISHED`：

1. 冻结总体的 84,798 个 alias class 均有唯一 ledger 行、lane hits 和 disposition；
2. forward campaign 与 coverage 完成，blocked fix roots 清零；
3. 5,789 个缺日期记录被消除或给出可验证的漏报上界；
4. 所有模型 `HIGH` 候选完成逐例因果裁决；
5. 冻结分层抽样 354 行全部人工裁决；
6. 至少 59 个独立 fresh positive repositories 零漏报，使单侧 95% recall 下界超过 0.95；
7. 连续两个冻结扩展轮次新增 verified alias class 为 0。

模型、SZZ、文件重叠和排序分数只决定先看谁，**永远不删除候选**；`BLOCKED` 与未审记录都是 unknown，不是 negative。

## 2. 冻结总体 ledger

| 项目 | 结果 |
|---|---:|
| 冻结 alias classes | 84,798 |
| eligible official records | 159,714 |
| 缺日期、仍阻塞的 official records | 5,789 |
| 旧 strict verified classes | 40 |
| 本轮新增 verified classes | 1 |
| 当前可审计 lower-bound corpus | **41** |
| explicit-ID AI commit matches | 2,262 commits / 1,036 classes |
| 冻结 stratified audit sample | 354（6 strata × 59，全部 pending） |

初始 disposition（ledger 在本轮裁决前冻结，新增结果通过 overlay 表达，避免事后改变抽样框）：

| Disposition | Classes |
|---|---:|
| `VERIFIED_POSITIVE` | 40 |
| `AUDITED_NEGATIVE` | 38 |
| `AUDITED_INCONCLUSIVE` | 3 |
| `RANKED_NEEDS_ADJUDICATION` | 352 |
| `EXPLICIT_ID_NEEDS_ADJUDICATION` | 1,036 |
| `FORWARD_NEEDS_ADJUDICATION` | 4,950 |
| `BLOCKED_HISTORY` | 2,947 |
| `REPOSITORY_FALLBACK_ONLY` | 671 |
| `NO_OBSERVABLE_SIGNAL` | 74,693 |
| `TERM_SCREENED_NONORIGIN` | 62 |
| `SCOPE_EXCLUDED` | 6 |

工件：[population ledger](../research/orchestrator-260809-1305/population-ledger.jsonl)、[summary](../research/orchestrator-260809-1305/population-ledger-summary.json)、[explicit-ID matches](../research/orchestrator-260809-1305/explicit-id-ai-commit-matches.jsonl)、[audit sample](../research/orchestrator-260809-1305/audit-sample.jsonl)。

## 3. DeepSeek 排序轮次与人工裁决

按照用户指定，优先使用 `deepseek-v4-flash`，OpenAI-compatible endpoint 为 `http://127.0.0.1:8317/v1`。最终单 worker 重跑完成 47 次成功调用，覆盖全部 270 个 resolved single-edge candidates：

| 模型优先级 | Edges |
|---|---:|
| HIGH | 8 |
| MEDIUM | 21 |
| LOW | 241 |

第一次并发运行在第 6 batch 遇到 HTTP 503；降为单 worker 后完整退出 0。失败运行首 batch 记录 4 个 HIGH，而稳定重跑为 3 个，因此额外保留并人工审查 CrowdSec 的另一个 branch counterpart，未让排序波动删除它。模型回执和完整结果分别见 [receipt](../research/orchestrator-260809-1305/deepseek-ranked-receipt.json) 与 [screen](../research/orchestrator-260809-1305/deepseek-ranked-screen.json)。

### 3.1 所有最终 HIGH 均已逐例裁决

| Alias class / edge | 结论 | 关键 history boundary |
|---|---|---|
| NetLicensing / `e826d695 → fbbb1d5f` | NOT_AI_CAUSAL | 漏认证 middleware 由更早的人类 commit `81f799ac` 引入；AI-bound candidate 未改漏洞块 |
| Vitest / `af88b1f5 → 385a1aef` | NOT_AI_CAUSAL | CDP bridge 与受影响版本早于 candidate；candidate 添加其他 guard，但未改 CDP surface |
| agentapi / `33124c23 → 5c425c62` | NOT_AI_CAUSAL | candidate 只改 Codex 终端高度/消息格式；fix 才添加 Host/Origin guards |
| CrowdSec / `f9a9e9d5 → 57a79354` | NOT_AI_CAUSAL | candidate 未改 `pkg/appsec/request.go`；fix 重写其中旧的 Content-Length body reader |
| WorkOS / `9be02e9a → d5305316` | NOT_AI_CAUSAL | squash 中唯一 Copilot member 只改 docstring；漏洞 state 逻辑由人类 member `c6d7ae20` 写入 |
| WorkOS / `9be02e9a → f56e1d62` | NOT_AI_CAUSAL | 同一 alias class 的另一 fix-root 表示；member-level 结论相同 |
| Guzzle Services / `73d4e126 → 2edaddc4` | NOT_AI_CAUSAL | CDATA sink 起源于 2014 `fecd548c`；AI-bound candidate 只加 null guard |
| Rancher Fleet / `b6115302 → 9cc729f7` | **AI_CAUSAL, grade B** | grouped version boundary 混了三条 advisory；纠正到真实 fix `c967a3c1` 后，仅 CVE-2026-44937/GHSA-jmf4-m7j9-g72r 成立 |

额外保守审查的 CrowdSec `d8b922d5 → 3d5c4d9b` 也为 `NOT_AI_CAUSAL`。完整四合同（AI binding、Reachability、Violation、History Boundary）、证据路径与逐例理由见 [ranked adjudications](../research/orchestrator-260809-1305/ranked-adjudications.json)。

### 3.2 新增 strict case：Rancher Fleet

**编号：CVE-2026-44937 / GHSA-jmf4-m7j9-g72r；alias class `alias-72b82f9a2e737ed2c555363e`。**

- **AI binding：** `b6115302142d...` 的 Author 为 Copilot，并有 `copilot-swe-agent[bot]` attribution。
- **Reachability：** candidate 是修复 `c967a3c18463...` 的祖先，且位于受影响的 v0.13 分支；真实 patched tag 包括 `v0.13.11`。
- **Violation：** repository hostname/path 被直接拼进 regexp，使攻击者 webhook URL 匹配无关 repository。
- **History Boundary：** regex 构造早于 candidate，故不把 AI commit 说成首次引入者。该 commit 原子地把活动 path arm 改写为 `u.EscapedPath()` 并扩展 Azure URL handling，却继续把路径作为 regexp 语法；pre-fix blame 将该活动行归给 Copilot，安全 patch 随后把同一行替换为 `regexp.QuoteMeta(...)` 并锚定结尾。因此按既有 SoK 定义归为 **qualified indirect causal extension / vulnerable reimplementation，grade B**。
- **公开 patch differential：** 已知 disclosed patch 的最小重放输出为：

```text
candidate_regex_matches_unrelated_repo=true
patched_regex_matches_unrelated_repo=false
```

模型把 CVE-2026-44935、CVE-2026-44936、CVE-2026-44937 合在一个错误的 version-boundary root 上；只有 44937 的 `pkg/webhook/webhook.go` mechanism 被纳入，另外两条从该 edge 排除。证据包与 SHA-256 清单见 [rancher-fleet](../research/orchestrator-260809-1305/rancher-fleet/)。

## 4. 为什么仍然不能写 converged

### 4.1 Forward source truth 未完成

| 未闭合边界 | 数量 |
|---|---:|
| fix roots 总数 | 10,850 |
| resolved fix roots | 4,065 |
| blocked fix roots | **6,785** |
| 其中 shallow-history boundary | 4,761 |
| unavailable/ambiguous fix object | 2,024 |
| 触及 blocked roots 的 alias classes | 5,759 |
| deferred candidate edges | 515,461 |
| same-repository fallback candidates | 5,606,121 |
| unresolved clone directories | 12 |

源工件明确写有 `campaign_complete=false`、`coverage_complete=false`。当前 [blocked-bound-analysis](../research/orchestrator-260809-1305/blocked-bound-analysis.json) 的状态为 `UNBOUNDED`；这些行保持 unknown。

### 4.2 已知 positives 暴露 lane 缺口

旧 40 个 verified classes 的捕获签名中，13 个是 `NONE`：当前 ledger lanes 没有重新捕获它们。其余签名为 forward-only 18、explicit-ID-only 2、forward+explicit 1、forward+reverse 4、official+explicit 1、public-web-only 1。这直接反驳“现有 lanes 已覆盖已知正例”。

### 4.3 Capture–recapture 只能诊断

forward 与 explicit-ID 的 Chapman 点估计为 59，近似区间为 `[26, 109.35]`；但 discovery systems 依赖、case ascertainment 非随机，且 13/40 没被当前系统捕获，所以 `usable_for_claim=false`。它提示仍有未观察总体，不能转换成 recall 声明。详见 [capture-recapture](../research/orchestrator-260809-1305/capture-recapture.json)。

### 4.4 Fresh-repository recall 下界不足

当前 fresh positives 只有 4 个、零观察漏报，单侧 95% recall 下界仅 `0.4728708045015879`。预注册目标是 59 个独立 positive repositories 且零漏报，对应下界 `0.950492390111773`；还差 **55** 个。

### 4.5 饱和停止规则被本轮新 case 重置

本轮 270-edge expansion 新增 1 个 verified alias class，因此是 `YIELD_CONTINUE`，连续 zero-yield rounds 为 **0**，不是 2。详见 [saturation rounds](../research/orchestrator-260809-1305/saturation-rounds.json)。

## 5. 当前 gate 状态

| Gate | 状态 |
|---|---|
| required artifacts | PASS |
| population ledger integrity | PASS |
| all final model HIGH adjudicated | PASS |
| report emitted | PASS |
| forward campaign complete | **FAIL** |
| forward coverage complete | **FAIL** |
| blocked fix roots closed | **FAIL** |
| missing-date bound | **FAIL** |
| stratified audit complete | **FAIL** |
| fresh recall lower bound > 0.95 | **FAIL** |
| two consecutive zero-yield rounds | **FAIL** |

结论：工件从 11 个失败门降到 **7 个失败门**，lower-bound corpus 从 40 增到 **41**，但 recall 仍未建立。

## 6. 下一轮的确定性队列

1. **纠正 fix anchor：** Rancher 证明 version-boundary carrier 会把多条 advisory 混在一起；先为 ranked、explicit-ID 与 forward queues 恢复 exact security-fix commits。
2. **闭合 6,785 blocked roots：** deepen 4,761 个 shallow histories，解析 2,024 个 unavailable/ambiguous objects，再重跑 candidate conservation。
3. **裁决 354-row frozen audit：** 六个 strata 各 59；未审记录一直保持 unknown。
4. **批量裁决高召回队列：** 1,036 个 explicit-ID classes 与 4,950 个 forward-history classes；模型仅排序。
5. **补 lane：** 为旧 40 positives 中当前签名为 `NONE` 的 13 个类建立可泛化、非 hard-code 的发现通道。
6. **补 fresh positives：** 再取得 55 个独立 repositories，并按冻结协议逐个跑全流程。
7. 每轮冻结输入与参数；只有连续两个新 verified class 为 0 的轮次，才满足饱和门。

## 7. 复现

```bash
# 重新构建总体 ledger（会重写冻结抽样，正式复现时使用相同 selection_seed）
python3 research/orchestrator-260809-1305/build_recall_ledger.py

# DeepSeek 排序：模型只排优先级，不决定 membership
python3 research/orchestrator-260809-1305/run_deepseek_ranked_screen.py

# 已公开 patch 的最小 differential
(cd research/orchestrator-260809-1305/rancher-fleet && go run regex-differential.go)

# 独立 recall gate；当前预期退出 1，因为七个召回门尚未闭合
python3 research/orchestrator-260809-1305/verify_recall_closure.py
```
