# Vibe Security Radar — research total account

Window: 2025-05-01 .. 2026-08-16 (census + live GHSA tail merged). Updated 2026-08-18.

## Funnel: all CVE+GHSA -> open-source repo -> code-writing AI commits

1. Total deduped CVE+GHSA (ACTIVE/PUBLISHED, WITHDRAWN/REJECTED excluded):
   84,060 census + 3,304 tail (08-10..16) = **87,364**
2. With an open-source repo (GHSA+CVE+OSV identity union): **41,990**
   (9,512 distinct repos; mapping includes CVE-reference repos, some of which are
   PoC/writeup repos rather than the project itself - quality refinement open)
3. Repo has 2025+ code-writing AI commits (bot-excluded): **3,683 repos**
4. Narrowed advisory classes: **23,868**

## Screening coverage (all repos in the class map now have verdicts)

- Repos with a verdict: 9,512/9,512 (100%). Of these:
  - CODE_AI verified: 3,683 (stage-2 code-file check, bot emails excluded)
  - excluded with reason in the rescan waves: 1,783 NO_MARKER + 521 NO_HITS
    + 73 DOCS_ONLY (the remainder of the 9,512 was excluded by the original
    2026-08 AI scan: repos scanned with no marker hits)
  - unreachable over git, each with a host-level reason: 283 (deleted/private/moved
    github repos, dead gitlab instances, unmappable reference URLs)
- Stage-2 totals across all rescan waves: 784 CODE_AI, 543 NO_HITS, 86 DOCS_ONLY
- Per-repo audit trail: artifacts/host-reasons-20260816.txt (no UNKNOWN verdicts)

## Chromium dedicated scan (2026-08-17)

214 chromium-family records (CVE+GHSA+OSV) -> 21 canonical chromium repos.
11 repos have verified 2025+ AI code commits (chromium/src 3,246 marker commits,
chromiumos kernel, v8, angle, pdfium, boringssl, infra, ffmpeg, webm/libvpx,
android pdfium/cts). Record verdicts: 111 CODE_AI, 103 NO_AI.
2025+ records: 8 -> 6 CODE_AI. These OSV ids are not census alias members,
tracked in artifacts/chromium-ai-scan-20260817.jsonl.



## Funnel account: unified status of the 23,868 classes (2026-08-18)

Absorbs website foundation research (fp211 gates), ledger verdicts, and
dossiers into one per-class status. One row per class in
artifacts/funnel-account-20260817.jsonl.

- AI_ROOT_CAUSE: 158 (AI 直接引入缺陷或作为 Co-Author 引入根因)
- AI_CODE_FLAWED: 44 (含 8 行因“照搬人类脆弱模式 / 不完整修复未堵死漏洞”重归类入 TP)
- AI_ASSISTED: 0 (已全部归并，不保留单独桶)
- EVIDENCE_GAP: 0
- AI_FAULT_LEGACY: 0
  -> TP 账本行合计: 202 rows (158 AI_ROOT_CAUSE + 44 AI_CODE_FLAWED)
  -> 唯一 Canonical TP 缺陷数: 160 unique cases (42 行同源重复/批量提交已标注 duplicate_of/is_duplicate，保留行但不重复计入独立缺陷)
  -> 11 个 blocked535 占位行已全部补齐完整结构化分析块 (modelcontextprotocol, openssl_encrypt, apm, mlflow, n8n-mcp, openclaw)
- NOT_AI: 4,043
- BLOCKED: 78
- PARTIALLY_ANALYZED: 2,115
- UNANALYZED: 17,430 (只有仓库级 AI 验证)

partial-wave (2026-08-18): PARTIALLY_ANALYZED 中"只找回 fix 版本"的 2,976
class 全量深挖完成（120 shard，grok-4.6 主力 + luna，每 case 研究漏洞来龙去脉
并判定 AI 角色）。判定分布：
- NOT_AI: 1,957
- UNKNOWN: 521（worker 给的宽口径，待复核）
- EVIDENCE_GAP: 421（有仓库有 fix 但拆不到引入 commit / 作者不明）
- AI_ROOT_CAUSE: 24
- AI_CODE_FLAWED: 14
- AI_ASSISTED: 1
- BLOCKED: 38（仓库不可达/闭源）
  -> 本波新增 AI 有责 39（24 root + 14 flawed + 1 assisted）
结果已并入账本（partial_wave 块 + partial_wave_verdict 字段），
证据: .ai-slop/state/partial-wave/results/shard-*-out.jsonl（2976 行）

partial-wave re-audit (2026-08-18): 首轮 980 个结论不理想的 case
（UNKNOWN 521 / EVIDENCE_GAP 421 / BLOCKED 38）全部复审（40 shard）。
结果：NOT_AI 90（UNKNOWN->NOT_AI 61, EVIDENCE_GAP->NOT_AI 28,
BLOCKED->NOT_AI 1），AI_CODE_FLAWED +2（UNKNOWN 1, EVIDENCE_GAP 1），
余下保持 EVIDENCE_GAP 811 / BLOCKED 77（多为闭源或 advisory 镜像仓库，
evidence 有说明）。AI 有责总计 41（24 root + 16 flawed + 1 assisted）。
账本带 partial_wave_reaudited + revised_from 审计轨迹。
证据: .ai-slop/state/partial-wave/reaudit/results/reaudit-*-out.jsonl

squash-audit (2026-08-18): 182 TP 全量拆解审计收尾。171 个未拆 case 全部
完成: 133 CONFIRM / 38 OVERTURN / 0 BLOCKED; 52 个 squash commit 通过
PR ref fetch 拆到写缺陷行的独立 commit, AI marker 落在缺陷行 commit 上
才维持 TP。结果已并入账本 (squash_audit 块 + squash_audit_verdict 字段),
证据: .ai-slop/state/squash-audit/results/shard-*-out.jsonl。

incomplete-fix reclassification (2026-08-18): 用户裁定——AI commit 写了
"不完整的修复"（修复没堵上、后续 advisory 重开/绕过）也算 AI 写的问题代码
=> AI_CODE_FLAWED。gemini-3.7-flash-high 独立复核（antigravity, agent
geminirc3, done）全部 AGREE：翻案 F38V（PraisonAI, Cursor 复制的 default-open
守卫）、6Q7J+Q6RR（scriban, 7.0.0 修补两处 DoS 均未堵上）、2HFG（openclaw,
[AI-assisted] 只补 pressKey/type 漏掉 sibling 路径）；维持 NOT_AI：RFR2
（datamodel-code-generator, SSRF 由人类 2021 引入、AI commit 只是 $ref 门控）。
账本翻案 4 行 / 3 unique case（scriban 双行同一 case），行内加
ai_incomplete_fix_reclassified + ai_incomplete_fix_reclassify_note（证据 +
gemini 复核引用）。证据: .ai-slop/state/incomplete-fix-review/
gemini-verdict-20260818.json + reclassify-20260818.json。

narrow70 deep-dive (2026-08-17): 70 cases re-analyzed with full lineage +
AI-code judgment (flash workers), then double-reviewed by grok-4.6 and
gemini-3.7-flash second opinions (per-case, evidence packs). Adjudicated:
46 AI根源, 16 AI代码有缺陷, 1 待补证据, 7 与AI无关. Manual verification on the 18 reviewer
disagreements: openclaw guard-removal and guard-simplification commits
confirmed; mruby (Matz primary author, Rovo co-author only) and feishu
(sync of pre-existing upstream code) downgraded to 待补证据.
Evidence: .ai-slop/state/narrow70/review/adjudicated.jsonl
- 1 conflict: GitPython GHSA-539m (网站判定 AI根源+AI修复不完整 vs
  ledger 判定与AI无关(窄口径); 保留网站判定, 已记入账本行)


blocked106 attack (2026-08-17): all 106 BLOCKED classes re-analyzed with
understanding-first protocol (local clones, git log -S/blame for the defect
line, squash decomposition, AI-marker check incl co-authored-by). Result:
104 NOT_AI (mostly upstream-declined/unfixed human-introduced code), 1
AI_CODE_FLAWED (oneflow CVE-2025-65886 interpolate_like, PR #10644 with
Co-authored-by: Copilot trailer), 1 remaining BLOCKED (arnold-usd
CVE-2026-0659: closed-source core, no defect line in the open repo).
Evidence: .ai-slop/state/blocked106/shard-*-out.jsonl (106 verdict lines)

POST-HOC VERIFICATION (2026-08-17): the single new TP (oneflow
CVE-2025-65886) was re-checked against the actual vuln semantics and
overturned. NVD references issue #10666 "Segmentation fault in flow.eye +
diag"; repro is flow.eye(3) + [1.0,2.0,3.0] (python list -> Tensor.__add__
-> PythonArg::TypeCheck rejects list, then PyTensor_Unpack does an
unchecked cast on non-Tensor -> UB segfault). The Copilot co-authored
commit b5cd55b (PR #10644) only edits interpolate.py (1 line) and never
touches the defect path. Defect line traced to 157f825b (PR #7985,
Houjiang Chen, 2022-04-24, no AI marker); upstream issue still OPEN.
Verdict corrected: AI_CODE_FLAWED -> NOT_AI. TP back to 182.

## TP reconciliation (2026-08-17)

Two parallel TP books existed and never merged - the source of the number confusion:

- Website "191 cases" = ghsa200-canvas foundation.jsonl curated showcase set
  (网站三层: 确认 12 / 严格 84 / 收窄 95). 其中只有 8 个是账本早期AI有责。
- Ledger B1_AI_FAULT = 118 unique case ids (167 verdict rows) from the mining
  waves (tp-mining-wave1, laneA/B, repo-batch dossiers).

Unified registry artifacts/tp-registry-20260817.jsonl:
- union = 301 unique case ids
  - 仅账本早期AI有责: 110
  - 仅网站严格: 68
  - foundation NARROW only: 66
  - CONFIRM only: 6
  - overlapping/mixed: ~51
- 248 of 301 map inside the 23,868 funnel classes; 53 outside (window/no-repo).
- Class-level inside 23,868: 104 classes carry a B1; a class-level tiered count
  is in artifacts/funnel-account-20260817.jsonl.

## Open work (honest gaps)

- 87,364 - 41,990 = 45,374 classes with no repo mapping: mostly closed-source,
  but GHSA records should be deterministically repo-matched (many still have
  package/reference URLs we have not fully mined). Next major block.
- PoC-noise cleanup: classes whose only repos are researcher PoC repos should be
  re-classified as no-project-repo rather than with-repo.
- Tail (08-10..16) not yet alias-deduped against census members.

Artifacts:
- artifacts/funnel-narrowed-20260816.jsonl
- artifacts/code-writer-repos-20260816.json
- artifacts/host-reasons-20260816.txt
- artifacts/chromium-ai-scan-20260817.jsonl

## Status codes (meaningful English, human-readable)

AI_ROOT_CAUSE | AI_CODE_FLAWED | EVIDENCE_GAP | AI_FAULT_LEGACY |
NOT_AI | BLOCKED | PARTIALLY_ANALYZED | UNANALYZED

Gates: AI_AUTHORSHIP_GATE, INTRODUCER_GATE, VULN_PATH_GATE,
NECESSITY_GATE, FIX_REVERSAL_GATE, RELEASE_GATE, UNIQUENESS_GATE
-> PASS | FAIL | MISSING_EVIDENCE
