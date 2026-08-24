# 135 后续：AI 不完整修复 Batch C（2026-08-12）

## 结论

本批新增 1 个发布级 `AI_INCOMPLETE_REMEDIATION_CONTRIBUTOR` 和 3 个 `PASS AI_INCOMPLETE_REMEDIATION_COMMIT_ONLY`。四者的 Git 因果、AI attribution 和 first-party closure 均成立；Vitest 与 Mistune 的 partial 和 closure 首次进入同一 release tag，所以只有 Langroid 增加发布级下界。

| 层级 | PASS | Components |
|---|---:|---|
| 发布级 incomplete remediation | 1 | Langroid CVE-2026-25481 |
| commit-only incomplete remediation | 3 | Vitest 1；Mistune 2 |

新增的 8 个 CVE/GHSA public IDs 与 frozen `strict-200-v3` 及此前主报告均零交集。

## 发布级 PASS

### Langroid：CVE-2026-25481 / GHSA-X34R-63HX-W57F

裁决：`PASS AI_INCOMPLETE_REMEDIATION_CONTRIBUTOR_RELEASED`。

- PR #850 是针对 CVE-2025-46724/46725 的 security remediation。human members `752285a5...`、`b68a8a79...` 建立 AST sanitizer；但在 PR branch 的 `556196b8...` 状态，`TableChatAgent.pandas_eval()` 错误引用未定义的 `config.full_eval`。该 `NameError` 落入现有 `except`，所以 untrusted expression 在这一状态 fail-closed，根本到不了 `compile` / `eval`。
- AI atomic member `b1c45e3fc0f3578a5dea9844c0216044321ae1c8` 带 Copilot co-author，唯一代码 delta 是把 `config.full_eval` 改成 `self.config.full_eval`。它确实让安全修复按设计工作，但也首次让表达式穿过弱 sanitizer 后到达 `eval`；删除这个 AI member，公开 exploit 在该 PR 状态不可达。因此它是必要 causal contributor，不只是注释或 carrier attribution。
- mainline squash carrier `0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6` 包含该 member，并从 `0.53.15` 起发布。不能把 carrier 整体说成 AI authored，原子 attribution 只落到上述一行 activation delta。
- 一方 [GHSA-X34R-63HX-W57F](https://github.com/langroid/langroid/security/advisories/GHSA-x34r-63hx-w57f) 明确把它定性为此前 WAF 的 bypass：validator 未限制 `Attribute`，可由 `df.__init__.__globals__['__builtins__']['eval']` 抽出 builtin，再利用 whitelisted DataFrame method 达到 RCE。
- closure `30abbc1a854dee22fbd2f8b2f575dfdabdb603ea` 新增 `visit_Attribute()`，拒绝 dunder/private attributes，并加入该 gadget 的精确回归测试；`0.59.32` 首含 closure。
- 发布见证：`git tag --contains 0d9e4a7b... --no-contains 30abbc1a...` 返回 70 个 tag，覆盖 `0.53.15` 至 `0.59.31`。

这条只标 `incomplete remediation contributor`，不标 AI 独立 origin：弱 AST policy 主体由 human members 写成，但 AI member 是把该 residual 从 fail-closed transient state 激活并送入正式发布的必要节点。

## Commit-only PASS

### 1. Vitest：CVE-2026-53633 / GHSA-G8MR-85JM-7XHM

裁决：`PASS AI_INCOMPLETE_REMEDIATION_COMMIT_ONLY`。

- AI partial：`af88b1f5d82844a4761ea9a977156c98e2b14ca8`，parent `5a7d56e2235d63441a23c54dc85ecffcbfe7cf44`。这是 v3 backport 的 mainline squash object，带 `Co-authored-by: Codex`；PR #10445 中 material members `3a30e871...`、`33f3f21e...` 也分别把 API write/exec guard 和 browser file checks 落到代码，不是只从 carrier trailer 反投影。
- partial 明确在网络暴露时默认关闭 `api.allowWrite` / `api.allowExec`，并在 filesystem、test execution 和 UI callers 上执行 guard；但 raw CDP RPC `sendCdpEvent` / `trackCdpEvent` 没有经过这两个 gate。
- 一方 [GHSA-G8MR-85JM-7XHM](https://github.com/vitest-dev/vitest/security/advisories/GHSA-g8mr-85jm-7xhm) 证明攻击者仍可用 CDP `Page.setDownloadBehavior` 与 `Runtime.evaluate` 覆写 `vite.config.ts` 并触发 host RCE，即使 write/exec 都显式为 false。
- closure：直接 child `385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7` 在 CDP 两个 RPC handler 前加入 `assertCdpAllowed(project)`，并把 coverage 所需 CDP 操作移到受控 server command。
- release gate：`git tag --contains af88... --no-contains 385a...` 为空；两者首次都进入 `v3.2.5`。因此不能称 v3.2.x 曾发布残缺 partial。

这条不标 AI origin：CDP bridge 更早已存在；AI 的真实贡献是引入一套安全 gate，却漏了等价高权限通道。

### 2. Mistune：CVE-2026-59923 / GHSA-8C25-4J27-2RV3

裁决：`PASS AI_INCOMPLETE_REMEDIATION_COMMIT_ONLY`。

- AI partial：`5afeaf6bf43649c575ebf016316fb46096993ece`，parent `067f90861088a496942f5eb43236135352b85d39`，带 `Co-Authored-By: Claude Opus 4.7`。
- partial 的安全目标非常具体：把 image/figure directive 的 `src` 从裸 `escape_text` 接到共享 `safe_url`，并添加 harmful/encoded scheme tests，使 directive 与 inline link/image 的 URL safety contract 一致。
- residual：当时 `safe_url` 在比较 scheme 前不做 percent-decode；partial 新增的 `javascript%3A...` 测试只断言输出不含解码后的字面串，因而没有发现编码值仍原样进入 `href/src`。
- 一方 [GHSA-8C25-4J27-2RV3](https://github.com/lepture/mistune/security/advisories/GHSA-8c25-4j27-2rv3) 精确描述 percent-encoded `javascript:` 绕过；closure `c7101fcbb6e8790e8e39157c5ca2238fc6dd6cbc` 在 `safe_url` 比较前最多三轮 `urllib.parse.unquote`，并增加可失败的回归测试。
- release gate：partial-only tag 集为空；partial 与 closure 都首次进入 `v3.3.0`。

### 3. Mistune：CVE-2026-59929 / GHSA-QFRW-5RXM-MHH2

裁决：`PASS AI_INCOMPLETE_REMEDIATION_COMMIT_ONLY`。

- 同一 AI partial `5afeaf6b...` 把 directive sink 交给 `safe_url`，但该函数仍是四项 denylist，只拒 `javascript:`、`vbscript:`、`file:`、`data:`。
- 一方 [GHSA-QFRW-5RXM-MHH2](https://github.com/lepture/mistune/security/advisories/GHSA-qfrw-5rxm-mhh2) 单列 legacy/chained schemes：`feed:`、`view-source:`、`jar:`、`livescript:`、`mocha:`、`ms-its:`、`mk:`、`res:`。这是与 percent encoding 不同的 parser/policy residual，且 advisory 明确覆盖 link 与 image sinks。
- 同一 closure `c7101fc...` 扩充 `HARMFUL_PROTOCOLS` 并增加针对这些 schemes 的测试。共享 candidate/fix 不等于 alias；两个 first-party advisories 的 bypass grammar 独立，故计两个 semantic components。
- release gate同上：只计 commit-level。

## 关键 FAIL / 防膨胀控制

| Candidate / public component | 结果 | 原因 |
|---|---|---|
| Flowise `e47d9466...` / CVE-2026-41269、CVE-2026-30821 | FAIL AI attribution | PR #5596 的 MIME/extension validator 由 human member `fca9d0bd...` 实现；唯一显式 Gemini member `3a4bb9cd...` 只改错误文案，`b5f3358a...` 只重构 extension map/换 logger。不能把 squash trailer 投射到安全机制。 |
| Flowise `afa24cc6...` / CVE-2026-41276 | FAIL wrong mechanism + attribution | Gemini member `4f5dc410...` 只加 128 字符 password 上限；advisory 是 null/empty reset token authentication bypass，真实 token guard 不在该 AI delta。 |
| WorkOS `9be02e9a...` / CVE-2026-42565 | FAIL AI attribution | squash 中唯一 Copilot member `20849753...` 只改 `AuthKitCore` 注释；危险 custom OAuth state / `returnPathname` 路径由 human member `c6d7ae20...` 创建。 |
| FormNotify `5eab0ea9...` / CVE-2026-5229 | FAIL metadata mismatch | candidate 已删除 client-cookie email fallback；CNA 的 `<=1.1.10` version claim 与该 tag 的实际代码相冲突，没有可复现 residual 时不按元数据硬收。 |

## 计数影响

- strict release-grade：125，不变；
- incomplete-remediation release-grade：23 + 1 = 24；
- 宽口径发布级确认下界：148 + 1 = **149**；
- commit-only：8 + 3 = 11（incomplete 10、strict 1）；
- 最宽 commit-level 工作数：156 + 4 = **160**。

`160` 仍不能写成发布级样本数。

## 可重放检查

```zsh
cd /home/hanqing/agents/ai-slop

vitest_repo=/home/hanqing/.cache/cve-analyzer/repos/vitest-dev_vitest
mistune_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_mistune_7fc5e66709aa98ace87decd926144cc77dd781398077b28f1571514c509ec8a7
langroid_repo=/home/hanqing/.cache/cve-analyzer/repos/langroid_langroid

# Langroid member/carrier attribution and released residual witness.
gh api repos/langroid/langroid/commits/b1c45e3fc0f3578a5dea9844c0216044321ae1c8 --jq '.commit.message, .files[].patch'
git -C "$langroid_repo" tag --contains 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6 --no-contains 30abbc1a854dee22fbd2f8b2f575dfdabdb603ea

# Commit objects and direct Vitest closure.
git -C "$vitest_repo" rev-list --parents -n 1 af88b1f5d82844a4761ea9a977156c98e2b14ca8
git -C "$vitest_repo" rev-list --parents -n 1 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7

# Both partial-only release queries must be empty.
git -C "$vitest_repo" tag --contains af88b1f5d82844a4761ea9a977156c98e2b14ca8 --no-contains 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7
git -C "$mistune_repo" tag --contains 5afeaf6bf43649c575ebf016316fb46096993ece --no-contains c7101fcbb6e8790e8e39157c5ca2238fc6dd6cbc

# First containing tags are v3.2.5 and v3.3.0 respectively for both sides.
git -C "$vitest_repo" tag --contains af88b1f5d82844a4761ea9a977156c98e2b14ca8 --sort=version:refname | head
git -C "$vitest_repo" tag --contains 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7 --sort=version:refname | head
git -C "$mistune_repo" tag --contains 5afeaf6bf43649c575ebf016316fb46096993ece --sort=version:refname | head
git -C "$mistune_repo" tag --contains c7101fcbb6e8790e8e39157c5ca2238fc6dd6cbc --sort=version:refname | head
```
