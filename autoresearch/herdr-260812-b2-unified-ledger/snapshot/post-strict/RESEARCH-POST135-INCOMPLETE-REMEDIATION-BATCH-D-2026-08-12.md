# 135 后续：AI 不完整修复 Batch D（2026-08-12）

## 结论

本批确认 **7 个发布级 `AI_INCOMPLETE_REMEDIATION` 组件、13 个新 public IDs**，没有新增 commit-only。它们都满足“AI 明确尝试修同一安全机制、残缺实现单独发布、后来一方 advisory 与 fix 精确关闭残留”的发布门；均不标成 AI 首次引入漏洞。

| # | Public component | Repo | AI partial -> complete closure | 发布见证 |
|---:|---|---|---|---|
| 1 | CVE-2026-18446 / GHSA-7P8R-X3MC-P8W7 | fastify/fast-uri | `0542a216... -> f3c6c905...` | partial-only `v4.1.1`；patched `4.1.2` |
| 2 | CVE-2026-33994 / GHSA-VC8F-X9PP-WF5P | locutusjs/locutus | `042af9ca... -> 345a6211...` | `v2.0.39`、`v3.0.0`–`v3.0.24`；patched `v3.0.25` |
| 3 | CVE-2026-58432 / GHSA-Q9PG-JJ6X-J9P6 | go-gitea/gitea | `1eced4a7...` / backport `e7fca90a... -> f7fd5102...` | partial in `v1.25.5`；advisory patched `1.27.0` |
| 4 | GHSA-Q6RR-FM2G-G5X8 | scriban/scriban | `2d01bd15... -> 205ca6a7...` | `7.0.0`–`7.2.0`；patched `7.2.1` |
| 5 | CVE-2026-33637 / GHSA-5RV5-XJ5J-3484 | lostisland/faraday | `a6d3a3a0... -> 3f1280c6...` | partial-only `v2.14.1`；patched `v2.14.2` |
| 6 | CVE-2026-55667 / GHSA-FMM7-X4GX-8JHR | filebrowser/filebrowser | `847d08bd... -> 7c2c0a11... -> 64511ce4...` | `v2.63.6`–`v2.63.15`；patched `v2.63.16` |
| 7 | CVE-2026-55668 / GHSA-8WC8-HF36-MJH9 | filebrowser/filebrowser | 同一修复链、独立 write invariant | 同上 |

截至 2026-08-12，一方 repo advisory API 对七项均返回 `state=published`、`withdrawn_at=null`。13 个 ID 与 frozen `strict-200-v3` 以及此前主报告做大小写归一化比较，交集均为 0。

## 准入边界

本批只接受同时满足以下条件的样本：

1. candidate 原子提交自身有可见 AI attribution；
2. candidate 的代码与提交主题明确在修复同一安全机制；
3. 残缺状态至少进入一个 release；
4. 后续 first-party advisory 给出具体 residual/bypass；
5. later fix 在同一 input、trust boundary 与 sink 上精确闭合；
6. public ID、official alias 与机制指纹均不和已有组件重复。

该类与 `STRICT_CAUSAL` 互斥。若漏洞在 candidate 之前就存在，或 candidate 净减风险，即使后来证明没修完整，也只标 `AI_INCOMPLETE_REMEDIATION_RELEASED`。

## 逐项证据

### 1. fast-uri：CVE-2026-18446 / GHSA-7P8R-X3MC-P8W7

裁决：`PASS AI_INCOMPLETE_REMEDIATION_RELEASED`。

- AI partial [`0542a216860fd70c062a4730e620576f62ded057`](https://github.com/fastify/fast-uri/commit/0542a216860fd70c062a4730e620576f62ded057)，parent `3a877384b5848967c963e0fd2b92d50539a80af9`，单 parent，正文和 trailer 均标明 Claude Opus 4.8。它明确识别 RFC parser 与 Node WHATWG URL 的 host-confusion：在 `//` authority 内出现 literal backslash 时返回 malformed，而不是让 `http://evil.com\@allowed.com` 在 policy parser 与 request parser 中得到不同 host。
- residual 不是另一个 CWE 的邻近 bug。[GHSA-7P8R-X3MC-P8W7](https://github.com/fastify/fast-uri/security/advisories/GHSA-7p8r-x3mc-p8w7) 明确证明 `\\`、`/\`、`\/` 作为 authority introducer，以及 TAB/LF/CR 分隔形式，仍造成同一 policy/use host desync。partial 只看已经由合法 `//` 引出的 authority，所以根本看不到这些 introducer。
- closure [`f3c6c905f47831007490f466c5945012e905cc52`](https://github.com/fastify/fast-uri/commit/f3c6c905f47831007490f466c5945012e905cc52)，parent `5e31a6b0f6408f79d7c23e8490b092aba4d873c5`，新增 malformed-introducer/whitespace 检查，并让 `resolve()` 对无法携带 error field 的 malformed input 抛错。
- 本地 tag gate 只有 `v4.1.1` 含 partial 而不含 closure；一方 advisory 给出的修复版本是 `4.1.2`、`3.1.5`、`2.4.4`。因此残缺实现确实独立发布。

### 2. Locutus：CVE-2026-33994 / GHSA-VC8F-X9PP-WF5P

裁决：`PASS AI_INCOMPLETE_REMEDIATION_RELEASED`。

- AI partial [`042af9ca7fde2ff599120783e720a17f335bb01c`](https://github.com/locutusjs/locutus/commit/042af9ca7fde2ff599120783e720a17f335bb01c)，parent `57ea89d4da3b9bcfc983fd27da77a1bdd5d53f01`，带 Claude Opus 4.5 attribution。提交主题就是修复 `parse_str` prototype-pollution guard：把可被覆盖的 `key.includes(...)` 换为 `/.../.test(key)`，并增加 prototype-tampering 测试。
- [GHSA-VC8F-X9PP-WF5P](https://github.com/locutusjs/locutus/security/advisories/GHSA-vc8f-x9pp-wf5p) 直接将其称为 CVE-2026-25521 的 incomplete fix：攻击者先覆盖 `RegExp.prototype.test` 使其恒假，再以 `__proto__[polluted]` 绕过同一 guard。
- closure [`345a6211e1e6f939f96a7090bfeff642c9fcf9e4`](https://github.com/locutusjs/locutus/commit/345a6211e1e6f939f96a7090bfeff642c9fcf9e4)，parent `9922b776adc2923bfa2157257161d87e45f8e668`，在 assignment sink 对每个 parsed segment 用 `Set.has` 拒绝危险 key，不再依赖可覆写的 regex prototype。
- partial-only tag 为 `v2.0.39` 与 `v3.0.0`–`v3.0.24`；closure 首次进入 `v3.0.25`，与 advisory range 完全一致。

### 3. Gitea：CVE-2026-58432 / GHSA-Q9PG-JJ6X-J9P6

裁决：`PASS AI_INCOMPLETE_REMEDIATION_RELEASED`。

- AI partial [`1eced4a7c099459af42412bb32a83241650c0f8f`](https://github.com/go-gitea/gitea/commit/1eced4a7c099459af42412bb32a83241650c0f8f)，parent `5f8e19fcef6d3de7af291a7dfab4f9e5a816ba974`，带 Copilot co-author。它新增 `canAccessDraftRelease`，给 API release 与 API attachment endpoints 加 draft/write-scope gate。release branch backport [`e7fca90a780e4d35eb1fa67b1f377ebd54e74611`](https://github.com/go-gitea/gitea/commit/e7fca90a780e4d35eb1fa67b1f377ebd54e74611) 同样带 Copilot attribution，并进入 `v1.25.5`。
- [GHSA-Q9PG-JJ6X-J9P6](https://github.com/go-gitea/gitea/security/advisories/GHSA-q9pg-jj6x-j9p6) 明确称其为 CVE-2026-27660 的 incomplete fix：API 已隐藏 draft release attachment，但三个 UUID-based web download routes 仍经 `ServeAttachment` 只查 repo read permission，匿名拿到 UUID 即可下载同一 draft artifact。
- closure [`f7fd51022495737cf960b8c4053a27d69148f664`](https://github.com/go-gitea/gitea/commit/f7fd51022495737cf960b8c4053a27d69148f664)，parent `38a582475374dd85206968162566c31dd27b47d3`，在 web `ServeAttachment` 对 release-linked attachment 加 `IsDraft` + write permission gate，并有 integration regression。backport object为 [`ab10e37acf7fabf7829a485cc3e13d118638a856`](https://github.com/go-gitea/gitea/commit/ab10e37acf7fabf7829a485cc3e13d118638a856)。
- 本地旧镜像已证明 partial backport 首次进入 `v1.25.5`；后续 fix object 由一方 commits API 读取，一方 advisory 当前给出受影响 `<=1.26.4`、patched `1.27.0`。不因本地镜像缺少后续对象而把该项降级。

### 4. Scriban：GHSA-Q6RR-FM2G-G5X8

裁决：`PASS AI_INCOMPLETE_REMEDIATION_RELEASED`。

- AI partial [`2d01bd15a1114fac2533aa005036e07389ee89db`](https://github.com/scriban/scriban/commit/2d01bd15a1114fac2533aa005036e07389ee89db)，parent `98563216488161a9edeba6c37c7cf82c98319c9b`，带 Copilot co-author，主题为 `Harden expression evaluation resource bounds`。它在 range、string multiply、`array.join`、shift 等多条表达式路径接入 `LoopLimit` / string-limit 控制。
- [GHSA-Q6RR-FM2G-G5X8](https://github.com/scriban/scriban/security/advisories/GHSA-q6rr-fm2g-g5x8) 指向同一资源边界的遗漏 sibling：`ScriptArray<T>.TryEvaluate` 的 `array * int` 仍可绕开 `LoopLimit`，造成超大分配或长度溢出。
- closure [`205ca6a7c2349d3d388bd5f1f7729ee198c0d5e5`](https://github.com/scriban/scriban/commit/205ca6a7c2349d3d388bd5f1f7729ee198c0d5e5)，parent `7fdf19df7db01c5e57888c5cc31e4d05f3d75440`，在 array multiplication 预先计算安全长度、检查 `LoopLimit` 并调用 `StepLoop`。
- partial-only tags 为 `7.0.0`–`7.2.0`；closure 首次进入 `7.2.1`。一方 advisory 的 affected/patched range 与 tags 一致。

### 5. Faraday：CVE-2026-33637 / GHSA-5RV5-XJ5J-3484

裁决：`PASS AI_INCOMPLETE_REMEDIATION_RELEASED`。

- AI partial [`a6d3a3a0bf59c2ab307d0abd91bc126aef5561bc`](https://github.com/lostisland/faraday/commit/a6d3a3a0bf59c2ab307d0abd91bc126aef5561bc)，parent `b23f710d28c0dba169470f568df4017a1e8beea7`，单 parent，带 Claude Opus 4.6 co-author。它明确修 `build_exclusive_url` 的 protocol-relative `//evil.com/path` host override，给 string input 加前缀保护。
- [GHSA-5RV5-XJ5J-3484](https://github.com/lostisland/faraday/security/advisories/GHSA-5rv5-xj5j-3484) 证明 Faraday 支持的 `URI("//evil.com/path")` sibling input 不响应 `start_with?`，仍被 URI join 当作 authority reference，向攻击者 host 转发 connection headers。
- closure [`3f1280c69e93297d574e85a2d462d05ebadf1d09`](https://github.com/lostisland/faraday/commit/3f1280c69e93297d574e85a2d462d05ebadf1d09)，parent `81dc1688742ad30fa747daba5a82592a1e4df8a8`，先把有 `host` 的 URI object 转成 string，再统一应用 protocol-relative guard，并增加 URI-object regression。
- `v2.14.1` 是唯一含 partial 而不含 closure 的 tag；closure 首次进入 `v2.14.2`。

### 6. File Browser 删除边界：CVE-2026-55667 / GHSA-FMM7-X4GX-8JHR

裁决：`PASS AI_INCOMPLETE_REMEDIATION_RELEASED`。

- AI partial [`847d08bdd135e5c3659f2e6dea2f0cd36617af9b`](https://github.com/filebrowser/filebrowser/commit/847d08bdd135e5c3659f2e6dea2f0cd36617af9b)，parent `0231b7ebdfbe77a6c54027d30c4856c3fd81ee4d`，带 Claude Opus 4.8 attribution。它明确修复 symlink scope escape，在 read/write paths 引入 `WithinScope`。该状态自 `v2.63.6` 发布。
- human intermediate [`7c2c0a11b31b2bb214d741005a0b02b1764208b3`](https://github.com/filebrowser/filebrowser/commit/7c2c0a11b31b2bb214d741005a0b02b1764208b3)，parent `3406d3d7f98dfc3c16e4ff7ff4a87e3bdfe221dd`，把 checks 集中为 `ScopedFs`，自 `v2.63.14` 发布；但 `Remove` / `RemoveAll` 两个 dereferencing operations 没调用共享 `guard()`。
- [GHSA-FMM7-X4GX-8JHR](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-fmm7-x4gx-8jhr) 明确称其为 CVE-2026-54094 的 incomplete fix：upload failure-cleanup 以 Create-only permission 调用 unguarded `RemoveAll`，可沿 scope 内 escaping directory symlink 删除 scope 外文件，并绕过 Delete permission。
- final closure [`64511ce45e3be379e965f7f4fb0929a068d5bb81`](https://github.com/filebrowser/filebrowser/commit/64511ce45e3be379e965f7f4fb0929a068d5bb81)，parent `be23ab3a15bf957928ecfed88de5ab67850c1b9c`，在 `Remove` / `RemoveAll` 调用共享 `guard()`，并加入真实 HTTP cleanup regression。

### 7. File Browser dangling-write 边界：CVE-2026-55668 / GHSA-8WC8-HF36-MJH9

裁决：`PASS AI_INCOMPLETE_REMEDIATION_RELEASED`。

- 与上项共享 `847d08bd... -> 7c2c0a11... -> 64511ce4...` 修复链，但不是 alias 或重复机制。
- [GHSA-8WC8-HF36-MJH9](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-8wc8-hf36-mjh9) 的 invariant 是 write/create：`within()` 遇到 dangling symlink target 不存在时，退回验证 link 的 lexical parent，于是 `OpenFile(O_CREATE)` 随后仍跟随 link，在 scope 外创建新文件。
- final closure 对 dangling leaf 执行 `Lstat` / `Readlink`，沿真实 symlink destination 继续验证，并限制 hop 数；回归测试断言 HTTP write 返回 403 且 scope 外文件不存在。
- 上一项是 delete sink + permission bypass；本项是 create/write sink + dangling-target resolution。输入、sink、权限条件、PoC 和 CVE/GHSA 均独立，故计两个 semantic components；共享 candidate/fix SHA 不能把它们折成 alias。

File Browser 的 partial-only tag 集是 `v2.63.6`–`v2.63.15`，final closure 首次进入 `v2.63.16`。其中 `v2.63.14` 的 human `ScopedFs` redesign 是中间修复，不改变最早 AI partial 已发布且同类 scope residual 延续到 final closure 的事实。

## 去重负控

| Candidate / family | 结果 | 原因 |
|---|---|---|
| File Browser CVE-2026-62843 / archive backslash | EXCLUDE duplicate | 已在 frozen strict ledger 作为 `847d08bd... -> 8503...` 的 AI-origin 独立组件；本批不能再按 incomplete remediation 计数 |
| MCP Atlassian GHSA-489g family | FAIL wrong mechanism | 原 SSRF fix `5cd697...` 无 AI marker；AI `594ca...` 修 domain substring，不是后续 DNS-rebinding residual |
| ProjectCapsule | FAIL later-human origin | 原始 typo 由 human `cc4fb45...` 引入、human `af2f377...` 修复；AI `6a762e...` 是后来邻近改动 |
| LightRAG GHSA-F4VV family | FAIL wrong chain | prior hardcoded-secret partial `8b8c858...` 为 human；AI `728f...` 修 JWT algorithm confusion，`bd1...` 只改 UX |
| OpenClaw follow-up candidates | FAIL attribution gate | 可见 original-fix carriers `1d8968...`、`764394...`、`8c9f35...`、`d3e8b17...` 没有 AI marker；未找到可归因 atomic member |
| 9Router GHSA-6G2F-W7G3-77VF | FAIL remediation order | original local-only checks `5e1c...` / `bb868...` 为 human；AI `da667...` 是后续完整修复，不是残缺 partial |
| Fedify GHSA-XW9Q-2MV6-9FR8 | FAIL remediation order | original 2024 remediation 为 human，AI later commit 是最终 hardening |
| Pydantic AI follow-ups GHSA-CQP8 / GHSA-CG7 families | FAIL attribution gate | original 与 follow-up security deltas均落到 human commits `d398...` / `1add...` |

这些负控保留在报告里，防止“有 AI commit + 有 later advisory”被机械提升为正例。

## 计数影响

- strict release-grade：125，不变；
- incomplete-remediation release-grade：24 + 7 = **31**；
- 宽口径发布级确认下界：149 + 7 = **156**；
- commit-only：11，不变；
- 最宽 commit-level 工作数：160 + 7 = **167**；
- 31 个发布级 incomplete-remediation 组件共 **48 个 public IDs**。

距离 200 个发布级宽口径组件还差 **44**；若把 11 个 commit-only 也放进研发工作集，距离 200 还差 **33**。二者不可混写。

## 可重放检查

```zsh
cd /home/hanqing/agents/ai-slop

fast_uri_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_fast-uri_7b01959f46e290214fdccf056bdabc875a193175aea6d87c3425d8dae59fc182
locutus_repo=/home/hanqing/.cache/cve-analyzer/repos/locutusjs_locutus
gitea_repo=/home/hanqing/.cache/cve-analyzer/repos/go-gitea_gitea
scriban_repo=/home/hanqing/.cache/cve-analyzer/repos/github.com_scriban_scriban
faraday_repo=/home/hanqing/.cache/cve-analyzer/repos/lostisland_faraday
filebrowser_repo=/home/hanqing/.cache/cve-analyzer/repos/filebrowser_filebrowser

# Partial-only release witnesses.
git -C "$fast_uri_repo" tag --contains 0542a216860fd70c062a4730e620576f62ded057 --no-contains f3c6c905f47831007490f466c5945012e905cc52
git -C "$locutus_repo" tag --contains 042af9ca7fde2ff599120783e720a17f335bb01c --no-contains 345a6211e1e6f939f96a7090bfeff642c9fcf9e4
git -C "$gitea_repo" tag --contains e7fca90a780e4d35eb1fa67b1f377ebd54e74611 --sort=version:refname
git -C "$scriban_repo" tag --contains 2d01bd15a1114fac2533aa005036e07389ee89db --no-contains 205ca6a7c2349d3d388bd5f1f7729ee198c0d5e5
git -C "$faraday_repo" tag --contains a6d3a3a0bf59c2ab307d0abd91bc126aef5561bc --no-contains 3f1280c69e93297d574e85a2d462d05ebadf1d09
git -C "$filebrowser_repo" tag --contains 847d08bdd135e5c3659f2e6dea2f0cd36617af9b --no-contains 64511ce45e3be379e965f7f4fb0929a068d5bb81

# Direct parent/candidate/fix evidence.
git -C "$fast_uri_repo" show -s --format=fuller 0542a216860fd70c062a4730e620576f62ded057 f3c6c905f47831007490f466c5945012e905cc52
git -C "$locutus_repo" diff 042af9ca^ 042af9ca -- src/php/strings/parse_str.js
git -C "$scriban_repo" show 205ca6a7c2349d3d388bd5f1f7729ee198c0d5e5
git -C "$faraday_repo" diff a6d3a3a0^ a6d3a3a0
git -C "$filebrowser_repo" show 64511ce45e3be379e965f7f4fb0929a068d5bb81 -- files/scoped.go http/resource_test.go

# Gitea mirror is stale after the partial; read later first-party objects without mutating it.
gh api repos/go-gitea/gitea/commits/f7fd51022495737cf960b8c4053a27d69148f664 \
  --jq '[.sha,(.parents|map(.sha)|join(",")),.commit.message,(.files|map(.filename)|join(","))] | @tsv'

# Current first-party advisory status/ranges, without printing credentials.
for spec in \
  fastify/fast-uri:GHSA-7p8r-x3mc-p8w7 \
  locutusjs/locutus:GHSA-vc8f-x9pp-wf5p \
  go-gitea/gitea:GHSA-q9pg-jj6x-j9p6 \
  scriban/scriban:GHSA-q6rr-fm2g-g5x8 \
  lostisland/faraday:GHSA-5rv5-xj5j-3484 \
  filebrowser/filebrowser:GHSA-fmm7-x4gx-8jhr \
  filebrowser/filebrowser:GHSA-8wc8-hf36-mjh9; do
  repo=${spec%:*}
  id=${spec##*:}
  gh api "repos/$repo/security-advisories/$id" \
    --jq '[.ghsa_id,(.cve_id // "-"),.state,.published_at,.withdrawn_at,
           (.vulnerabilities | map([.vulnerable_version_range,.patched_versions] | join(" => ")) | join("; "))] | @tsv'
done
```

## 产物边界

证据来自本地 first-party Git objects、release tags 与当前 repo advisory/commits API。OSV `introduced`、模型裁决、同文件命中和 commit subject 仅用于 routing，未作为因果证明。本批没有修改 ledger、adjudication JSON、脚本或产品代码。
