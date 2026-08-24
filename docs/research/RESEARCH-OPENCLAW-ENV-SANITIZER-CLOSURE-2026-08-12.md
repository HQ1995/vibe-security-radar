# OpenClaw host-env sanitizer residual closure（2026-08-12）

日期：2026-08-12

在线取证时间：2026-08-12T16:28:11Z

仓库：`openclaw/openclaw`

本地一方 Git 镜像：`/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw`

## 结论

对 AI-generated [PR #63277](https://github.com/openclaw/openclaw/pull/63277) 的 squash member、发布 tag、后续 fix PR 和 4 个一方 repo advisory 完成逐项重放后，本报告确认 **4 个发布级 `AI_INCOMPLETE_REMEDIATION` 组件，共 5 个大小写归一化 public IDs**。

| 层级 | 组件 | Public IDs | 结果 |
|---|---:|---:|---|
| `AI_INCOMPLETE_REMEDIATION_RELEASED` | **4** | **5** | PASS |
| `STRICT_CAUSAL` | 0 | 0 | FAIL；candidate parent 已经存在这些 denylist gaps |
| `COMMIT_ONLY` | 0 | 0 | FAIL；partial carrier 从 `v2026.4.10` 起已独立发布 |

| # | Public component | 独立 residual 指纹 | 后续 fix member / carrier | 发布见证 | 裁决 |
|---:|---|---|---|---|---|
| 1 | [GHSA-ccwh-wwpp-6wg5](https://github.com/openclaw/openclaw/security/advisories/GHSA-ccwh-wwpp-6wg5) / [CVE-2026-53864](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/53xxx/CVE-2026-53864.json) | Node.js runtime-control env 进入 Node child / coverage-output sink | `0f3aecb3…` + `254872e1…` / `91590132…` | partial `v2026.4.10`–`v2026.5.26`；code fix 首见 `v2026.5.27` | PASS released incomplete |
| 2 | [GHSA-hjr6-g723-hmfm](https://github.com/openclaw/openclaw/security/advisories/GHSA-hjr6-g723-hmfm) | `BASHOPTS` / `KSH_ENV` / `FPATH` / `TCLLIBPATH` 进入 interpreter startup/search-path sink | `bbd94a73…` / `9f413acc…` | partial through `v2026.6.5`；fix 首见 `v2026.6.6` | PASS released incomplete |
| 3 | [GHSA-9969-8g9h-rxwm](https://github.com/openclaw/openclaw/security/advisories/GHSA-9969-8g9h-rxwm) | `GIT_ALLOW_PROTOCOL` / `GIT_PROTOCOL_FROM_USER` 可放宽 Git `ext::` transport | 8-member code set / `86bab969…` | partial through `v2026.6.5`；fix 首见 `v2026.6.6` | PASS released incomplete |
| 4 | [GHSA-wxh3-g47h-q3mc](https://github.com/openclaw/openclaw/security/advisories/GHSA-wxh3-g47h-q3mc) | 5 个 `RUSTUP_*` request override 选择 toolchain / download roots | `0c02bd68…` + `df5c589c…` + `7caa0223…` / `7cdec287…` | partial through `v2026.6.5`；fix 首见 `v2026.6.6` | PASS released incomplete |

四项共用一个 AI partial-remediation carrier，但不是一个组件拆四行：它们的 attacker-controlled env family、下游解释器/工具 sink、一方 advisory 和后续 fix PR 都独立。反过来，每个 advisory 内的多个变量只计一个组件。

## 准入门与 claim boundary

发布级 `AI_INCOMPLETE_REMEDIATION` 须同时满足：

1. candidate 是明确的 AI-authored/AI-generated security remediation；
2. atomic delta 实质修改同一个 host-env sanitizer 机制；
3. 带 residual 的 carrier 至少独立进入一个发布 tag；
4. 后来的一方 advisory 精确描述该环境变量类和下游影响；
5. 后续 first-party fix member/carrier 关闭同一 input、trust boundary 和 sink；
6. public ID、official alias 和语义组件指纹与已有账本无重复。

这些是“AI 修完了大量同类项，但 denylist 仍不完整”的证据，**不是 AI 首次创造了 host-env 漏洞**的证据。OSV、CVE 版本字段或模型判断没有被当作因果证明。

## PR #63277：squash 不是原子对象

### AI provenance 与 transfer

- PR #63277 的 title 标有 `[AI]`；PR body 明确说整个 PR 由 OpenAI Codex 生成并经人工复核。这是 **PR-level first-party attribution**，不是从 squash carrier 作者或文件 blame 猜测。
- PR base 和 squash carrier parent 均为 `71617ef2f056e786a39362542594090854ce62bd`；PR head 为 `d684b03765f5cbdc511e35170c65f7032ec4037b`，main carrier 为 `2d126fc62343a7b6895351f96e4e1474bc358140`。
- `git diff --quiet 2d126fc6… d684b037…` 返回 0，证明 carrier tree 与 PR head 一致；carrier 只表达 squash transfer，不取代 member 审计。
- `e118fd9cdd98a0e1a62e781e2a6c03a5c405b6c5` 与 carrier patch-id 相同，但只在无关 remote branch，没有发布 tag；裁决为 **NR duplicate**，不另计。

### 真实 atomic members

`refs/pull/63277/head` 有 15 个线性 member。与本因果边直接相关的拆分是：

| Member | Parent | 原子作用 | 用于裁决 |
|---|---|---|---|
| `3affd5e8f9ca6e2f51d00bebde6c1c277e8a5161` | `71617ef2…` | 第一个 production atom：大幅扩展 shared JSON/Swift denylist 并加 sanitizer tests | **accepted atomic partial start** |
| `ce66f9f2…`–`38502755…` | 线性 review chain | 删减过宽列表、补特定解释器/配置变量、调整 tests | carrier 语义组成，不单独计组件 |
| `9699ce6382ade6c47652f393b08a20bc8d053f20` | `fcd7a642…` | 其中一次大幅收窄 review；把 branch 临时加过的 `NODE_REPL_HISTORY` / `TCLLIBPATH` 又删掉 | 仅证明 incomplete review；base 也未阻断，不是 strict origin |
| `f13109e755284811dc64e37590189b97ea0591f1` | `38502755…` | 新增 inherited-env classifier/例外列表，并让 runtime 使用该语义 | supporting production atom |
| `07886f8b97b000ac44117c1d978d3559782c4502` | `f13109e7…` | 新增 232-entry reported baseline 和 test | **NR test-only**，不当 causal member |
| `c6dd4343…`、`5d623592…`、`c65d2ca8…` | review chain | parity/例外列表的收尾调整 | carrier 语义组成 |
| `d684b03765f5cbdc511e35170c65f7032ec4037b` | `c65d2ca8…` | changelog only | NR docs-only |

因此，报告不把 `2d126fc6…` 写成“AI 原子 commit”；计数边是 **PR-level Codex attribution + atomic production member `3affd5e8…` + patch-equivalent release carrier `2d126fc6…`**。`f13109e7…` 是同 PR 的另一个 production atom，但不产生第二个样本。

## 逐项因果闭合

### 1. Node.js control variables — PASS released incomplete

- Candidate parent、atomic partial 与发布 carrier 都未阻断后来 PR #87308 加入的 Node control-variable 集；因此不能标 `STRICT_CAUSAL`。
- [PR #87308](https://github.com/openclaw/openclaw/pull/87308) 与其一方 review 证据确认四个最终 blocked names：`NODE_REPL_EXTERNAL_MODULE`、`NODE_V8_COVERAGE`、`NODE_REDIRECT_WARNINGS`、`NODE_REPL_HISTORY`。最小 production member set 是 `0f3aecb3b76cc8f194ef045ad241bc239025b0ae` 和 `254872e11bfb60faa7d90cde249f9cd01bae1858`；carrier `91590132f68aee16ece7061048bdc9917ef6c00b` 与 PR head `ff0cd505…` tree-identical。
- Advisory 只公开说“two Node.js control variables”，没有公开变量名。根据 member 顺序，`0f3aecb3…` 的 `NODE_REPL_EXTERNAL_MODULE` / `NODE_V8_COVERAGE` 与“child process / coverage output”高度对应；但这只是高置信 inference。本报告保守地将两个 production members 整体记为 closure set，不伪造 advisory 未公开的精确子集。
- Candidate carrier 首见 `v2026.4.10`；共 26 个 stable tags（`v2026.4.10`–`v2026.5.26`）含 partial 但不含 code fix。`91590132…` 的首个 stable tag 是 `v2026.5.27`。
- 一方 repo/global advisory 写 patched `2026.5.26`，CVEList 写 `<2026.5.26`；但 `v2026.5.26` 的 peeled commit 不含 fix，`package.json` 也为 `2026.5.26`。报告保留该元数据/代码冲突，发布门依据不受争议的早期受影响 tag（如 `v2026.5.22`）与实际首个 code-fixed tag `v2026.5.27`。

### 2. Interpreter startup/search-path variables — PASS released incomplete

- PR #63277 carrier 仍未阻断 `BASHOPTS`、`KSH_ENV`、`FPATH`、`TCLLIBPATH`；[PR #91618](https://github.com/openclaw/openclaw/pull/91618) 的第一个 production member `bbd94a730fc091f6bd603932d3e8887b18dbd01f` 一次性把四者加入 shared denylist，之后四个 members 只改 tests/fixtures。
- Squash carrier `9f413acc183df1edf82da1426aaebc95e47cb989` 与 PR head `b6a4e021…` tree-identical，首个 stable containing tag 是 `v2026.6.6`。
- `3affd5e8…` 曾在未发布 PR branch 临时加入 `TCLLIBPATH`，`9699ce63…` 又删掉；但 PR base 本来就未阻断它，所以这是 incomplete-remediation review 失败，不是重新引入。
- Candidate-only stable tags 从 `v2026.4.10` 延续到 `v2026.6.5`；一方 advisory 确认 `<=2026.6.1` 受影响、`2026.6.6` patched。`v2026.6.1` 是无争议的发布 residual witness。

### 3. Git ext transport controls — PASS released incomplete

- PR #63277 carrier 不含 `GIT_ALLOW_PROTOCOL` 或 `GIT_PROTOCOL_FROM_USER`。[PR #91619](https://github.com/openclaw/openclaw/pull/91619) 的一方 body、review 和真实 Git 探测都指向同一机制：单纯丢弃变量可能回到更宽松的 Git default，所以需要同时阻断 request override、过滤 inherited allowlist，并将 permissive `GIT_PROTOCOL_FROM_USER` 强制成 `0`。
- 可重放的 minimum semantic implementation chain 为：`56d263f836a167051b80b48dd060c0276ba1fde9`（两 key）、`bb5daaf6c38bdf2c5d6b74bf0f3aa950d431cf91`（restrictive boolean）、`5894e1267f345d412982c19e3b6d680c315c62e3` + `b1b9f35f672486713205994ac83dba92c4a06c4f`（allowlist 过滤）、`4843b7b8a4ee0ac7e6ae6bce47e2912504e2d5ef` + `a1beddf76b79811c810d75b31af02110bcc3d4fa` + `5f691df7b31ee50d58e5ce7966dd4ee32ee9082d`（数字/无效/permissive 语义收尾）、`c422f19b48c8a4dd65edaaa2e3bd0028ec475269`（共享 inherited sanitizer）。三个 test-only members 和 merge-sync members 不充当 fix atom。
- Squash carrier `86bab9699d0d238eb3358acbec0b1f1ae53e57ae` 与最终 PR head `5de0064d…` tree-identical；首个 stable containing tag 是 `v2026.6.6`。Candidate-only `v2026.6.1` 是一方 affected 范围内的独立发布见证。

### 4. Rustup startup/toolchain variables — PASS released incomplete

- PR #63277 carrier 不含任何 `RUSTUP_*` policy entry。[PR #91615](https://github.com/openclaw/openclaw/pull/91615) 后来将 `RUSTUP_HOME`、`RUSTUP_TOOLCHAIN`、`RUSTUP_DIST_ROOT`、`RUSTUP_DIST_SERVER`、`RUSTUP_UPDATE_ROOT` 纳入 request-override block，同时保留 trusted inherited operator 值。
- 最小 production member chain 是 `0c02bd688396ebe0ef08a6edcc5068e5a77c10f1`（HOME/TOOLCHAIN）、`df5c589caaf496f536de789316075b0545c5c9ac`（改为 override-only 且保留 inherited）、`7caa02231b7becee6f72266b2a7dcc3494dc5a7d`（三个 dist/update roots）。其余 members 为 tests/tooling cleanup。
- Squash carrier `7cdec2870604d56dc55c0dc64c511daa8321a991` 与 PR head `a4d2b51c…` tree-identical，首个 stable containing tag 是 `v2026.6.6`。`v2026.6.1` 是一方 affected 范围内的 candidate-only 发布见证。

## 去重与负控

| 对象 | 裁决 | 理由 |
|---|---|---|
| 4 个 GHSA 合成 1 个 | FAIL over-dedup | shared sanitizer 不等于 shared sink；Node、shell/interpreter、Git transport、Rustup 各有独立 env family、子进程语义、advisory 和 fix PR |
| 每个 GHSA 按变量数拆分 | FAIL under-dedup | 一方已把同一 runtime/tool family 的 siblings 合并为一个 advisory；每个 advisory 只计一个 component |
| `9699ce63…` 标 `STRICT_CAUSAL` | FAIL | 它只撤销 PR branch 临时阻断；`71617ef2…` base 也未阻断相同变量 |
| `07886f8b…` | NR | baseline/test-only，无 production sanitizer delta |
| `e118fd9c…` | NR duplicate | 与 main carrier patch-id 相同，但无 main ancestry/发布 tag |

5 个 public IDs 与 frozen `strict-200-v3` 的 200 IDs 大小写归一化交集为 0，与已有 `docs/` 发布级计数报告也无命中。它们是新 public components，不是 OSV/CVE/GHSA alias 重复。

## 一方 advisory 元数据

- 4 个 repo advisory 都能由 `openclaw/openclaw` 的一方 REST endpoint 直接读取，`state=published`、`withdrawn_at=null`，公开 HTML 均返回 200。
- 4 个条目都指向 `npm/openclaw`，都给出了受影响版本范围和首个 patched version。
- `GHSA-ccwh-wwpp-6wg5` 已进入 GitHub 全局 Advisory Database，并映射到已发布的 `CVE-2026-53864`。
- 另外 3 个条目在本次取证时仍是 **公开 repo advisory，但未进入 GitHub 全局 Advisory Database**：repo API 的 `cve_id=null`、identifiers 只有 GHSA；全局 REST 返回 404，GraphQL 返回 `NOT_FOUND`，全局 HTML 也返回 404。
- 因而，“repo-published”和“已被 GitHub 全局库/CVE 收录”必须分层记录，不能把后 3 个误写成未发布，也不能替它们推测 CVE。

## 一方 repo advisory 事实

下表字段均直接来自 `GET /repos/openclaw/openclaw/security-advisories/{ghsa_id}`。

| Advisory | 一方描述所指机制 | 受影响 / patched | 发布时间（UTC） | repo 严重度 / CVSS | CWE | reporter |
|---|---|---|---|---|---|---|
| [GHSA-ccwh-wwpp-6wg5](https://github.com/openclaw/openclaw/security/advisories/GHSA-ccwh-wwpp-6wg5) | host environment sanitizer 漏掉两个 Node.js control variables；较低信任的 workspace `.env`、tool env override 或 skill env block 可把它们传给后续 Node.js child process 或 coverage output path | `<= 2026.5.22` / `2026.5.26` | `2026-05-28T17:38:45Z` | `medium` / repo CVSS 未填 | CWE-184 | `nayakchinmohan` |
| [GHSA-hjr6-g723-hmfm](https://github.com/openclaw/openclaw/security/advisories/GHSA-hjr6-g723-hmfm) | host exec environment filtering 漏掉 interpreter startup variables；较低信任 caller/configured input path 可在预期授权之外执行或持久化动作 | `<= 2026.6.1` / `2026.6.6` | `2026-06-30T00:38:25Z` | `high` / `8.8` | CWE-78, CWE-184 | `nayakchinmohan` |
| [GHSA-9969-8g9h-rxwm](https://github.com/openclaw/openclaw/security/advisories/GHSA-9969-8g9h-rxwm) | host exec environment filtering 可允许 Git ext transport；影响表述是较低信任路径可在预期授权之外执行或持久化动作 | `<= 2026.6.1` / `2026.6.6` | `2026-06-30T00:38:34Z` | `high` / `8.8` | CWE-78, CWE-184 | `nayakchinmohan` |
| [GHSA-wxh3-g47h-q3mc](https://github.com/openclaw/openclaw/security/advisories/GHSA-wxh3-g47h-q3mc) | host exec environment filtering 漏掉 rustup startup variables；影响表述同样是越过 caller 的预期授权执行或持久化动作 | `<= 2026.6.2` / `2026.6.6` | `2026-06-30T00:38:50Z` | `high` / `8.8` | CWE-94, CWE-184, CWE-426 | `SEORY0` |

补充事实：

- 后 3 个 repo advisory 的 CVSS 向量完全相同：`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`。
- 4 个 repo advisory 的 `updated_at` 都等于各自 `published_at`；`vulnerable_functions` 都为空数组。
- 4 个描述都明确限定在所述 feature/configuration，并保留 OpenClaw 的 trusted-operator model；这限制影响前提，但不替代对真实调用链的验证。
- 公告没有列出所遗漏环境变量的完整变量名集合；不能从标题自行补全变量清单。

## GitHub 全局库与 CVE 层

### `GHSA-ccwh-wwpp-6wg5`

GitHub 全局记录 [GHSA-ccwh-wwpp-6wg5](https://github.com/advisories/GHSA-ccwh-wwpp-6wg5) 为 `reviewed`，并显式列出 `CVE-2026-53864`：

| 字段 | repo advisory endpoint | GitHub global advisory endpoint |
|---|---|---|
| CVE / identifiers | `cve_id=null`；仅 GHSA | `CVE-2026-53864`；GHSA + CVE |
| severity | `medium` | `high` |
| CVSS | 未填 | v3.1 `8.1`；v4 `7.6` |
| published_at | `2026-05-28T17:38:45Z` | `2026-06-18T13:02:49Z` |
| affected / patched | `<= 2026.5.22` / `2026.5.26` | `<= 2026.5.22` / `2026.5.26` |
| CWE | CWE-184 | CWE-184 |

官方 [CVEList record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/53xxx/CVE-2026-53864.json) 进一步确认：

- `cveMetadata.state=PUBLISHED`，CNA/assigner 是 VulnCheck；
- `datePublished=2026-06-16T18:05:09.983Z`；
- package URL 是 `pkg:npm/openclaw`，repo 指向 `openclaw/openclaw`；
- 版本表达为 `>=0, <2026.5.26`，并把 `2026.5.26` 标为 unaffected；
- CVSS v3.1 为 `8.1`，v4.0 为 `7.6`，CWE 为 CWE-184；
- vendor-advisory reference 回指上述 OpenClaw repo advisory。

这里有两个必须保留的元数据差异：

1. repo advisory 的 severity 是 `medium`，GitHub 全局库/CVEList 是 `high`；
2. GitHub repo/global API 的 affected 字符串是 `<= 2026.5.22`，CVEList 表达为 `< 2026.5.26`。

本报告不根据元数据猜测中间版本是否实际发布，也不选择性覆盖其中一层；后续 release/tag 核验应单独裁决。

### 另外 3 个 GHSA

| GHSA | repo HTML | repo REST | `cve_id` / identifiers | global REST / GraphQL | global HTML |
|---|---:|---|---|---|---:|
| GHSA-hjr6-g723-hmfm | 200 | `state=published` | `null` / GHSA only | 404 / `NOT_FOUND` | 404 |
| GHSA-9969-8g9h-rxwm | 200 | `state=published` | `null` / GHSA only | 404 / `NOT_FOUND` | 404 |
| GHSA-wxh3-g47h-q3mc | 200 | `state=published` | `null` / GHSA only | 404 / `NOT_FOUND` | 404 |

可冻结的表述是：**截至取证时间，它们是公开且未撤回的一方 repo advisories，但在可观察的一方 GitHub 全局映射中仍为 GHSA-only。** 404/`NOT_FOUND` 只说明当前未被全局 endpoint 解析，不能扩大成“永远不会有 CVE”。

## Fact / inference 边界

### 可直接引用的一方事实

- 公告身份、公开状态、package、版本范围、patched version、severity、CVSS、CWE、reporter、发布时间和未撤回状态。
- 公告自己描述的四类残留：Node.js control variables、interpreter startup variables、Git ext transport、rustup startup variables。
- `ccwh` 的 GitHub 全局记录与 CVEList 对 `CVE-2026-53864` 的显式映射。
- PR #63277 的 Codex attribution、base/head/carrier SHA、15-member 顺序，以及每个后续 fix PR 的一方 body/member 列表。
- Git object 的 parent/delta、PR-head/carrier tree identity、stable-tag ancestry 与 tag 中的 `package.json` version。

### 组合证据后的裁决与仍保留的不确定性

- `AI_INCOMPLETE_REMEDIATION` 是对 PR-level AI provenance、atomic code delta、一方 advisory、later reversal 与 release ancestry 的组合裁决；不是 advisory 自己的原文结论。
- `ccwh` 公告未公开“two variables”的名字；因此不把某两个 names 当作一方直接事实，而用整个 PR #87308 production set 做 closure。
- repo/global/CVEList 对 `ccwh` 的 patched/affected 范围与 Git tag containment 存在冲突；报告不把任一层静默覆盖另一层。
- 后 3 个 GHSA 截至取证时无全局 GitHub advisory/CVE mapping；其 GHSA-only 状态可能未来变化。

因此，本报告的 **4 PASS 是 release-grade 因果闭合**，但类别仅限 `AI_INCOMPLETE_REMEDIATION`；不得在后续汇总中改写为 AI origin 或把争议版本字段写成无冲突事实。

## 可重放命令

以下命令在 zsh 下可直接重放，不输出凭据：

```zsh
repo=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw

# Fetch the exact squash-member refs.
git -C "$repo" fetch origin \
  '+refs/pull/63277/head:refs/remotes/origin/pr-63277-head' \
  '+refs/pull/87308/head:refs/remotes/origin/pr-87308-head' \
  '+refs/pull/91618/head:refs/remotes/origin/pr-91618-head' \
  '+refs/pull/91619/head:refs/remotes/origin/pr-91619-head' \
  '+refs/pull/91615/head:refs/remotes/origin/pr-91615-head'

# PR-level AI provenance and exact member lists.
for pr in 63277 87308 91618 91619 91615; do
  gh api "repos/openclaw/openclaw/pulls/$pr" \
    --jq '[.html_url,.merged_at,.merge_commit_sha,.base.sha,.head.sha,.title,.body]'
  gh api --paginate "repos/openclaw/openclaw/pulls/$pr/commits" \
    --jq '.[] | [.sha,.parents[0].sha,.commit.author.name,.commit.author.email,.commit.message]'
done

# The main carriers are exact tree transfers of the PR heads.
git -C "$repo" diff --quiet 2d126fc62343a7b6895351f96e4e1474bc358140 d684b03765f5cbdc511e35170c65f7032ec4037b
print -- "candidate_tree_rc=$?"
git -C "$repo" diff --quiet 91590132f68aee16ece7061048bdc9917ef6c00b ff0cd505acd14e523fa6590414bd2ec27a009d01
print -- "node_fix_tree_rc=$?"
git -C "$repo" diff --quiet 9f413acc183df1edf82da1426aaebc95e47cb989 b6a4e021c02e8d2a83336c26c9798f7d741af05d
print -- "interpreter_fix_tree_rc=$?"
git -C "$repo" diff --quiet 86bab9699d0d238eb3358acbec0b1f1ae53e57ae 5de0064d196772f3c729f46fb9cf930fc3973486
print -- "git_fix_tree_rc=$?"
git -C "$repo" diff --quiet 7cdec2870604d56dc55c0dc64c511daa8321a991 a4d2b51c91be6a40a927cb3e7479433c301a820c
print -- "rustup_fix_tree_rc=$?"

# Candidate/fix deltas. These expose production members instead of trusting squash subjects.
git -C "$repo" show --stat --patch 3affd5e8f9ca6e2f51d00bebde6c1c277e8a5161
git -C "$repo" show --stat --patch f13109e755284811dc64e37590189b97ea0591f1
git -C "$repo" show --stat --patch 0f3aecb3b76cc8f194ef045ad241bc239025b0ae
git -C "$repo" show --stat --patch 254872e11bfb60faa7d90cde249f9cd01bae1858
git -C "$repo" show --stat --patch bbd94a730fc091f6bd603932d3e8887b18dbd01f
for sha in \
  56d263f836a167051b80b48dd060c0276ba1fde9 \
  bb5daaf6c38bdf2c5d6b74bf0f3aa950d431cf91 \
  5894e1267f345d412982c19e3b6d680c315c62e3 \
  b1b9f35f672486713205994ac83dba92c4a06c4f \
  4843b7b8a4ee0ac7e6ae6bce47e2912504e2d5ef \
  a1beddf76b79811c810d75b31af02110bcc3d4fa \
  5f691df7b31ee50d58e5ce7966dd4ee32ee9082d \
  c422f19b48c8a4dd65edaaa2e3bd0028ec475269; do
  git -C "$repo" show --stat --patch "$sha"
done
git -C "$repo" show --stat --patch 0c02bd688396ebe0ef08a6edcc5068e5a77c10f1
git -C "$repo" show --stat --patch df5c589caaf496f536de789316075b0545c5c9ac
git -C "$repo" show --stat --patch 7caa02231b7becee6f72266b2a7dcc3494dc5a7d

# Release gate: nonempty output proves independently released partial states.
candidate=2d126fc62343a7b6895351f96e4e1474bc358140
for fix in \
  91590132f68aee16ece7061048bdc9917ef6c00b \
  9f413acc183df1edf82da1426aaebc95e47cb989 \
  86bab9699d0d238eb3358acbec0b1f1ae53e57ae \
  7cdec2870604d56dc55c0dc64c511daa8321a991; do
  git -C "$repo" tag --contains "$candidate" --no-contains "$fix" \
    --sort=version:refname | rg '^v[0-9]{4}\.[0-9]+\.[0-9]+$'
done

# First stable containing tags for candidate and fixes.
for sha in "$candidate" \
  91590132f68aee16ece7061048bdc9917ef6c00b \
  9f413acc183df1edf82da1426aaebc95e47cb989 \
  86bab9699d0d238eb3358acbec0b1f1ae53e57ae \
  7cdec2870604d56dc55c0dc64c511daa8321a991; do
  git -C "$repo" tag --contains "$sha" --sort=version:refname \
    | rg '^v[0-9]{4}\.[0-9]+\.[0-9]+$' | head -1
done

# Static key witness at the candidate base/carrier and each closure carrier.
keys_re='^(NODE_(REPL_EXTERNAL_MODULE|V8_COVERAGE|REDIRECT_WARNINGS|REPL_HISTORY)|BASHOPTS|KSH_ENV|FPATH|TCLLIBPATH|GIT_ALLOW_PROTOCOL|GIT_PROTOCOL_FROM_USER|RUSTUP_)'
for rev in \
  71617ef2f056e786a39362542594090854ce62bd \
  2d126fc62343a7b6895351f96e4e1474bc358140 \
  91590132f68aee16ece7061048bdc9917ef6c00b \
  9f413acc183df1edf82da1426aaebc95e47cb989 \
  86bab9699d0d238eb3358acbec0b1f1ae53e57ae \
  7cdec2870604d56dc55c0dc64c511daa8321a991; do
  print -- "@@ $rev"
  git -C "$repo" show "${rev}:src/infra/host-env-security-policy.json" \
    | jq -r --arg re "$keys_re" \
      '[.blockedEverywhereKeys[],.blockedOverrideOnlyKeys[]] | map(select(test($re))) | unique[]'
done

ids=(
  GHSA-ccwh-wwpp-6wg5
  GHSA-hjr6-g723-hmfm
  GHSA-9969-8g9h-rxwm
  GHSA-wxh3-g47h-q3mc
)

# 一方 repo advisory 元数据。
for id in $ids; do
  gh api -H 'X-GitHub-Api-Version: 2022-11-28' \
    "/repos/openclaw/openclaw/security-advisories/$id" \
    --jq '{ghsa_id,state,cve_id,identifiers,summary,description,severity,cvss,cwes,vulnerabilities,published_at,updated_at,withdrawn_at,credits,html_url}'
done

# GitHub 全局 Advisory Database；后三项预期为 HTTP 404。
for id in $ids; do
  gh api -H 'X-GitHub-Api-Version: 2022-11-28' "/advisories/$id" \
    --jq '{ghsa_id,cve_id,type,severity,cvss,cvss_severities,cwes,vulnerabilities,published_at,updated_at,withdrawn_at,html_url}'
  rc=$?
  print -- "$id global_rest_rc=$rc"
done

# GraphQL 全局索引；后三项预期为 NOT_FOUND。
for id in $ids; do
  gh api graphql -F ghsaId="$id" \
    -f query='query($ghsaId:String!){securityAdvisory(ghsaId:$ghsaId){ghsaId identifiers{type value} severity publishedAt updatedAt withdrawnAt permalink vulnerabilities(first:10){nodes{package{name ecosystem} vulnerableVersionRange firstPatchedVersion{identifier}}}}}'
done

# 公开页面可见性：4 个 repo pages 为 200；只有 ccwh 的 global page 为 200。
for id in $ids; do
  curl -L -sS -o /dev/null -w "$id repo=%{http_code} %{url_effective}\\n" \
    "https://github.com/openclaw/openclaw/security/advisories/$id"
  curl -L -sS -o /dev/null -w "$id global=%{http_code} %{url_effective}\\n" \
    "https://github.com/advisories/$id"
done

# CVE-2026-53864 的官方 CVEList v5 record。
gh api -H 'Accept: application/vnd.github.raw+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  '/repos/CVEProject/cvelistV5/contents/cves/2026/53xxx/CVE-2026-53864.json' \
  --jq '{cveMetadata:.cveMetadata,cna:{title:.containers.cna.title,affected:.containers.cna.affected,references:.containers.cna.references,metrics:.containers.cna.metrics,problemTypes:.containers.cna.problemTypes}}'

# Frozen strict-ledger dedup: expected no output.
public_ids=(
  GHSA-CCWH-WWPP-6WG5 CVE-2026-53864 GHSA-HJR6-G723-HMFM
  GHSA-9969-8G9H-RXWM GHSA-WXH3-G47H-Q3MC
)
for id in $public_ids; do
  jq -r '.public_ids[]?' \
    /home/hanqing/agents/ai-slop/research/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
    | tr '[:lower:]' '[:upper:]' | rg -x "$id"
done
```

## Source URLs

- Repo advisories：
  - <https://github.com/openclaw/openclaw/security/advisories/GHSA-ccwh-wwpp-6wg5>
  - <https://github.com/openclaw/openclaw/security/advisories/GHSA-hjr6-g723-hmfm>
  - <https://github.com/openclaw/openclaw/security/advisories/GHSA-9969-8g9h-rxwm>
  - <https://github.com/openclaw/openclaw/security/advisories/GHSA-wxh3-g47h-q3mc>
- GitHub global advisory：<https://github.com/advisories/GHSA-ccwh-wwpp-6wg5>
- CVEList：<https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/53xxx/CVE-2026-53864.json>
