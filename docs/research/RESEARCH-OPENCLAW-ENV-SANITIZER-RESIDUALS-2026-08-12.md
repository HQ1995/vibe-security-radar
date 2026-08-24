# OpenClaw env sanitizer residuals：因果闭合与一方 advisory（2026-08-12）

日期：2026-08-12

在线取证截止：2026-08-12T17:35:59Z

仓库：`openclaw/openclaw`

本地一方 Git 镜像：`/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw`

## 终态裁决

本报告只核验 AI-generated [PR #63277](https://github.com/openclaw/openclaw/pull/63277) 的第一个 production member `3affd5e8f9ca6e2f51d00bebde6c1c277e8a5161`、发布 carrier `2d126fc62343a7b6895351f96e4e1474bc358140` 与本页所列 advisory 之间的因果边。不把“都和环境变量有关”当作 same-mechanism；不使用 OSV、模型评分或 advisory 版本字段代替 Git 因果证据。

准入规则是：

1. `71617ef2f056e786a39362542594090854ce62bd` 时必须已有可达的相关 sink；否则是候选之后新增的漏洞，不能倒算给 `3affd5e8…`。
2. `3affd5e8…` 必须实质改动同一 input/trust boundary 下的 sibling family，而不只是同时序。
3. 完整 PR carrier 必须仍保留 residual，且该 carrier 与 later fix 之间存在 stable tag 发布见证。
4. later fix 的 direct parent 必须仍可达相同漏洞，production member 必须关闭同一接受谓词或 sink invariant。

| Advisory | 是否是 `3affd5e8…` 同边界 residual | `71617ef2…` / later-fix direct parent | 真实发布状态 | later exact fix | 去重与终态 |
|---|---|---|---|---|---|
| [GHSA-24vr-rprv-67rf](https://github.com/openclaw/openclaw/security/advisories/GHSA-24vr-rprv-67rf) | **否**；`npm_execpath` runtime-deps sink 由 `6d409a61…` 在 candidate 后才加入 | 前者无该 sink；`7a23c188…` 有漏洞 | candidate 与后加 sink 共存的 stable 状态为 `v2026.4.20`–`v2026.4.27` | `b1a84c32…` / `ccb3af55…`，精确移除 runner 对 `npm_execpath` 的信任 | 与 Homebrew 不重复，但裁决 `FAIL_POST_CANDIDATE_SINK` |
| [GHSA-4pqj-3c56-5fqq](https://github.com/openclaw/openclaw/security/advisories/GHSA-4pqj-3c56-5fqq) | **是**；`3affd5e8…` 已阻断 AWS/Azure/GitHub credential siblings，却留下已被 provider 读取的其他 auth vars | 两者均保留漏洞；later parent `9adbab05…` | `v2026.4.10`–`v2026.5.27` | `6d31c78c…` + `6852e4a1…` / `85277c2d…`，显式列表加动态 provider registry | credential exposure 不与 endpoint redirection/已有四条重复；`AI_INCOMPLETE_REMEDIATION_RELEASED` |
| [GHSA-8wg3-5mcm-fjq8](https://github.com/openclaw/openclaw/security/advisories/GHSA-8wg3-5mcm-fjq8) | **是**；`3affd5e8…` 曾加入 `HOMEBREW_PREFIX` 等 siblings，review chain 又从 carrier 删掉，同时始终漏掉 `HOMEBREW_BREW_FILE` | 两者均保留漏洞；later parent `94b4b3c6…` | 按 Git code fix 为 `v2026.4.10`–`v2026.4.29` | `734a35d9…` + `67619d87…` / `f86953f3…`，workspace block + 彻底移除 ambient Homebrew selection | 与 npm/gcloud 不重复；`AI_INCOMPLETE_REMEDIATION_RELEASED`，但保留 advisory 写 `2026.5.27` 的冲突 |
| [GHSA-fq9j-vw4w-fr6v](https://github.com/openclaw/openclaw/security/advisories/GHSA-fq9j-vw4w-fr6v) | **是**；`3affd5e8…` 处理 `CLOUDSDK_CONFIG` / `CLOUDSDK_CORE_PROJECT` siblings，却漏掉已有 gcloud sink 的 `CLOUDSDK_PYTHON` | 两者均保留漏洞；later parent `cba0a348…` | `v2026.4.10`–`v2026.4.29` | `57400d73…` / `86251f43…`，workspace 阻断加 trusted Python override | 与 `hjr6` 的通用 shell/interpreter startup 不重复；`AI_INCOMPLETE_REMEDIATION_RELEASED` |
| [GHSA-wc84-j36w-pw4x](https://github.com/openclaw/openclaw/security/advisories/GHSA-wc84-j36w-pw4x) | **否**；`STATE_DIRECTORY` runtime-deps sink 由 `a99490fb…` 在 candidate 后才加入 | 前者无该 sink；`089a3063…` 有漏洞 | 后加 sink 与 candidate 共存的 stable 状态为 `v2026.4.22`–`v2026.4.29` | `9a6dced7…` / `42dfc36d…`，精确阻断 workspace key | 与 `24vr` 共享 subsystem 但分别是 root/executable sink；`FAIL_POST_CANDIDATE_SINK` |
| [GHSA-8f46-3xx3-8c9m](https://github.com/openclaw/openclaw/security/advisories/GHSA-8f46-3xx3-8c9m) | **否**；这是 gateway precheck 与 node execution 的 env-equivalence/approval-binding invariant，不是 denylist completeness | 两者均有 mismatch；later parent `e59e65be…` | `v2026.4.10`–`v2026.6.1` | production chain `092dc3ee…`, `69f20e86…`, `d5a07f0a…`, `8d2fa50f…` / `c208a106…` | 与现有四条不重复，但属 approval 机制；`FAIL_DIFFERENT_INVARIANT` |
| [GHSA-55cf-xx38-4p9p](https://github.com/openclaw/openclaw/security/advisories/GHSA-55cf-xx38-4p9p) | **是**；`3affd5e8…` 已把 `AMQP_URL` / `DATABASE_URL` / `MONGODB_URI` / `REDIS_URL` 等 endpoint controls 纳入被 dotenv 调用的 shared classifier，却漏掉已有 connector sinks | 两者均保留漏洞；later parent `8b8df813…` | `v2026.4.10`–`v2026.4.21` | `faa4d990…` + `2419571e…` / `0623079e…`，显式 connector keys + Matrix `_HOMESERVER` suffix | endpoint redirection 不与 provider credentials/已有四条重复；`AI_INCOMPLETE_REMEDIATION_RELEASED` |
| [GHSA-hxvm-xjvf-93f3](https://github.com/openclaw/openclaw/security/advisories/GHSA-hxvm-xjvf-93f3) | **否**；`3affd5e8…` 未改动 `OPENCLAW_*` namespace，可归属的 partial fix 是更早的 PR #62660 | 两者均保留 namespace gap；later parent `e1818116…` | `v2026.4.10`–`v2026.4.15` 的共存是真的，但只是时序共存 | `f4a634e1…` / `018494fa…`，加入 fail-closed `OPENCLAW_` prefix | 与 `7wv4` 属同一早期 runtime-namespace repair chain；`FAIL_PRIOR_LINEAGE` |
| [GHSA-7wv4-cc7p-jhxc](https://github.com/openclaw/openclaw/security/advisories/GHSA-7wv4-cc7p-jhxc) | **否**；fix 早于 candidate | `f4704184…` 有漏洞，但 `dbfcef31…` 已是 `71617ef2…` 的 ancestor | 不存在“含 candidate 不含 fix”的 stable tag；fix 首见 `v2026.4.9` | `b783302e…` + `bc4f47c4…` / `dbfcef31…` | 与 `hxvm` 是同一 namespace 的 partial → fail-closed 链；`FAIL_PRE_CANDIDATE_FIXED` |

表中没有把任何项标为 `STRICT_CAUSAL`：经准入的 residual 在 candidate parent 中已经存在，所以只能说 AI security remediation 没修完，不能说 AI 首次创造了漏洞。发布门也没有使用 PR member 本身：`3affd5e8…` 只在 PR branch，stable 见证来自与 PR head 表达同一最终 delta 的 squash carrier `2d126fc6…`，其首个 stable containing tag 是 `v2026.4.10`。

## Candidate 原子性与机制边界

- PR #63277 的 title 带 `[AI]`，body 明示由 OpenAI Codex 生成并经人工复核。这是 PR-level 一方 provenance，不是从 author name 猜测。
- `3affd5e8…` 的 direct parent 是 `71617ef2…`；它是第一个 production atom，扩展 shared `host-env-security-policy.json` 及 Swift parity。它没有修改 `src/infra/dotenv.ts`，但该文件在 parent 中已把 `isDangerousHostEnvVarName()` / `isDangerousHostEnvOverrideVarName()` 作为 workspace dotenv 接受谓词的一部分，因此 `3affd5e8…` 的 policy delta 会真实改变 workspace `.env` 行为。
- 精确 sibling witness：`3affd5e8…` 相对 parent 加入 AWS/Azure/GitHub credentials、`AMQP_URL` / database URLs、`CLOUDSDK_CONFIG` / `CLOUDSDK_CORE_PROJECT`、`HOMEBREW_CELLAR` / `HOMEBREW_PREFIX` / `HOMEBREW_REPOSITORY`。最终 carrier 保留了 credential 和 endpoint siblings，但 review chain 删掉 Cloud SDK 和 Homebrew siblings；这两条仍是 incomplete-remediation review 失败，但不是 strict origin。
- 相反，`npm_execpath` 的 bundled-runtime-deps sink 和 `STATE_DIRECTORY` 的 runtime-deps sink 都在 candidate 后才进入 main；`OPENCLAW_*` 是 PR #62660/#69376 的独立 repair chain；node approval env parity 是 approval-binding invariant。这些都不因共享“environment”一词而归给 `3affd5e8…`。

## 逐项因果证据

### Provider credentials

`71617ef2…` 已有 `DEEPSEEK_API_KEY` 等 provider consumers，workspace dotenv 只显式阻断少数 Anthropic/OpenAI keys。`3affd5e8…` 又把 AWS/Azure/GitHub credential siblings 纳入会被 dotenv 调用的 shared policy，说明 auth/credential family 确实在其修复边界内。PR #83655 的 `6d31c78c…` 加入 first-party provider credential set，`6852e4a1…` 再从 trusted provider registry 动态构建 blocklist；两者组成公告所述广义 provider-credential closure。

### Homebrew executable selection

`71617ef2…` 的 `src/infra/brew.ts` 直接使用 `HOMEBREW_BREW_FILE` / `HOMEBREW_PREFIX`，`src/agents/skills-install.ts` 也使用 ambient prefix。`3affd5e8…` 加入了 Homebrew siblings，但 carrier 又移除，所以 parent 与 released carrier 都保留漏洞。PR #74463 的 `734a35d9…` 阻断 workspace keys 并让 in-tree skill path 默认不信任 ambient Homebrew vars；`67619d87…` 删掉可重新 opt-in 的分支，构成最小 final invariant。

Git 显示 `f86953f3…` 首见 `v2026.5.2`，而 `v2026.5.2`、`v2026.5.26`、`v2026.5.27` 均已阻断两个 workspace keys，且 brew resolver 不再读取它们。`f86953f3…..v2026.5.27` 之间没有同机制重引入；`v2026.5.27` 的相关历史只有 Docker 缺 brew 提示等不同行为。因此本报告保留两层事实：一方 advisory/global/CVE 都写 `<2026.5.27` / `2026.5.27`，但可重放代码闭合首见 `v2026.5.2`。这不会被静默改写成一致。

### Cloud SDK Python selection

`71617ef2…` 的 Gmail setup 在 `process.env.CLOUDSDK_PYTHON` 已设时不再覆盖，workspace dotenv 又会接受该 key。`3affd5e8…` 处理 Cloud SDK 配置/project siblings，但未阻断 interpreter selector。PR #74492 的 production member `57400d73…` 同时在 workspace 边界阻断它，并对 gcloud child 强制 trusted/undefined Python，因此是 exact same-mechanism defense in depth。

### Connector endpoint redirection

`71617ef2…` 已有 Matrix/Mattermost/IRC/Synology env consumers，而 workspace predicate 只有窄的显式列表和 `_API_HOST` / `_BASE_URL` suffixes。`3affd5e8…` 把 AMQP/database endpoint controls 纳入同一有效 predicate，但没有覆盖 connector-specific names。PR #70240 的 `faa4d990…` 阻断五个明列 key，`2419571e…` 加入 Matrix per-account `_HOMESERVER` suffix；公告明列的 traffic-redirection 机制因而闭合。

### 保留的因果负项

- `24vr`：candidate parent 中连 `src/plugins/bundled-runtime-deps.ts` 都不存在。`6d409a61…` 于 `v2026.4.20` 才引入 `npm_execpath` runner candidate；所以 later parent 和 release 是真的，later fix 也是 exact，但不是 `3affd5e8…` 没修完。
- `wc84`：`a99490fb…` 于 `v2026.4.22` 才引入 `STATE_DIRECTORY` runtime-deps root sink。它与 `24vr` 是两个独立后加 sink，不因同属 bundled dependencies 而合并，也不因 candidate 较早而倒归因。
- `8f46`：`71617ef2…` 的 gateway 用 gateway-side `params.env` 做 allowlist precheck，而 node `system.run.prepare` 未接收要实际执行的 env；later fix 精确修正了这个 mismatch。但 PR #63277 body 明示“No exec approval model changes”，`3affd5e8…` 的 denylist delta 也没有修改 approval binding，所以这是独立机制。
- `hxvm` / `7wv4`：PR #62660 的 `dbfcef31…` 在 `v2026.4.9` 先修一批 OpenClaw runtime controls，并已是 candidate parent 的 ancestor；PR #69376 的 `018494fa…` 再用整个 `OPENCLAW_` prefix fail closed。这是先前 fix 的 partial→closure 链，`3affd5e8…` 没有修改这个 namespace。

## 语义去重

- 与旧报告的 Node control vars、通用 interpreter startup vars、Git ext transport 和 Rustup startup vars 都没有 public-ID alias 重叠。`fq9j` 最接近 interpreter 类，但它限于 Gmail setup 的 gcloud Python selector，具有独立 input key、feature gate、sink 和 fix PR，不与 `hjr6` 合并。
- `4pqj` 保护 provider auth material，`55cf` 保护 connector destination；即使 endpoint redirection 可能间接带走 credential，两者的受控 key family 和下游安全属性也不同。
- `24vr` 与 `8wg3` 都是 installer executable selection，但分别针对 npm bundled-runtime-deps 和 Homebrew skill install，不合并。`24vr` 与 `wc84` 共享 bundled-runtime-deps subsystem，但分别控制 executable 和 dependency root，也不合并。
- `hxvm` 是 `7wv4` 同一 `OPENCLAW_*` runtime-control namespace 的 fail-closed closure；两条在本 candidate 裁决中作为一条早期 repair lineage 处理，不制造两个 `3affd5e8…` residual。
- CVE alias 只与同行 GHSA 绑定：`24vr`→`CVE-2026-53846`、`8wg3`→`CVE-2026-53819`、`fq9j`→`CVE-2026-53842`、`wc84`→`CVE-2026-53858`、`55cf`→`CVE-2026-45003`、`hxvm`→`CVE-2026-44114`、`7wv4`→`CVE-2026-43531`。`4pqj` 和 `8f46` 在取证时仍是 GHSA-only。

## First-party advisory 状态

本页每个精确 GHSA 的 `openclaw/openclaw` repo endpoint 均返回 `state=published`、`withdrawn_at=null`，repo HTML 为 HTTP 200，package 为 `npm/openclaw`，并给出 affected/patched range。这一层足以证明“一方公开发布”，不需要 OSV 背书。

GitHub global/CVE 层必须分开：`4pqj` 和 `8f46` 的 global REST/HTML 为 404、GraphQL 为 `NOT_FOUND`，只能写成当前 GHSA-only，不能改写成 unpublished；其他映射与分层字段见下表。

## 前缀解析

解析来源：分页读取 `GET /repos/openclaw/openclaw/security-advisories` 后做大小写无关前缀匹配。

| 输入前缀 | 匹配数 | 精确 GHSA | repo summary |
|---|---:|---|---|
| `GHSA-55cf` | 1 | `GHSA-55cf-xx38-4p9p` | Workspace dotenv files cannot override connector endpoint hosts |
| `GHSA-hxvm` | 1 | `GHSA-hxvm-xjvf-93f3` | Workspace dotenv could override OpenClaw runtime-control environment variables |
| `GHSA-7wv4` | 1 | `GHSA-7wv4-cc7p-jhxc` | Workspace `.env` could inject OpenClaw runtime-control variables |

## Repo advisory 一方事实

下表字段均来自 `GET /repos/openclaw/openclaw/security-advisories/{ghsa_id}`。`CVSS —` 表示 repo endpoint 未填 score/vector，不表示风险为零。

| Advisory | description 所指 residual / impact | affected → patched | repo severity / CVSS / CWE | reporter | published / updated（UTC） |
|---|---|---|---|---|---|
| [GHSA-24vr-rprv-67rf](https://github.com/openclaw/openclaw/security/advisories/GHSA-24vr-rprv-67rf) | workspace `.env` 的 `npm_execpath` 可改变 bundled dependency install helper 使用的 package-manager executable，运行非预期本地程序 | `< 2026.4.29` → `2026.4.29` | medium / — / — | `feynman-hou` | `2026-05-28T17:39:58Z` / 同值 |
| [GHSA-4pqj-3c56-5fqq](https://github.com/openclaw/openclaw/security/advisories/GHSA-4pqj-3c56-5fqq) | workspace dotenv 可覆盖 provider credentials，并把本应留在 trusted boundary 内的数据或凭据暴露出去 | `< 2026.5.28` → `2026.5.28` | high / 7.1 / CWE-184, CWE-200 | `Har1sh-k` | `2026-06-30T01:11:32Z` / 同值 |
| [GHSA-8wg3-5mcm-fjq8](https://github.com/openclaw/openclaw/security/advisories/GHSA-8wg3-5mcm-fjq8) | workspace `.env` 可覆盖 skill install helper 的 Homebrew executable selection，运行非预期 Homebrew-compatible executable | `< 2026.5.27` → `2026.5.27` | medium / — / — | `feynman-hou` | `2026-05-28T17:39:53Z` / 同值 |
| [GHSA-fq9j-vw4w-fr6v](https://github.com/openclaw/openclaw/security/advisories/GHSA-fq9j-vw4w-fr6v) | `CLOUDSDK_PYTHON` workspace override 可改变 Gmail setup 中 `gcloud` 使用的 Python runtime | `< 2026.5.2` → `2026.5.2` | medium / — / — | `feynman-hou` | `2026-05-28T17:39:54Z` / 同值 |
| [GHSA-wc84-j36w-pw4x](https://github.com/openclaw/openclaw/security/advisories/GHSA-wc84-j36w-pw4x) | `STATE_DIRECTORY` workspace override 可在 runtime dependency root resolution 前改变路径，从非预期 state path 加载 bundled dependencies | `< 2026.5.2` → `2026.5.2` | medium / — / — | `feynman-hou` | `2026-05-28T17:39:55Z` / 同值 |
| [GHSA-8f46-3xx3-8c9m](https://github.com/openclaw/openclaw/security/advisories/GHSA-8f46-3xx3-8c9m) | node exec approval 的 gateway environment 与 node environment 可不一致，使动作越过 caller 的预期授权 | `< 2026.6.5` → `2026.6.5` | high / 8.8 / CWE-863 | `anshumanbh` | `2026-06-30T01:11:26Z` / 同值 |
| [GHSA-55cf-xx38-4p9p](https://github.com/openclaw/openclaw/security/advisories/GHSA-55cf-xx38-4p9p) | workspace dotenv 可设置 Matrix、Mattermost、IRC、Synology 等 connector endpoint variables，把 runtime traffic 重定向到非 operator-configured endpoint | `<= 2026.4.21` → `2026.4.22` | medium / — / CWE-427, CWE-610 | `qi-scape` | `2026-04-23T16:31:58Z` / 同值 |
| [GHSA-hxvm-xjvf-93f3](https://github.com/openclaw/openclaw/security/advisories/GHSA-hxvm-xjvf-93f3) | workspace dotenv 未充分保留 `OPENCLAW_` runtime-control namespace；描述举例 `OPENCLAW_GIT_DIR` 可影响 source-update/installer flow | `< 2026.4.20` → `2026.4.20` | medium / — / CWE-184 | `foodlook` | `2026-04-21T20:37:18Z` / 同值 |
| [GHSA-7wv4-cc7p-jhxc](https://github.com/openclaw/openclaw/security/advisories/GHSA-7wv4-cc7p-jhxc) | workspace `.env` 可注入 runtime-control variables，影响 update sources、gateway URLs、ClawHub resolution、browser executable paths 等 | `< 2026.4.9` → `>= 2026.4.9` | high / — / — | `zsxsoft`；sponsor `KeenSecurityLab` | `2026-04-16T15:19:14Z` / `2026-04-16T15:19:15Z` |

补充字段：

- 本页目标的 repo snapshot 均为 `cve_id=null`、identifiers 仅含对应 GHSA，`vulnerable_functions=[]`。
- `GHSA-4pqj-3c56-5fqq` 的 repo CVSS 是 `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`。
- `GHSA-8f46-3xx3-8c9m` 的 repo CVSS 是 `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`。
- 相关描述保留 OpenClaw trusted-operator model 的作用域限定；可利用性依赖 lower-trust input 是否能到达所述路径。

### Advisory 自带的 fix references

以下为 description 自己声明的引用；本报告又独立验证了 carrier patch-id 与 stable-tag containment：

- `GHSA-55cf-xx38-4p9p`：`0623079e98abf7202591f1b04a89755eb7ec9272`，并声明包含于 `v2026.4.22`。
- `GHSA-hxvm-xjvf-93f3`：`018494fa3ebb9145112e68b56fe1cb2e9f9a9ed6`，声明 fixed in `2026.4.20`。
- `GHSA-7wv4-cc7p-jhxc`：`dbfcef319618158fa40b31cdac386ea34c392c0c` / PR `#62660`，声明首个 stable tag 是 `v2026.4.9`。

## GitHub global / CVEList 分层

GitHub global 列的 CVSS 顺序为 v3.1 / v4.0。表中已映射的 CVEList records 均为 `PUBLISHED`，assigner 均为 VulnCheck，vendor-advisory reference 均回指相应 OpenClaw repo advisory。

| GHSA | GitHub global 状态 / CVE / published_at | global severity / CVSS / CWE | CVEList affected → unaffected | 与 repo/CVE 层的差异或负项 |
|---|---|---|---|---|
| GHSA-24vr-rprv-67rf | [reviewed](https://github.com/advisories/GHSA-24vr-rprv-67rf) / [CVE-2026-53846](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/53xxx/CVE-2026-53846.json) / `2026-06-18T20:33:54Z` | high / 7.1 / 7.0 / CWE-426 | `< 2026.4.29` → `2026.4.29` | repo 是 medium，且 CVSS/CWE 未填 |
| GHSA-4pqj-3c56-5fqq | REST 404；GraphQL `NOT_FOUND`；global HTML 404 | — | 无可观察 CVE mapping | repo 已 published/high/7.1/CWE-184+CWE-200；不能因 global 缺失降成 unpublished |
| GHSA-8wg3-5mcm-fjq8 | [reviewed](https://github.com/advisories/GHSA-8wg3-5mcm-fjq8) / [CVE-2026-53819](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/53xxx/CVE-2026-53819.json) / `2026-07-02T16:57:30Z` | high / 8.8 / 8.7 / CWE-426 | `< 2026.5.27` → `2026.5.27` | repo 是 medium，且 CVSS/CWE 未填 |
| GHSA-fq9j-vw4w-fr6v | [reviewed](https://github.com/advisories/GHSA-fq9j-vw4w-fr6v) / [CVE-2026-53842](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/53xxx/CVE-2026-53842.json) / `2026-06-18T13:04:09Z` | high / 7.1 / 7.0 / CWE-426 | `< 2026.5.2` → `2026.5.2` | repo 是 medium，且 CVSS/CWE 未填 |
| GHSA-wc84-j36w-pw4x | [reviewed](https://github.com/advisories/GHSA-wc84-j36w-pw4x) / [CVE-2026-53858](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/53xxx/CVE-2026-53858.json) / `2026-06-18T20:39:19Z` | high / 7.1 / 7.0 / CWE-426 | `< 2026.5.2` → `2026.5.2` | repo 是 medium，且 CVSS/CWE 未填 |
| GHSA-8f46-3xx3-8c9m | REST 404；GraphQL `NOT_FOUND`；global HTML 404 | — | 无可观察 CVE mapping | repo 已 published/high/8.8/CWE-863；当前只能写 GHSA-only |
| GHSA-55cf-xx38-4p9p | [reviewed](https://github.com/advisories/GHSA-55cf-xx38-4p9p) / [CVE-2026-45003](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/45xxx/CVE-2026-45003.json) / `2026-05-04T20:22:15Z` | medium / v3 未填、v4 5.3 / CWE-427+CWE-610 | `< 2026.4.22` → `2026.4.22` | CVEList 改为 v3 5.0、v4 4.1、CWE-441；三层不一致 |
| GHSA-hxvm-xjvf-93f3 | [reviewed](https://github.com/advisories/GHSA-hxvm-xjvf-93f3) / [CVE-2026-44114](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/44xxx/CVE-2026-44114.json) / `2026-04-25T23:47:05Z` | high / 7.8 / 8.5 / CWE-184 | `< 2026.4.20` → `2026.4.20` | repo 是 medium 且 CVSS 未填；CWE 一致 |
| GHSA-7wv4-cc7p-jhxc | [reviewed](https://github.com/advisories/GHSA-7wv4-cc7p-jhxc) / [CVE-2026-43531](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/43xxx/CVE-2026-43531.json) / `2026-04-17T21:56:12Z` | medium / 8.8 / 6.8 / CWE-15 | `< 2026.4.9` → `2026.4.9` | repo severity 是 high 且无 CVSS/CWE；CVEList 是 v3 7.3、v4 7.0、CWE-15 |

## 保留的负项与元数据冲突

1. **Global 缺失不是 repo 未发布**：`4pqj`、`8f46` 的 repo pages/REST 均公开且 published，但 global REST/HTML/GraphQL 均不能解析。
2. **Repo CVE 字段不能单独用于否定 alias**：目标 repo snapshots 的 `cve_id` 均为 null；除 `4pqj` / `8f46` 当前 GHSA-only 外，表中其余行均有 global + CVEList 显式映射。
3. **缺失 CVSS/CWE 不是零风险**：多条 repo 记录未填 CVSS 或 CWE；global/CVE 层后来补充的字段也可能互相冲突。
4. **`55cf` 三层冲突**：repo/global 用 CWE-427+CWE-610；CVEList 用 CWE-441。global v4 是 5.3，CVEList v4 是 4.1 并另有 v3 5.0。affected 字符串也分别是 `<=2026.4.21` 与 `<2026.4.22`。
5. **`7wv4` severity/score 不一致**：repo 标 high；global 标 medium，但同时给 v3.1 8.8；CVEList 的 v3.1 又是 7.3。不能挑一层覆盖其他层。
6. **`55cf` summary 文案本身含歧义**：summary 写的是“cannot override”，但 Impact 明确描述 affected versions 中 workspace dotenv 可以重定向 endpoints。本报告原样保留标题，以 Impact 说明漏洞行为，不擅自改写一方字段。
7. **前缀解析负项**：所列前缀均唯一命中，没有未解析或多匹配；该结果只在本次分页快照上成立。

## Fact / inference 边界

### 可直接引用的一方事实

- repo advisory 的公开身份、state、withdrawn、summary、description、package、affected/patched、severity、CVSS、CWE、reporter 和时间戳；
- GitHub global record 的 reviewed/CVE mapping，以及 CVEList 的 `PUBLISHED` 状态和 affected ranges；
- description 明列的具体环境变量或类别，以及三个早期 advisory 自带的 fix references。

### 组合证据后的裁决与限制

- PR #63277 body 直接支持 PR-level Codex provenance；member/parent delta、patch-id、tag ancestry 和 later-fix parent 状态由本地一方 Git 对象独立重放。
- `AI_INCOMPLETE_REMEDIATION_RELEASED` 是“候选修复没有覆盖已存在的同类 sink”的组合裁决，不是 advisory 自身的原文，也不是 AI origin 声明。
- reporter、发布时间、patched version、CWE 或“env”共性只用于 routing；`24vr`、`wc84`、`8f46`、`hxvm`、`7wv4` 的负裁决证明这些信号未被当作因果证据。
- 本次没有重建 npm tarball；release 门依据 Git stable-tag ancestry 与 tag 中的 `package.json` version。`55cf` advisory 自身另声明 npm artifact 包含 fix，但那是一方公告事实，不写成本次独立 tarball 验证。

## 可重放命令

以下命令适用于 zsh，不输出 token：

```zsh
repo=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw

# 抓取 candidate 及 later-fix PR heads；不修改 main/worktree。
for pr in 63277 73262 83655 74463 74492 75940 81488 70240 69376 62660; do
  git -C "$repo" fetch origin \
    "+refs/pull/$pr/head:refs/remotes/origin/pr-$pr-head"
  gh api "repos/openclaw/openclaw/pulls/$pr" \
    --jq '[.number,.base.sha,.head.sha,.merge_commit_sha,.merged_at,.title,.body]'
  gh api --paginate "repos/openclaw/openclaw/pulls/$pr/commits" \
    --jq '.[] | [.sha,.parents[0].sha,.commit.message]'
done

# Candidate atom/parent 与会影响 workspace dotenv 的 sibling-family delta。
git -C "$repo" show --stat --patch \
  3affd5e8f9ca6e2f51d00bebde6c1c277e8a5161
for rev in \
  71617ef2f056e786a39362542594090854ce62bd \
  3affd5e8f9ca6e2f51d00bebde6c1c277e8a5161 \
  2d126fc62343a7b6895351f96e4e1474bc358140; do
  print -- "===== $rev"
  git -C "$repo" show \
    "${rev}:src/infra/host-env-security-policy.json" |
    jq -r '[.blockedEverywhereKeys[],.blockedOverrideOnlyKeys[]]|unique[]' |
    rg '^(AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)|AZURE_CLIENT_(ID|SECRET)|GH_TOKEN|GITHUB_TOKEN|AMQP_URL|DATABASE_URL|MONGODB_URI|REDIS_URL|CLOUDSDK_CONFIG|CLOUDSDK_CORE_PROJECT|CLOUDSDK_PYTHON|HOMEBREW_(BREW_FILE|CELLAR|PREFIX|REPOSITORY)|STATE_DIRECTORY|NPM_EXECPATH)$' || true
  git -C "$repo" show "${rev}:src/infra/dotenv.ts" |
    rg -n -C 4 'shouldBlockWorkspaceRuntimeDotEnvKey|shouldBlockWorkspaceDotEnvKey|isDangerousHost'
done

# Squash carriers 与 PR delta 的 patch-id 等价性。
carrier_specs=(
  63277:2d126fc62343a7b6895351f96e4e1474bc358140
  73262:ccb3af556fcb1618f30e94bdd55f77cec07c45a0
  83655:85277c2db1fa98af84b234df91bbab1f87a37d96
  74463:f86953f354e0d0e5286e57ad99acadc157b2891b
  74492:86251f43916d8210d38d8f69c9fb0b0070a88fdf
  75940:42dfc36da50ad81c3fb2fef64e7849e6bbda8283
  81488:c208a1061951ba37bf98eaa8ba7b810f7a8ec548
  70240:0623079e98abf7202591f1b04a89755eb7ec9272
  69376:018494fa3ebb9145112e68b56fe1cb2e9f9a9ed6
  62660:dbfcef319618158fa40b31cdac386ea34c392c0c
)
for spec in $carrier_specs; do
  pr=${spec%%:*}
  carrier=${spec#*:}
  base=$(gh api "repos/openclaw/openclaw/pulls/$pr" --jq .base.sha)
  head=$(git -C "$repo" rev-parse "refs/remotes/origin/pr-$pr-head")
  merge_base=$(git -C "$repo" merge-base "$base" "$head")
  pr_patch=$(git -C "$repo" diff "$merge_base" "$head" |
    git patch-id --stable | cut -d' ' -f1)
  carrier_patch=$(git -C "$repo" diff "$carrier^" "$carrier" |
    git patch-id --stable | cut -d' ' -f1)
  print -- "$pr pr_patch=$pr_patch carrier_patch=$carrier_patch"
done

# later-fix 最小 production members；负项也保留它们的 exact-fix 证据。
fix_members=(
  b1a84c3279c50a28d5bf73aa6081dcb174c813eb
  6d31c78cbb9b92624ee493171e7626d4c89cf170
  6852e4a13ad15bcd5dff0aa84cc9b5b30785d07e
  734a35d950ea6d9f3c5109c49acc8af05bb99d74
  67619d87d39557ed8e27537d9da3921e61b827d6
  57400d735a611b2b61fdac6b84bdda419615fd9d
  9a6dced78af3fe9e44a1b525c984c84efbfc731e
  092dc3ee8b1bd9159fdc99d7c397bf37d389020c
  69f20e86b84ce8385588b7765f2afa615f5d2e94
  d5a07f0a6543487d37b63efe6b59bba451b72c38
  8d2fa50ff476d5787648a95a453c9d88c8841f33
  faa4d99094b9caf60d8e1f955816dd3c758341ca
  2419571e105ec8796f02b18673d884b9b858f5e1
  f4a634e13f41ff99167b8c610e71a54510fda40e
  b783302e90bd2c3976eb3029e3790d60d1917dd2
  bc4f47c41b0cb20b49e8b27b49e8342b2da188af
)
for sha in $fix_members; do
  git -C "$repo" show --stat --patch "$sha"
done

# Release gate：输出即 carrier 已发布但 exact fix 未发布的 stable tags。
candidate=2d126fc62343a7b6895351f96e4e1474bc358140
fix_carriers=(
  ccb3af556fcb1618f30e94bdd55f77cec07c45a0
  85277c2db1fa98af84b234df91bbab1f87a37d96
  f86953f354e0d0e5286e57ad99acadc157b2891b
  86251f43916d8210d38d8f69c9fb0b0070a88fdf
  42dfc36da50ad81c3fb2fef64e7849e6bbda8283
  c208a1061951ba37bf98eaa8ba7b810f7a8ec548
  0623079e98abf7202591f1b04a89755eb7ec9272
  018494fa3ebb9145112e68b56fe1cb2e9f9a9ed6
  dbfcef319618158fa40b31cdac386ea34c392c0c
)
git -C "$repo" show -s --format='%H%n%P%n%s' \
  3affd5e8f9ca6e2f51d00bebde6c1c277e8a5161 \
  $fix_carriers
for fix in $fix_carriers; do
  # Carrier^ 是表中的 later-fix direct parent；patch 同时显示
  # parent 保留的危险路径与 carrier 关闭的 invariant。
  git -C "$repo" show --stat --patch "$fix"
  git -C "$repo" tag --contains "$candidate" --no-contains "$fix" \
    --sort=version:refname | rg '^v[0-9]{4}\.[0-9]+\.[0-9]+$' || true
done

# Post-candidate sink 负控：所列 sink 都不是 candidate ancestor，且首见更晚 tag。
for sink in \
  6d409a61820c008bd5cf64c0c22dee31a3792bb7 \
  a99490fba4af1dc52bde0a8c2c2916e1757d9662; do
  git -C "$repo" merge-base --is-ancestor "$sink" "$candidate"
  rc=$?
  print -- "$sink ancestor_of_candidate_rc=$rc"
  git -C "$repo" tag --contains "$sink" --sort=version:refname |
    rg '^v[0-9]{4}\.[0-9]+\.[0-9]+$' | head -1
done

# Post-candidate sink 与 carrier 的真实共存交集；不使用多个
# `git tag --contains` 直接求交，因为 Git 对重复 contains 选项取 OR。
for spec in \
  6d409a61820c008bd5cf64c0c22dee31a3792bb7:ccb3af556fcb1618f30e94bdd55f77cec07c45a0 \
  a99490fba4af1dc52bde0a8c2c2916e1757d9662:42dfc36da50ad81c3fb2fef64e7849e6bbda8283; do
  sink=${spec%%:*}
  fix=${spec#*:}
  for tag in ${(f)"$(git -C "$repo" tag --contains "$candidate" \
    --no-contains "$fix" --sort=version:refname | \
    rg '^v[0-9]{4}\.[0-9]+\.[0-9]+$')"}; do
    git -C "$repo" merge-base --is-ancestor "$sink" "$tag" || continue
    print -- "$sink $tag"
  done
done

# 早期 namespace 链路；前两条预期 rc=0，反向预期 rc=1。
git -C "$repo" merge-base --is-ancestor \
  dbfcef319618158fa40b31cdac386ea34c392c0c \
  71617ef2f056e786a39362542594090854ce62bd
git -C "$repo" merge-base --is-ancestor \
  dbfcef319618158fa40b31cdac386ea34c392c0c "$candidate"
git -C "$repo" merge-base --is-ancestor \
  "$candidate" dbfcef319618158fa40b31cdac386ea34c392c0c

# Homebrew advisory 版本与 code-history 冲突。
for tag in v2026.5.2 v2026.5.26 v2026.5.27; do
  git -C "$repo" grep -n -E \
    'HOMEBREW_BREW_FILE|HOMEBREW_PREFIX|resolveBrewExecutable' \
    "$tag" -- src/infra/dotenv.ts src/infra/brew.ts src/agents/skills-install.ts
done
git -C "$repo" log --first-parent --format='%H %ad %s' --date=short \
  f86953f354e0d0e5286e57ad99acadc157b2891b..v2026.5.27 -- \
  src/infra/dotenv.ts src/infra/brew.ts src/agents/skills-install.ts

ids=(
  GHSA-24vr-rprv-67rf
  GHSA-4pqj-3c56-5fqq
  GHSA-8wg3-5mcm-fjq8
  GHSA-fq9j-vw4w-fr6v
  GHSA-wc84-j36w-pw4x
  GHSA-8f46-3xx3-8c9m
  GHSA-55cf-xx38-4p9p
  GHSA-hxvm-xjvf-93f3
  GHSA-7wv4-cc7p-jhxc
)

# 全量分页解析三个前缀；输出应恰为三个精确 ID。
gh api --paginate --slurp \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  '/repos/openclaw/openclaw/security-advisories?per_page=100' |
  jq '[.[][] | select(
    (.ghsa_id | ascii_downcase | startswith("ghsa-55cf")) or
    (.ghsa_id | ascii_downcase | startswith("ghsa-hxvm")) or
    (.ghsa_id | ascii_downcase | startswith("ghsa-7wv4"))
  ) | .ghsa_id] | sort'

# Repo advisory 全字段。
for id in $ids; do
  gh api -H 'X-GitHub-Api-Version: 2022-11-28' \
    "/repos/openclaw/openclaw/security-advisories/$id" \
    --jq '{ghsa_id,state,cve_id,identifiers,summary,description,severity,cvss,cvss_severities,cwes,vulnerabilities,published_at,updated_at,withdrawn_at,credits,url,html_url}'
done

# Global 层；4pqj/8f46 预期 rc=1、HTTP 404。
for id in $ids; do
  gh api -H 'X-GitHub-Api-Version: 2022-11-28' "/advisories/$id" \
    --jq '{ghsa_id,cve_id,type,summary,description,severity,cvss,cvss_severities,cwes,vulnerabilities,published_at,updated_at,withdrawn_at,references,html_url}'
  rc=$?
  print -- "$id global_rest_rc=$rc"
done

# `4pqj` / `8f46` global 负项的 GraphQL 复核；预期 NOT_FOUND。
for id in GHSA-4pqj-3c56-5fqq GHSA-8f46-3xx3-8c9m; do
  gh api graphql -F ghsaId="$id" \
    -f query='query($ghsaId:String!){securityAdvisory(ghsaId:$ghsaId){ghsaId identifiers{type value} severity publishedAt updatedAt withdrawnAt permalink}}'
done

# Repo/global 公开 HTML 状态。
for id in $ids; do
  curl -L -sS -o /dev/null -w "$id repo=%{http_code} global=" \
    "https://github.com/openclaw/openclaw/security/advisories/$id"
  curl -L -sS -o /dev/null -w "%{http_code}\\n" \
    "https://github.com/advisories/$id"
done

# 表中已映射的官方 CVEList records。
for spec in \
  53xxx/CVE-2026-53846.json \
  53xxx/CVE-2026-53819.json \
  53xxx/CVE-2026-53842.json \
  53xxx/CVE-2026-53858.json \
  45xxx/CVE-2026-45003.json \
  44xxx/CVE-2026-44114.json \
  43xxx/CVE-2026-43531.json; do
  gh api -H 'Accept: application/vnd.github.raw+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "/repos/CVEProject/cvelistV5/contents/cves/2026/$spec" \
    --jq '{cveMetadata:.cveMetadata,cna:{title:.containers.cna.title,affected:.containers.cna.affected,references:.containers.cna.references,metrics:.containers.cna.metrics,problemTypes:.containers.cna.problemTypes}}'
done
```

## Source URLs

所有 repo advisory URLs 已链接在 repo 表；已映射的 global advisory 和 CVEList URLs 已链接在 global/CVE 表。当前 global 负项的 canonical repo URLs 是：

- <https://github.com/openclaw/openclaw/security/advisories/GHSA-4pqj-3c56-5fqq>
- <https://github.com/openclaw/openclaw/security/advisories/GHSA-8f46-3xx3-8c9m>
