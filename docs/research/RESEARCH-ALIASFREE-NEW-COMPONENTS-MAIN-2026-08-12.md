# AI 安全失败双口径主报告（2026-08-12）

## 结论

用户确认“AI 修漏洞但没有修完整”也应计入研究对象。这个判断可以成立，但必须与“AI 首次引入漏洞”分开标注，否则会把净减风险的安全修复反写成漏洞 origin。

本报告采用互斥的两类正例：

1. `STRICT_CAUSAL`：AI 原子提交首次创建、重新引入，或实质新增了 advisory 所述攻击面；
2. `AI_INCOMPLETE_REMEDIATION`：漏洞或更宽攻击面早已存在，AI 明确尝试修复同一安全机制，但发布后的实现仍留有具体绕过，后续一方修复精确关闭该残留。

当前组件级 census 为：

| 层级 | 组件数 | 含义 |
|---|---:|---|
| 冻结 strict-200-v3 | 110 | 已有发布级 `STRICT_CAUSAL` 基线 |
| 新增、已完整闭合的 strict | +6 | Batch A 3、Hermes 2、Coolify 1 |
| OpenClaw strict closure | +9 | 12 个 frontier 经原子重放后 9 PASS / 3 FAIL |
| **严格发布级确认下界** | **125** | `110 + 6 + 9` |
| 新增、已发布的不完整 AI 修复 | +48 | Batch E 再增 17；和 strict public IDs 零交集 |
| **宽口径发布级确认下界** | **173** | `125 strict + 48 incomplete remediation` |
| 未独立发布的 commit-only | +13 | incomplete 12、strict 1；不进入发布级下界 |
| **最宽 commit-level 工作数** | **186** | 不应写成发布级样本数 |

因此，面向论文或公开统计时可使用 **125 个 strict 发布级组件**；按用户确认的宽口径，则是 **173 个发布级确认组件**。`186` 只适合 commit-level 研发统计。

冻结基线文件：

```text
research/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl
110 components / 200 case-normalized public IDs
SHA-256 0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81
```

本报告没有修改 ledger、adjudication JSON、脚本或产品代码。

## 判定门

### `STRICT_CAUSAL`

必须同时满足：

1. 一方 CVE/GHSA 已发布且未撤回；
2. AI marker 位于真实原子 causal commit，自身可读，不能从 merge/squash/release carrier 反投影；
3. `candidate^ -> candidate` 新增或重开 advisory 所述输入、信任边界和 sink；
4. 一方 fix 或完整 fix-set 对该增量有精确 reversal；
5. direct ancestry 或 squash member/carrier topology 闭合；
6. public ID、official alias、仓库、accepted edge 和机制指纹均未与基线重复。

### `AI_INCOMPLETE_REMEDIATION`

发布级正例必须同时满足：

1. candidate 自身有明确 AI 归因；
2. candidate 的主题或 delta 明确在修复同一安全机制，不是普通功能或邻近文件改动；
3. candidate 发布后仍存在具体、可复述的 residual/bypass；
4. 一方 advisory 指向该残留，后续 first-party fix 精确关闭它；
5. 残缺 candidate 至少进入一个受影响发布版本；
6. 只标 `incomplete remediation`，不标 `origin`。

同一 PR 或同一发布前被 review 修掉的临时 commit 只进入 `COMMIT_ONLY`，不进入发布级下界。OSV `introduced`、同文件、blame、模型票和 commit subject 只能用于 routing。

## 新增的 6 个已完整闭合 strict 组件

| Public component | Repo | Atomic AI origin | First-party reversal | 裁决 |
|---|---|---|---|---|
| CVE-2026-40069 / GHSA-9HFR-GW99-8RHX | sgbett/bsv-ruby-sdk | `a1f2e62cb3dc48014c1770ec44d61811ae4b7105` | member `db97de475518eef752ed52b25f49f09cbe24c187`, carrier `4992e8a265fd914a7eeb0405c69d1ff0122a84cc` | ARC broadcaster 首次把多种失败状态当成功 |
| CVE-2026-40070 / GHSA-HC36-C89J-5F4J | sgbett/bsv-ruby-sdk | `d14dd19f976eb5e92e0ea6755e56864f5b1ae047` + `6a4d8984026dc8f533d408f8ea737af7f7b2713d` | 同一 member `db97de475518eef752ed52b25f49f09cbe24c187` | direct/issuance 两条路径持久化未验证证书签名；一个组件 |
| CVE-2026-45136 / GHSA-G3XQ-3GMV-QQ8G | cnighswonger/claude-code-cache-fix | member `e19169011a7ca59c3ccee67c626c658ba47eb275`, carrier `7b9322a86a5cae3230c30943bd659d7f67b0387c` | member `0a3e3c130e1ec803a2107fe83775d97f5f8f6dde`, carrier `613e4df30547f3e6baf32d161eddc828f171da17` | hook JSON 被插入 triple-quoted Python source |
| CVE-2026-49973 / GHSA-P52P-4VMG-4VQ3 | nesquena/hermes-webui | `b8b62722ec2f6b3cd394737ab409c35650f29ca6` | member `f2ef2851d389cf7a41308dcf0180d7cfbe446379`, carrier `1126e541325d401538f6a272a9c024c37d47ae08` | 首次密码建立可被远程先到者接管 |
| CVE-2026-49956 / GHSA-MGXW-V6RH-WCV6 | nesquena/hermes-webui | `d2b27f6f1edb83634730f93dc8f19721d877bd07` | member `8d8ae89d27a4547b2edc388a986ef0d55549f7d4`, carrier `2c7b530071bb29ae4184e83e33be5799d529568e` | AI 在已有 session search 上新增 multi-profile 隔离边界，但没有给 search 加 active-profile 过滤；parent 不存在该跨 profile 路径 |
| CVE-2026-34198 | coollabsio/coolify | `e1fe58639756cf7b232458eddd6978e4ed0031f5` | member `e1d4b4682efc898ba5aa3751b2da2072f89c7e24`, carrier `98569e4edbfc316877c9e0d27ea89fab3c49e3bd` | Conductor 自动提交首次加入 trust-host negative-cache early return |

前三项的完整一方证据、member/carrier 分离、ancestry 与去重见：

```text
RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md
SHA-256 a7dd3db373af0fae98c10f8c96c58180cf80fc132fb6fb53fedbd44f3aae22c2
```

Hermes 与 Coolify 的结论使用本地 first-party Git、CVEList CNA、repo advisory 和原子 fix member；carrier 只表达 topology。

## OpenClaw strict closure：9 PASS / 3 FAIL

原 12 个 `FRONTIER_PASS` 已逐项完成原子提交、squash transfer、fix reversal 和 release witness 重放。最终只接受 9 个语义组件；原第 8、11、12 行分别因 AI hunk 在 squash 前被擦除、ghost-blame、无机制连接而 FAIL。

| # | Public advisory / mechanism | Accepted AI edge |
|---:|---|---|
| 1 | GHSA-H2VW-PH2C-JVWF：MiniMax dotenv redirect | `7d7f5d85… -> 2f066965…` |
| 2 | GHSA-G8P2-7WF7-98MQ：gatewayUrl token exfiltration/RCE | `c74551c2… -> a7534dc2…` |
| 3 | GHSA-9F72-QCPW-2HXC：prompt image `workspaceOnly` | `8d74578c… -> 370d1155…` |
| 4 | GHSA-XQ94-R468-QWGJ：Browserbase CDP DNS rebinding contributor | `75602014… -> 121c452d…` |
| 5 | GHSA-W85G-3H6X-4XH2：sips pixel DoS contributor | `8d74578c… -> 0ed4f8a7…` |
| 6 | GHSA-MF5G-6R6F-GHHM：Synology rate limit | member `cc048a29…`, carrier `03586e3d… -> 0b4d0733…` |
| 7 | GHSA-2QRV-RC5X-2G2H / GHSA-82QX-6VJ7-P8M2：workspace shadow，同一机制组件 | member `fc1b156d…`, carrier `f4cc93dc… -> 53c29df2… + 1fede43b…` |
| 9 | GHSA-XH72-V6V9-MWHC / GHSA-G353-MGV3-8PCJ：Feishu webhook，同一机制组件 | `b0c67ea… -> 7844bc89… / c8003f1b…` |
| 10 | GHSA-2Q7J-2VHX-56G8 / GHSA-W8WF-3QVJ-6XQF：Feishu account tool gate，同一机制组件 | `5f6e1c19… -> d4f11d30…` |

完整逐项证据见 `RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md`（SHA-256 `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6`）。不得把 merge/squash carrier 当成 AI 原子 origin。

## 48 个发布级 `AI_INCOMPLETE_REMEDIATION`，另有 13 个 commit-only

### 已有 13 个因果闭合组件（其中 11 个发布级）

| # | Public component | Repo | AI partial remediation -> complete fix | 精确残留 |
|---:|---|---|---|---|
| 1 | GHSA-5WP8-Q9MX-8JX8 | qhkm/zeptoclaw | `91f6c2bf…`, `d3480ca9…`, member `3c4368da…` -> `68916c3e…` | literal glob、combined flags、first-token chaining、empty Strict allowlist 绕过 |
| 2 | CVE-2026-47390 / GHSA-5C6W-WWFQ-7QQM | mervinpraison/praisonai | `3cd664bf7b7db5f774c1e7e3123a1a24c68ba700` -> `179cab02dbec0c1e9b601507a65908e079876004` | SSRF exact-string blocklist 漏 numeric/hex/alternate loopback encodings |
| 3 | CVE-2026-47392 / GHSA-4MR5-G6F9-CFRH | mervinpraison/praisonai | 同一 `3cd664bf… -> 179cab02…` | pseudo-sandbox 可由 `print.__self__` 等对象图绕过；独立 Python-exec 组件 |
| 4 | CVE-2026-54526 | argoproj/argo-workflows | `251bb231… -> 358cc396…`; v4 copy `2727f3f7… -> 277e9cef…` | WorkflowSpec allowlist 整块放行 ArtifactGC nested fields；两分支一个组件 |
| 5 | CVE-2026-50570 / GHSA-QF5V-M7P4-95RP | fission/fission | member `2db76f65…`, carrier `e484df84… -> 2569b42b…` | capability denylist 漏 `SYS_TIME`，后改 allowlist |
| 6 | CVE-2026-44430 / GHSA-R48C-V28R-PF6V | modelcontextprotocol/registry | member `257eb178…`, carrier `1201cbd8… -> f5f40bd9…` | `safeDialContext` 漏 6to4、NAT64、site-local IPv6 |
| 7 | CVE-2026-50566 / GHSA-M63V-2G9W-2W6V | fission/fission | member `2db76f65…`, carrier `e484df84… -> 695d3e97…` | **COMMIT_ONLY**：只校验 PodSpec containers，漏 Runtime/Builder standalone container |
| 8 | CVE-2026-50568 / GHSA-R5JH-Q2MW-GCX4 | fission/fission | member `0d851525…`, carrier `5a3d68a3… -> 8298e33e…` | lexical `HasPrefix` path sanitizer 有 sibling-prefix 绕过，后换 `os.Root` confinement |
| 9 | CVE-2026-33632 / GHSA-WPXJ-VHFP-HHVM | craigjbass/clearancekit | `a3d1733d2691a0d40209c48b01bf9291bf645207` -> `6181c4a22eccbeca973c77f4bd023eb795c13786` | AI 从 AUTH_OPEN 扩到七类事件，却漏 AUTH_EXCHANGEDATA / AUTH_CLONE |
| 10 | CVE-2026-34745 / GHSA-FVVP-RJ8G-C7GC | ShaneIsrael/fireshare | `157386c85f6683f89192dae52115069b435b6d34` -> member `70b5b35aadd55c7936a25effd6f3e9ee4c124879`, carrier `b76915607924756e6fa1a5f6c8823c38d611fb24` | authenticated upload 已清理 filename，但公开 sibling 的 attacker `checkSum` 仍进入 temp path |
| 11 | CVE-2026-54094 / GHSA-239W-M3H6-CH8V | filebrowser/filebrowser | `847d08bdd135e5c3659f2e6dea2f0cd36617af9b` -> intermediate `7c2c0a11b31b2bb214d741005a0b02b1764208b3` -> final `64511ce45e3be379e965f7f4fb0929a068d5bb81` | caller-specific symlink check 先由 human `ScopedFs` redesign 集中；最终 closure 才补 dangling write 与 unguarded delete。两个独立 residual 另在 Batch D 计数 |
| 12 | GHSA-P5RM-JG5C-8C77 | microsoft/kiota | member `f51f4971ea3459cd410b363b34e156a116b530f4`, carrier `de3d18d9fe31ced4ac749728d3a2f94811f59268` -> `430008e9d700b3fe80f206c672415cfbd8e830e7` | **COMMIT_ONLY**：最多五轮 percent-decode 后 fail-open，另漏 NUL/control 与 Unicode full-width traversal |
| 13 | CVE-2026-47137 / GHSA-M4WX-M65X-GHRR | patriksimek/vm2 | `46cbbdde4e19b743974c942278080231004146ca` -> `01a7552add345d5a6862623884e6b79a85bf0568` -> `86ab819f202c3a8dad88cef5705f2e416c5188d7` | guard 只拒绝 `{nesting:true, require:false}`，漏 omitted/falsy/non-object require 和 truthy non-boolean nesting |

这些组件在 causal-v2 中因不满足 strict but-for 被正确排除；本报告只是在新的宽口径下重新分类，不改写旧报告的 strict 结论。发布 topology 重放后，表中 1–6、8–11、13 计入发布级；7 和 12 只计 commit-level。

两个降级都有直接 tag 反证：Fission carrier `e484df8460bb4e8026e24210120602aa7f181f64` 与 complete fix `695d3e97e3a20463ab7c8c081843e69e65e952e5` 都首次进入 `v1.24.0`；Kiota carrier `de3d18d9fe31ced4ac749728d3a2f94811f59268` 与 complete fix `430008e9d700b3fe80f206c672415cfbd8e830e7` 都首次进入 `v1.34.0`。两组 `git tag --contains partial --no-contains complete` 均为空。

### 新确认的 7 个 GitPython 发布级组件

GitPython 的一组公开 advisory 给出了很干净的“AI 安全修复 -> 发布 -> residual -> 后续修复”序列。候选均由 `GPT 5.5/5.6 <codex@openai.com>` 直接 author，不依赖 carrier 继承。

| Public advisory | AI partial remediation / 首个含它的 tag | Later fix / patched release | Residual mechanism |
|---|---|---|---|
| GHSA-R9MR-M37C-5FR3 | `701ce32fe5ba8cb622c0e0342a376a6beb47d738` / 3.1.51 | `e8d0fbf774d1f6baa3b481adfe48bd262e43b453` / 3.1.54 | `_option_candidates` 只检查单字符 kwarg key，value 被拆成第二个 option token |
| GHSA-94P4-4CQ8-9G67 | `8ac5a30519b6f4af85398b9b9d7064ff4d452da2` / 3.1.52 | `863417457a0633db7ea5aed4fd01e0b291a41162` / 3.1.55 | clone caller 禁止 env expansion，但 Remote.create/Submodule.add sibling 仍扩展 URL 中的环境变量 |
| GHSA-6P8H-3WGX-97GF | `701ce32fe5ba8cb622c0e0342a376a6beb47d738` / 3.1.51 | `ffcb5359e87619f4fe4a70a4aff5f08c5580ba97` / 3.1.54 | clone unsafe-option denylist 漏 `--template`，可安装并运行 hook |
| GHSA-3RP5-JJMW-4WV2 | `54538428f79b0c91ba52cda5229856a6edf7ac06` / 3.1.50 | `1ed1b924f4e2d2ee7bab296df77b978af21853f1` / 3.1.53 | config name 只拒 CR/LF/NUL，未拒能闭合 section header 的未加引号 `]` |
| GHSA-539M-9XH6-Q6RR | `701ce32fe5ba8cb622c0e0342a376a6beb47d738` / 3.1.51 | `7a4f5dcb7bf3cbcbf6e438017efcdfe0bc0d36ca` / 3.1.57 | archive denylist 漏 `--add-file` / `--add-virtual-file`，另漏 clone `--bundle-uri` |
| GHSA-P538-C434-8V24 | `701ce32fe5ba8cb622c0e0342a376a6beb47d738` / 3.1.51 | `38553b6fddc7f6a667cdb45a6762343a08fc72b2` / 3.1.56 | guarded revision siblings 之外，`Commit.count()` 仍把 `--output` 传给 rev-list |
| GHSA-3F7W-8RR8-F37F | `1d51b891d7f236044a6aa17498ec682b63dad6e6` / 3.1.54 | `3af0c2516c5e18c829da30338614688f6b69b49c` / 3.1.57 | Diffable.diff 已 guard，但 IndexFile.checkout / TagReference.create sibling 仍转发危险 option |

Repo advisory API 于 2026-08-12 返回七项均 `state=published`、`withdrawn_at=null`。它们的受影响/修复版本分别闭合到 3.1.53/3.1.54、3.1.53/3.1.55、3.1.53/3.1.54、3.1.52/3.1.53、3.1.56/3.1.57、3.1.55/3.1.56、3.1.56/3.1.57。

一方 API 也不是自动真值：GHSA-539M-9XH6-Q6RR 与 GHSA-3F7W-8RR8-F37F 当前的 `patched_versions` 原始字段反常地写成 `<= 3.1.57`。本报告不用该操作符做证明，而是用 fix commit 的首个 contains-tag `3.1.57`、前一版 `3.1.56` 及代码 reversal 闭合发布边界。

`181e8ede… -> 56806080…` 没有单独发布：两者一起首次进入 3.1.51，所以不把同 PR 中间态另算一个发布级漏洞。

### 新确认的 Coolify 发布级组件

| Public component | AI partial remediation | Later fix | Residual and release proof |
|---|---|---|---|
| CVE-2026-42204 / GHSA-CHG4-63HM-XV9X | `c9922c30c2a6bf922653a5f2d631aab4fea685c4` (parent `e39678aea584be533f89052d4e2939f2d8834449`, Claude Opus 4.6 trailer) | member `817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1` (parent `1cf6c7d0aef8e0edb800ae43f44ded102397cb13`), carrier `e1aac50b745cf499e710b7e35cd2a9d6a1538dd9` | AI 明确给 install/build/start commands 加 `shellSafeCommandRules()`，但扁平 regex 明文允许 bare `&`；后续 token-aware grammar 才区分 `&&`/`||` 并拒绝 bare `&`。candidate 进入 beta.471，CVE 影响 beta.471-beta.473。 |

## 首批 commit-only：3 个因果成立但未独立发布的残缺修复

- Fission CVE-2026-50566 / GHSA-M63V-2G9W-2W6V：`e484df8460bb4e8026e24210120602aa7f181f64 -> 695d3e97e3a20463ab7c8c081843e69e65e952e5`，两者首次同在 `v1.24.0`。
- Kiota GHSA-P5RM-JG5C-8C77：`de3d18d9fe31ced4ac749728d3a2f94811f59268 -> 430008e9d700b3fe80f206c672415cfbd8e830e7`，两者首次同在 `v1.34.0`。
- Coolify CVE-2026-34167：下述 partial/final 都首次进入 `v4.0.0-beta.471`。

### Coolify CVE-2026-34167 的机制

`a94517f452e225046e01c08385d6a7aedf085c7d`（parent `69ea7dfa50f431fd205b2adb18b04d41c92443f2`，Claude Opus 4.6）明确尝试 scope ActivityMonitor lookup，但在 `team_id` 缺失时 fail-open，测试也把允许行为固化。后续 member `3e0d48faeaab950bfd063dfca908f1d140316ede`（parent `c8efbf107a339d9b4c4cadaaf7761154471d0993`）加 `#[Locked]`、team/server ownership fallback、无归属 fail-closed，并在活动创建时写入 `team_id`；carrier 为 `2729dffb3e30167c1ffd642357b7e0bb99b7d180`。

这条机制成立，但 candidate 与完整修复都首次进入 beta.471，没有独立发布过残缺 candidate。因此：

- commit-level：`PASS AI_INCOMPLETE_REMEDIATION_COMMIT_ONLY`；
- release-level：不进入发布级下界，只进入 commit-level 工作数。

## Batch B：再确认 4 个发布级、5 个 commit-only

发布级新增为 n8n-mcp CVE-2026-42449 / GHSA-56C3-VFP2-5QQJ，以及 Prospero CVE-2026-59233、CVE-2026-59234、CVE-2026-59240。commit-only 新增为 Dynatrace GHSA-P7W7-4929-VPJ5、WACRM CVE-2026-49141、MISP CVE-2026-56422、OmniFaces GHSA-FP43-VJ7G-PG92 四个 incomplete-remediation 组件，以及 Prospero CVE-2026-59237 一个 strict origin 组件。

完整 candidate/parent/fix、release tag 和反例见 `RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md`（SHA-256 `318912fbc789ef7f0708044d2041c24fa69198f878c2c668b04af86031d4616e`）。

## Batch C：再确认 1 个发布级 contributor、3 个 commit-only incomplete remediation

- Langroid CVE-2026-25481 / GHSA-X34R-63HX-W57F：Copilot atomic member `b1c45e3f...` 把错误的 `config.full_eval` 改为 `self.config.full_eval`，使 PR branch 从 fail-closed 进入弱 AST sanitizer 后的 `eval`。残缺 carrier `0d9e4a7b...` 在 `0.53.15` 至 `0.59.31` 发布；`30abbc1a...` 才拒绝一方 PoC 使用的 dunder attribute gadget。只标 incomplete-remediation contributor，不标 AI 独立 origin。
- Vitest CVE-2026-53633 / GHSA-G8MR-85JM-7XHM：Codex partial 引入 write/exec gates，但漏 raw CDP 等价高权限通道；`385a1aef...` 精确补 gate。两者首次同在 `v3.2.5`。
- Mistune CVE-2026-59923 / GHSA-8C25-4J27-2RV3：Claude partial 把 image directive 接入 `safe_url`，但 percent-encoded scheme 仍绕过；`c7101fcb...` 补 decode-before-check。
- Mistune CVE-2026-59929 / GHSA-QFRW-5RXM-MHH2：同一 partial 留下独立的 legacy/chained-scheme denylist gap；同一 closure 扩充策略。两者与 partial 都首次在 `v3.3.0` 发布。

完整代码差分、first-party advisory、tag gate 与 attribution 反例见 `RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-C-2026-08-12.md`（SHA-256 `b1e03cb193003ebbba83b73b8d8bbcbcd72f02148ba00812967a2721e60a8ffd`）。

## Batch D：再确认 7 个发布级 incomplete remediation

- fast-uri CVE-2026-18446 / GHSA-7P8R-X3MC-P8W7：Claude partial 只拒绝合法 `//` authority 内的 literal backslash；`v4.1.1` 仍漏 `\\`、`/\`、`\/` 与 whitespace-split authority introducers，`f3c6c905...` 才闭合。
- Locutus CVE-2026-33994 / GHSA-VC8F-X9PP-WF5P：Claude partial 用 `RegExp.prototype.test` 替代可覆写的 `String.prototype.includes`，但攻击者同样可覆写 regex prototype；`345a6211...` 在 assignment sink 用 `Set.has` 拒绝危险 path segments。
- Gitea CVE-2026-58432 / GHSA-Q9PG-JJ6X-J9P6：Copilot partial 给 API draft-release/attachment routes 加 write gate，却漏 UUID-based web download siblings；`f7fd5102...` 在 `ServeAttachment` 补同一 gate。
- Scriban GHSA-Q6RR-FM2G-G5X8：Copilot resource-bound remediation 覆盖多种 expression operations，却漏 `array * int` sibling；`205ca6a7...` 补 `LoopLimit`、安全长度与 `StepLoop`。
- Faraday CVE-2026-33637 / GHSA-5RV5-XJ5J-3484：Claude partial 修 string `//host`，但支持的 `URI("//host")` input 仍可 override base host；`3f1280c6...` 统一转 string 后 guard。
- File Browser CVE-2026-55667 / GHSA-FMM7-X4GX-8JHR：symlink-scope remediation 链漏 `Remove` / `RemoveAll` guard，failed-upload cleanup 可越 scope 删除且绕过 Delete permission。
- File Browser CVE-2026-55668 / GHSA-8WC8-HF36-MJH9：同一链另漏 dangling-symlink write，`OpenFile(O_CREATE)` 可在 scope 外创建文件。它与删除项的 sink、权限、PoC 和 public IDs 独立，故不按 alias 合并。

完整 parent/candidate/fix、release tags、一方 advisory、去重负控与 replay 命令见 `RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md`（SHA-256 `3a8482a6badb0b8bff5dbf64adc18b37493c68dc56a25598be91ee3be7e727cd`）。其中 File Browser archive/backslash 的 CVE-2026-62843 已存在于 frozen strict ledger，本批明确排除重复。

## Batch E：再确认 17 个发布级、2 个 commit-only incomplete remediation

- 发布级：Scriban 2、Gitea OAuth 1、PraisonAI JWT 1、Coolify shell validation 1、GitPython 12，共 17 个组件、20 个 public IDs。
- commit-only：Gitea private-org member sibling 与 Coolify ActivityMonitor，共 2 个组件、4 个 public IDs；两组 partial/closure 都在各自首个 fixed release 才出现。
- GitPython 新增 12 项均有独立 first-party GHSA、具体 API/option/sink 和 later closure；不是把同一 alias 或同一 PoC 拆行。Scriban 两项分别是 parser recursion 与 lazy range multiplication，也不是重复。
- PraisonAI CVE-2026-62181 被保留为反例：一方虽标 `>=4.6.78` patched，但代码只挡 1/4 实现中的字面 `-exec`，不能准入。

完整原子 candidate、PR member/carrier、release topology、19 项 advisory 状态和负控见 `RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md`（SHA-256 `f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad`）。

## 关键排除项

| Candidate / component | 结果 | 原因 |
|---|---|---|
| CSS Parser CVE-2026-53727 | EXCLUDE | Claude `7d2ddf01…` 已完整把 remote fetch 路由到 SSRF filter 并分离 `file://`；`e0a151…` 只加未来回归断言，没有具体残留绕过 |
| vm2 CVE-2026-47208 | EXCLUDE | 真正 partial fix `6bbfbb3…` 的正文甚至明写 residual，但该提交及可见 PR/member 没有 AI marker；相邻 AI security commits修的是别的机制 |
| AutoBangumi CVE-2026-59101 | NR | AI root/reintroduction 强，但公开 `487bdf…` 本身仍允许 advisory 明列 private/loopback SSRF，尚无 later exact closure |
| OpenC3 CVE-2026-42085 | EXCLUDE | `9957a9…` 是 path-traversal remediation；后续 allowlist 是 defense-in-depth，当前没有一方具体 bypass 证明 |
| Fiber CVE-2026-30246 | EXCLUDE | AI `047de649…` 修 delimiter/DoS；query cache-key 漏洞已经由更早 human `075894…` 修复，后续 method/path hardening 是不同机制 |
| CPython CVE-2025-15366 backports | EXCLUDE | Claude backport 恢复 RFC quoting 是兼容性修复，不是明确的安全 remediation；CR/LF/NUL rejection 是后续独立安全边界 |
| GitPython GHSA-2F96 | COMMIT_ONLY/EXCLUDE FROM RELEASE | `181e8ede…` 与补全它的 `56806080…` 同在首个 3.1.51 tag，没有发布残缺中间态 |
| PraisonAI CVE-2026-62181 / GHSA-CV3G-HJ65-PCFH | EXCLUDE | advisory 标 `>=4.6.78` patched，但 release commit 只拦 Python SandboxExecutor 的字面 `-exec`；`-execdir`、`-delete` 与另外三条实现仍在，later exact reversal 不成立 |
| Coolify 其余本轮 12 项 | EXCLUDE | wrong edge、不同 field/sink、refactor preservation 或真正 fix member 被 carrier/邻近候选遮蔽；详见本轮只读审计结论 |

## 去重与 claim boundary

- 48 个发布级 incomplete-remediation 组件共 68 个 public IDs；13 个 commit-only 组件共 19 个 CVE/GHSA public IDs（12 个 incomplete、1 个 strict）。两组与 frozen strict-200-v3 `public_ids` 做大小写归一化比较，overlap 均为 0；
- 同一 AI candidate 可留下多个独立机制组件，例如 `3cd664bf…` 的 SSRF 与 Python exec、`2db76f65…` 的 capability 与 container validation、`701ce32f…` 的四个 Git option residual；它们只有在 input/sink/invariant 和一方 advisory 都独立时才分开计数；
- Argo 的 v3/v4 branch copy、OpenClaw 的 duplicate GHSA、以及同一 alias/CVE 只计一个语义组件；OpenClaw 原 12 个 frontier 只有 9 个通过；
- 共享 fix SHA 不是 alias 证据；共享 repo 或同文件也不是；
- `125` 是 strict 发布级确认下界，`173` 是加入 incomplete remediation 后的宽口径发布级下界，`186` 是再含 13 个 commit-only 组件的最宽工作数。

## 可重放检查

```zsh
cd /home/hanqing/agents/ai-slop

# Frozen baseline shape and digest.
wc -l research/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl
jq -r '.public_ids[]' research/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
  | tr '[:lower:]' '[:upper:]' | sort -u | wc -l
sha256sum research/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl

# GitPython release topology; partial fixes really shipped before later closure.
gitpython_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_gitpython_c572da6f272ffa3a525231f03f831cb57d014c35a0987b3e1e11b8ec7575b6f1
git -C "$gitpython_repo" tag --contains 701ce32fe5ba8cb622c0e0342a376a6beb47d738 --sort=version:refname | head
git -C "$gitpython_repo" tag --contains 8ac5a30519b6f4af85398b9b9d7064ff4d452da2 --sort=version:refname | head
git -C "$gitpython_repo" tag --contains 54538428f79b0c91ba52cda5229856a6edf7ac06 --sort=version:refname | head
git -C "$gitpython_repo" tag --contains 1d51b891d7f236044a6aa17498ec682b63dad6e6 --sort=version:refname | head

# Direct parent/fix deltas for representative residual classes.
git -C "$gitpython_repo" diff 701ce32fe^ 701ce32fe -- git/cmd.py git/objects/commit.py git/remote.py git/repo/base.py
git -C "$gitpython_repo" show e8d0fbf774d1f6baa3b481adfe48bd262e43b453 -- git/cmd.py
git -C "$gitpython_repo" diff 54538428^ 54538428 -- git/config.py
git -C "$gitpython_repo" show 1ed1b924f4e2d2ee7bab296df77b978af21853f1 -- git/config.py

# Release gate: empty output means the partial and complete fixes first shipped together.
fission_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_fission_4d88e44809c5e5f15bf7f3dd33b6092f06b4eeb19114e21ba2df793b6177b725
kiota_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_kiota_1a605361924cedd4b87d4b150a7a8d8ccb0b499d69c61337976f92cd1387ef52
coolify_repo=/home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify
git -C "$fission_repo" tag --contains e484df8460bb4e8026e24210120602aa7f181f64 --no-contains 695d3e97e3a20463ab7c8c081843e69e65e952e5
git -C "$kiota_repo" tag --contains de3d18d9fe31ced4ac749728d3a2f94811f59268 --no-contains 430008e9d700b3fe80f206c672415cfbd8e830e7
git -C "$coolify_repo" tag --contains a94517f452e225046e01c08385d6a7aedf085c7d --no-contains 3e0d48faeaab950bfd063dfca908f1d140316ede

# Positive release control: beta.471-.473 contain the partial fix but not the closure.
git -C "$coolify_repo" tag --contains c9922c30c2a6bf922653a5f2d631aab4fea685c4 --no-contains 817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1

# Official repo advisory status, without printing credentials.
for id in \
  GHSA-r9mr-m37c-5fr3 GHSA-94p4-4cq8-9g67 GHSA-6p8h-3wgx-97gf \
  GHSA-3rp5-jjmw-4wv2 GHSA-539m-9xh6-q6rr GHSA-p538-c434-8v24 \
  GHSA-3f7w-8rr8-f37f; do
  gh api "repos/gitpython-developers/GitPython/security-advisories/$id" \
    --jq '[.ghsa_id,.state,.published_at,.withdrawn_at,
           .vulnerabilities[0].vulnerable_version_range,
           .vulnerabilities[0].patched_versions] | @tsv'
done
```

## 产物边界

本报告整合已有冻结报告、本地 first-party Git、CVEList v5 CNA、repo advisory API 和实际 release tags。没有把 DeepSeek/Claude/Codex 的模型裁决当成证明；模型输出只用于 routing。没有使用 OSV `introduced` 作为因果真值。

本轮只新增 Batch D 证据报告并更新本主报告；脏工作树中的其他修改和未跟踪产物均未触碰。
