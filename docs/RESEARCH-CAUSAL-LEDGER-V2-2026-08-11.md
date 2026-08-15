# Causal ledger v2：11 个负控、逐 edge 最小性与 fail-closed 准入契约

日期：2026-08-11

范围：`autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v1/ledger.jsonl`、其两个 builder，以及 initial 10-component exclusion 后仍为 multi-edge 的 10 个 component。本文只记录一手复核、证据契约与预期 census，不修改 ledger、JSON 或代码。

## 结论

当前 118 个 semantic component 中，11 个必须从 positive ledger 移入 negative-control ledger：

- `F_WRONG_EDGE`：U008、U080；
- `F_REFACTOR_PRESERVATION`：U031；
- `F_INCOMPLETE_HARDENING`：U011、U062、U074、U076、U098、U100、U109、U110。

此外，仍为正组件的 U020、U021 各含不合格 pair：U020 的 `31c617c8…→ddfdacb2…` 是真实 causal precursor，但单个 `ddfdacb2…` 不完成 policy re-apply，故 pair 因 `insufficient_fix_reversal` 拒绝；`614a7946…→56d617b7…` 是 refactor preservation；U021 的 `8c1989e3…→aab0bda7…` 是 incomplete hardening。组件分别由 `5a887953…→56d617b7…` 与 `4c9c826c…→aab0bda7…` 保持为正。

最终为 **107 个真实 causal component、190 个公开标识（98 CVE + 92 GHSA）**；base 为 85 个、supplement 为 22 个，相对 v1 移除 11 个 component / 17 个 public ID（10 CVE + 7 GHSA）。190 个是标识数，CVE/GHSA alias 不得宣传为 190 个独立漏洞。edge 账目为 **117 个 accepted occurrence、116 个唯一 `(candidate, fix)` pair、17 个 rejected occurrence**；唯一保留的跨组件重复 pair 是 Feishu 的 `4286755f…→5b4121d6…`，其两个 `mechanism_key` 分别是 local-file disclosure 与 SSRF，不是 alias duplicate。本次对 `strict-ledger-union-v2` 的独立重放已精确得到这些数值。

initial 10-component exclusion 后的 multi-edge 集合共有 10 components / 25 candidate→fix pairs。本轮逐 pair 复核结果为 **19 PASS / 6 FAIL**；U011 的 3 条全部失败，因此最终 surviving multi-edge 子集为 7 components / 17 accepted pairs。component role census 相应为 76 个 `direct_root|reintroduction` 合并项、31 个 `new_surface`。

冻结输入的 raw-file SHA-256 为 `996e81f5298bf695a7d91bc0b2646a314146aaad97aa417fbc4fa5b255ab078c`；其 `summary.json` 中的 `ledger_sha256` 是 canonical-object digest，不是 raw-file digest。

## 为什么 v1 会放进误报

`scripts/build_atomic_ai_causal_ledger.py::_accepted_edges()` 只校验 SHA/枚举/AI marker 的字段形状；`_class_adjudications()` 随后把带自由文本 `reason` 的 `PASS` 直接转成 accepted edges。代码没有读取 repo，也没有机器校验 candidate 的直接 parent、风险方向、caller/surface 增量或 fix reversal。

`scripts/merge_strict_ai_causal_supplement.py::_validate_edge()` 比 base 严格一些：它检查 commit 存在、candidate 自身 AI marker，以及 direct candidate 或 squash carrier 到 fix 的 ancestry。但它仍未证明：

1. candidate 的直接 parent 是否已有同样或更严重的漏洞；
2. candidate 是增风险还是减风险；
3. fix 修的是 candidate delta，还是 candidate 之前/之后的另一机制；
4. squash member 与 carrier 的 PR/member 映射是否真实，carrier 是否只是装载容器。

冻结 `strict-supplement-v1/adjudications.json` 明确含 4 个 `incomplete_hardening_contributor`，并被 union 接纳。当前工作树的 supplement builder 已把该枚举从 positive allowlist 移除，这是正确的第一道回归门；但冻结 union 尚未重建，而且 base 的 wrong-edge/refactor 及结构化因果检查仍未解决。

## v2 最小 schema

每个 component 仍只代表一个去重后的 semantic vulnerability。每条 edge 至少必须持久化以下字段；自由文本可以补充，不能替代结构字段。

| 字段 | 必填含义 |
|---|---|
| `status` | `PASS` / `FAIL` / `NEEDS_REVIEW` / `BLOCKED` |
| `causal_role` | positive 只能为 `direct_root`、`reintroduction`、`new_surface`；非 positive 为 `null` |
| `edge_role` | 每个 accepted pair 为 `root_step`、`reintroduction_step`、`new_surface_step` 或 `necessary_chain_member`；不得用 component-level PASS 代替逐 edge 判定 |
| `failure_kind` | `noncausal_hardening`、`refactor_preservation`、`wrong_edge`、`insufficient_fix_reversal`、`origin_topology_mismatch` 或 `null` |
| `component_id`, `primary_id`, `public_ids` | alias component 与官方公开标识；公开标识全局不重叠 |
| `mechanism_key` | component 内唯一的 attacker-input/guard/sink/impact 键；同一 pair 服务多个 component 时必须各有不同键和一方对象支持 |
| `official_advisory_objects` | 一方 CVE/GHSA 对象的 path、SHA-256、published/state；OSV 只能是 routing |
| `repository_identity` | 规范化 upstream identity，不以任意本地目录名代替 |
| `candidate_sha`, `candidate_parent_sha` | 原子候选及其真实直接 parent；parent 必须等于 `candidate^` |
| `origin_kind` | `direct_commit`、`squash_member`、`upstream_atomic` 或 `branch_copy` |
| `carrier_sha`, `carrier_parent_sha` | 仅 squash member 必填；永不把 carrier 的 AI 归因传给 member |
| `member_carrier_proof` | PR/member relation artifact、member patch paths/hunks、carrier landing ancestry；缺一则 `NEEDS_REVIEW` |
| `ai_signal` | 必须来自 atomic candidate 自身的 author/trailer/tool marker，并记录原文和来源 |
| `advisory_mechanism` | 结构化的 attacker input → guard/transform → sink → impact，以及涉及的 production paths/symbols |
| `parent_state` | `absent`、`protected`、`vulnerable_same`、`vulnerable_broader` 或 `unknown` |
| `candidate_effect` | `create_mechanism`、`remove_guard`、`add_reachable_surface`、`no_exposure_change`、`reduce_incompletely` 或 `unrelated` |
| `fix_sha`, `fix_set`, `fix_reversal` | 单 fix 或完整 fix 集、对应 symbols/paths，以及它如何撤销 candidate 建立/重开的机制或关闭新增 surface；pair 的 `fix_sha` 单独不完整时不得 PASS |
| `evidence_commands` | 可重放的 parent/candidate/fix/advisory 命令；所有路径和 full SHA 固定 |

一个共享 validator 应同时供 base 和 supplement builder 使用，避免两套准入规则再次漂移。

## PASS/FAIL 不变量

`PASS` 必须同时满足官方对象可读、atomic candidate 自身有 AI 信号、直接 parent 可读、机制与 advisory 对齐，以及 fix 或完整 `fix_set` 对 exact mechanism 有 reversal。`root_step`、`reintroduction_step`、`new_surface_step` 的 candidate 风险方向必须为正；`necessary_chain_member` 必须满足 exact but-for/minimality 且不是净 hardening。component 角色互斥：

- `direct_root`：direct parent 中 exact unsafe mechanism 不存在，candidate delta 首次建立；删除 candidate 后该机制不存在。
- `reintroduction`：direct parent 已受保护，candidate 明确 revert/remove/weaken guard，并在 candidate 版本立即恢复可利用状态。
- `new_surface`：共享旧 sink/缺陷可以更早存在，但 candidate 新增真实可达 caller、route、provider、model 或 platform branch；删除 candidate 会消除这个新增攻击面。它不能宣传为首次 root。

`necessary_chain_member` 是 edge role，不是第四种 component role。它只允许 candidate 新增 advisory-specific trigger、schema、guard semantics 或输入端，随后另一 root step 才完成利用链；必须证明删掉该原子 hunk 会切断 exact mechanism，并由完整 `fix_set` 中的修复实际 neutralize。它不能把净减风险的弱 blocklist/allowlist 重新包装成 positive。

以下必须 fail closed：

- parent 是 `vulnerable_same`/`vulnerable_broader` 且 candidate 是净减风险的不完整修补 → `noncausal_hardening`；
- caller、sink、可达性和风险均未增加的等价抽取/重写 → `refactor_preservation`；
- advisory 指名的危险行来自其他 commit，或 candidate 未触及该机制 → `wrong_edge`；
- candidate 确为 causal precursor，但所配单个 fix 只修一个副作用、未关闭完整机制 → pair 为 `insufficient_fix_reversal`；candidate 可保留在研究说明，不能进入 exact-pair ledger；
- branch member 实际经 squash carrier 落地主线却标作 `direct_commit` → `origin_topology_mismatch`；即使风险方向另有 FAIL，也必须同时记录 topology 错；
- parent、官方对象、atomic member 或 fix reversal 任一不可读/不确定 → `NEEDS_REVIEW`，不得 `PASS`。

`dangerous_revert` 应映射到 `reintroduction`；`guard_weakening` 只有在 candidate 相对受保护 parent 当场增风险时才能映射到 `reintroduction`。`incomplete_hardening_contributor` 不再是 positive 类型。

## 11 个必须保留的负控

官方机制来自 CVEList v5 的 published CNA objects 与 GitHub Advisory Database 的 reviewed GHSA object；Git 结论来自 full-SHA 的直接 parent、candidate delta、fix 和必要时的 blame。CVEList snapshot 为 `8ca64b5ad6b84d3cd5741b023610b8494800f174`，Advisory Database snapshot 为 `39d8887723797efc1804585dd06585c9fd751226`。

| union row | component / public IDs | v1 edge | 一方对象 + Git 反证 | v2 结果 |
|---|---|---|---|---|
| U008 | `alias-10d5f77aca6a1a97f753022d` / CVE-2026-62312 | `7648c3412b403a29f04967c4b4e9725e228791d4 → da667836cc7584bea0edd893de1d590c9ea279dc` | CNA 指名 Host/locality bypass + MCP args。candidate 只新增 real-IP rate limiting 基础设施、reset-password route 并导出既有 `isLocalRequest`; 它未让 locality 信任该 header，也未新增 MCP args sink。危险 `x-9r-real-ip` locality 使用由后续 human `b282f0554972ea35281520738759d76abcd0b0b3` 写入。 | `FAIL/wrong_edge` |
| U011 | `alias-1a8156c9b0ac4e49d726cdc4` / GHSA-5WP8-Q9MX-8JX8 | `91f6c2bf98e40238ad4d175513f0ee400fd62068`、`d3480ca94087b74f110bb5b80fc8219b32c8b8b5`、member `3c4368da0ab48c1091858d3f9503c378a209997f` → `68916c3e4f3af107f11940b27854fc7ef517058b` | GHSA 指名 literal glob、combined flags、first-token chaining 与 empty Strict allowlist 绕过。parent 已有 unrestricted shell execution；`91f6` 仅新增 security module，后续 `3110942a…` 才接线；`d348` 增加 11 个 deny patterns；`3c436` 增加可选 allowlist。三者均净减风险，删除会恢复更宽执行。且 `3c436` 不是 fix ancestor，而是 carrier `1712debbea60af6adf4a8a5939a43f7ef9a1ac16` 的 squash member；v1 的 `direct_commit` topology 也错。 | `FAIL/noncausal_hardening` + `origin_topology_mismatch` |
| U031 | `alias-5094de4875d0d8fda0a4bf6a` / CVE-2026-34034 | `a8aa4524751d1530031f6134d49474d254bbab72 → 096d4369e59b3db7ace2db3ca42588c41b9b6019` | CNA 指名 `sentinel_token` shell interpolation。parent 已在 Application、Server、8 个 Standalone models 及 `StartSentinel` 使用未校验 token；candidate 只是把同一 10 个 model 方法抽到 `HasMetrics`，caller/surface 未增加。 | `FAIL/refactor_preservation` |
| U062 | `alias-adaf8ed9e0a157cba9b63805` / CVE-2026-47390, GHSA-5C6W-WWFQ-7QQM | `3cd664bf7b7db5f774c1e7e3123a1a24c68ba700 → 179cab02dbec0c1e9b601507a65908e079876004` | CNA 明说 SSRF **protection bypass**。parent 已对 attacker URL 做 unrestricted `Session.get`; candidate 新增弱 `_validate_url`，fix 才补 alternate loopback encodings。删除 candidate 会恢复更宽 SSRF。 | `FAIL/noncausal_hardening` |
| U074 | `alias-ca062bdf2a1afef0fdfe5205` / CVE-2026-47392, GHSA-4MR5-G6F9-CFRH | 同 U062 | parent 的 `execute_code` 暴露完整 `__builtins__`; candidate 改为弱 restricted builtins/pattern list，CNA 指名 `print.__self__` 绕过；fix 加 AST/blocked attrs。删除 candidate 会恢复任意 Python execution。 | `FAIL/noncausal_hardening` |
| U076 | `alias-cd7f25d7556aeb5acdff1359` / CVE-2026-54526 | `251bb231d62a0f4e5e03dcc13c3f2ae456b2fa34 → 358cc3968c8f06f1be0967e41df191088db0b662`；v4 branch copy `2727f3f701677d467dfb5e053c57237cbc752c3c → 277e9cef0ad16d7eaaab253573d0695951a65dbd` | CNA 标题即 “Incomplete fix”。parent 只拒顶层 `PodSpecPatch`，其余敏感 WorkflowSpec 可 merge；candidate 加 allowlist，阻断大多数旧越权但整块允许 `ArtifactGC`; fix 再拒 nested `PodSpecPatch/ServiceAccountName/PodMetadata`。删除 candidate 更危险。 | `FAIL/noncausal_hardening` |
| U080 | `alias-d3345ebc2e154b22dcd94ce0` / CVE-2026-56675 | 同 U008 | CNA 指名 reverse-proxy locality collapse。candidate 版本的 locality 仍仅看 Host/Origin；把 socket-derived header 当 locality anchor 的 exact lines 是后续 human `b282f055`。 | `FAIL/wrong_edge` |
| U098 | `alias-ffbfb9902ecac6b93a73d35d` / CVE-2026-50570, GHSA-QF5V-M7P4-95RP | member `2db76f65dbfe4f657b4a4efb506ed63b24623e92` → carrier `e484df8460bb4e8026e24210120602aa7f181f64` → `2569b42bfadbcb7d78b55a00a60f77937e522699` | CNA 指名 incomplete capability denylist。member parent 没有 `podspec_safety.go`; member 新增六项 denylist，fix 改 allowlist并覆盖 `SYS_TIME`。这是净 hardening，不是 root。 | `FAIL/noncausal_hardening` |
| U100 | `alias-df787a23a3ac89c4e14c8a5e` / CVE-2026-44430, GHSA-R48C-V28R-PF6V | member `257eb178cfb05335c68f793a5b1fba16c32e3769` → carrier `1201cbd82b2cf6d4b56edfc05c763059a12f9fdb` → `f5f40bd98084466eaf18fe48ea62a0d534caa774` | parent 使用无 private-IP guard 的标准 client；member 明确新增 `safeDialContext`/blocklist；CNA 与 fix 只补 6to4/NAT64/site-local IPv6。删除 member 会恢复 unrestricted SSRF。 | `FAIL/noncausal_hardening` |
| U109 | `alias-2e848b53793009fca2ca1de3` / CVE-2026-50566, GHSA-M63V-2G9W-2W6V | member `2db76f65dbfe4f657b4a4efb506ed63b24623e92` → carrier `e484df8460bb4e8026e24210120602aa7f181f64` → `695d3e97e3a20463ab7c8c081843e69e65e952e5` | member 首次验证 PodSpec containers，但 parent 对 PodSpec 和 standalone Runtime/Builder Container 都更宽；fix 抽出 `ValidateContainerSafety` 并接入遗漏字段。 | `FAIL/noncausal_hardening` |
| U110 | `alias-dbd0a92c62e19f8c406c2078` / CVE-2026-50568, GHSA-R5JH-Q2MW-GCX4 | member `0d851525a35ba517dda7fe892333df5d0919dffc` → carrier `5a3d68a349b001302b1acb6e838f05283160548d` → `8298e33ea7457702f893eae11077987cf905edb4` | parent 的 Builder.Clean 直接 `filepath.Join` attacker name；member 明说 harden Clean，并改走已有但有 sibling-prefix 缺陷的 `SanitizeFilePath`; fix 用 `RootJoin`/`os.Root` confinement。删除 member 回到 raw join。 | `FAIL/noncausal_hardening` |

官方对象的 exact paths：

```text
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/62xxx/CVE-2026-62312.json
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/34xxx/CVE-2026-34034.json
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/47xxx/CVE-2026-47390.json
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/47xxx/CVE-2026-47392.json
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/54xxx/CVE-2026-54526.json
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/56xxx/CVE-2026-56675.json
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/50xxx/CVE-2026-50570.json
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/44xxx/CVE-2026-44430.json
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/50xxx/CVE-2026-50566.json
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/50xxx/CVE-2026-50568.json
/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/03/GHSA-5wp8-q9mx-8jx8/GHSA-5wp8-q9mx-8jx8.json
```

三项新增校正所依赖对象的 SHA-256 分别为：GHSA-5WP8 `2dadc4ca9b6944e557d695d6097257d44d4bdd12048aefef6d54d566990884ba`、CVE-2026-34218 `15d92eed529812a83dfa1ac3c1a43bf790c3cc957f36302f46df63c02909109a`、CVE-2026-27203 `6ed8ed31134c83bde9414c79c89a787cda788bad6e8d7c13ae5f81fba94692a2`。

## Multi-edge：25 条 pair 的逐项因果与最小性

这里的 PASS/FAIL 是 pair-level 结论。`atomic/topology` 同时检查 candidate 自身 AI marker、`candidate^` delta，以及 member→carrier→fix；component 有一条真 edge 不会替另一条 edge 自动 PASS。

| source | candidate → fix | atomic / parent-delta-fix 结论 | pair verdict |
|---|---|---|---|
| U007 / CVE-2026-1979 | `1de6340f1bc81564274890660f66444e48d660b0 → e50f15c1c6e131fa7934355eb02b8173b13df415` | direct atomic；新增 undefined pinned-variable 的 3-byte `OP_JMP` trigger，随后 `2b72…` 才误当 4-byte `OP_JMPNOT`；fix 的 opcode check neutralize 此交互。 | `PASS/necessary_chain_member` |
| U007 | `2b72d8a7c153e2afb22245ad9e40e0c7d5b1aa70 → e50f15c1c6e131fa7934355eb02b8173b13df415` | direct atomic；parent 已有 trigger，candidate 首次写入未校验的 `s->iseq[fail_pos-2]=OP_JMPIF`；fix 加 exact `OP_JMPNOT` 条件。 | `PASS/root_step` |
| U011 / GHSA-5WP8-Q9MX-8JX8 | `91f6c2bf98e40238ad4d175513f0ee400fd62068 → 68916c3e4f3af107f11940b27854fc7ef517058b` | direct atomic；parent shell sink 已 unrestricted，candidate 只新增尚未接线的 deny module；`3110942a…` 后续接线，fix 再补 glob/metacharacter。删除 candidate 更危险。 | `FAIL/noncausal_hardening` |
| U011 | `d3480ca94087b74f110bb5b80fc8219b32c8b8b5 → 68916c3e4f3af107f11940b27854fc7ef517058b` | direct atomic；parent 已有弱 blocklist，candidate 新增 11 个 encoded/script deny regex，净减少暴露；fix 只使 flags parsing 更完整。 | `FAIL/noncausal_hardening` |
| U011 | `3c4368da0ab48c1091858d3f9503c378a209997f → 68916c3e4f3af107f11940b27854fc7ef517058b` | atomic member 新增 Off/Warn/Strict allowlist，但 parent 只有更宽 blocklist，故仍为净 hardening。member 不在 fix ancestry；真实 squash carrier 是 `1712debbea60af6adf4a8a5939a43f7ef9a1ac16`。 | `FAIL/noncausal_hardening` + `origin_topology_mismatch` |
| U020 / CVE-2026-34218 | `31c617c8286a0707e1c7e65ec6469013d40b3ff1 → ddfdacb2633681bbd9c2f41dbd536ea039386628` | direct atomic；candidate 的 nil-client guard 是后续 misordering 的 necessary precursor，但 old daemon 流程在 client start 后 push。`ddfd…` 只补 post-start cache clear，未重做被 guard 跳过的 policy apply；完整 closure 是 `[ddfdacb2…,56d617b7…]`。 | `FAIL/insufficient_fix_reversal`；precursor 本身不判 noncausal |
| U020 | `5a887953c45551879797fd9e11a2055cf9386d7e → 56d617b778c571e3c29b803636d9807940992daa` | direct atomic；把 daemon 合入 opfilter，并在 `XPCServer.init` 于 `adapter.start()` 前 apply；nil guard 确定性跳过 managed/user rules。fix 把 apply 移到 start 后。 | `PASS/root_step` |
| U020 | `614a7946aecf2456893498f24ac18be5ed57f196 → 56d617b778c571e3c29b803636d9807940992daa` | direct atomic；parent 已在 `XPCServer.init` before-start apply；candidate 仅移到 `main.swift`，仍在 start 前，风险/可达性不变。 | `FAIL/refactor_preservation` |
| U021 / CVE-2026-27203 | `4c9c826c6fc8b64a20e948cb46fefdda42d5244d → aab0bda75ea9dd27aa37d0d8524d7cf41b3c4a9a` | direct atomic；parent 无 `.env` writeback sink，candidate 首次用 regex + raw `key=value` 写 attacker token；fix 改 parse/merge/stringify。 | `PASS/root_step` |
| U021 | `8c1989e36ad2950fcf4c8f9f95027ebf487e0f61 → aab0bda75ea9dd27aa37d0d8524d7cf41b3c4a9a` | direct one-line atomic；parent 已可 newline injection；candidate 加双引号只修 `#` truncation，仍未 escape quote/newline，删除恢复更宽缺陷。 | `FAIL/noncausal_hardening` |
| U024 / CVE-2026-49949 | `b6b77b4b8ea803b671dea666bc76135e6af0c057 → 08c171b6b487654a0eb188494fa24bd1c4272a2e` | direct atomic；新增 DeepSeek bearer-token request surface，credential header survives into later shared transport；fix 对跨 origin/downgrade redirect 加 guard。 | `PASS/new_surface_step` |
| U024 | `8348c85cd8d43affa0c9d83be20ff42d895fe1dc → 08c171b6b487654a0eb188494fa24bd1c4272a2e` | direct atomic；新增 OpenRouter bearer-token credits/key surfaces；parent 无该 provider，fix 覆盖同一 shared transport。 | `PASS/new_surface_step` |
| U024 | `c3a0304298597ace4026a9778cb0025309b628a3 → 08c171b6b487654a0eb188494fa24bd1c4272a2e` | direct atomic；新增 Kimi bearer + cookie request surface；后续 `ad33b327…` 仅把请求集中到 shared client，candidate 的 secret-bearing surface 保留，fix 加 redirect boundary。 | `PASS/new_surface_step` |
| U046 / CVE-2026-58195 | `2a1e2777dd6a993f678d9596dd7c6c4fd0c444d9 → 0c2ec967736a8b6b85832c6bae2a3e74989705ec` | direct atomic；parent 已有 stdio unsafe tools，candidate 新增 HTTP/SSE MCP route 并在 `http-sse.ts` 拼接 attacker args 到 `execSync`；fix 改安全 argv/validation。 | `PASS/new_surface_step` |
| U046 | `319c98616bc968b6810c6c0b49e04806e7379530 → 0c2ec967736a8b6b85832c6bae2a3e74989705ec` | direct atomic；parent 无 `agentic-flow/src/mcp` tree，candidate restore 时首次加入 advisory 列出的多组 unsafe `execSync` sinks；fix 逐文件关闭。 | `PASS/root_step` |
| U051 / CVE-2026-2376 | member `bb7c06aec08ad6135b8d4b475b96a44e19b62ef9` / carrier `92b6f4729a5e29159f8864f923e5ea22081f9bb8` → `9afe28a53b85fc40ce367cc78a5addcead88abe1` | squash member；原子 delta 新增 POST create 并持久化未校验 `external_registry_url`；carrier 只承载 PR，fix 在 API/model/adapter 校验。 | `PASS/new_surface_step` |
| U051 | member `24d6083f5a43f0e5961eb1ed3bafe4c9cf468c63` / carrier `92b6f4729a5e29159f8864f923e5ea22081f9bb8` → `9afe28a53b85fc40ce367cc78a5addcead88abe1` | squash member；独立新增 PUT update 写入同一 attacker URL，是与 POST 不同的可达入口；fix 同时校验。 | `PASS/new_surface_step` |
| U051 | member `a6d759cd016b452f58bb0b3cca30487745f074d7` / carrier `3869d001aec3e90271bd71ab7ed1490383254dca` → `9afe28a53b85fc40ce367cc78a5addcead88abe1` | squash member；原子 delta 新增 Quay/Harbor adapter，从 stored URL 发请求并默认跟 redirect；fix 校验每跳并禁 redirect。 | `PASS/root_step` |
| U061 / CVE-2026-28451 | upstream atomic `4286755f26bcfdd5c704cc4eb0cabfdc1b314e68` / import carrier `2267d58afcc70fe19408b8f0dce108c340f3426d` → `5b4121d6011a48c71e747e3c18197f180b872c5d` | upstream root commit（parent 为空）创建 `sendMediaFeishu` raw `fetch(mediaUrl)`；carrier 把 hunk 带入 `extensions/feishu`，fix 改走 hardened loader。 | `PASS/root_step` |
| U061 | upstream atomic `822b5f37b76284d247823efea51c47e0b975e9d1` / import carrier `2267d58afcc70fe19408b8f0dce108c340f3426d` → `5b4121d6011a48c71e747e3c18197f180b872c5d` | upstream atomic；新增 docx markdown image `downloadImage(url)→fetch`，与 sendMedia 为独立 caller/surface；fix 改 `fetchRemoteMedia`。 | `PASS/new_surface_step` |
| U114 / CVE-2026-8147 | `f685d19b59889d9a93445a78abdde276ab33cf7c → f9b1eb510478570609ef451984a255775aa4b937` | direct atomic；新增 public `BatchGetTraceInfos` proto/route schema，但尚无 handler；是后续未授权 endpoint 的必要 route member，fix 为该 RPC 注册 validator。 | `PASS/necessary_chain_member` |
| U114 | `3e590361e0e251382ae30cbc9993d604bfdb67d5 → f9b1eb510478570609ef451984a255775aa4b937` | direct atomic；parent 已有 proto，candidate 新增 handler、`HANDLERS` 注册和 arbitrary trace-id lookup，未注册 auth validator；fix exact registration。 | `PASS/root_step` |
| U115 / CVE-2026-53598 | `a0e6108842a3bfc840a33db819a4415fbdac333d → 88ac9948d7d37995edbb2f6d36913436626c39e1` | direct atomic；新增 TypeScript v2 runtime，`${file:...}` 直接 `resolve` + `readFileSync`，无 root/canonical check；fix 加 allowed roots。 | `PASS/new_surface_step` |
| U115 | `bd50f65d671e22d367ce318ff71529d2f0a71df6 → 88ac9948d7d37995edbb2f6d36913436626c39e1` | direct atomic；新增 C# loader 的 `Path.GetFullPath` + `File.ReadAllText` reference resolver，无 containment；fix 加 canonical root contract。 | `PASS/new_surface_step` |
| U115 | `19137b339d34824df300fc6bceae932ffd327d8e → 88ac9948d7d37995edbb2f6d36913436626c39e1` | direct atomic；新增 Rust runtime resolver 的 unrestricted `read_to_string`；fix 加 traversal/symlink/allowed-root checks。 | `PASS/new_surface_step` |

六条 extra rejected pairs 精确为 U011 的 3 条、U020 的 `31c617c8…` 与 `614a7946…`、U021 的 `8c1989e3…`。其中 `31c617c8…` 是唯一“candidate 有因果贡献但当前 pair 不可发表”的情况；它不能与真正 noncausal 的 hardening/refactor 混为一类。

### 唯一跨组件重复 pair 不是 alias duplicate

`4286755f26bcfdd5c704cc4eb0cabfdc1b314e68 → 5b4121d6011a48c71e747e3c18197f180b872c5d` 同时出现于：

- `alias-5a43c1628113d632bf3692b9` / CVE-2026-26321、GHSA-8JPQ-5H99-FF5R：attacker `mediaUrl` 被 `isLocalPath` 分流到 `fs.readFileSync`，造成 local-file disclosure；
- U061 / `alias-ad337734a611a97f040638ad` / CVE-2026-28451、GHSA-X22M-J5QQ-J49M：HTTP(S) `mediaUrl` 被 raw `fetch`，造成 internal-service SSRF 并重上传响应。

同一 upstream atomic commit 的同一函数建立两个 protocol-disjoint sinks，官方 CNA objects 分别给出不同 input/impact，fix 也同时删除 local-read branch并替换 remote-fetch branch。因此 ledger 保留两个 edge **occurrence**，但唯一 pair census 只计一次；必须用两个 `mechanism_key`，不得把四个公开 ID 合并为一个 alias component。

## Primary-source replay

先读一方机制与受影响版本：

```zsh
cve_root=/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026
for cve_file in \
  "$cve_root/62xxx/CVE-2026-62312.json" \
  "$cve_root/34xxx/CVE-2026-34034.json" \
  "$cve_root/47xxx/CVE-2026-47390.json" \
  "$cve_root/47xxx/CVE-2026-47392.json" \
  "$cve_root/54xxx/CVE-2026-54526.json" \
  "$cve_root/56xxx/CVE-2026-56675.json" \
  "$cve_root/50xxx/CVE-2026-50570.json" \
  "$cve_root/44xxx/CVE-2026-44430.json" \
  "$cve_root/50xxx/CVE-2026-50566.json" \
  "$cve_root/50xxx/CVE-2026-50568.json"
do
  jq '{id:.cveMetadata.cveId,state:.cveMetadata.state,title:.containers.cna.title,descriptions:.containers.cna.descriptions,affected:.containers.cna.affected,references:.containers.cna.references}' "$cve_file"
done

for cve_file in \
  "$cve_root/1xxx/CVE-2026-1979.json" \
  "$cve_root/34xxx/CVE-2026-34218.json" \
  "$cve_root/27xxx/CVE-2026-27203.json" \
  "$cve_root/49xxx/CVE-2026-49949.json" \
  "$cve_root/58xxx/CVE-2026-58195.json" \
  "$cve_root/2xxx/CVE-2026-2376.json" \
  "$cve_root/26xxx/CVE-2026-26321.json" \
  "$cve_root/28xxx/CVE-2026-28451.json" \
  "$cve_root/8xxx/CVE-2026-8147.json" \
  "$cve_root/53xxx/CVE-2026-53598.json"
do
  jq '{id:.cveMetadata.cveId,state:.cveMetadata.state,title:.containers.cna.title,descriptions:.containers.cna.descriptions,references:.containers.cna.references}' "$cve_file"
done

ghsa_zepto=/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/03/GHSA-5wp8-q9mx-8jx8/GHSA-5wp8-q9mx-8jx8.json
jq '{id,summary,details,vulnerabilities,references}' "$ghsa_zepto"
```

9Router wrong-edge：

```zsh
nine_repo=/home/hanqing/.cache/cve-analyzer/repos/github.com_decolua_9router
git -C "$nine_repo" show 7648c3412b403a29f04967c4b4e9725e228791d4^:src/dashboardGuard.js
git -C "$nine_repo" show 7648c3412b403a29f04967c4b4e9725e228791d4 -- src/dashboardGuard.js custom-server.js
git -C "$nine_repo" blame -L 92,100 da667836cc7584bea0edd893de1d590c9ea279dc^ -- src/dashboardGuard.js
git -C "$nine_repo" show da667836cc7584bea0edd893de1d590c9ea279dc -- src/dashboardGuard.js custom-server.js
```

Coolify refactor-preservation：

```zsh
coolify_repo=/home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify
git -C "$coolify_repo" grep -n sentinel_token a8aa4524751d1530031f6134d49474d254bbab72^ -- app/Models app/Actions/Server/StartSentinel.php
git -C "$coolify_repo" diff a8aa4524751d1530031f6134d49474d254bbab72^ a8aa4524751d1530031f6134d49474d254bbab72 -- app/Models app/Traits/HasMetrics.php
git -C "$coolify_repo" show 096d4369e59b3db7ace2db3ca42588c41b9b6019 -- app/Traits/HasMetrics.php app/Actions/Server/StartSentinel.php app/Models/ServerSetting.php
```

PraisonAI incomplete hardening：

```zsh
praison_repo=/home/hanqing/.cache/cve-analyzer/repos/github.com_mervinpraison_praisonai
git -C "$praison_repo" show 3cd664bf7b7db5f774c1e7e3123a1a24c68ba700^:src/praisonai-agents/praisonaiagents/tools/spider_tools.py
git -C "$praison_repo" show 3cd664bf7b7db5f774c1e7e3123a1a24c68ba700^:src/praisonai-agents/praisonaiagents/tools/python_tools.py
git -C "$praison_repo" show 3cd664bf7b7db5f774c1e7e3123a1a24c68ba700 -- src/praisonai-agents/praisonaiagents/tools/spider_tools.py src/praisonai-agents/praisonaiagents/tools/python_tools.py
git -C "$praison_repo" show 179cab02dbec0c1e9b601507a65908e079876004 -- src/praisonai-agents/praisonaiagents/tools/spider_tools.py src/praisonai-agents/praisonaiagents/tools/python_tools.py
```

Argo incomplete hardening：

```zsh
argo_repo=/home/hanqing/.cache/cve-analyzer/repos/argoproj_argo-workflows
git -C "$argo_repo" show 251bb231d62a0f4e5e03dcc13c3f2ae456b2fa34^:workflow/controller/operator.go
git -C "$argo_repo" show 251bb231d62a0f4e5e03dcc13c3f2ae456b2fa34 -- workflow/controller/operator.go workflow/util/merge.go
git -C "$argo_repo" show 358cc3968c8f06f1be0967e41df191088db0b662 -- workflow/util/merge.go
git -C "$argo_repo" show 2727f3f701677d467dfb5e053c57237cbc752c3c -- workflow/controller/operator.go workflow/util/merge.go
git -C "$argo_repo" show 277e9cef0ad16d7eaaab253573d0695951a65dbd -- workflow/util/merge.go
```

Fission 三项 incomplete hardening：

```zsh
fission_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_fission_4d88e44809c5e5f15bf7f3dd33b6092f06b4eeb19114e21ba2df793b6177b725
git -C "$fission_repo" show 2db76f65dbfe4f657b4a4efb506ed63b24623e92^:pkg/apis/core/v1/validation.go
git -C "$fission_repo" show 2db76f65dbfe4f657b4a4efb506ed63b24623e92:pkg/apis/core/v1/podspec_safety.go
git -C "$fission_repo" show 2569b42bfadbcb7d78b55a00a60f77937e522699 -- pkg/apis/core/v1/podspec_safety.go pkg/executor/util/merge.go
git -C "$fission_repo" show 695d3e97e3a20463ab7c8c081843e69e65e952e5 -- pkg/apis/core/v1/podspec_safety.go pkg/apis/core/v1/validation.go pkg/executor/util/merge.go
git -C "$fission_repo" show 0d851525a35ba517dda7fe892333df5d0919dffc^:pkg/builder/builder.go
git -C "$fission_repo" show 0d851525a35ba517dda7fe892333df5d0919dffc -- pkg/builder/builder.go
git -C "$fission_repo" show 8298e33ea7457702f893eae11077987cf905edb4 -- pkg/builder/builder.go pkg/utils/utils.go pkg/utils/root.go
```

Registry incomplete hardening：

```zsh
registry_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_registry_29b2997ea8cfaf7ac0827767387398565017ee92e1678eef1fd86a2417fb2402
git -C "$registry_repo" show 257eb178cfb05335c68f793a5b1fba16c32e3769^:internal/api/handlers/v0/auth/http.go
git -C "$registry_repo" show 257eb178cfb05335c68f793a5b1fba16c32e3769 -- internal/api/handlers/v0/auth/http.go internal/api/handlers/v0/auth/http_internal_test.go
git -C "$registry_repo" show f5f40bd98084466eaf18fe48ea62a0d534caa774 -- internal/api/handlers/v0/auth/http.go internal/api/handlers/v0/auth/http_internal_test.go
```

Multi-edge pair 逐项重放（每个 `show candidate^ candidate` 都是 atomic parent delta；carrier 另列）：

```zsh
mruby_repo=/home/hanqing/.cache/cve-analyzer/repos/mruby_mruby
git -C "$mruby_repo" show 1de6340f1bc81564274890660f66444e48d660b0^ 1de6340f1bc81564274890660f66444e48d660b0 2b72d8a7c153e2afb22245ad9e40e0c7d5b1aa70 e50f15c1c6e131fa7934355eb02b8173b13df415 -- mrbgems/mruby-compiler/core/codegen.c

zepto_repo=/home/hanqing/.cache/cve-analyzer/repos/qhkm_zeptoclaw
git -C "$zepto_repo" show 91f6c2bf98e40238ad4d175513f0ee400fd62068^ 91f6c2bf98e40238ad4d175513f0ee400fd62068 -- src/security/shell.rs src/tools/shell.rs
git -C "$zepto_repo" show 3110942a86855fee18451e2025b906c1e1da2ad7 -- src/tools/shell.rs
git -C "$zepto_repo" show d3480ca94087b74f110bb5b80fc8219b32c8b8b5^ d3480ca94087b74f110bb5b80fc8219b32c8b8b5 -- src/security/shell.rs
git -C "$zepto_repo" show 3c4368da0ab48c1091858d3f9503c378a209997f^ 3c4368da0ab48c1091858d3f9503c378a209997f 1712debbea60af6adf4a8a5939a43f7ef9a1ac16 68916c3e4f3af107f11940b27854fc7ef517058b -- src/security/shell.rs
if git -C "$zepto_repo" merge-base --is-ancestor 3c4368da0ab48c1091858d3f9503c378a209997f 68916c3e4f3af107f11940b27854fc7ef517058b; then
  print 'unexpected: member is a direct fix ancestor' >&2
  return 1
fi
git -C "$zepto_repo" merge-base --is-ancestor 1712debbea60af6adf4a8a5939a43f7ef9a1ac16 68916c3e4f3af107f11940b27854fc7ef517058b

clearance_repo=/home/hanqing/.cache/cve-analyzer/repos/github.com_craigjbass_clearancekit
git -C "$clearance_repo" show 31c617c8286a0707e1c7e65ec6469013d40b3ff1^ 31c617c8286a0707e1c7e65ec6469013d40b3ff1 -- opfilter/ESInboundAdapter.swift opfilter/XPCClient.swift opfilter/main.swift
git -C "$clearance_repo" show 5a887953c45551879797fd9e11a2055cf9386d7e^ 5a887953c45551879797fd9e11a2055cf9386d7e -- opfilter/XPCServer.swift opfilter/main.swift
git -C "$clearance_repo" show 614a7946aecf2456893498f24ac18be5ed57f196^ 614a7946aecf2456893498f24ac18be5ed57f196 56d617b778c571e3c29b803636d9807940992daa -- opfilter/XPC/XPCServer.swift opfilter/main.swift
git -C "$clearance_repo" show ddfdacb2633681bbd9c2f41dbd536ea039386628 -- opfilter/main.swift opfilter/EndpointSecurity/ESJailAdapter.swift
git -C "$clearance_repo" blame 56d617b778c571e3c29b803636d9807940992daa^ -- opfilter/main.swift

ebay_repo=/home/hanqing/.cache/cve-analyzer/repos/yosefhayim_ebay-mcp
git -C "$ebay_repo" show 4c9c826c6fc8b64a20e948cb46fefdda42d5244d^ 4c9c826c6fc8b64a20e948cb46fefdda42d5244d 8c1989e36ad2950fcf4c8f9f95027ebf487e0f61 aab0bda75ea9dd27aa37d0d8524d7cf41b3c4a9a -- src/auth/oauth.ts

codexbar_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_codexbar_33118aaca129ca3c666f8cce2b0c2f27fef12501e76700a9e2ddb94277e54115
git -C "$codexbar_repo" show b6b77b4b8ea803b671dea666bc76135e6af0c057^ b6b77b4b8ea803b671dea666bc76135e6af0c057 -- Sources/CodexBarCore/Providers/DeepSeek
git -C "$codexbar_repo" show 8348c85cd8d43affa0c9d83be20ff42d895fe1dc^ 8348c85cd8d43affa0c9d83be20ff42d895fe1dc -- Sources/CodexBarCore/Providers/OpenRouter
git -C "$codexbar_repo" show c3a0304298597ace4026a9778cb0025309b628a3^ c3a0304298597ace4026a9778cb0025309b628a3 -- Sources/CodexBarCore/Providers/Kimi
for provider_file in \
  Sources/CodexBarCore/Providers/DeepSeek/DeepSeekUsageFetcher.swift \
  Sources/CodexBarCore/Providers/OpenRouter/OpenRouterUsageStats.swift \
  Sources/CodexBarCore/Providers/Kimi/KimiUsageFetcher.swift
do
  git -C "$codexbar_repo" blame 08c171b6b487654a0eb188494fa24bd1c4272a2e^ -- "$provider_file"
done
git -C "$codexbar_repo" show 08c171b6b487654a0eb188494fa24bd1c4272a2e -- Sources/CodexBarCore/ProviderHTTPClient.swift

agentic_repo=/home/hanqing/.cache/cve-analyzer/repos/github.com_ruvnet_agentic-flow
git -C "$agentic_repo" show 2a1e2777dd6a993f678d9596dd7c6c4fd0c444d9^ 2a1e2777dd6a993f678d9596dd7c6c4fd0c444d9 -- agentic-flow/src/mcp/fastmcp/servers/http-sse.ts
git -C "$agentic_repo" diff 319c98616bc968b6810c6c0b49e04806e7379530^ 319c98616bc968b6810c6c0b49e04806e7379530 -- agentic-flow/src/mcp
git -C "$agentic_repo" diff 0c2ec967736a8b6b85832c6bae2a3e74989705ec^1 0c2ec967736a8b6b85832c6bae2a3e74989705ec -- agentic-flow/src/mcp

quay_repo=/home/hanqing/.cache/cve-analyzer/repos/quay_quay
git -C "$quay_repo" show bb7c06aec08ad6135b8d4b475b96a44e19b62ef9^ bb7c06aec08ad6135b8d4b475b96a44e19b62ef9 24d6083f5a43f0e5961eb1ed3bafe4c9cf468c63^ 24d6083f5a43f0e5961eb1ed3bafe4c9cf468c63 -- endpoints/api/org_mirror.py data/model/org_mirror.py
git -C "$quay_repo" show a6d759cd016b452f58bb0b3cca30487745f074d7^ a6d759cd016b452f58bb0b3cca30487745f074d7 -- util/orgmirror
git -C "$quay_repo" show 92b6f4729a5e29159f8864f923e5ea22081f9bb8 3869d001aec3e90271bd71ab7ed1490383254dca 9afe28a53b85fc40ce367cc78a5addcead88abe1 -- endpoints/api/org_mirror.py data/model/org_mirror.py util/orgmirror

feishu_upstream=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_clawdbot-feishu_f25c435dc88d86d445a87247b170272688547b364c53338716dbbc464a40122d
openclaw_repo=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
git -C "$feishu_upstream" rev-list --parents -n 1 4286755f26bcfdd5c704cc4eb0cabfdc1b314e68
git -C "$feishu_upstream" show 4286755f26bcfdd5c704cc4eb0cabfdc1b314e68 -- src/media.ts
git -C "$feishu_upstream" show 822b5f37b76284d247823efea51c47e0b975e9d1^ 822b5f37b76284d247823efea51c47e0b975e9d1 -- src/docx.ts
git -C "$openclaw_repo" show 2267d58afcc70fe19408b8f0dce108c340f3426d -- extensions/feishu/src/media.ts extensions/feishu/src/docx.ts
git -C "$openclaw_repo" show 5b4121d6011a48c71e747e3c18197f180b872c5d -- extensions/feishu/src/media.ts extensions/feishu/src/docx.ts

mlflow_repo=/home/hanqing/.cache/cve-analyzer/repos/mlflow_mlflow
git -C "$mlflow_repo" show f685d19b59889d9a93445a78abdde276ab33cf7c^ f685d19b59889d9a93445a78abdde276ab33cf7c -- mlflow/protos/service.proto
git -C "$mlflow_repo" show 3e590361e0e251382ae30cbc9993d604bfdb67d5^ 3e590361e0e251382ae30cbc9993d604bfdb67d5 -- mlflow/server/handlers.py mlflow/store/tracking/rest_store.py
git -C "$mlflow_repo" show f9b1eb510478570609ef451984a255775aa4b937 -- mlflow/server/auth/__init__.py

prompty_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_prompty_ba6a1d7460939067e71d556935dcb2f90f9e63b468d1b9590bbd336664a20bca
git -C "$prompty_repo" show a0e6108842a3bfc840a33db819a4415fbdac333d^ a0e6108842a3bfc840a33db819a4415fbdac333d -- runtime/typescript/prompty/src/core/loader.ts
git -C "$prompty_repo" show bd50f65d671e22d367ce318ff71529d2f0a71df6^ bd50f65d671e22d367ce318ff71529d2f0a71df6 -- runtime/csharp/Prompty.Core/ReferenceResolver.cs runtime/csharp/Prompty.Core/PromptyLoader.cs
git -C "$prompty_repo" show 19137b339d34824df300fc6bceae932ffd327d8e^ 19137b339d34824df300fc6bceae932ffd327d8e -- runtime/rust/prompty/src/loader
git -C "$prompty_repo" show 88ac9948d7d37995edbb2f6d36913436626c39e1 -- runtime/typescript/packages/core/src/core/loader.ts runtime/csharp/Prompty.Core/ReferenceResolver.cs runtime/rust/prompty/src/loader
```

## Squash 最小归因规则

`squash_member` 的 causal candidate 永远是 member，不是 carrier：

1. 用 member 自己的 `member^ → member` 判断风险方向和最小机制；
2. AI signal 必须出现在 member 自身；carrier marker 不可继承；
3. relation artifact/PR history 必须证明 member 被 carrier 吸收，并证明 candidate 所指 production hunks 没被后续 member 替换成另一机制；
4. 只用 `carrier → fix` 证明 mainline 可达性；fix reversal 仍必须对准 member 建立/重开的 exact mechanism；
5. 若只能找到 squash carrier，找不到 atomic member 或 member-parent，则 `NEEDS_REVIEW`，不能用 carrier 顶替。

现有 relation closure 可从 `autoresearch/orchestrator-260811-atomic150/squash-assistant-single-relation-v2/` 重放；`docs/RESEARCH-SQUASH-SINGLE-MEMBER-2026-08-11.md` 是索引，不替代 relation artifact、member Git objects 和官方 advisory。

## 迁移验收

v2 重建只有同时满足下列条件才可替代冻结 union：

- positive ledger 中 11 个 rejected component/public-ID 集合为零；negative-control ledger 中 11/11 完整保留；
- positive census 精确为 107 components / 190 public IDs / 98 CVE / 92 GHSA，base 85 + supplement 22；
- edge census 精确为 117 accepted occurrences / 116 unique pairs / 17 rejected occurrences；
- 角色账目先保持 76 个 `direct_root|reintroduction` 合并待拆、31 个 `new_surface`；在 76 个逐项拆成两个枚举前，不发布各自独立数量；
- 11 个负控以及 U020/U021 的 3 条 edge-only rejection 均能触发 shared validator 的明确拒绝分支；
- U020 的 `31c617c8…→ddfdacb2…` 不得出现在 exact-pair positive；研究说明必须保留 precursor 与完整 closure `[ddfdacb2…,56d617b7…]`；
- U011 的 `3c4368da…` 必须记录为 member / carrier `1712debbea…`，不得继续标 `direct_commit`；
- Feishu 重复 pair 必须保留两个不同 `mechanism_key` occurrence，同时 unique-pair census 只计一次；
- squash positive 全部具备 atomic member、member parent、member AI signal、member↔carrier proof 和 carrier→fix ancestry；
- `NEEDS_REVIEW`/`BLOCKED` 不因达到 150-ID 门槛而丢弃；
- 190 public IDs 虽超过 150 门槛，但只对应 107 个独立 semantic vulnerabilities，报告必须同时展示两个分母。

可重放 census：

```zsh
v2_dir=autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2
jq -s '{components:length,public_ids:([.[].public_ids[]]|unique|length),cves:([.[].public_ids[]|select(startswith("CVE-"))]|unique|length),ghsas:([.[].public_ids[]|select(startswith("GHSA-"))]|unique|length)}' "$v2_dir/ledger.jsonl"
jq -s '{accepted_occurrences:([.[]|.evidence[]?.accepted_edges[]?]|length),unique_pairs:([.[]|.evidence[]?.accepted_edges[]?|(.candidate_sha+"->"+.fix_sha)]|unique|length)}' "$v2_dir/ledger.jsonl"
wc -l "$v2_dir/rejected.jsonl" "$v2_dir/rejected_edges.jsonl"
sha256sum "$v2_dir/ledger.jsonl" "$v2_dir/rejected.jsonl" "$v2_dir/rejected_edges.jsonl" "$v2_dir/summary.json"
```

本次重放的四个 raw-file SHA-256 依次为 `35173d2824e496bf112bd80eb59e207971ca519808d33f1b93adedbb72d1e03d`、`90152a311bb519bd56ccd138edd42ca7d665250ca75d7baeba98831775023a91`、`531deb6be06de669d782ca4bda8fdf84a9bd90289c15df75dd92d5dea8796434`、`bf8a6c1e68bd11e499fead4ed059d103abc03150fa38db00c01cd2b9025a9220`。
