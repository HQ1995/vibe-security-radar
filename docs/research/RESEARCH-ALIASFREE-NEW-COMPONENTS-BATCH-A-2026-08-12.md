# strict-200-v3 之外的 alias-free 新组件：Batch A（2026-08-12）

## 结论先行

以 `research/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl` 为冻结基线，本批重新从一方 advisory、PR member 和本地 Git parent delta 出发核验了 5 个候选组件。结果是：

- **PASS 3 个语义组件 / 6 个 public IDs**；
- **FAIL 2 个组件 / 4 个 public IDs**；
- **NR 0**；
- PASS 与冻结基线在 public ID、official alias class、repository、accepted candidate/fix SHA、entrypoint/sink 机制指纹上均为零交集；
- 三个 PASS 彼此也不是 alias 或同机制重复。两个 BSV advisory 虽由同一个 hotfix member 修复，但分别是交易广播状态判定和身份凭证签名真实性，输入、边界、sink、回归测试与正式 public IDs 均不同，不能因共享修复提交而合并。

冻结基线当前为 **110 rows / 110 components / 200 case-normalized CVE-or-GHSA IDs**，文件 SHA-256 为：

```text
0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81
```

若主线只应用本报告的三个 PASS，批次局部算术是 **+3 components / +6 IDs**，即 113 components / 206 IDs。此处只是研究提议；本报告没有修改 ledger、JSON、脚本或任何既有文件。

## 机器可读摘要

`candidate` 和 `fix_member` 都是最小可恢复的一方 PR member；`carrier` 只表达 topology，不承载 AI 因果归因。

```jsonl
{"component_id":"alias-a8072571949b65fa46002d16","ids":["CVE-2026-40069","GHSA-9HFR-GW99-8RHX"],"repo":"github.com/sgbett/bsv-ruby-sdk","parent":"18750ea3481515d993d71ffb1e8370bd8718361f","candidate":"a1f2e62cb3dc48014c1770ec44d61811ae4b7105","origin_carrier":"61cca91368693927436cda964fef231068ac3744","fix_parent":"76e65c2779f62e5b60cbff0668c52f03ad56cc5b","fix_member":"db97de475518eef752ed52b25f49f09cbe24c187","fix_carrier":"4992e8a265fd914a7eeb0405c69d1ff0122a84cc","status":"PASS","reason":"direct_root"}
{"component_id":"alias-77f9a22ad8e8eb7f178f97b9","ids":["CVE-2026-40070","GHSA-HC36-C89J-5F4J"],"repo":"github.com/sgbett/bsv-ruby-sdk","accepted_edges":[{"parent":"886983306b7bc79cb0ea24bf4f6b52cf7826aa8b","candidate":"d14dd19f976eb5e92e0ea6755e56864f5b1ae047","origin_carrier":"a5246912bf7dc6e5b85dc3b9928d59748cf57e8e","path":"direct"},{"parent":"390f645a81a8f6e8cf3d74e6f8becfa7e5c06444","candidate":"6a4d8984026dc8f533d408f8ea737af7f7b2713d","origin_carrier":"0f2eaa03e85c9a638efe9d9c9b53a60b3372657c","path":"issuance"}],"fix_parent":"76e65c2779f62e5b60cbff0668c52f03ad56cc5b","fix_member":"db97de475518eef752ed52b25f49f09cbe24c187","fix_carrier":"4992e8a265fd914a7eeb0405c69d1ff0122a84cc","status":"PASS","reason":"two_direct_roots_one_component"}
{"component_id":"alias-2ad5323008ffeebb3948943a","ids":["CVE-2026-45136","GHSA-G3XQ-3GMV-QQ8G"],"repo":"github.com/cnighswonger/claude-code-cache-fix","parent":"a57bc4c9700554c9580a14466aad14671c03f0e9","candidate":"e19169011a7ca59c3ccee67c626c658ba47eb275","origin_pr_head":"f5e2f64a822d7c14c48bf4a10b46a75c4ce40a08","origin_carrier":"7b9322a86a5cae3230c30943bd659d7f67b0387c","release_carrier":"379da7ecbf9a89965cacc2e3fd163c48bc51ebaa","fix_parent":"9f3d85d6bcfd95c83500cf32c7a867f3a27add21","fix_member":"0a3e3c130e1ec803a2107fe83775d97f5f8f6dde","fix_pr_head":"7c36ad5c4dddab5a05fbfc407730f153767b0751","fix_carrier":"613e4df30547f3e6baf32d161eddc828f171da17","status":"PASS","reason":"squash_member_direct_root"}
{"ids":["CVE-2026-54249","GHSA-H7P7-W5GC-XJ3W"],"repo":"github.com/pydantic/pydantic-ai","candidate_carrier":"272c92ac35b2ad81b6c9eddbda425b27de4b0762","causal_members":["b6866b45bc42a63c29b5051640588c408e88f211","a6b5b5a9feb98044699b039b555d5fe89b56cf0e"],"noncausal_ai_member":"12508f1550e73b6ae78764212e51390c065b5025","fix":"ed31bdd64e11ce1475916a398ee3312791ed2d38","status":"FAIL","reason":"squash_carrier_ai_attribution_laundering"}
{"component_id":"alias-c5a7e76e9787edf4ea076555","ids":["CVE-2026-42449","GHSA-56C3-VFP2-5QQJ"],"repo":"github.com/czlonkowski/n8n-mcp","parent":"643c98bcf7663fe8f08f6dfd21d2ddeb56634387","candidate":"d9d847f230923d96e0857ccecf3a4dedcc9b0096","fix":"9639f757853149f0cb16663cc8b6b6468f27a25f","status":"FAIL","reason":"incomplete_hardening_on_preexisting_sink_and_unresolved_fork_carrier"}
```

## 判定门与证据边界

一个组件只有同时满足以下条件才记 PASS：

1. 项目仓库的一方 GitHub Security Advisory 已 `published` 且 `withdrawn_at=null`，并明确绑定 CVE/GHSA；
2. AI marker 位于真实 causal commit 自身，不从 PR、release、merge 或 squash carrier 反投影；
3. `candidate^ -> candidate` 新增 advisory 所述输入、信任边界和不安全 sink；
4. 最小可恢复的 `fix_member^ -> fix_member` 直接反转该增量；
5. direct 历史用 `merge-base --is-ancestor` 闭合；squash 历史同时要求 member 到 PR head 的 ancestry、GitHub PR 的 member/carrier 映射、carrier 的主线 ancestry和目标 hunk 等价；
6. official alias closure、基线 ID、仓库、accepted SHA 和机制指纹均不重叠。

OSV `introduced`、模型票、subject、同文件和发布日期只用于 routing。本报告没有用这些信号替代 parent delta、fix reversal 或 topology。

## PASS 1：ARC 广播器把失败状态当成功

### Official identity

- 一方 advisory：[GHSA-9HFR-GW99-8RHX](https://github.com/sgbett/bsv-ruby-sdk/security/advisories/GHSA-9hfr-gw99-8rhx)，repo API 状态 `published`，`published_at=2026-04-08T21:00:10Z`，`withdrawn_at=null`；
- CVE：[CVE-2026-40069](https://www.cve.org/CVERecord?id=CVE-2026-40069)，CNA 状态 `PUBLISHED`；
- official census closure：`alias-a8072571949b65fa46002d16`，成员恰为 `CVE-2026-40069` 与 `GHSA-9hfr-gw99-8rhx`；
- advisory 明确写出：ARC 在 [`a1f2e62cb3dc48014c1770ec44d61811ae4b7105`](https://github.com/sgbett/bsv-ruby-sdk/commit/a1f2e62cb3dc48014c1770ec44d61811ae4b7105) 引入，窄失败谓词自引入即存在；受影响 `>=0.1.0,<0.8.2`，修复于 `0.8.2`。

本地 repo：

```text
/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_bsv-ruby-sdk_58f6342c9787b0e42df822f35a61e2c42920a2e13a5631d4fe60b65f6ea8429e
```

### Parent → atomic candidate

- parent：`18750ea3481515d993d71ffb1e8370bd8718361f`；
- atomic candidate：[`a1f2e62cb3dc48014c1770ec44d61811ae4b7105`](https://github.com/sgbett/bsv-ruby-sdk/commit/a1f2e62cb3dc48014c1770ec44d61811ae4b7105)；
- 自身 marker：`Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`；
- candidate 是 [PR #26](https://github.com/sgbett/bsv-ruby-sdk/pull/26) 的单一功能 member，不是 merge carrier。PR carrier 是 `61cca91368693927436cda964fef231068ac3744`，其第二父包含该 member。

`18750ea... -> a1f2e62...` 原子新增 `lib/bsv/network/arc.rb`，其中：

```ruby
REJECTED_STATUSES = %w[REJECTED DOUBLE_SPEND_ATTEMPTED].freeze
...
def rejected_status?(tx_status)
  REJECTED_STATUSES.include?(tx_status)
end
```

因此 `INVALID`、`MALFORMED`、`MINED_IN_STALE_BLOCK`，以及 `txStatus` / `extraInfo` 中的 `ORPHAN` 不会 raise，`broadcast()` 会返回成功对象。parent 没有 ARC broadcaster；删除 candidate 后该可达 sink 不存在，所以满足 but-for。

### Atomic fix reversal 与 ancestry

- fix parent：`76e65c2779f62e5b60cbff0668c52f03ad56cc5b`；
- 最小可恢复 fix member：[`db97de475518eef752ed52b25f49f09cbe24c187`](https://github.com/sgbett/bsv-ruby-sdk/commit/db97de475518eef752ed52b25f49f09cbe24c187)；
- 一方 PR：[PR #306](https://github.com/sgbett/bsv-ruby-sdk/pull/306)；
- 官方引用的双父 carrier：[`4992e8a265fd914a7eeb0405c69d1ff0122a84cc`](https://github.com/sgbett/bsv-ruby-sdk/commit/4992e8a265fd914a7eeb0405c69d1ff0122a84cc)，parents 为 `5b49ee946bca66ad810c6588aa1eac274a0c790e` 与 `8957ece19d9f0176843c4e68f2e53d6bbf644169`。

`db97de...` 在目标文件把 failure set 扩为五个状态，并对 `txStatus` 和 `extraInfo` 加 `ORPHAN` 检查，直接反转窄谓词。该 member 同时修三个 P0 finding，是 PR 中最小可恢复 commit；本裁决只归因其 `lib/bsv/network/arc.rb` hunk。后续 `8957ece...` 做大小写和 malformed-2xx 防御性加固，其 message 明确说明“不改变 core fix”，不是本 advisory 核心 reversal 的起点。

Git ancestry：

```text
a1f2e62cb3dc48014c1770ec44d61811ae4b7105 -> db97de475518eef752ed52b25f49f09cbe24c187   rc=0
db97de475518eef752ed52b25f49f09cbe24c187 -> 8957ece19d9f0176843c4e68f2e53d6bbf644169   rc=0
8957ece19d9f0176843c4e68f2e53d6bbf644169 -> 4992e8a265fd914a7eeb0405c69d1ff0122a84cc   rc=0
```

机制指纹：

```text
github.com/sgbett/bsv-ruby-sdk
lib/bsv/network/arc.rb::ARC#handle_broadcast_response/rejected_status?
ARC txStatus+extraInfo -> failure-as-success -> BroadcastResponse
reversal: expanded status set + ORPHAN predicate
```

裁决：**PASS `direct_root`**。

## PASS 2：`acquire_certificate` 持久化未验证的 certifier signature

### Official identity

- 一方 advisory：[GHSA-HC36-C89J-5F4J](https://github.com/sgbett/bsv-ruby-sdk/security/advisories/GHSA-hc36-c89j-5f4j)，repo API 状态 `published`，`published_at=2026-04-08T21:00:05Z`，`withdrawn_at=null`；
- CVE：[CVE-2026-40070](https://www.cve.org/CVERecord?id=CVE-2026-40070)，CNA 状态 `PUBLISHED`；
- official census closure：`alias-77f9a22ad8e8eb7f178f97b9`，成员恰为 `CVE-2026-40070` 与 `GHSA-hc36-c89j-5f4j`；
- advisory 明确列出 direct-path origin `d14dd19...` 和 issuance-path origin `6a4d898...`，两条路径归属于一个未验证签名组件；修复版本为 `bsv-sdk 0.8.2` / `bsv-wallet 0.3.4`。

repo path 与 PASS 1 相同。

### Parent → atomic candidates

这是一个组件的两条独立可达 surface，不是两个漏洞计数。

#### Direct path

- parent：`886983306b7bc79cb0ea24bf4f6b52cf7826aa8b`；
- candidate：[`d14dd19f976eb5e92e0ea6755e56864f5b1ae047`](https://github.com/sgbett/bsv-ruby-sdk/commit/d14dd19f976eb5e92e0ea6755e56864f5b1ae047)；
- marker：`Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>`；
- [PR #210](https://github.com/sgbett/bsv-ruby-sdk/pull/210) 只有该一个 implementation member；双父 carrier 为 `a5246912bf7dc6e5b85dc3b9928d59748cf57e8e`。

candidate 新增 `WalletClient#acquire_certificate` 及 direct path，把调用者提供的 `signature` 原样装入 certificate hash，随后由 `acquire_certificate` 写入 storage；没有调用任何 verify。parent 不存在该 certificate-management surface。公开 advisory 的伪造 PoC 正是任意 `signature:` 进入此路径。

#### Issuance path

- parent：`390f645a81a8f6e8cf3d74e6f8becfa7e5c06444`；
- candidate：[`6a4d8984026dc8f533d408f8ea737af7f7b2713d`](https://github.com/sgbett/bsv-ruby-sdk/commit/6a4d8984026dc8f533d408f8ea737af7f7b2713d)；
- marker：`Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>`；
- [PR #219](https://github.com/sgbett/bsv-ruby-sdk/pull/219) 只有该一个 implementation member；双父 carrier 为 `0f2eaa03e85c9a638efe9d9c9b53a60b3372657c`。

parent 的 issuance protocol 明确 `raise UnsupportedActionError`；candidate 删除这个 fail-closed boundary，新增对 `certifier_url` 的 HTTP POST，并把响应体中的 `signature`、`fields` 等直接组成 certificate 返回给 storage，仍无 verify。该 delta 因而新增网络可达的第二条伪造路径。

### Atomic fix reversal 与 ancestry

fix parent、最小 member、PR 和 carrier 与 PASS 1 相同：

```text
fix parent   76e65c2779f62e5b60cbff0668c52f03ad56cc5b
fix member   db97de475518eef752ed52b25f49f09cbe24c187
fix carrier  4992e8a265fd914a7eeb0405c69d1ff0122a84cc
```

`db97de...` 新建 `lib/bsv/wallet_interface/certificate_signature.rb`，以 BRC-52 canonical preimage 和 claimed certifier key 验证签名；`acquire_via_direct` 与 `acquire_via_issuance` 都在返回、进而持久化之前调用 `CertificateSignature.verify!`。伪造或 malformed signature 会 raise，证书不再落库。这是两条 candidate surface 的同一安全不变量 reversal。

Git ancestry：

```text
d14dd19f976eb5e92e0ea6755e56864f5b1ae047 -> db97de475518eef752ed52b25f49f09cbe24c187   rc=0
6a4d8984026dc8f533d408f8ea737af7f7b2713d -> db97de475518eef752ed52b25f49f09cbe24c187   rc=0
db97de475518eef752ed52b25f49f09cbe24c187 -> 4992e8a265fd914a7eeb0405c69d1ff0122a84cc   rc=0
```

机制指纹：

```text
github.com/sgbett/bsv-ruby-sdk
lib/bsv/wallet_interface/wallet_client.rb::acquire_via_direct/acquire_via_issuance
caller-or-HTTP certificate.signature -> storage -> later trusted certificate operations
reversal: BRC-52 CertificateSignature.verify! before persistence
```

裁决：**PASS `two_direct_roots_one_component`**。

## PASS 3：statusline stdin 经 triple-quoted Python source 注入导致本地代码执行

### Official identity

- 一方 advisory：[GHSA-G3XQ-3GMV-QQ8G](https://github.com/cnighswonger/claude-code-cache-fix/security/advisories/GHSA-g3xq-3gmv-qq8g)，repo API 状态 `published`，`published_at=2026-05-07T22:33:51Z`，`withdrawn_at=null`；
- CVE：[CVE-2026-45136](https://www.cve.org/CVERecord?id=CVE-2026-45136)，CNA 状态 `PUBLISHED`；
- official census closure：`alias-2ad5323008ffeebb3948943a`，成员恰为 `CVE-2026-45136` 与 `GHSA-g3xq-3gmv-qq8g`；
- advisory 明列 vulnerable pattern `json.loads('''$input''')`、受影响 `>=3.5.0,<3.5.2`、patched `3.5.2`，并链接 issue #108、PR #110 和官方 fix carrier。

本地 repo：

```text
/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_claude-code-cache-fix_bd29d6d04905e86d154d806e186569df01926be518f7cecb24c306369fc7c339
```

### Squash origin：先拆 member，再用 carrier 证明落地

- source parent：`a57bc4c9700554c9580a14466aad14671c03f0e9`；
- 最小 causal member：[`e19169011a7ca59c3ccee67c626c658ba47eb275`](https://github.com/cnighswonger/claude-code-cache-fix/commit/e19169011a7ca59c3ccee67c626c658ba47eb275)；
- 自身 marker：`Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`；
- [PR #105](https://github.com/cnighswonger/claude-code-cache-fix/pull/105) head：`f5e2f64a822d7c14c48bf4a10b46a75c4ce40a08`；
- PR #105 的 one-parent squash carrier：`7b9322a86a5cae3230c30943bd659d7f67b0387c`，parent `9da46315b73c8e180ac6239f667bda072ce5c422`；
- v3.5.0 release PR #106 carrier：`379da7ecbf9a89965cacc2e3fd163c48bc51ebaa`，parent 正是 `7b9322a...`。

source parent 虽已有 `input=$(cat)`，但 Python source 完全不引用该变量。`e191690...` 为了从 hook stdin 取得 `session_id`，首次加入：

```sh
result=$(python3 -c "
    ...
    stdin_data = json.loads('''$input''') if '''$input''' else {}
    ...
")
```

Claude Code hook JSON 会携带 `cwd`、workspace path、transcript path 等含用户可控文件名的数据。三个单引号可提前关闭 Python literal，后续字节成为 Python source。删除该 member 后没有 stdin→Python-source 边；保留它即使其他 PR member 全部删除，注入仍成立，满足 but-for。

不能把 `7b9322a...` 或 OSV 路由出的 v3.5.0 release carrier `379da7ec...` 归因为 AI origin。严格 attribution 是 `e191690...`；carrier 只证明该 hunk进入 mainline/release。

### Squash fix：atomic member 与官方 carrier 分离

- fix base：`9f3d85d6bcfd95c83500cf32c7a867f3a27add21`；
- 最小 fix member：[`0a3e3c130e1ec803a2107fe83775d97f5f8f6dde`](https://github.com/cnighswonger/claude-code-cache-fix/commit/0a3e3c130e1ec803a2107fe83775d97f5f8f6dde)；
- [PR #110](https://github.com/cnighswonger/claude-code-cache-fix/pull/110) head：`7c36ad5c4dddab5a05fbfc407730f153767b0751`；
- GitHub advisory/CNA 引用的 one-parent squash carrier：[`613e4df30547f3e6baf32d161eddc828f171da17`](https://github.com/cnighswonger/claude-code-cache-fix/commit/613e4df30547f3e6baf32d161eddc828f171da17)，parent 同为 `9f3d85...`；tag `v3.5.2`。

`0a3e3c...` 把 stdin 捕获到 `CC_INPUT` 环境变量，再用单引号 heredoc `<<'PYEOF'` 提供固定 Python source，Python 只通过 `os.environ.get('CC_INPUT')` 读取数据。目标文件上 `fix_member` 与 `fix_carrier` 的 stable patch-id 相同：

```text
a2c5b537cf0624b524b24f52d02e91983bf821e9
```

因此该 member 是官方 carrier 中直接反转 source interpolation 的原子修复，而不是 docs/release 相邻提交。

Squash 的 member 本来不会成为 mainline carrier 的 Git ancestor；正确的双轨 topology 是：

```text
source member e191690... -> PR #105 head f5e2f64...                     rc=0
origin carrier 7b9322a... -> release carrier 379da7e... -> fix base 9f3d85... rc=0
fix member 0a3e3c... -> PR #110 head 7c36ad5...                         rc=0
origin carrier 7b9322a... -> fix carrier 613e4df...                        rc=0
member target-file patch-id == carrier target-file patch-id                  true
```

机制指纹：

```text
github.com/cnighswonger/claude-code-cache-fix
tools/quota-statusline.sh::hook stdin parser
JSON path fields -> shell interpolation -> Python source -> local code execution
reversal: environment data + single-quoted heredoc source separation
```

裁决：**PASS `squash_member_direct_root`**。

## 三个 PASS 的 alias / non-overlap 证明

| Component | Official aliases | Repository / entrypoint | 输入 → sink | Reversal | 与另外两个的关系 |
|---|---|---|---|---|---|
| `alias-a807...` | CVE-2026-40069 ↔ GHSA-9HFR | `bsv-ruby-sdk` / ARC response handler | ARC status JSON → false success | 扩 failure predicate | 与证书存储、shell/Python 都无共同边界 |
| `alias-77f9...` | CVE-2026-40070 ↔ GHSA-HC36 | `bsv-ruby-sdk` / certificate acquisition | caller/HTTP signature → trusted storage | BRC-52 verify before persist | 与 ARC 仅共享仓库及 hotfix member，不共享 input/sink/invariant |
| `alias-2ad5...` | CVE-2026-45136 ↔ GHSA-G3XQ | `claude-code-cache-fix` / statusline shell | hook JSON → Python source | env/heredoc data-code separation | 独立仓库、语言、入口与修复 |

冻结 ledger 中没有三个 official class ID、六个 public IDs、两个仓库 identity、六个 accepted candidate/fix SHA，也没有 `ARC broadcaster`、`REJECTED_STATUSES`、`CertificateSignature`、`certifier signature`、`quota-statusline`、`triple-quote` 或 `CC_INPUT` 机制锚点。故这里不是 baseline alias、同仓库重复修复或 mechanism rename。

特别说明：`db97de...` 同时承载 PASS 1 和 PASS 2 的两个不相交 hunk。共享修复 SHA 是发布批处理拓扑，不是 alias 证据。两个一方 advisory 各有独立 CVE/GHSA、独立 affected surface 和独立安全不变量；官方也没有互相声明 alias。

## FAIL 1：Pydantic `UploadedFile/providerMetadata`——AI trailer 在 squash carrier，真实成因 member 是人类提交

- 一方 advisory：[GHSA-H7P7-W5GC-XJ3W](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-h7p7-w5gc-xj3w)，`published_at=2026-06-10T14:29:58Z`，`withdrawn_at=null`，绑定 [CVE-2026-54249](https://www.cve.org/CVERecord?id=CVE-2026-54249)；
- 本地 repo：`/home/hanqing/.cache/cve-analyzer/repos/pydantic_pydantic-ai`；
- routed/mainline carrier：[`272c92ac35b2ad81b6c9eddbda425b27de4b0762`](https://github.com/pydantic/pydantic-ai/commit/272c92ac35b2ad81b6c9eddbda425b27de4b0762)，parent `0b0ec325b651ece0f0087f8a059a91a262a5efdc`，message 带 Claude Opus 4.6 trailer；
- [PR #3942](https://github.com/pydantic/pydantic-ai/pull/3942) 的真实 member history 显示：
  - `b6866b45bc42a63c29b5051640588c408e88f211` 首次把 client file part 重建为 `UploadedFile`；无 AI marker；
  - `a6b5b5a9feb98044699b039b555d5fe89b56cf0e` 把该重建迁到 `load_provider_metadata(part.provider_metadata)` 并取 `uploaded_file_id/provider`；无 AI marker；
  - `12508f1550e73b6ae78764212e51390c065b5025` 才带 `Co-Authored-By: Claude Opus 4.6`，但只改 docs、OTel mapping 顺序/docstring 和 Bedrock document naming，没有触碰 `ui/vercel_ai/_adapter.py` 的危险重建边；
- fix：[`ed31bdd64e11ce1475916a398ee3312791ed2d38`](https://github.com/pydantic/pydantic-ai/commit/ed31bdd64e11ce1475916a398ee3312791ed2d38)，parent `49f62a386041abd6e0d960dd629c3b4fe28eac63`，默认丢弃 client-submitted `UploadedFile`，机制 reversal 本身成立。

也就是说，carrier 的 Claude trailer 来自同 PR 的后期非因果 review member，不能反投影到两个真正创建 `providerMetadata -> UploadedFile` 路径的人类 member。它还与 baseline 已有 `pydantic-ai` 的 `FileUrl.force_download` SSRF 组件共享“服务端凭证获取外部资源”信任边界，更需要逐 member 区分，不能靠同仓库/相似机制补 AI attribution。

裁决：**FAIL `squash_carrier_ai_attribution_laundering`**。

## FAIL 2：n8n-mcp IPv4-mapped IPv6 bypass——AI commit 是既有 SSRF sink 上的不完整收窄

- 一方 advisory：[GHSA-56C3-VFP2-5QQJ](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-56c3-vfp2-5qqj)，`published_at=2026-04-22T20:37:28Z`，`withdrawn_at=null`，绑定 [CVE-2026-42449](https://www.cve.org/CVERecord?id=CVE-2026-42449)；
- 本地 repo：`/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_n8n-mcp_7f3ec1dcf0d7cdaa7f65f6c0aed32341a5c14c9c95b456fff2c6e355a78931a1`；
- candidate：[`d9d847f230923d96e0857ccecf3a4dedcc9b0096`](https://github.com/czlonkowski/n8n-mcp/commit/d9d847f230923d96e0857ccecf3a4dedcc9b0096)，parent `643c98bcf7663fe8f08f6dfd21d2ddeb56634387`，有 Claude Opus 4.6 trailer；
- fix：[`9639f757853149f0cb16663cc8b6b6468f27a25f`](https://github.com/czlonkowski/n8n-mcp/commit/9639f757853149f0cb16663cc8b6b6468f27a25f)，parent `59b665bda36797823df238aeaf20adb862c9f451`；`d9d847... -> 9639f...` ancestry 为 rc=0。

反证有两层：

1. parent 已允许 caller-controlled `InstanceContext.n8nApiUrl` 进入 `N8nApiClient`/axios，并明确允许 localhost、IPv4 和任意 IPv6；同一个 credential-forwarding SSRF sink 已经存在。`d9d847...` 是修复早先 GHSA-4GGG 的 remediation：新增 `validateUrlSync()`，阻断部分 IPv4/private targets，却遗漏 IPv4-mapped IPv6。相对 parent，风险是净收窄，不是 root、reintroduction 或新 surface；
2. commit subject 为 `Merge commit from fork`，单父但包含 28 个 source/dist/test/release 文件；没有公开 PR/source branch 可恢复出最小 member。即使忽略第一层，它也不满足“fork/squash 必须拆最小 member”。

`9639f...` 增加 `isPrivateOrMappedIpv6()` 并在同一 sync validator 中调用，确实修了 bypass；但 fix reversal 不能把一个风险降低但不完整的 remediation 倒推成风险增量。

裁决：**FAIL `incomplete_hardening_on_preexisting_sink`**，并附加 topology 阻断 `minimum_member_unresolved`。

## 可重放命令

### 1. 冻结基线、official alias 与零交集

```zsh
ledger_file='research/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl'
official_classes='research/orchestrator-260809-0539/current-official-census/alias_classes.jsonl'

sha256sum "$ledger_file"
jq -s '{rows:length,components:([.[].component_id]|unique|length),ids:([.[].public_ids[]|ascii_upcase]|unique|length)}' "$ledger_file"

for class_id in \
  alias-a8072571949b65fa46002d16 \
  alias-77f9a22ad8e8eb7f178f97b9 \
  alias-2ad5323008ffeebb3948943a
do
  jq -c --arg class_id "$class_id" 'select(.class_id==$class_id)' "$official_classes"
  jq -e --arg class_id "$class_id" 'select(.component_id==$class_id)' "$ledger_file" >/dev/null
  print -r -- "baseline_class_lookup $class_id rc=$?"  # 预期 4/no row
done

for public_id in \
  CVE-2026-40069 GHSA-9HFR-GW99-8RHX \
  CVE-2026-40070 GHSA-HC36-C89J-5F4J \
  CVE-2026-45136 GHSA-G3XQ-3GMV-QQ8G
do
  jq -e --arg public_id "$public_id" \
    'select(any(.public_ids[]; ascii_upcase == ($public_id|ascii_upcase)))' \
    "$ledger_file" >/dev/null
  print -r -- "baseline_public_id_lookup $public_id rc=$?"  # 预期 4/no row
done

# 不假定 evidence 的具体 schema，直接扫描整份冻结 ledger；三组命令均预期无命中。
rg -ni 'bsv-ruby-sdk|claude-code-cache-fix|sgbett|cnighswonger' "$ledger_file"
rg -ni \
  'a1f2e62cb3dc48014c1770ec44d61811ae4b7105|d14dd19f976eb5e92e0ea6755e56864f5b1ae047|6a4d8984026dc8f533d408f8ea737af7f7b2713d|db97de475518eef752ed52b25f49f09cbe24c187|e19169011a7ca59c3ccee67c626c658ba47eb275|0a3e3c130e1ec803a2107fe83775d97f5f8f6dde' \
  "$ledger_file"
rg -ni \
  'ARC broadcaster|REJECTED_STATUSES|CertificateSignature|certifier signature|quota-statusline|triple-quote|CC_INPUT|txStatus|extraInfo|BRC-52|statusline stdin' \
  "$ledger_file"
```

### 2. 一方 advisory 与 CNA 状态

```zsh
gh api repos/sgbett/bsv-ruby-sdk/security-advisories/GHSA-9hfr-gw99-8rhx \
  --jq '{ghsa_id,cve_id,state,published_at,withdrawn_at,summary,vulnerabilities,description}'
gh api repos/sgbett/bsv-ruby-sdk/security-advisories/GHSA-hc36-c89j-5f4j \
  --jq '{ghsa_id,cve_id,state,published_at,withdrawn_at,summary,vulnerabilities,description}'
gh api repos/cnighswonger/claude-code-cache-fix/security-advisories/GHSA-g3xq-3gmv-qq8g \
  --jq '{ghsa_id,cve_id,state,published_at,withdrawn_at,summary,vulnerabilities,description}'

for cve_id in CVE-2026-40069 CVE-2026-40070 CVE-2026-45136
do
  curl -fsSL "https://cveawg.mitre.org/api/cve/$cve_id" | \
    jq '{id:.cveMetadata.cveId,state:.cveMetadata.state,published:.cveMetadata.datePublished,references:.containers.cna.references}'
done
```

### 3. BSV parent/candidate/fix、topology 与 ancestry

```zsh
bsv_repo='/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_bsv-ruby-sdk_58f6342c9787b0e42df822f35a61e2c42920a2e13a5631d4fe60b65f6ea8429e'

for commit_sha in \
  a1f2e62cb3dc48014c1770ec44d61811ae4b7105 \
  d14dd19f976eb5e92e0ea6755e56864f5b1ae047 \
  6a4d8984026dc8f533d408f8ea737af7f7b2713d \
  db97de475518eef752ed52b25f49f09cbe24c187 \
  61cca91368693927436cda964fef231068ac3744 \
  a5246912bf7dc6e5b85dc3b9928d59748cf57e8e \
  0f2eaa03e85c9a638efe9d9c9b53a60b3372657c \
  4992e8a265fd914a7eeb0405c69d1ff0122a84cc
do
  git -C "$bsv_repo" show -s --format='%H%n%P%n%an <%ae>%n%ad%n%B' --date=iso-strict "$commit_sha"
done

git -C "$bsv_repo" diff 18750ea3481515d993d71ffb1e8370bd8718361f a1f2e62cb3dc48014c1770ec44d61811ae4b7105 -- lib/bsv/network/arc.rb
git -C "$bsv_repo" diff 886983306b7bc79cb0ea24bf4f6b52cf7826aa8b d14dd19f976eb5e92e0ea6755e56864f5b1ae047 -- lib/bsv/wallet_interface
git -C "$bsv_repo" diff 390f645a81a8f6e8cf3d74e6f8becfa7e5c06444 6a4d8984026dc8f533d408f8ea737af7f7b2713d -- lib/bsv/wallet_interface
git -C "$bsv_repo" diff 76e65c2779f62e5b60cbff0668c52f03ad56cc5b db97de475518eef752ed52b25f49f09cbe24c187 -- \
  lib/bsv/network/arc.rb \
  lib/bsv/wallet_interface/wallet_client.rb \
  lib/bsv/wallet_interface/certificate_signature.rb

for ancestry_pair in \
  a1f2e62cb3dc48014c1770ec44d61811ae4b7105:db97de475518eef752ed52b25f49f09cbe24c187 \
  d14dd19f976eb5e92e0ea6755e56864f5b1ae047:db97de475518eef752ed52b25f49f09cbe24c187 \
  6a4d8984026dc8f533d408f8ea737af7f7b2713d:db97de475518eef752ed52b25f49f09cbe24c187 \
  db97de475518eef752ed52b25f49f09cbe24c187:4992e8a265fd914a7eeb0405c69d1ff0122a84cc
do
  git -C "$bsv_repo" merge-base --is-ancestor "${ancestry_pair%%:*}" "${ancestry_pair##*:}"
  print -r -- "$ancestry_pair rc=$?"  # 全部预期 0
done

gh api repos/sgbett/bsv-ruby-sdk/pulls/26/commits --paginate --jq '.[]|[.sha,.parents[0].sha,.commit.message]|@tsv'
gh api repos/sgbett/bsv-ruby-sdk/pulls/210/commits --paginate --jq '.[]|[.sha,.parents[0].sha,.commit.message]|@tsv'
gh api repos/sgbett/bsv-ruby-sdk/pulls/219/commits --paginate --jq '.[]|[.sha,.parents[0].sha,.commit.message]|@tsv'
gh api repos/sgbett/bsv-ruby-sdk/pulls/306/commits --paginate --jq '.[]|[.sha,.parents[0].sha,.commit.message]|@tsv'
```

### 4. statusline squash member/carrier、reversal 与 patch identity

```zsh
cache_repo='/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_claude-code-cache-fix_bd29d6d04905e86d154d806e186569df01926be518f7cecb24c306369fc7c339'

git -C "$cache_repo" show -s --format='%H%n%P%n%an <%ae>%n%ad%n%B' --date=iso-strict \
  e19169011a7ca59c3ccee67c626c658ba47eb275
git -C "$cache_repo" diff a57bc4c9700554c9580a14466aad14671c03f0e9 e19169011a7ca59c3ccee67c626c658ba47eb275 -- tools/quota-statusline.sh

gh api repos/cnighswonger/claude-code-cache-fix/pulls/105 --jq \
  '{number,merged,merge_commit_sha,base:.base.sha,head:.head.sha,html_url}'
gh api repos/cnighswonger/claude-code-cache-fix/pulls/105/commits --paginate --jq \
  '.[]|[.sha,.parents[0].sha,.commit.message]|@tsv'
gh api repos/cnighswonger/claude-code-cache-fix/pulls/106 --jq \
  '{number,merged,merge_commit_sha,base:.base.sha,head:.head.sha,html_url}'

git -C "$cache_repo" show -s --format='%H%n%P%n%an <%ae>%n%ad%n%B' --date=iso-strict \
  0a3e3c130e1ec803a2107fe83775d97f5f8f6dde
git -C "$cache_repo" diff 9f3d85d6bcfd95c83500cf32c7a867f3a27add21 0a3e3c130e1ec803a2107fe83775d97f5f8f6dde -- tools/quota-statusline.sh

gh api repos/cnighswonger/claude-code-cache-fix/pulls/110 --jq \
  '{number,merged,merge_commit_sha,base:.base.sha,head:.head.sha,html_url}'
gh api repos/cnighswonger/claude-code-cache-fix/pulls/110/commits --paginate --jq \
  '.[]|[.sha,.parents[0].sha,.commit.message]|@tsv'

for ancestry_pair in \
  e19169011a7ca59c3ccee67c626c658ba47eb275:f5e2f64a822d7c14c48bf4a10b46a75c4ce40a08 \
  7b9322a86a5cae3230c30943bd659d7f67b0387c:379da7ecbf9a89965cacc2e3fd163c48bc51ebaa \
  379da7ecbf9a89965cacc2e3fd163c48bc51ebaa:9f3d85d6bcfd95c83500cf32c7a867f3a27add21 \
  0a3e3c130e1ec803a2107fe83775d97f5f8f6dde:7c36ad5c4dddab5a05fbfc407730f153767b0751 \
  7b9322a86a5cae3230c30943bd659d7f67b0387c:613e4df30547f3e6baf32d161eddc828f171da17
do
  git -C "$cache_repo" merge-base --is-ancestor "${ancestry_pair%%:*}" "${ancestry_pair##*:}"
  print -r -- "$ancestry_pair rc=$?"  # 全部预期 0
done

git -C "$cache_repo" diff 9f3d85d6bcfd95c83500cf32c7a867f3a27add21 0a3e3c130e1ec803a2107fe83775d97f5f8f6dde -- tools/quota-statusline.sh | git patch-id --stable
git -C "$cache_repo" diff 9f3d85d6bcfd95c83500cf32c7a867f3a27add21 613e4df30547f3e6baf32d161eddc828f171da17 -- tools/quota-statusline.sh | git patch-id --stable
```

### 5. 两个拒绝项的定点反证

```zsh
pydantic_repo='/home/hanqing/.cache/cve-analyzer/repos/pydantic_pydantic-ai'

gh api repos/pydantic/pydantic-ai/pulls/3942/commits --paginate --jq \
  '.[]|[.sha,.parents[0].sha,.commit.author.name,.commit.author.email,.commit.message]|@tsv'
git -C "$pydantic_repo" show --format= b6866b45bc42a63c29b5051640588c408e88f211 -- \
  pydantic_ai_slim/pydantic_ai/ui/vercel_ai/_adapter.py
git -C "$pydantic_repo" show --format= a6b5b5a9feb98044699b039b555d5fe89b56cf0e -- \
  pydantic_ai_slim/pydantic_ai/ui/vercel_ai/_adapter.py
git -C "$pydantic_repo" show --format= 12508f1550e73b6ae78764212e51390c065b5025
git -C "$pydantic_repo" diff 49f62a386041abd6e0d960dd629c3b4fe28eac63 ed31bdd64e11ce1475916a398ee3312791ed2d38 -- \
  pydantic_ai_slim/pydantic_ai/ui

n8n_repo='/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_n8n-mcp_7f3ec1dcf0d7cdaa7f65f6c0aed32341a5c14c9c95b456fff2c6e355a78931a1'
git -C "$n8n_repo" show d9d847f230923d96e0857ccecf3a4dedcc9b0096^:src/types/instance-context.ts
git -C "$n8n_repo" diff d9d847f230923d96e0857ccecf3a4dedcc9b0096^ d9d847f230923d96e0857ccecf3a4dedcc9b0096 -- \
  src/types/instance-context.ts src/utils/ssrf-protection.ts src/services/n8n-api-client.ts
git -C "$n8n_repo" diff 9639f757853149f0cb16663cc8b6b6468f27a25f^ 9639f757853149f0cb16663cc8b6b6468f27a25f -- \
  src/utils/ssrf-protection.ts
git -C "$n8n_repo" merge-base --is-ancestor \
  d9d847f230923d96e0857ccecf3a4dedcc9b0096 \
  9639f757853149f0cb16663cc8b6b6468f27a25f
```

## Claim boundary

本报告证明的是三个候选组件满足严格的 commit-level AI causal gate，并且在本轮冻结的 strict-200-v3 中 alias-free / mechanism-free。它不声称 OSV range 精确，不把同文件或模型输出当证明，也没有把 GitHub merge/squash carrier 的综合 trailer 分摊给所有 member。主线若采纳，应按三个 official alias class 各建一行；certificate component 中保留两条 accepted origin edge；BSV 共享 hotfix member 只在 topology/evidence 中复用，不能据此合并组件。
