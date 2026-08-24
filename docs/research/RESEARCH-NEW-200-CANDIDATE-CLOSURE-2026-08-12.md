# 200-public-ID 候选严格收口（2026-08-12）

## 结论先行

以 `strict-ledger-union-v2` 的 **107 components / 190 unique CVE-or-GHSA IDs** 为冻结起点，本轮逐提交审计了 **21 个互异语义组件、40 个未入账公开 ID、24 个 AI candidate occurrences**。这些 ID 与冻结账本的大小写归一化交集为零，21 个组件的仓库与 fix fingerprint 也均未命中账本；但因果裁决为：

- **PASS 0**；
- **FAIL 20**：13 个 `wrong_edge`，4 个 `vulnerable_same` / pre-existing mechanism，3 个把 remediation 或 merge carrier 错当 origin；
- **NR 1**：AutoBangumi 的 AI root/reintroduction 成立，但公开补丁没有反转 advisory 明列的 internal/private-address SSRF，故 `insufficient_fix_reversal`；
- **提议 supplemental rows = 0，edges = 0**；本批次后的冻结计数仍为 **107 components / 190 IDs**。

这不是“没找到新 ID”，而是新 ID 没有同时跨过 origin、atomicity 与 exact-reversal 三道门。尤其不能为了达到 200，把同文件、先后关系、AI 修复提交或不完整 hardening 发表成 AI-origin causal edge。

## 冻结范围、来源与判定门

### 冻结物

| 对象 | 冻结值 |
|---|---|
| 接受账本 | `research/orchestrator-260811-atomic150/strict-ledger-union-v2/ledger.jsonl` |
| 账本 SHA256 | `282d2975d0ee24e9949cc4d108ad5a1ffd9b045ad8548cc6b1661aaf2c18392e` |
| 账本 census | 107 JSONL rows / 107 components / 190 case-normalized unique `public_ids` |
| CVE List V5 | `/home/hanqing/.cache/cve-analyzer/cvelistV5` @ `8ca64b5ad6b84d3cd5741b023610b8494800f174` |
| GitHub Advisory DB | `/home/hanqing/.cache/cve-analyzer/advisory-database` @ `39d8887723797efc1804585dd06585c9fd751226` |
| V15 nonempty same-file candidate concatenation | SHA256 `df83f2a1d413c48cbd24bd6f99b5ee1e1cb665b8aa52ff4db466891f288a0fec` |
| V15 atomic-AI-unit concatenation | SHA256 `04f79d2ca00b350777e97ff93a798d314eee31994854c99bb0ed917438655004` |

本地官方源快照晚于多数候选，但早于 ADK、Jodit、Trix 三条 2026-07-24 之后的记录；这三条又以当前 GitHub Advisory 页面核状态：[ADK / CVE-2026-18236](https://github.com/advisories/GHSA-8qg5-x5vm-75jx)、[Jodit / CVE-2026-65841](https://github.com/advisories/GHSA-45qg-252v-3f7p)、[Trix / GHSA-53g2-mvcc-q9x3](https://github.com/advisories/GHSA-53g2-mvcc-q9x3)。其余 CVE/GHSA 均来自上述冻结官方对象。所有 21 个组件均为 published/active、`withdrawn=null`（或 CVE state `PUBLISHED`）；官方状态只是准入前提，不替代因果证明。

### Fail-closed causal gate

一个 supplemental row 只有同时满足下列条件才可 `PASS`：

1. **Official identity**：CVE/CNA 或 GitHub Advisory 已发布且未撤回；alias 必须来自官方对象。
2. **Atomic AI unit**：精确 40-SHA，自身 commit author/message/trailer 有 AI marker；不能从相邻提交或 PR carrier 反投影。
3. **Risk-increasing direct-parent delta**：`candidate^ -> candidate` 必须新增 root、重引入已消失机制，或新增具体可达 surface。已有同一不安全 sink 上的重构、功能邻近、incomplete hardening 都不算。
4. **Same mechanism**：candidate delta、官方 advisory 和 fix 必须是同一输入、边界、sink 与安全不变量。
5. **Exact atomic reversal**：`fix^ -> fix` 必须反转 candidate 所增风险；只补 scheme、错误信息或一条 sibling path 而仍保留 advisory 核心缺陷，不算 exact fix。
6. **Squash/merge topology**：发表最小真实 member；carrier 只作可达性证书。若官方引用 carrier，必须恢复 member 并证明 `member -> carrier -> fixed release`，绝不把 carrier 归给 AI。

## 机器可读摘要

以下为 JSONL；`ids` 只计本项目使用的 CVE/GHSA public-ID namespace，`candidate`/`fix`/`fix_member` 均为完整 40-SHA。

```jsonl
{"n":1,"ids":["CVE-2026-10692","GHSA-647R-72HF-4VMH"],"repo":"github.com/johnhuang316/code-index-mcp","candidate":["a1c953ab37cfa40a4ad5823efc7276433d6fee4e"],"fix":"25bc02fac74051ddae15ce79e952f00211b1ea6b","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":2,"ids":["CVE-2026-18236","GHSA-8QG5-X5VM-75JX"],"repo":"github.com/google/adk-python","candidate":["0959b06dbdf3037fe4121f12b6d25edca8fb9afc"],"fix":"c03f333769feaeaa9fe8910fbe95cb9f2d513f54","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":3,"ids":["CVE-2026-21882","GHSA-2J3P-GQW5-G59J"],"repo":"github.com/asfhtgkdavid/theshit","candidate":["0fc1b4f701171346848fd4f3b3faa967442108fb"],"fix_member":"e24169064d77e51788b496ca13f18d96cbbbbb0c","fix_carrier":"5293957b119e55212dce2c6dcbaf1d7eb794602a","status":"FAIL","reason":"vulnerable_same","net_ids":0}
{"n":4,"ids":["CVE-2026-26201","GHSA-F5P9-J34Q-PWCC"],"repo":"github.com/jm33-m0/emp3r0r","candidate":["1b448e5cbbd1a794cceab33c4fff6a32459e12fa"],"fix":"ea4d074f081dac6293f3aec38f01def5f08d5af5","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":5,"ids":["CVE-2026-30625","GHSA-CW73-5F7H-M4GV"],"repo":"github.com/upsonic/upsonic","candidate":["06850227980f003293a818846915484a09324292"],"fix":"855053fce0662227d9246268ff4a0844b481a305","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":6,"ids":["CVE-2026-32287","GHSA-65XW-VW82-R86X"],"repo":"github.com/antchfx/xpath","candidate":["02c01b0b4051e7edd1bf40f3d595cc9143936aaa"],"fix":"afd4762cc342af56345a3fb4002a59281fcab494","status":"FAIL","reason":"vulnerable_same","net_ids":0}
{"n":7,"ids":["CVE-2026-35679","GHSA-MH64-F367-WJJW"],"repo":"github.com/zcash/zcash","candidate":["d05253eb83c3425846fb39321ea04e70a3cc2835"],"fix":"db969c63f48f0f9fc518112ed0b7ace1af78b9d0","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":8,"ids":["CVE-2026-40504","GHSA-3R49-76F3-PF2M"],"repo":"github.com/marcobambini/gravity","candidate":["bb850e88847d4c07c07468c5b1b38c4875f723af"],"fix":"18b9195598d9b944376754c6d1ad76e38a4adca1","status":"FAIL","reason":"vulnerable_same","net_ids":0}
{"n":9,"ids":["CVE-2026-41180","GHSA-533Q-W4G6-5586"],"repo":"github.com/psi-4ward/psitransfer","candidate":["d1ffc37721159ccd2c8400d233baff60960d964d"],"fix":"8b547bf3e09757122efa00aab90281e3915aa0c6","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":10,"ids":["CVE-2026-42199","GHSA-38C5-483C-4QQP"],"repo":"github.com/becheran/grid","candidate":["9bf8d0b96f5e4dcc917aa3da123a5f63711d705a","781d36c5d8ebc5903c49a77a294f1edd5ecec8cb"],"fix":"be213bd3528727148bef2d523c89e95d1fd9c072","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":11,"ids":["CVE-2026-44375","GHSA-2CWQ-PWFR-WCW3"],"repo":"github.com/aarnott/nerdbank.messagepack","candidate":["4751a197be204d07e59563a1a144a8680c5af272"],"fix_member":"924121abb18f1c776212ff8b62a6df7004207534","fix_carrier":"7d1eb319cfabe7280e70699946c9a48579fa2f30","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":12,"ids":["CVE-2026-50130"],"repo":"github.com/pi-hole/pi-hole","candidate":["de7cb639d504959dc4abcf8e5e3a82e5c9c21454"],"fix_member":"88b47a280ab6ee40449dce7f8536971a507530ff","fix_carrier":"18002bf7c6bf382fe5861d01321f427019e1be89","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":13,"ids":["CVE-2026-53727","GHSA-9PMC-P236-855H"],"repo":"github.com/premailer/css_parser","candidate":["7d2ddf0189cd54b54f378f59daefa10cb036e476"],"fix":"e0a151458b2a801ae265ba420862ef8b1127b3ae","status":"FAIL","reason":"remediation_as_origin","net_ids":0}
{"n":14,"ids":["CVE-2026-54446","GHSA-X9VC-9FFQ-P3GJ"],"repo":"github.com/labs64/netlicensing-mcp","candidate":["e826d695df5a08d250dc88e9d8843ff0042ce35a"],"fix":"fbbb1d5ff88eb5400ec933a84e75601ebee48927","status":"FAIL","reason":"vulnerable_same","net_ids":0}
{"n":15,"ids":["CVE-2026-5603","GHSA-XQV9-QR76-HFQ2"],"repo":"github.com/elgentos/magento2-dev-mcp","candidate":["235f93bea9c914c23d4429db346884f6c2261ac2"],"fix_member":"235f93bea9c914c23d4429db346884f6c2261ac2","fix_carrier":"aa1ffcc0aea1b212c69787391783af27df15ae9d","status":"FAIL","reason":"remediation_as_origin","net_ids":0}
{"n":16,"ids":["CVE-2026-65841","GHSA-45QG-252V-3F7P"],"repo":"github.com/xdan/jodit","candidate":["e5ba033f57018563431e1849e51cb4a6b1492d2d"],"fix":"49a31f451f6b686f5610022a1d4406ee85138dc5","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":17,"ids":["CVE-2026-8276","GHSA-JCQV-2G3V-GM88"],"repo":"github.com/bettercap/bettercap","candidate":["3020b234eecc5fec8b606cef03f28684cafaede2"],"fix_member":"3020b234eecc5fec8b606cef03f28684cafaede2","fix_carrier":"0eaa375c5e5446bfba94a290eff92967a5deac9e","status":"FAIL","reason":"remediation_as_origin","net_ids":0}
{"n":18,"ids":["CVE-2026-8634","GHSA-FM77-94QM-4894"],"repo":"github.com/openclaw/crabbox","candidate":["ebb08b04da5364292d8bff9f376288030ab191f5"],"fix":"eaae40ae4ce009e60633f16f7f19600c74557f6f","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":19,"ids":["CVE-2026-8723","GHSA-Q8MJ-M7CP-5Q26"],"repo":"github.com/ljharb/qs","candidate":["e3062f78f5233b338ceeb8e8dfa5a07dea4b32a8","a0a81ea2071acce3eff41a040f719ac8f5c4f64c"],"fix":"21f80b33e5c8b3f7eba1034fff0da4a4a37a1d41","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":20,"ids":["GHSA-53G2-MVCC-Q9X3"],"repo":"github.com/basecamp/trix","candidate":["bf3890805a20367e85f72193bc960b15dea0031e"],"fix":"9c0a993d9fc2ffe9d56b013b030bc238f9c0557c","status":"FAIL","reason":"wrong_edge","net_ids":0}
{"n":21,"ids":["CVE-2026-59101","GHSA-P8RR-9CVG-CX5J"],"repo":"github.com/estrellaxd/auto_bangumi","candidate":["5382aec8dc68dfe5544be50fb811e6e6fb46f1cf","61ff20fef663aaac88add4f5d72fd560ed6d2abd"],"intermediate_full_guard":"c7c709fa66796536c9899eaa607fd06156e75437","published_fix":"487bdfec545e805ae416e6ddf28651bd274d6a73","status":"NR","reason":"insufficient_fix_reversal","net_ids":0}
```

## 逐组件 parent/delta/fix 裁决

所有 candidate 都有自身 marker：Cursor/Jules/Copilot bot author identity，或 `Co-Authored-By: Claude...` / `Generated with Claude Code` trailer。故下表的拒绝均为**因果或 fix-reversal 反证**，不是 attribution 缺失。

| # | 官方组件 | AI candidate 与 marker | parent/delta/fix 机制核验 | 裁决 |
|---:|---|---|---|---|
| 1 | [CVE-2026-10692 / GHSA-647R-72HF-4VMH](https://github.com/advisories/GHSA-647r-72hf-4vmh) | [`a1c953ab37cfa40a4ad5823efc7276433d6fee4e`](https://github.com/johnhuang316/code-index-mcp/commit/a1c953ab37cfa40a4ad5823efc7276433d6fee4e), Cursor identity | delta 加 Java summary parsing；[`25bc02fac74051ddae15ce79e952f00211b1ea6b`](https://github.com/johnhuang316/code-index-mcp/commit/25bc02fac74051ddae15ce79e952f00211b1ea6b) 修 `is_safe_regex_pattern` / advanced regex mode。只有 `server.py` 文件交集，没有 regex 安全边界 delta。 | **FAIL `wrong_edge`** |
| 2 | [CVE-2026-18236 / GHSA-8QG5-X5VM-75JX](https://github.com/advisories/GHSA-8qg5-x5vm-75jx) | [`0959b06dbdf3037fe4121f12b6d25edca8fb9afc`](https://github.com/google/adk-python/commit/0959b06dbdf3037fe4121f12b6d25edca8fb9afc), `google-labs-jules[bot]` | delta 过滤 `FunctionTool.run_async` 的意外参数；[`c03f333769feaeaa9fe8910fbe95cb9f2d513f54`](https://github.com/google/adk-python/commit/c03f333769feaeaa9fe8910fbe95cb9f2d513f54) 建立 confirmation target/history/registration/argument matching。候选没有创建 continuation confirmation forgery。 | **FAIL `wrong_edge`** |
| 3 | [CVE-2026-21882 / GHSA-2J3P-GQW5-G59J](https://github.com/advisories/GHSA-2j3p-gqw5-g59j) | [`0fc1b4f701171346848fd4f3b3faa967442108fb`](https://github.com/AsfhtgkDavid/theshit/commit/0fc1b4f701171346848fd4f3b3faa967442108fb), Copilot bot | parent 已以 `Command::new(...).output()` 在现有 euid 下重跑；candidate 只改成 spawn+timeout，仍未降权。真实 fix member [`e24169064d77e51788b496ca13f18d96cbbbbb0c`](https://github.com/AsfhtgkDavid/theshit/commit/e24169064d77e51788b496ca13f18d96cbbbbb0c) 加 `initgroups/setgid/setuid`，官方引用的 [`5293957b...`](https://github.com/AsfhtgkDavid/theshit/commit/5293957b119e55212dce2c6dcbaf1d7eb794602a) 是两父 merge carrier。 | **FAIL `vulnerable_same`** |
| 4 | [CVE-2026-26201 / GHSA-F5P9-J34Q-PWCC](https://github.com/advisories/GHSA-f5p9-j34q-pwcc) | [`1b448e5cbbd1a794cceab33c4fff6a32459e12fa`](https://github.com/jm33-m0/emp3r0r/commit/1b448e5cbbd1a794cceab33c4fff6a32459e12fa), Copilot author/trailer | candidate 改 preflight client/waitgroup/cancel；共享 maps 已存在。fix [`ea4d074f081dac6293f3aec38f01def5f08d5af5`](https://github.com/jm33-m0/emp3r0r/commit/ea4d074f081dac6293f3aec38f01def5f08d5af5) 才系统性同步 maps。candidate 没新增竞态 map 或不安全访问。 | **FAIL `wrong_edge`** |
| 5 | [CVE-2026-30625 / GHSA-CW73-5F7H-M4GV](https://github.com/advisories/GHSA-cw73-5f7h-m4gv) | [`06850227980f003293a818846915484a09324292`](https://github.com/upsonic/upsonic/commit/06850227980f003293a818846915484a09324292), Cursor identity | delta 只删 debug prints；advisory 是 npm/npx allowed-command RCE。[`855053fce0662227d9246268ff4a0844b481a305`](https://github.com/upsonic/upsonic/commit/855053fce0662227d9246268ff4a0844b481a305) 也不是对 candidate delta 的反转。 | **FAIL `wrong_edge`** |
| 6 | [CVE-2026-32287 / GHSA-65XW-VW82-R86X](https://github.com/advisories/GHSA-65xw-vw82-r86x) | [`02c01b0b4051e7edd1bf40f3d595cc9143936aaa`](https://github.com/antchfx/xpath/commit/02c01b0b4051e7edd1bf40f3d595cc9143936aaa), Claude trailer | candidate 重置 ancestor/filter maps；`logicalQuery.Select` 的危险 true-loop 自 2022 human root 已存在。fix [`afd4762cc342af56345a3fb4002a59281fcab494`](https://github.com/antchfx/xpath/commit/afd4762cc342af56345a3fb4002a59281fcab494) 删除旧 loop，未反转 candidate。 | **FAIL `vulnerable_same`** |
| 7 | [CVE-2026-35679 / GHSA-MH64-F367-WJJW](https://github.com/advisories/GHSA-mh64-f367-wjjw) | [`d05253eb83c3425846fb39321ea04e70a3cc2835`](https://github.com/zcash/zcash/commit/d05253eb83c3425846fb39321ea04e70a3cc2835), Claude trailer | candidate 清理 alert-system remnants；`main.cpp` 交集只是 unknown-command exclusion。fix [`db969c63f48f0f9fc518112ed0b7ace1af78b9d0`](https://github.com/zcash/zcash/commit/db969c63f48f0f9fc518112ed0b7ace1af78b9d0) 修 Sprout proof verification / `fChecked`。 | **FAIL `wrong_edge`** |
| 8 | [CVE-2026-40504 / GHSA-3R49-76F3-PF2M](https://github.com/advisories/GHSA-3r49-76f3-pf2m) | [`bb850e88847d4c07c07468c5b1b38c4875f723af`](https://github.com/marcobambini/gravity/commit/bb850e88847d4c07c07468c5b1b38c4875f723af), Claude trailer | omnibus 0.9.5 commit 虽触及 `gravity_vm_exec`，却没改变 `gravity_fiber_reassign` / register-window stack growth；危险 `stacktop +=`、`FN_COUNTREG` 与 callers blame 到 2017/2018 human history。fix [`18b9195598d9b944376754c6d1ad76e38a4adca1`](https://github.com/marcobambini/gravity/commit/18b9195598d9b944376754c6d1ad76e38a4adca1) 新增 max-stack/bounds。 | **FAIL `vulnerable_same`** |
| 9 | [CVE-2026-41180 / GHSA-533Q-W4G6-5586](https://github.com/advisories/GHSA-533q-w4g6-5586) | [`d1ffc37721159ccd2c8400d233baff60960d964d`](https://github.com/psi-4ward/psitransfer/commit/d1ffc37721159ccd2c8400d233baff60960d964d), Claude trailer | candidate 只给 download response 加 `Cache-Control: no-transform`；[`8b547bf3e09757122efa00aab90281e3915aa0c6`](https://github.com/psi-4ward/psitransfer/commit/8b547bf3e09757122efa00aab90281e3915aa0c6) 修 upload PATCH encoded/decoded traversal。 | **FAIL `wrong_edge`** |
| 10 | [CVE-2026-42199 / GHSA-38C5-483C-4QQP](https://github.com/advisories/GHSA-38c5-483c-4qqp) | [`9bf8d0b96f5e4dcc917aa3da123a5f63711d705a`](https://github.com/becheran/grid/commit/9bf8d0b96f5e4dcc917aa3da123a5f63711d705a), [`781d36c5d8ebc5903c49a77a294f1edd5ecec8cb`](https://github.com/becheran/grid/commit/781d36c5d8ebc5903c49a77a294f1edd5ecec8cb), Copilot bot | 两条 candidate 新增 `delete_row/delete_col` 及测试。fix [`be213bd3528727148bef2d523c89e95d1fd9c072`](https://github.com/becheran/grid/commit/be213bd3528727148bef2d523c89e95d1fd9c072) 给 `expand_rows/prepend` 加 overflow checks。 | **FAIL `wrong_edge` ×2** |
| 11 | [CVE-2026-44375 / GHSA-2CWQ-PWFR-WCW3](https://github.com/advisories/GHSA-2cwq-pwfr-wcw3) | [`4751a197be204d07e59563a1a144a8680c5af272`](https://github.com/AArnott/Nerdbank.MessagePack/commit/4751a197be204d07e59563a1a144a8680c5af272), Copilot bot | candidate 改 converter exception reporting；漏洞是 DateTime extension length 驱动 `stackalloc`。真实 fix member [`924121abb18f1c776212ff8b62a6df7004207534`](https://github.com/AArnott/Nerdbank.MessagePack/commit/924121abb18f1c776212ff8b62a6df7004207534)；[`7d1eb319...`](https://github.com/AArnott/Nerdbank.MessagePack/commit/7d1eb319cfabe7280e70699946c9a48579fa2f30) 是两父 PR carrier。 | **FAIL `wrong_edge`** |
| 12 | [CVE-2026-50130](https://www.cve.org/CVERecord?id=CVE-2026-50130) | [`de7cb639d504959dc4abcf8e5e3a82e5c9c21454`](https://github.com/pi-hole/pi-hole/commit/de7cb639d504959dc4abcf8e5e3a82e5c9c21454), Copilot trailer | candidate 加 gravity tests / `resetRepo` quoting；漏洞是 root-owned logrotate config 被非特权写路径替换。真实 fix member [`88b47a280ab6ee40449dce7f8536971a507530ff`](https://github.com/pi-hole/pi-hole/commit/88b47a280ab6ee40449dce7f8536971a507530ff) 把配置移至 `/etc/logrotate.d/pihole`；[`18002bf7...`](https://github.com/pi-hole/pi-hole/commit/18002bf7c6bf382fe5861d01321f427019e1be89) 是 merge carrier。 | **FAIL `wrong_edge`** |
| 13 | [CVE-2026-53727 / GHSA-9PMC-P236-855H](https://github.com/advisories/GHSA-9pmc-p236-855h) | [`7d2ddf0189cd54b54f378f59daefa10cb036e476`](https://github.com/premailer/css_parser/commit/7d2ddf0189cd54b54f378f59daefa10cb036e476), Claude trailer | commit subject/body 明写 `vuln-fix`，把 remote fetch 路由到 SSRF filter 并默认禁 `file://`；它与先行 tests `ba74c3c...`、后续 guard [`e0a151458b2a801ae265ba420862ef8b1127b3ae`](https://github.com/premailer/css_parser/commit/e0a151458b2a801ae265ba420862ef8b1127b3ae) 构成修复链。risk delta 为负，不能当 origin。 | **FAIL `remediation_as_origin`** |
| 14 | [CVE-2026-54446 / GHSA-X9VC-9FFQ-P3GJ](https://github.com/advisories/GHSA-x9vc-9ffq-p3gj) | [`e826d695df5a08d250dc88e9d8843ff0042ce35a`](https://github.com/Labs64/NetLicensing-MCP/commit/e826d695df5a08d250dc88e9d8843ff0042ce35a), Claude trailer | candidate 加 destructive-operation confirmation tokens。其 parent 已有 `ApiKeyMiddleware` 的 missing-key pass-through，client 也已 fallback 到 server env key。fix [`fbbb1d5ff88eb5400ec933a84e75601ebee48927`](https://github.com/Labs64/NetLicensing-MCP/commit/fbbb1d5ff88eb5400ec933a84e75601ebee48927) 才拒绝 missing key。 | **FAIL `vulnerable_same`** |
| 15 | [CVE-2026-5603 / GHSA-XQV9-QR76-HFQ2](https://github.com/advisories/GHSA-xqv9-qr76-hfq2) | [`235f93bea9c914c23d4429db346884f6c2261ac2`](https://github.com/elgentos/magento2-dev-mcp/commit/235f93bea9c914c23d4429db346884f6c2261ac2), Copilot bot | member subject 是 `fix: prevent command injection...`，以 `execFile`/shell quoting 消除漏洞；[`aa1ffcc0...`](https://github.com/elgentos/magento2-dev-mcp/commit/aa1ffcc0aea1b212c69787391783af27df15ae9d) 只是两父 merge carrier，第二父正是该 member。 | **FAIL `remediation_as_origin`** |
| 16 | [CVE-2026-65841 / GHSA-45QG-252V-3F7P](https://github.com/advisories/GHSA-45qg-252v-3f7p) | [`e5ba033f57018563431e1849e51cb4a6b1492d2d`](https://github.com/xdan/jodit/commit/e5ba033f57018563431e1849e51cb4a6b1492d2d), Claude trailer | candidate 改 storage provider；与 fix 唯一共同文件是 changelog。fix [`49a31f451f6b686f5610022a1d4406ee85138dc5`](https://github.com/xdan/jodit/commit/49a31f451f6b686f5610022a1d4406ee85138dc5) 在 clean-html visitor 处理 SVG/MathML tag canonicalization。 | **FAIL `wrong_edge`** |
| 17 | [CVE-2026-8276 / GHSA-JCQV-2G3V-GM88](https://github.com/advisories/GHSA-jcqv-2g3v-gm88) | [`3020b234eecc5fec8b606cef03f28684cafaede2`](https://github.com/bettercap/bettercap/commit/3020b234eecc5fec8b606cef03f28684cafaede2), Copilot bot | member subject 明写修 crafted MySQL handshake panic，是 exact security remediation；[`0eaa375c...`](https://github.com/bettercap/bettercap/commit/0eaa375c5e5446bfba94a290eff92967a5deac9e) 是两父 merge carrier，第二父为该 member。 | **FAIL `remediation_as_origin`** |
| 18 | [CVE-2026-8634 / GHSA-FM77-94QM-4894](https://github.com/advisories/GHSA-fm77-94qm-4894) | [`ebb08b04da5364292d8bff9f376288030ab191f5`](https://github.com/openclaw/crabbox/commit/ebb08b04da5364292d8bff9f376288030ab191f5), Copilot trailer | candidate 加 Azure login/Windows sync，交集仅 SSH tests。fix [`eaae40ae4ce009e60633f16f7f19600c74557f6f`](https://github.com/openclaw/crabbox/commit/eaae40ae4ce009e60633f16f7f19600c74557f6f) 修 repo config environment wildcard。 | **FAIL `wrong_edge`** |
| 19 | [CVE-2026-8723 / GHSA-Q8MJ-M7CP-5Q26](https://github.com/advisories/GHSA-q8mj-m7cp-5q26) | [`e3062f78f5233b338ceeb8e8dfa5a07dea4b32a8`](https://github.com/ljharb/qs/commit/e3062f78f5233b338ceeb8e8dfa5a07dea4b32a8), [`a0a81ea2071acce3eff41a040f719ac8f5c4f64c`](https://github.com/ljharb/qs/commit/a0a81ea2071acce3eff41a040f719ac8f5c4f64c), Claude trailers | candidates 修 formatter/delimiter bugs；官方 advisory 明列 comma+`encodeValuesOnly` 的危险 shape 由 2023 human `4c4b23d...` 引入。fix [`21f80b33e5c8b3f7eba1034fff0da4a4a37a1d41`](https://github.com/ljharb/qs/commit/21f80b33e5c8b3f7eba1034fff0da4a4a37a1d41) 加 null guard。 | **FAIL `wrong_edge` ×2** |
| 20 | [GHSA-53G2-MVCC-Q9X3](https://github.com/advisories/GHSA-53g2-mvcc-q9x3) | [`bf3890805a20367e85f72193bc960b15dea0031e`](https://github.com/basecamp/trix/commit/bf3890805a20367e85f72193bc960b15dea0031e), Claude trailer | candidate 把 Karma 换成 web-test-runner；生成的 bundled `action_text-trix/.../trix.js` 变化来自构建/metadata，source `StringPiece.fromJSON` 没有风险 delta。fix [`9c0a993d9fc2ffe9d56b013b030bc238f9c0557c`](https://github.com/basecamp/trix/commit/9c0a993d9fc2ffe9d56b013b030bc238f9c0557c) 在 source model 加 DOMPurify href validation。 | **FAIL `wrong_edge`** |
| 21 | [CVE-2026-59101 / GHSA-P8RR-9CVG-CX5J](https://github.com/advisories/GHSA-p8rr-9cvg-cx5j) | [`5382aec8dc68dfe5544be50fb811e6e6fb46f1cf`](https://github.com/EstrellaXD/Auto_Bangumi/commit/5382aec8dc68dfe5544be50fb811e6e6fb46f1cf) 明写 Generated with Claude Code；[`61ff20fef663aaac88add4f5d72fd560ed6d2abd`](https://github.com/EstrellaXD/Auto_Bangumi/commit/61ff20fef663aaac88add4f5d72fd560ed6d2abd) 有 Claude trailer | `5382aec8` 原子新增 pre-auth setup downloader 的任意-host HTTP request；[`c7c709fa66796536c9899eaa607fd06156e75437`](https://github.com/EstrellaXD/Auto_Bangumi/commit/c7c709fa66796536c9899eaa607fd06156e75437) 曾完整阻止 private/reserved/loopback，`61ff20fe` 又明确为 allow private IP 删除 guard，二者都是强 causal origin/reintroduction。可是公开 [`487bdfec545e805ae416e6ddf28651bd274d6a73`](https://github.com/EstrellaXD/Auto_Bangumi/commit/487bdfec545e805ae416e6ddf28651bd274d6a73) 只限制 `http/https`、停止回显 raw errors，代码/commit message 均保留 private/loopback；[CNA](https://www.cve.org/CVERecord?id=CVE-2026-59101) 明列的 internal/reserved probing 没被反转。 | **NR `insufficient_fix_reversal`**；不得发表 `5382→487b` 或 `61ff→487b` 为 exact edge |

### Squash/merge 拓扑的独立结论

本批没有可接受 squash-origin。三条官方 fix 引用的是 merge carrier，必须保留其真实 atomic fix member：

| 组件 | atomic fix member | carrier | 证明 |
|---|---|---|---|
| theshit | `e24169064d77e51788b496ca13f18d96cbbbbb0c` | `5293957b119e55212dce2c6dcbaf1d7eb794602a` | member 可达 carrier；carrier parents 为 `1979ca49... ab59d6a7...` |
| Nerdbank.MessagePack | `924121abb18f1c776212ff8b62a6df7004207534` | `7d1eb319cfabe7280e70699946c9a48579fa2f30` | member 可达 carrier；member 与 carrier 共享 first-parent base `4da53afa...` |
| Pi-hole | `88b47a280ab6ee40449dce7f8536971a507530ff` | `18002bf7c6bf382fe5861d01321f427019e1be89` | member 可达 carrier；carrier parents 为 `d8625e29... 33feea11...` |

Magento 与 bettercap 的情形相反：路由出的“candidate”本身就是 atomic security-fix member；各自 carrier 的第二父正是该 member。这证明 AI remediation，不能证明 AI origin。

## 精确 supplemental 提议与 count impact

```json
{"supplemental_rows":[],"supplemental_edges":[],"delta_components":0,"delta_public_ids":0,"post_components":107,"post_public_ids":190}
```

上述 canonical compact JSON（`jq -cS` 输出）的 SHA256 为：

```text
c3f8a8396d5094fba760885a860823d6e74fc64b00abfb4cbcedbbfbae8b278f
```

目标 200 相对冻结基线仍差 10 IDs。本报告不评价主线在冻结点之后由其他独立研究新增的组件；它只证明这 21 个候选组件不能贡献安全的新增 row。

## 完整复核命令与本地 repo paths

### Census、ID/semantic dedup 与官方状态

```zsh
ledger='research/orchestrator-260811-atomic150/strict-ledger-union-v2/ledger.jsonl'

jq -s '{rows:length,components:([.[].component_id]|unique|length),ids:([.[].public_ids[]]|map(ascii_upcase)|unique|length)}' "$ledger"
sha256sum "$ledger"

# V15 中 20 个非空 class / 22 candidate occurrences / 38 CVE-or-GHSA IDs。
find research/orchestrator-260811-atomic150/global-same-file-v15 \
  -name same-file-candidates.jsonl -type f -size +0c -print0 \
  | sort -z | xargs -0 cat \
  | jq -s '{classes:([.[].analysis_subject]|unique|length),pairs:length,ids:([.[].member_ids[]]|map(ascii_upcase)|unique|length)}'

# 另加 AutoBangumi 两个 IDs 后，以 jq/comm 对 baseline public_ids 做大小写归一化差集；预期 overlap=[]、candidate_ids=40。
jq -r '.public_ids[]|ascii_upcase' "$ledger" | sort -u > /tmp/ai-slop-v2-ids.txt
{
  find research/orchestrator-260811-atomic150/global-same-file-v15 \
    -name same-file-candidates.jsonl -type f -size +0c -print0 \
    | sort -z | xargs -0 cat | jq -r '.member_ids[]|ascii_upcase'
  print -r -- CVE-2026-59101 GHSA-P8RR-9CVG-CX5J
} | sort -u > /tmp/ai-slop-new-candidate-ids.txt
comm -12 /tmp/ai-slop-v2-ids.txt /tmp/ai-slop-new-candidate-ids.txt
wc -l /tmp/ai-slop-v2-ids.txt /tmp/ai-slop-new-candidate-ids.txt

git -C /home/hanqing/.cache/cve-analyzer/cvelistV5 rev-parse HEAD
git -C /home/hanqing/.cache/cve-analyzer/advisory-database rev-parse HEAD
jq '{state:.cveMetadata.state,published:.cveMetadata.datePublished}' \
  /home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/59xxx/CVE-2026-59101.json
rg --files /home/hanqing/.cache/cve-analyzer/advisory-database/advisories \
  | rg -i '/GHSA-p8rr-9cvg-cx5j.json$' | xargs jq '{id,published,withdrawn,aliases}'

# fix-fingerprint semantic dedup；对本报告列出的 21 个 fix/carrier SHA 逐一执行，预期均无输出。
rg -i '<full-fix-or-carrier-sha>' "$ledger"
```

`/tmp` 文件只是复核时的临时排序输入，不是研究产物。

### 通用 atomic replay 与 24 个 candidate occurrences

下列 zsh 片段逐 pair 打印 commit identity/parents/message、candidate direct-parent delta、atomic fix direct-parent delta，并验证 ancestry；命令内路径和 SHA 均已具体化。

```zsh
audit_pair() {
  local repo_dir="$1" candidate_sha="$2" fix_sha="$3"
  git -C "$repo_dir" cat-file -e "${candidate_sha}^{commit}"
  git -C "$repo_dir" cat-file -e "${fix_sha}^{commit}"
  git -C "$repo_dir" show -s --format='%H%n%P%n%an <%ae>%n%ad%n%B' --date=iso-strict "$candidate_sha"
  git -C "$repo_dir" diff --stat "${candidate_sha}^" "$candidate_sha"
  git -C "$repo_dir" diff "${candidate_sha}^" "$candidate_sha"
  git -C "$repo_dir" show -s --format='%H%n%P%n%an <%ae>%n%ad%n%B' --date=iso-strict "$fix_sha"
  git -C "$repo_dir" diff --stat "${fix_sha}^" "$fix_sha"
  git -C "$repo_dir" diff "${fix_sha}^" "$fix_sha"
  git -C "$repo_dir" merge-base --is-ancestor "$candidate_sha" "$fix_sha"
}

audit_pair /home/hanqing/.cache/cve-analyzer/repos/github.com_johnhuang316_code-index-mcp a1c953ab37cfa40a4ad5823efc7276433d6fee4e 25bc02fac74051ddae15ce79e952f00211b1ea6b
audit_pair /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_adk-python_824d4e8405c309c82eed6cc2fe1ebc5da8307af63d37b5e67aef8166682d31a3 0959b06dbdf3037fe4121f12b6d25edca8fb9afc c03f333769feaeaa9fe8910fbe95cb9f2d513f54
audit_pair /home/hanqing/.cache/cve-analyzer/repos/asfhtgkdavid_theshit 0fc1b4f701171346848fd4f3b3faa967442108fb e24169064d77e51788b496ca13f18d96cbbbbb0c
audit_pair /home/hanqing/.cache/cve-analyzer/repos/jm33-m0_emp3r0r 1b448e5cbbd1a794cceab33c4fff6a32459e12fa ea4d074f081dac6293f3aec38f01def5f08d5af5
audit_pair /home/hanqing/.cache/cve-analyzer/repos/upsonic_upsonic 06850227980f003293a818846915484a09324292 855053fce0662227d9246268ff4a0844b481a305
audit_pair /home/hanqing/.cache/cve-analyzer/repos/github.com_antchfx_xpath 02c01b0b4051e7edd1bf40f3d595cc9143936aaa afd4762cc342af56345a3fb4002a59281fcab494
audit_pair /home/hanqing/.cache/cve-analyzer/repos/v2_github.com_zcash_d52a7db184027971aec3f8210b63f50290f64ff31ab252069d93395b615d5992 d05253eb83c3425846fb39321ea04e70a3cc2835 db969c63f48f0f9fc518112ed0b7ace1af78b9d0
audit_pair /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_gravity_64e9fc509a8445f0f071b86bf8b1fdcda8ff6bb419d8c4a9606a37d9183df690 bb850e88847d4c07c07468c5b1b38c4875f723af 18b9195598d9b944376754c6d1ad76e38a4adca1
audit_pair /home/hanqing/.cache/cve-analyzer/repos/psi-4ward_psitransfer d1ffc37721159ccd2c8400d233baff60960d964d 8b547bf3e09757122efa00aab90281e3915aa0c6
audit_pair /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_grid_1fc4c367adc4ef465853da0f2a4f7c25e6acd013c7aee0c568df997a46abf5af 9bf8d0b96f5e4dcc917aa3da123a5f63711d705a be213bd3528727148bef2d523c89e95d1fd9c072
audit_pair /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_grid_1fc4c367adc4ef465853da0f2a4f7c25e6acd013c7aee0c568df997a46abf5af 781d36c5d8ebc5903c49a77a294f1edd5ecec8cb be213bd3528727148bef2d523c89e95d1fd9c072
audit_pair /home/hanqing/.cache/cve-analyzer/repos/github.com_aarnott_nerdbank.messagepack 4751a197be204d07e59563a1a144a8680c5af272 924121abb18f1c776212ff8b62a6df7004207534
audit_pair /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_pi-hole_735c58304cfa641475686b3455c386f02f564db05d74d37ae7234e0d07ad8c8c de7cb639d504959dc4abcf8e5e3a82e5c9c21454 88b47a280ab6ee40449dce7f8536971a507530ff
audit_pair /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_css_parser_0ef00638fae85d798c7bcf0ba4a9d3e0c9f808025a083c3b58ffa6e6b9a30f40 7d2ddf0189cd54b54f378f59daefa10cb036e476 e0a151458b2a801ae265ba420862ef8b1127b3ae
audit_pair /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_netlicensing-mcp_1c714c3b69c68668ac6a3dc60c2aa8cf2aea0ef4d1f6dd7633c2d7654433148d e826d695df5a08d250dc88e9d8843ff0042ce35a fbbb1d5ff88eb5400ec933a84e75601ebee48927
audit_pair /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_magento2-dev-mcp_fb17ab9ac6ee64baf932ce63f1509933c075a5104d79cb508c7a4543f5f97357 235f93bea9c914c23d4429db346884f6c2261ac2 aa1ffcc0aea1b212c69787391783af27df15ae9d
audit_pair /home/hanqing/.cache/cve-analyzer/repos/v2_github.com_jodit_adce409b9adeba953dd932670cb115c5cbba45a25ca1559cb062f2068b1ba539 e5ba033f57018563431e1849e51cb4a6b1492d2d 49a31f451f6b686f5610022a1d4406ee85138dc5
audit_pair /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_bettercap_de9c2f353a2e8b36df111b3b3d274b344e80c12849c24e37e70eb6c5649dd603 3020b234eecc5fec8b606cef03f28684cafaede2 0eaa375c5e5446bfba94a290eff92967a5deac9e
audit_pair /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_crabbox_e1a8d263782692c4ab16ef8e980393c58538ef65faf8403e3d370e1ec0123599 ebb08b04da5364292d8bff9f376288030ab191f5 eaae40ae4ce009e60633f16f7f19600c74557f6f
audit_pair /home/hanqing/.cache/cve-analyzer/repos/ljharb_qs e3062f78f5233b338ceeb8e8dfa5a07dea4b32a8 21f80b33e5c8b3f7eba1034fff0da4a4a37a1d41
audit_pair /home/hanqing/.cache/cve-analyzer/repos/ljharb_qs a0a81ea2071acce3eff41a040f719ac8f5c4f64c 21f80b33e5c8b3f7eba1034fff0da4a4a37a1d41
audit_pair /home/hanqing/.cache/cve-analyzer/repos/basecamp_trix bf3890805a20367e85f72193bc960b15dea0031e 9c0a993d9fc2ffe9d56b013b030bc238f9c0557c
audit_pair /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_auto_bangumi_4021d9210b67fb76e94527ac9a528c0c6d218abf93781a18189250ff2b9c4776 5382aec8dc68dfe5544be50fb811e6e6fb46f1cf 487bdfec545e805ae416e6ddf28651bd274d6a73
audit_pair /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_auto_bangumi_4021d9210b67fb76e94527ac9a528c0c6d218abf93781a18189250ff2b9c4776 61ff20fef663aaac88add4f5d72fd560ed6d2abd 487bdfec545e805ae416e6ddf28651bd274d6a73
```

### Topology、pre-existing mechanism 与 incomplete-fix 定点命令

```zsh
# Merge/member：均预期 exit 0；同时打印 carrier 双父。
git -C /home/hanqing/.cache/cve-analyzer/repos/asfhtgkdavid_theshit merge-base --is-ancestor e24169064d77e51788b496ca13f18d96cbbbbb0c 5293957b119e55212dce2c6dcbaf1d7eb794602a
git -C /home/hanqing/.cache/cve-analyzer/repos/asfhtgkdavid_theshit show -s --format='%H %P %s' 5293957b119e55212dce2c6dcbaf1d7eb794602a e24169064d77e51788b496ca13f18d96cbbbbb0c
git -C /home/hanqing/.cache/cve-analyzer/repos/github.com_aarnott_nerdbank.messagepack merge-base --is-ancestor 924121abb18f1c776212ff8b62a6df7004207534 7d1eb319cfabe7280e70699946c9a48579fa2f30
git -C /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_pi-hole_735c58304cfa641475686b3455c386f02f564db05d74d37ae7234e0d07ad8c8c merge-base --is-ancestor 88b47a280ab6ee40449dce7f8536971a507530ff 18002bf7c6bf382fe5861d01321f427019e1be89

# Candidate 是 remediation member，而不是 origin。
git -C /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_magento2-dev-mcp_fb17ab9ac6ee64baf932ce63f1509933c075a5104d79cb508c7a4543f5f97357 show -s --format='%H%n%P%n%B' 235f93bea9c914c23d4429db346884f6c2261ac2 aa1ffcc0aea1b212c69787391783af27df15ae9d
git -C /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_bettercap_de9c2f353a2e8b36df111b3b3d274b344e80c12849c24e37e70eb6c5649dd603 show -s --format='%H%n%P%n%B' 3020b234eecc5fec8b606cef03f28684cafaede2 0eaa375c5e5446bfba94a290eff92967a5deac9e

# AutoBangumi：显示 full guard、AI reintroduction 和 published incomplete fix。
auto_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_auto_bangumi_4021d9210b67fb76e94527ac9a528c0c6d218abf93781a18189250ff2b9c4776
git -C "$auto_repo" show -s --format='%H%n%P%n%B' 5382aec8dc68dfe5544be50fb811e6e6fb46f1cf c7c709fa66796536c9899eaa607fd06156e75437 61ff20fef663aaac88add4f5d72fd560ed6d2abd 487bdfec545e805ae416e6ddf28651bd274d6a73
git -C "$auto_repo" diff 61ff20fef663aaac88add4f5d72fd560ed6d2abd^ 61ff20fef663aaac88add4f5d72fd560ed6d2abd -- backend/src/module/api/setup.py
git -C "$auto_repo" diff 487bdfec545e805ae416e6ddf28651bd274d6a73^ 487bdfec545e805ae416e6ddf28651bd274d6a73 -- backend/src/module/api/setup.py

# 典型 pre-existing blame / generated-artifact false edge。
git -C /home/hanqing/.cache/cve-analyzer/repos/github.com_antchfx_xpath blame -l afd4762cc342af56345a3fb4002a59281fcab494^ -- query.go
git -C /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_gravity_64e9fc509a8445f0f071b86bf8b1fdcda8ff6bb419d8c4a9606a37d9183df690 log --all --reverse -S 'gravity_fiber_reassign' -- src/runtime/gravity_vm.c
git -C /home/hanqing/.cache/cve-analyzer/repos/ljharb_qs log --all --reverse -S 'maybeMap(obj, encoder)' -- lib/stringify.js
git -C /home/hanqing/.cache/cve-analyzer/repos/basecamp_trix diff bf3890805a20367e85f72193bc960b15dea0031e^ bf3890805a20367e85f72193bc960b15dea0031e -- src/trix/models/string_piece.js action_text-trix/app/assets/javascripts/trix.js
```

## Claim boundary

V12–V15 文档、OSV ranges、same-file overlap 与模型判断仅用于召回。本报告的裁决来自本地 first-party Git 的 parent/delta/fix、官方 advisory/CNA 机制和 topology；没有把 routing evidence 升格为 causal proof。V12 的 Conductor 与 V14 的 mail-mcp-bridge PASS 已在冻结 190-ID 账本中，不能重复计数；V15 cross-file pool 的模型提升项也已由生产路径 blame 反证。本批能安全交付的是一组高价值 negative/NR controls，而不是新的 accepted edge。
