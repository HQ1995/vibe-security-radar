# 新候选 V13 一手证据复核（2026-08-11）

## 结论

固定的 11 个 mechanism packets 中，**PASS 0、FAIL 11、NEEDS_REVIEW 0、BLOCKED 0**。29 条候选 edge 全部拒绝，没有 accepted edge。

| 状态 | class |
|---|---|
| FAIL | CVE-2026-30631、CVE-2026-56790、CVE-2025-66565、CVE-2026-46433、CVE-2026-39313、CVE-2025-64443、CVE-2026-54549、CVE-2026-7581、CVE-2026-41900、CVE-2026-54496、CVE-2026-46420 |

本批最值得保留的方法学反例有四类：

- `exact_blame_hit=true` 仍可能只是候选碰到后来安全修复所改文件或行；MeTube 和 MCP Gateway 的候选父版本已经包含完整危险语义。
- AI 提交可能是 advisory 的**早期修复**而不是 origin；Orchard 的 Claude 提交明确实现 var-base-mul fix。
- 一方 advisory 的 commit 引用也可能不是修复提交；CVE-2026-30631 引用的 `3d37894c...` 只升级 Prisma，真正危险工具来自另一个人类提交。
- merge 只能当 carrier；GoFiber Utils 的最小安全修复 member 是 `fa3e394a...`，不能只记 merge `6c6cf047...`。

## 判定规则与来源边界

- 只有 candidate parent→delta、advisory-specific mechanism、真实 fix reversal/最小 ancestry、AI metadata 绑定 causal atomic/member 四项同时闭合才 PASS。
- CVEList 和 GitHub Advisory Database 只确定 advisory 对象、受影响机制和上游引用；实际 origin/fix 以仓库历史为准。
- OSV 未用于本批 packet 构建或裁决；`same-file`、`exact_blame_hit` 和模型票均只是 routing evidence。
- AI 修复、版本 bump、依赖 bump、同文件无关重构、新入口继承旧危险语义，均不能作为 AI origin。

packet 的 advisory source 全部是本地 CVEList/GitHub Advisory Database 一方记录，`advisory_source_status=first_party`：

```text
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/{2025,2026}/**/CVE-*.json
/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/**/GHSA-*.json
```

## 逐类裁决

| class / repo | 状态 | rejected edge | 一手反证 |
|---|---|---|---|
| CVE-2026-30631 / bytebot-ai | **FAIL** | reject `8cf21724ca82bc6deaa7bdb7c2bbe98877b23dbf` → cited `3d37894ce07ef8d8b40adc7fd309ad96c2a71313` | Claude candidate 是 backend auth infrastructure，shared-path 命中仅为 `package.json` 增加 `better-auth`。`computer_write_file` 由后续无 AI marker 的人类提交 `cdd54fb1472b027bb3da60403f4d26da61c6f620` 创建并原样转发 attacker path。advisory 引用的 `3d37894c` 只更新 Prisma packages，不修该函数，因此既不能把后续人类 origin 反投影给 AI，也不能把 advisory 的 commit 字段当 fix。 |
| CVE-2026-56790 / canboat | **FAIL** | reject `516c8ec14001faf55ba06bcbeeaae95100b6682b` → `a5a22b74b9ac5688019cba62669df08562cebd6f` | Claude candidate 修改 `analyzer/fieldtype.c` 的 unit/physical mapping。漏洞是 `analyzer/pgn.c::searchForPgn()` 的闭区间二分越界；危险 `while (start <= end)` 可追到人类提交 `930eb149127b37547b157c4acc29a595a3386271`，候选未触碰或重实现该函数。fix 同时修多个文件造成同文件 carrier 噪声。 |
| CVE-2025-66565 / gofiber/utils | **FAIL** | reject `6e68559bccafa386cfd2841bcb930666e31b6db6`, `9fc4fde77211c851ade963e1a6c9a82e64ab4e94` → carrier `6c6cf047032b9c8dff43d29f990b4b10e9b02d47`; true member `fa3e394a8c2cce100a75bdc4983996f1278a9d99` | 两个 Claude candidates 只新增/重构 `TrimSpace`。可预测 UUID fallback 已由旧人类历史建立：`UUID()` 的 rand failure→nil UUID 来自 `a08da07bc473fecaf93f427a1719c4a6867bb2ad`，`UUIDv4()` failure→`UUID()` 来自 `ff0c7c4707b1e5bd309e7fd77f0dc0865be782c4`。安全补丁在 merge 第二父链的 `fa3e394a`；候选与机制无关。 |
| CVE-2026-46433 / lldpd | **FAIL** | reject `036564423277b5b311999856f6d96347b64b9c6e` → `ca931be63a9cae0fcd8e9b6ae4e916d49f141cd6` | Claude candidate 只让 `lldpd_get_os_release()` 在空结果时返回 NULL。漏洞/fix 位于 `lldpd_decode()` VLAN decapsulation 的 `memmove(..., s - 2 * ETHER_ADDR_LEN)` 长度，函数、输入和 reversal 都不相交；父版本多年以前已含危险算术。 |
| CVE-2026-39313 / QuantGeekDev/mcp-framework | **FAIL** | reject `652694df11aad221e32e151793d04769c47dc64d`, `f165b99be7719047f573894cd045a7fabfcea5f7`, `3f7beaab832079d8efcb75b4ace529bb63bbe2b3` → `f97d2bb76d6359faf10cd1fc54b4911476b62524` | candidates 分别加 Origin validation/loopback bind、health endpoint、共享 CORS defaults。无大小上限的 `readRequestBody()` 由人类提交 `4019e11d6c48153bb80838469cfc994a46862ba2` 创建，三个候选均未改变 `body += chunk.toString()` 或 `maxMessageSize` enforcement。 |
| CVE-2025-64443 / docker/mcp-gateway | **FAIL** | reject `2b758ad53a4219524680dec7b0862d3192050650`, `5da98c05f631f00872c8c42f85a99a152bcf9c7d`, `b7b4ef358c7a711e7ef969922fa471454f9a8298` → `fe073985c8eb6e0c9317d2f198c07686f70ea06d` | 两条 `exact_blame_hit=true` 也不成立。第一条加 OAuth DCR/catalog/token-event plumbing，后两条只选取/整理 catalog URL。第一条父版本已经支持 `--transport ... sse or streaming`，`pkg/gateway/transport.go` 已直接 `httpServer.Serve(ln)`；三个 delta 均未引入或改变 listener authentication。fix 新增 SSE/streaming auth token，修的是旧 listener。 |
| CVE-2026-54549 / pipeboard-co/meta-ads-mcp | **FAIL** | reject five candidates (`b3d16fbb...`, `d0c0ebd3...`, `3fc33a45...`, `32b4d160...`, `f29523bd...`) → `7d9926336bbdac6285a988d043c4ccfe126c94c5` | 第一条 Claude candidate 是 bid constraints；其余四条是 Cursor/Claude version-only bumps。SSRF sink `download_image()` / `try_multiple_download_methods()` 来自人类 refactor `ac18da881e8e7bc3bc0d31bbe685ccbf908f66ec`；fix 增加 public-address/redirect validation。五条候选均未改 outbound URL fetch。 |
| CVE-2026-7581 / alexa69/metube | **FAIL** | reject five Copilot candidates (`565a7150...`, `1f4c4df8...`, `6e9b2dd7...`, `916ed330...`, `ecfc1883...`) → `0072d3488ae5b8d922d3ee87458d829993742a32` | 两条 `exact_blame_hit=true` 仍是假边。候选分别改 yt-dlp presets/overrides、download defaults、serializer；其父版本都已含 `socketio.AsyncServer(cors_allowed_origins='*')` 和反射请求 Origin。危险 socket CORS 可追到人类 `574ed747ebefd6b4f53e310f2d7c9f11c613f49c`，header 反射可追到人类 `d106e213fcd0b9c0ec19623a9ddf6d3c995da72d`。候选未改变 CORS 语义。 |
| CVE-2026-41900 / Stalin-143/OpenLearnX | **FAIL** | reject `f04fc76eb9a31dd3f2b3e29eabc2ad541c610430`, `a1f9cd4114024adf933ce28bf468a38c7991e101`, `a0095225184b00f2e7962e61796644553c15b123` → `14765d7d1856d564747c55c5412e2f38feab079e` | Copilot candidates 只处理 admin token、secret logging 和 frontend dependency versions。直接用 host `subprocess.run()` 执行提交代码的 compiler route 至少自人类提交 `8c56eb9e361d49fddf40ea8b2c69b5b7a863007f` 已存在；fix 重写 compiler/service sandbox。三个 candidates 未修改执行机制。 |
| CVE-2026-54496 / zcash/orchard | **FAIL** | reject `8c0c71e06778fe706265aa31a6a58b25630ee93a`, `8e9e736e44bdf3e20a367f260d31a23cb0d6d900`, `51956fb794e409e874c0d43f17f54391d05b1799` → release dependency update `8de172448be10f3a470f9ac83198dc8a185986ad` | 唯一 `exact_blame_hit=true` 的 Claude commit 主题和正文均明确是 “for the var-base-mul fix”：它 pin 已修 `halo2_gadgets`，并区分 `FixedPostNu6_2` 与历史 `InsecurePreNu6_2` circuit。它是 2026-05-31 的 remediation；advisory 时间线把漏洞引入定在 2022-05-31 NU5。另两条是 dependency/bench follow-up。AI 修复不能计为 AI origin。 |
| CVE-2026-46420 / shivammathur/setup-php | **FAIL** | reject Copilot bot `9dffd40113080c0ac167ef55469a7367bd07a556`, `f9fbb516a66b4d45d459eafb16828bba6536dfbd` → `eeef37e059fb5368a5bc8ed8ce45ff54bd39b80b` | 两个 candidate 仅加入并随 review 回退/改名 `roave/backward-compatibility-check` tool；`src/tools.ts` 的唯一 production delta 是 `parts[1]` 与 `data['tool']` 的往返替换。advisory/fix 针对 repository-controlled PHP version 被插入 shell/PowerShell，并在 `readPHPVersion()`、`parseVersion()` 等处加严格校验。没有 candidate→危险 version resolution 的因果链。 |

## 最小复现命令

```zsh
ROOT=/home/hanqing/agents/ai-slop
REPOS="$ROOT/research/orchestrator-260811-atomic150/global-batch-v13-repositories.json"

repo=$(jq -r '.[] | select(.slug=="bytebot") | .repository_path' "$REPOS")
git -c gc.auto=0 -C "$repo" log --all --reverse -S computer_write_file -- packages/bytebotd/src/mcp/computer-use.tools.ts
git -C "$repo" show --stat 8cf21724 3d37894c

repo=$(jq -r '.[] | select(.slug=="mcp-gateway") | .repository_path' "$REPOS")
git -C "$repo" grep -n -E 'sse or streaming|httpServer.Serve' 2b758ad5^ -- cmd pkg
git -C "$repo" diff 2b758ad5^ 2b758ad5 -- cmd/docker-mcp/commands/gateway.go pkg/gateway

repo=$(jq -r '.[] | select(.slug=="metube") | .repository_path' "$REPOS")
git -C "$repo" grep -n -E "cors_allowed_origins|Access-Control-Allow-Origin" 565a7150^ -- app/main.py
git -c gc.auto=0 -C "$repo" log --all --reverse -S "cors_allowed_origins='*'" -- app/main.py

repo=$(jq -r '.[] | select(.slug=="orchard") | .repository_path' "$REPOS")
git -C "$repo" show -s --format=fuller 8c0c71e0
git -C "$repo" diff 8c0c71e0^ 8c0c71e0 -- Cargo.toml src/circuit.rs
```

## 模型使用边界

DeepSeek V13 对完成解析的 26 条 edge 全判 `NOT_AI_CAUSAL`；Orchard packet 因单次响应达到长度上限而被模型阶段标为 blocked。人工审计独立收口了全部 29 条 edge，并以提交父状态、真实 diff、最小 merge member 和一方 advisory 机制为依据将 11 类全部判 FAIL。模型输出没有进入 claim-grade 证据。
