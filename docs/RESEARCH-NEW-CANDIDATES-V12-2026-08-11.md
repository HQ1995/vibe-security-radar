# 新候选 V12 一手证据复核（2026-08-11）

## 结论

固定的 9 个 mechanism packets 中，**PASS 1、FAIL 8、NEEDS_REVIEW 0、BLOCKED 0**。

| 状态 | class |
|---|---|
| PASS | CVE-2026-58138（Conductor） |
| FAIL | CVE-2026-47157、CVE-2026-33243、CVE-2026-32885、CVE-2026-58168、CVE-2026-42864、CVE-2026-34745、CVE-2025-67743、CVE-2026-16488 |

唯一接受的原子 edge 是：

```text
840ec19c1f68f46b1c9c6a68e6bfa0d9481c3434
  -> c691e35e768caeb802c9f06ecdd9674c80081af1
origin_kind=direct_commit
AI signal=Claude Code generation marker + Claude co-author trailer
```

`87a7d96aabbb706d6e84f812b93da5165028d18f` 是祖先链上的部分修复；最终 accepted edge 使用包含该部分修复并继续关闭 GraalJS escape surface 的 `c691e35e...`。两条修复引用不重复计算为两个 origin。

## 判定规则与 OSV 边界

- 四项同时闭合才 PASS：candidate parent→delta、advisory-specific mechanism、真实 fix reversal/最小 ancestry、AI metadata 绑定 causal atomic/member。
- OSV、同文件、`exact_blame_hit`、模型多数票和修复提交触达路径都只用于 recall/routing，不能证明 origin。
- squash、merge、import 是 carrier；归因必须落回 atomic/member。本批 DeepTutor 的 `90046374...` 是 merge carrier，真正修复逻辑在其父链。
- AI 修复旧漏洞不等于 AI 引入漏洞；AI 对旧代码做不改变危险语义的 lint/refactor 也不算 causal contributor。
- 新 surface 只有在候选创造或实质重实现 advisory 覆盖的可达危险路径、且 fix 关闭该路径时才成立。仅继承旧 sink 或保留旧行不成立。

一手 advisory 路由来自本地 CVEList checkout：

```text
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2025/67xxx/CVE-2025-67743.json
/home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/{16xxx,32xxx,33xxx,34xxx,42xxx,47xxx,58xxx}/CVE-*.json
```

结论本身以这些记录引用的上游 security advisory、commit 和实际 git history/diff 为准，不使用 OSV `introduced` 作为事实。

## 逐类裁决

| class / repo | 状态 | accepted/rejected edge | 一手闭环或反证 |
|---|---|---|---|
| CVE-2026-58138 / conductor-oss/conductor | **PASS** | accept `840ec19c1f68f46b1c9c6a68e6bfa0d9481c3434` → final fix `c691e35e768caeb802c9f06ecdd9674c80081af1`; partial fix `87a7d96aabbb706d6e84f812b93da5165028d18f` | Candidate 有 Claude Code marker/trailer，并把父版本 Nashorn `getScriptEngine("--no-java")` 换成 GraalJS `Context.newBuilder("js").allowHostAccess(HostAccess.ALL)`。CVE 精确点名 `HostAccess.ALL`/`allowAllAccess(true)` RCE。`87a7d96a` 先 deny 高危 Java classes，`c691e35e` 再禁 host class loading、native access、thread/process creation 等；ancestry 为 candidate→partial→final。AI 提交创造了 advisory 机制，不是只新增调用者。 |
| CVE-2026-47157 / subzeroid/aiograpi | **FAIL** | reject `650977351f9be15edae856c3de0ace825cb5c3fb` → `9c24151916beca622e588bfb3167c98711ff744f` | Candidate 有 Claude trailer，但其父版本已在 `challenge_api`、captcha、phone/SMS paths 用服务端 `api_path` 拼接 `https://i.instagram.com...`。候选只改写/整理 captcha flow，并保留同一危险 URL 语义；fix 同时验证四条旧路径。没有新 path 或安全边界降级，故不能把旧 SSRF origin 归给 AI refactor。 |
| CVE-2026-33243 / barebox | **FAIL** | reject `3d6d2414...`, `ef2e9ab5...` → `aca01795056d51060cb096f9a1ea309361743e05` | 两个 Claude-coauthored candidates 分别修 `fdt_ensure_space` double-free 和 `fdt_machine_is_compatible` heap OOB；advisory/fix 是 FIT `hashed-nodes` signature verification bypass。机制、函数和 reversal 均不相交。 |
| CVE-2026-32885 / ddev | **FAIL** | reject `0c26d82f8020a1d680f90b5a7c00fe708aade91b` → `05cbe299770a590b89bfc8dddab33e61b4302e43` | Candidate 仅修改测试 cleanup panic。未校验 archive extraction 自 2017 年 `1f8f947c...` 已存在；候选不改 `Untar`/`Unzip` production path。 |
| CVE-2026-58168 / HKUDS/DeepTutor | **FAIL** | reject packet candidates, including Cursor `2c4769a96f926ff0642c4e34a461071412c7c903`; carrier fix `90046374b3dcd4f8a866d2d64a64440bc08eb2ef` | Cursor candidate 只首次建立 v1 grant，尚无 `mcp_tools` 或 `allowed_mcp_tools`。无 AI marker 的人类提交 `46093e5e2b5bdc907977a096d71274d18b8bc644` 才同时新增 v2 `mcp_tools: None`、`allowed_mcp_tools()` 以及注释明确的 “None = unrestricted” 语义。AI 旧框架不是该默认值的必要 delta；不能把后续人类 origin 反投影给 Cursor。`90046374` 还是 merge carrier。 |
| CVE-2026-42864 / ManoManoTech/firefighter-incident | **FAIL** | reject `84ccb563...`, `16e527a6...` → `2586679e...` | candidates 是 RaidArea→IncidentCategory migration 与 P5 priority mapping；advisory 是 `CreateJiraBotView` 的 `AllowAny` + `httpx.get` SSRF。该 view 可追到 2023 年人类提交 `f1514b693458754b41e26e3b8f9133d0deb6da47`，候选没有引入或重实现 endpoint/sink。 |
| CVE-2026-34745 / ShaneIsrael/fireshare | **FAIL** | reject Copilot fix `157386c85f6683f89192dae52115069b435b6d34` and unrelated candidates → `b76915607924756e6fa1a5f6c8823c38d611fb24` | 未认证 `/api/uploadChunked/public` 与危险 `checkSum` path 在人类提交 `34bcc73384ad4ca489a9e2b88f9b97ba1acb03c2` 已直接创建。Copilot `157386c8` 是对 authenticated endpoint 的安全修复，遗漏 public sibling；这是 incomplete remediation，不是 public endpoint 的 origin。 |
| CVE-2025-67743 / LearningCircuit/local-deep-research | **FAIL** | reject five routed candidates → `b79089ff30c5d9ae77e6b903c408e1c26ad5c055` | `DownloadService` 中 raw `requests.get` 由人类提交 `3e8cef7cf1ba12876c694c2feb48429284546c8d` 创建。路由候选涉及 search/reasoning/notifications/metrics，未修改该 SSRF sink；omnibus security fix 不能制造跨文件 origin。 |
| CVE-2026-16488 / QUSETIONS/MiniCode-Python | **FAIL** | reject `dd6e934a...`, `f8cd3c21...`, `13603ef1...`, `3b2f45e8...` → `9d868dc2550f426c6ddf8ee98f30ffe450ca5e32` | 自动加载 project `.mcp.json` 的 `read_mcp_config_file(project_mcp_path(cwd))` 来自无 AI marker 的 root commit `4e5253badc964a1ba41f26394969e65b39162e28`。四个 AI candidates 是 Windows/TS parity 或 lint/cleanup，未引入/重实现该 trust decision。修复本身有 Claude trailer，但 remediation 不能作为漏洞 origin。 |

## 最小复现命令

```zsh
CV=/home/hanqing/.cache/cve-analyzer/cvelistV5/cves
CON=/home/hanqing/.cache/cve-analyzer/repos/conductor-oss_conductor
DT=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_deeptutor_2e314d4e2fbe00222fc624ecbc35cfc5617014df4d115b46bdaca90c3a846e94
MINI=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_minicode-python_50985d6f33d7d92214c83d53048f35852704e1ab808637fa5f747d9c0956bf90

jq -r '.containers.cna | .title,.descriptions[0].value,([.references[].url]|join(" "))' "$CV/2026/58xxx/CVE-2026-58138.json"
git -C "$CON" diff 840ec19c^ 840ec19c -- core/src/main/java/com/netflix/conductor/core/events/ScriptEvaluator.java
git -C "$CON" show --format= 87a7d96a c691e35e -- core/src/main/java/com/netflix/conductor/core/events/ScriptEvaluator.java
git -C "$CON" merge-base --is-ancestor 840ec19c 87a7d96a
git -C "$CON" merge-base --is-ancestor 87a7d96a c691e35e

git -C "$DT" show --format=fuller 2c4769a -- deeptutor/multi_user/grants.py
git -C "$DT" diff 46093e5e^ 46093e5e -- deeptutor/multi_user/grants.py deeptutor/multi_user/tool_access.py
git -C "$MINI" log --all --reverse --format='%H %aI %s%n%b' -S 'read_mcp_config_file(project_mcp_path' -- minicode/config.py
```

## 模型使用边界

DeepSeek V12 仅负责对 27 条候选 edge 排序：3 AI_CAUSAL、6 INCONCLUSIVE、18 NOT_CAUSAL。人工审计否决了其中 aiograpi 与 DeepTutor 的正向/疑似正向路由，最终只保留 Conductor。模型输出和 OSV 均未进入 accepted edge 的 claim-grade 证据。
