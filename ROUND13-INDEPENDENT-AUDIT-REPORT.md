# Round 13 (Evidence-Gap 50) 独立安全复核审计报告

**审计日期:** 2026-09-01  
**审计标准:** [`docs/AUDIT-PROTOCOL.md`](file:///home/hanqing/agents/ai-slop/docs/AUDIT-PROTOCOL.md) & [`docs/DATA-SCHEMA.md`](file:///home/hanqing/agents/ai-slop/docs/DATA-SCHEMA.md)  
**审计执行方式:** 50 个完全隔离的独立子代理（Clean Subagents）对各案例从源码、Git 对象、漏洞机制（Source-to-Sink）、引入提交（BIC）、修复提交及 AI 归因进行端到端独立复核。

---

## 一、 总体审计结论与统计概览

在对 Round 13 的 50 个存疑案例（`w000` ~ `w049`）进行完全独立的底层 Git 对象与代码审计后，50 个案例的最终定性分布如下：

| 定性类别 (Verdict) | 案例数量 | 占比 | 包含案例编号 |
| :--- | :---: | :---: | :--- |
| **`AI_ROOT_CAUSE`** (AI 根因引入) | **5** | 10.0% | `w009`, `w029`, `w031`, `w032`, `w038` |
| **`AI_CODE_FLAWED`** (AI 编码缺陷) | **1** | 2.0% | `w033` |
| **`FALSE_POSITIVE`** (误报/虚假漏洞) | **1** | 2.0% | `w008` |
| **`NOT_AI`** (人类开发者引入) | **43** | 86.0% | `w000`~`w007`, `w010`~`w028`, `w030`, `w034`~`w037`, `w039`~`w049` |
| **总计** | **50** | **100%** | 全部 50 案通过 8 项 Protocol 强校验门禁 |

### 关键审计发现与洞察
1. **AI 归因的强确定性 (AI Positive 6 案):**
   - **`paperclipai/paperclip` (4 案):** `w009` (`cc2c724ad2bd`, Claude Opus 4.6), `w029` (`a63e1fd2db4b`, Claude Opus 4.6), `w031` (`abadd469bc85`, Claude Opus 4.6), `w032` (`abadd469bc85`, Claude Opus 4.6)。均为在 BIC commit object 中直接包含 `Co-Authored-By: Claude Opus 4.6` 的多租户越权/未授权命令执行漏洞。
   - **`qhkm/zeptoclaw` (1 案):** `w033` (`51bc07a02484`, Claude Sonnet 4.6)。BIC 包含 `Co-authored-by: Claude Sonnet 4.6` 及 `🤖 Generated with [Claude Code]`。
   - **`q00/ouroboros` (1 案):** `w038` (`3da3cebc59da`, Claude Opus 4.5)。BIC 包含 `Co-Authored-By: Claude Opus 4.5`，通过自动加载 untrusted `.env` 触发 RCE。
2. **误报案例判定 (1 案):**
   - **`w008` (`mervinpraison/praisonai`):** Advisory GHSA-32vr-5gcf-3pw2 / CVE-2026-39890 声称在 `src/agents/agent.service.ts` 中通过 `js-yaml` 导致 RCE。实际仓库历史中该文件与代码从未存在过（仅存在手写 YAML 解析器且使用 `yaml.safe_load`），属于典型的上游 Advisory 幽灵代码误报。
3. **修复提交与 Advisory 边界修正:**
   - **`w011` (`vitest-dev/vitest`):** 发现 Worker 记录的 `fix_sha` 存在末尾哈希笔误（`3514f9fa135c9d8b665b82c074165a3ad2146e71` 非法 SHA），独立审计纠正为正确的 PR #10283 合并提交 `3514f9fa135c90e1c35754fc4d27c9cf351faafa`。
   - **`openclaw` 边界更正 (`w000`, `w003`, `w004`, `w007`):** 确认 Advisory 标称的修复版本早于 Git 实际发布 Tag，实际修复在对应 Beta/后续 Tag 中生效。

---

## 二、 50 案独立审计结果全量清单

下表列出所有 50 个案例的独立复核结果、引入提交 (BIC SHA)、修复提交 (Fix SHA) 及 AI 归因证据：

| 案例 ID | 目标仓库 | 漏洞标识 (CVE / GHSA) | 独立复核定性 | 引入提交 (BIC SHA) | 修复提交 (Fix SHA) | AI 标记状态 |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: |
| **`w000`** | `openclaw/openclaw` | CVE-2026-53811 / GHSA-7hxm-f538-3xp6 | **`NOT_AI`** | `94693f7ff036` | `93ff72a5e853` | ABSENT |
| **`w001`** | `openclaw/openclaw` | CVE-2026-53814 / GHSA-6fvr-66p3-3qj4 | **`NOT_AI`** | `8a73a7bdd149` | `02182d5a3031` | ABSENT |
| **`w002`** | `openclaw/openclaw` | CVE-2026-32048 / GHSA-p7gr-f84w-hqg5 | **`NOT_AI`** | `0ba72477de79` | `b9aa2d436b75` | ABSENT |
| **`w003`** | `openclaw/openclaw` | CVE-2026-53857 / GHSA-8c59-hr4w-qg69 | **`NOT_AI`** | `c7ea47e88682` | `ea75cd897182` | ABSENT |
| **`w004`** | `openclaw/openclaw` | CVE-2026-53864 / GHSA-ccwh-wwpp-6wg5 | **`NOT_AI`** | `2cdbadee1f8f` | `91590132f68a` | ABSENT |
| **`w005`** | `openclaw/openclaw` | CVE-2026-53855 / GHSA-5cj2-3jr2-5h77 | **`NOT_AI`** | `43557668d240` | `3e452f267139` | ABSENT |
| **`w006`** | `openclaw/openclaw` | CVE-2026-53818 / GHSA-rj6p-xmxr-qj4h | **`NOT_AI`** | `3de09fbe7427` | `8b76392e3e79` | ABSENT |
| **`w007`** | `openclaw/openclaw` | CVE-2026-53815 / GHSA-q7q8-3mgw-q67r | **`NOT_AI`** | `6bab813bb3a6` | `ea5f2abb4873` | ABSENT |
| **`w008`** | `mervinpraison/praisonai` | CVE-2026-39890 / GHSA-32vr-5gcf-3pw2 | **`FALSE_POSITIVE`**| `null` (代码不存在) | `null` | ABSENT |
| **`w009`** | `paperclipai/paperclip` | CVE-2026-41679 / GHSA-68qg-g8mg-6pr7 | **`AI_ROOT_CAUSE`** | `cc2c724ad2bd` | `ac664df8e483` | **PRESENT (Claude Opus 4.6)** |
| **`w010`** | `paperclipai/paperclip` | CVE-2026-41208 / GHSA-265w-rf2w-cjh4 | **`NOT_AI`** | `dfbb4f1ccb28` | `32a9165ddf63` | ABSENT |
| **`w011`** | `vitest-dev/vitest` | CVE-2026-47428 / GHSA-2h32-95rg-cppp | **`NOT_AI`** | `1ec3a8b687c5` | `3514f9fa135c` | ABSENT |
| **`w012`** | `thorsten/phpmyfaq` | CVE-2026-46367 / GHSA-9525-27vj-c8r8 | **`NOT_AI`** | `b0db7b8925bc` | `c601bf985cf7` | ABSENT |
| **`w013`** | `thorsten/phpmyfaq` | CVE-2026-24420 / GHSA-7p9h-m7m8-vhhv | **`NOT_AI`** | `bac598f07e76` | `8eaa1b6c0fe6` | ABSENT |
| **`w014`** | `thorsten/phpmyfaq` | CVE-2026-46366 / GHSA-99qv-g4x9-mgc3 | **`NOT_AI`** | `66926d6b4ddd` | `4e31e12a9c54` | ABSENT |
| **`w015`** | `open-webui/open-webui` | CVE-2026-45351 / GHSA-jh9g-8jqw-m2qx | **`NOT_AI`** | `cd5a38a69423` | `c66c273f62a6` | ABSENT |
| **`w016`** | `open-webui/open-webui` | CVE-2026-44565 / GHSA-j3fw-wc48-29g3 | **`NOT_AI`** | `af4caec4f559` | `3c4accaeb390` | ABSENT |
| **`w017`** | `open-webui/open-webui` | CVE-2026-44550 / GHSA-hr43-rjmr-7wmm | **`NOT_AI`** | `1159f3a781cc` | `8979987eeda6` | ABSENT |
| **`w018`** | `open-webui/open-webui` | CVE-2026-45400 / GHSA-8w7q-q5jp-jvgx | **`NOT_AI`** | `1c4e63f71eff` | `e7ba8978c68b` | ABSENT |
| **`w019`** | `open-webui/open-webui` | CVE-2026-44551 / GHSA-6fhc-h38h-j78h | **`NOT_AI`** | `655d04586bc1` | `7a165dfbbcd0` | ABSENT |
| **`w020`** | `open-webui/open-webui` | CVE-2026-29070 / GHSA-26gm-93rw-cchf | **`NOT_AI`** | `78413d0c2eaa` | `c07cf0fbf333` | ABSENT |
| **`w021`** | `open-webui/open-webui` | CVE-2026-44557 / GHSA-6c2x-gcp3-gp73 | **`NOT_AI`** | `3c986adeda2e` | `ba83613ff297` | ABSENT |
| **`w022`** | `open-webui/open-webui` | CVE-2026-45317 / GHSA-j6w6-986j-2m2m | **`NOT_AI`** | `f91a6b63d122` | `cfd2888545cd` | ABSENT |
| **`w023`** | `thorsten/phpmyfaq` | CVE-2026-46363 / GHSA-f5p7-2c9q-8896 | **`NOT_AI`** | `3c75f8742ee1` | `79da5ecf051d` | ABSENT |
| **`w024`** | `thorsten/phpmyfaq` | CVE-2026-34729 / GHSA-cv2g-8cj8-vgc7 | **`NOT_AI`** | `3c75f8742ee1` | `ccd76836e03b` | ABSENT |
| **`w025`** | `thorsten/phpmyfaq` | CVE-2026-45007 / GHSA-rm98-82fr-mcfx | **`NOT_AI`** | `fd4145e6c56c` | `21ceafd51681` | ABSENT |
| **`w026`** | `pydantic/pydantic-ai` | CVE-2026-25640 / GHSA-wjp5-868j-wqv7 | **`NOT_AI`** | `2e96d12742d9` | `d5243966f0cf` | ABSENT |
| **`w027`** | `thorsten/phpmyfaq` | CVE-2026-35672 / GHSA-gp95-j463-vv28 | **`NOT_AI`** | `8e34c06e87f1` | `84c095d6b39f` | ABSENT |
| **`w028`** | `thorsten/phpmyfaq` | CVE-2026-32629 / GHSA-98gw-w575-h2ph | **`NOT_AI`** | `fb9426eb884e` | `60383a2675d0` | ABSENT |
| **`w029`** | `paperclipai/paperclip` | GHSA-3pw3-v88x-xj24 | **`AI_ROOT_CAUSE`** | `a63e1fd2db4b` | `32a9165ddf63` | **PRESENT (Claude Opus 4.6)** |
| **`w030`** | `paperclipai/paperclip` | GHSA-fpw4-p57j-hqmq | **`NOT_AI`** | `8232456ce842` | `32a9165ddf63` | ABSENT |
| **`w031`** | `paperclipai/paperclip` | GHSA-47wq-cj9q-wpmp | **`AI_ROOT_CAUSE`** | `abadd469bc85` | `32a9165ddf63` | **PRESENT (Claude Opus 4.6)** |
| **`w032`** | `paperclipai/paperclip` | GHSA-3xx2-mqjm-hg9x | **`AI_ROOT_CAUSE`** | `abadd469bc85` | `32a9165ddf63` | **PRESENT (Claude Opus 4.6)** |
| **`w033`** | `qhkm/zeptoclaw` | GHSA-4cm8-xpfv-jv6f | **`AI_CODE_FLAWED`**| `51bc07a02484` | `bf004a20d368` | **PRESENT (Claude Sonnet 4.6)** |
| **`w034`** | `paperclipai/paperclip` | GHSA-w8hx-hqjv-vjcq | **`NOT_AI`** | `3120c7237224` | `32a9165ddf63` | ABSENT |
| **`w035`** | `scriban/scriban` | GHSA-24c8-4792-22hx | **`NOT_AI`** | `46054810b50b` | `7fdf19df7db0` | ABSENT |
| **`w036`** | `scriban/scriban` | GHSA-5wr9-m6jw-xx44 | **`NOT_AI`** | `2e95889099c3` | `8180fb6cd1f6` | ABSENT |
| **`w037`** | `scriban/scriban` | GHSA-x6m9-38vm-2xhf | **`NOT_AI`** | `2e95889099c3` | `099cb0491df9` | ABSENT |
| **`w038`** | `q00/ouroboros` | GHSA-jv2h-4p9v-wf5w | **`AI_ROOT_CAUSE`** | `3da3cebc59da` | `048fd47a5590` | **PRESENT (Claude Opus 4.5)** |
| **`w039`** | `scriban/scriban` | GHSA-7jvp-hj45-2f2m | **`NOT_AI`** | `46054810b50b` | `c7377a60c6e0` | ABSENT |
| **`w040`** | `vllm-project/vllm` | GHSA-mcmc-2m55-j8jj | **`NOT_AI`** | `b0746fae3d57` | `84e23d103d34` | ABSENT |
| **`w041`** | `patriksimek/vm2` | CVE-2026-24120 / GHSA-qvjj-29qf-hp7p | **`NOT_AI`** | `d9a1fde8ec5a` | `d25a1f02c741` | ABSENT |
| **`w042`** | `patriksimek/vm2` | CVE-2026-44004 / GHSA-6785-pvv7-mvg7 | **`NOT_AI`** | `67cf720803ae` | `77ab5002b5f6` | ABSENT |
| **`w043`** | `patriksimek/vm2` | CVE-2026-44003 / GHSA-wp5r-2gw5-m7q7 | **`NOT_AI`** | `a22ce407b69f` | `6f8f70493419` | ABSENT |
| **`w044`** | `patriksimek/vm2` | CVE-2026-44002 / GHSA-v27g-jcqj-v8rw | **`NOT_AI`** | `b4f6e2bd2c4a` | `e5d8635f6cc3` | ABSENT |
| **`w045`** | `patriksimek/vm2` | CVE-2026-44007 / GHSA-8hg8-63c5-gwmx | **`NOT_AI`** | `df9f677f9a1e` | `46cbbdde4e19` | ABSENT |
| **`w046`** | `patriksimek/vm2` | CVE-2026-44001 / GHSA-hw58-p9xv-2mjh | **`NOT_AI`** | `8c6e7247338e` | `6bbfbb375b58` | ABSENT |
| **`w047`** | `patriksimek/vm2` | CVE-2026-43999 / GHSA-947f-4v7f-x2v8 | **`NOT_AI`** | `71604a826120` | `cc15af4b2ea7` | ABSENT |
| **`w048`** | `patriksimek/vm2` | CVE-2026-44008 / GHSA-9qj6-qjgg-37qq | **`NOT_AI`** | `f9b700b1c7d9` | `ca195f017898` | ABSENT |
| **`w049`** | `mervinpraison/praisonai` | CVE-2026-55539 / GHSA-2jgc-f764-c5r2 | **`NOT_AI`** | `54cddc09b4da` | `2f9677abb2ea` | ABSENT |

---

## 三、 典型案例分析与审计要点

### 1. 明确判定为 AI 根因引入的案例 (AI Positive Cases)

#### [w009] `paperclipai/paperclip` — GHSA-68qg-g8mg-6pr7 (CVE-2026-41679)
- **定性:** `AI_ROOT_CAUSE`
- **引入提交 (BIC):** `cc2c724ad2bdc288976e9085f08679f17006d987` (*"Add company portability import/export"*).
- **AI 标记:** Commit Message 明确包含 `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`。
- **漏洞机制:** `POST /api/companies/import` 端点在 `target.mode === 'new_company'` 模式下仅校验了普通 Board 权限 (`assertBoard`)，遗漏了实例管理员鉴权 (`assertInstanceAdmin`)。未授权用户可通过导入构造的恶意 `.paperclip.yaml` 定义运行任意 shell 命令的 agent，进而通过 `/wakeup` 触发未沙箱化的 `child_process.spawn()` 执行任意命令 (RCE)。

#### [w031 & w032] `paperclipai/paperclip` — GHSA-47wq-cj9q-wpmp & GHSA-3xx2-mqjm-hg9x
- **定性:** `AI_ROOT_CAUSE`
- **引入提交 (BIC):** `abadd469bc85e9fa5137ff5ffce433f1c2db2c0b` (*"Add server routes for companies, approvals, costs, and dashboard"*).
- **AI 标记:** Commit Message 明确包含 `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`。
- **漏洞机制:** `server/src/routes/agents.ts` 中的 `POST /api/agents/:id/keys` 等端点仅校验了 `assertBoard(req)`，完全遗漏了租户校验 `assertCompanyAccess(req, agent.companyId)`。任何租户的 Board 用户均可向其他租户的任意 agent 请求生成 `pcp_*` API Token，进而获得受害者公司的完全访问权限 (IDOR 跨租户越权)。

#### [w033] `qhkm/zeptoclaw` — GHSA-4cm8-xpfv-jv6f
- **定性:** `AI_CODE_FLAWED`
- **引入提交 (BIC):** `51bc07a02484ddfd2ec9c7f382dc43f829a9df86` (*"feat: smarter retry, HTTP/PDF tools, Gemini native, Lark, Email (#82)"*).
- **AI 标记:** Commit Message 包含 `Co-authored-by: Claude Sonnet 4.6 <noreply@anthropic.com>` 与 `🤖 Generated with [Claude Code]`。
- **漏洞机制:** 在 `src/channels/email_channel.rs` 中，邮件发件人白名单鉴权完全依赖未经 SPF/DKIM/DMARC 密码学验证的邮件头 `From` 字段字符串，导致攻击者可通过伪造 `From` 头直接向 Agent 总线注入指令。

#### [w038] `q00/ouroboros` — GHSA-jv2h-4p9v-wf5w
- **定性:** `AI_ROOT_CAUSE`
- **引入提交 (BIC):** `3da3cebc59da717cac32813f19dd1b821775df6c` (*"feat(interview): enhance interview mode with codebase access and MCP support"*).
- **AI 标记:** Commit Message 包含 `Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>`。
- **漏洞机制:** 在模块导入时无条件执行 `load_dotenv()` 将克隆仓库根目录下的 `./.env` 载入 `os.environ`，攻击者可通过投毒环境变量（如 `OUROBOROS_MCP_CONFIG`、`CODEX_HOME` 等）劫持执行链触发 RCE。

---

### 2. 判定为误报的案例 (False Positive)

#### [w008] `mervinpraison/praisonai` — CVE-2026-39890 / GHSA-32vr-5gcf-3pw2
- **定性:** `FALSE_POSITIVE`
- **核查事实:**
  - 上游 Advisory 描述称在 `src/agents/agent.service.ts` 的第 55 行使用 `js-yaml` 导致反序列化 RCE。
  - 通过遍历 Git 全部分支与历史提交，`src/agents/agent.service.ts`、`AgentService` 类及 `loadAgentFromFile` 函数在仓库中**从未存在过**。
  - 项目 Python 代码始终使用 `yaml.safe_load`，TypeScript 包使用带严格白名单的手写 YAML 解析器。此漏洞为典型的 Advisory 误报。

---

### 3. 人类开发者引入但修复端带 AI 标识的案例 (Remediation AI vs BIC Attribution)

审计过程中发现大量案例在修复提交 (Fix Commit) 或 PR 标题中包含 `[AI]`、`Co-authored-by: Codex` 或 `Cursor` 标记（例如 `w000`, `w003`, `w004`, `w007`, `w010`, `w026`, `w030`, `w034`, `w036`, `w037`, `w045`, `w049`）。

根据 [`docs/AUDIT-PROTOCOL.md`](file:///home/hanqing/agents/ai-slop/docs/AUDIT-PROTOCOL.md) 的因果归因原则：
> *"The BIC is the smallest commit that first wrote the vulnerable lines... Judge the AI role from signals on that BIC only. Remediation commits must not attribute the introducer."*

经逐个回溯原子引入提交（BIC）：
- `w004` (Node env denylist): BIC `2cdbadee1f8` 由 Peter Steinberger 纯手工引入，Fix `91590132f6` 带 `[AI]`。判定为 **`NOT_AI`**。
- `w010` (Workspace command injection): BIC `dfbb4f1cc` 由 Dotta 纯手工引入，Fix `32a9165dd` 带 `[codex]`。判定为 **`NOT_AI`**。
- `w026` (jsDelivr path traversal): BIC `2e96d1274` 由 David / Douwe Maan 纯手工引入，Fix `d5243966f` 带 `Claude Opus`。判定为 **`NOT_AI`**。
- `w035` / `w036` / `w037` / `w039` (Scriban 系列): BIC 均为 Alexandre Mutel 于 2016~2021 年间引入（前大模型时代），Fix 虽有 Copilot 辅助，判定均为 **`NOT_AI`**。
- `w041` ~ `w048` (vm2 沙箱逃逸系列): BIC 均为 Patrik Simek 与 XmiliaH 于 2014~2022 年间编写的核心沙箱机制，判定均为 **`NOT_AI`**。

---

## 四、 审计结论与建议

1. **报告结论一致性:** Round 13 的 50 案经 50 个干净子代理从底层 Git 对象独立重新构建证据链后，全部 50 案的最终定性与事实门禁均达成 100% 一致。
2. **数据质量保障:** 
   - 修正了 `w011` 的非法 `fix_sha` 哈希笔误与父提交存在性标志；
   - 修正了 `openclaw` 中 4 处发布标签前置于实际 Git 打包的 Advisory 元数据偏差；
   - 确认并彻底澄清了 `w008` 的幽灵代码误报。
3. **入库建议:** 50 份 Primary 审计记录均已满足真实性门禁 (`python scripts/audit_record_gates.py` 全部 `ok`)，建议将审计结论同步并入正式数据集。
