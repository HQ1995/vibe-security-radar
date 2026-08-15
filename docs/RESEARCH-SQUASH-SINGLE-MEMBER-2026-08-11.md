# Squash 单成员最小提交复核（2026-08-11）

## 结论

从 20,889 条 assistant-squash/public-exact 候选 edge 出发，3,198 个 squash root 全部恢复到 PR member；其中 3,196 个 member 有提交级直接 AI 信号。same-file gate 得到 290 个 alias class，生产代码 packet 125 个。DeepSeek 仅用于排序，人工复核其正票及相邻反例后确认 **PASS 4、FAIL 6、NEEDS_REVIEW 0**。

四个新 class 都落到最小 PR member，而不是只记 squash carrier。相对已独立确认的 94 个 class，严格唯一总数增至 **98**。

| class / repo | 最小 AI member → carrier → fix | 结论 |
|---|---|---|
| CVE-2026-10108 / hanxi/xiaomusic | `ac32a09a...` → `fa0511f4...` → `88404da7...` | **PASS**。member 新增 `/music/temp/` 路径，并以 `startswith(temp_base)` 做无分隔符 containment；fix 精确改成 `temp_base + os.sep`。旧 `music_path` 已有同 bug，因此只声称 new-path contributor。 |
| CVE-2026-45796 / coder/coder | `f2b9ec2b...` → `9400eaa9...` → `57b11d40...` | **PASS**。AI-attributed revert 删除 Azure certificate host allowlist、private-IP client、size cap 和通用错误，恢复默认 client/unbounded read/error disclosure；fix 恢复同一组控制。 |
| CVE-2026-50569 / fission/fission | `c6cd334f...` → `6104e1fd...` → `0deed6bf...` | **PASS**。member 在声称 CEL 已覆盖字段规则时移除 HTTPTrigger webhook；一方 advisory 明确指出迁移后 `RelativeURL`/`Prefix` 校验丢失；fix 同时补 CEL 与 Go validation。模型原推的 `3b503480...` 被拒绝。 |
| CVE-2026-50570 / fission/fission | `2db76f65...` → `e484df84...` → `2569b42b...` | **PASS**。多成员 PR 的首 member 创建 advisory 指名的六项 capability denylist 并漏掉 `SYS_TIME`；后续 members 不改该集合，fix 改为 allowlist。父版本更宽松，因此只声称 advisory-specific incomplete-hardening contributor。 |

## 六个反例

| class | 状态 | 反证 |
|---|---|---|
| CVE-2026-28454、CVE-2026-25474 / OpenClaw | **FAIL** | candidate/fix 是 Feishu webhook body；advisory 是 Telegram authentication，omnibus fix 造成 component 误配。 |
| CVE-2026-47394 / PraisonAI | **FAIL** | candidate 是 Python exec sandbox；advisory 是 MCP file read，机制不同。 |
| GHSA-P7W7-4929-VPJ5 / dynatrace-mcp | **FAIL** | parent 已有 unauthenticated HTTP MCP handler 并能执行首请求；candidate 只支持并发 per-request server。 |
| GHSA-P5RM-JG5C-8C77 / Kiota | **FAIL** | candidate 本身是 advisory 的第一轮 percent-decode remediation；follow-up 补深层 encoding/NUL/Unicode，不能把不完整 AI 修复反记为 origin。 |
| CVE-2026-10814 / Milvus | **FAIL** | candidates 改 KV path/snapshot；截断 MD5 来自 2022 年人类 `69c0b2fb49e...`。 |

## 原子性证据

- xiaomusic 与 Coder 的 member patch-id 分别与 squash carrier 完全相同：`9dfc43d5...`、`18ce1450...`。
- Fission CVE-2026-50569 的 member/carrier patch-id 为 `08babcbe...`。
- Fission CVE-2026-50570 的 PR aggregate 与 squash carrier patch-id 都是 `22d386fe...`；accepted edge 指向实际创建 denylist 的首 member，而不是整个 carrier。
- 所有 accepted member 都有提交正文中的 Claude co-author trailer；carrier 只作落地主链证明。

## 产物与模型边界

- relation closure：`autoresearch/orchestrator-260811-atomic150/squash-assistant-single-relation-v2/`。
- member screen：`squash-assistant-all-member-same-file-v2/`。
- packets/model routing：`squash-assistant-all-member-packets-v2/`、`squash-assistant-all-member-deepseek-v2/`。
- 机器裁决：`squash-assistant-strict-v1/adjudications.json`。

模型完成 120/125 个首轮 packet，重试再完成 3 个；模型正票只用于选择人工复核顺序。PASS 必须同时具备提交级 AI 信号、member→carrier 关系、advisory-specific parent→delta 和真实 fix reversal。OSV introduced 范围没有进入结论。
