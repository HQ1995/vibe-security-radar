# 新候选 V14 一手证据复核（2026-08-11）

## 结论

排名 74–97 的 24 个仓库经 first-party same-file gate 后得到 8 个 advisory 类、29 条原始 edge；feature-first packet 上限保留 15 条。人工裁决为 **PASS 1、FAIL 7、NEEDS_REVIEW 0、BLOCKED 0**。

| 状态 | class |
|---|---|
| PASS | CVE-2026-7386（mail-mcp-bridge） |
| FAIL | CVE-2026-15525、CVE-2026-2532、CVE-2026-25766、CVE-2025-68475、CVE-2026-57942、CVE-2026-47144、CVE-2026-14160 |

唯一接受的原子 edge 是：

```text
26be5ccbf17501852e98f7699d77ec4f63128ece
  -> 638b162b26532e32fa8d8047f638537dbdfe197a
origin_kind=direct_commit
AI signal=Claude Code generation marker + Claude Sonnet 4.5 co-author trailer
```

该 component 已在合并账本 row 103 以相同 edge PASS，因此 V14 对严格唯一总数的净增量是 **0**，不能重复计数。

## 来源与门禁

- 24 个仓库全部先做同文件候选筛选；只有 8 个类进入人工复核。
- packet 的 7 个类全部命中本地 CVEList/GitHub Advisory Database 一方记录，未使用 OSV。
- Escargot 的 fix parent 是 promisor remote 不再提供的对象，blame 阶段 fail-closed；但 candidate 只改 `test/vendortest` gitlink，而 advisory fix 修改生产 C++，足以用独立非因果反证收口为 FAIL。
- `exact_blame_hit` 仍只作 routing：AdLoop 的四条 exact hits 命中 omnibus fix 的其他行；真正 SSRF origin 不在候选集合。
- AI 安全修复不算 origin：Fedify candidate 本身就是 ReDoS 修复。

## 逐类裁决

| class / repo | 状态 | accepted/rejected edge | 一手闭环或反证 |
|---|---|---|---|
| CVE-2026-7386 / fatbobman/mail-mcp-bridge | **PASS** | accept `26be5ccbf17501852e98f7699d77ec4f63128ece` → `638b162b26532e32fa8d8047f638537dbdfe197a` | Claude candidate 原子新增 attachment extraction/cleanup MCP tools；`message_id.strip('<>')` 后直接 `base_path / clean_message_id`，既可让 extraction 越界写文件，也可让 cleanup 的 `shutil.rmtree()` 越界删目录。fix 新增 `attachment_paths.py`，把 Message-ID URL-safe base64 编成单一目录段并做 resolve/relative containment，两个危险调用点同时反转。父版本没有附件模块，AI marker 与 causal delta 直接绑定。该 edge 与合并账本 row 103 完全相同，不重复计数。 |
| CVE-2026-15525 / kLOsk/adloop | **FAIL** | reject packet 的五条 Claude candidates → `217399723e3a2fb39389e5355d49ed80aaf9ea7c` | candidates 分别新增 ad-group、negative-keyword-list、SharedSet read、Keyword Planner、asset removal tools；都未创建或修改 `write.py::_validate_urls()` 的本地 fetch。真正的 `urllib.request.urlopen()` SSRF 函数和 final URL 调用由无 AI marker 的人类提交 `10e40a29a7bee6ee5f94efd514edf8ea6a4fe965` 原子创建。四条 `exact_blame_hit=true` 只是 omnibus fix 同时重构 `server.py` 的噪声。 |
| CVE-2026-2532 / lintsinghua/DeepAudit | **FAIL** | reject Jules `1c0ec2b13dc19b28bc5aaa40d73a2ea0c62032cd` → `da853fdd8cbe9d42053b45d83f25708ba29b8b27` | candidate 在 `embedding_config.py` 改配置持久化、API key 返回和自定义模型；其父版本已经有 `test_embedding` 并把 `request.base_url` 送入 `EmbeddingService`。fix 只调整该旧 endpoint 的固定响应时长/latency 计算。candidate 未新增 route、base URL sink 或时序边界。 |
| CVE-2026-25766 / labstack/echo | **FAIL** | reject `b4ea9248360d741dfcb83ac9692d8b1b2626df04` → `b1d443086ea27cf51345ec72a71e9b7e9d9ce5f1` | Claude candidate 只修 `context.go` 注释 typo，没有运行时 delta。advisory/fix 是 Windows backslash static-file traversal，位于不同生产路径。 |
| CVE-2025-68475 / fedify-dev/fedify | **FAIL** | reject `2bdcb24d7d6d5886e0214ed504b63a6dc5488779` → release/fix `bf2f0783634efed2663d1b187dc55461ee1f987a` | candidate 主题即 “Fix ReDoS vulnerability”，把灾难性回溯 regex 改为分阶段 HTML parsing 并限制 body；它消除而非引入 advisory 机制。后续 fix/reference 保留同一修复，不能把 AI remediation 当 origin。 |
| CVE-2026-57942 / LibreTranslate/LibreTranslate | **FAIL** | reject Copilot `83cc8dd7b88c4a4c5e0a7ffe35b27c6b85aa48fa`, `05e09f577be2ac2815efb9128b95736afa3236db` → `397fd224080515d4001a1bc60c8fed53e3c56b6f` | 两条 candidates 只实现葡萄牙语/中文 auto-detect fallback。fix 通过显式 `trust_forwarded_for` 控制 X-Forwarded-For 是否进入 client IP/rate-limit；候选未触碰 `get_remote_address()`、proxy trust 或限流。 |
| CVE-2026-47144 / BKDDFS/shamefile | **FAIL** | reject Claude `a3728b12a0663434df20cd4259821260530a51f5` → `77b0aeea318503582818c708518c601fedc43557` | candidate 仅把 registry 定位到 git root/CWD 并支持 single-file scan；其父版本尚无 `shame next`。真正从不可信 registry entry.location 拼路径并 `read_to_string()` 的 `print_entry_snippet()` 由五天后的无 AI marker 人类提交 `481fd296529dff47e83dfe1ef62e91c6a6aaaef2` 创建。fix 改为渲染 registry 内缓存 content，反转的是后续人类 origin。 |
| CVE-2026-14160 / samsung/escargot | **FAIL** | reject `2dee22f5c7b8bf31cb7252d7731fae8c07f2842c` → `9e8084ecc2f68e8584d389414c3f37fda12dab7d` | Claude candidate 唯一 changed file 是 `test/vendortest` gitlink；fix 的安全逻辑在 `src/builtins/BuiltinAtomics.cpp` 与 `src/runtime/ArrayBufferObject.cpp`。候选没有生产代码 delta，不能引入 advisory 的 ArrayBuffer/Atomics 缺陷。缺失 fix parent 只阻塞逐行 blame，不影响这一独立反证。 |

## 最小复现命令

```zsh
ROOT=/home/hanqing/agents/ai-slop
REPOS="$ROOT/research/orchestrator-260811-atomic150/global-batch-v14-repositories.json"

repo=$(jq -r '.[] | select(.slug=="mail-mcp-bridge") | .repository_path' "$REPOS")
git -C "$repo" diff 26be5ccb^ 26be5ccb -- extract_attachments.py cleanup_attachments.py mail_mcp_server.py
git -C "$repo" show --format= 638b162b -- src/attachment_paths.py src/extract_attachments.py src/cleanup_attachments.py

repo=$(jq -r '.[] | select(.slug=="adloop") | .repository_path' "$REPOS")
git -c gc.auto=0 -C "$repo" log --all --reverse -S 'def _validate_urls' -- src/adloop/ads/write.py
git -C "$repo" blame 21739972^ -L 69,112 -- src/adloop/ads/write.py

repo=$(jq -r '.[] | select(.slug=="shamefile") | .repository_path' "$REPOS")
git -c gc.auto=0 -C "$repo" log --all --reverse -S 'fn print_entry_snippet' -- src/main.rs
git -C "$repo" show --format= 481fd296 -- src/main.rs
```

## 模型使用边界

DeepSeek 对成功解析的 14 条 edge 给出 1 `AI_CAUSAL`、13 `NOT_AI_CAUSAL`；Shamefile packet 因响应解析失败被模型阶段标为 blocked。人工审计独立确认 Mail MCP edge，并用历史顺序确认 Shamefile 的真实危险实现晚于 candidate 且无 AI marker。模型只用于排序，没有进入 claim-grade 证据。
