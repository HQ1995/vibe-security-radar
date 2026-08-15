# NEEDS_REVIEW 上游/分支原子来源恢复（2026-08-11）

## 结论

本轮只处理合并账本中两个因 import/来源边界而降级的 OpenClaw 类。两项均完成 first-party advisory、candidate parent→delta、明确 AI 绑定、载体/分支关系和 fix reversal 闭环：**row 78 PASS、row 93 PASS、FAIL 0、NEEDS_REVIEW 0、BLOCKED 0**。

| row | component | accepted atomic edge | origin kind |
|---:|---|---|---|
| 78 | CVE-2026-22171 / GHSA-vj3g-5px3-gr46 | `a604df8c83d179a6e9fc07987ebef610faaf4991` → `c821099157a9767d4df208c6b12f214946507871`；carrier `2267d58afcc70fe19408b8f0dce108c340f3426d` | `upstream_atomic` |
| 93 | CVE-2026-32067 / GHSA-vjp8-wprm-2jw9 | `f05553413db29ebcf5d8c75c8a6154a9e9987690` → `a0c5e28f3bf0cc0cd9311f9e9ec2ca0352550dcf` | `direct_commit` |

合并账本的 first-party semantic 唯一下界由 **80 增至 82**。再加不在 156 行内、已独立闭合的 Conductor CVE-2026-58138，当前严格已知唯一总数由 **81 增至 83**。这不是把 import carrier 当原子来源，也没有依赖 OSV `introduced`。

## 裁决门禁

- GitHub Advisory Database packet 中的一方 advisory 对象只定义 component、机制与 fix；OSV 不参与定案。
- import、sync、rebase/cherry-pick 只承担 lineage；AI 归因必须绑定真实 atomic contributor 或与其明确关联的一方 PR metadata。
- candidate 的直接 parent 必须缺少本轮计入的机制；fix 必须反转 candidate 所建立的 advisory-specific 边界。
- “必要前置功能”本身不自动计 contributor。row 93 没有拿早期多账号提交 `5f6e1c19...` 充数，而是恢复了后来首次接入未分区 pairing store 的原子提交。

## row 78：Feishu media key 临时路径穿越

一方 GHSA 明确点名 `extensions/feishu/src/media.ts`：不可信 `imageKey` / `fileKey` 被直接插入 `os.tmpdir()` 下的临时路径，可通过 traversal 把 SDK 下载写到目录外；首个 fix 是 `c821099...`。

上游 `m1heng/clawdbot-feishu` 的原子提交 `a604df8...`：

- parent `c08f969be8a0bc227dee61574cdebd44d5b8fdf3` 中没有 inbound media download 实现；candidate 一次新增 `downloadImageFeishu()`、`downloadMessageResourceFeishu()` 及其调用链。
- candidate 新增两条危险模板：`feishu_img_${Date.now()}_${imageKey}` 与 `feishu_${Date.now()}_${fileKey}`，随后传给 SDK `writeFile()`。
- commit message 明确带 `Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>`。
- OpenClaw import `2267d58a...` 中两条危险语句与上游 candidate 的去缩进文本 SHA-256 都是 `0edaa14950ec75ef85ae190fcf6f48b1f398f55bb7a817e6d913ede468a1b001`；它是 transfer carrier，不承接 atomic origin。
- `2267d58a...` 是 `c821099...` 的祖先。fix 把两处 key 派生后缀精确替换成 `crypto.randomUUID()`，直接反转 traversal primitive。

因此接受：

```text
candidate_sha=a604df8c83d179a6e9fc07987ebef610faaf4991
fix_sha=c821099157a9767d4df208c6b12f214946507871
origin_kind=upstream_atomic
carrier_sha=2267d58afcc70fe19408b8f0dce108c340f3426d
ai_signal=Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
```

## row 93：多账号 pairing store 未分区

一方 GHSA 把问题定义为 multi-account channel 中 pairing-store access 缺少 account scope：一个账号批准的 sender 可在另一个账号被接受；fix 明列 `a0c5e28...`。

真实贡献链不是 import，也不是早期多账号同步本身：

- Claude 共著 `5f6e1c19...` 先建立多账号 Feishu runtime，但其 candidate/parent 都没有 `readAllowFromStore("feishu")` 或 `upsertPairingRequest()`；单拿它不能闭合本 advisory，故不作为 accepted origin。
- final-history 原子提交 `f0555341...` 的 parent 已有多账号 routing，但还没有 pairing-store read。candidate 首次在每账号的 `handleFeishuMessage()` 中调用全局 `readAllowFromStore("feishu")`，并把结果并入 command authorization；key 只有 channel，没有 `account.accountId`。这已经形成 GHSA 所述跨账号批准复用路径。
- GitHub commits→pulls 一方 API 把 `f0555341...` 关联到 PR #14876；PR body 明确写 `AI-assisted: yes`、`Model: GPT-5.3-Codex`。这项 metadata 绑定该 PR 的具体生产补丁，不从作者名或模型投票推断。
- 紧随其后的同 PR follow-up `daf13dbb...`（原 PR SHA `51ac4447...`，stable patch-id 相同）把同一个未分区 read 扩到 DM policy，并新增同样只按 `channel: "feishu"` 的全局 pairing write；它扩大影响，但不是本次 AI accepted edge 的必要替身。
- `f0555341...` 是 `a0c5e28...` 的祖先。fix 创建 `createScopedPairingAccess({ channel: "feishu", accountId: account.accountId })`，并把原 global read/write 都替换为 scoped helper，精确关闭跨账号 bleed。

因此接受：

```text
candidate_sha=f05553413db29ebcf5d8c75c8a6154a9e9987690
fix_sha=a0c5e28f3bf0cc0cd9311f9e9ec2ca0352550dcf
origin_kind=direct_commit
ai_signal=PR #14876: AI-assisted: yes; Model: GPT-5.3-Codex
```

不依赖上游 `b219b3fc...` 的 `Crane <crane-is-bot@...>` 身份，也不把模糊 bot 名当 AI 证明。

## 最小复现命令

```zsh
ROOT=/home/hanqing/agents/ai-slop
UP="$ROOT/.ai-slop/cache/cve-analyzer/repos/v2_github.com_clawdbot-feishu_f25c435dc88d86d445a87247b170272688547b364c53338716dbbc464a40122d"
OC="$ROOT/.ai-slop/cache/cve-analyzer/repos/v2_github.com_openclaw_c2e21135e2e4d103a91f04425616aa5d7d8c5dd28582aa10a12b6898fde51b0f"
PACKETS="$ROOT/autoresearch/orchestrator-260811-atomic150/openclaw-feature-review-packets-v1/packets.jsonl"

# 一方 advisory objects
jq -c 'select(any(.advisories[]?; ((.aliases // []) | index("CVE-2026-22171")))) | .advisories[] | select((.aliases // []) | index("CVE-2026-22171")) | {id,aliases,summary,details}' "$PACKETS"
jq -c 'select(any(.advisories[]?; ((.aliases // []) | index("CVE-2026-32067")))) | .advisories[] | select((.aliases // []) | index("CVE-2026-32067")) | {id,aliases,summary,details}' "$PACKETS"

# row 78：上游 creation、carrier 等价和 fix reversal
git -C "$UP" show --format=fuller a604df8c83d179a6e9fc07987ebef610faaf4991 -- src/media.ts
git -C "$UP" show a604df8c83d179a6e9fc07987ebef610faaf4991:src/media.ts | rg -n -C 3 'Date.now.*(imageKey|fileKey)'
git -C "$OC" show 2267d58afcc70fe19408b8f0dce108c340f3426d:extensions/feishu/src/media.ts | rg -n -C 3 'Date.now.*(imageKey|fileKey)'
git -C "$OC" merge-base --is-ancestor 2267d58afcc70fe19408b8f0dce108c340f3426d c821099157a9767d4df208c6b12f214946507871
git -C "$OC" diff c821099157a9767d4df208c6b12f214946507871^ c821099157a9767d4df208c6b12f214946507871 -- extensions/feishu/src/media.ts

# row 93：parent 缺失、candidate 引入、PR AI disclosure 与 fix reversal
git -C "$OC" show f05553413db29ebcf5d8c75c8a6154a9e9987690^:extensions/feishu/src/bot.ts | rg 'readAllowFromStore|upsertPairingRequest' || true
git -C "$OC" diff f05553413db29ebcf5d8c75c8a6154a9e9987690^ f05553413db29ebcf5d8c75c8a6154a9e9987690 -- extensions/feishu/src/bot.ts
git -C "$OC" merge-base --is-ancestor f05553413db29ebcf5d8c75c8a6154a9e9987690 a0c5e28f3bf0cc0cd9311f9e9ec2ca0352550dcf
git -C "$OC" diff a0c5e28f3bf0cc0cd9311f9e9ec2ca0352550dcf^ a0c5e28f3bf0cc0cd9311f9e9ec2ca0352550dcf -- extensions/feishu/src/bot.ts
gh api repos/openclaw/openclaw/commits/f05553413db29ebcf5d8c75c8a6154a9e9987690/pulls --jq '.[] | {number,title,body,html_url}'
```

## 证据边界

- GHSA 内容来自本轮已冻结 packet 内的一方 advisory object；git 机制来自本地 commit objects。
- PR #14876 的 AI disclosure 于 2026-08-11 通过 GitHub 一方 API 读取；PR body 未来可编辑，复现命令保留当前 claim 的来源和边界。
- DeepSeek、同文件命中、blame hit、OSV `introduced` 均未作为 PASS 证明。
