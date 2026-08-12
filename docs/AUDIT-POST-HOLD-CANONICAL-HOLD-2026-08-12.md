# Post-hold canonical ledger：199 source rows，结论仍为 HOLD

审计日期：2026-08-12（America/New_York）

## 结论

本轮把 Batch 2 的冻结账本、Batch F/G、OpenClaw sanitizer closure 与 residual 审计合并进一个 machine ledger。机械结果是：

| 口径 | 结果 |
|---|---:|
| Ledger records | 247 |
| Canonical source components | 211 |
| Strict released source rows | 132 |
| Incomplete-remediation released source rows | 67 |
| Broad released source envelope | **199** |
| Commit-only source rows | 12 |
| Widest source envelope | 211 |
| `integration_ready` | **false** |
| `final_count` | **null** |

不能发布“已确认 200”。这 199 条发布级 source rows 的真实状态分解是：

| 状态 | 发布级行数 | 是否可直接进入最终计数 |
|---|---:|---|
| PASS | 191 | 仅表示当前 ledger 的行级 PASS；继承的未抽样行仍受覆盖限制 |
| NARROW | 4 | 只能按写明的窄机制使用 |
| UNKNOWN | 1 | 否 |
| REJECT | 3 | 否 |

先前的 `200` 只是含重复 umbrella 的 source envelope；File Browser 终审后降为 `199`。账本按 fail-closed 规则输出 `HOLD`，没有把 REJECT、UNKNOWN 或 NARROW 偷换成 PASS。

## 本轮 28 个发布级候选的红队结果

本轮新增 28 个语义组件、39 个 public IDs：`STRICT_RELEASED=7`、`INCOMPLETE_RELEASED=21`。独立重放后为 `PASS=26`、`NARROW=2`、`REJECT=0`、`UNKNOWN=0`。

| 行 | 裁决 | 类别 | Public identity | Candidate → release fix | Vulnerable → fixed | Mechanism fingerprint label |
|---|---|---|---|---|---|---|
| F01 | PASS | STRICT | CVE-2026-44547 / GHSA-CWP8-RM8G-Q5C9 | `f9afc3c5` → `1bfc187a` | `7.2.2` → `7.3.1` | `churchcrm-public-api-login-removes-lockout-and-2fa` |
| F02 | PASS | STRICT | GHSA-MFMP-Q643-VJ39 | `0ea20d01` → `330d0d6a` | `7.4.2` → `7.4.3` | `churchcrm-groupview-role-listoption-label-xss` |
| F03 | PASS | STRICT | GHSA-M649-24Q9-Q6R4 | `0ea20d01` → `ae2b7355` | `7.5.1` → `7.6.0` | `churchcrm-group-member-url-attribute-xss` |
| F04 | PASS | STRICT | GHSA-HM7V-JRHM-FMFX | `6ef78813` → `ae2b7355` | `7.5.1` → `7.6.0` | `churchcrm-shared-person-action-attribute-xss` |
| F05 | PASS | INCOMPLETE | GHSA-F2FQ-4RMP-9X8C | `cbea916e` → `07be35d7` | `7.5.1` → `7.6.0` | `churchcrm-2fa-failure-counter-residual` |
| F06 | PASS | STRICT | CVE-2026-58409 / GHSA-37MF-VQ43-5QP9 | `095bf81b` → `1b4e2c70` | `7.3.3` → `7.4.0` | `churchcrm-community-plugin-webroot-php-rce` |
| F07 | PASS | INCOMPLETE | CVE-2026-57120 / GHSA-PV2J-RGHR-V5R9 | `179cab02` → `2adfe7e8` | `v4.6.58` → `v4.6.59` | `praisonai-python-sandbox-format-resolver-bypass` |
| F08 | PASS | INCOMPLETE | GHSA-3FP5-V549-9V66 | `8e41c118` → `55d1324c` | `v2026.6.8` → `v2026.6.9` | `openclaw-flock-wrapper-approval-binding-residual` |
| F09 | PASS | INCOMPLETE | GHSA-575V-8HFQ-M3MC | `3cc8b2a3` → `a90eb934` | `v2026.6.5` → `v2026.6.6` | `openclaw-sandbox-bind-ancestor-policy-residual` |
| F10 | PASS | INCOMPLETE | GHSA-X863-PQJW-HMGF | `3d93174c` → `78f3985c` | `v2026.5.18` → `v2026.5.19` | `openclaw-browser-act-current-tab-preflight-residual` |
| F11 | PASS | INCOMPLETE | GHSA-2X93-H3HG-2XFP | `b75ad800` → `06047005` | `v2026.5.22` → `v2026.5.26` | `openclaw-browser-snapshot-current-tab-preflight-residual` |
| F12 | PASS | INCOMPLETE | GHSA-8V95-QQCM-QP9H | `1c85eff9` → `517ce3df` | `v2026.5.26` → `v2026.5.27` | `openclaw-device-pair-approve-admin-gap` |
| F13 | PASS | INCOMPLETE | GHSA-QJPC-QF9M-XWMR | `0e702f10` → `96fba91b` | `v2026.5.12` → `v2026.5.18` | `openclaw-trusted-proxy-unpaired-scope-residual` |
| F14 | PASS | INCOMPLETE | GHSA-9C3V-684M-579C | `47eb2d48` → `3c6259eb` | `v2026.6.1` → `v2026.6.5` | `openclaw-mcp-sse-redirect-header-residual` |
| F15 | PASS | INCOMPLETE | GHSA-J4CX-JVQ7-79VM | `17ceca86` → `19fb9f12` | `v2026.5.28` → `v2026.6.1` | `openclaw-trajectory-export-redaction-residual` |
| F16 | PASS | INCOMPLETE | GHSA-WP73-F3GG-W4VR | `6c918ca8` → `797bcd5b` | `v2026.6.1` → `v2026.6.5` | `openclaw-clickclack-toolsallow-propagation-residual` |
| F17 | PASS | INCOMPLETE | GHSA-7JX6-764P-FGG9 | `6e498a1f` → `08a73dbe` | `v2026.5.26` → `v2026.5.27` | `openclaw-qqbot-same-chat-approval-fallback` |
| F18 | PASS | INCOMPLETE | GHSA-2HFG-4FH4-QP7F | `e0b8ddc1` → `3d93174c` | `v2026.5.12` → `v2026.5.18` | `openclaw-browser-action-kind-navigation-coverage-residual` |
| G01 | PASS | STRICT | CVE-2026-58407 / CVE-2026-58410 / GHSA-3J8Q-FWPJ-F8J5 / GHSA-JJCJ-H3CM-P7X7 | `b3edc225` → `83c19611` | `7.3.3` → `7.4.0` | `churchcrm-notes-object-scope-authorization` |
| G03 | PASS | STRICT | CVE-2026-44548 / GHSA-JX5R-P82P-2P8M | `6ef78813` → `f1c11f9f` | `7.4.0` → `7.4.3` | `churchcrm-fundraiser-destructive-get-csrf` |
| E01 | PASS | INCOMPLETE | CVE-2026-53864 / GHSA-CCWH-WWPP-6WG5 | `3affd5e8` → `91590132` | `v2026.5.22` → `v2026.5.27` | `openclaw-host-env-node-runtime-controls-residual` |
| E02 | PASS | INCOMPLETE | GHSA-HJR6-G723-HMFM | `3affd5e8` → `9f413acc` | `v2026.6.1` → `v2026.6.6` | `openclaw-host-env-interpreter-startup-residual` |
| E03 | PASS | INCOMPLETE | GHSA-9969-8G9H-RXWM | `3affd5e8` → `86bab969` | `v2026.6.1` → `v2026.6.6` | `openclaw-host-env-git-ext-transport-residual` |
| E04 | PASS | INCOMPLETE | GHSA-WXH3-G47H-Q3MC | `3affd5e8` → `7cdec287` | `v2026.6.1` → `v2026.6.6` | `openclaw-host-env-rustup-controls-residual` |
| R01 | PASS | INCOMPLETE | GHSA-4PQJ-3C56-5FQQ | `3affd5e8` → `85277c2d` | `v2026.5.27` → `v2026.5.28` | `openclaw-workspace-provider-credential-residual` |
| R02 | NARROW | INCOMPLETE | CVE-2026-53819 / GHSA-8WG3-5MCM-FJQ8 | `3affd5e8` → `f86953f3` | `v2026.4.29` → `v2026.5.2` | `openclaw-workspace-homebrew-executable-residual` |
| R03 | NARROW | INCOMPLETE | CVE-2026-53842 / GHSA-FQ9J-VW4W-FR6V | `3affd5e8` → `86251f43` | `v2026.4.29` → `v2026.5.2` | `openclaw-workspace-gcloud-python-residual` |
| R04 | PASS | INCOMPLETE | CVE-2026-45003 / GHSA-55CF-XX38-4P9P | `3affd5e8` → `0623079e` | `v2026.4.21` → `v2026.4.22` | `openclaw-workspace-connector-endpoint-residual` |

R02/R03 的 `NARROW` 是实质限制：PR #63277 的 Codex-generated、human-reviewed 广义修复与后续同边界 closure 成立，但 Homebrew/Cloud SDK sibling 行在 review chain 中被删。它们只能表述为 PR-level incomplete-remediation contribution，不能写成“发布 carrier 保留了对应 AI 原子 hunk”。

## 同步保留的 6 个 REJECT 控制

| Route | Public identity | 原因 |
|---|---|---|
| G02 | CVE-2026-40480 / GHSA-5W59-32C8-933V | AI 只重排已有 person GET/export 漏洞，回退 candidate 不消除漏洞 |
| 24vr | CVE-2026-53846 / GHSA-24VR-RPRV-67RF | `npm_execpath` sink 在 sanitizer candidate 之后才加入 |
| wc84 | CVE-2026-53858 / GHSA-WC84-J36W-PW4X | `STATE_DIRECTORY` sink 在 candidate 之后才加入 |
| 8f46 | GHSA-8F46-3XX3-8C9M | gateway/node env equivalence 是 approval-binding invariant，不是 denylist completeness |
| hxvm | CVE-2026-44114 / GHSA-HXVM-XJVF-93F3 | `OPENCLAW_*` 属于更早的独立 repair lineage |
| 7wv4 | CVE-2026-43531 / GHSA-7WV4-CC7P-JHXC | 对应 fix 已早于 sanitizer candidate |

这些记录是 non-counting controls，避免以后因同 SHA、同文件或“都是 env”重新抬回候选池。

## 继承的 4 个发布级 UNKNOWN 终审

| Row | 终审 | 直接依据 |
|---|---|---|
| Gitea CVE-2026-58432 / GHSA-Q9PG-JJ6X-J9P6 | **PASS** | [仓库 advisory](https://github.com/go-gitea/gitea/security/advisories/GHSA-q9pg-jj6x-j9p6) 与 global reviewed advisory 直接声明 formal alias；Copilot `1eced4a7...` 给 API draft release/attachment 加 write gate，`f7fd5102...` 给遗漏的 web `ServeAttachment` 加同一 gate。发布分支见证为 `e7fca90a...` in `v1.25.5`、`ab10e37a...` in `v1.27.0`。 |
| PraisonAI CVE-2026-57148 / GHSA-F38V-77QJ-H4JQ | **PASS** | [仓库 advisory](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-f38v-77qj-h4jq) 与 global reviewed advisory 直接声明 formal alias；Cursor `179cab02...` 的 guard 把 unset `PLATFORM_ENV` 当 dev，`e0fb8e7d...` 关闭 default-open。PyPI `0.1.4` sdist 保留公开默认 key；`0.1.6` 已改用 resolved secret。 |
| File Browser CVE-2026-54094 / GHSA-239W-M3H6-CH8V | **REJECT / non-counting** | [原 advisory](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-239w-m3h6-ch8v) 在 `2.63.14` 已修；AI `847d08bd...` 是 remediation，不是该 CVE origin。主行列出的后续 dangling-write 与 unguarded-delete 已分别由 CVE-2026-55668、CVE-2026-55667 计数，没有第三个独立机制。 |
| Coolify CVE-2026-34198 / GHSA-CGJ8-7M5Q-X5GV | **UNKNOWN** | `e1fe5863...` 的 cold-cache early return 确实延续到 fix，且发布区间成立；但唯一 atomic marker 是 generic `Changes auto-committed by Conductor`。Conductor [官方文档](https://www.conductor.build/docs/reference/checkpoints) 明确 checkpoint 可同时包含 user 与 AI changes，因此该 subject 不能证明具体 hunk 为 AI 生成。 |

PraisonAI 的发布口径同时纠正：repo advisory 写 `>=0.1.5`，但 PyPI 没有 `0.1.5`；global reviewed advisory 与实际 sdist 均支持首次可用修复版 `0.1.6`。本账本使用 `0.1.4 → 0.1.6`，不沿用旧报告的 `0.1.5`。

GitHub repo/global advisory 已直接声明 Gitea 与 PraisonAI 的 CVE/GHSA alias。CVE Services 在本次重放仍返回 404；这被记录为同步状态，而不是反向否定一方正式分配。

## 仍阻断最终 200 的发布级行

### REJECT（3）

- Gitea OAuth reactivation：CVE-2026-55987 / GHSA-VRHC-JJFC-M3M3。
- GitPython positional `--file`：GHSA-3WXW-XV34-2FRG。
- Scriban lazy multiplication：GHSA-89CF-6HMV-8RXM。

### UNKNOWN（1）

- Coolify TrustHosts cold-cache attribution：CVE-2026-34198 / GHSA-CGJ8-7M5Q-X5GV。

### NARROW（4）

- Hermes cross-profile session search：CVE-2026-49956 / GHSA-MGXW-V6RH-WCV6。
- OpenClaw Feishu webhook scoped evidence：CVE-2026-32974 / CVE-2026-44109 / GHSA-G353-MGV3-8PCJ / GHSA-XH72-V6V9-MWHC。
- 本轮 R02 Homebrew。
- 本轮 R03 Cloud SDK Python。

即使把四条 NARROW 全按其窄范围保留，当前也只有 195 个可接纳发布级 source rows；至少还要替换 3 个 REJECT、闭合 1 个 UNKNOWN，并新增 1 个无重复组件，才可能到 200。继承的 74 条 post-strict 中只有 20 条做过 Batch 1 adversarial sampling，这一 coverage blocker 也尚未消失。

## Verifier 闸门

本轮 verifier 实际通过：

- 8 个 source artifacts 的 SHA-256 全匹配；
- builder 对 `ledger.jsonl` / `summary.json` byte-identical；
- 247 个 row keys 唯一，211 个 canonical components 守恒；
- 358 个 canonical public-ID occurrences 全部唯一，无跨组件 alias collision；
- 211 个 exact mechanism fingerprints 全部唯一；该机械检查不替代上面的 File Browser 语义终审；
- 新增 39 个 public IDs 内部唯一，且与 Batch 2 canonical public IDs 零交集；
- 28 个 mechanism fingerprints 唯一；
- 新增 77 个 candidate/carrier/fix Git objects 与 Batch 2 edge-object 集零交集；
- 共享 candidate/fix 的每一行都有显式 reuse justification；
- 新闭合的 PraisonAI JWT 行与 F07 Python sandbox 行共享 multi-purpose `179cab02...`，双方均登记不同 input/sink 的 reuse justification；
- live Git replay 为 28/28：candidate/carrier 在 vulnerable tag，fix 不在 vulnerable tag，fix 在 fixed tag；
- 29/29 一方 repo advisories 当前 `published` 且未撤回；有 CVE 的行经 repo/global identifiers 闭合；
- 追加重放 Gitea/PraisonAI 2/2：formal alias、candidate/fix 和 release/package containment 均闭合；
- 最终仍强制 `status=HOLD`、`integration_ready=false`、`final_count=null`。

闸门分级保持保守：发布级 public-ID alias 为 `PASS`，但含三条 commit-only UNKNOWN 的 widest alias 为 `PARTIAL`；exact fingerprint 为 `PASS`，全量语义复核仍为 `PARTIAL`；release containment 也为 `PARTIAL`，因为上述 30 条有本轮 live replay，其余继承行沿用冻结 Batch2 证据，没有在本轮把 199 条全部重新下载/构建。因此 `integration_ready` 不能翻成 true。

## 可重放命令

```zsh
python3 autoresearch/orchestrator-260812-posthold-canonical/build.py --check
python3 autoresearch/orchestrator-260812-posthold-canonical/verify.py
python3 autoresearch/orchestrator-260812-posthold-canonical/verify.py --live
python3 autoresearch/orchestrator-260812-posthold-canonical/test_canonical.py
```

`--live` 只读取三个本地一方 Git clones，并通过 `gh api` 读取公开 advisory；命令不打印 credential。结构 verifier 与 test 不需要网络。

## Durable artifacts

- `autoresearch/orchestrator-260812-posthold-canonical/ledger.jsonl`
- `autoresearch/orchestrator-260812-posthold-canonical/summary.json`
- `autoresearch/orchestrator-260812-posthold-canonical/result.json`
- `autoresearch/orchestrator-260812-posthold-canonical/adjudications.json`
- `autoresearch/orchestrator-260812-posthold-canonical/inherited_corrections.json`
- `autoresearch/orchestrator-260812-posthold-canonical/source_manifest.json`
- `autoresearch/orchestrator-260812-posthold-canonical/build.py`
- `autoresearch/orchestrator-260812-posthold-canonical/verify.py`
- `autoresearch/orchestrator-260812-posthold-canonical/test_canonical.py`

本报告没有改写 Batch 2 的冻结 artifact。它在单一新账本中显式接纳、收窄或拒绝 post-hold 行，并保留所有未闭合项，因此可以作为下一轮替换 3 个 REJECT、闭合 1 个 UNKNOWN 并新增至少 1 个组件的起点；四条 NARROW 仍只能按各自窄口径使用，不能作为“200 已完成”的依据。
