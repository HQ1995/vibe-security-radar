# 135 后续：AI 不完整修复 Batch E（2026-08-12）

## 结论

本批确认 **17 个发布级 `AI_INCOMPLETE_REMEDIATION` 组件、20 个新 public IDs**，另确认 **2 个 `COMMIT_ONLY` 组件、4 个新 public IDs**。它们都不是“AI 首次创造旧漏洞”的证据；准入点是 AI 原子提交明确修过同一安全机制，却留下后来由一方 advisory 和精确 fix 闭合的残余。

| 层级 | 组件数 | Public IDs | 计入发布级下界 |
|---|---:|---:|---|
| `AI_INCOMPLETE_REMEDIATION_RELEASED` | 17 | 20 | 是 |
| `AI_INCOMPLETE_REMEDIATION_COMMIT_ONLY` | 2 | 4 | 否 |

19 项一方 repo advisory 均为 `state=published`、`withdrawn_at=null`。24 个大小写归一化 public IDs 与 frozen `strict-200-v3` 的 200 个 IDs 交集为 0，也未在此前 Batch A-D/Main 的已计数组件中出现。

## 准入门

发布级正例必须同时满足：

1. candidate 原子对象自身有 AI author、co-author 或明确 trailer；
2. candidate 的 delta 明确在修 advisory 所述机制，不靠邻近文件或 carrier 继承归因；
3. residual 至少进入一个一方认定为受影响的发布版本；
4. later fix 在同一 input、trust boundary 和 sink 上精确关闭 residual；
5. direct ancestry 或 PR member/carrier/backport transfer 可重放；
6. public alias 与机制组件均未和既有账本重复。

candidate 和 closure 若在同一首个 release 才出现，只记 `COMMIT_ONLY`。OSV `introduced`、版本字段、模型票和 subject 只用于 routing；本批实际发现一条“官方写 patched、代码仍未闭合”的负控，并未收录。

## 组件总表

| # | Public component | Repo | AI atomic partial -> later closure | Release gate | 裁决 |
|---:|---|---|---|---|---|
| 1 | GHSA-6Q7J-XR26-3H2C | scriban/scriban | `f55280a0... -> 8fdbd687...` | partial in `7.2.0`; fixed `7.2.1` | RELEASED |
| 2 | CVE-2026-55987 / GHSA-VRHC-JJFC-M3M3 | go-gitea/gitea | member `eff673fc...`, carrier `c43eb7c3...`, backport member `fd4641dc...`, carrier `2bde4fa5... -> fce961b4...` | affected through `1.26.4`; fixed `1.27.0` | RELEASED |
| 3 | CVE-2026-57148 / GHSA-F38V-77QJ-H4JQ | MervinPraison/PraisonAI | `179cab02... -> e0fb8e7d...` | platform `0.1.4`; fixed `0.1.5` | RELEASED |
| 4 | CVE-2026-42204 / GHSA-CHG4-63HM-XV9X | coollabsio/coolify | `c9922c30... ->` member `817128c5...`, carrier `e1aac50b...` | beta.471-beta.473; fixed beta.474 | RELEASED |
| 5 | GHSA-V396-V7Q4-X2QJ | gitpython-developers/GitPython | `c9a26789... -> 56806080...` | affected `3.1.50`; fixed `3.1.51` | RELEASED |
| 6 | GHSA-MV93-W799-CJ2W | GitPython | `c417af46... -> 54538428...` | through `3.1.49`; fixed `3.1.50` | RELEASED |
| 7 | GHSA-FJR4-X663-MWXC | GitPython | `701ce32f... -> 1d51b891...` | through `3.1.53`; fixed `3.1.54` | RELEASED |
| 8 | GHSA-HH9P-6WH2-4MFC | GitPython | `3af0c251... -> f2550b65...` | through `3.1.57`; fixed `3.1.58` | RELEASED |
| 9 | GHSA-9RJ7-RF2P-W77R | GitPython | `7a4f5dcb... -> d9ddb55b...` | through `3.1.57`; fixed `3.1.58` | RELEASED |
| 10 | GHSA-4GMW-GG2M-W46P | GitPython | `3af0c251... -> 9b5dcaf8...` | through `3.1.57`; fixed `3.1.58` | RELEASED |
| 11 | GHSA-WVPP-8HX9-P66J | GitPython | `e8d0fbf7... -> 96a888f4...` | through `3.1.57`; fixed `3.1.58` | RELEASED |
| 12 | GHSA-JM78-9FVV-MHGR | GitPython | `1ed1b924... -> a495ccd3...` | through `3.1.57`; fixed `3.1.58` | RELEASED |
| 13 | GHSA-284H-M62Q-GF8W | GitPython | `c417af46... -> 4b4e47fc...` | through `3.1.58`; fixed `3.1.59` | RELEASED |
| 14 | GHSA-8MCC-HRX5-HVXC | GitPython | `7a4f5dcb... -> b68afff4...` | through `3.1.58`; fixed `3.1.59` | RELEASED |
| 15 | GHSA-5XXX-QHH7-9287 | GitPython | `701ce32f... -> 1b0d2d9b...` | through `3.1.58`; fixed `3.1.59` | RELEASED |
| 16 | GHSA-3WXW-XV34-2FRG | GitPython | `3af0c251... -> 1b0d2d9b...` | through `3.1.58`; fixed `3.1.59` | RELEASED |
| 17 | GHSA-89CF-6HMV-8RXM | scriban/scriban | `2d01bd15... -> 973edd1f...` | through `7.2.5`; fixed `7.2.6` | RELEASED |
| 18 | CVE-2026-58427 / GHSA-PRR9-9MP4-5GP2 | go-gitea/gitea | member `2828e4bf...`, carrier `685b62c6... ->` member `44ea3a8d...`, carrier `122ebcf0...` | both first in `1.27.0` | COMMIT_ONLY |
| 19 | CVE-2026-34167 / GHSA-962V-GXMW-56HC | coollabsio/coolify | `a94517f4... ->` member `3e0d48fa...`, carrier `2729dffb...` | both first in beta.471 | COMMIT_ONLY |

## 一方因果证据

### Scriban：两个不同资源边界

`f55280a09575e577fcf7f5629007e0814594e3ac` 的 parent 是 `760dc21259f3da6a5adbd3148c260e25f1751706`，带 Copilot co-author，主题就是给 array initializer 强制 parser depth。它在 array initializer 局部加 guard，却继续让共享 `EnterExpression` 在超限后只记错、不停止递归。GHSA-6Q7J-XR26-3H2C 的深层括号/表达式 PoC 因此仍能栈耗尽；`8fdbd687bbe8f00085c4c4c5b2b3b8d529933949` 才在 shared parser control flow 超限时停止。`7.2.0` 含 partial 而不含 closure，`7.2.1` 首次含 closure。

GHSA-89CF-6HMV-8RXM 是另一条 runtime 资源边界。Copilot partial `2d01bd15a1114fac2533aa005036e07389ee89db` 已给多种 expression operation 接入 `LoopLimit`；后来 `205ca6a7...` 又补 materialized `ScriptArray * int`，但 lazy `ScriptRange.Multiply` 仍不计步。`973edd1f1c10fae7d3a8650ac0d309d52072102c` 才给 lazy multiplication 调用同一 loop accounting。parser recursion 与 lazy multiplication 的代码路径、资源 invariant、PoC 和 GHSA 均不同，不合并。

### Gitea：release-grade OAuth 与 commit-only private-org sibling

OAuth 修复 PR 的最小 AI member 是 `eff673fcaf9a4a39d7c1fe93816f7e20a581561e`，parent `49417483679aabcffd84fad147fc2392272cf8d0`，正文带 `Assisted-by: claude-code:claude-opus-4-7`。parent 已把 OAuth callback 改成不自动激活；AI member 为保留 sync-disabled 自动恢复，又以 `AccessToken`、`RefreshToken`、`ExpiresAt` 全空作为 sync-disable signature。没有 refresh token 的 auth source 会使管理员手工禁用用户也满足该 signature，于是 callback 重新激活。main squash carrier 为 `c43eb7c33a100ffc7b2367adf165f7085e0ccdc5`；release/v1.26 的 patch-equivalent member/carrier 是 `fd4641dc591a5f4dedacb6654c77cf66f8e4740d` / `2bde4fa5d268415fdce9442826d63443ad81d47f`。`fce961b44aa9631f8e9f5d6b3168d16d9a6728af` 后来关闭 empty-token misclassification；一方 advisory 将 `<=1.26.4` 标 affected、`1.27.0` 标 fixed。

private-org 组件的 AI member `2828e4bf72d486bb11bb81ebf26aa20254b62bae`（Claude trailer）只给 `/public_members` 两个 handlers 加 visibility gate；`/members` sibling 继续枚举私有组织成员。`44ea3a8d24638ca4a395d641d39f476ae1dc421d` 才给 `/members` 加同一 gate。对应 carriers 是 `685b62c60fc595e3612a85f0895471876db56292` 与 `122ebcf0a8f6f187575a42ad3023d8f8c5e9181b`。两者都在 `1.26.4` 之后、`1.27.0` 之前，故因果成立但只记 commit-only。

### PraisonAI：生产环境默认值 fail-open

Cursor co-authored atomic `179cab02dbec0c1e9b601507a65908e079876004` 的 parent 是 `402d7ed9fc5926babaa70c97a6ee5353e3d0dd62`。它明确给 platform JWT issuance 加 production guard，却让 `PLATFORM_ENV` 未设置时默认成 `dev`，从而继续接受公开默认 secret `dev-secret-change-me`。该状态进入 platform `0.1.4`。`e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747` 将 unset env 视为非显式 dev，并生成随机 ephemeral secret；platform `0.1.5` 首次含 closure。

### Coolify：一个 released、一个 commit-only

Claude co-authored `c9922c30c2a6bf922653a5f2d631aab4fea685c4` 给 install/build/start 字段接入 `shellSafeCommandRules()`，但共享扁平 regex 明文允许 bare `&`。该残缺规则进入 beta.471-beta.473。原子 member `817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1` 用 token-aware grammar 区分 `&&` / `||` 并拒绝 bare `&`，merge carrier 为 `e1aac50b745cf499e710b7e35cd2a9d6a1538dd9`，首次进入 beta.474。

Claude co-authored `a94517f452e225046e01c08385d6a7aedf085c7d` 明确 scope ActivityMonitor lookup，却在 activity 缺 `team_id` 时 fail-open，测试也固化该行为。member `3e0d48faeaab950bfd063dfca908f1d140316ede` 增加 locked property、team/server ownership fallback、无归属 fail-closed，并在生产路径写 `team_id`；carrier 为 `2729dffb3e30167c1ffd642357b7e0bb99b7d180`。partial 与 closure 同在 beta.471，故只记 commit-only。

### GitPython：12 个 first-party residual components

这些不是把一个 GHSA 拆成十二行。每项有独立 repo advisory、不同 Git option/config input、不同 high-level API 或 sink，并有精确 later fix。

| Public advisory | AI remediation 本身做了什么 | 精确 residual / later fix |
|---|---|---|
| GHSA-V396-V7Q4-X2QJ | GPT 5.4 `c9a26789...` 将 clone `multi_options` 在 `shlex` 拆分后再做 unsafe check | exact-token gate 漏 joined `-uVALUE/-cVALUE`；GPT `56806080c1348749b07daa4a2024ce47b3cad285` 解析 clustered/joined short options |
| GHSA-MV93-W799-CJ2W | GPT 5.5 `c417af46...` 拒绝 config value 的 CR/LF/NUL | section name 仍能注入换行；GPT `54538428f79b0c91ba52cda5229856a6edf7ac06` 补 section-name validation |
| GHSA-FJR4-X663-MWXC | GPT 5.6 `701ce32f...` 建立共享 unsafe Git option guards，覆盖 archive/revision/blame/network callers | `Diffable.diff` 未接入，`--output` 可任意覆写；GPT `1d51b891d7f236044a6aa17498ec682b63dad6e6` 接入 guard |
| GHSA-HH9P-6WH2-4MFC | GPT 5.6 `3af0c251...` 给 checkout-index/tag file options 加 guard | `IndexFile.remove`、`Head.checkout` 的 `--pathspec-from-file` siblings 未覆盖；`f2550b65bf60ca087190981e2c7b6865e201f40c` 闭合 |
| GHSA-9RJ7-RF2P-W77R | GPT `701ce32f...` / `7a4f5dcb...` 建 clone unsafe-option denylist并继续补项 | `Repo.init --template` 未使用该 gate；`d9ddb55bdc66ffe8c9932fe460e6b8c8211e47c7` 闭合 |
| GHSA-4GMW-GG2M-W46P | `3af0c251...` 已识别同类 Git file-option sink并保护邻近 APIs | read-tree callers 未接入，可写 attacker-selected index；`9b5dcaf85da5946dbf69dcd53f9edba08f760b32` 闭合 |
| GHSA-WVPP-8HX9-P66J | GPT `e8d0fbf7...` 明确修 split short-option value validation | `split_single_char_options=False` 不把 joined value 纳入 candidates；`96a888f4d782cb2f80452148e48e60ce4af6d541` 闭合 |
| GHSA-JM78-9FVV-MHGR | GPT `1ed1b924...` 给 config section delimiter 加结构化校验 | option name 的 `=/#/space` 仍可伪造 directive；`a495ccd3b547ccd60b2187215823b72a9c0188bf` 闭合 |
| GHSA-284H-M62Q-GF8W | `c417af46...` 已保护直接写入的恶意 multiline config value | read-existing -> unrelated write 会把 dormant multiline 值重序列化成 live directive；`4b4e47fc1224e23b0c8ee7220a7192818f2e4abb` 闭合 |
| GHSA-8MCC-HRX5-HVXC | `7a4f5dcb...` 继续扩展 clone unsafe-option denylist | 漏 `--separate-git-dir`；`b68afff45af0f49e79a3e2d2162018986b37ad5d` 闭合 |
| GHSA-5XXX-QHH7-9287 | `701ce32f...` 建 revision-output denylist并接入多个 APIs | `Repo.blame --contents/-S` 可读任意文件；`1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6` 闭合 |
| GHSA-3WXW-XV34-2FRG | `3af0c251...` 明确给 `TagReference.create` 的 file option 加 guard | 只看 kwargs，positional reference 可携带 `--file`；同一 `1b0d2d9b...` 闭合 |

前 3 项分别以 `3.1.50 -> 3.1.51`、`3.1.49 -> 3.1.50`、`3.1.53 -> 3.1.54` 形成发布见证。第 4-8 项的一方 affected 上界是 `3.1.57`、fix 是 `3.1.58`；tag `3.1.58` 的 peeled commit `30be45d786e95023e23c616fec5cbabca861b44c` 包含五个 closure。第 9-12 项 affected 上界是 `3.1.58`、fix 是 `3.1.59`；tag `3.1.59` 的 peeled commit `66340d77aab9a7468f4aed3681d4ef1e3c0ec931` 包含三个 closure（`1b0d2d9b...` 同时关闭两个独立 API residual）。

## 未收录负控

| Candidate / advisory | 结果 | 反证 |
|---|---|---|
| PraisonAI CVE-2026-62181 / GHSA-CV3G-HJ65-PCFH | FAIL insufficient fix reversal | 一方 advisory 把 `>=4.6.78` 标 patched，但 release commit `393de394...` 只在 Python SandboxExecutor 拦字面 `-exec`；`-execdir`、`-delete`、Python `safe_shell`、TS utility shell 与 TS SandboxExecutor 仍未闭合。不能用版本字段覆盖代码反证 |
| GitPython GHSA-2F96-G7MH-G2HX | FAIL/COMMIT_ONLY, not a new release component | GPT `181e8ede...` 与补全 joined short option 的 `56806080...` 同在首个 `3.1.51`；本批 V396 的发布 witness 是受影响 `3.1.50` 中更早、已发布的 `c9a26789...` partial，不把同 PR 临时态另计 |
| GitPython GHSA-HMQ2 / GHSA-7833 families | FAIL attribution gate | 对应 pre-existing submodule/name 或 prior security delta 为 human；AI 只做 final closure |
| Pydantic UI CVE-2026-54249 | FAIL squash projection | `272c92ac...` carrier 的 Claude trailer 来自无关 review hunk；UploadedFile 重构的真实 members `b6866b45...` / `a6b5b5a9...` 无 AI marker |
| FastChat / Kyverno follow-ups | FAIL remediation order | AI 只出现在后续完整 fix/test，不是残缺 partial |

## 计数影响

- strict release-grade：125，不变；
- incomplete-remediation release-grade：31 + 17 = **48**；
- 宽口径发布级确认下界：156 + 17 = **173**；
- commit-only：11 + 2 = **13**，其中 incomplete 12、strict 1；
- 最宽 commit-level 工作数：167 + 19 = **186**；
- 48 个发布级 incomplete-remediation 组件共 **68 个 public IDs**；13 个 commit-only 组件共 **19 个 public IDs**。

因此距离 200 个发布级宽口径组件还差 **27**；若只看包含 commit-only 的研发工作集，还差 **14**。两者不可混写。

## 可重放检查

```zsh
cd /home/hanqing/agents/ai-slop

gitpython_repo=/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_github.com_gitpython_c572da6f272ffa3a525231f03f831cb57d014c35a0987b3e1e11b8ec7575b6f1
scriban_repo=/home/hanqing/.cache/cve-analyzer/repos/github.com_scriban_scriban
praison_repo=/home/hanqing/.cache/cve-analyzer/repos/github.com_mervinpraison_praisonai
coolify_repo=/home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify

# Candidate 自身 AI attribution 与 direct parent。
git -C "$gitpython_repo" show -s --format=fuller c9a26789 c417af46 701ce32f 3af0c251 e8d0fbf7 1ed1b924 7a4f5dcb
git -C "$scriban_repo" show -s --format=fuller f55280a0 2d01bd15
git -C "$praison_repo" show -s --format=fuller 179cab02
git -C "$coolify_repo" show -s --format=fuller c9922c30 a94517f4

# 本地已有 release topology。
git -C "$gitpython_repo" tag --contains c9a26789 --no-contains 56806080 --sort=version:refname
git -C "$gitpython_repo" tag --contains c417af46 --no-contains 54538428 --sort=version:refname
git -C "$gitpython_repo" tag --contains 701ce32f --no-contains 1d51b891 --sort=version:refname
git -C "$scriban_repo" tag --contains f55280a0 --no-contains 8fdbd687 --sort=version:refname
git -C "$scriban_repo" tag --contains 2d01bd15 --no-contains 973edd1f --sort=version:refname
git -C "$coolify_repo" tag --contains c9922c30 --no-contains 817128c5 --sort=version:refname

# 3.1.58 / 3.1.59 后续对象不写入旧本地镜像，直接读一方 refs/compare。
git ls-remote --tags https://github.com/gitpython-developers/GitPython.git 'refs/tags/3.1.58*' 'refs/tags/3.1.59*'
gh api repos/gitpython-developers/GitPython/compare/f2550b65bf60ca087190981e2c7b6865e201f40c...3.1.58 --jq .status
gh api repos/gitpython-developers/GitPython/compare/4b4e47fc1224e23b0c8ee7220a7192818f2e4abb...3.1.59 --jq .status

# Gitea squash/backport 必须回到 PR members，不从 carrier 反投影。
gh api repos/go-gitea/gitea/pulls/38009/commits --paginate \
  --jq '.[] | [.sha,.commit.author.name,.commit.author.email,.commit.message] | @tsv'
gh api repos/go-gitea/gitea/pulls/38183/commits --paginate \
  --jq '.[] | [.sha,.commit.author.name,.commit.author.email,.commit.message] | @tsv'

# Praison CV3G 负控：所谓 patched tag 仍有四实现残留。
git -C "$praison_repo" grep -n -E 'safeCommands.*find|SAFE_COMMANDS|find.*-exec' v4.6.78 -- \
  src/praisonai-ts/src/tools/utility-tools.ts \
  src/praisonai-ts/src/cli/features/sandbox-executor.ts \
  src/praisonai/praisonai/cli/features/safe_shell.py \
  src/praisonai/praisonai/cli/features/sandbox_executor.py

# 一方 advisory 状态；不输出凭据。
for spec in \
  scriban/scriban:GHSA-6q7j-xr26-3h2c \
  go-gitea/gitea:GHSA-vrhc-jjfc-m3m3 \
  MervinPraison/PraisonAI:GHSA-f38v-77qj-h4jq \
  coollabsio/coolify:GHSA-chg4-63hm-xv9x \
  gitpython-developers/GitPython:GHSA-v396-v7q4-x2qj \
  gitpython-developers/GitPython:GHSA-mv93-w799-cj2w \
  gitpython-developers/GitPython:GHSA-fjr4-x663-mwxc \
  gitpython-developers/GitPython:GHSA-hh9p-6wh2-4mfc \
  gitpython-developers/GitPython:GHSA-9rj7-rf2p-w77r \
  gitpython-developers/GitPython:GHSA-4gmw-gg2m-w46p \
  gitpython-developers/GitPython:GHSA-wvpp-8hx9-p66j \
  gitpython-developers/GitPython:GHSA-jm78-9fvv-mhgr \
  gitpython-developers/GitPython:GHSA-284h-m62q-gf8w \
  gitpython-developers/GitPython:GHSA-8mcc-hrx5-hvxc \
  gitpython-developers/GitPython:GHSA-5xxx-qhh7-9287 \
  gitpython-developers/GitPython:GHSA-3wxw-xv34-2frg \
  scriban/scriban:GHSA-89cf-6hmv-8rxm \
  go-gitea/gitea:GHSA-prr9-9mp4-5gp2 \
  coollabsio/coolify:GHSA-962v-gxmw-56hc; do
  repo=${spec%:*}
  id=${spec##*:}
  gh api "repos/$repo/security-advisories/$id" \
    --jq '[.ghsa_id,(.cve_id // "-"),.state,.withdrawn_at,
           (.vulnerabilities | map([.vulnerable_version_range,.patched_versions] | join(" => ")) | join("; "))] | @tsv'
done
```

## 产物边界

本批使用 first-party Git objects、PR member lists、release refs 与 repo advisories。没有修改 frozen ledger、adjudication JSON、脚本或产品代码。共享 candidate/fix SHA 只有在 public advisory、输入路径、sink 与 invariant 均独立时才允许对应多个组件；alias 或同一机制复述仍只计一次。
