# GHSA-6Q7J-XR26-3H2C — Scriban parser-recursion origin re-review

## 结论

这条 `ir_chain` 的原始漏洞提交可以闭合，不应继续保持 `UNKNOWN`。

| 角色 | 提交 | 结论 |
|---|---|---|
| 原始递归漏洞 BIC / 建议 `original_sha` | [`46054810b50b03a6d19cd51886321cbbefa5d589`](https://github.com/scriban/scriban/commit/46054810b50b03a6d19cd51886321cbbefa5d589) | 仓库根提交首次公开写入 `ParseExpression`、`ParseArrayInitializer`、`ParseParenthesis` 和 unary 递归路径，完全没有 expression-depth 终止门禁。作者、提交者均为 Alexandre Mutel；无 AI marker。|
| 非终止 `EnterExpression` 守卫的首写提交 | [`e0f646d899e60c8b88f01ebae6f998fc49116e09`](https://github.com/scriban/scriban/commit/e0f646d899e60c8b88f01ebae6f998fc49116e09) | 首次把 `ExpressionDepthLimit` 接到表达式递归，但超限时仅 `LogError` 并置 flag，继续递归。其直接父提交不含这些表达式守卫。作者、提交者均为 Alexandre Mutel；无 AI marker。|
| AI-assisted 不完整修复 | [`f55280a09575e577fcf7f5629007e0814594e3ac`](https://github.com/scriban/scriban/commit/f55280a09575e577fcf7f5629007e0814594e3ac) | 仅给 `ParseArrayInitializer` 外包 `EnterExpression`/`LeaveExpression`，依赖上述非终止守卫；commit trailer 为 `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`。|
| 最终闭合 | [`8fdbd687bbe8f00085c4c4c5b2b3b8d529933949`](https://github.com/scriban/scriban/commit/8fdbd687bbe8f00085c4c4c5b2b3b8d529933949) | `EnterExpression` 超限时改为 fatal log 并抛 `FatalParserException`，同时加入 `RuntimeHelpers.EnsureSufficientExecutionStack()`。提交对象没有 AI trailer。|

建议页面字段：

```text
original_sha         = 46054810b50b03a6d19cd51886321cbbefa5d589
original_author_kind = HUMAN
original_author_name = Alexandre Mutel
```

`e0f646d...` 应作为“失效门禁首写”保留在解释中；它不是 array-recursion 的最早 BIC。页面也不应再称 `f55280a...` “写了 parser guard”：该提交只把既有守卫接入 array initializer。

### 精确拓扑与身份

| 提交 | 直接父 | author / committer | AI marker |
|---|---|---|---|
| `46054810b50b03a6d19cd51886321cbbefa5d589` | 无（zero-parent root） | Alexandre Mutel `<alexandre_mutel@live.com>` / 同一身份 | 无 |
| `e0f646d899e60c8b88f01ebae6f998fc49116e09` | `5f039d2d2bb86e680a8c06d7cc739f26d7324705` | Alexandre Mutel `<alexandre_mutel@live.com>` / 同一身份 | 无 |
| `b5ac4bf30459fdc76964e3f751e16f7e96079ea7` | `a6fe6074199e5c04f4d29dc8d8e652b24d33e3e4` | Dishan Sachin `<134765302+skdishansachin@users.noreply.github.com>` / Alexandre Mutel `<alexandre_mutel@live.com>` | 无；只有 Alexandre Mutel 的 human co-author trailer |
| `f55280a09575e577fcf7f5629007e0814594e3ac` | `760dc21259f3da6a5adbd3148c260e25f1751706` | Alexandre Mutel `<alexandre_mutel@live.com>` / 同一身份 | `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>` |
| `8fdbd687bbe8f00085c4c4c5b2b3b8d529933949` | `205ca6a7c2349d3d388bd5f1f7729ee198c0d5e5` | Alexandre Mutel `<alexandre_mutel@live.com>` / 同一身份 | 无 |

## 一方 advisory 定义的生命周期

- 当前一方 advisory [GHSA-6Q7J-XR26-3H2C](https://github.com/scriban/scriban/security/advisories/GHSA-6q7j-xr26-3h2c) 明确说明：`ExpressionDepthLimit` 超限后只记录非 fatal 错误，括号、数组、对象和 unary 的递归仍继续，最终触发不可捕获的 `StackOverflowException`。它把本案定义为 [GHSA-WGH7-7M3C-FX25](https://github.com/scriban/scriban/security/advisories/GHSA-wgh7-7m3c-fx25) 与 [GHSA-P6Q4-FGR8-VX4P](https://github.com/scriban/scriban/security/advisories/GHSA-p6q4-fgr8-vx4p) 的不完整修复。
- GHSA-WGH7 描述最初的通用 expression recursion，受影响至 6.5.8，声称 6.6.0 修复；其一方引用包括 `b5ac4bf...`。
- GHSA-P6Q4 描述 nested array initializer 绕过该修复，声称 7.0.0 修复；其递归链正是 `ParseArrayInitializer -> ExpectAndParseExpression -> ParseExpression -> ParseArrayInitializer`。
- 当前 advisory 的范围为 6.6.0–7.2.0，修复版本为 7.2.1。这是“两个修复均未真正终止递归”的残余范围，不代表原始递归代码直到 6.6.0 才出现。

## 原始 BIC：`46054810...`

完整一方历史中，`git blame --line-porcelain -L 772,840 f55280a^ -- src/Scriban/Parsing/Parser.Expressions.cs` 把 `ParseArrayInitializer` 的函数声明、循环，以及关键的 `ExpectAndParseExpression(scriptArray)` 路径追溯到 `46054810...` 的旧路径 `src/Textamina.Scriban/Parsing/Parser.Expressions.cs`。

该根提交中的因果链为：

1. `Template.Parse` 调用 `ParseInternal`，构造 `Parser` 并调用 `Parser.Run`（`Template.cs:48-52,94-110`）。
2. `ParseExpression` 遇到 `[` 调用 `ParseArrayInitializer`，遇到 `(` 调用 `ParseParenthesis`，遇到 unary token 调用 `ParseUnaryExpression`（`Parser.Expressions.cs:91-147`）。
3. `ParseArrayInitializer` 在第 334 行调用 `ExpectAndParseExpression(scriptArray)`；嵌套 `[` 因此重新进入同一调用链（第 313-362 行）。
4. `ParseParenthesis` 同样在第 469 行调用 `ExpectAndParseExpression`；unary 路径在第 87 行递归。
5. 根树中对 `ExpressionDepthLimit`、`EnterExpression`、`_expressionDepth` 的 `git grep` 均为空。仅有 `StatementDepthLimit`，它不是 expression-recursion 门禁。

### 父边界与 move 排除

`git rev-list --parents -n 1 46054810...` 只输出提交自身：它是公开仓库的零父提交。因此没有更早 public parent tree 可含这些行；“父中不存在”由根拓扑直接成立，而不是由缺失或 shallow history 推断。

后续 [`19867811c2bbd3a438e188b85ea370da946ad06e`](https://github.com/scriban/scriban/commit/19867811c2bbd3a438e188b85ea370da946ad06e) 只是 99% similarity 的 namespace/path rename（`Textamina.Scriban` -> `Scriban`）。它不是 BIC。跨 rename blame 仍回到 `46054810...`，未发现可进一步分解的公开 member commit。

根提交很大（初始公开树），但它是完整一方历史中首次存活的源码对象；不存在 carrier、revert 或 squash member 可以替代它作为更小的公开 BIC。

## 非终止 guard 的首写：`e0f646d...`

`git log -S '_isExpressionDepthLimitReached'` 和 `git log -S 'ExpressionDepthLimit'` 把表达式守卫的首写定位到 `e0f646d...`。该提交新增：

```csharp
private void EnterExpression()
{
    _expressionDepth++;
    if (Options.ExpressionDepthLimit.HasValue &&
        !_isExpressionDepthLimitReached &&
        _expressionDepth > Options.ExpressionDepthLimit.Value)
    {
        LogError(...);
        _isExpressionDepthLimitReached = true;
    }
}
```

它还在 `ParseExpression` 入口调用 `EnterExpression()`。超限分支没有 return、throw 或 fatal 标记，flag 只抑制重复日志。因此这正是当前 advisory 所说的“记录错误但继续递归”。

直接父提交为 [`5f039d2d2bb86e680a8c06d7cc739f26d7324705`](https://github.com/scriban/scriban/commit/5f039d2d2bb86e680a8c06d7cc739f26d7324705)：

- `git grep` 找不到 `ExpressionDepthLimit`、`_isExpressionDepthLimitReached`、`EnterExpression` 或 `LeaveExpression`；
- 但父树已包含 `ParseExpression -> ParseParenthesis/ParseArrayInitializer` 以及各自的 `ExpectAndParseExpression` 递归路径；
- 父树只有针对 statement blocks 的 `StatementDepthLimit`，不能终止 expression recursion。

因此 `e0f646d...` 是非终止 expression guard 的最小一方首写提交，直接父缺失已经闭合。它是单父提交，不是 merge；commit object 只有 Alexandre Mutel 的 author/committer 和普通提交消息，没有 `Co-Authored-By`、bot、generator 或其他 AI 标记。

## 两次不完整修复与最终闭合

### 6.6.0 默认门禁：`b5ac4bf...`

[`b5ac4bf30459fdc76964e3f751e16f7e96079ea7`](https://github.com/scriban/scriban/commit/b5ac4bf30459fdc76964e3f751e16f7e96079ea7) 把 `EnterExpression` 的 limit 读取改为 `Options.ExpressionDepthLimit ?? 250`，使默认配置启用计数，但保留了非 fatal `LogError` 和继续执行。这解释了为什么 6.6.0 虽宣称修复 GHSA-WGH7，当前 advisory 仍能在 6.6.0 上复现。该提交作者为 Dishan Sachin、co-author 为 Alexandre Mutel；没有 AI marker。

### 7.0.0 array 包装：`f55280a...`

`f55280a...` 的两文件 diff 仅：

- 用 `EnterExpression(); try { ... } finally { LeaveExpression(); }` 包住既有 `ParseArrayInitializer`；
- 新增 depth 20、limit 10 的测试，只断言 `template.HasErrors` 和错误消息。

它没有修改 `EnterExpression` 的实现，也没有断言递归已停止。直接父 `760dc212...` 已有原始 array recursion 和非终止 guard，唯独 array path 尚未调用该 guard。故这是 AI-assisted 的不完整 remediation，而不是原始递归漏洞 BIC，也不是 guard 首写。

### 7.2.1 真正闭合：`8fdbd687...`

`8fdbd687...` 在同一个 `EnterExpression` 控制点完成修复：

- 配置深度超限时以 fatal 方式记录并抛 `FatalParserException.Instance`；
- 在每次进入时调用 `RuntimeHelpers.EnsureSufficientExecutionStack()`，不足时同样 fatal + throw；
- 新测试覆盖 10,000 层 parentheses、arrays、objects、unary 和 Liquid parsing，而不是只检查浅层错误日志。

`git tag --contains` 的最早相关 release 边界与 advisory 一致：`b5ac4bf...` 从 6.6.0 起，`f55280a...` 从 7.0.0 起，`8fdbd687...` 从 7.2.1 起。三者 ancestry 依次成立。

## 作者与 AI marker 边界

- `46054810...`：author/committer `Alexandre Mutel <alexandre_mutel@live.com>`，2016-01-25；无 trailer，原始漏洞为 human-authored。
- `e0f646d...`：author/committer 同上，2017-11-03；无 trailer，失效 guard 也为 human-authored。
- `b5ac4bf...`：Dishan Sachin + Alexandre Mutel；无 AI marker。
- `f55280a...`：Alexandre Mutel，明确 Copilot co-author trailer；该 marker 只归因于不完整 array remediation。
- `8fdbd687...`：author/committer Alexandre Mutel；原始 commit object 没有 AI trailer。旧材料中“8fdbd687 itself carries a Copilot trailer”的说法与该对象不符。

因此可维持项目规则下的 `AI_INCOMPLETE_REMEDIATION`，但必须把“原始人类漏洞”“人类写的非终止 guard”“AI-assisted array remediation”“最终 closure”分成四个节点，不能把 Copilot marker 倒推到原始 parser 或 guard。

## 可复核命令

所有较重 Git 操作均以 `numactl --cpunodebind=1 --membind=1` 执行；clone 为非 shallow，一方 heads/tags 已重新 fetch，`git fsck --connectivity-only --no-dangling` 通过。

```sh
repo=.ai-slop/state/repos/scriban

git -C "$repo" rev-parse --is-shallow-repository
git -C "$repo" fetch --prune --tags origin '+refs/heads/*:refs/remotes/origin/*'
git -C "$repo" fsck --connectivity-only --no-dangling

git -C "$repo" blame --line-porcelain -L 772,840 \
  760dc21259f3da6a5adbd3148c260e25f1751706 \
  -- src/Scriban/Parsing/Parser.Expressions.cs
git -C "$repo" rev-list --parents -n 1 \
  46054810b50b03a6d19cd51886321cbbefa5d589

git -C "$repo" log --all --reverse -S '_isExpressionDepthLimitReached' \
  -- src/Scriban/Parsing/Parser.cs src/Scriban/Parsing/Parser.Expressions.cs
git -C "$repo" diff 5f039d2d2bb86e680a8c06d7cc739f26d7324705 \
  e0f646d899e60c8b88f01ebae6f998fc49116e09 -- \
  src/Scriban/Parsing/Parser.cs src/Scriban/Parsing/Parser.Expressions.cs \
  src/Scriban/Parsing/ParserOptions.cs

git -C "$repo" diff a6fe6074199e5c04f4d29dc8d8e652b24d33e3e4 \
  b5ac4bf30459fdc76964e3f751e16f7e96079ea7 -- \
  src/Scriban/Parsing/Parser.Expressions.cs src/Scriban/Parsing/ParserOptions.cs

git -C "$repo" diff 760dc21259f3da6a5adbd3148c260e25f1751706 \
  f55280a09575e577fcf7f5629007e0814594e3ac \
  -- src/Scriban/Parsing/Parser.Expressions.cs src/Scriban.Tests/TestParser.cs
git -C "$repo" show 8fdbd687bbe8f00085c4c4c5b2b3b8d529933949 \
  -- src/Scriban/Parsing/Parser.Expressions.cs src/Scriban.Tests/TestParser.cs

git -C "$repo" cat-file -p 46054810b50b03a6d19cd51886321cbbefa5d589
git -C "$repo" cat-file -p e0f646d899e60c8b88f01ebae6f998fc49116e09
git -C "$repo" cat-file -p b5ac4bf30459fdc76964e3f751e16f7e96079ea7
git -C "$repo" cat-file -p f55280a09575e577fcf7f5629007e0814594e3ac
git -C "$repo" cat-file -p 8fdbd687bbe8f00085c4c4c5b2b3b8d529933949
```

## 证据边界

本复核闭合了公开一方 Git 历史中的原始递归 BIC、失效 guard 首写、直接父边界、AI marker 边界和最终修复。没有运行会故意打爆进程栈的 PoC；该运行时结果由一方 advisory 和修复测试定义，而提交归因完全来自本地重新 fetch 后的一方 Git 对象。未修改 canonical ledger、发布 JSON 或站点代码。
