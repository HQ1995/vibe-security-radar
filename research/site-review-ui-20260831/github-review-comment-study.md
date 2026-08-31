# GitHub inline review comment 交互研究

**研究日期：** 2026-08-31  
**范围：** GitHub 拉取请求中的 inline review comment，用于指导本站所有 case 的代码证据展示，不只是 vLLM 一个 case。  
**来源约束：** 只使用 GitHub Docs、GitHub GraphQL/REST 文档、Primer 官方文档/源码，以及公开 GitHub PR 页面。

## 结论

用户要的不是“一个可折叠 hunk 旁边放一张说明卡”，而是 GitHub 的评审阅读模型：

1. 页面先展示少量必要 diff 上下文，关键代码行默认可见；远处上下文缩成可展开的分隔行。GitHub 的真实 PR diff DOM 使用独立的 `js-expandable-line` 表格行，提供 `Expand Up` / `Expand Down` / `Expand All` 控件；官方审查文档也确认 Files changed 是逐行审查的主视图。[公开 PR diff](https://github.com/primer/react/pull/8325/files?diff=unified&w=0) [GitHub Docs](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/reviewing-proposed-changes-in-a-pull-request)
2. 注释必须绑定到确切的 `path + side + line` 或者 `start_line..line`，并在该代码行之后横跨 diff 宽度展示，而不是只绑定到整个 hunk。GitHub REST API 将这些定位字段定义为 review comment 的正式数据模型；`position` 这种相对 hunk 的旧定位已被废弃。[GitHub REST API](https://docs.github.com/en/rest/pulls/comments?apiVersion=2022-11-28#create-a-review-comment-for-a-pull-request)
3. 只标注真正帮助理解漏洞机制的行：攻击者可控输入、缺失检查、危险 sink、状态/边界错误，以及 fix 中直接封闭该路径的检查。这是本项目的编辑准则，不是 GitHub 的产品规则；GitHub 只规定 line comment 用于讨论文件中某个具体实现。[GitHub 官方 comment 指南](https://docs.github.com/en/rest/guides/working-with-comments#pull-request-review-comments)
4. 本站是只读证据页，不应伪装成真实社交评审：不需要头像、作者、Reply、Resolve conversation 或反应按钮。安全可复刻的是“精确行锚点 + 代码下方的边框注释块 + 折叠上下文”，而不是把研究注释冒充成 GitHub 人类对话。GitHub 官方明确把 review conversation 定义为多条 comment 的 thread，并拥有 reply/resolve 权限状态。[GraphQL `PullRequestReviewThread`](https://docs.github.com/en/enterprise-cloud@latest/graphql/reference/objects#pullrequestreviewthread)

## 1. DOM 与视觉层级

### 1.1 可验证的页面结构

公开 PR diff 在 2026-08-31 的登出状态 HTML 中呈现为如下层级；这是当日 DOM 观察，不是 GitHub 承诺的稳定 API：

```text
file container
├─ file header / path / actions
└─ table.diff-table
   ├─ thead (screen-reader-only column names)
   └─ tbody
      ├─ tr.js-expandable-line
      │  ├─ td.blob-num-expandable (expand control)
      │  └─ td.blob-code-hunk (@@ range)
      ├─ tr (code line)
      │  ├─ old line-number cell
      │  ├─ new line-number cell
      │  └─ code cell
      └─ inline review thread row after its target line
```

真实 diff 中行号与代码是表格列，隐藏上下文是同一表格里的独立行；这使注释和它指向的代码在纵向阅读流中直接相邻。[公开 PR diff](https://github.com/primer/react/pull/8325/files?diff=unified&w=0)

GitHub Docs 的操作流程与此一致：用户 hover 具体代码行，点击行号旁的蓝色评论图标；也可选择连续多行后评论。[GitHub Docs](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/commenting-on-a-pull-request#adding-comments-to-a-pull-request)

### 1.2 评论块层级

真实公开 review thread 在 Conversation 视图的当日 DOM 包含：外层有 border 和 rounded radius 的 thread container，可折叠头，状态 Label，以及隐藏/显示的 thread body；内部 comment 是“头像 + 作者/时间/操作 + Markdown body”。[公开 Primer PR thread](https://github.com/primer/react/pull/8325#discussion_r3867919573)

对本站，应保留与阅读有关的两层即可：

```text
target diff line(s)
└─ research annotation
   ├─ short label: Root cause / Missing guard / Security fix
   └─ 1–3 sentences: what this code does and why it matters
```

不要展示没有真实语义的“reviewer”身份或“resolved”状态。

## 2. 注释与 diff 行的绑定

GitHub 的一级绑定键不是 hunk 文本，而是：

- `path`：文件路径；
- `commit_id` / `original_commit_id`：当前与原始 commit；
- `line` + `side`：单行或多行范围的结束行；
- `start_line` + `start_side`：多行范围的起始；
- `diff_hunk`：作为上下文，不替代行键。

[GitHub REST review-comments schema](https://docs.github.com/en/rest/pulls/comments?apiVersion=2022-11-28#get-a-review-comment-for-a-pull-request)

GraphQL thread 进一步保存 `path`, `line`, `originalLine`, `startLine`, `originalStartLine`, `diffSide`, `startDiffSide` 和 `subjectType`，并明确区分行级与文件级 thread。[GitHub GraphQL](https://docs.github.com/en/enterprise-cloud@latest/graphql/reference/objects#pullrequestreviewthread)

**对本项目的直接含义：** 所有 case 的注释数据都应有可重现的行锚点。只有文字搜索词或整个 hunk 的 `annotation` 不足以稳定地复刻 GitHub 模型；如果无法确认具体行，宁可不显示注释，不要用 UI 猜测。

## 3. 上下文折叠与默认展开

GitHub 的实际 diff 不是“全文默认折叠”，而是“变更 hunk 和少量上下文默认可见，远处未变更行被隐藏”。公开 PR DOM 中可观察到带 `data-left-range` / `data-right-range` 的 `Expand Up`, `Expand Down`, `Expand All` 控件。[公开 PR diff](https://github.com/primer/react/pull/8325/files?diff=unified&w=0)

本站应用同样的阅读原则，而不需要复制 GitHub 的每个按钮：

- 关键锦标行和直接相邻上下文默认展开；
- 每个锦标范围保留约 3 行上下文是合理的本站编辑默认值，但不应宣称这是 GitHub 的固定数字；
- 有多个距离较远的关键点时，展示多个小窗口，中间用 `Show N hidden lines` 一类分隔控件；
- 不把整个大 hunk 因为“有注释”而全部展开；
- 不让用户先展开整个 hunk 才能看到关键注释。

## 4. Outdated、resolved 和 thread

GitHub 把状态分开建模：`isOutdated` 表示新变更使该 thread 过时，`isResolved` 表示对话已被解决，`isCollapsed` 表示 thread 被折叠（resolved），并记录 `resolvedBy`。[GitHub GraphQL](https://docs.github.com/en/enterprise-cloud@latest/graphql/reference/objects#pullrequestreviewthread)

GitHub Docs 说明，点击 **Resolve conversation** 会折叠整个对话并标记 resolved；Files changed 顶部的 Conversations 菜单可区分 unresolved、resolved 和 outdated。[GitHub Docs](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/commenting-on-a-pull-request#resolving-conversations)

这些状态不适用于本站的静态研究注释：

- 我们的 annotation 不是等待作者回复的 review thread；
- 如果上游 commit 发生变化使行锚点失效，应在发布前重新定位或将该注释标记为 unresolved evidence，而不是在网站上显示 GitHub 式“Outdated”社交状态；
- 同一行有多条必要说明时可按研究逻辑排序，但不需要 Reply 线程 UI。

## 5. 颜色、间距、边框与字体

### 可安全复刻

- 使用浅绿表示 addition，浅红表示 deletion，蓝色系表示 hunk/展开控件。Primer 官方 light theme 参考值包括 addition line `#e6ffec`、addition number `#ccffd8`、deletion line `#ffebe9`、deletion number `#ffd7d5`，hunk number `rgba(84,174,255,0.4)`。实现时应优先使用 `diffBlob-*` token，而不是写死 hex。[Primer Theme Reference](https://primer.style/product/getting-started/react/theme-reference/#colors)
- 普通容器使用 1px 边框和 6px 中等圆角，这与 Primer 的 `--borderWidth-default` 和 `--borderRadius-default` 一致。[Primer size primitives](https://www.primer.style/product/primitives/size/#border)
- 代码用 Primer monospace stack，官方 code-block token 为 13px，line-height 1.5；注释正文可用 14px body medium，line-height 1.5。[Primer typography](https://primer.style/product/primitives/typography/)
- 注释应贴近所指代码。Primer 的 messaging 指南明确把“proximity”当作信息突出程度的一部分，并要求消息尽量靠近相关操作/内容。[Primer notification messaging](https://www.primer.style/product/ui-patterns/notification-messaging/#placement)

### 不能声称“精确复刻 GitHub”

- GitHub dotcom 的 diff/comment 组件不是公开 Primer 组件的完整、稳定 API；Primer 维护者曾明确表示 `blob-code` diff styles 是 GitHub 内部自定义样式。[Primer CSS discussion](https://github.com/primer/css/discussions/1772)
- 公开 GitHub HTML 中的 class 名、Turbo frame、自定义元素和具体 padding 随时可变，不应当作产品规格。[公开 Primer PR thread](https://github.com/primer/react/pull/8325#discussion_r3867919573)
- 因此可以说“采用 GitHub review 的信息架构”，不能说“像素级复刻 GitHub”，除非后续在多主题、多视口下进行当日截图对比。

## 6. 移动端退化

Primer 官方要求页面从 320px 宽开始不丢失信息或功能，不依赖 hover，触摸目标至少 24px，并建议尽量达到 44px。[Primer responsive](https://primer.style/product/getting-started/foundations/responsive)

Primer layout 把 `<768px` 定义为 narrow/单列范围，要求多列布局在小屏分解为不丢功能的移动视图。[Primer layout](https://primer.style/product/getting-started/foundations/layout/#responsive-foundations)

因此本站应：

- 始终保留“代码行 → 注释”的纵向顺序，不在移动端把注释变成侧栏；
- 代码区水平滚动，注释正文自然换行；
- 行号保留但缩小固定宽度，不删除注释锚点所需的行信息；
- 展开隐藏行的按钮必须可点击、可聚焦，不能只靠 hover 出现；
- AI change 和 Security fix 保持两个连续的纵向区段，不在窄屏并排两个 diff。

**证据边界：** GitHub 公开文档没有发布 dotcom inline review comment 在每个窄屏宽度下的精确 CSS/布局规格。上述移动方案是根据 Primer 官方 responsive 约束得出的实现要求，不应写成“GitHub 移动端就是这样”。

## 7. 适用于所有 case 的数据与发布要求

要在 246 个公开 case 中统一实现，每条关键注释至少应有：

```json
{
  "role": "candidate|fix",
  "path": "relative/file/path",
  "commit_sha": "full SHA",
  "side": "old|new",
  "start_line": 120,
  "end_line": 123,
  "kind": "attacker-control|missing-guard|dangerous-sink|state-error|security-fix",
  "body": "Short, human-readable explanation grounded in these exact lines."
}
```

这不是要为每行写注释。每个 case 只需选出能闭合“输入 → 缺陷 → 后果 → 修复”的最少关键点；如果一条注释不能改善这条因果链的理解，就不应存在。

发布时的最小门禁：

1. `path + commit_sha + side + start_line/end_line` 能唯一定位并与发布 diff 一致；
2. `body` 不是 commit title、hunk 标题或模板 fallback；
3. 每条注释都指向默认可见的行；
4. 无有效行锚点时不渲染注释，并在数据层记录 unresolved reason；
5. AI change 与 Security fix 的注释不串区，两者分别绑定自己的 commit/path/line。

## 可执行的 UI 验收标准

- 打开任意 case，不需先点击 hunk 标题即可看到关键代码和它下方的注释。
- 注释与其锦标行相邻，不在整个 hunk 顶部，不在独立右栏。
- 上下非关键代码默认收起，隐藏行数和展开操作明确。
- 没有行锦标的 hunk 不展示伪造的 case-level 注释。
- 注释只解释“这几行做了什么、为什么导致/修复漏洞”，不解释网站自己的 UI。
- 320px 宽仍能按顺序阅读行、注释和展开控件，不依赖 hover。

