# Round11 disagreement re-research 综合报告

## 方法与范围

本报告只综合本目录 README 指定的 33 份 re-research 结果，未重研 case，未读取 primary、review、disagreement 原文、其他 case 数据或网络资料。每案仅从 `Decision` 与 `Corrections` 提取：对 memo 的判定、建议 primary verdict、建议 review verdict 和关键新证据。

范围校验：README 清单、物理 `wXXX.md` 文件和下表均为同一组 33 个唯一 ID，无缺失、无额外 case。所有 33 份均按规定顺序包含 11 个必需章节，Decision 首值均为 `AGREE` / `PARTIAL` / `DISAGREE` 之一。

## 总体统计

| 维度 | 结果 |
|---|---:|
| `AGREE` | 24 |
| `PARTIAL` | 2 |
| `DISAGREE` | 7 |
| 合计 | 33 |

建议 primary verdict histogram：

| Primary verdict | 数量 |
|---|---:|
| `NOT_AI` | 22 |
| `AI_ROOT_CAUSE` | 5 |
| `EVIDENCE_GAP` | 4 |
| `FALSE_POSITIVE` | 2 |
| 合计 | 33 |

建议 review verdict 为 `CORRECTION_REQUIRED` 24 案、`CONFIRMED` 7 案、`EVIDENCE_GAP` 2 案。

## 33 案综合表

| Case | 对 memo | 建议 primary | 建议 review | 关键新证据 / 修正 |
|---|---|---|---|---|
| [w002](w002.md) | `AGREE` | `AI_ROOT_CAUSE` | `CORRECTION_REQUIRED` | 原子 BIC 改为 `8a5ed7e62417441ed98b39481ac1a47510c1a9ef`，其对象自带 Claude Code 生成/共同作者标记；受影响下界改为 1.3.0，fix 仅能支持列表同步范围。 |
| [w006](w006.md) | `AGREE` | `AI_ROOT_CAUSE` | `CORRECTION_REQUIRED` | BIC 与 AI 归因不变；CNA 2.0.0 下界被 tag 包含关系反驳，loader 从 2.9.0、完整 MCP 链从 2.25.1 才有代码证明。 |
| [w007](w007.md) | `AGREE` | `FALSE_POSITIVE` | `CORRECTION_REQUIRED` | 宽松 CORS 存在，但没有敌意站点获取或自动携带受害者权限的 source-to-sink；因果字段应置空。 |
| [w008](w008.md) | `AGREE` | `FALSE_POSITIVE` | `CORRECTION_REQUIRED` | 所有可达 fallback 的 nonce 为 12 字节，AES-CTR 要求 16 字节；构造失败被捕获并 fail closed，不存在明文返回路径。 |
| [w010](w010.md) | `DISAGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | 三条路径的公开原子 first-write 均可分解且为人类作者；不再存在 memo 接受的 BIC/身份缺口。 |
| [w011](w011.md) | `AGREE` | `AI_ROOT_CAUSE` | `CORRECTION_REQUIRED` | AI-marked BIC 和 direct fix 不变；搜索本来就公开，撤销仍需所有权签名，绕过实际影响是未认证上传合法的自签名 bundle。 |
| [w019](w019.md) | `AGREE` | `AI_ROOT_CAUSE` | `CORRECTION_REQUIRED` | AI 归因必须限于 session-token early-return 构成项；聚合公告无单一 BIC，既有修复只是部分修复，dashboard/WS 仍有 unpatched gap。 |
| [w029](w029.md) | `AGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | BIC 父树缺失组件，`introducer_parent_absent` 应为 true；另有四个早期 affected release 由等价 squash landing 证实。 |
| [w078](w078.md) | `AGREE` | `AI_ROOT_CAUSE` | `CONFIRMED` | 因果链全部闭合；唯一实质错误是 PR 4180 实有 `merge_commit_sha`，PR member 与 landed BIC 的 stable patch-id 一致。 |
| [w088](w088.md) | `AGREE` | `NOT_AI` | `CONFIRMED` | create/update 端点有两个独立原子 BIC，两者均是 Thorsten Rinne 且无 AI 标记；父缺失布尔值需修正。 |
| [w115](w115.md) | `DISAGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | SVN copy history 回溯到 ZDRES-233 原子 r349422/r349421；另需分开 ZDRES-232 三条分支 BIC、多个 fix 与真正完整修复版本。 |
| [w122](w122.md) | `AGREE` | `EVIDENCE_GAP` | `EVIDENCE_GAP` | 本地 `allCustomerGroups` 生命周期可闭合，但无第一方证据将它唯一绑定到指定 CVE/GHSA；不能用条件性人类标记得出 `NOT_AI`。 |
| [w123](w123.md) | `DISAGREE` | `NOT_AI` | `CONFIRMED` | memo 把 Adobe Commerce 的 2.4.4-p14/p15 误当为 Magento Open Source 必需对象；产品线拆分后所谓 release gap 不成立。 |
| [w124](w124.md) | `DISAGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | Apache SVN r349422 直接引入原生反序列化路径，r349421 无此路径；原 primary 的 2024 Git 对象是不完整 mitigation，不是 BIC。 |
| [w133](w133.md) | `DISAGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | review 混合了旧的无界反序列化与新的 null-clazz/`acceptMatchers` 绕过；`691a9df5a0aff0dddeedc5181f6e5832ee90dcea` 是后一机制的原子 BIC，且人类作者闭合。 |
| [w136](w136.md) | `PARTIAL` | `NOT_AI` | `CORRECTION_REQUIRED` | memo 正确否定 2024 BIC，但过早接受了 origin gap；Apache SVN r349422/r349421 恢复了 first-write 和精确前驱。 |
| [w139](w139.md) | `DISAGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | 官方 source repo 而非 dist clone 保存两个独立 vulnerable path 的原子 BIC/父、PR history、fix 和 tags，因果门已闭合。 |
| [w153](w153.md) | `AGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | 父树缺失机制，布尔值应为 true；PR #234 有两个可见 member，但原子 BIC 和 `NOT_AI` 不变。 |
| [w165](w165.md) | `AGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | BIC 对象的同一具名 GitHub User 作者/提交者且无 AI 标记满足本 lane 规则；代码验证 affected 下界是 0.20.0，非 0。 |
| [w166](w166.md) | `AGREE` | `NOT_AI` | `CONFIRMED` | 因果与作者链已闭合，只缺 post-fix 4.5/5.0 tag；早期 repair 非独立完整 fix，需记录 completing commits。 |
| [w167](w167.md) | `DISAGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | 上游 LZ4 history 公开；真正 BIC 是 LZ4 `36104610053f34bbe033fad50263ce33cd4e9bcc`，而非 MessagePack-CSharp vendoring，上游 BIC 对象支持人类归因。 |
| [w180](w180.md) | `AGREE` | `EVIDENCE_GAP` | `CORRECTION_REQUIRED` | 公告指定的 v5.13.0 portal/PDF 两条 render path 已调用 `Purify::clean()`；无法闭合 unsanitized sink，但已发布 CVE 也不足以判 false positive。 |
| [w206](w206.md) | `AGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | 原公告的未认证/通用 RCE 叙事错误，但指定上传路由在特定配置下存在已认证路径逃逸写；因此不是 `FALSE_POSITIVE`。 |
| [w207](w207.md) | `AGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | squash landing 可由 PR #112 成员重建，原子 BIC 改为 `68ec1b65143352bc11dfd82bba5af56c6c2023c8`，父、decomposition 列表一并修正。 |
| [w227](w227.md) | `AGREE` | `NOT_AI` | `CONFIRMED` | BIC 对象的具名 repo owner 作者/提交者且无 AI/bot/generator 标记已满足规则；无 primary 字段需修正。 |
| [w252](w252.md) | `AGREE` | `NOT_AI` | `CONFIRMED` | 因果与作者链闭合；仅 0.75.9 公开 source/artifact membership 不可复现，另需区分 annotated tag 与 peeled commit。 |
| [w277](w277.md) | `AGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | `introducer_parent_absent` 应为 true，且 2023 BIC/父必须使用当时历史路径；所有者账号与 PR member 支持人类归因。 |
| [w289](w289.md) | `AGREE` | `EVIDENCE_GAP` | `EVIDENCE_GAP` | BIC 是未签名、无父、70,762 行 initial snapshot；即使映射到用户名，既无积极人类写作信号也无 AI 标记，归因必须 fail closed。 |
| [w312](w312.md) | `AGREE` | `EVIDENCE_GAP` | `CORRECTION_REQUIRED` | BIC 只有占位身份 `Your Name <you@example.com>`，且 GitHub 映射到 `invalid-email-address`，不能证明具名人类作者。 |
| [w326](w326.md) | `AGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | BIC 的具名人类作者/提交者支持 `NOT_AI`；但无 tag/release 证明“v.1.0”，且 PR member 为 loose object，不能以当前 `git log --all` 声称发现它。 |
| [w358](w358.md) | `AGREE` | `NOT_AI` | `CORRECTION_REQUIRED` | 公开对象已闭合因果与作者链；只需记录若干 vendor-only enterprise builds 的精确 source/ancestry membership 不可公开复现。 |
| [w387](w387.md) | `AGREE` | `NOT_AI` | `CONFIRMED` | 因果闭合，仅 v1.3.8/企业 v1.3.9 公开 release 对象缺口；v2.0.4 仅修 Jackson 3 path，Jackson 2 compatibility path 至 v2.0.5 才修。 |
| [w395](w395.md) | `PARTIAL` | `NOT_AI` | `CORRECTION_REQUIRED` | memo 正确否定 primary false positive，但 Gradio PR #2256 保存七个 pre-squash commits；首个 member 是人类作者原子 BIC，上游 direct fix 也可定位。 |

## 推翻 memo 的 7 案

- [w010](w010.md)：memo 接受 BIC/身份 gap；re-research 用三个公开、人类作者的路径级 BIC 关闭。
- [w115](w115.md)：memo 停在 Git import；SVN r349422/r349421 恢复 ZDRES-233 原子起源，并揭示多机制/多分支 fix 表达需重写。
- [w123](w123.md)：memo 的缺口来自混淆 Adobe Commerce 与 Magento Open Source 产品线；对本 repo case 不是必需对象。
- [w124](w124.md)：memo 接受 pre-Git 起源 gap；Apache SVN r349422/r349421 直接关闭 BIC/前驱链。
- [w133](w133.md)：memo 将旧 CVE 的无界反序列化与本 CVE 的 null-clazz/allowlist bypass 混为一个机制；分开后本案原子 BIC 成立。
- [w139](w139.md)：memo 因 dist clone 不完整而保留 gap；官方 source repo 保存两条路径的完整 BIC-to-fix lifecycle。
- [w167](w167.md)：memo 接受上游起源 gap；公开 LZ4 history 定位原子 BIC，排除下游 vendoring 对象。

## `PARTIAL` 的 2 案
- [w136](w136.md)：memo 正确否定 2024 BIC 与 import object，但错误接受 unresolved origin；SVN 历史可关闭。
- [w395](w395.md)：memo 正确否定 `FALSE_POSITIVE`，但错误认为 Gradio BIC 不可得；PR 保存 pre-squash members。

## 限制与交付边界

- 本报告是二级综合，只反映 33 份 re-research 的 `Decision` / `Corrections`；没有独立复核其原始证据或扩展结论。
- 未修改任何 primary 记录、independent-review 结果、disagreement memo 或 ledger；本文中的 verdict 均是建议值，尚未 merge 回 canonical artifacts。
