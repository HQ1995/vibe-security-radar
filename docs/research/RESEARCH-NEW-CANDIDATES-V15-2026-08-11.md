# 新候选 V15 一手证据复核（2026-08-11）

## 结论

V15 冻结了 66 个 class、139 条 candidate/fix pair。DeepSeek 首轮仅作召回排序，提升 5 个 class 的 7 条 edge；严格重跑仍提升 2 条、阻塞 2 条。对这 5 个 class 做本地提交父状态、真实 diff、blame 与一方 advisory 机制复核后，结果为 **PASS 0、FAIL 5、NEEDS_REVIEW 0、BLOCKED 0**，严格唯一总数仍为 **98**。

其余 61 个模型 deferred class 没有被当作负例；它们仍保存在无损 inventory，后续 lane 可以换排序方法继续挖。

| class / repo | 状态 | 一手反证 |
|---|---|---|
| CVE-2026-32287 / antchfx/xpath | **FAIL** | Claude candidate `c92c3eb...` 只改 `build.go` 的 grouped `last()`。fix `afd4762...` 删除 `query.go::logicalQuery.Select()` 的循环体；该危险函数逐行 blame 到 2022 年人类 root `5da9b3e...`。模型把调用图邻近误当成 origin。 |
| CVE-2026-34235 / pjsip/pjproject | **FAIL** | advisory/fix 是 VP9 RTP unpacketizer 的 `desc_len += N_S * 4` 越界。两条 Claude candidates 分别改 Opus/SILK/Speex frame count 和 SIP subscription UAF；VP9 危险算术 blame 到 2022 年人类 `5ac9104514...`。 |
| CVE-2026-45799 / square/wire | **FAIL** | promoted candidate `bff93ef...` 只新增 Swift `google.protobuf.Struct` 类型，fix `47d5b0...`/`e4e56f...` 修 Kotlin `ProtoReader.skipGroup()`。另两候选只改 schema option/parser。两处危险 Kotlin 行分别来自 2019、2024 年人类提交。 |
| CVE-2026-34590 / gitroomhq/postiz-app | **FAIL** | Claude candidate `354b206...` 改 AppSumo service；fix `5ae4c950...` 在 `WebhooksDto.url` 加 `IsSafeWebhookUrl`。旧 `/webhooks` route 和只有 `@IsUrl()` 的字段由 2025 年人类 `fc11d8c14...` 建立。 |
| CVE-2026-32774 / Vulnogram | **FAIL** | Copilot `47d1464...` 是 client-side `SimpleHtml` autofix；fix `2f0e21b...` 在 server-side `routes/comments.js` 存储前 sanitize。`hypertext: text` 两个写入点从 2022 年人类 root `06fedea...` 起已存在。其余三条 autofix 与该 sink 无关。 |

## 证据与边界

- 冻结队列：`research/orchestrator-260811-atomic150/global-cross-file-v15/`。
- 模型路由：`global-cross-file-deepseek-v15/`；严格重跑：`global-cross-file-strict-deepseek-v15/`。
- 机器裁决：`global-cross-file-strict-v15/adjudications.json`。
- CVEList/GitHub Advisory Database 只提供 advisory 对象、机制和上游引用；最终判断来自本地 Git 的 parent→delta、真实 fix 与 blame。
- OSV 没有作为因果或 introduced 证据。

## 最小复现命令

```zsh
git -C /home/hanqing/.cache/cve-analyzer/repos/github.com_antchfx_xpath \
  blame -L 985,1000 afd4762^ -- query.go

git -C /home/hanqing/.cache/cve-analyzer/repos/pjsip_pjproject \
  blame -L 190,225 f4c7d082^ -- pjmedia/src/pjmedia-codec/vpx_packetizer.c

git -C /home/hanqing/.cache/cve-analyzer/repos/gitroomhq_postiz-app \
  blame 5ae4c950^ -- libraries/nestjs-libraries/src/dtos/webhooks/webhooks.dto.ts

git -C /home/hanqing/.cache/cve-analyzer/repos/github.com_vulnogram_vulnogram \
  blame 2f0e21b^ -- routes/comments.js
```

## 模型使用边界

首轮 66 个 packet 共 73 次物理调用，模型输出 7 条 promoted edge；严格重跑又把 Postiz/Vulnogram 降为 unlikely，并因 packet 截断把 Wire 标为 blocked。人工直接查看完整提交后确认 7 条 promoted edge 全是假边。模型票只说明优先检查哪里，不能替代一方机制和 Git 因果闭环。
