# Audit protocol

怎么审一个 case 的规矩。核心就一条:**不机械扫描**——先把漏洞的成因和完整生命周期理解透彻,再判定 AI 角色。

## 每个 case 必做

1. **理解漏洞**:成因、触发路径、受影响版本、修复行为。理解不透彻不动手。
2. **BIC 拆到最小**:脆弱行的 first writer,必须是最小原子 commit;squash 拆到 PR constituents,记 `introducer_sha` + `decomposed_shas`。
3. **找 fix**:修复 commit 记 `fix_sha`/`direct_fix_sha`;没有修复就明确记 `unpatched`。
4. **incomplete fix 全链路**:原始引入 → 修复尝试 → 残余绕过 → 最终闭合(`ir_chain`),缺一环不结案。
5. **定 AI 角色**:只认**最小 BIC 上**的信号;squash 聚合的 Co-Authored-By 不算脆弱行信号(信号不在 BIC 上就降级)。
6. **研究记录写进账本**:`roundN_research` 里记 verdict / reasoning / flaw_origin / bug_semantics / ai_marker / 所有 sha,然后跑 `scripts/merge_funnel_lane.py` 及时更新总账。
7. **补全必要信息**:advisory identity(禁止 ALIAS 发布——按 仓库公告 → OSV commit 查询 → OSV package → NVD → websearch 挖真实 GHSA/CVE)、advisory 日期(禁 BIC 日期)。

## 禁止

- 模板词填充(`introduced_with_feature` / `ai` / `introducer`)
- 发布 `ALIAS-*` case
- 用 introducer commit 日期当 `published_at`
- 发布端去重(去重必须在账本级,`site_publication.publish=false`)

发布门禁由 `scripts/publish_tp_ledger.py` 强制(重复/日期/ir_chain/SHA/hunks/release),本文件不管代码细节。数据字段语义见 `docs/DATA-SCHEMA.md`,文件归属见 `docs/AGENT-OWNERSHIP.md`。
