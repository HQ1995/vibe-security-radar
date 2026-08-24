# Batch G：ChurchCRM Notes 对象级授权因果闭合

审计日期：2026-08-12（America/New_York）

## 结论

本批只提出 **2 个尚未整合的发布级 strict 组件**，并保留 **1 个负控**。它不改变 Batch 2 unified ledger 的 `strict/broad/widest=125/172/184`，也不改变 `integration_ready=false`。

| 行 | 判定 | Public identity | AI candidate | Exact closure | 发布见证 | 机制边界 |
|---|---|---|---|---|---|---|
| G01 | STRICT_CAUSAL，advisory-scope narrow | CVE-2026-58407 / GHSA-3J8Q-FWPJ-F8J5 的 VULN-02/03；CVE-2026-58410 / GHSA-JJCJ-H3CM-P7X7 仅 notes 重叠路径 | `b3edc22580116beb6bc8463d1876f2a7c9b96a28` | `83c19611701b96300872390071440151360dfb48` | candidate 在 `7.1.0`、`7.3.3`；closure 不在 `7.3.3`、在 `7.4.0` | 新建 person/family Notes CRUD，但只检查 Notes role，没有验证 attacker-controlled person/family ID 是否属于调用者作用域 |
| G02 | REJECT / FALSE_REFACTOR_PRESERVATION | CVE-2026-40480 / GHSA-5W59-32C8-933V | `6253c9ab1200a04c226e5f7d2a6ac726e354ca4f` | `5691b0dbc16f8bad3f33e162848189aa447a049c` + `28ea7a2965fc2fe30e150fadb1ae38a97f8225c2` | advisory `<=7.1.2`，fixed `7.2.0` | Copilot 重排 person route；parent 已有相同 `GET /person/{id}`、相同 `exportTo('JSON')` 和相同缺失对象授权 |
| G03 | STRICT_CAUSAL，advisory-scope narrow + release correction | CVE-2026-44548 / GHSA-JX5R-P82P-2P8M 仅 FundRaiserDelete 路径 | member `6ef78813e04987da217bbb081706715c1ecb19e9`，carrier `ede1bfb08633e6d1157744e99d176e258fc58aba` | carrier `f1c11f9fefa3d0fe37373f10a0c659087684c36d`（内部 members 新建 safe route 并删除 legacy endpoint） | vulnerable `7.1.0`–`7.4.0`；实际 fixed `7.4.3` | 新建从列表可达、收到 GET 即删除 fundraiser 的 endpoint；closure 改为 POST + session-wide CSRF middleware + role gates |

## G01：直接新建可利用 surface

`b3edc225…` 的 parent 中不存在 `src/api/routes/people/notes.php`。candidate 新建该文件并注册七个 Notes API；其中 person/family list 与 create 路由分别接收 `personId`、`familyId`，只挂 `NotesRoleAuthMiddleware` 以及负责加载实体的 `PersonMiddleware` / `FamilyMiddleware`。candidate 没有验证目标对象属于当前 EditSelf 用户，因此直接创建跨 person/family 读写 notes 的攻击面。提交正文明确包含 `Generated with Claude Code` 和 `Co-authored-by: Claude Sonnet 4.6`。

`83c19611…` 对同一路径实施精确反转：person notes 的 GET/POST 在读写前调用 `canEditPerson()`；`FamilyMiddleware` 在放行所有 family-scoped handler 前调用 `canViewFamily()` 并 fail closed。删除 candidate 会让这些新 Notes API 整体消失，满足 but-for；这不是对旧 route 的 blame 搬运。

两个 advisory 不能按 ID 或子标题膨胀计数。GHSA-3J8Q 的 VULN-02 与 VULN-03 分别列 person/family notes，GHSA-JJCJ 又覆盖 family notes、family profile 与 timeline。这里按保守下界把同一 AI 新建 Notes API 单元、同一缺失对象级授权不变量和同一 closure 合为 **一个组件**；对 GHSA-JJCJ 只归因 notes 重叠路径，不归因 candidate 之前已经存在的 family profile/timeline endpoints。四个 public IDs 是两份 advisory 的标识，不是四个组件。

## G02：AI blame 命中但因果不成立

`6253c9ab…` 是 `copilot-swe-agent[bot]` 的 middleware consolidation。它确实删掉并重新加入 person GET handler，但其 parent 已有：

```php
$group->get('', function (...) {
    $person = $request->getAttribute('person');
    return SlimUtils::renderStringJSON($response, $person->exportTo('JSON'));
});
```

candidate 后仍是同一 route、同一实体加载、同一完整 ORM serialization，且没有新增调用方或放宽 gate。`5691b0db…` 先加过宽的 EditRecords role gate，`28ea7a29…` 再用 `canEditPerson()` 完成对象级授权。回退 candidate 到 parent 并不会消除 CVE-2026-40480，因此即使 blame 和 AI metadata 都命中，也必须拒绝。

## G03：omnibus advisory 中只有新 FundRaiserDelete 路径成立

`6ef78813…` 的 parent 没有 `FundRaiserDelete.php`。该 Claude co-authored member 同时新增列表里的 GET delete 链接和 24 行 endpoint：读取 `$_GET['FundRaiserID']` 后立即调用 `FundRaiserQuery::findPk(...)->delete()`，没有 POST 或 CSRF 验证。其 `FundRaiserDelete.php` hunk 与发布 carrier `ede1bfb0…` 的 stable patch-id 均为 `40cd75d7…`，carrier 首次进入 `7.1.0`。删除 candidate 会同时移除 attacker-triggerable link 和 destructive GET sink，but-for 因果成立。

GHSA-JX5R 同时列 FundRaiserDelete、PropertyTypeDelete、NoteDelete；后两者是 candidate 之前多年的旧 endpoint，本报告不归因也不拆数。只把 FundRaiserDelete 子路径记作一个 narrow 组件。

一方 advisory 的版本字段存在可重放的错误：它写 `<=7.2.2 → 7.3.2`，但 upstream 根本没有 `7.3.2` tag，且 `7.3.3` 与 `7.4.0` 仍包含相同 GET-delete 文件。真实 closure 是 `f1c11f9f…`：删除 legacy endpoint，并在 `/fundraiser/{fundraiserId}/delete` 上只注册 POST；`src/fundraiser/index.php` 将所有 state-changing methods 包在 `CSRFMiddleware` 中，缺失/无效 token 以 403 fail closed，route 另有 ManageFundraisers 与 DeleteRecords gate。该 carrier 不在 `7.4.0`、在 `7.4.3`。因此这里明确校正为 `7.1.0–7.4.0 → 7.4.3`，禁止把 advisory 的错误 patched version 当 release proof。

## 一方证据与重放

- [GHSA-3J8Q-FWPJ-F8J5](https://github.com/ChurchCRM/CRM/security/advisories/GHSA-3j8q-fwpj-f8j5) 当前 `published`、未撤回，明确列出 VULN-02 person notes 与 VULN-03 family notes，范围 `<=7.3.3`、patched `7.4.0`。
- [GHSA-JJCJ-H3CM-P7X7](https://github.com/ChurchCRM/CRM/security/advisories/GHSA-jjcj-h3cm-p7x7) 当前 `published`、未撤回，明确复现 EditSelf 用户跨 family 读写 notes，范围 `7.3.3`、patched `7.4.0`。
- [GHSA-5W59-32C8-933V](https://github.com/ChurchCRM/CRM/security/advisories/GHSA-5w59-32c8-933v) 当前 `published`、未撤回，描述旧 person GET IDOR；它支持 fix 语义，不支持把后续 Copilot refactor 当 origin。
- [GHSA-JX5R-P82P-2P8M](https://github.com/ChurchCRM/CRM/security/advisories/GHSA-jx5r-p82p-2p8m) 当前 `published`、未撤回，明确列出 FundRaiserDelete 的 tokenless destructive GET；其 patched-version 元数据与实际 tag/source 冲突，已在 G03 校正。

```zsh
church=/home/hanqing/.cache/cve-analyzer/repos/churchcrm_crm

# Parent 中 Notes API 不存在；candidate 直接新建。
! git -C "$church" cat-file -e \
  b3edc22580116beb6bc8463d1876f2a7c9b96a28^:src/api/routes/people/notes.php
git -C "$church" diff b3edc225^ b3edc225 -- src/api/routes/people/notes.php

# Candidate-only released witness 与 exact closure。
git -C "$church" merge-base --is-ancestor b3edc225 7.1.0
git -C "$church" merge-base --is-ancestor b3edc225 7.3.3
! git -C "$church" merge-base --is-ancestor 83c19611 7.3.3
git -C "$church" merge-base --is-ancestor 83c19611 7.4.0

# 负控：parent 与 candidate 都已有同一 person GET/export sink。
git -C "$church" show 6253c9ab^:src/api/routes/people/people-person.php | \
  rg -n -C 8 "group->get\\('',|exportTo\\('JSON'\\)"
git -C "$church" show 6253c9ab:src/api/routes/people/people-person.php | \
  rg -n -C 8 "group->get\\('',|exportTo\\('JSON'\\)"

# G03：member/carrier 新建相同 destructive GET；实际 closure 到 7.4.3。
git -C "$church" diff 6ef78813^ 6ef78813 -- src/FundRaiserDelete.php | git patch-id --stable
git -C "$church" diff ede1bfb0^ ede1bfb0 -- src/FundRaiserDelete.php | git patch-id --stable
git -C "$church" show 7.4.0:src/FundRaiserDelete.php
! git -C "$church" merge-base --is-ancestor f1c11f9f 7.4.0
git -C "$church" merge-base --is-ancestor f1c11f9f 7.4.3
git -C "$church" show 7.4.3:src/fundraiser/index.php | rg -n -C 5 'CSRFMiddleware'
git -C "$church" show 7.4.3:src/fundraiser/routes/fundraiser.php | \
  rg -n -C 12 "post\('/\{fundraiserId\}/delete|isDeleteRecordsEnabled"
```

上述 G01/G03 public IDs 与 frozen strict ledger、Batch 2 unified ledger 均零命中；这只证明没有 ID 级重复，不替代下一轮 unified mechanism fingerprint 和独立 red-team。G01/G03 在进入 canonical ledger 前仍是 proposal，不能抬高总数或任何下界。
