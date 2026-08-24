# Hostile red-team: GHSA-G353, GHSA-MFMP, GHSA-M649

**REJECT + two PASS_PROPOSAL.** Countable PASS remains 0 until leader admission. Packet delta 0. Canonical91 stays **91 HOLD**.

This is an independent hostile review of three hypothesized squash landings: G353 Feishu verification-token without encrypt-key on `5c2cb6c591e4b63c2df0549ad2202403256e2a96` / parent `49c60e9065d98a6848e62c717315eb91eeaa6038` / closer `7844bc89a1612800810617c823eb0c76ef945804`; MFMP GroupView OptionName HTML text and M649 tel/mailto attributes on shared squash `80a3e620a4aa046c2644937a5a2fa799a2e750d6` / parent `9166d9983afcc59df343cf19c7595351d6f750af` with closers `330d0d6a2e6995f017d5943bd3b4806d713b181c` and `ae2b73550452056cc45a65a4165340ae17c2c3e5`. nearclosed-l is routing only and is not evidence. Worker PASS is proposal only. This packet does not admit rows, does not rebuild canonical91, and does not support a greater-than-200 claim.

Conservation: assigned=3, reviewed=3, unreviewed=0. Equation `3=3+0`.

Identity is pinned as an offline normalized first-party advisory projection in cases.jsonl and result.json: exact GHSA id, repository, package ecosystem/name, vulnerable range, patched version, published/withdrawn state, first-party URL, retrieved timestamp, and SHA-256 of the canonical projection. Replay validates those fields and source URLs without network.

## GHSA-G353-MGV3-8PCJ REJECT

GitHub-reviewed GHSA-g353-mgv3-8pcj on openclaw/openclaw is published, not withdrawn, and aliases CVE-2026-32974. Repo `cve_id` is null; the global catalog carries the CVE. The advisory names Feishu webhook mode that accepted forged events when only `verificationToken` was configured without `encryptKey`, npm `openclaw` `<= 2026.3.11`, patched `2026.3.12`, closer `7844bc89`.

Identity, topology, and uniqueness pass. Member `b0c67ea0` is Claude-marked with the same `monitor.ts` blob as the squash and is not an ancestor of the squash or of the named tags. That is not transferred.

The hypothesized pairing fails the other four gates. Parent schema already had optional `encryptKey` and `verificationToken`. Parent `client.ts` already passed both into `Lark.EventDispatcher` (blob `3c308907`, identical on parent and squash; pickaxe hits earlier `5f6e1c19`). Parent `monitor.ts` logged webhook mode not implemented. The squash adds unconstrained `Lark.adaptDefault`. The advisory-named 2026.3.11 hole is the later-human token-without-encryptKey gate: unmarked `a23e0d51` requires `verificationToken` only; unmarked `f46bd2e0` splits `monitor.account.ts` / `monitor.transport.ts`, files the squash does not contain. `v2026.3.11` schema blob `4060e6e2` still lacks `requires channels.feishu.encryptKey`. `monitor.ts` blob `50241d36` is identical on `v2026.3.11` and `v2026.3.12`. Closer `7844bc89` adds schema/startup `encryptKey` require and does not touch transport. Later unmarked `496ca3a6` fail-closes transport signatures and is in `v2026.3.12` / npm `2026.3.12` gitHead `6472949f`, not in `v2026.3.11`. GHSA-xh72 names residual fail-open plus blank card-action tokens, closer `c8003f1b`, patched `2026.4.15`.

Pinned original-retrieval npm archive sha256 `4c6641bac62ce2ccb86d8df2d0252dc2a4769fe3ddca12c1f1ee1013ebd65dba` (`2026.3.11`) and `2ee324fc0d378deb13cf24be16a3996aec35e27f44d1a58ba9a1ded3afce3d37` (`2026.3.12`) stay in the case records. Replay does not fetch registries. Git peel schema/account on `v2026.3.11` require `verificationToken` only; `v2026.3.12` requires `encryptKey`. GitHub release `target_commitish` `main` is not containment.

G353 is distinct from Q447 (unbounded body, closer `3cbcba10`, already in `v2026.3.11`) and from XH72. Shared squash SHA is not duplication. The row is still REJECT at this scope because later humans author the released token-without-encryptKey path and `7844bc89` is not a full transport reversal of the named advisory.

Gates: identity PASS, ai_hunk FAIL, topology PASS, but_for FAIL, fix_reversal FAIL, release FAIL, uniqueness PASS.

## GHSA-MFMP-Q643-VJ39 PASS_PROPOSAL

Published repo advisory GHSA-mfmp-q643-vj39, not withdrawn; global catalog 404 is not a missing identity. Names GroupView OptionName HTML pills/dropdowns and GroupRoles option labels; affected `< 7.4.3`, patched `7.4.3`. No CVE alias.

Count squash `80a3e620` on its own Claude Sonnet 4.6 marker, `n_parents=1`. Member `0ea20d01` is Claude Opus 4.6 with a different GroupView.js blob and is not a tag ancestor. GroupRoles.js blob `62dfbce1` is identical on parent and squash; that named sibling is preexisting and out of scope. Parent GroupView.js has no `buildRolePills`. Squash adds unescaped `i18next.t(role.OptionName)` into `$pills.html` and cart/actions dropdowns. First-parent pickaxe for `buildRolePills` on `7.4.2` hits only the squash. Later Copilot `6b82eb3e` restyles tomselect maps; the unescaped pill concatenations remain in `7.4.2` blob `1cb473c5`. Closer `330d0d6a` (no AI trailer; `n_parents=1`) wraps `window.CRM.escapeHtml` on those GroupView sites and on GroupRoles.js. Members `3b8b4745` / `367dd18e` are not ancestors of the closer or of `7.4.3`. `7.4.3` GroupView.js blob `116f1bff` and GroupRoles.js blob `a1fdf716` equal the closer. Packagist `churchcrm/crm` 404; containment is git tags `7.4.2` / `7.4.3` peeling to `f54eea0f` / `dbdc6133` with `src/composer.json` name `churchcrm/crm` versions matching the tags. GitHub release draft/prerelease/target facts are pinned in result.json and are not live-queried.

Gates: all seven PASS at the scoped GroupView HTML-text contributor.

## GHSA-M649-24Q9-Q6R4 PASS_PROPOSAL

Published repo advisory GHSA-m649-24q9-q6r4, not withdrawn; global catalog 404. Names tel:/mailto:/data-name attribute XSS in GroupView.js; affected `7.5.1`, patched `7.6.0`. First-party text distinguishes GHSA-mfmp (HTML text, `escapeHtml`, 7.4.3) and states that encoder would not close these sinks.

Same counted squash `80a3e620`. Parent has zero `tel:` and zero `mailto:` hits. Parent CellPhone is default text. Parent Email is a span plus `title=`, not `mailto:`. Parent already has quoted `data-name` from `ede1bfb0` (also the counted HM7V carrier). First-parent pickaxe for `tel:` and `mailto:` on `7.5.1` hits the squash; `data-name` pickaxe hits `ede1bfb0`. Scoped count is the AI-added URL attributes. `dd9220a3` only adds `target=_blank` on mailto. `0c011a10` (Claude Opus 4.8) rewrites multi-recipient mailto menus, not the DataTable tel/mailto concatenations. `7.5.1` blob `ed5347f0` still has `href="tel:" + escaped`. Closer `ae2b7355` (no AI trailer; `n_parents=1`; also names HM7V and GHSA-6rgg) switches tel/mailto/data-name to `escapeAttribute`. Member `5631bb08` is not transferred. `7.6.0` blob `041a9794` equals the closer. No later first-parent GroupView.js rewrite between closer and `7.6.0`.

Gates: all seven PASS at the scoped tel/mailto contributor.

## Duplicate and uniqueness tests

MFMP and M649 are not duplicates: separate first-party GHSA objects, HTML text versus URL attributes, closers `330d0d6a` versus `ae2b7355`, patched `7.4.3` versus `7.6.0`. Shared origin squash is not duplication. Parent does not already contain `buildRolePills`, `tel:`, or `mailto:`. Parent does contain GroupRoles.js OptionName HTML and GroupView `data-name`; those siblings are scoped out.

M649 is distinct from counted HM7V (`churchcrm-shared-person-action-attribute-xss` on CRMJSOM.js `data-person_name`). First-party HM7V text says a fix to either file leaves the other exploitable. Shared closer `ae2b7355` is not duplication. Distinct from counted CWP8 login lockout.

G353, MFMP, and M649 are absent from canonical91 strict 91. Counted Feishu rows 8JPQ and J4XF are different mechanisms on `2267d58a`. Q447 and XH72 are uncounted distinct identities. CVE aliases are stored and not counted.

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical91. Publication and more-than-200 stay HOLD.
