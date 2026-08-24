# fp211 unseen three-gate remainder (exact 6)

Verdict first: **0 PASS proposals**, **6 NARROW**, 0 REJECT, 0 UNKNOWN, 0 BLOCKED. Assigned 6, reviewed 6, unreviewed 0. Conservation 6=6+0. Pool equation 12=6+6. packet_delta=0. Canonical strict count remains **84**. Publication and more-than-200 stay **HOLD**. Worker PASS is a proposal only; this packet emits none.

Selection was frozen before research in `selected.jsonl`. The fp211 NARROW pool with exactly three non-PASS gates has sixteen rows. Canonical84 already counts GHSA-8JPQ-5H99-FF5R and GHSA-W28W-GP39-M4P6. 2026-08-14 selected/cases packets already hold GHSA-7C3W-FXGH-FRC7 and GHSA-4PQR-V6C3-X77J. The remaining twelve sort by ordinal. `herdr-260814-ghsa200-fp211-unseen-threegate6a-grok46-low` takes the first six. This packet freezes the remaining exact six. No padding, no substitution, and no overlap with unseen-twogate5 or unseen-twogate8.

Frozen remainder, ordinal order:

1. ordinal 85 `strict-200-v3:alias-fdeaf38897f73c8d938cfa65` / GHSA-RXXP-482V-7MRH (identity+but_for+fix_reversal)
2. ordinal 87 `strict-200-v3:alias-8099a555171349d287af92d` / GHSA-H4RQ-P45C-642R (topology+but_for+fix_reversal)
3. ordinal 91 `strict-200-v3:alias-2788167921d685f8a3bb43a5` / GHSA-X2XQ-QHJF-5MVG (topology+but_for+fix_reversal)
4. ordinal 97 `strict-200-v3:alias-f0b371318e30448b9a250d8a` / GHSA-WXW3-Q3M9-C3JR (topology+but_for+fix_reversal)
5. ordinal 102 `strict-200-v3:alias-1c31c40c0a061d5194e8ba95` / GHSA-VW3V-WHVP-33V5 (topology+but_for+fix_reversal)
6. ordinal 199 `posthold:F18` / GHSA-2HFG-4FH4-QP7F (identity+ai_hunk+release)

Baseline is committed canonical84 `ca034f064fd696201c81baae7392c14f0d501d2b`, ledger sha256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`, strict count 84. Inherited fp211 PASS values are not proof. OSV/CVE alias routing is not identity. An AI squash or merge cannot receive a member hunk by trailer. Incomplete remediation requires an explicit AI security attempt and a same-boundary patch delta.

## NARROW (uncounted)

| ID | Repo | Unresolved gates | Minimal counterexample |
| --- | --- | --- | --- |
| GHSA-RXXP-482V-7MRH | openclaw/openclaw | but_for, fix_reversal | Parent already fetched remote media without maxBytes. Candidate 506bed5a is a Claude sticker call site of that helper. Closer 73d93dee is multi-channel. |
| GHSA-H4RQ-P45C-642R | rconfig/rconfig | identity, but_for, fix_reversal | Global GHSA is unreviewed and the repo advisory is 404. StoreUserRequest.php blob is unchanged by the Claude member. Closer 84822f40 allowlists the shared FormRequest. |
| GHSA-X2XQ-QHJF-5MVG | ddev/ddev | topology, but_for, fix_reversal, release | Member 93f80ea4 is not a tag ancestor. archive.go blobs are three-way unequal. Parent Unzip/TypeReg already Join without a dest prefix. |
| GHSA-WXW3-Q3M9-C3JR | better-auth/better-auth | topology, but_for, fix_reversal, release | Cursor member 3d3435b3 is in no named tag. Parent already matched /callback/:id on parseGenericState. npm gitHead is null. |
| GHSA-VW3V-WHVP-33V5 | significant-gravitas/autogpt | topology, but_for, fix_reversal, release | Member a75c1af2 is not a tag ancestor. Parent platform services already lacked logging: blocks. Closer 57a06f70 is a packed multi-GHSA DoS PR. |
| GHSA-2HFG-4FH4-QP7F | openclaw/openclaw | identity, ai_hunk, release | Subject is [AI-assisted] with a human co-author and no model trailer. Global GHSA aliases CVE-2026-53812 outside public_ids_keep. npm gitHead is null. |

## Per-case

### GHSA-RXXP-482V-7MRH (85, openclaw/openclaw) — NARROW

Identity PASS: published repository advisory names `openclaw/openclaw` and inbound media byte-limit misses across channels. Global reviewed GHSA aliases CVE-2026-32049. CVE aliases are not counting units.

AI-hunk PASS: atomic Claude Opus 4.5 commit `506bed5a` (one parent). Topology PASS: that commit is an ancestor of git tags `v2026.2.21`/`v2026.2.22` and of npm gitHeads `35a57bc9`/`70dd6a30`. No carrier.

But-for NARROW: parent `9daa8464` already called `fetchRemoteMedia` without `maxBytes` and applied the cap in `saveMediaBuffer`. The candidate adds a Telegram sticker call site of the same helper. The GHSA names multiple channels.

Fix-reversal NARROW: `73d93dee` is a multi-channel inbound-fetch cap (bluebubbles, msteams, zalo, discord, telegram), not a sticker-only reversal.

Release PASS: npm `2026.2.21-2` gitHead `35a57bc9` contains the candidate and not the closer; npm `2026.2.22` gitHead `70dd6a30` contains both. GitHub releases exist and are not drafts. npm gitHeads are not the git tag peels. Uniqueness PASS versus canonical84. Shared origin SHA with GHSA-XWCJ does not merge cases.

Not incomplete remediation: the candidate is a feature, not an explicit security attempt.

### GHSA-H4RQ-P45C-642R (87, rconfig/rconfig) — NARROW

Identity NARROW: global GHSA is `type=unreviewed`. Repository advisory 404. No first-party GHSA object maps the Users API role mechanism.

AI-hunk PASS on member `4b0938dd` (Claude Opus 4.8, one parent). Topology PASS: that member is an ancestor of annotated tag `core-8.2.3`, which peels to merge carrier `ebb39d59`. v1 `UserController.php` blob `a51f880a` equals the tag. The carrier is a two-parent merge with empty name-status. Authorship is not transferred onto the merge.

But-for NARROW: `StoreUserRequest.php` blob `bd685aac` is identical on parent and member. `role` remains `required` with no allowlist. The token Users controller is a 15-line subclass of the session Users controller.

Fix-reversal NARROW: `84822f40` allowlists `role` on that shared FormRequest, including the pre-existing session API.

Release PASS: `core-8.2.3` contains the member and not the closer; `core-8.2.8` contains the closer. GitHub releases exist and are not drafts. Session `UserController.php` blob `a3662afa` is listed in the parent tree but `git show` fails closed under `GIT_NO_LAZY_FETCH=1` (promisor object missing). Uniqueness PASS.

### GHSA-X2XQ-QHJF-5MVG (91, ddev/ddev) — NARROW

Identity PASS: published repository advisory names `ddev/ddev` and ZipSlip in `Untar` and `Unzip`, alias CVE-2026-32885.

AI-hunk PASS on member `93f80ea4` (Claude, one parent). Topology NARROW: the member is not an ancestor of squash carrier `5f988451` or of tags `v1.25.1`/`v1.25.2`. `archive.go` blobs are three-way unequal: member `850c6f5f`, carrier/`v1.25.1` `491dd68b`. The carrier is also Claude-marked. Do not transfer.

But-for NARROW: parent already `filepath.Join(dest, fname)` for Unzip and Untar TypeReg without dest prefix checks. The GHSA names both extractors and does not name TypeSymlink.

Fix-reversal NARROW: `05cbe299` adds HasPrefix checks for Untar, symlink targets, and Unzip together. Release NARROW when the counted commit is the member. GitHub `v1.25.1`/`v1.25.2` exist and are not drafts. Uniqueness PASS.

### GHSA-WXW3-Q3M9-C3JR (97, better-auth/better-auth) — NARROW

Identity PASS: published repository advisory names `better-auth/better-auth`. `cve_id` is null. The GHSA is cookie-backed OAuth state mismatch without PKCE.

AI-hunk PASS on member `3d3435b3` (Cursor, one parent). Topology NARROW: the member is not an ancestor of squash `0deaaa4e` or of `v1.6.0`/`v1.6.1`/`v1.6.2`. oauth-proxy blobs are three-way unequal: member `224bd605`, carrier `e0f2841f`, `v1.6.0` `e8577b6a`. Do not transfer.

But-for NARROW: parent already matched `/callback/:id` and already called `parseGenericState`. The member adds `/oauth2/callback/:providerId` on that same helper.

Fix-reversal NARROW: `9deb7936` verifies `oauthState` on cookie storage. That repairs the pre-existing helper. Release NARROW for the member. npm `better-auth` 1.6.0/1.6.1/1.6.2 `gitHead` is null. GitHub releases exist and are not drafts. Uniqueness PASS.

### GHSA-VW3V-WHVP-33V5 (102, significant-gravitas/autogpt) — NARROW

Identity PASS: published repository advisory names missing Docker log rotation on platform containers and aliases CVE-2025-32425. Global `/advisories` 404.

AI-hunk PASS on member `a75c1af2` (Claude, one parent). Topology NARROW: the member is not an ancestor of squash `f172b314` or of `autogpt-platform-beta-v0.6.30`/`v0.6.32`. compose blobs are three-way unequal: member `3da6115e`, carrier `46fa4087`, `v0.6.30` `bf3d17fc`. Do not transfer.

But-for NARROW: parent already ran the platform services with zero `logging:` blocks. Enabling frontend without json-file rotation does not originate unbounded logs on those siblings. The GHSA names platform containers, not a frontend-only hole.

Fix-reversal NARROW: `57a06f70` is packed multi-GHSA DoS PR 10798. Release NARROW for the member. GitHub releases exist and are not drafts. Uniqueness PASS.

### GHSA-2HFG-4FH4-QP7F (199, openclaw/openclaw) — NARROW

Identity NARROW: published repository advisory names browser act interaction SSRF residual and is GHSA-only. Global reviewed GHSA aliases CVE-2026-53812, which this row's `public_ids_keep` does not contain. Cross-bound identity is not counted. Conservation forbids adding the CVE.

AI-hunk NARROW: atomic commit `e0b8ddc1` has `[AI-assisted]` in the subject and `Co-authored-by: Devin Robison`. No model trailer. Topology PASS: that commit is an ancestor of `v2026.5.12` and `v2026.5.18`. No carrier.

But-for PASS under the incomplete-remediation patch-delta rule: the candidate is an explicit security rewrite of the pressKey/type(submit) navigation helper on `pw-tools-core.interactions.ts`, and closer `3d93174c` amends that same boundary to cover more act kinds. Parent already had a post-interaction check on pressKey and the three-phase helper on click/evaluate. Residual select/fill/evaluate is why the GHSA still exists. AI hunk is not proven, so the class is not countable.

Fix-reversal PASS on that later same-file closer. Release NARROW: git tags contain the candidate without the closer at `v2026.5.12` and the closer at `v2026.5.18`, but npm `2026.5.12`/`2026.5.18` `gitHead` is null, so registry bytes are not bound. GitHub releases exist and are not drafts. Uniqueness PASS.

## Claim boundary

This packet does not edit tracked files, canonical ledgers, publication data, or other worker directories. It does not commit or push. Worker PASS remains a proposal; this packet has zero PASS. packet_delta=0. start_count=84. current_leader_accepted_count=84. Publication stays HOLD. Greater-than-200 remains unsupported.

Status is **TERMINAL**. Expansion stopped. No further candidates.
