# Unreviewed residual-19 identity and patch-delta adjudication

## Verdict

Proposed admissions: **0 / 19**.

- The community-unreviewed prose and repository references match the named
  repository and mechanism for 17 rows. That descriptive match is not the
  frozen CONTRACT's `identity_gate`: every input object has
  `github_reviewed=false`, `affected=[]`, and no locally proved first-party
  package binding.
- Proposed `identity_gate`: **0 PASS, 16 UNKNOWN, 3 FAIL**. The hard failures
  are the duplicate OpenClaw identity and the two cross-bound Repomix rows.
- Exactly one reviewed duplicate was proved locally: unreviewed
  `GHSA-55RV-68Q5-WXMQ` is the same case as reviewed
  `GHSA-q2qc-744p-66r2`. Appsmith instead has an unresolved three-ID split.
- All 19 supplied `fix_ref` rows are **final closures**, not advisories covering
  a residual introduced by those fixes. Seventeen have an explicit
  Claude/Copilot coauthor or assistance marker. Appsmith and AFFiNE instead
  contain only CodeRabbit-generated release-note metadata, which is not code
  authorship evidence. There are 18 unique fix commits because the two Repomix
  rows share one SHA. Proposed `AI_INCOMPLETE_REMEDIATION`: **0**.
- Reviewed-tree absence is only negative local search evidence. It does not
  prove global semantic uniqueness, so no row receives
  `uniqueness_gate=PASS`: **1 FAIL, 18 UNKNOWN**.
- Released containment was not established for any attempted-remediation to
  later-closure chain. `release_gate` remains **UNKNOWN for all 19**.

## Frozen evidence and decision rules

- Contract:
  `/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md`,
  SHA-256
  `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
- Input:
  `/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unreviewed-residual-19.jsonl`,
  SHA-256
  `883904b47f2546d896ffe1b8ec0f3208b2eb6ecc4f14b4ee6816343c245bf100`.
- Advisory database (`ADB` below):
  `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database`,
  clean `origin/main` at
  `e6f87ed4d230d03c7f5b820f2961898b1590d1aa` (2026-08-15
  `Publish Advisories`). Every advisory blob below is read from that exact
  tree, not the checkout's older `HEAD`.
- Commit pool (`POOL` below):
  `/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>`. Commit IDs and
  parent-to-fix diffs are primary Git evidence from their named repository. No
  GitHub API or web lookup was used.

For each row I searched the entire `advisories/github-reviewed/` tree at the
frozen ADB ref by CVE alias, exact fix SHA, repository reference, and a
mechanism-specific term. An exact alias search found no reviewed match for any
of the 19 CVEs. Exact fix/mechanism search found only OpenClaw's reviewed
duplicate. Searches such as `render_tag_badges`, `/pubsub/subscribe/`,
`Net::CIDR::Lite`, `importModule()`, `misp_standard`, `CF-Connecting-IP`,
`SetPhotosShared`, `SQL query editor`, `POST /api/pack`,
`isValidRemoteValue`, `newline_len`, `CalendarDeleteEventController`,
`TicketDeleteController`, `ContactExportVCard`, `X509V3_EXT_d2i`,
`Users::getUser`, `Doc.Read permission`, and `scan_folder` had no reviewed hit
apart from OpenClaw's `sessionId resolution` term. This establishes only the
bounded local result recorded here.

`repo_mechanism_match=YES` below means that the community-unreviewed prose plus
its references names the repository/product and exact vulnerable invariant.
It does **not** mean `identity_gate=PASS`. Under the CONTRACT, an unreviewed
NVD-derived object with no affected package and no locally available
first-party advisory remains `UNKNOWN`. `FAIL` is reserved here for positive
counterevidence: an exact duplicate identity or a cross-bound repository.

The patch-delta question is narrower than “was an AI involved in a fix?” The
same advisory must cover a residual omitted by an AI-authored security
boundary, and a later same-boundary closure must amend it. In every row here,
the advisory and the AI-marked commit instead identify `fix_ref` itself as the
closure. An older incomplete fix, a related sibling path, or another issue in
the same squash does not transfer residual authorship onto `fix_ref`.

## Proposed gate matrix

The complete seven-gate counts recorded in `cases.jsonl` are:
`identity_gate` 0 PASS / 3 FAIL / 16 UNKNOWN; `ai_hunk_gate` 0 / 19 / 0;
`topology_gate` 17 / 0 / 2; `but_for_gate` 0 / 19 / 0;
`fix_reversal_gate` 19 / 0 / 0; `release_gate` 0 / 0 / 19; and
`uniqueness_gate` 0 / 1 / 18. The exact diffs affirmatively fail AI-hunk and
but-for causality and pass fix reversal. Topology passes for the 17 same-repo
rows and remains UNKNOWN for the two cross-bound fork rows.

The compact matrix below emphasizes the disputed identity, uniqueness,
patch-delta, and release dimensions. `release_gate=UNKNOWN` means no released
artifact was proved to contain an AI attempted remediation without a later
closure.

| Case | `repo_mechanism_match` | Reviewed duplicate at ADB ref | `identity_gate` | `uniqueness_gate` | Supplied commit role | Patch-delta gate | `release_gate` | Proposal |
|---|---|---|---|---|---|---|---|---|
| GHSA-8GV5-4Q99-4CXM | YES | None found | UNKNOWN | UNKNOWN | Final closure | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-XX2H-7258-XW7C | YES | None found | UNKNOWN | UNKNOWN | Final closure | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-55RV-68Q5-WXMQ | YES | **GHSA-q2qc-744p-66r2 (exact)** | **FAIL** for this duplicate ID | **FAIL** | Final closure | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY; duplicate identity |
| GHSA-5VF8-328M-MXJ5 | YES | None found | UNKNOWN | UNKNOWN | Final closure | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-FW62-67J2-4WMC | YES | None found | UNKNOWN | UNKNOWN | Final closure of an older residual | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-FRWX-J879-PMQV | YES | None found | UNKNOWN | UNKNOWN | Final closure | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-72FG-F46J-5GVP | YES | None found | UNKNOWN | UNKNOWN | Final closure | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-6649-8H33-MV2C | YES | None found | UNKNOWN | UNKNOWN | Final closure within a multi-fix commit | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-6J63-XFWQ-F8VJ | YES; exact public ID conflicted | None found; `GHSA-vvxf...` vs `GHSA-vjfq...` unresolved | UNKNOWN | UNKNOWN | Final closure | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY; ID HOLD |
| GHSA-5WJ3-M77Q-J278 | **CROSS_BOUND**: upstream affected repo, fork fix | None found | **FAIL** | UNKNOWN; overlaps GHSA-8WVR | Final closure in fork | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY; cross-bound identity |
| GHSA-8WVR-GQ96-HF34 | **CROSS_BOUND**: upstream affected repo, fork fix | None found | **FAIL** | UNKNOWN; subsumed by GHSA-5WJ3 prose | Final closure in fork | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY; cross-bound identity |
| GHSA-5WQV-8X52-77Q2 | YES | None found | UNKNOWN | UNKNOWN | Final closure of an older residual | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-Q2F8-HPWM-236J | YES | None found | UNKNOWN | UNKNOWN | Final closure within a multi-fix commit | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-2WG2-5V89-CGH7 | YES | None found | UNKNOWN | UNKNOWN | Final closure | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-8666-8WPQ-7C9Q | YES | None found | UNKNOWN | UNKNOWN | Final closure | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-8WQQ-45FP-2XMP | YES | None found | UNKNOWN | UNKNOWN | Final closure | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-HPHP-FMHR-5FQH | YES | None found | UNKNOWN | UNKNOWN | Final closure | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-M4GP-5XH5-XHQ4 | YES | None found | UNKNOWN | UNKNOWN | Final closure | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |
| GHSA-R6M9-HRQM-HX9H | YES | None found | UNKNOWN | UNKNOWN | Final closure within a multi-fix commit | FAIL | UNKNOWN | REJECT_AI_FIX_ONLY |

## Per-row evidence

### 1. GHSA-8GV5-4Q99-4CXM — Vulnerability-Lookup SSE account-state gate

- Advisory: `ADB/advisories/unreviewed/2026/08/GHSA-8gv5-4q99-4cxm/GHSA-8gv5-4q99-4cxm.json`,
  Git blob `f7ec20b9cbb225cd3ac7ef38d22651929b14945d`, alias
  `CVE-2026-73405`. It names Vulnerability-Lookup,
  `/pubsub/subscribe/<topic>`, `token_required`, and the missing
  `is_active` / `is_confirmed` checks; its only repository binding is the
  same-repo fix reference. Descriptive repo/mechanism match is YES; no
  reviewed alias, SHA, repo, or mechanism match was found. With no
  first-party reviewed advisory or affected package, `identity_gate=UNKNOWN`.
- Fix: `POOL/vulnerability-lookup__vulnerability-lookup`, commit
  `bef837242657acf680832be56b94428df130ed67`, parent
  `d29901655c50cf3c25737d9ea86180268df51b57`. The local parent-to-fix diff in
  `website/web/views/pubsub.py` adds exactly the two account-state rejection
  checks described by the advisory. That is direct final-closure evidence,
  not a later advisory amending a residual of this AI commit.

### 2. GHSA-XX2H-7258-XW7C — Vulnerability-Lookup reference-tag XSS

- Advisory: `ADB/advisories/unreviewed/2026/08/GHSA-xx2h-7258-xw7c/GHSA-xx2h-7258-xw7c.json`,
  blob `99e1ad09b0244f45b02c8e42004f24cd8eadd041`, alias
  `CVE-2026-73374`. It names Vulnerability-Lookup,
  `render_tag_badges`, `containers.cna.references[].tags[]`, raw interpolation,
  and `Markup`. Match is YES; no reviewed duplicate was found;
  `identity_gate=UNKNOWN`.
- Fix: `POOL/vulnerability-lookup__vulnerability-lookup`, commit
  `d29901655c50cf3c25737d9ea86180268df51b57`, parent
  `7d3e57531d8a18f04dd4313c6252943c6362c38f`. The local exact diff imports
  `markupsafe.escape()`, applies it to every tag before the `Markup` wrapper,
  and adds regression tests. Its immediate child
  `bef83724...` changes the unrelated SSE authorization path, not this XSS
  boundary. The supplied AI SHA is final closure only.

### 3. GHSA-55RV-68Q5-WXMQ — exact duplicate of reviewed OpenClaw GHSA

- Unreviewed advisory:
  `ADB/advisories/unreviewed/2026/04/GHSA-55rv-68q5-wxmq/GHSA-55rv-68q5-wxmq.json`,
  blob `b9cd9ae663bbcabc6a1256243046a5c87eb0ee83`, alias
  `CVE-2026-35636`. It directly references
  `GHSA-q2qc-744p-66r2`.
- Reviewed object:
  `ADB/advisories/github-reviewed/2026/03/GHSA-q2qc-744p-66r2/GHSA-q2qc-744p-66r2.json`,
  blob `f618a31d3b5bf175e754437fe922e4e548db1126`. It names package
  `openclaw`, the same `session_status` post-`sessionId` resolution visibility
  bypass, the same affected range beginning at `2026.3.11`, and the exact same
  fix `d9810811b6c3c9266d7580f00574e5e02f7663de`. The direct cross-reference,
  mechanism, range, and SHA prove semantic duplication even though the reviewed
  object has no CVE alias. The row ID's `identity_gate=FAIL` and
  `uniqueness_gate=FAIL`; the reviewed GHSA would pass its own identity gate.
- Fix diff: in
  `/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/openclaw`,
  parent `5e8cb22176e9235e224be0bc530699261eb60e53` to `d9810811...` changes
  `src/agents/tools/session-status-tool.ts` from testing the already-rewritten
  `requestedKeyRaw` to testing the pre-resolution `isExplicitAgentKey` flag.
  It is the closure named by both objects. Related predecessor and later
  `session_status` advisories are not authorship-transfer evidence for this
  row.

### 4. GHSA-5VF8-328M-MXJ5 — Net::CIDR::Lite Unicode/newline parsing

- Advisory: `ADB/advisories/unreviewed/2026/05/GHSA-5vf8-328m-mxj5/GHSA-5vf8-328m-mxj5.json`,
  blob `f89cbce66967504f8818eee681ce3e7ea33a892c`, alias
  `CVE-2026-45190`. It names Net::CIDR::Lite and the exact validator/parser
  mismatch for Unicode digits and trailing newlines. Match is YES; no reviewed
  alias, repository, fix-SHA, or mechanism match exists at the frozen ref;
  `identity_gate=UNKNOWN`.
- Fix: `POOL/stigtsp__Net-CIDR-Lite`, commit
  `ca9542adec87110556601d7ce48381ea8d13e692`, parent
  `9a0759afb56ec1a442d7cbb657ac07f6f3c29b17`. The local exact diff replaces
  Unicode-capable `\d` and newline-tolerant anchors with ASCII classes and
  absolute anchors. The advisory cites this SHA as the patch. No later
  same-boundary closure is identified, so this supplied AI commit is final
  closure.

### 5. GHSA-FW62-67J2-4WMC — Net::CIDR::Lite zero-padded masks

- Advisory: `ADB/advisories/unreviewed/2026/05/GHSA-fw62-67j2-4wmc/GHSA-fw62-67j2-4wmc.json`,
  blob `82a40b1f6c299850e1a24d81d6eab55f36297e7a`, alias
  `CVE-2026-45191`. It names Net::CIDR::Lite and zero-padded masks such as
  `/00` and `/01`. Match is YES; no reviewed duplicate was found;
  `identity_gate=UNKNOWN`.
- Fix: `POOL/stigtsp__Net-CIDR-Lite`, commit
  `24e2c439ec405e5256024b9acefd4f7008c5ed0c`, parent
  `990abf34e5d0f2908762771bd96749030e9f9902`. The local exact diff changes the
  mask grammar to require zero or a nonzero decimal prefix. Its primary body
  explicitly calls the bug an incomplete fix of
  `CVE-2021-47154`; the local ADB maps that older CVE to another unreviewed
  object and commit `23b6ff0590dc279521863a502e890ef19a5a76fc`, not to the supplied AI SHA.
  Thus `24e2c439...` is the later closure. Whether the 2021 attempt had any AI
  marker is not proved here and remains UNKNOWN; it cannot be transferred from
  the 2026 fixer.

### 6. GHSA-FRWX-J879-PMQV — MISP `importModule` write authorization

- Advisory: `ADB/advisories/unreviewed/2026/07/GHSA-frwx-j879-pmqv/GHSA-frwx-j879-pmqv.json`,
  blob `60bc503f638d8a5655d08f8c58484b86db6cbe20`, alias
  `CVE-2026-60124`. It names MISP, `EventsController::importModule()`, the
  `misp_standard` branch, and missing modification rights. Match is YES. The
  locally reviewed MISP-prefix records concern MISP-maltego or misp-modules and
  different mechanisms; exact mechanism and SHA searches are empty.
  `identity_gate=UNKNOWN`.
- Fix diff: in
  `/home/hanqing/.cache/ghsa200-worker-clones/redbase-odd/clones/misp`, commit
  `d0725fc34fda256cc57e5a8f0543cd541033e008`, parent
  `567d246cf716a19a8ec19d073da438c1b7c849cc`, adds
  `if (!$mayModify) { throw new ForbiddenException(...) }` immediately inside
  the `misp_standard` branch of `app/Controller/EventsController.php`. This is
  exactly the advisory's final closure.

### 7. GHSA-72FG-F46J-5GVP — HestiaCP unauthenticated proxy header trust

- Advisory: `ADB/advisories/unreviewed/2026/05/GHSA-72fg-f46j-5gvp/GHSA-72fg-f46j-5gvp.json`,
  blob `0b66125cfe56ed560bfa4d9ec9bdb59a4fc1d911`, alias
  `CVE-2026-43634`. It names HestiaCP, unauthenticated
  `CF-Connecting-IP` trust, and the fail2ban/IP-allowlist/audit effects; the
  references point to the same repository's issue, PR, and fix. Match is YES;
  no reviewed duplicate was found; `identity_gate=UNKNOWN`.
- Fix: `POOL/hestiacp__hestiacp`, commit
  `f381e294500f671cf12716c638afd0bfde901f88`, parent
  `29a0a712fa1e48aa80d89b560cc58bd1421749f2`. The local exact diff removes
  broad forwarded-header trust and permits `CF-Connecting-IP` only when
  `REMOTE_ADDR` validates as Cloudflare. No advisory-covered residual after
  this AI fix or later closure is present. Release containment stays UNKNOWN.

### 8. GHSA-6649-8H33-MV2C — LibrePhotos `SetPhotosShared` owner scope

- Advisory: `ADB/advisories/unreviewed/2026/06/GHSA-6649-8h33-mv2c/GHSA-6649-8h33-mv2c.json`,
  blob `952e12e37c9a5807c69f0b7215b2d492528a105c`, alias
  `CVE-2026-57943`. It names LibrePhotos, `SetPhotosShared`, manipulation of
  `shared_to`, and missing ownership validation. Same-repo issue, PR, commit,
  and release references give a descriptive match. No reviewed duplicate was
  found; the unreviewed/empty-affected identity remains UNKNOWN.
- Fix: `POOL/LibrePhotos__librephotos`, commit
  `325bd1f5fda71c6d56737aa09cfce0cb8106675a`, parent
  `989366be4cc91071832258a6b6846da7731669ae`. The local exact diff scopes the
  photo lookup used by both share and unshare branches to
  `owner=request.user`. The same commit fixes several other authorization
  bugs, but those sibling closures do not make this advisory a residual of the
  AI change. Supplied SHA role: final closure.

### 9. GHSA-6J63-XFWQ-F8VJ — Appsmith SQL autocomplete XSS, public-ID conflict

- Advisory: `ADB/advisories/unreviewed/2026/06/GHSA-6j63-xfwq-f8vj/GHSA-6j63-xfwq-f8vj.json`,
  blob `fd0eea8e4dafcd33a65f8283d43f92b944076eb2`, alias
  `CVE-2026-7299`. It names Appsmith, SQL autocomplete, database object names,
  and unsafe `innerHTML`; match is YES.
- Identity conflict: the unreviewed object references first-party
  `GHSA-vvxf-f8q9-86gh`, while the primary fix commit's subject, body, source
  comment, and link all name `GHSA-vjfq-fvfc-3vjw`. Neither ID exists anywhere
  in the frozen ADB reviewed tree. The reviewed Appsmith objects that do exist
  concern SQL injection, super-user creation, and origin validation, not this
  XSS. This packet cannot choose or merge the two absent IDs:
  `identity_gate=UNKNOWN`, `uniqueness_gate=UNKNOWN`.
- Fix diff: `POOL/appsmithorg__appsmith`, commit
  `99d69180919981ed9bc5484050d809a5bec68acc`, parent
  `a0d0c2fa996507f0b543c3d1c0532a5fd2963fb8`. In
  `app/client/src/components/editorComponents/CodeEditor/hintHelpers.ts` it
  replaces `LiElement.innerHTML = text` with `LiElement.textContent = text`;
  sibling autocomplete sinks are routed through a new text-only helper. That
  is final closure of the described sink, not an advisory-covered residual of
  this AI commit.

### 10. GHSA-5WJ3-M77Q-J278 — Repomix SSRF, cross-bound fork fix

- Advisory: `ADB/advisories/unreviewed/2026/07/GHSA-5wj3-m77q-j278/GHSA-5wj3-m77q-j278.json`,
  blob `4980cf265021f11179280b092031ea3a967327d3`, alias
  `CVE-2026-59702`. It names `/api/pack`, `git clone`, public/private network
  SSRF, and `file://` local access. The affected issue and repository links are
  `yamadashy/repomix`, while the only fix commit is in
  `CrazyForks/repomix`. Therefore the mechanism matches but the repository
  boundary does not: `repo_mechanism_match=CROSS_BOUND` and
  `identity_gate=FAIL` for this supplied row.
- No reviewed duplicate was found. However this broad description expressly
  includes the `file://`/local-filesystem behavior that is the whole of
  `GHSA-8WVR-GQ96-HF34`, and both use the same fix SHA. Separate uniqueness is
  not proved. Because the two CVEs/issues could have intended separately
  scoped network and filesystem cases, the conservative gate is UNKNOWN, not
  an invented PASS or an unconditional merge.
- Fix: `POOL/CrazyForks__repomix`, commit
  `c748b524f41225e7fc6f89ad0084520901a453cf`, parent
  `959319230117821ea7fbd2b03ea484849f60c6fd`. The local exact diff adds an
  HTTPS allowlist and private/reserved-host blocking immediately before the
  clone sink, explicitly closing upstream issues `#1703` and `#1704`. That is
  a final closure in the fork. Upstream carrier/topology and release
  containment are UNKNOWN. The message also acknowledges a bounded DNS-rebind
  TOCTOU, but neither input advisory covers that residual and no later closure
  is supplied.

### 11. GHSA-8WVR-GQ96-HF34 — Repomix `file://` local-repository read

- Advisory: `ADB/advisories/unreviewed/2026/07/GHSA-8wvr-gq96-hf34/GHSA-8wvr-gq96-hf34.json`,
  blob `90ee3f393766a84a745827030ed16d84813b290c`, alias
  `CVE-2026-59703`. It names `isValidRemoteValue`, the `file://` scheme, the
  clone endpoint, and reading local Git repositories. As above, the issue and
  package repository are upstream `yamadashy/repomix`, while the AI SHA is
  fork-only evidence from `CrazyForks/repomix`. `identity_gate=FAIL`.
- No reviewed duplicate was found, but the mechanism is a subset of the broad
  SSRF row and the exact fix is shared. `uniqueness_gate=UNKNOWN`; reviewed-tree
  absence cannot separate the two community records.
- The same commit `c748b524f41225e7fc6f89ad0084520901a453cf` is the final
  closure cited by this advisory. It is not evidence that the advisory covers
  a residual introduced by that commit.

### 12. GHSA-5WQV-8X52-77Q2 — YAML::Syck newline scan follow-on

- Advisory: `ADB/advisories/unreviewed/2026/07/GHSA-5wqv-8x52-77q2/GHSA-5wqv-8x52-77q2.json`,
  blob `b9b00a5367e4d2a190ecdfb4ad85aa5ce1a77439`, alias
  `CVE-2026-57077`. It names YAML::Syck, `newline_len` / `is_newline`, the
  block-scalar document-boundary over-read, and explicitly calls it an
  incomplete fix of `CVE-2025-11683`. Match is YES; neither current nor older
  CVE has a reviewed mechanism match at the frozen ref;
  `identity_gate=UNKNOWN`.
- Fix: `POOL/toddr__YAML-Syck`, commit
  `44c90a109ec3215ee7ce747bd11209835e123d8b`, parent
  `e786a13e71fc2f64c5e6ee87762424b62a9ed9d4`. The local exact diff adds
  explicit limits to `is_newline()` / `newline_len()`, updates every call site,
  and bounds the backward chomp walk. The advisory is a residual of an
  **older** attempted fix;
  the supplied AI SHA is the later closure. The older attempt's SHA and AI
  authorship are not locally established and remain UNKNOWN; authorship cannot
  be copied backward from the fixer.

### 13. GHSA-Q2F8-HPWM-236J — Prospero calendar-event delete IDOR

- Advisory: `ADB/advisories/unreviewed/2026/07/GHSA-q2f8-hpwm-236j/GHSA-q2f8-hpwm-236j.json`,
  blob `1b0096d7dc6b0d5da3e45d96977bdc00cba2481a`, alias
  `CVE-2026-59234`. It names Prospero Flow CRM,
  `CalendarDeleteEventController`, the GET delete route, and the missing owner
  scope. Match is YES; no reviewed duplicate was found;
  `identity_gate=UNKNOWN`.
- Fix: `POOL/Roskus__prospero-flow-crm`, commit
  `8c26eed4d80544c30e55448e12a8e999af6d2b70`, parent
  `7e86b0845b14887b101a4516020fedafbff23564`. The local exact diff replaces
  `Calendar::find($id)->delete()` with an `id` plus authenticated `user_id`
  query as part of a wider destructive-IDOR fix. That directly
  closes the advisory. Other delete controllers in the same commit are
  siblings, not evidence of an incomplete AI boundary.

### 14. GHSA-2WG2-5V89-CGH7 — Prospero ticket cross-tenant access

- Advisory: `ADB/advisories/unreviewed/2026/08/GHSA-2wg2-5v89-cgh7/GHSA-2wg2-5v89-cgh7.json`,
  blob `924a8803e5d9167e74f70f516c931b050adb75d6`, alias
  `CVE-2026-19539`. It names Prospero's ticket component and the unscoped read,
  save, and delete operations, including the wrong request type that bypassed
  delete authorization. Match is YES; no reviewed duplicate exists locally;
  `identity_gate=UNKNOWN`.
- Fix: `POOL/Roskus__prospero-flow-crm`, commit
  `b2b6ffdace0972ab62d1f7e8cdab0ed213bfc4a9`, parent
  `361566c1ddb01df16f2cff0aa836f04be174f3c4`. The local exact diff adds
  company-scoped lookups to ticket read/save/delete and restores
  `TicketDeleteRequest`. This is final closure, not a later amendment to an AI
  attempted remediation.

### 15. GHSA-8666-8WPQ-7C9Q — Prospero contact write/export IDOR

- Advisory: `ADB/advisories/unreviewed/2026/08/GHSA-8666-8wpq-7c9q/GHSA-8666-8wpq-7c9q.json`,
  blob `10a5c569cab35ce8aded5710e3dde3102a756225`, alias
  `CVE-2026-19433`. It names Prospero contact save and vCard export operations
  and their missing tenant scope. Match is YES; no reviewed duplicate was
  found; `identity_gate=UNKNOWN`.
- Fix diff: `POOL/Roskus__prospero-flow-crm`, commit
  `f16b4af2027b17bef7c604c92dbd86cf38082398`, parent
  `f36c2a115f4c28c82181f1798c01582ae953b932`. The local diff changes both
  contact repositories and both vCard controllers from unscoped `find` calls
  to `id + Auth::user()->company_id` queries. It is the exact final closure.

### 16. GHSA-8WQQ-45FP-2XMP — Crypt::OpenSSL::X509 NULL dereferences

- Advisory: `ADB/advisories/unreviewed/2026/07/GHSA-8wqq-45fp-2xmp/GHSA-8wqq-45fp-2xmp.json`,
  blob `3a2f1f734444323b24c9fa6ab9f237344ceb5c69`, alias
  `CVE-2026-58101`. It names Crypt::OpenSSL::X509,
  `X509V3_EXT_d2i`, the four helpers, and the two NULL shapes. Match is YES; no
  reviewed duplicate was found; `identity_gate=UNKNOWN`.
- Fix diff: `POOL/dsully__perl-crypt-openssl-x509`, commit
  `4c1e2370556097c253ae27abe9e1097ea377fbd2`, parent
  `757289bfce095455c104d4adfe9312e7b339620f`. `X509.xs` gains direct NULL
  guards for `basicC`, `ia5string`, `auth_att`, and `keyid_data`, including the
  optional `akid->keyid` case named by the advisory. This is final closure.

### 17. GHSA-HPHP-FMHR-5FQH — Leantime `getUser` credential disclosure

- Advisory: `ADB/advisories/unreviewed/2026/07/GHSA-hphp-fmhr-5fqh/GHSA-hphp-fmhr-5fqh.json`,
  blob `5bf828661e4aeb3fb457fab0bf153e78967578b2`, alias
  `CVE-2026-59712`. It names Leantime, JSON-RPC `Users::getUser`, arbitrary user
  IDs, and exposed hashes/TOTP/session material. Match is YES. The existing
  reviewed Leantime advisories concern unrelated HTML injection and older
  issues; no exact duplicate was found. `identity_gate=UNKNOWN`.
- Fix diff: `POOL/Leantime__leantime`, commit
  `4f2612d13e0e8a2093092a846b44506cf133b671`, parent
  `b6e7f1434b9e5d83bd76daea3dc0b21bdfe47171`. It adds
  `SENSITIVE_USER_FIELDS`, strips them before API-facing service returns, and
  moves internal consumers that need full rows to the repository. Review
  follow-ups are included in the same atomic commit; there is no later
  advisory-covered residual. Supplied role: final closure.

### 18. GHSA-M4GP-5XH5-XHQ4 — AFFiNE workspace history permission

- Advisory: `ADB/advisories/unreviewed/2026/07/GHSA-m4gp-5xh5-xhq4/GHSA-m4gp-5xh5-xhq4.json`,
  blob `b8e4a2f7f7f1f2d65d451fee75054f65d82a0abf`, alias
  `CVE-2026-59262`. It names AFFiNE, the GraphQL `histories` field, arbitrary
  document GUIDs, and missing `Doc.Read`. Match is YES; no reviewed duplicate
  was found; `identity_gate=UNKNOWN`.
- Fix: `POOL/toeverything__AFFiNE`, commit
  `1f0bcd01a37a522393fc1b288395e3a72a79ccad`, parent
  `5b7f83a6e3b41d06415fa8eb5c4eb767dcf12a39`. The local exact diff injects the
  current user and asserts `Doc.Read` before listing document histories. No
  later residual/closure is supplied; the commit's role is final closure.

### 19. GHSA-R6M9-HRQM-HX9H — InvokeAI unauthenticated `scan_folder`

- Advisory: `ADB/advisories/unreviewed/2026/07/GHSA-r6m9-hrqm-hx9h/GHSA-r6m9-hrqm-hx9h.json`,
  blob `ee971e39a8baa31ba1b0819115e8748dbb2af62e`, alias
  `CVE-2026-65012`. It names InvokeAI, `GET /api/v2/models/scan_folder`, the
  attacker-controlled path, and unauthenticated enumeration/status oracle.
  Same-repo issue, PR, commit, and release references give a descriptive
  match. Reviewed InvokeAI records at the frozen ref concern other endpoints
  and mechanisms. `identity_gate=UNKNOWN`.
- Fix: `POOL/invoke-ai__InvokeAI`, commit
  `d315b8967f548732912bd9b390853ed4af97d8cb`, parent
  `d498e26355f6adfdd8c7f39ea0927b75cdc4eada`. The local exact diff makes
  `scan_folder` require `AdminUserOrDefault` and normalizes path-failure
  responses; subsequent hunks harden other endpoints.
  The explicitly deferred binary-serving routes are untouched siblings, not
  this advisory's residual. The supplied AI commit is final closure only;
  release containment remains UNKNOWN.

## Diff-evidence boundary

Parent-to-fix diffs were locally replayed for all 19 rows (18 unique commits;
the Repomix rows share one SHA). Every functional delta removes, guards, or
scopes the advisory-named vulnerable operation. None adds a security boundary
that a later same-mechanism fix amends. This exact-diff evidence closes the
supplied SHA's role as final fix, but it does not invent first-party identity,
global uniqueness, or released attempted-remediation containment; those gates
remain UNKNOWN where stated above.

## Bottom line

The unreviewed sweep discovered AI-associated **fixes**, not new causal cases.
OpenClaw is already represented by a reviewed first-party GHSA; Repomix is
cross-bound and internally overlapping; Appsmith's first-party ID is
conflicted; the remaining community objects do not close CONTRACT identity.
None of the 19 advisories names a residual of its supplied AI fix followed by
a later same-boundary closure. The correct proposal is zero admissions and no
`uniqueness_gate=PASS` inferred from negative search.
