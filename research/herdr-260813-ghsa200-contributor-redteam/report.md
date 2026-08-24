# Contributor red-team: upgrade-a AI_NEW_SURFACE_CONTRIBUTOR non-PASS ordinals

**Status: `REDTEAM_COMPLETE`.** Assigned 39 upgrade-a rows whose `contribution_class` is `AI_NEW_SURFACE_CONTRIBUTOR` and whose worker verdict is not PASS. Independent first-party GHSA and Git replay under the user objective that AI material contribution / indirect causation is countable; whole-advisory sole origin is not required.

A KEEP here is a **proposal**, not leader admission. Worker PASS/KEEP remains a proposal.

**Contract bind:** leader `CONTRACT.md` sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. The revision clarifies `AI_INCOMPLETE_REMEDIATION` patch-delta only (rollback may reopen a broader old hole; count a residual bypass in an AI-added boundary that a later same-mechanism fix amends; untouched sibling holes do not count). This assignment has **zero** incomplete-remediation rows (all 39 are `AI_NEW_SURFACE_CONTRIBUTOR`). Contributor/direct but-for is unchanged. Verdicts unchanged: KEEP 7, NARROW 32.

Clones: `/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/`. Advisories: `/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/advisories/` plus `pages/`. Advisory-database revision `6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86` (2026-08-13T18:29:41Z). No `/tmp` clones. Sibling worker conclusions were not used as evidence.

| Ordinal | GHSA | Upgrade-a | Red-team |
|--------:|------|-----------|----------|
| 3 | GHSA-PWF7-47C3-MFHX | NARROW | **KEEP** |
| 8 | GHSA-J4XF-96QF-RX69 | NARROW | **KEEP** |
| 10 | GHSA-5WQV-FHMR-PJGH | NARROW | NARROW |
| 21 | GHSA-6C8G-7P36-R338 | NARROW | NARROW |
| 22 | GHSA-42M6-XH7C-6XM4 | NARROW | NARROW |
| 24 | GHSA-2M67-CXXQ-C3H8 | NARROW | NARROW |
| 25 | GHSA-PQGX-6WG3-GMVR | NARROW | NARROW |
| 28 | GHSA-QJ77-C3C8-9C3Q | NARROW | NARROW |
| 29 | GHSA-XMXX-7P24-H892 | NARROW | NARROW |
| 30 | GHSA-PQH8-P93P-2RX7 | NARROW | NARROW |
| 31 | GHSA-8JPQ-5H99-FF5R | NARROW | **KEEP** |
| 33 | GHSA-3CVX-236H-M9FJ | NARROW | NARROW |
| 34 | GHSA-Q9J6-XCVX-PX63 | NARROW | NARROW |
| 37 | GHSA-GC24-PX2R-5QMF | NARROW | NARROW |
| 40 | GHSA-HFF7-CCV5-52F8 | NARROW | NARROW |
| 47 | GHSA-Q447-RJ3R-2CGH | NARROW | NARROW |
| 52 | GHSA-7C3W-FXGH-FRC7 | NARROW | **KEEP** |
| 55 | GHSA-C339-W3CQ-2RJR | NARROW | NARROW |
| 60 | GHSA-Q6QF-4P5J-R25G | NARROW | NARROW |
| 62 | GHSA-JFV4-H8MC-JCP8 | NARROW | NARROW |
| 70 | GHSA-Q5PP-GVJG-H7V4 | NARROW | NARROW |
| 71 | GHSA-HHFF-FJ5F-QG48 | NARROW | NARROW |
| 77 | GHSA-W4H3-GPV2-82QC | BLOCKED | NARROW |
| 78 | GHSA-F7FH-QG34-X2XH | NARROW | NARROW |
| 79 | GHSA-VMW2-QWM8-X84C | BLOCKED | NARROW |
| 80 | GHSA-RQPP-RJJ8-7WV8 | BLOCKED | NARROW |
| 85 | GHSA-RXXP-482V-7MRH | BLOCKED | NARROW |
| 87 | GHSA-H4RQ-P45C-642R | BLOCKED | NARROW |
| 88 | GHSA-5J8P-5RRJ-8WJG | BLOCKED | NARROW |
| 91 | GHSA-X2XQ-QHJF-5MVG | BLOCKED | NARROW |
| 95 | GHSA-G5CG-8X5W-7JPM | BLOCKED | NARROW |
| 96 | GHSA-RQP8-Q22P-5J9Q | BLOCKED | **KEEP** |
| 97 | GHSA-WXW3-Q3M9-C3JR | BLOCKED | NARROW |
| 100 | GHSA-C4M7-2GWP-VW76 | BLOCKED | NARROW |
| 101 | GHSA-2JRP-274C-JHV3 | BLOCKED | NARROW |
| 102 | GHSA-VW3V-WHVP-33V5 | BLOCKED | NARROW |
| 103 | GHSA-2CM6-R77W-6G96 | BLOCKED | NARROW |
| 104 | GHSA-WXHM-2MQ7-7697 | NARROW | **KEEP** |
| 105 | GHSA-W28W-GP39-M4P6 | BLOCKED | **KEEP** |

## KEEP proposals (scoped contributor)

### Ordinal 3 - KEEP (proposal) - GHSA-PWF7-47C3-MFHX

First-party GHSA names `inputs.prek-version`, `extra_args`, and `extra-args` in the composite action. Parent `action.yaml` already interpolated `extra_args`. Copilot squash **carrier** `a7c5a005` (author Copilot, `#7`) adds unsanitized `${{ inputs.prek-version }}`. Member `070aae8e` is Copilot but is **not** an ancestor of `v1.0.5`/`v1.0.6`. File is `action.yaml`, not `action.yml`. `v1.0.5` still interpolates prek-version (blame `a7c5a005`). Fix `6b7c6ef5` / `v1.0.6` puts version in `env PREK_VERSION` and also validates extra_args. Scoped but-for: deleting the Copilot prek-version hunk removes that named surface; extra_args may remain.

### Ordinal 8 - KEEP (proposal) - GHSA-J4XF-96QF-RX69

First-party GHSA is npm `openclaw`, Feishu `allowFrom` display-name collision, fix `4ed87a66`, patched `>= 2026.2.22`. fp211/upgrade-a `repository: m1heng/clawdbot-feishu` is identity-wrong. Parent `src/feishu/access.ts` is ID-only. Claude-coauthored import carrier `2267d58a` adds `extensions/feishu/src/policy.ts` name matching. `v2026.2.21` still name-matches via `resolveAllowlistMatchSimple`. Fix `4ed87a66` enforces Feishu id-only in `v2026.2.22`. Member `4286755f` is not in OpenClaw history. Distinct from ordinal 31.

### Ordinal 31 - KEEP (proposal) - GHSA-8JPQ-5H99-FF5R

Advisory names `sendMediaFeishu` treating `mediaUrl` as local paths, npm `openclaw` `< 2026.2.14`. Same import carrier `2267d58a` **adds** `sendMediaFeishu`. Parent has no `sendMediaFeishu`. `v2026.2.13` has `isLocalPath`; fix `5b4121d6` in `v2026.2.14` routes through `loadWebMedia`. Leftover `createReadStream(string)` is upload helpers, not the named mediaUrl sink. Repository recovered as `openclaw/openclaw`.

### Ordinal 52 - KEEP (proposal) - GHSA-7C3W-FXGH-FRC7

Repo GHSA (global 404) names unencoded `job_id` including `/artifacts`, `/artifacts/tree`, `download_job_artifacts`, `get_job_artifact_file`. Claude `c156ac76` adds those artifact tools. Parent already had unencoded trace/play/retry. `v2.0.32` contains the artifacts URLs. Fix `e2a81a04` / `v2.1.32` uses `encodeGitLabPathSegment(jobId)` on artifacts and parent sinks. Scoped KEEP for **artifact** surfaces only.

### Ordinal 96 - KEEP (proposal) - GHSA-RQP8-Q22P-5J9Q

Advisory: Synology Chat multi-account collapse onto a shared webhook path; npm `openclaw` `< 2026.3.22`; fix `980940aa`. Claude carrier `03586e3d` **first adds** `extensions/synology-chat/` (parent has none). Default `webhookPath: accountOverride ?? channelCfg ?? "/webhook/synology"`. Blame on `v2026.2.22` is `03586e3d`. Fix is in `v2026.3.22`, not `v2026.2.22`. Member `cc048a29` is not in the OpenClaw object store.

### Ordinal 104 - KEEP (proposal) - GHSA-WXHM-2MQ7-7697

Advisory names `${file:...}` across PyPI/npm/crates/NuGet; npm `@prompty/core` `<= 2.0.0-beta.1` fixed `2.0.0-beta.2`. Copilot-coauthored `a0e61088` adds the TS `${file:}` loader; Python parent already had it. `a0e61088` is an ancestor of `typescript/2.0.0-beta.1`. Fix `88ac9948` is an ancestor of `typescript/2.0.0-beta.2`. Bare tags `2.0.0-beta.1` do not exist. Scoped KEEP for the **npm/@prompty/core** surface only. Distinct GHSA from 105.

### Ordinal 105 - KEEP (proposal) - GHSA-W28W-GP39-M4P6

Advisory names unrestricted Nunjucks member access in `@prompty/core`, patched `2.0.0-beta.5`. Same Copilot-coauthored `a0e61088` adds `new nunjucks.Environment(null, ...)`. `typescript/2.0.0-beta.1` still has that Environment. GHSA-cited merge `047756f4` is **not** an ancestor of `typescript/2.0.0-beta.5`, but `e4a0ebf4` (`fix(typescript): restrict Nunjucks template execution`) is an ancestor of both that merge and `typescript/2.0.0-beta.5`. Scoped KEEP for the TypeScript v2 Nunjucks renderer; the advisory's separate `<=0.1.4` line is out of scope.

## NARROW (independent; upgrade-a BLOCKED rows recovered)

No remaining BLOCKED: every row has a first-party GHSA object (global, advisory-database, or repo security-advisory API). Identity recovery does not by itself produce KEEP.

- **10 GHSA-5WQV-FHMR-PJGH** (`nesquena/hermes-webui`): Advisory does not explicitly cover the AI state.db surface. Parent already loaded foreign session transcripts. Mere coexistence with the named /api/session IDOR.
- **21 GHSA-6C8G-7P36-R338** (`adamhathcock/sharpcompress`): Old-bug-preserving refactor / same callers moved into traits. Deleting the AI delta does not remove the named directory-entry ZipSlip.
- **22 GHSA-42M6-XH7C-6XM4** (`steipete/codexbar`): Mere coexistence with a parent sink. AI hunks do not add the named credential-forwarding transport.
- **24 GHSA-2M67-CXXQ-C3H8** (`qhkm/zeptoclaw`): New I/O site of a parent class. Advisory does not uniquely name pdf_read. Count as coexistence, not a scoped named surface.
- **25 GHSA-PQGX-6WG3-GMVR** (`kromitgmbh/titra`): Risk-reducing incomplete hardening / engine swap, not origin of the named unsanitized timeEntryRule. Parent already executed the rule.
- **28 GHSA-QJ77-C3C8-9C3Q** (`openclaw/openclaw`): Not a demonstrated new named cmd.exe parser surface. Member missing; do not transfer authorship.
- **29 GHSA-XMXX-7P24-H892** (`openclaw/openclaw`): New route coexistence with parent captured-auth. Same SHA as ordinal 40 (Tailscale HTTP), different GHSA.
- **30 GHSA-PQH8-P93P-2RX7** (`dynatrace-oss/dynatrace-mcp`): Class coexistence with parent DQL interpolation. Git tags are npm-style 1.2.0/2.1.1, not v*.
- **33 GHSA-3CVX-236H-M9FJ** (`openclaw/openclaw`): AI hunk is not the named allowInsecureAuth surface. Same SHA as ordinal 80 (WS scopes).
- **34 GHSA-Q9J6-XCVX-PX63** (`coollabsio/coolify`): New action coexistence with the named GetLogs sink. Identity recovered via repo GHSA (global 404).
- **37 GHSA-GC24-PX2R-5QMF** (`maziggy/bambuddy`): Advisory does not uniquely name that debug sink. Product-wide missing auth pre-exists.
- **40 GHSA-HFF7-CCV5-52F8** (`openclaw/openclaw`): New call site of a parent sink. Same SHA as ordinal 29, different GHSA.
- **47 GHSA-Q447-RJ3R-2CGH** (`openclaw/openclaw`): Sibling channel bodies pre-exist. New Feishu body is coexistence with a product-wide named class.
- **55 GHSA-C339-W3CQ-2RJR** (`coollabsio/coolify`): Chain-node is weak versus the named isInstanceAdmin gate. Identity recovered via repo GHSA.
- **60 GHSA-Q6QF-4P5J-R25G** (`openclaw/openclaw`): Reachability of a parent missing workspaceOnly invariant, not a new named origin.
- **62 GHSA-JFV4-H8MC-JCP8** (`openclaw/openclaw`): New sweeper coexistence with parent pkill. Advisory names unvalidated PID kill generally.
- **70 GHSA-Q5PP-GVJG-H7V4** (`microsoft/apm`): New call site of a parent helper. Advisory explicitly names .apm paths, not .claude/agents.
- **71 GHSA-HHFF-FJ5F-QG48** (`openclaw/openclaw`): Reachability of a parent ungated preflight, not origin of missing member authorization.
- **77 GHSA-W4H3-GPV2-82QC** (`openclaw/openclaw`): New caller of a shared loader. Identity recovered; mechanism still coexistence. Same SHA as ordinal 60.
- **78 GHSA-F7FH-QG34-X2XH** (`openclaw/openclaw`): Identity mismatch with the named /json/version hop. Direct ws is a different surface.
- **79 GHSA-VMW2-QWM8-X84C** (`jasperfx/marten`): New API of a parent SQL fragment. Advisory names the regConfig parameter class that pre-existed. Identity recovered (upgrade-a BLOCKED).
- **80 GHSA-RQPP-RJJ8-7WV8** (`openclaw/openclaw`): AI hunk is not the named WS scope-binding origin. Same SHA as ordinal 33. Identity recovered; still NARROW on mechanism.
- **85 GHSA-RXXP-482V-7MRH** (`openclaw/openclaw`): New fetch site of a shared unbounded-media helper. Identity recovered; mechanism still coexistence.
- **87 GHSA-H4RQ-P45C-642R** (`rconfig/rconfig`): Same request class moved to a new Users API. Parent session API already used the unvalidated FormRequest. Identity recovered.
- **88 GHSA-5J8P-5RRJ-8WJG** (`hanxi/xiaomusic`): Advisory PoC names parent /music, not /music/temp. Identity recovered; still NARROW.
- **91 GHSA-X2XQ-QHJF-5MVG** (`ddev/ddev`): Old-bug-preserving expansion of the same extract sink. Identity recovered; still NARROW.
- **95 GHSA-G5CG-8X5W-7JPM** (`openclaw/openclaw`): Heartbeat coexistence with a pre-existing exec-event reason. Identity recovered; upgrade-a BLOCKED.
- **97 GHSA-WXW3-Q3M9-C3JR** (`better-auth/better-auth`): AI matcher never shipped in a named tag. Identity recovered; still NARROW.
- **100 GHSA-C4M7-2GWP-VW76** (`q00/ouroboros`): CLI_PATH selector is not the later named project-.env load. Identity recovered; still NARROW.
- **101 GHSA-2JRP-274C-JHV3** (`pydantic/pydantic-ai`): New caller of shared download_item SSRF. Identity recovered; still NARROW.
- **102 GHSA-VW3V-WHVP-33V5** (`significant-gravitas/autogpt`): Sibling services already unbounded. Identity recovered via repo GHSA (global 404).
- **103 GHSA-2CM6-R77W-6G96** (`mlflow/mlflow`): New handler of a parent unvalidated trace class. Release wording NARROW versus GHSA 3.14.0 patched claim.

## Shared SHAs (uniqueness still PASS)

- `2267d58a`: ordinals 8 (Feishu senderName) and 31 (sendMediaFeishu)
- `f4b03599`: ordinals 29 (`/v1/responses` SecretRef) and 40 (Tailscale HTTP)
- `079af0d0`: ordinals 33 (token device-skip) and 80 (WS scopes)
- `8d74578c`: ordinals 60 (image workspaceOnly) and 77 (native media UNC)
- `a0e61088`: ordinals 104 (`${file:}`) and 105 (Nunjucks)

## Clone HEADs

| Repo | HEAD | Date |
|------|------|------|
| apm | `3aa0365540e3d9ef4685740cea6a09094ff35377` | 2026-08-06T08:09:25+00:00 |
| autogpt | `9c8bb5550f446ba5d3046b78896578742495b3cf` | 2026-08-12T22:14:20-05:00 |
| bambuddy | `a28bdc54785855b91a5684689c252bae61328e5e` | 2026-08-08T14:12:35+02:00 |
| better-auth | `2ad2928f967afa9f9858caecd01466ecb8686982` | 2026-08-13T18:21:53+00:00 |
| clawdbot-feishu | `b07885b756accb6756ddf696b60972a413317287` | 2026-03-29T23:07:33+08:00 |
| codexbar | `cc8da27cec92029a6435bfee4a703a719290234e` | 2026-07-20T19:41:45-07:00 |
| coolify | `098d3d4c253a5a79aa8d166854a1b0a202077259` | 2026-02-15T23:57:13+01:00 |
| ddev | `9630417dbf41f0e4f24375a70698782950632c9a` | 2026-08-13T14:34:17-06:00 |
| dynatrace-mcp | `2df7089fc07a88660575a9f476f7b15a29da5a82` | 2026-07-24T11:38:07+02:00 |
| gitlab-mcp | `926d42c8780cb9ec0cf3b5e187575bc3db205ff0` | 2026-08-03T13:36:16+09:00 |
| hermes-webui | `07118df53c8db0c7fc31e8d244367871526c6347` | 2026-08-13T18:21:14+00:00 |
| marten | `d3a536e8265f58b01cb27c64ed3bd06ceda845cd` | 2026-08-11T14:56:26-05:00 |
| mlflow | `ffa0e39ea07f3294c158d058833e16630e9d24f7` | 2026-08-14T00:23:49+08:00 |
| openclaw | `faa62024123c2a7abbc61de44613c4b11ba61a5d` | 2026-08-13T13:17:36-07:00 |
| ouroboros | `fc774f7b962964f8ed7e559e1c4618f4699a65f7` | 2026-08-14T02:06:04+09:00 |
| prek-action | `f4730629a3c8729a30e11c9747f950f38f388390` | 2026-02-15T10:01:08+08:00 |
| prompty | `c4e7bd4939d3c3622361fcd5c63237691fee79f5` | 2026-08-04T05:37:09+00:00 |
| pydantic-ai | `1e8f040c27a585530285857f1629e84e50d60669` | 2026-08-13T15:47:24-05:00 |
| rconfig | `e82824b0eaddc8ec4f97ca1c6a14feba9b58f2b6` | 2026-08-13T18:08:25+01:00 |
| sharpcompress | `6062623dd8856b01d3afa18831bd5cfe1a58130f` | 2026-07-25T17:27:43+01:00 |
| titra | `dc17abce5fd88c8be918b5b24916a9b77db51566` | 2026-06-19T11:57:36+00:00 |
| xiaomusic | `e159329b3fabff97a9a6cafa9e149eda4d31b3b6` | 2026-06-09T05:24:33+00:00 |
| zeptoclaw | `478028ac29ba42799b5816f4bc2d83f5aa0d2561` | 2026-03-07T19:18:44+08:00 |

Assigned ordinals asserted: [3, 8, 10, 21, 22, 24, 25, 28, 29, 30, 31, 33, 34, 37, 40, 47, 52, 55, 60, 62, 70, 71, 77, 78, 79, 80, 85, 87, 88, 91, 95, 96, 97, 100, 101, 102, 103, 104, 105].

