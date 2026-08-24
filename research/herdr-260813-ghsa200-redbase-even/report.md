# Red-team: fp211 released-admitted even ordinals

**Status: `REDTEAM_COMPLETE`.** Filter: `counting.fp211_released_publication_admitted == true` and `fp211_adjudication.ordinal % 2 == 0`. Asserted 26 ordinals: 2, 6, 12, 14, 18, 26, 32, 42, 44, 46, 54, 58, 64, 66, 76, 106, 112, 118, 148, 160, 162, 164, 166, 176, 182, 210. Ledger labels were hypotheses. Public id is the unique `GHSA-*` value. KEEP here is a proposal only.

Clones and advisory JSON live under `/home/hanqing/.cache/ghsa200-worker-clones/redbase-even/`. No canonical edits.

| Ordinal | GHSA | Red-team |
|--------:|------|----------|
| 2 | GHSA-VVFR-G83F-8QCV | **KEEP** |
| 6 | GHSA-GW85-XP4Q-5GP9 | **KEEP** |
| 12 | GHSA-GH4H-34GR-87R7 | **KEEP** |
| 14 | GHSA-83XP-526H-J3WW | **KEEP** |
| 18 | GHSA-FPMV-5WGW-QHHR | **KEEP** |
| 26 | GHSA-C4HM-4H84-2CF3 | **KEEP** |
| 32 | GHSA-Q6QC-XP4Q-RJQ5 | **KEEP** |
| 42 | GHSA-VJ3G-5PX3-GR46 | **KEEP** |
| 44 | GHSA-7F6V-3GX7-27Q8 | **NARROW** |
| 46 | GHSA-68V4-HMWV-F43H | **KEEP** |
| 54 | GHSA-RV2Q-F2H5-6XMG | **KEEP** |
| 58 | GHSA-X22M-J5QQ-J49M | **KEEP** |
| 64 | GHSA-6MWV-4MRM-5P3M | **KEEP** |
| 66 | GHSA-877V-W3F5-3PCQ | **KEEP** |
| 76 | GHSA-QPMQ-6WJC-W28Q | **KEEP** |
| 106 | GHSA-C4GH-RV8H-Q9VW | **KEEP** |
| 112 | GHSA-HC36-C89J-5F4J | **KEEP** |
| 118 | GHSA-G8P2-7WF7-98MQ | **NARROW** |
| 148 | GHSA-4FXP-2M36-QV64 | **UNKNOWN** |
| 160 | GHSA-7P8R-X3MC-P8W7 | **KEEP** |
| 162 | GHSA-Q9PG-JJ6X-J9P6 | **KEEP** |
| 164 | GHSA-5RV5-XJ5J-3484 | **KEEP** |
| 166 | GHSA-8WC8-HF36-MJH9 | **KEEP** |
| 176 | GHSA-JM78-9FVV-MHGR | **KEEP** |
| 182 | GHSA-CWP8-RM8G-Q5C9 | **KEEP** |
| 210 | GHSA-PFVM-W89X-94JW | **NARROW** |

Counts: KEEP 22, NARROW 3, UNKNOWN 1, REJECT 0, BLOCKED 0.

## Method

First-party GitHub advisory JSON (global and repo) plus `git` ancestry, commit messages, and named-tag containment. Missing top-level `mechanism_key` was reconstructed from advisory text plus the reversed hunk. Actively tested: old-bug preservation, remediation-as-origin, squash/merge mis-blame, later-human blob drift, insufficient/umbrella fixes, alias duplicates.

## KEEP (proposal)

**2** — Global GHSA-vvfr / CVE-2026-6830 (repo GHSA 404). Claude member `d2b27f6f` first adds `_reload_dotenv`; parent has no `api/profiles.py`. Member is ancestor of merge `f21b088a` and `v0.24`. Fix `88dc8bbe` pops `_loaded_profile_env_keys` and is in `v0.50.12` not `v0.24`.

**6** — Repo+global GHSA-gw85. Hypothesized member `cc048a29` is absent from this clone. AI-marked squash `03586e3d` adds empty-allowlist `return true`; `v2026.2.22` `security.ts` blob equals the squash. Fix `0ee30361` is in `v2026.2.24`.

**12** — Claude `700ff33d` first adds `bindings.oauth2` tokens. `3.38.1` has that commit and no `sanitizeTestResult.ts`. Fix `bca426de` is in `3.39.25`.

**14** — Remediation-as-origin. Claude security fix `847d08bd` rewrites archive `\` to `/`, creating POSIX zip-slip (GHSA-83xp). Reversed by `8503ba61`. `v2.63.6` / `v2.63.17`. Distinct from ordinal 166.

**18** — Repo GHSA-fpmv (global 404). Claude merge `5a887953` is in `v4.2.11-97eb073` not the fix. Fix `56d617b7` is in `v4.2.14-56d617b`.

**26** — Repo GHSA-c4hm (global 404). `claude-flow` `29d52dfc` first adds the MCP bridge; git `v3.16.2` / `v3.16.3` close release (npm gitHead not re-peeled).

**32** — Global GHSA-q6qc (repo 404). Claude `f82c7836` adds unauthenticated `EmbeddedServer`. `v3.5.5` / `v3.5.6`.

**42** — Feishu temp-path traversal. Origin is upstream Claude `a604df8c` in `m1heng/clawdbot-feishu`, not OpenClaw import `2267d58a`. Fix `c8210991`. `v2026.2.12` / `v2026.2.19`.

**46** — Claude `06dd9b8e` follows media redirects. Fix `f865a545` drops cross-origin auth headers. `v2026.3.28` / `v2026.3.31`.

**54** — Claude `079af0d0` skips device identity when a token is present. Fix `ddcb2d79`. `v2026.2.21` / `v2026.2.22` (local `v2026.2.21-2` missing).

**58 / 66** — Shared upstream Claude `4286755f` and import carrier `2267d58a`, distinct invariants and fixes: unguarded media fetch (`5b4121d6`, `v2026.2.13`/`v2026.2.14`) versus quoted/thread sender allowlist (`f45e5a65`, `v2026.3.28`/`v2026.3.31`). Not aliases of 42.

**64** — Repo GHSA-6mwv (global 404). Claude/Cursor `706e6513` adds kiro API-key routing; `126aa244` allowlists AWS region. `v0.5.2` lacks the fix.

**76** — Repo GHSA-qpmq (global 404). Claude “logs viewer” commit still first adds mapping-dropdown `innerHTML` with `member.avatar`. Fix `d5ae67e5` uses DOM APIs. `v1.4.1` / `v1.4.2`.

**106** — Copilot `a0e61088` adds the TypeScript v2 gray-matter loader. `c27402da` rejects JS engines and names the GHSA. `typescript/2.0.0-beta.2` / `beta.3`.

**112** — Two Claude commits persist unverified certificate signatures. One umbrella fix `db97de47` (also other P0s) reverses verification. `v0.8.1` / `v0.8.2`.

**160** — Claude incomplete rem `0542a216` of backslash authority. Human `f3c6c905` rejects remaining introducers. `v4.1.1`; `v4.1.2`’s parent is the fix.

**162** — Copilot API-only draft ACL (`1eced4a7` / backport `e7fca90a`) is incomplete. Upstream web gate `f7fd5102` is **not** in `v1.27.0`; backport `ab10e37a` is. `v1.26.4` still lacks the web gate.

**164** — Claude string `//` guard is incomplete for URI objects. Human `3f1280c6`. Distinct from GHSA-33mh. `v2.14.1` / `v2.14.2`.

**166** — Same origin SHA as 14, dangling-symlink write fallback. Fix `64511ce4`. `v2.63.15` / `v2.63.16`. Not an alias of GHSA-83xp.

**176** — GPT-5.6 section-delimiter validator preserves unsafe option names. Follow-on `a495ccd3` names GHSA-jm78. Tags `3.1.57` / `3.1.58`.

**182** — Repo GHSA-cwp8 (global 404). Claude member `f9afc3c5` deletes live `isLocked` / 2FA from `public-user.php`. Squash `18b21153` carries the same file blob and Claude trailer; member is not a `7.2.2` ancestor. Tag login still returns `apiKey` after password only. Later email commit `68e42fe0` changes the blob without restoring 2FA. `7.3.1` contains `1bfc187a`.

## NARROW

**44** — Worker SHA `3e176213` is not on `main` and is in no tag. Landed Copilot origin is `4f28b6950` (`#904`), blamed on the `v1.13.8` `SwaggerUIBundle(stringifyJSON(...))` line. Parent Scalar path already used unescaped `stringifyJSON`. Fix in `v1.13.9`. File-level swagger origin is real; GHSA-level DIRECT_ROOT KEEP is refused.

**118** — Claude query-param `gatewayUrl` `applySettings` is real (`v2026.1.20`–`v2026.1.24` without the modal fix). Official last affected `2026.1.28` has **no git tag** in this clone. `v2026.1.29` contains `a7534dc2`. Release gate NARROW.

**210** — Claude member/carrier blobs of `TurnServer.cs` match and the parent lacks the file. Repo consolidation `aebe49c5` moves the path to `src/SIPSorcery/net/TURN/TurnServer.cs`, so `v10.0.13` blob ≠ member blob. `ReceiveUdpAsync` / outer catch still present. `v10.0.14` matches fix `ccb0b5a8`. Topology NARROW.

## UNKNOWN

**148** — Global GHSA-4fxp (repo 404). Claude incomplete rem (auth without authorize) and later Claude authorize patch are both in git, but **no tag** contains `52e5e193` without `86a7d655`. `v5.5.3` and `v5.14.0` contain both. Released containment unproven.

## Counterexample classes hit

Remediation-as-origin (14), shared-SHA distinct mechanisms (14/166, 42/58/66), squash member missing (6, 182), later-human blob drift (182, 210), umbrella fix (112, 182), incomplete rem (148, 160, 162, 164, 166, 176), wrong candidate SHA (44), missing affected tag (118, 148).
