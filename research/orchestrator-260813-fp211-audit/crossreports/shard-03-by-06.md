# Cross-review shard 03 by reviewer 06 (ordinals 73–108)

Coverage: exactly 36 canonical `COMPONENT_ROW` records, ordinals **73–108**.
Verdicts: CONFIRM=3, NARROW=27, FALSE_POSITIVE=5, UNKNOWN=1, BLOCKED=0. Unclosed release peels stay UNKNOWN; this review does not promote a row to CONFIRM on a git-tag proxy for an unpeeled npm artifact.
Public cases are counted by verified advisory identity, not by row or mechanism count: prefer a first-party `GHSA-*` as `case_id`; retain a CVE only as a formal alias of that GHSA; merge two GHSAs only with first-party identifier evidence. This shard’s 36 rows are therefore not 36 public cases.
Only CONFIRM/HIGH is claim-grade without another review. First-pass citations, OSV `introduced`, baseline PASS/NARROW/REJECT/UNKNOWN, and carrier AI labels were treated as hypotheses, never proof.

Owned outputs: `crossreviews/shard-03-by-06.jsonl`, `crossreports/shard-03-by-06.md`.
Raw clones/pages under `/tmp/fp211-cross-06`. MISP reads used the symlink `/tmp/fp211-cross-06/clones/misp` → `~/.cache/cve-analyzer/repos/misp_misp` read-only.
No canonical, first-pass, or code edits. No commit.

## Independent method

Every assigned ordinal was re-checked against (1) GitHub advisory objects or first-party repo advisories when the global GHSA 404ed, and (2) git parent/candidate/carrier/fix blobs plus `merge-base --is-ancestor` on fetched tags. First-pass JSONL was compared only after those probes. Tags that first pass left unfetched (ddev, fission, ouroboros, ironclaw, garminconnect, rconfig, actual, coolify, prompty) were fetched into the cross-review clones before release gates were scored.

## Verdict disagreements with first pass

None. CONFIRM stays 73/76/81. FP stays 75/83/89/90/94. UNKNOWN stays 84. NARROW stays on every other assigned ordinal, including **106** (quoted `matter(raw)` hunk, but npm `@prompty/core` 2.0.0-beta.3 gitHead remains unpeeled so `release_gate=UNKNOWN`; git tags `typescript/2.0.0-beta.*` are not treated as that packument).

## Public-ID keep/remove disagreements with first pass

None. Conservation matches input `public_ids` on every row. The only split remains ordinal **94**: keep `GHSA-7JM2-G593-4QRC`; remove `CVE-2026-45001` and `GHSA-9FC9-8V4X-F5CP`. Independently confirmed from first-party `GHSA-7jm2` (`cve_id=null`, identifiers=[GHSA]) versus unreviewed `GHSA-9fc9` (identifiers include the CVE; 7jm2 appears only in `references[]`).

Identity-evidence note that does **not** change keep/remove: global reviewed `GHSA-w28w` has `cve_id=null`, but first-party `microsoft/prompty` repo advisory identifiers include `CVE-2026-73299`. Both IDs stay in `public_ids_keep` for **105**; `identity_gate` stays NARROW because the same GHSA also ranges `<=0.1.4`.

## Gate disagreements with first pass

| Ord | Gate | First | This | Independent evidence |
|---|---|---|---|---|
| **83** | release | UNKNOWN | PASS | After fetching Coolify tags: candidate in `v4.0.0-beta.454` without fix; fix in `v4.0.0-beta.466`. Identity/but-for still FAIL (named routes pre-exist). |
| **85** | release | UNKNOWN | PASS | `v2026.2.21` candidate without `73d93dee`; `v2026.2.22` has the fix. Verdict stays NARROW (sticker fetch site ≠ multi-channel origin). |
| **87** | release | UNKNOWN | PASS | `core-8.2.3` peels to carrier `ebb39d59` (mem/car present, fix absent). `core-8.2.8` peels to `63bfd1b0` but `84822f40` **is** an ancestor. Topology/but-for stay NARROW. |
| **90** | release | UNKNOWN | FAIL | `v1.24.0` (advisory affected) has neither member nor carrier nor fix; `v1.25.0` has carrier **and** fix. Candidate never sat in the affected artifact. but-for already FAIL. |
| **91** | release | UNKNOWN | PASS | `v1.25.1` carrier without fix; `v1.25.2` has `05cbe299`. Verdict stays NARROW (new TypeSymlink on old Join; multipurpose ZipSlip fix). |
| **95** | release | NARROW | PASS | Git tags match GHSA: `v2026.3.28` carrier without fix; `v2026.3.31` has `a30214a6`. Topology/but-for stay NARROW. |
| **96** | release | UNKNOWN | PASS | `v2026.2.22` carrier without fix; `v2026.3.22` has `980940aa`. Squash topology still NARROW. |
| **100** | release | UNKNOWN | PASS | `v0.38.2` carrier without fix; `v0.39.0` has `4e70b760`. Env-override remains contributor vs later dotenv. |
| **102** | fix_reversal | PASS | NARROW | Fix `57a06f70` is multipurpose DoS (#10798: logging plus iteration/llm/rss/text/xml). Frontend compose without rotation is a new surface, not the whole advisory. |
| **106** | ai_hunk | NARROW | PASS | Quoted `matter(raw)` with no engines override in Copilot `loader.ts`. `release_gate` stays UNKNOWN (npm `@prompty/core` gitHead unpeeled). Verdict stays NARROW. |
| **107** | release | UNKNOWN | PASS | Use prefixed tags: `ironclaw-v0.29.1` carrier without fix; `ironclaw-v1.0.0` has `a1d7c3ba`. Plain `v0.29.1`/`v1.0.0` do not contain these commits. Member is not an ancestor of listed carrier. |

Gates that first pass left UNKNOWN and this review **preserved** as UNKNOWN (not inferred PASS):

- **84** claimed 8.1.2/8.1.3 still missing; only later 8.2.4 recovered.
- **99** git `v26.5.2`/`v26.6.0` contain neither carrier nor fix; first git tag with both is `v26.7.0`, which is not the advisory’s npm `26.6.0`.
- **106** advisory artifact is npm `@prompty/core` 2.0.0-beta.3; git tags `typescript/2.0.0-beta.*` are not that packument.
- **108** git tags `0.3.4`/`0.3.5` exist but `name-rev --tags` of candidate and fix is undefined; those tags do not contain the commits.

Citation correction that is not a gate change: ordinal **74** relevant hunk is `src/transcript.ts` (`realpathSync` + cache `0o600`), not `src/index.ts`.

Independent blob compare that first pass skipped: ordinal **93** `extensions/matrix/src/channel.ts` member blob `eb67c49c` ≠ carrier blob `366f74ad`. Topology stays NARROW; this is why 93 is not upgraded to CONFIRM.

## CONFIRM

- **73** AI_DIRECT_ROOT HIGH: new `EventTemplateImporter.php` overwrite preserves `org_id`; Claude Opus 4.7; parent file absent; fix `7c2200d1` adds org check; cand in v2.5.37–38 without fix, fix in v2.5.39. GHSA-243v unreviewed aliases CVE-2026-10855.
- **76** AI_DIRECT_ROOT HIGH: global GHSA-qpmq 404; first-party Anchorr advisory aliases CVE-2026-32890 (stored XSS User Mapping). Claude `403ccf07` first introduces `option.innerHTML` interpolating `member.avatar`/`displayName`. Fix `d5ae67e5`. cand in v1.4.1; fix in v1.4.2.
- **81** AI_DIRECT_ROOT HIGH: GHSA-rv39 quotes token-presence skip — that is the `079af0d0` `hasTokenAuth` hunk. Fix `fe81b1d7` requires `sharedAuthOk`. v2026.2.1 without fix; v2026.2.2 has fix. Distinct from 80 (scopes residual, different fix).

## FALSE_POSITIVE counterexamples

### 75 `not_origin_of_named_mechanism`

Human `c736f11a` introduces `hasBrowserOriginHeader && !hasProxyHeaders`. Listed AI `20523b91` is `trustedProxyAuthOk` pairing. Human `ebed3bbd` removes the Origin skip.

### 83 `not_origin_of_named_mechanism`

First-party GHSA-f47p names POST `/v1/projects`, POST `/v1/servers`, GET `/v1/servers/{uuid}/validate` under `api.ability:read`. Parent already has all three. Candidate adds Hetzner + POST cloud-tokens validate. Fix `c15bcd56` only moves **validate** endpoints to write.

### 89 `unreleased_dangerous_revert`

Claude revert of Azure cert-host allowlist. Fix `57b11d40` is a child of carrier `9400eaa9` (~40 min later). `carrier-not-fix` tags = []. v2.33.2/2.33.3 contain neither; v2.34.0 contains both. GHSA older 2.32/2.31 ranges are DefaultClient, not this revert.

### 90 `not_origin_of_named_mechanism`

Fix message: `Validate()` **never** checked RelativeURL/Prefix. Webhook retire is context. Additionally, candidate is absent from affected `v1.24.0`.

### 94 `old_bug_preserving_refactor`

Parent of carrier `29f20624` already has exec-only `PROTECTED_GATEWAY_CONFIG_PATHS`. Member `53764bbb` (GitHub API; missing locally) simplifies a richer branch-local guard that main did not ship. Public `case_id` is only first-party `GHSA-7JM2`.

## NARROW counterexamples (identity/scope/topology/fix-set/release)

Do not auto-upgrade NARROW→CONFIRM unless all seven gates are PASS/NA. Squash/merge-member topology and contributor-not-origin but-for are usually legitimate NARROW, not overuse. First-pass NARROW overuse in this shard was mostly **unfetched tags**, not those topology/contributor calls. After fetch, release closed on 85/87/91/95/96/100/107 without promoting those rows to CONFIRM.

- **74** AI_DIRECT_ROOT: realpath+mode is not a root jail (`/etc/passwd` still resolves). Path is `src/transcript.ts`.
- **77** AI_NEW_SURFACE_CONTRIBUTOR: parent `media.ts` already strips `file://`; Claude adds a native autoload caller. Keep CVE-2026-34510 + GHSA-W4H3; do not add reviewed GHSA-h3x4 (`cve_id=CVE-2026-34426`). Distinct from ord 60.
- **78** AI_NEW_SURFACE_CONTRIBUTOR: GHSA-f7fh impact wording is `/json/version` second-hop; landed fix is the direct-WS branch. Same SHA as shard-04 120 is a different DNS-guard fix.
- **79** AI_NEW_SURFACE_CONTRIBUTOR: PrefixSearch is a new API on pre-existing FullTextWhereFragment. Patch-equivalent member/carrier. Member not in V8.36.0; carrier is.
- **80** AI_NEW_SURFACE_CONTRIBUTOR: `079af0d0` is the device skip, not self-declared scopes. Release independently closed (already PASS in first pass): v2026.3.11 without `5e389d5e`; v2026.3.12 has it.
- **82** AI_DIRECT_ROOT: mega v0.3.0 dump; unused `_channelType`. Fix commit exists via GitHub API; local blob unread; v0.3.1/v0.4.0 contain cand, neither contains fix.
- **85** AI_NEW_SURFACE_CONTRIBUTOR: sticker `fetchRemoteMedia` without `maxBytes`, then `saveMediaBuffer(..., maxBytes)`. Distinct from ord 9.
- **86** AI_GUARD_WEAKENING: Nashorn `--no-java` → GraalJS `HostAccess.ALL`. Ordered min fix `[87a7d96a, c691e35e]`. Residual `js.load` in v3.30.0/v3.30.1.
- **87** AI_NEW_SURFACE_CONTRIBUTOR: new token Users API inherits `StoreUserRequest`.
- **88** AI_NEW_SURFACE_CONTRIBUTOR: public IDs name parent `/music` sibling-prefix PoC; AI adds `temp/` `startswith` without `os.sep`.
- **91** AI_NEW_SURFACE_CONTRIBUTOR: TypeSymlink without dest containment; parent TypeReg already Join.
- **92** AI_DIRECT_ROOT: nickname matcher is AI (GitHub API Co-Authored-By Claude); member blob missing locally. v2026.3.2 carrier without fix; v2026.3.22 has `7ade3553`.
- **93** AI_DIRECT_ROOT: thread-root injection is AI origin; member≠carrier blobs. v2026.2.12 carrier without fix; v2026.3.31 has `8a563d60`.
- **95** AI_NEW_SURFACE_CONTRIBUTOR: EXEC_EVENT special-case on a parent that already scheduled exec-event heartbeats.
- **96** AI_NEW_SURFACE_CONTRIBUTOR: inherited default `webhookPath`. Distinct from ord 6 (empty-allowlist) and shard-04 122 (rate-limit).
- **97** AI_NEW_SURFACE_CONTRIBUTOR: baseline REJECT `missing_published_artifact` is false — `v1.6.0`/`auth@1.6.1` contain carrier without cookie fix. New `/oauth2/callback/:providerId` matcher inherits parent unbound nonce. Member is not ancestor of carrier. Not FP: the new matcher is a real published surface.
- **98** AI_DIRECT_ROOT: delimiter-free hash concat is AI origin; mega-squash carrier; official patch still truncates.
- **99** AI_DIRECT_ROOT: Claude-authored new `escapeCsv`; release UNKNOWN because git `v26.6.0` ≠ npm 26.6.0 peel.
- **100** AI_NEW_SURFACE_CONTRIBUTOR: `OUROBOROS_CLI_PATH` env override vs later project `.env`.
- **101** AI_NEW_SURFACE_CONTRIBUTOR: new PDF `force_download` on a parent that already downloaded ImageUrl; public IDs name the shared SSRF helper.
- **102** AI_NEW_SURFACE_CONTRIBUTOR: new Compose frontend without log rotation; siblings already unbounded; first-party GHSA-vw3v aliases CVE-2025-32425 (global 404).
- **103** AI_NEW_SURFACE_CONTRIBUTOR: one more unvalidated trace RPC; GHSA-2cm6 names all trace APIs; input already says not origin of CVE-2026-8147. Fix already in v3.13.0 while GHSA wording is prior to 3.14.0.
- **104** AI_NEW_SURFACE_CONTRIBUTOR: TS v2 copies Python `${file:...}` sink. npm/git `typescript/2.0.0-beta.1` vs `beta.2`.
- **105** AI_NEW_SURFACE_CONTRIBUTOR: unrestricted Nunjucks; first-party aliases CVE-2026-73299; dual `<=0.1.4` plus v2 ranges; listed fix `047756f4` is a merge not in `typescript/2.0.0-beta.5`.
- **106** AI_DIRECT_ROOT: Copilot `loader.ts` calls `matter(raw)` with no engines override; GHSA-c4gh aliases CVE-2026-53597. `ai_hunk` PASS from the quoted call. `release_gate` UNKNOWN: npm `@prompty/core` 2.0.0-beta.3 gitHead unpeeled; git `typescript/2.0.0-beta.*` is not that packument.
- **107** AI_GUARD_WEAKENING: newline omitted from `split(['|','&',';'])`; listed carrier is a later independent Claude PR.
- **108** AI_DIRECT_ROOT: new `client.py` `dump()` umask; listed carrier `f74174a5` is merge of the **fix** (`77a3837f` is a parent). Release UNKNOWN: git 0.3.4/0.3.5 do not contain the commits.

## UNKNOWN

- **84** release_gate=UNKNOWN: claimed artifacts 8.1.2/8.1.3 were not recovered. Jules `57b76343` is SELECT-then-UPDATE `token_used_at` (opposite role vs ord 56 PayPal fix). Human `fdf67a6f` is atomic `UPDATE ... AND token_used_at IS NULL`. Reviewed GHSA-VH5J has no CVE.

## Uniqueness (shared SHAs, distinct mechanisms)

| SHA | Ords | Decision |
|---|---|---|
| `cc048a29` / `03586e3d` | 6 vs **96** | Distinct: empty-allowlist vs inherited webhookPath. |
| `506bed5a` | 9 vs **85** | Distinct: token-in-URL vs omitted maxBytes. |
| `079af0d0` | 15/33/54/**80**/**81** | Distinct fixes/invariants; 81 is direct token-presence, 80 is scopes residual. |
| `57b76343` | 56 vs **84** | Opposite roles: PayPal-body FIX vs token-replay CANDIDATE. |
| `8d74578c` | 60 vs **77** | Distinct: image-tool workspaceOnly vs native media UNC caller. |
| `a0e61088` | **104/105/106** | Distinct TS v2 sinks: file resolver, Nunjucks, gray-matter. |
| `75602014` | **78** vs shard-04 120 | Distinct: direct-WS CDP vs DNS-guard. |

Same repository or same fix alone does not merge distinct mechanisms.

## Representative replay commands

```bash
# identity (global 404s recovered first-party)
python3 -c "import json;from pathlib import Path
for n in ('qpmq','f47p','vw3v','w28w','7jm2'):
 d=json.loads(Path(f'/tmp/fp211-cross-06/pages/{n}.repo.json').read_text())
 print(n, d.get('cve_id'), [x['value'] for x in d.get('identifiers') or []])"

# 73/76/81/106 CONFIRM peels
git -C /tmp/fp211-cross-06/clones/misp merge-base --is-ancestor 41450bdb5d31ab017e147ccc921951ee6a70e134 v2.5.37
git -C /tmp/fp211-cross-06/clones/anchorr show 403ccf079be0ee5e6660f0ed2fa64174d76eff2f -- web/script.js | rg innerHTML
git -C /tmp/fp211-cross-06/clones/openclaw show 079af0d0b02ca2c722f90b6c4e38e27ba16227b4 | rg hasTokenAuth
git -C /tmp/fp211-cross-06/clones/prompty show a0e6108842a3bfc840a33db819a4415fbdac333d:runtime/typescript/prompty/src/core/loader.ts | rg 'matter|engines'
git -C /tmp/fp211-cross-06/clones/prompty merge-base --is-ancestor c27402da2487075be577f06aa79df627fb9d6853 typescript/2.0.0-beta.3

# FP
git -C /tmp/fp211-cross-06/clones/openclaw show c736f11a16d6bc27ea62a0fe40fffae4cb071fdb | rg hasProxyHeaders
git -C /tmp/fp211-cross-06/clones/coolify grep -n "post('/projects'" 62c394d3a1dba6aa6d4ab1456b7a7911f6b72639^ -- routes/api.php
comm -23 <(git -C /tmp/fp211-cross-06/clones/coder tag --contains 9400eaa957fb019b0084bd1c8599ec0f671f17cb | sort) <(git -C /tmp/fp211-cross-06/clones/coder tag --contains 57b11d405f17492aa789d4b9ff33366f961a37f8 | sort)
git -C /tmp/fp211-cross-06/clones/fission merge-base --is-ancestor c6cd334f008676963c68fc7be7924aa02731e061 v1.24.0
git -C /tmp/fp211-cross-06/clones/openclaw show 29f206243b2d636e10ebf794a27d937d63f04b49^:src/agents/tools/gateway-tool.ts | sed -n '24,32p'

# release gates first pass left UNKNOWN
git -C /tmp/fp211-cross-06/clones/openclaw merge-base --is-ancestor 73d93dee64127a26f1acd09d0403b794cdeb4f5c v2026.2.22
git -C /tmp/fp211-cross-06/clones/rconfig merge-base --is-ancestor 84822f4051ed97d651b1b4d191c6da2aa8c3c037 core-8.2.8
git -C /tmp/fp211-cross-06/clones/ddev merge-base --is-ancestor 05cbe299770a590b89bfc8dddab33e61b4302e43 v1.25.2
git -C /tmp/fp211-cross-06/clones/ouroboros merge-base --is-ancestor 4e70b760b4eb157469b58645339ba831f6513d37 v0.39.0
git -C /tmp/fp211-cross-06/clones/ironclaw merge-base --is-ancestor a1d7c3ba428ed575900469b207fb5668725f9a71 ironclaw-v1.0.0
git -C /tmp/fp211-cross-06/clones/actual merge-base --is-ancestor 068185751c03b42e726e3c60b718413d5f96c306 v26.6.0
git -C /tmp/fp211-cross-06/clones/garminconnect name-rev --tags 21aea2d95b823a15c81a3efe87566de5dcc3befc
```

## Limitations

- Did not checkout/fetch/modify `~/.cache/cve-analyzer/repos/*` except read-only MISP via symlink.
- OpenClaw members `ce12b909` and `53764bbb` are absent from the local clone; GitHub commit API pages under `/tmp/fp211-cross-06/pages/92-member.json` and `94-member.json` were used.
- Mysti fix blob remains unread locally; ChannelBridge reversal for 82 is from `gh api` commit message (`/tmp/fp211-cross-06/pages/82-fix.json`).
- `@actual-app/cli` 26.5.2/26.6.0 still have no gitHead peel; git tags of those names do not contain the commits.
- `@prompty/core` 2.0.0-beta.3 npm gitHead was not peeled; ordinal 106 `release_gate` stays UNKNOWN.
- Garminconnect git tags 0.3.4/0.3.5 do not contain candidate or fix; PyPI peel was not closed.
- No BLOCKED row: every missing prerequisite had a safe alternative (GitHub API page, first-party advisory, or explicit UNKNOWN).
- Uniqueness vs shards 01/02/04/05/06 used first-pass shared-SHA tables plus this shard’s probes; other shards’ independent mechanism splits were not re-litigated beyond distinct source/sink/fix.

## Reusable lessons

1. **Quote the call, then PASS ai_hunk — not CONFIRM.** `matter(raw)` without `engines` is the gray-matter hunk; release still needs the advisory npm artifact peeled.
2. **Fetch tags before UNKNOWN.** First-pass NARROW overuse here was mostly empty clones, not squash topology.
3. **Git tag name ≠ advisory version.** `v26.6.0` without the commits, `0.3.5` without the fix, and unprefixed `v1.0.0` vs `ironclaw-v1.0.0` are not release PASS.
4. **Annotated tags that peel away from the fix SHA can still contain it as an ancestor** (rconfig `core-8.2.8`).
5. **Named endpoints on the parent are fatal** even after release closes (Coolify 83).
6. **Fix commit messages can confess pre-existence** (Fission 90) and **candidate-absent-from-affected-tag** can FAIL release in addition.
7. **Listed carrier may be the fix merge or a later independent PR** (garminconnect `f74174a5`; ironclaw `b58b4215`).
8. **Same SHA ≠ duplicate.** Require distinct source/sink/invariant/fix; `a0e61088` feeds 104/105/106. Do not CONFIRM 106 on `typescript/2.0.0-beta.*` git tags when the advisory is npm `@prompty/core`.
9. **Global GHSA 404 is not missing identity** if the first-party repo advisory exists (qpmq, f47p, vw3v). First-party `cve_id` can recover a CVE the global object omits (w28w) without merging unrelated version ranges.
10. **Two GHSAs merge only on identifiers.** 94 keeps `GHSA-7JM2` (no CVE); `GHSA-9FC9`+`CVE-2026-45001` stay removed.
11. **realpath is not a root jail.** Claude-hud 234d9aa.
12. **Do not trust REJECT missing_published_artifact** without listing carrier-not-fix tags (better-auth 97).
13. **Member-vs-carrier blob inequality blocks CONFIRM** even when the mechanism is AI-direct (93).
14. **Multipurpose fixes NARROW fix_reversal** (AutoGPT 102; ddev 91 ZipSlip).
