# Cross-review shard 06 by reviewer 03 (ordinals 181–211)

Coverage: exactly ordinals **181–211** (31 rows) from `inputs/shard-06.jsonl`.
Owned outputs: `crossreviews/shard-06-by-03.jsonl`, `crossreports/shard-06-by-03.md`.
Evidence root: `/tmp/fp211-cross-03` (independent clones, `advisories/`, `evidence/`). No canonical/first-pass/code edits. No commit.

First-pass citations were hypotheses, not proof. Every ordinal was re-checked against the first-party GHSA object plus Git parent/candidate/fix/tag evidence in `/tmp/fp211-cross-03/clones/`.

## Verdict counts

- CONFIRM: 3 — ordinals 182, 185, 210
- NARROW: 16
- FALSE_POSITIVE: 12 — ordinals 181, 190, 191, 193, 202, 203, 204, 205, 206, 207, 208, 209
- UNKNOWN: 0
- BLOCKED: 0

CONFIRM/HIGH only: 182 (F01 lockout/2FA delete), 185 (F04 new `data-person_name`), 210 (I01 new TurnServer UDP loop).
No UNKNOWN/BLOCKED row: every assigned ordinal had a first-party GHSA object plus clone hunks sufficient to close or falsify the claimed mechanism.

## Disagreements with first pass

Public-ID keep/remove sets are identical to first pass for all 31 rows. SHA `candidate_set` / `carrier_set` / `minimum_fix_set` are identical. No duplicate public IDs across the 211-row input population.

### Verdict disagreements (6)

| Ord | First pass | Cross-review 03 | Why |
|---|---|---|---|
| 193 | NARROW | **FALSE_POSITIVE** `preexisting_incomplete_predicate` | Parent already had `if (authz.callerDeviceId && !authz.isAdminCaller)` on `device.pair.approve`. Candidate nested `requestsNonOperatorDeviceRole` inside that leak. GHSA range starts `>=2026.1.20`. Fix `517ce3df` drops a conjunct the candidate did not introduce. |
| 202 | NARROW | **FALSE_POSITIVE** `unattempted_env_family` | `NODE_REPL_HISTORY` added on member `3affd5e8` then **dropped on carrier** `2d126fc6`. Parent and released carrier never contain the advisory Node control keys. Dropped member keys are not a released attempt. |
| 203 | NARROW | **FALSE_POSITIVE** `unattempted_env_family` | `TCLLIBPATH` member-only then dropped; `BASHOPTS`/`KSH_ENV`/`FPATH` never present. Same unattempted-on-carrier pattern as 204. |
| 206 | NARROW | **FALSE_POSITIVE** `different_invariant` | GHSA is workspace **dotenv → provider credentials**. Candidate only expanded **host-exec** denylist (`AWS_*` survived squash). Fix `85277c2` is `src/infra/dotenv.ts`, never the sanitizer. |
| 207 | NARROW | **FALSE_POSITIVE** `unattempted_env_family` | `HOMEBREW_BREW_FILE` never in parent/member/carrier. Ambient PREFIX/CELLAR/REPOSITORY added then dropped. Fix `f86953f` is `brew.ts`/`dotenv.ts`. |
| 209 | NARROW | **FALSE_POSITIVE** `unattempted_env_family` | Named Mattermost/IRC/Matrix/Synology hosts never present. Generic `AMQP_URL`/`DATABASE_URL` on exec denylist ≠ dotenv connector-host blocklist. Fix `0623079e` is `dotenv.ts`. |

### Gate-value disagreements (including same-verdict rows)

| Ord | Gate | First pass | Cross-review 03 |
|---|---|---|---|
| 193 | `but_for_gate` | NARROW | FAIL |
| 193 | `fix_reversal_gate` | PASS | NARROW |
| 199 | `identity_gate` | PASS | NARROW |
| 202 | `but_for_gate` | NARROW | FAIL |
| 202 | `fix_reversal_gate` | PASS | NARROW |
| 203 | `but_for_gate` | NARROW | FAIL |
| 203 | `fix_reversal_gate` | PASS | NARROW |
| 206 | `but_for_gate` | PASS | FAIL |
| 206 | `fix_reversal_gate` | PASS | FAIL |
| 207 | `but_for_gate` | NARROW | FAIL |
| 207 | `fix_reversal_gate` | PASS | FAIL |
| 209 | `but_for_gate` | NARROW | FAIL |
| 209 | `fix_reversal_gate` | PASS | FAIL |

### Public-ID disagreements

None on `public_ids_keep` / `public_ids_remove`.

Identity observation that cannot change conservation: ordinal **199** global advisory `GHSA-2hfg-4fh4-qp7f` aliases **CVE-2026-53812**, which is not in the input `public_ids`. It cannot be kept or removed. `identity_gate` NARROW (first pass PASS).

### Reasoning disagreement with same gate value

Ordinal **201** `release_gate` stays NARROW, but first pass said git first-containing vulnerable carrier is 7.4.0. Independent zsh-safe `cat-file` shows `src/FundRaiserDelete.php` present at **7.2.0 through 7.4.0** (matches advisory `<=7.2.2`) and absent at 7.4.3. Squash member `6ef78813` is not an ancestor of tags; carrier `ede1bfb0` is in 7.2.0. Remaining NARROW reasons: sibling pages PropertyTypeDelete/NoteDelete, missing patched tag 7.3.2, git fix 7.4.3.

## False-positive counterexamples

### 181 `post:gitea-private-org-members@canonical` — `sibling_endpoint_unattempted_old_bug`

- AI member `2828e4bf` (Assisted-by Claude) gates only `ListPublicMembers` / `IsPublicMember`. Parent `ListMembers` already lacked `HasOrgOrUserVisible`.
- GHSA residual is `/members` (`<=1.26.4`). AI partial and ListMembers closure both land in `v1.27.0`. `release_gate=NA`.
- Replay: `git -C /tmp/fp211-cross-03/clones/gitea diff 2828e4bf^ 2828e4bf -- routers/api/v1/org/member.go`

### 190 `posthold:F09` — `different_invariant`

- Candidate `3cc8b2a3` never edits `validate-sandbox-security.ts`. Residual is runtime ancestor-covers-denied-descendant.
- Replay: `git -C /tmp/fp211-cross-03/clones/openclaw show --stat --format=full 3cc8b2a3d0a163bc9e7bc9e5f72bc2b9dde24e74`

### 191 `posthold:F10` — `unattempted_route_preflight`

- Candidate is ordinal 199's fix `3d93174c` (`pw-tools-core.interactions.ts` only). F10 invariant is current-tab URL in `agent.act.ts`.
- Replay: `git -C /tmp/fp211-cross-03/clones/openclaw show --stat --format=full 3d93174c4398088066a1de9372ea1103cd713df1`

### 193 `posthold:F12` — `preexisting_incomplete_predicate` *(disagrees with first pass)*

- Parent already had `if (authz.callerDeviceId && !authz.isAdminCaller)` on `device.pair.approve`.
- Candidate nested extra non-operator-role checks inside that leak. Advisory range `>=2026.1.20`.
- Fix `517ce3df` drops the pre-existing conjunct.
- Replay: `git -C /tmp/fp211-cross-03/clones/openclaw show 1c85eff9^:src/gateway/server-methods/devices.ts | sed -n '151,175p'`

### 202 `posthold:E01` — `unattempted_env_family` *(disagrees)*

- `NODE_REPL_HISTORY` member=True, carrier=False. Other NODE_* advisory keys never present.
- Replay: `git -C /tmp/fp211-cross-03/clones/openclaw show 2d126fc6:src/infra/host-env-security-policy.json | grep NODE_REPL || true`

### 203 `posthold:E02` — `unattempted_env_family` *(disagrees)*

- `TCLLIBPATH` dropped on carrier; `BASHOPTS`/`KSH_ENV`/`FPATH` never present.
- Replay: `git -C /tmp/fp211-cross-03/clones/openclaw show 2d126fc6:src/infra/host-env-security-policy.json | grep -E 'TCLLIBPATH|BASHOPTS' || true`

### 204 `posthold:E03` — `unattempted_env_family`

- `GIT_ALLOW_PROTOCOL` / `GIT_PROTOCOL_FROM_USER` False in parent, member, and carrier.

### 205 `posthold:E04` — `unattempted_env_family`

- `RUSTUP_*` never added. `CARGO_HOME` pre-existed.

### 206 `posthold:R01` — `different_invariant` *(disagrees)*

- AWS keys survived on the **exec sanitizer**. GHSA and fix `85277c2` are **dotenv.ts** provider credentials.
- Replay: `git -C /tmp/fp211-cross-03/clones/openclaw show --stat --format='%s' 85277c2db1fa98af84b234df91bbab1f87a37d96`

### 207 `posthold:R02` — `unattempted_env_family` *(disagrees)*

- `HOMEBREW_BREW_FILE` never present. Fix `f86953f` is `brew.ts`/`dotenv.ts`. Git first-containing of that SHA is `v2026.5.2`, not advisory 2026.5.27.

### 208 `posthold:R03` — `unattempted_env_family`

- `CLOUDSDK_PYTHON` never present. Sibling CONFIG/PROJECT keys dropped on squash are not the PYTHON interpreter boundary.

### 209 `posthold:R04` — `unattempted_env_family` *(disagrees)*

- Named connector hosts never present. Generic URL keys on exec denylist ≠ dotenv connector hosts. Fix `0623079e` is `dotenv.ts`.

## Narrow counterexamples (agreed unless noted)

### 183 F02

- New `buildRolePills` unescaped `OptionName`. Parent `GroupRoles.js` option-label sink pre-exists. Repo-only GHSA.

### 184 F03

- New `tel:`/`mailto:`. Quoted `data-name` pre-existed. Shared origin with 183, distinct sinks.

### 186 F05

- Restored 2FA/lockout; invalid OTP 401 without `setFailedLogins`. Advisory lists 7.5.1 only; partial carrier `1bfc187a` first in **7.3.1**.

### 187 F06

- New `PluginInstaller.php`; `ALLOWED_EXTENSIONS` includes `php`. Advisory `<=7.3.3` predates git first-containing **7.3.0**.

### 188 F07

- Cursor `_SANDBOX_BLOCKED_CALLS` without `format`/`format_map`. PyPI `praisonaiagents` range vs git `v4.6.58`/`v4.6.59`. Distinct from ordinal 128 GHSA-4MR5 and 169 JWT (same SHA).

### 189 F08

- Same `DISPATCH_WRAPPER_SPECS` unwrap table; flock never unwrapped. Advisory `<=2026.6.6` omits git tag `v2026.6.8`.

### 192 F11

- Snapshot SSRF attempted for Chrome MCP `tab.url`; residual is current-tab CDP snapshot preflight. Advisory `>=2026.4.14` vs git witness `v2026.5.22`.

### 194 F13

- Candidate body is “clamp unapproved trusted proxy websocket scopes”. Residual is pairing-before-proxy (`shouldSkipControlUiPairing`). Distinct from ordinal 23 GHSA-VVGP and 75 origin-check.

### 195 F14

- Streamable HTTP MCP Authorization scrub; GHSA names SSE. Distinct from ordinal 46 media redirect.

### 196 F15

- Candidate redacts persisted auth / `trajectory/runtime.ts`; never edits `trajectory/export.ts`.

### 197 F16

- Runner `toolsAllow` inheritance; ClickClack inbound adapter not in candidate files.

### 198 F17

- Primary QQBot approval callback authorized; same-chat fallback residual. Same `interaction-handler.ts` family.

### 199 F18

- `[AI-assisted]` + Devin co-author: `ai_hunk` cannot PASS. pressKey/type(submit) only; residual select/fill/evaluate. Global CVE-2026-53812 not in input IDs.

### 200 G01

- Keep all four IDs. GHSA-3J8Q omnibus nine findings — only VULN-02/03 notes.php. GHSA-JJCJ family API — notes overlap only. Two GHSAs are **not** aliases. Candidate creates `notes.php` (Claude Code). Fix `83c19611` adds `canEditPerson`. In 7.3.3 without fix; 7.4.0 with fix.

### 201 G03

- New GET `FundRaiserDelete.php`. Advisory also names older PropertyTypeDelete/NoteDelete. Missing patched tag 7.3.2. File **is** in 7.2.0–7.4.0; gone in 7.4.3. Shared origin with 185, different sink.

### 211 I02

- Cursor-created `signature.ex` returns ok without `:public_key.verify`. Advisory `1.0.0`; git tag is **`v1.0`**.

## Ordinal 200 — each public ID

Input IDs: `CVE-2026-58407`, `CVE-2026-58410`, `GHSA-3J8Q-FWPJ-F8J5`, `GHSA-JJCJ-H3CM-P7X7`. `public_ids_remove=[]`.

| Public ID | Disposition | First-party object | Attribution |
|---|---|---|---|
| GHSA-3J8Q-FWPJ-F8J5 | KEEP | ChurchCRM repo advisory published | Only VULN-02/03 notes.php IDOR |
| CVE-2026-58407 | KEEP | Formal alias in GHSA-3j8q `identifiers[]` | Same omnibus; count once with GHSA-3J8Q |
| GHSA-JJCJ-H3CM-P7X7 | KEEP | ChurchCRM repo advisory published | Notes overlap only; profile/timeline predate |
| CVE-2026-58410 | KEEP | Formal alias in GHSA-jjcj `identifiers[]` | Count once with GHSA-JJCJ |

## Primary-source citations

- Gitea GHSA-prr9: https://github.com/go-gitea/gitea/security/advisories/GHSA-prr9-9mp4-5gp2
- ChurchCRM advisories under https://github.com/ChurchCRM/CRM/security/advisories/ (local copies `/tmp/fp211-cross-03/advisories/repo-ghsa-*.json`)
- OpenClaw advisories under https://github.com/openclaw/openclaw/security/advisories/
- OpenClaw PR 63277 Codex: https://github.com/openclaw/openclaw/pull/63277
- PraisonAI GHSA-pv2j: https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-pv2j-rghr-v5r9
- SIPSorcery GHSA-pfvm: https://github.com/sipsorcery-org/sipsorcery/security/advisories/GHSA-pfvm-w89x-94jw
- Relyra GHSA-jv46: https://github.com/szTheory/relyra/security/advisories/GHSA-jv46-xfwm-36j7
- Env key matrix: `/tmp/fp211-cross-03/evidence/env-denylist.json`

## Replay

```bash
python3 -c "import json,pathlib,sys; sys.path.insert(0,'autoresearch/orchestrator-260813-fp211-audit'); from verify import load_jsonl, verify_row, HERE; exp={r['ordinal']:r for r in load_jsonl(HERE/'manifest.jsonl')}; rows=load_jsonl(HERE/'crossreviews'/'shard-06-by-03.jsonl');
[verify_row(r, exp[r['ordinal']]) for r in rows]; print(len(rows), rows[0]['ordinal'], rows[-1]['ordinal'])"
git diff --check -- autoresearch/orchestrator-260813-fp211-audit/crossreviews/shard-06-by-03.jsonl autoresearch/orchestrator-260813-fp211-audit/crossreports/shard-06-by-03.md
# per-row git replays are in each JSONL replay_commands array; clones live under /tmp/fp211-cross-03/clones/
# zsh: quote tree-ish paths as 7.2.2':src/FundRaiserDelete.php' — :s is a zsh modifier
```

## Limitations

- Several ChurchCRM/OpenClaw GHSAs are repo-only (global github.com/advisories 404); identity used the repo advisory JSON plus global 404.
- OpenClaw E01–R04 share squash member `3affd5e8` / carrier `2d126fc6` from Codex PR #63277; member has no AI trailer. `ai_hunk_gate` is NARROW on all eight. CONFIRM forbidden.
- CVE aliases CVE-2026-53864 / 53819 / 53842 / 45003 are kept even when the first-party GHSA `identifiers[]` lists only the GHSA. CVE-2026-53812 on ordinal 199 cannot be added.
- ChurchCRM squash members (F01–F06, G03) are often not ancestors of the release tag; carriers are.
- Advisory version ranges frequently predate git first-containing tags or name missing tags (ChurchCRM 7.3.2, Relyra v1.0.0).
- Uniqueness vs the rest of the 211 used the audit input population (no intra-population public-ID collision; OpenClaw rows 16/23/46/75 are different GHSAs; PraisonAI 128/169 share commit `179cab02` with 188 but different mechanisms).
- This shard is not a public-case count. Omnibus IDs on ordinal 200 must not inflate cases.
- Full `verify_crossreviews.py` still requires the other five shards.

## Reusable experience

- Sibling endpoint or sibling env-key hardening is not incomplete remediation of a residual the candidate never touched (181 ListMembers, 204 GIT_*, 205 RUSTUP_*, 208 CLOUDSDK_PYTHON).
- A key added on a squash **member** and dropped on the **carrier** is unattempted on the released artifact (202 NODE_REPL_HISTORY, 203 TCLLIBPATH, 207 HOMEBREW_PREFIX). Do not NARROW that as incomplete remediation.
- Host-exec denylist and workspace dotenv are different invariants even when key names overlap (206 AWS_*, 207 Homebrew, 209 connector URLs).
- Nested extra checks inside a **pre-existing** incomplete predicate are old-bug-preserving, not origin of the advisory residual (193).
- A later row's fix SHA must not be reused as another row's origin (191 used 199's fix).
- Schema-level absolute-path extraction is a different invariant from runtime ancestor-covers-denied-descendant (190).
- PR-level Codex / `[AI]` squash subjects cannot CONFIRM relevant-hunk provenance.
- Handle each public ID: keep 404-free aliases, narrow omnibus children, never silently drop IDs; a global CVE absent from input `public_ids` cannot be kept or removed (199).
- New-file AI components with member==carrier blob can CONFIRM when parent lacked the file and the advisory residual is in that blob (210).
- EscapeHtml in a quoted attribute is a new sink when the parent lacked that attribute (185 CONFIRM vs 184 NARROW data-name).
- zsh `:s` modifiers can make `tag:path` `cat-file` checks lie; concatenate `"$t"":path"`.
