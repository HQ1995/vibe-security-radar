# Shard 06 false-positive audit (ordinals 181–211)

Coverage: exactly ordinals **181–211** (31 rows) from `inputs/shard-06.jsonl`.
Owned outputs: `shards/shard-06.jsonl`, `reports/shard-06.md`.
Evidence root: `/tmp/fp211-shard-06` (clones, `advisories/`, `evidence/`). No canonical/ledger/manifest edits.

## Verdict counts

- CONFIRM: 3 — ordinals 182, 185, 210
- NARROW: 22
- FALSE_POSITIVE: 6 — ordinals 181, 190, 191, 204, 205, 208
- UNKNOWN: 0
- BLOCKED: 0

CONFIRM/HIGH only: 182 (F01 lockout/2FA delete), 185 (F04 new `data-person_name`), 210 (I01 new TurnServer UDP loop).
No UNKNOWN/BLOCKED row: every assigned ordinal had a first-party GHSA object plus clone hunks sufficient to close or falsify the claimed mechanism. Gates that still fail to fully close are marked NARROW or FAIL, not inferred PASS.

## False-positive counterexamples

### 181 `post:gitea-private-org-members@canonical` — `sibling_endpoint_unattempted_old_bug`

- Advisory residual ListMembers existed in the candidate parent; AI member never edited ListMembers. Removing 2828e4bf does not remove /members enumeration.
- GHSA affected <=1.26.4 describes the old ListMembers leak, not a released AI-partial state; AI public_members partial and ListMembers closure both land in v1.27.0.
- Replay: `git -C /tmp/fp211-shard-06/clones/gitea show --format=full 2828e4bf72d486bb11bb81ebf26aa20254b62bae -- routers/api/v1/org/member.go`

### 190 `posthold:F09` — `different_invariant`

- GHSA-575V residual is runtime ancestor-covers-denied-descendant in validate-sandbox-security.ts. Candidate never edited that file and did not introduce that invariant.
- Removing 3cc8b2a3 leaves the advisory residual intact; it only reused an existing absolute-path schema check.
- Replay: `git -C /tmp/fp211-shard-06/clones/openclaw show --stat --format=full 3cc8b2a3d0a163bc9e7bc9e5f72bc2b9dde24e74`

### 191 `posthold:F10` — `unattempted_route_preflight`

- F10 invariant is current-tab URL before /act. Candidate never touched agent.act.ts.
- Assigning F18's closure as F10's candidate is a sibling-route mislabel, not incomplete remediation of the act-route preflight.
- Replay: `git -C /tmp/fp211-shard-06/clones/openclaw show --stat --format=full 3d93174c4398088066a1de9372ea1103cd713df1`

### 204 `posthold:E03` — `unattempted_env_family`

- Candidate never added GIT_ALLOW_PROTOCOL or GIT_PROTOCOL_FROM_USER. Removing 3affd5e8/2d126fc6 does not remove the GHSA residual.
- This is not incomplete remediation of a Git-transport boundary that was never attempted.
- Replay: `git -C /tmp/fp211-shard-06/clones/openclaw show 3affd5e8f9ca6e2f51d00bebde6c1c277e8a5161:src/infra/host-env-security-policy.json | grep GIT_ALLOW_PROTOCOL || true`

### 205 `posthold:E04` — `unattempted_env_family`

- RUSTUP_* keys were never added by the Codex denylist member. CARGO_HOME pre-existed. but-for fails.
- Replay: `git -C /tmp/fp211-shard-06/clones/openclaw show 3affd5e8f9ca6e2f51d00bebde6c1c277e8a5161:src/infra/host-env-security-policy.json | grep RUSTUP || true`

### 208 `posthold:R03` — `unattempted_env_family`

- CLOUDSDK_PYTHON was never present in parent, member, or carrier. Sibling CLOUDSDK_CONFIG/PROJECT additions (later dropped) are not an attempt of the PYTHON interpreter boundary.
- Keep CVE-2026-53842 as an unresolved GHSA alias; do not treat sibling gcloud keys as this mechanism.
- Replay: `git -C /tmp/fp211-shard-06/clones/openclaw show 3affd5e8f9ca6e2f51d00bebde6c1c277e8a5161:src/infra/host-env-security-policy.json | grep CLOUDSDK || true`

## Narrow counterexamples

### 183 `posthold:F02`

- GroupRoles.js option-label sink pre-exists the AI member, so one of the four GHSA sinks is old-bug preservation inside a new GroupView rebuild.
- Lesson: When an AI rebuild copies an old unescaped option renderer into new pill HTML, split new sinks from preserved ones; a single GHSA that names both must be narrowed, not counted as a clean origin of every listed line.

### 184 `posthold:F03`

- Quoted data-name attribute sink predates the AI member; only tel:/mailto: are new in 0ea20d01.
- Lesson: Shared origin with F02 is allowed when attacker fields and DOM contexts differ, but any pre-existing data-name sink inside the same GHSA must narrow but-for.

### 186 `posthold:F05`

- Repo advisory lists affected 7.5.1 only, but the partial carrier 1bfc187a is first in 7.3.1; release wording must use git first-containing tags.
- Lesson: A restored security gate that fail-closes on the success path but skips lockout accounting on the 2FA failure path is incomplete remediation of that gate, not a second origin of the prior bypass.

### 187 `posthold:F06`

- Advisory vulnerable_version_range <=7.3.3 includes releases before the installer exists; git first-containing tag is 7.3.0.
- Lesson: A brand-new web-root extractor that allowlists php is a new RCE surface even if the commit is titled security; still narrow identity when the GHSA paints every earlier release as affected.

### 188 `posthold:F07`

- GHSA package range is pip praisonaiagents <=1.6.52 / >=1.6.59 while git tags used here are v4.6.58/v4.6.59; same commit 179cab02 is also ordinal 169 JWT candidate.
- Lesson: Do not merge sandbox advisories by shared defense file: GHSA-PV2J names the format resolver residual of the Cursor AST denylist, and GHSA-4MR5 is the earlier __self__ path; still narrow git-tag vs PyPI coordinates.

### 189 `posthold:F08`

- Candidate attempted script/time wrapper blocking, not the flock allow-always residual named by GHSA-3FP5.
- Advisory patched_versions 2026.6.9 vs git first-containing v2026.6.9 is aligned, but affected <=2026.6.6 does not name v2026.6.8.
- Lesson: Hardening a wrapper-trust plan is incomplete remediation only for residuals on that same unwrap boundary; flock allow-always still needs a named unwrap, and advisory ranges must be checked against git tags.

### 192 `posthold:F11`

- Candidate gated snapshot SSRF on Chrome MCP tab.url; residual is current-tab validation before snapshot on local-managed CDP.
- Advisory patched 2026.5.26 matches git; vulnerable_tag v2026.5.22 is a git subset of >=2026.4.14.
- Lesson: An [AI] snapshot SSRF patch that covers Chrome MCP tab.url still leaves a current-tab CDP snapshot residual; that is incomplete remediation of the same snapshot boundary.

### 193 `posthold:F12`

- Admin gate was attempted but predicated on callerDeviceId, so empty-device callers bypassed node approval admin.
- Lesson: An admin deny gated on callerDeviceId && !isAdminCaller is incomplete: non-device callers never enter the deny, and the later fix is dropping the device-id conjunct.

### 194 `posthold:F13`

- Candidate clamped unbound websocket scopes; residual is pairing-before-proxy-scopes, a related but not identical Control UI auth invariant.
- vulnerable_tag v2026.5.12 vs patched 2026.5.18; confirm git tags rather than advisory prose.
- Lesson: Scope clamping on Control UI websockets is not automatically pairing-before-proxy; keep GHSA-QJPC separate from other OpenClaw pairing GHSAs.

### 195 `posthold:F14`

- Candidate scrubbed streamable HTTP MCP redirects; GHSA names SSE transport residual.
- Advisory patched 2026.6.5 vs git v2026.6.5; vulnerable_tag v2026.6.1 is a git subset.
- Lesson: Scrubbing Authorization on streamable HTTP MCP redirects is incomplete when the advisory residual is SSE (or another) redirect transport.

### 196 `posthold:F15`

- Candidate attempted broad persisted-payload redaction; it did not edit trajectory/export.ts, so the export-walker residual is a sibling artifact on the same redactor invariant.
- Lesson: A persisted-auth redaction patch is incomplete for trajectory export only if the shared redactor invariant was attempted; still narrow because the export walker file was never edited.

### 197 `posthold:F16`

- Candidate inherited toolsAllow into embedded runner policy; ClickClack reply adapter was not in the candidate files.
- Lesson: Inheriting toolsAllow in the runner is incomplete when a provider reply adapter (ClickClack) still drops the restriction.

### 198 `posthold:F17`

- Candidate authorized QQBot approval callbacks; residual is same-chat fallback buttons still treating co-location as authorization.
- Lesson: Authorizing the primary QQBot approval callback is incomplete if a same-chat fallback button still skips command authorization.

### 199 `posthold:F18`

- Relevant hunk is labeled [AI-assisted] with human co-author; no model trailer on the blob. ai_hunk cannot PASS.
- Candidate covered pressKey/type(submit) only; GHSA residual includes select/fill/evaluate.
- Lesson: [AI-assisted] plus a human co-author is not hunk-level AI provenance for CONFIRM; pressKey/type-submit is still a real partial of the interaction-navigation family closed by 3d93174c.

### 200 `posthold:G01`

- GHSA-3J8Q/CVE-2026-58407 is an omnibus of nine findings; only VULN-02/03 are this notes API. Identity must be narrowed to those children.
- GHSA-JJCJ/CVE-2026-58410 also covers family profile and timeline endpoints that the candidate did not create.
- public_ids_remove stays empty: neither GHSA is 404/withdrawn, and removing them would drop the public identity of the notes overlap.
- Lesson: When four public IDs attach to two non-aliased GHSAs, keep every ID, attribute only the overlapping notes routes, and refuse CONFIRM on omnibus identity.

### 201 `posthold:G03`

- Advisory also names PropertyTypeDelete.php and NoteDelete.php, which this candidate did not add.
- Advisory patched 7.3.2 is a missing tag; git first-containing vulnerable carrier is 7.4.0 and fix is 7.4.3, after advisory 7.2.2.
- Lesson: A new GET-delete page is a real AI origin for that page only; an omnibus CSRF GHSA that also names older delete pages and a missing patched tag must be narrowed.

### 202 `posthold:E01`

- Hunk-level AI is PR-level Codex plus [AI] carrier subject; member blob has no trailer, so ai_hunk cannot PASS.
- First-party GHSA-CCWH does not list CVE-2026-53864; keep the CVE as an unresolved alias rather than remove it.
- NODE_REPL_HISTORY was added on the member then dropped on the squash carrier; other NODE_* advisory keys were never attempted.
- Lesson: PR-level Codex plus an [AI] squash subject is not hunk provenance; a denylist key added on a member and dropped on the carrier is incomplete, not a clean origin of every NODE_* name in the GHSA.

### 203 `posthold:E02`

- Only TCLLIBPATH was attempted (then dropped on carrier). BASHOPTS, KSH_ENV, and FPATH were never in the candidate denylist.
- ai_hunk remains NARROW for the same PR-level Codex reason as E01.
- Lesson: Adding one interpreter-startup key on a squash member does not attempt every named sibling key; remaining names stay unattempted residuals of the same denylist family.

### 206 `posthold:R01`

- Candidate added AWS credential keys and they survived the squash; other provider API keys named around the GHSA were not attempted.
- ai_hunk NARROW for PR-level Codex; GHSA-4PQJ identifiers[] GHSA-only
- Lesson: AWS_* credentials added on the denylist member are a real incomplete provider-cred family; they do not merge with OPENCLAW_ namespace rows or unattempted vendor API keys.

### 207 `posthold:R02`

- Ambient Homebrew path keys were added on the member then dropped on the carrier; HOMEBREW_BREW_FILE was never attempted.
- Release wording 2026.5.27 does not match git v2026.5.2 first-containing the listed fix SHA.
- Lesson: Keep the CVE when the GHSA omits it, but narrow release to git first-containing tags; dropped squash-member Homebrew keys are incomplete, not BREW_FILE origin.

### 209 `posthold:R04`

- Candidate blocked generic URL connector vars that survived the squash; named Mattermost/IRC hosts were never in the candidate denylist.
- Keep CVE-2026-45003; first-party GHSA does not list it.
- Lesson: Generic AMQP/DB/Redis URL denylist entries are not Mattermost/IRC host origin; keep the GHSA and narrow to the keys actually added.

### 211 `posthold:I02`

- Advisory writes Relyra 1.0.0 but the git tag is v1.0; release wording must use the actual tag name.
- Lesson: A Cursor-created verifier that returns {:ok} after shape/trust checks without crypto is a new-file origin; still narrow when the advisory's 1.0.0 tag does not exist.

## Ordinal 200 — each public ID

Input IDs: `CVE-2026-58407`, `CVE-2026-58410`, `GHSA-3J8Q-FWPJ-F8J5`, `GHSA-JJCJ-H3CM-P7X7`. `public_ids_remove=[]`.

| Public ID | Disposition | First-party object | Attribution |
|---|---|---|---|
| GHSA-3J8Q-FWPJ-F8J5 | KEEP | ChurchCRM repo advisory published; omnibus nine findings | Only VULN-02/03 notes.php IDOR. Not SSRF/token/credential/group/finance legs. |
| CVE-2026-58407 | KEEP | Formal alias in GHSA-3j8q `identifiers[]` | Same omnibus; count once with GHSA-3J8Q. |
| GHSA-JJCJ-H3CM-P7X7 | KEEP | ChurchCRM repo advisory published; EditSelf family API IDOR | Notes overlap only. Family profile + timeline predate candidate. |
| CVE-2026-58410 | KEEP | Formal alias in GHSA-jjcj `identifiers[]` | Same family-API object; count once with GHSA-JJCJ. |

The two GHSAs are **not** formal aliases of each other. uniqueness_gate PASS (one notes-API mechanism, four IDs retained). identity_gate NARROW. Candidate `b3edc225` creates `notes.php` (Claude Code). Fix `83c19611` adds `canEditPerson`. In 7.3.3 without fix; in 7.4.0 with fix.

## Primary-source citations

- Gitea GHSA-prr9: https://github.com/go-gitea/gitea/security/advisories/GHSA-prr9-9mp4-5gp2
- ChurchCRM advisories under https://github.com/ChurchCRM/CRM/security/advisories/ (local copies `/tmp/fp211-shard-06/advisories/repo-ghsa-*.json`)
- OpenClaw advisories under https://github.com/openclaw/openclaw/security/advisories/
- OpenClaw PR 63277 Codex: https://github.com/openclaw/openclaw/pull/63277
- PraisonAI GHSA-pv2j: https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-pv2j-rghr-v5r9
- SIPSorcery GHSA-pfvm: https://github.com/sipsorcery-org/sipsorcery/security/advisories/GHSA-pfvm-w89x-94jw
- Relyra GHSA-jv46: https://github.com/szTheory/relyra/security/advisories/GHSA-jv46-xfwm-36j7
- Clone check matrix: `/tmp/fp211-shard-06/evidence/env-denylist-keys.txt`

## Replay

```bash
python autoresearch/orchestrator-260813-fp211-audit/verify.py --allow-partial
python3 -c "import json,pathlib; p=pathlib.Path('autoresearch/orchestrator-260813-fp211-audit/shards/shard-06.jsonl'); rows=[json.loads(l) for l in p.read_text().splitlines() if l.strip()]; print(len(rows), rows[0]['ordinal'], rows[-1]['ordinal'])"
# per-row git replays are in each JSONL replay_commands array; clones live under /tmp/fp211-shard-06/clones/
```

## Limitations

- Several ChurchCRM GHSAs are repo-only (global github.com/advisories 404); identity used the repo advisory JSON.
- OpenClaw E01–R04 share squash member `3affd5e8` / carrier `2d126fc6` from Codex PR #63277; member has no AI trailer. ai_hunk_gate is NARROW on all eight. CONFIRM forbidden.
- CVE aliases CVE-2026-53864 / 53819 / 53842 / 45003 are kept even when the first-party GHSA `identifiers[]` lists only the GHSA.
- ChurchCRM squash members (F01–F06, G03) are often not ancestors of the release tag; carrier SHAs are.
- Advisory version ranges frequently predate git first-containing tags or name missing tags (ChurchCRM 7.3.2, Relyra v1.0.0).
- Uniqueness vs the rest of the 211 used the audit input population (no intra-shard public-ID collision; OpenClaw rows 16/23/46/75 are different GHSAs; PraisonAI 127/128/169 share commit `179cab02` with 188 but different mechanisms).
- This shard is not a public-case count. Omnibus IDs on ordinal 200 must not inflate cases.

## Reusable experience

- Sibling endpoint or sibling env-key hardening is not incomplete remediation of a residual the candidate never touched (181 ListMembers, 204 GIT_*, 205 RUSTUP_*, 208 CLOUDSDK_PYTHON).
- A later row's fix SHA must not be reused as another row's origin (191 used 199's fix).
- Schema-level absolute-path extraction is a different invariant from runtime ancestor-covers-denied-descendant (190).
- PR-level Codex / `[AI]` squash subjects cannot CONFIRM relevant-hunk provenance.
- Handle each public ID: keep 404-free aliases, narrow omnibus children, never silently drop IDs.
- New-file AI components with member==carrier blob can CONFIRM when parent lacked the file and the advisory residual is in that blob (210).
- EscapeHtml in a quoted attribute is a new sink when the parent lacked that attribute (185 CONFIRM vs 184 NARROW data-name).
