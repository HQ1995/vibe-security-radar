# Third-party conflict adjudication — reviewer 05

Contract: `AUDIT_CONTRACT.md`. Input: `conflict_inputs/reviewer-05.jsonl`.
Owned outputs: `adjudications/reviewer-05.jsonl`, this report.
Raw clones/pages: `/tmp/fp211-adjudicate-05/{clones,pages,notes}`.
No first/second-pass files, canonical ledger, builders, or code were edited. No commit.

Coverage: **exactly 8 assigned ordinals**, sorted: **10, 22, 35, 96, 107, 133, 202, 209**.

Exclusion check (packet fields, not inferred): every row has `third_reviewer=5` and `5 ∉ {first_reviewer, second_reviewer}`:

| ordinal | first | second | third | changed_fields |
|---:|---:|---:|---:|---|
| 10 | 1 | 4 | 5 | identity_gate |
| 22 | 1 | 4 | 5 | identity_gate |
| 35 | 1 | 4 | 5 | identity_gate |
| 96 | 3 | 6 | 5 | release_gate |
| 107 | 3 | 6 | 5 | release_gate |
| 133 | 4 | 1 | 5 | verdict, but_for_gate, causal_class |
| 202 | 6 | 3 | 5 | verdict, but_for_gate, fix_reversal_gate, causal_class, false_positive_class |
| 209 | 6 | 3 | 5 | verdict, but_for_gate, fix_reversal_gate, causal_class, false_positive_class |

First/second-pass rows were routing, not proof. Primary GHSA/CVE objects and parent/candidate/fix/release git were re-inspected independently.

## Verdict counts

| Verdict | n | ordinals |
|---|---:|---|
| NARROW | 5 | 10, 22, 96, 107, 133 |
| FALSE_POSITIVE | 2 | 202, 209 |
| UNKNOWN | 1 | 35 |
| CONFIRM | 0 | — |
| BLOCKED | 0 | — |
| **total** | **8** | assigned |

None of these is `CONFIRM/HIGH`.

## Conflict resolutions

### 10 / GHSA-5wqv / CVE-2026-55197 — identity PASS (not NARROW)

Global `/advisories/GHSA-5wqv-fhmr-pjgh` identifiers include `CVE-2026-55197`. Repo `nesquena/hermes-webui` advisory 404 is preserved. The IDs name GET `/api/session` cross-profile transcripts; they belong to this public case.

Claude `ee672df4` adds `profile=` → `_get_profile_home(profile)/state.db` on an endpoint whose parent already did `Session.load` from global `SESSION_DIR/{sid}.json` and `get_state_db_session_messages(sid)` without a profile. Peeled `v0.51.442` contains the candidate; peeled `v0.51.443` equals fix `2a3baa71`. Distinct from ordinal 2 (dotenv) and 115 (profile search).

A 404 on one GHSA surface does not NARROW identity when the other first-party object formally aliases. Mechanism scope stays NARROW (`AI_NEW_SURFACE_CONTRIBUTOR`): deleting the candidate leaves the sidecar IDOR.

### 22 / GHSA-42m6 / CVE-2026-49949 — identity PASS (not NARROW)

Global advisory aliases the CVE. Repo `steipete/codexbar` GHSA 404 preserved. Three Claude commits add OpenRouter/DeepSeek/Kimi callers that originally used `URLSession.shared` + Bearer. Human `f62bb8c8` later introduces `ProviderHTTPClient`. At `v0.32.0` those fetchers call `ProviderHTTPClient.shared.response` with no redirect guard; `08c171b6` / `v0.33.0` adds `guardedRedirectRequest`.

Identity closes via the global alias. Topology/but-for stay NARROW: the candidates are not origin of the shared transport.

### 35 / GHSA-4mpw / CVE-2026-34049 — identity PASS; verdict UNKNOWN preserved

Repo advisory aliases `CVE-2026-34049` (incomplete MongoDB collection-name injection). Global `/advisories` 404 preserved. Candidate `473c3227` is only `Changes auto-committed by Conductor` (Andras Bacsai), no AI trailer. Parent `733c20fc` already interpolated `mongodump --excludeCollection`. Candidate adds `create_backup` as a new HTTP writer of `databases_to_backup`. Claude marker is on fix member `99043600`. Candidate/carrier present in `v4.0.0-beta.436`; fix `b1de75a7` first in `v4.0.0-beta.471`. Sibling 68 already `duplicate_of` this row.

Identity PASS. `ai_hunk_gate` remains UNKNOWN. Do not infer PASS from a missing counterexample.

### 96 / GHSA-rqp8 / CVE-2026-35635 — release PASS (not UNKNOWN)

Repo GHSA is GHSA-only; global advisory aliases the CVE. Claude member `cc048a29` introduces Synology Chat with inherited default `webhookPath=/webhook/synology` (`accounts.ts` blob identical on member, carrier `03586e3d`, and `v2026.2.22`). Member is **not** an ancestor of the carrier; `channel.ts` blobs differ. `registerPluginHttpRoute` on member/carrier/`v2026.2.22` does not pass `replaceExisting:true` (that token in the fix diff is not the intro hunk; `replaceExistingScope` is a different supervisor API).

Independently peeled: `v2026.2.22` contains carrier, not member, not `980940aa`; `v2026.3.22` contains the fix. GHSA affected `< 2026.3.22`. Same intro SHA as ordinals 6 and 122 with different fixes/invariants.

Release UNKNOWN was only missing tag peels. Topology stays NARROW (squash / non-ancestor member), so not CONFIRM.

### 107 / GHSA-cw23 / CVE-2026-18980 — release PASS (not UNKNOWN)

Global advisory aliases the CVE and names `classify_command_risk` / patch `a1d7c3ba`. Repo GHSA 404 preserved. Claude `b20880c1` removes parent full-command `contains()` High matching and moves High inside `split(['|','&',';'])`, omitting newline. Listed carrier `b58b4215` is a later independent Claude PR (`merge-base --is-ancestor` fails). `shell.rs` blobs differ, but `ironclaw-v0.29.1` still has the split-without-newline High loop.

Independently present tags: `ironclaw-v0.29.1` contains carrier, not member, not fix; `ironclaw-v1.0.0` `shell.rs` blob equals the fix. Plain `v0.29.1` / `v1.0.0` do not exist. Missing unprefixed tags are not release UNKNOWN once the prefixed crate tags close containment. Topology stays NARROW.

### 133 / GHSA-r5jh / CVE-2026-50568 — NARROW, not CONFIRM

Repo and global advisories alias. Parent already defined `SanitizeFilePath` (`filepath.Clean` + `strings.HasPrefix`) and called it from `Builder.Handler` and fetcher. Claude `0d851525` only wires that helper onto `Builder.Clean` (previously unsanitized `filepath.Join`). Squash carrier `5a3d68a3` (`v1.23.0~12`) has the same Clean hunk. `8298e33e` switches callers to `os.Root` and is first in `v1.25.0`, absent from `v1.24.0`. CNA cleanup `5aac6f0b` deletes the unused helper after reversal.

Removing the candidate restores unsanitized Clean but **leaves** the advisory HasPrefix helper and every pre-existing caller. That is a new surface of a preexisting weak sanitizer, not proven sole origin / incomplete fix of the named helper. `but_for_gate=NARROW`, `causal_class=AI_NEW_SURFACE_CONTRIBUTOR`. CONFIRM is refused.

### 202 / GHSA-ccwh / CVE-2026-53864 — FALSE_POSITIVE

Repo GHSA identifiers are GHSA-only; global aliases the CVE (identity NARROW, keep both). PR #63277 was generated by OpenAI Codex; squash subject `[AI]`; member `3affd5e8` has no trailer (`ai_hunk` NARROW).

`NODE_REPL_HISTORY`: parent N, member Y, carrier N, `v2026.5.22` N, `v2026.5.26` N, `v2026.5.27` Y. `NODE_REPL_EXTERNAL_MODULE` / `NODE_V8_COVERAGE` / `NODE_REDIRECT_WARNINGS` never appear on parent/member/carrier. `91590132` adds those four keys and is first in `v2026.5.27`, not the advisory's `2026.5.26`.

A key added on a squash member and dropped on the released carrier is unattempted on the shipped denylist. Removing the candidate does not remove advisory Node control keys from an artifact that never had them. `but_for_gate=FAIL`, `false_positive_class=unattempted_env_family`. Distinct from 203–208 (different GHSAs).

### 209 / GHSA-55cf / CVE-2026-45003 — FALSE_POSITIVE

Repo GHSA GHSA-only; global aliases CVE (keep both, identity NARROW). Same Codex PR / `[AI]` squash as 202. Carrier denylist has `AMQP_URL` / `DATABASE_URL` / `MONGODB_URI` / `REDIS_URL` and never `MATTERMOST_URL` / `IRC_URL`. Advisory residual is workspace **dotenv** override of Matrix/Mattermost/IRC/Synology hosts. Fix `0623079e` (`v2026.4.22`) edits `src/infra/dotenv.ts` only and does not reverse a sanitizer hunk.

Generic exec-denylist URLs are not those named connector hosts. Removing the candidate leaves the dotenv residual intact. `but_for_gate=FAIL`, `fix_reversal_gate=FAIL`, `unattempted_env_family`.

## Public-ID conservation

Every row: `public_ids_keep` = sorted manifest `public_ids`, `public_ids_remove` = `[]`. No `duplicate_of`. No silent ID drop.

## Limitations

- Ironclaw tags were already on the local clone after fetch; unprefixed `v0.29.1`/`v1.0.0` remain absent.
- GHSA-ccwh does not name the two Node variables in the summary text; git key presence was used instead.
- OpenClaw npm gitHead was not re-peeled where git tags already closed containment (96, 202, 209).
- Fission member is not an ancestor of the squash carrier; Clean hunk equality was used, not whole-file blob equality.

## Reusable experience

1. Repo-or-global GHSA 404 is evidence to preserve, not identity NARROW, when the other first-party object formally aliases the CVE.
2. Do not leave `release_gate=UNKNOWN` when tags were simply not fetched; peel the prefixed crate/release tags the CNA actually used.
3. A squash member key that never ships on the carrier is unattempted on the released artifact, not `AI_INCOMPLETE_REMEDIATION`.
4. Attaching a preexisting weak helper to a new caller is `AI_NEW_SURFACE_CONTRIBUTOR` with `but_for=NARROW`; it is not CONFIRM of the helper's original bypass.
5. Generic URL denylist entries are not named connector-host / dotenv residuals; fail but-for rather than narrowing the env family.
