# Red-team: upgrade-b ordinals 114, 122, 211

**Status: `REDTEAM_COMPLETE`.** Upgrade-b rows were hypotheses. Independent first-party GHSA fetch and Git replay from `/home/hanqing/.cache/ghsa200-worker-clones/red-upgrade-b-direct`. A KEEP here is still only a proposal. `fresh-am` and `fresh-am-batch2` were not read as evidence and were not modified.

| Ordinal | GHSA | Hypothesis | Red-team |
|--------:|------|------------|----------|
| 114 | GHSA-P52P-4VMG-4VQ3 | assigned | **NARROW** |
| 122 | GHSA-MF5G-6R6F-GHHM | PASS | **KEEP** |
| 211 | GHSA-JV46-XFWM-36J7 | PASS | **NARROW** |

Clones: `.../clones/{nesquena__hermes-webui,openclaw__openclaw,szTheory__relyra}`. Advisory JSON: `.../advisories/`.

## Ordinal 114 — NARROW

Global GHSA-p52p-4vmg-4vq3 / CVE-2026-49973 describes unauthenticated `_set_password` on the settings API with no network-origin restriction, fixed before 0.51.358. The object is `type=unreviewed`, `repository_advisory_url` is null, `vulnerabilities=[]`, and the repository advisory API returns 404. Identity therefore does not close as a first-party reviewed GHSA with a structured affected range.

Atomic `b8b62722` (2026-04-03) has `Co-Authored-By: Claude Opus 4.6 (1M context)`. Parent `1c6db07c` has no `_set_password`. The candidate adds `save_settings` consumption of `_set_password` on top of an already-unauthenticated POST `/api/settings`. That is a real new surface and is but-for for the named parameter: removing it eliminates first-run password takeover via `_set_password`.

Exact hunk blame at last vulnerable tag `v0.51.357` does not hold to the Claude commit. `api/config.py:5959` blames `31a721417` (onboarding wizard #285; Nathan Esquenazi / gabogabucho; no AI marker). The parent of that commit already had the single-quoted pop. `api/routes.py` `requested_password` blames `8b857d9ef` (login-module-patch; no AI marker). `v0.51.357` already has `_onboarding_gate_allows` for `/api/onboarding/setup` and still does not gate first-password `_set_password`.

Fix `f2ef2851` (merged as `v0.51.358` = `1126e541`) adds the local-network gate on `requested_password and not auth_enabled_before`. That reverses the advisory invariant. `1126e541` is a merge of `5dceb299` and the fix; it is the fixed tag, not the origin. Candidate is an ancestor of `v0.51.357`; the fix is not.

Uniqueness against the 212-case ledger: distinct from GHSA-VVFR (dotenv), GHSA-5WQV (session-db), and GHSA-MGXW. `identity_gate` and `ai_hunk_gate` stay NARROW. New-surface but-for is real; this is not a KEEP.

## Ordinal 122 — KEEP (proposal)

First-party reviewed GHSA-mf5g-6r6f-ghhm / CVE-2026-35646 names `openclaw/openclaw`, pre-auth Synology Chat webhook token brute-force, and fix `0b4d07337467f4d40a0cc1ced83d45ceaec0863c`. Repo advisory range is `<= 2026.3.24` patched `2026.3.25`. Global structured range is `< 2026.3.28` patched `2026.3.28`. npm and git have `2026.3.24` and `2026.3.28`; `2026.3.25` does not exist as a tag or npm version. Repo text says `2026.3.25` was a planned cut published ahead of the artifact. Containment uses global 3.24 / 3.28, which exist.

Squash member `cc048a29` is Claude-marked and creates `webhook-handler.ts`. It is not an ancestor of any of `v2026.2.22`, `v2026.3.24`, or `v2026.3.28`. Authorship is not transferred onto that member. The landed squash `03586e3d` (single parent `fbf0c99d`) carries the same Claude trailer and the identical blob `d1dae50a`. `v2026.2.22` blame of the unthrottled `validateToken` 401 is `03586e3d`. Parent of the member has no file. Post-auth `rateLimiter.check(payload.user_id)` does not throttle invalid-token guesses.

`v2026.3.24` blob differs. Blame of the still-unthrottled 401 is `bb16ab9e` (Peter Steinberger refactor; no AI marker). Its parent already returned 401 Invalid token with no `InvalidTokenRateLimiter`. That is a move of the AI-introduced path, not a new origin.

Fix `0b4d0733` adds `InvalidTokenRateLimiter` on the 401 path only (`webhook-handler.ts` + tests). `v2026.3.28` contains that fix; `v2026.3.24` does not. This is not GHSA-GW85-XP4Q-5GP9: that advisory is empty `allowedUserIds` fail-open, range `2026.2.22`–`2026.2.23`, fix `0ee30361`. Shared member SHA is not duplication.

KEEP is for squash `03586e3d` at the unthrottled-token-401 scope only.

## Ordinal 211 — NARROW

First-party reviewed GHSA-jv46-xfwm-36j7 / CVE-2026-49454 names `szTheory/relyra`, SAML `SignatureValue` not cryptographically verified, range `>= 1.0.0, < 1.2.0`, patched `1.2.0`. Fix commits named: `2e456897` (candidate arm crypto) and `8910200` (metadata pin).

Atomic `2aeba972` has `Made-with: Cursor` and creates `signature.ex`. Parent lacks the file. `verified_signed_node` returns `{:ok, %SignedNode{}}` for a single candidate with no `:public_key.verify`. `v1.1.0` blame of that arm is still `2aeba972`. `v1.0` and `v1.1.0` share blob `023e3069`. Fix `2e456897` inserts `cryptographically_verify` before building `%SignedNode{}` and is an ancestor of `v1.2.0`, not of `v1.1.0`. `8910200` does not touch `signature.ex`; it is out of this arm's reversal scope.

Release does not close the official range. Hex `1.1.0` and `1.2.0` exist (HTTP 200); Hex `1.0.0` is 404. GitHub Releases match. Git tag `v1.0` exists but `mix.exs` version is `0.1.0`, not `1.0.0`. Using Hex 1.1.0 as a substitute for advisory 1.0.0 is a range workaround, not identity completeness. File-level 1.1.0 origin remains real; GHSA-level KEEP is refused. `release_gate` stays NARROW.

## Sources

| Repo | HEAD | Date |
|------|------|------|
| nesquena/hermes-webui | `5b0246de61dfa0c278e8b5804155a741163481f6` | 2026-08-13T20:44:06+00:00 |
| openclaw/openclaw | `b3d5265f58522bab67e06168d436b3b328cbae60` | 2026-08-13T14:02:39-07:00 |
| szTheory/relyra | `ebee8b38825dcd2002f2b8aa0f8f89b38f63fc1e` | 2026-06-14T19:00:27-04:00 |

Hypothesis input: `herdr-260813-ghsa200-upgrade-b/cases.jsonl` SHA-256 `50493a20909eef41ac835042207a6e5b32fcd82f8c9486185de2e3e62d5cd84f`. Page SHA-256 values are in `result.json`.
