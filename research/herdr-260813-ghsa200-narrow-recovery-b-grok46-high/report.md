# GHSA 200+ narrow-recovery-b (ordinals 111–211 NARROW/UNKNOWN, excluding already-countable identities)

Lane: `autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high/`

Worker PASS is a proposal, never admission. The leader must independently replay identity, Git topology, and release containment before any row enters a canonical ledger.

This packet is bounded. It reviews only first-party GHSA cases from `final_mechanisms.jsonl` ordinals 111–211 whose audit verdict is NARROW or UNKNOWN, after excluding identities already listed in `herdr-260813-ghsa200-final-candidate-review-codex/result.json` `countable_first_party_ghsa_ids`. It does not review CONFIRM, FALSE_POSITIVE, ordinals 1–110, or fresh identities. Whole-shard completion is not inferred.

## Answer

Three GHSA cases are proposed as seven-gate PASS at the exact scoped mechanism, including released containment. Four UNKNOWN cases stay UNKNOWN. Twenty-six cases stay NARROW. No REJECT or BLOCKED rows. No silent drops.

| Terminal | GHSA cases | Identities |
|---|---:|---|
| PASS (proposal) | 3 | GHSA-G3XQ-3GMV-QQ8G, GHSA-F38V-77QJ-H4JQ, GHSA-PV2J-RGHR-V5R9 |
| NARROW (preserved) | 26 | remaining assigned NARROW, including both ordinal-200 identities |
| UNKNOWN (preserved) | 4 | GHSA-CGJ8-7M5Q-X5GV, GHSA-48P8-G2FX-3WWM, GHSA-MF7V-X7R6-FQ57, GHSA-FP43-VJ7G-PG92 |

Excluded because already countable (not reviewed here): GHSA-3WXW-XV34-2FRG (ordinal 180), GHSA-JV46-XFWM-36J7 (ordinal 211).

Assigned after exclusion: 32 ordinals / 33 first-party GHSA rows (ordinal 200 has two non-aliased identities). Reviewed: 33. Unreviewed among assigned: 0. Conservation: assigned = reviewed + unreviewed (33 = 33 + 0). Unreviewed among the rest of fp211 or other shards: not in scope and not inferred complete.

This packet does not admit a 200-case claim. Routing, commit-subject, merge-carrier-without-marker, and OSV `introduced` evidence were not promoted into causality. AI incomplete-remediation rows were tested under the patch-delta rule.

## Proposed PASS

### 113 `GHSA-G3XQ-3GMV-QQ8G` — quota-statusline triple-quote injection — PASS (proposal)

Contribution class: `AI_DIRECT_ROOT`.

Independent first-party GHSA is reviewed and aliases CVE-2026-45136; repository advisory is published. Affected npm `claude-code-cache-fix` `>=3.5.0, <3.5.2`, patched `3.5.2`.

Squash member `e19169011` is Claude-marked and first interpolates `json.loads('''$input''')`, but it is not a tag ancestor of `v3.5.0` and its `tools/quota-statusline.sh` blob `4d61ea15` is not the released blob. This packet does not transfer that member's authorship onto a later commit.

Origin counted here is Claude-marked carrier `7b9322a86` (`Co-Authored-By: Claude Opus 4.7`). Parent `python3 -c` reads `quota-status.json` from disk and does not interpolate `$input`. Carrier blob `626f3494` equals `v3.5.0` and `v3.5.1`. `merge-base --is-ancestor 7b9322a86 v3.5.0` succeeds. GitHub Releases `v3.5.0` / `v3.5.2` exist and are not drafts. `v3.5.2` uses `json.loads(os.environ.get('CC_INPUT') or '{}')` (blob `853af306`, equal to named fix member `0a3e3c13`). npm `gitHead` for `3.5.0` is neither the git tag nor the origin SHA; containment uses git tag plus GitHub Release. npm `3.5.2` `gitHead` equals the released reversal commit `613e4df3`, which also carries Claude Opus 4.7.

### 169 `GHSA-F38V-77QJ-H4JQ` — JWT default-open `PLATFORM_ENV` — PASS (proposal)

Contribution class: `AI_INCOMPLETE_REMEDIATION`. `remediation_patch_delta_gate=PASS`.

Independent first-party GHSA is reviewed and aliases CVE-2026-57148; repository advisory is published. Package is PyPI `praisonai-platform` `<= 0.1.4`, patched `>= 0.1.5`.

Cursor-coauthored `179cab02` adds `_issue_token` RuntimeError that still treats unset `PLATFORM_ENV` as `dev`. Parent already warned at import with that default; the AI commit materially rewrites the issuance boundary. Hashed PyPI wheel `0.1.4` (`sha256=6c64b97add99510856506ce052155099dd03f89ceb2d9d5b1a849ee89fbc5882`) contains that incomplete issuance guard. PyPI has no `0.1.5`. Hashed wheel `0.1.6` (`sha256=a4e909ba1e6784cac45510b30a0a24b3f89dbc64d775c8f9e08560fa49bcfc8d`) ships `jwt_secret.resolve_jwt_secret()` that refuses the development default unless `PLATFORM_ENV` is explicitly `dev` and otherwise generates an ephemeral key. Missing textual patch version `0.1.5` does not fail release_gate when a real later package contains the same-mechanism reversal. Monorepo git tags `v4.6.x` and pyproject `0.1.4` at the git fix are the wrong product mapping and are counterevidence, not a veto of the hashed wheels. Rollback would reopen broader default-secret JWT issuance; that is allowed for this class.

### 188 `GHSA-PV2J-RGHR-V5R9` — `str.format` omitted from AI CALLS denylist — PASS (proposal)

Contribution class: `AI_INCOMPLETE_REMEDIATION`. `remediation_patch_delta_gate=PASS`.

Independent first-party GHSA is reviewed and aliases CVE-2026-57120. Package is pip `praisonaiagents` `<= 1.6.52`, patched `>= 1.6.59`.

Same Cursor commit `179cab02` introduces `_SANDBOX_BLOCKED_CALLS` without `format` / `format_map`. Parent had only a local `_blocked_attrs` dunder set. Hashed wheel `1.6.52` still has that CALLS frozenset without `format`. `2adfe7e8` appends `format` and `format_map` to the same frozenset and is first in git `v4.6.59` / PyPI `1.6.59` (`sha256=30e70d4f0dfdf9604183d631350c47681dc93ba07c0e3176f6728050d47a0c31`). Extra PyPI versions `1.6.53`–`1.6.58` also omit `format` and do not defeat existential containment of `1.6.52` inside the named affected range. Distinct from countable GHSA-4MR5 (`__self__`) and from 169 (JWT). Shared SHA does not merge mechanisms.

## UNKNOWN preserved

- **116 `GHSA-CGJ8-7M5Q-X5GV`**: published repo advisory (global `/advisories` 404). Candidate `e1fe5863` is `Changes auto-committed by Conductor` with no AI trailer. A later Claude fix is not origin.
- **129 `GHSA-48P8-G2FX-3WWM`**: published repo and global GHSA. Landed objects are single-parent `Merge commit from fork` with Claude trailers. Private-fork members are absent. Trailer on the squash-from-fork object is not hunk provenance.
- **153 `GHSA-MF7V-X7R6-FQ57`**: independent fetch is unreviewed global GHSA with empty `vulnerabilities` and repo advisory 404. Candidate and listed fix first coexist in `v2.5.42` and touch different controllers.
- **154 `GHSA-FP43-VJ7G-PG92`**: published multi-family GHSA. Candidate and listed fix first coexist in `5.4.2` and reverse different named boundaries.

## NARROW preserved (not promoted)

Promotion requires all seven gates PASS at the exact scoped mechanism. Independent first-party fetch and Git replay confirmed the blocking gates below. Prior upgrade-b PASS hypotheses for 170, 192, and 195 were not inherited; patch-delta independently fails those three.

**New-surface / not whole-advisory but-for:** 117, 120, 121, 125, 133. The first-party GHSA names a parent or shared mechanism (MiniMax dotenv host, browser DNS rebinding, sips fail-open, Feishu tools-disablement, SanitizeFilePath HasPrefix including pre-existing fetcher callers). AI added a consumer, ingest path, or new caller. Contract allows counting a narrowed contributor only with a demonstrated material delta of the *named* mechanism; these rows do not close that bar.

**Packed or omnibus identity, with some identity hygiene closed:** 123, 124, 183, 184, 187, 199, 200 (both), 201. Independent fetch can PASS identity for a kept reviewed/published GHSA object (123 `GHSA-2QRV`, 124 `GHSA-G353`, 125 `GHSA-2Q7J`) while topology or but-for still fails. ChurchCRM 200 remains two non-aliased omnibus GHSAs overlapping notes routes. 115 stays identity NARROW: unreviewed empty-vulnerabilities global GHSA and repo 404.

**Squash-member / released-blob topology:** 113 is promoted by counting the AI-marked carrier that *is* the released blob. 126, 133, 156, 186, 187 stay NARROW because the AI member is not a tag ancestor and/or member/carrier/tag blobs are three-way unequal, and unlike 113 the released blob is not an AI-marked origin commit.

**Patch-delta incomplete remediation that is sibling-path or later-layer:** 170 (AI `startswith` is not the 3.1.50 residual; human `14219588` introduced the exact matcher that `56806080` later amends), 189 (flock unwrap never attempted), 192 (parent snapshot SSRF asserts; current-tab is a broader sibling path), 194 (pairing-before-proxy is not scope clamping), 195 (SSE transport untouched by streamable-HTTP scrub), 196 (export.ts never edited), 197 (ClickClack files never edited), 198 (same-chat fallback is a sibling authorization path).

**Release wording / missing tag / git-versus-package without a hashed artifact pair:** 186 (member not ancestor despite 7.5.1/7.6.0 releases), 187 (member not ancestor; 7.2.2 in advisory range has no installer), 201 (patched tag `7.3.2` missing; omnibus CSRF pages).

## Assigned-set accounting

| Population | Count |
|---|---:|
| fp211 mechanisms ordinals 111–211 with verdict NARROW or UNKNOWN | 34 |
| GHSA case rows for those mechanisms | 35 (ordinal 200 has two identities) |
| Excluded already-countable identities | 2 |
| Assigned after exclusion | 33 |
| Reviewed | 33 |
| Unreviewed among assigned | 0 |
| PASS proposals | 3 |
| NARROW preserved | 26 |
| UNKNOWN preserved | 4 |

Ordinals 1–110, CONFIRM, FALSE_POSITIVE, and fresh GHSA discoveries were not assigned and are not implied complete.

## Method

First-party global GHSA and repository-advisory JSON were previously fetched with `gh api` into `snapshot/pages/` and hashed in `snapshot/first_party_objects.jsonl`. This finalize step does not fetch more evidence. `replay.txt` is an executable fail-fast zsh script (`set -euo pipefail`). Git is invoked from a zsh array `git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)` expanded as `"${git_cmd[@]}" -C ...`. Command strings such as `G='git ...'` are not used. The script binds input hashes, asserts assigned = reviewed + unreviewed, checks the three PASS proposals against git topology and snapshot pages, and re-checks preserved NARROW counterexamples. It does not clone, fetch, print credentials, or imply whole-shard completion.

Git replay uses existing clones under `/tmp/ghsa200-worker-clones/upgrade-b/clones/` read-only. Ancestry uses `merge-base --is-ancestor`, never `git tag --contains`. OSV `introduced`, commit subjects, merge-carrier-without-marker, and prior worker votes were routing only.

No existing tracked file, canonical ledger, publication data, or other worker directory was edited. No commit or push.
