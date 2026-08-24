# Independent red-team of three narrow-recovery-b PASS proposals

**Verdict first: 2 KEEP proposals, 1 NARROW, 0 REJECT, 0 UNKNOWN, 0 BLOCKED.**

This is review only. It is not leader admission, not a canonical-ledger rebuild, and not support for a more-than-200 claim. `causal_admission` is false.

Hostile input: the three PASS rows in `autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high/cases.jsonl` (`GHSA-G3XQ-3GMV-QQ8G`, `GHSA-F38V-77QJ-H4JQ`, `GHSA-PV2J-RGHR-V5R9`). KEEP requires all seven contract gates independently PASS at the exact counted scope. Source-string equality is not release provenance.

| Terminal | GHSA | Disposition |
|---|---|---|
| KEEP (proposal) | GHSA-G3XQ-3GMV-QQ8G | Carrier own-marker plus first-parent hunk; npm 3.5.0/3.5.2 tarball blobs equal git |
| NARROW | GHSA-F38V-77QJ-H4JQ | Patch-delta fails: named residual is the parent import-time JWT default; 0.1.6 maps to v4.6.62, not e0fb8e7 |
| KEEP (proposal) | GHSA-PV2J-RGHR-V5R9 | Wheel 1.6.52/1.6.59 python_tools.py blobs equal 179cab02 / 2adfe7e8; CALLS append is the named residual |

## Headline finding (NARROW)

**GHSA-F38V-77QJ-H4JQ fails `remediation_patch_delta_gate`, `but_for_gate`, `fix_reversal_gate`, and `release_gate`.**

The first-party GHSA is a residual of GHSA-3qg8: praisonai-platform 0.1.4 still boots on `dev-secret-change-me`. The published PoC forges a JWT and calls `_verify_token`. That path never runs `_issue_token`.

Parent `179cab02^` already has the import-time default-open guard `os.environ.get("PLATFORM_ENV", "dev") != "dev"`. Cursor `179cab02` copies that same predicate into `_issue_token`. That is a duplicate sibling, not a new omitted case in an AI-added boundary.

Hashed PyPI 0.1.4 sdist and wheel `auth_service.py` are byte-identical to `179cab02` (content sha256 `cc29d43c…`, git blob `061846a9`). Exact package-to-source mapping of the *vulnerable* artifact therefore succeeds. It does not save patch-delta.

Claimed minimum fix `e0fb8e7` (human Maulana, cites GHSA-3qg8) rewrites import-time `JWT_SECRET` resolution and *deletes* the AI `_issue_token` RuntimeError. PyPI 0.1.6 wheel `auth_service.py` blob `a4caa2bf` and `jwt_secret.py` blob `9b1481e9` equal git `v4.6.62`, not `e0fb8e7` blob `26cde645`. `v4.6.62` pyproject version is `0.1.5`; the published wheel is labeled `0.1.6`. The later wheel does not map to the claimed minimum fix. Repo patched `>= 0.1.5` while PyPI has no 0.1.5.

Worker PASS is refused. Identity, AI-hunk, topology, and uniqueness still PASS. The row stays NARROW.

## KEEP GHSA-G3XQ-3GMV-QQ8G (ordinal 113)

Contribution class: `AI_DIRECT_ROOT`.

Independent first-party GHSA is reviewed, aliases CVE-2026-45136, names npm `claude-code-cache-fix` `>= 3.5.0, < 3.5.2`, patched `3.5.2`. Repository advisory is published.

**Carrier attribution attack failed.** Counted SHA `7b9322a86` is a single-parent squash (parent `9da46315`) with its own `Co-Authored-By: Claude Opus 4.7` trailer. First-parent diff of `tools/quota-statusline.sh` is +75/−19: parent `python3 -c` reads `quota-status.json` from disk and does not interpolate `$input`; the squash introduces `json.loads('''$input''')`. Member `e19169011` is also Claude-marked but is not a `v3.5.0` ancestor and its blob `4d61ea15` is not the released blob. Authorship is not transferred.

**Package mapping succeeded with exact git blobs.** Annotated tag `v3.5.0` object `52e44d31` peels to commit `379da7ec`, which is the npm `3.5.0` `gitHead`. npm tarball `claude-code-cache-fix-3.5.0.tgz` (sha1 `9977aea6`, matches registry) member `package/tools/quota-statusline.sh` `git hash-object` is `626f3494`, equal to `7b9322a86` and `v3.5.0`/`v3.5.1`. npm `3.5.2` tarball member hashes to `853af306`, equal to released squash `613e4df3` (`v3.5.2^{commit}` and npm `3.5.2` `gitHead`). That squash is single-parent, Claude-marked, and its first-parent diff replaces `$input` interpolation with `CC_INPUT` plus `os.environ.get('CC_INPUT')`.

Hostile correction: hypothesis `minimum_fix_set` listed non-ancestor member `0a3e3c13` beside `613e4df3`. Independent KEEP keeps only `613e4df3`. Blob equality of the member is not ancestry.

## KEEP GHSA-PV2J-RGHR-V5R9 (ordinal 188)

Contribution class: `AI_INCOMPLETE_REMEDIATION`. `remediation_patch_delta_gate=PASS`.

Independent first-party GHSA is reviewed, aliases CVE-2026-57120. Global range is `< 1.6.59` patched `1.6.59`. Repository advisory is `<= 1.6.52` patched `>= 1.6.59`. Existential containment uses 1.6.52, which sits in both ranges.

Parent `python_tools.py` has local `_blocked_attrs` and no `_SANDBOX_BLOCKED_CALLS`. Cursor `179cab02` introduces `_SANDBOX_BLOCKED_CALLS` without `format` / `format_map`. The GHSA names that CALLS omission. `2adfe7e8` (also Cursor-coauthored) first-parent inserts one line `'format', 'format_map'` into that same frozenset. That is an amendment of the AI-added boundary, not an untouched sibling path.

**Wheel mapping succeeded with exact git blobs.** PyPI `praisonaiagents-1.6.52-py3-none-any.whl` (sha256 `28e09b51`) member `praisonaiagents/tools/python_tools.py` `git hash-object` is `83c5d833`, equal to `179cab02` and `v4.6.40` through `v4.6.58`. The 1.6.52 wheel therefore is the candidate file, not a later rewrite that merely still contains matching strings. PyPI `1.6.59` wheel (sha256 `30e70d4f`, upload 2026-06-17T07:24:04Z, same minute as git `v4.6.59`) hashes to `fd8d68b7`, equal to `2adfe7e8`.

Shared SHA `179cab02` is the complete `__self__` fix of countable GHSA-4MR5 and the JWT candidate of 169. Uniqueness holds by first-party GHSA identity and sink.

## Attacks that did not stick

- **G3XQ carrier without own first-parent hunk:** the counted squash itself introduces the interpolation. Member-to-carrier transfer was not used.
- **G3XQ npm gitHead vs tag object:** peeled commit equals gitHead; tarball blob equals that commit's file.
- **PV2J wheel merely contains strings:** 1.6.52/1.6.59 python_tools.py blobs equal the claimed git SHAs.
- **PV2J same-SHA duplication with GHSA-4MR5:** different GHSA, different mechanism (`__self__` ATTRS vs format CALLS).
- **F38V 0.1.4 does not map to 179cab02:** it does (blob `061846a9` / sha256 `cc29d43c`). Mapping success is why patch-delta, not identity, is the refusal.

## Method

First-party global GHSA and repository-advisory JSON were reread from the source packet snapshot (hashed in `replay.txt`). Git topology used existing upgrade-b clones read-only under `/tmp/ghsa200-worker-clones/upgrade-b/clones/`. Published npm tarballs and PyPI wheels/sdists were fetched into this lane's `snapshot/artifacts/` and compared with `git hash-object`. Ancestry uses `merge-base --is-ancestor`, never `git tag --contains`. Replay is an executable fail-fast zsh script. Worker PASS is a proposal. No existing tracked file, canonical ledger, or other worker directory was edited. No commit or push.
