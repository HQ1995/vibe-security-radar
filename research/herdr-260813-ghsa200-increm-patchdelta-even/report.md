# Patch-delta review: assigned AI_INCOMPLETE_REMEDIATION even ordinals

**Status: COMPLETE.** Worker PASS rows were hypotheses. This packet independently replayed first-party GHSA objects and Git/tag containment from `/home/hanqing/.cache/ghsa200-worker-clones/increm-patchdelta-even`. A KEEP here is still only a proposal. Causal class is `AI_INCOMPLETE_REMEDIATION` on every row. Old incremred NARROW verdicts are counterevidence only.

Schema: every `AI_INCOMPLETE_REMEDIATION` row records `remediation_patch_delta_gate` in addition to the seven legacy gates. KEEP requires `remediation_patch_delta_gate=PASS` and `but_for_gate=PASS`, with `but_for_gate` interpreted by the patch-delta rule. NARROW rows record `remediation_patch_delta_gate=NARROW`.

Contract test used: patch-delta, not origin rollback but-for. Reverting an AI remediation and reopening a broader old vulnerability is not, by itself, a failure. KEEP requires a first-party GHSA that names a residual inside an AI-authored guard/parser/normalizer/denylist/allowlist, a released artifact that ships that incomplete boundary, and a later same-mechanism fix that directly amends that AI-added boundary for the omitted case. AI hardening surface A while leaving unrelated old surface B untouched is not countable.

| Ordinal | GHSA | Upgrade-b | Old incremred | This review |
|--------:|------|-----------|---------------|-------------|
| 128 | GHSA-4MR5-G6F9-CFRH | PASS | NARROW | **NARROW** |
| 134 | GHSA-WPXJ-VHFP-HHVM | PASS | NARROW | **KEEP** |
| 138 | GHSA-R9MR-M37C-5FR3 | PASS | NARROW | **KEEP** |
| 142 | GHSA-539M-9XH6-Q6RR | PASS | NARROW | **KEEP** |
| 170 | GHSA-V396-V7Q4-X2QJ | PASS | NARROW | **NARROW** |
| 180 | GHSA-3WXW-XV34-2FRG | PASS | NARROW | **KEEP** |
| 192 | GHSA-2X93-H3HG-2XFP | PASS | NARROW | **NARROW** |

## KEEP proposals (4)

### Ordinal 134 - KEEP - GHSA-WPXJ-VHFP-HHVM

Published repo advisory (global `/advisories` 404 reproduced): opfilter bypass via `AUTH_EXCHANGEDATA` and `AUTH_CLONE` after GHSA-25f8; affected `<= 4.2.3` patched `>= 4.2.4`.

Claude Sonnet 4.6 trailer on `a3d1733d` rewrites the ES subscription allowlist from AUTH_OPEN-only to seven additional AUTH_* types and still omits CLONE/EXCHANGEDATA. GitHub Release `v4.2.3-d488a1e` contains the candidate and not `6181c4a2`. `6181c4a2` (also Claude-marked) appends those two event types to the same subscription list and is first in Release `v4.2.4-6181c4a`. The residual is an omitted case in the AI-added allowlist, not an unrelated sibling file.

### Ordinal 138 - KEEP - GHSA-R9MR-M37C-5FR3

Repo and global GHSA: single-character kwarg VALUE token smuggling past `_option_candidates`; `<= 3.1.53` patched `3.1.54`.

GPT 5.6 `701ce32f` introduces `_option_candidates` that collects dashified keys only. Parent has no helper. PyPI/GitHub `3.1.53` contains the candidate and not `e8d0fbf7`. `e8d0fbf7` Refs this GHSA and extends the same helper to dash-prefixed values. Distinct from 142 (archive denylist) and 180 (tag positionals).

### Ordinal 142 - KEEP - GHSA-539M-9XH6-Q6RR

Repo and global GHSA: incomplete `unsafe_git_archive_options` omits `--add-file` / `--add-virtual-file`. Global vulnerabilities array is `<= 3.1.56` patched `3.1.57`. The repo `patched_versions` string `<= 3.1.57` is inconsistent and is not used for containment.

Same AI commit `701ce32f` introduces the denylist with `--exec/--output/-o` only. `7a4f5dcb` names this GHSA and appends the omitted archive options to that list. `3.1.56` residual; `3.1.57` closed. Same SHA as 138 is a different sink and a different first-party GHSA.

### Ordinal 180 - KEEP - GHSA-3WXW-XV34-2FRG

Published repo advisory (global 404 reproduced): title and body name incomplete fix of `3af0c251`; positional `reference="--file=<path>"` bypasses kwargs-only guard; `<= 3.1.58` patched `>= 3.1.59`.

GPT 5.6 `3af0c251` adds `unsafe_git_tag_options` and `Git._option_candidates([], kwargs)`. `1b0d2d9b` changes that same call to `Git._option_candidates([path, reference], kwargs)`. PyPI `3.1.58`/`3.1.59` are unyanked; git tags match. GitHub Releases API for those two tags returned 403 rate-limit on this worker; release_gate uses git+PyPI. This is omitted collection into the AI-added guard, not an unrelated later surface.

## NARROW (3)

### Ordinal 128 - NARROW - GHSA-4MR5-G6F9-CFRH

Repo and global GHSA-4mr5 / CVE-2026-47392: `print.__self__` sandbox leak; `praisonaiagents <= 1.6.39` patched `1.6.40`.

`claude[bot]` `3cd664bf` adds `safe_builtins`. Identity, AI-hunk, topology, and v4.6.39/v4.6.40 containment pass. Patch-delta fails: the advisory residual is `__self__` missing from later AST `_blocked_attrs` (first added by human `cb820212e`). `179cab02` amends that later list, not the AI allowlist. That is a later-layer hole, not an omitted case inside the AI-authored boundary.

### Ordinal 170 - NARROW - GHSA-V396-V7Q4-X2QJ

GHSA names joined shorts on GitPython `= 3.1.50` patched `3.1.51`.

GPT 5.4 `c9a26789` switches clone checking onto shlex tokens while `check_unsafe_options` still uses `startswith` (so `-uVALUE` is already rejected). The 3.1.50 exact matcher is later non-AI `14219588`. `56806080` amends that human matcher. The AI change is not the incomplete boundary the GHSA names.

### Ordinal 192 - NARROW - GHSA-2X93-H3HG-2XFP

Published repo advisory (global 404): snapshot routes miss post-navigation SSRF; `>= 2026.4.14 < 2026.5.26` patched `2026.5.26`.

`[AI]` `b75ad800` adds Chrome-MCP `assertBrowserNavigationResultAllowed` on two branches. Parent `agent.snapshot.ts` already had SSRF asserts. `06047005` applies current-tab validation on a broader snapshot path. That is AI surface A plus untouched/sibling old surface B, which the contract excludes. `v2026.5.22` has candidate not fix; `v2026.5.26` has the later commit. npm `gitHead` is empty.

## Sources

| Repo | HEAD used for replay |
|------|----------------------|
| praisonai | `0e55b360566e16d797bfc81658a4f21527ef05e6` |
| clearancekit | `d94d921492481d05d53143a9ca1c501b3ddd9163` |
| GitPython | `f44c1fb0e5dc3b3f0df58c7834ceed336f0d36fc` |
| openclaw | `b3d5265f58522bab67e06168d436b3b328cbae60` |

Clones and advisory JSON: `/home/hanqing/.cache/ghsa200-worker-clones/increm-patchdelta-even/{clones,pages}/`.

Input hashes: leader `CONTRACT.md` `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`; upgrade-b `cases.jsonl` `50493a20909eef41ac835042207a6e5b32fcd82f8c9486185de2e3e62d5cd84f`.
