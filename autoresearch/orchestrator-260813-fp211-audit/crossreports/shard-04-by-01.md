# FP211 shard-04 independent cross-review (reviewer 01)

Pinned contract: `autoresearch/orchestrator-260813-fp211-audit/AUDIT_CONTRACT.md` at repo `cd97a295956a8d3d46330bf9b0300ddded21f737`.
Rotation: reviewer 01 → shard 04 (ordinals 109–144).
Owned outputs only: `crossreviews/shard-04-by-01.jsonl`, this report.
Raw clones/pages/notes: `/tmp/fp211-cross-01/{clones,pages,notes}`.
No canonical files, first-pass shards/reports, code, caches, or commits were modified.

First-pass `shards/shard-04.jsonl` and `reports/shard-04.md` were treated as hypotheses. Every assigned ordinal was re-checked against independently fetched GHSA/CVE/repo-advisory pages and `git` parent/candidate/fix evidence in `/tmp/fp211-cross-01/clones`. First-pass citations were not treated as proof.

Coverage is mechanical 36/36. That is not 36 confirmed cases.

**Finalization boundary:** new broad discovery stopped. This JSONL and report are materialized from evidence already under `/tmp/fp211-cross-01` plus the independently collected parent/candidate/fix notes. Unclosed gates stay NARROW or UNKNOWN; none were labeled CONFIRM to fill coverage. BLOCKED unused: local clones and first-party pages existed for all 36 ordinals.

## Verdict counts

| Verdict | n | Ordinals |
|---------|---|----------|
| FALSE_POSITIVE | 3 | 109, 140, 144 |
| UNKNOWN | 2 | 116, 129 |
| NARROW | 11 | 110, 113, 115, 117, 120, 121, 123, 124, 125, 126, 133 |
| CONFIRM | 20 | 111, 112, 114, 118, 119, 122, 127, 128, 130–132, 134–139, 141–143 |
| BLOCKED | 0 | — |

CONFIRM/HIGH: **111, 112, 118, 119, 135, 137** (6). First pass also listed **113**; this review demotes 113 to NARROW/HIGH on topology blob mismatch.

132 and 136 remain CONFIRM with `release_gate=NA` (commit-only; incomplete attempt and complete fix share the first released tag).

UNKNOWN 116 and 129 are preserved. Evidence is insufficient for FAIL. 133 is NARROW, not CONFIRM: parent already had `SanitizeFilePath`/`HasPrefix`.

## Public-ID conservation

`public_ids_keep ∪ public_ids_remove` equals each input `public_ids` set. **No public-ID disagreement with first pass.** Rows 109–122 and 126–144 keep every listed ID. Rows **123, 124, 125** still remove the packed non-alias extras (identity_gate=NARROW). Scan of all 211 input `public_ids`: no collisions.

## Every disagreement with first pass

### Verdict disagreements (5)

| Ord | First pass | This review | Why |
|-----|------------|-------------|-----|
| **113** | CONFIRM/HIGH | **NARROW/HIGH** | Origin member blob ≠ released carrier blob for `tools/quota-statusline.sh`. Member `e19169011…` blob `4d61ea1531…`; carrier/`v3.5.0`/`v3.5.1` blob `626f3494c0…`. Both contain `json.loads('''$input''')`, so the mechanism is real, but topology cannot PASS. Fix member `0a3e3c13…` blob `853af30658…` equals `v3.5.2`. |
| **133** | CONFIRM/MEDIUM | **NARROW/MEDIUM** | Parent already defined `SanitizeFilePath`/`HasPrefix`. Claude `0d851525…` only wires that preexisting helper onto Builder.Clean. `but_for` is not closed as sole origin of the advisory helper. Do not CONFIRM. |
| **140** | CONFIRM/MEDIUM | **FALSE_POSITIVE/HIGH** `old_bug_preserving_refactor` | Parent of `701ce32f` already had `unsafe_git_clone_options = [--upload-pack, -u, --config, -c]` with no `--template`. `701ce32f` kept that identical list while rewriting option collection. Deleting the candidate leaves clone `--template` unblocked. Incomplete-remediation requires an explicit same-boundary attempt; merely preceding GHSA-6P8H is insufficient. Contrast **142**, where the same commit *introduces* `unsafe_git_archive_options`. |
| **141** | NARROW/MEDIUM (`uniqueness=NARROW`) | **CONFIRM/MEDIUM** | `54538428` GPT 5.5 added `_assure_config_name_safe` rejecting CR/LF/NUL, leaving unquoted `]`. `1ed1b924` extends the same validator. That is textbook same-boundary incomplete remediation. Sharing the SHA with ordinal 171 / GHSA-MV93 (newline) is not a duplicate: same fix alone does not merge distinct mechanisms. uniqueness NARROW was overuse. |
| **144** | NARROW/MEDIUM (`uniqueness=NARROW`) | **FALSE_POSITIVE/HIGH** `wrong_edge` | `1d51b891` GPT subject is `fix: guard diff output options`; files are `git/diff.py`, `git/index/base.py` (diff path), `test/test_diff.py`. Zero checkout / TagReference / `--prefix` / `--file` hunks. GHSA-3F7W is `IndexFile.checkout()` `--prefix` and `TagReference.create()` `--file`, first added by `3af0c251`. Same pattern as shard-05 ordinal 172. Uniqueness vs ordinal 180 is a later residual of `3af0c251`, not a reason to keep 144 as incomplete-remediation of checkout/tag. |

### Gate-only disagreements (verdict unchanged)

| Ord | Gate | First pass | This review | Why |
|-----|------|------------|-------------|-----|
| **115** | `topology_gate` | PASS | **NARROW** | Fix member `8d8ae89d` `api/routes.py` blob `d5c5be6ab3…` ≠ carrier/`v0.51.269` blob `433317aeb3…`. |
| **115** | `uniqueness_gate` | NARROW | **PASS** | Shared SHA `d2b27f6f` with ordinal 2 dotenv is a distinct invariant (profile search vs dotenv). Same SHA ≠ duplicate. |
| **133** | `but_for_gate` | PASS | **NARROW** | See verdict table. preexisting `SanitizeFilePath` in parent. |
| **121** | `uniqueness_gate` | NARROW | **PASS** | Shared SHA `8d74578c` with 119 is workspaceOnly vs sips decoder; distinct mechanisms. |
| **123** | `uniqueness_gate` | NARROW | **PASS** | Packed extras are an identity problem (`identity_gate` stays NARROW). After remove, no same-mechanism duplicate vs other 211 rows. |
| **124** | `uniqueness_gate` | NARROW | **PASS** | Same: identity NARROW for XH72/44109; uniqueness PASS after remove. |
| **125** | `uniqueness_gate` | NARROW | **PASS** | Same: identity NARROW for W8WF/62188; uniqueness PASS after remove. |
| **140** | `but_for_gate` | PASS | **FAIL** | See verdict table. |
| **141** | `uniqueness_gate` | NARROW | **PASS** | See verdict table. |
| **144** | `ai_hunk_gate` | PASS | **FAIL** | Relevant checkout/tag hunk is not in `1d51b891`. |
| **144** | `but_for_gate` | PASS | **FAIL** | Deleting `1d51b891` leaves checkout/tag unguarded as in parent. |
| **144** | `uniqueness_gate` | NARROW | **PASS** | Wrong-edge FP, not a same-mechanism duplicate of 172. |

### Public-ID disagreements

**None.** Keep/remove sets match first pass on every ordinal, including 123/124/125 packed extras.

### Causal-class / false-positive-class changes (tied to verdict)

- 113: still `AI_DIRECT_ROOT`; topology NARROW only.
- 133: `AI_INCOMPLETE_REMEDIATION` → `AI_NEW_SURFACE_CONTRIBUTOR`.
- 140: `AI_INCOMPLETE_REMEDIATION` → `OLD_BUG_PRESERVING_REFACTOR`; `false_positive_class=old_bug_preserving_refactor`.
- 144: `AI_INCOMPLETE_REMEDIATION` → `WRONG_EDGE`; `false_positive_class=wrong_edge`.

## False-positive counterexamples

### 109 UltraDAG — FALSE_POSITIVE / HIGH (`unreleased_counted_as_released`) — agree with first pass

Keep `CVE-2026-40583` and `GHSA-Q8WX-2CRX-C7PP`. Claude `361e71d4329b672482531122117631ec5358953a` adds `apply_smart_op_tx` fee+nonce before Vote council checks; reversal `2f5a3a237ea519b48d71e6e3093c89f60694c7be`. Peeled `v0.1.0` = `3b0589a20bc3afebed861f664ceb6167a6785770`. `rev-list --count v0.1.0..361e71d4` = **513**. `merge-base --is-ancestor 361e71d4 v0.1.0` fails. Only GitHub Release observed: prerelease `latest`. CNA `affected = 0.1` maps that old tag. Mechanism is real at commit scope; released counting fails.

### 140 GitPython clone `--template` — FALSE_POSITIVE / HIGH (`old_bug_preserving_refactor`) — overturn

Keep `GHSA-6P8H-3WGX-97GF`. Parent of `701ce32fe5ba8cb622c0e0342a376a6beb47d738` already listed clone `--upload-pack/-u/--config/-c` and omitted `--template`. The GPT rewrite of `_option_candidates` did not attempt to complete that denylist. `ffcb5359e87619f4fe4a70a4aff5f08c5580ba97` later adds `--template`; that does not make `701ce32f` the incomplete origin.

### 144 GitPython checkout/tag options — FALSE_POSITIVE / HIGH (`wrong_edge`) — overturn

Keep `GHSA-3F7W-8RR8-F37F`. `1d51b891d7f236044a6aa17498ec682b63dad6e6` guards Diffable.diff / IndexFile.diff `--output` only. Minimum fix of the advisory sinks is `3af0c2516c5e18c829da30338614688f6b69b49c`. Shard-05 ordinal 180 claiming duplicate-of-144 is a later uniqueness note on `3af0c251`, not a reason to count 144.

## UNKNOWN rows (preserved)

### 116 Coolify TrustHosts — UNKNOWN / MEDIUM

Repo advisory `GHSA-CGJ8-7M5Q-X5GV` / `CVE-2026-34198` (global `/advisories` 404). Candidate `e1fe58639756cf7b232458eddd6978e4ed0031f5` is `"Changes auto-committed by Conductor"` with **no AI marker**. It adds the cold-cache early return in `TrustHosts.php`. Fix `e1d4b4682efc898ba5aa3751b2da2072f89c7e24` has a Claude trailer and first appears in `v4.0.0-beta.471`. Code containment holds; AI hunk provenance does not. Do not infer FAIL from a missing marker.

### 129 Argo ArtifactGC — UNKNOWN / MEDIUM

Repo advisory `GHSA-48P8-G2FX-3WWM` / `CVE-2026-54526`. Landed objects `251bb231…` and `2727f3f7…` are single-parent `"Merge commit from fork"` commits with Claude trailers that wholesale-allow `ArtifactGC`. Fixes `358cc396…` (`v3.7.15`) and `277e9cef…` (`v4.0.6`). Private-fork members are **not in the clone**. A trailer on the squash-from-fork object does not prove the ArtifactGC hunk is AI versus human.

## NARROW rows (including 113 demotion)

### 113 statusline injection — topology blob mismatch (overturn from CONFIRM)

AI origin is squash member `e19169011…` (Claude Opus 4.7). Parent had `python3 -c` without `$input` interpolation. Released `v3.5.0`/`v3.5.1` carry the injection on a **different blob** than the origin member. Cannot CONFIRM.

### 110 SolidCAM VMID XML — binary-only

Repo `GHSA-92VG-F4FQ-FXM9` / `CVE-2026-42212`. Peeled `v1.0.0` Claude `d1944bca…` adds `GpplVmidParser`/`ResolveVmidPath` strings absent from parent. Fix `9d0ba808…` = peeled `v1.0.2` (`MaxVmidFileSize`). `v1.0.1` contains origin without the fix. No C# source hunk. `ai_hunk_gate=NARROW`.

### 115 Hermes profile search

Claude `d2b27f6f…` adds profile fields without scoping preexisting `/api/sessions/search`. Fix carrier first in `v0.51.269`. `but_for=NARROW` (new surface). `topology=NARROW` (fix blob mismatch). `uniqueness=PASS` vs ordinal 2 dotenv.

### 117 MiniMax TTS — new surface, not dotenv origin

Parent already reads `MINIMAX_API_HOST` in `minimax-vlm.ts`. Claude `7d7f5d85…` adds TTS `speech-provider`. Fix `2f066965…` first in `v2026.4.20`.

### 120 Browserbase DNS — shared later guard

Claude `75602014…` adds ws/wss Browserbase CDP. Parent already had `cdpUrl`. Fix `121c452d…` is a shared DNS/navigation guard (`v2026.4.10`).

### 121 sips DoS — same candidate as 119, uniqueness PASS

Same SHA `8d74578c…` as 119. Parent already had sips fail-open decode. Global GHSA `cve_id` empty; CNA `CVE-2026-41334` aliases `GHSA-w85g`. Keep both IDs.

### 123/124/125 packed public IDs — identity NARROW, uniqueness PASS

Agree with first-pass keep/remove:

- **123** keep `CVE-2026-41295`+`GHSA-2QRV-RC5X-2G2H`; remove `CVE-2026-43571`+`GHSA-82QX-6VJ7-P8M2` (catalog residual, patched 2026.4.10, separate identifiers/fix).
- **124** keep `CVE-2026-32974`+`GHSA-G353-MGV3-8PCJ`; remove `CVE-2026-44109`+`GHSA-XH72-V6V9-MWHC` (webhook residual + card-action). Ledger SHAs `c3b1ca45…` / `014d7184…` missing from clone. `topology=NARROW`.
- **125** keep `CVE-2026-62187`+`GHSA-2Q7J-2VHX-56G8`; remove `CVE-2026-62188`+`GHSA-W8WF-3QVJ-6XQF`. Both GHSAs repo-only, global 404, `cve_id` null; CNA vendor-advisory refs map each pair. Shared later fix `d4f11d30…` does not alias them.

### 126 zeptoclaw shell filter — multi-purpose squash

Claude blocklist `91f6c2bf…` (in `v0.6.0+`) plus allowlist member `3c4368da…` with empty-Strict passthrough, copied onto carrier `1712debbea60…` (also lands Linux sandbox). Complete `68916c3e…` first in `v0.6.2`. `topology=NARROW`. Keep `GHSA-5WP8-Q9MX-8JX8` only.

### 133 Fission path prefix — preexisting helper, new caller (overturn from CONFIRM)

Claude `0d851525…` wires preexisting `SanitizeFilePath`/`HasPrefix` onto previously unsanitized Builder.Clean. Carrier `5a3d68a3…` first in `v1.23.0`. `os.Root` `8298e33e…` first in `v1.25.0`. Ignore CNA cleanup `5aac6f0b`. Parent already had the advisory helper; `but_for=NARROW`. Not CONFIRM.

## CONFIRM notes

- **111/112 BSV**: Claude `a1f2e62…` introduces ARC with incomplete `REJECTED`/`DOUBLE_SPEND_ATTEMPTED`; `d14dd19f`/`6a4d8984` persist without verify. Minimum fix member `db97de47…` (not merge `4992e8a2`). Origin ancestor of `v0.8.1`; fix first in `v0.8.2`. Shared fix, distinct mechanisms, uniqueness PASS. HIGH.
- **114 Hermes first-user**: unreviewed global GHSA-P52P still lists `CVE-2026-49973`; repo 404. Claude `b8b62722…` adds `_set_password`. MEDIUM.
- **118/119 OpenClaw**: query `gatewayUrl` apply and prompt-image without `workspaceOnly`. HIGH.
- **122 Synology**: squash member `cc048a29…` and carrier `03586e3d…` share webhook-handler blob `d1dae50a…` (topology PASS). Token check before per-`user_id` rate limit. Fix `0b4d0733…` first in `v2026.3.28`. CNA `2026.3.25` is not a git tag. MEDIUM.
- **127/128 PraisonAI**: `claude[bot]` `3cd664bf…` hostname SSRF list **and** restricted-builtins sandbox. Complete `179cab02…` (not CNA merge `b0d8f777`). First complete tag `v4.6.40`. Distinct invariants. MEDIUM.
- **130/132 Fission**: incomplete cap denylist vs standalone container on the same `2db76f65…`/`e484df84…`. 130 released residual `v1.24.0`→`v1.25.0`. 132 complete `695d3e97…` also first in `v1.24.0` (`release_gate=NA`). MEDIUM.
- **131 MCP**: incomplete `safeDialContext`; 6to4/NAT64/site-local in `f5f40bd9…` first `v1.7.7`. MEDIUM.
- **134 ClearanceKit**: Claude `a3d1733d…` AUTH_* expansion omits `AUTH_EXCHANGEDATA`/`AUTH_CLONE`. Hashed tags `v4.2.3-d488a1e` / `v4.2.4-6181c4a`. MEDIUM.
- **135 Fireshare**: Copilot `157386c8…` `secure_filename` leaves public `checkSum` unsanitized. HIGH.
- **136 Kiota**: Copilot bounded percent-decode; complete `430008e9…` shares first tag `v1.34.0`. `release_gate=NA`. MEDIUM.
- **137 vm2**: Claude `46cbbdde…` is peeled `v3.11.1` and rejects only `{nesting:true, require:false}`. Human `01a7552` is **not** an ancestor of `v3.11.1`–`v3.11.3` by merge-base. Complete `86ab819f…` first in `v3.11.4`. HIGH.
- **138/139/142/143 GitPython**: incomplete remediations where the AI commit actually introduced or attempted the advisory boundary (`_option_candidates` value hole; clone-only `expand_vars=False`; **new** archive denylist; `iter_items` `--output` leaving `Commit.count`). MEDIUM.
- **141 GitPython `]`**: CONFIRM/MEDIUM as above (overturn from NARROW uniqueness).

## Shared-SHA uniqueness (not merges)

Same SHA, distinct invariant, both kept; uniqueness PASS unless noted:

| SHA | Rows |
|-----|------|
| `d2b27f6f…` | ordinal 2 dotenv vs 115 profile-search |
| `8d74578c…` | 119 workspaceOnly vs 121 sips |
| `3cd664bf…` / `179cab02…` | 127 SSRF vs 128 python-exec |
| `db97de47…` (fix) | 111 ARC vs 112 cert |
| `2db76f65…` / `e484df84…` | 130 capabilities vs 132 standalone container |
| `701ce32f…` | 138 kwarg / **140 FP clone `--template`** / 142 archive / 143 `Commit.count` |
| `54538428…` | 141 `]` residual vs 171 newline complete fix |
| `1d51b891…` | **144 FP checkout/tag** vs 172 diff `--output` complete fix |

## Replay commands (cross-cutting)

Do **not** use `git tag --contains`. Always:

```bash
git --no-optional-locks -C /tmp/fp211-cross-01/clones/<repo> merge-base --is-ancestor <sha> <tag>; echo $?
```

Decisive blob checks used in this review:

```bash
git -C /tmp/fp211-cross-01/clones/claude-code-cache-fix rev-parse \
  e19169011a7ca59c3ccee67c626c658ba47eb275:tools/quota-statusline.sh \
  7b9322a86a5cae3230c30943bd659d7f67b0387c:tools/quota-statusline.sh \
  v3.5.0:tools/quota-statusline.sh

git -C /tmp/fp211-cross-01/clones/GitPython show \
  701ce32fe5ba8cb622c0e0342a376a6beb47d738^:git/repo/base.py | rg -n 'unsafe_git_clone' -A 12

git -C /tmp/fp211-cross-01/clones/GitPython show --stat \
  1d51b891d7f236044a6aa17498ec682b63dad6e6
```

Identity pages: `/tmp/fp211-cross-01/pages/{ghsa,repo-advisory,cve}/` (uppercase GHSA filenames). Repo-only GHSAs that 404 at `GET /advisories/{id}` were recovered with `gh api repos/{owner}/{repo}/security-advisories/{id}`.

## Limitations

- Binary SolidCAM row has no recoverable C# hunk.
- Argo private-fork history is unavailable; 129 stays UNKNOWN.
- Conductor auto-commits have no AI marker policy in this contract; 116 stays UNKNOWN.
- OpenClaw 124 missing ledger members cannot be invented.
- GHSA `patched_versions` text was wrong for GitPython 142 (`<= 3.1.57`) and several CNA version strings (UltraDAG 0.1, OpenClaw 2026.3.25, Fission `<1.24.0` on 132).
- Uniqueness vs the other 175 canonical rows used the frozen 211-row `public_ids` scan plus mechanism comparison for shared SHAs, not a second full clone pass of those rows.
- 133 is left NARROW rather than CONFIRM because the `HasPrefix` helper pre-existed; no further clone discovery was run at finalization.

## Reusable lessons

1. Topology PASS needs the **released blob** to match the origin-member relevant hunk, or the origin member itself to be an ancestor of the vulnerable tag. Identical injection text on a later carrier blob is not enough for CONFIRM (113). Identical blob on a zero-tag squash member and its carrier *is* enough (122).
2. Incomplete-remediation requires an **explicit same-boundary attempt**. Reusing a preexisting denylist (140) or guarding a sibling API (144) is merely preceding → FALSE_POSITIVE.
3. Introducing a new incomplete denylist in the same commit can still CONFIRM a different row (142 archive vs 140 clone).
4. Uniqueness NARROW is for same-mechanism duplicates, not shared SHAs. Same validator with a leftover character class is CONFIRM, not uniqueness NARROW (141). Packed extra IDs are identity NARROW, not uniqueness NARROW (123–125).
5. Release containment is `merge-base --is-ancestor` of peeled tags, not `git tag --contains` / CNA / OSV `introduced` (137).
6. A Claude trailer on a fix or on a merge-from-fork squash is not origin provenance (116, 129). Preserve UNKNOWN.
7. Same-tag incomplete+complete pairs stay commit-only (`release_gate=NA`) (132, 136).
8. Count cases by public advisory identity. Residual series, sibling tool families, mixed-mechanism later GHSAs, and shared fixes are not aliases.
