# FP211 shard-04 adversarial audit (ordinals 109–144)

Pinned contract: `autoresearch/orchestrator-260813-fp211-audit/AUDIT_CONTRACT.md`.
Owned outputs: `shards/shard-04.jsonl`, this report.
Raw clones/pages: `/tmp/fp211-shard-04/{clones,pages,notes}`.
No canonical files, other shards, caches, or commits were modified.

Coverage is mechanical 36/36 for this shard. That is not 36 confirmed cases.

**Counting rule (follow-up):** final cases are counted by **public advisory identity**. A GHSA and CVE are one identity only when identifiers/CNA actually alias them. Same mechanism, residual series, sibling tool family, or shared fix is **not** an alias. Packed extra identities on ordinals 123/124/125 were moved to `public_ids_remove`.

## Verdict counts

| Verdict | n | Ordinals |
|---------|---|----------|
| FALSE_POSITIVE | 1 | 109 |
| UNKNOWN | 2 | 116, 129 |
| NARROW | 11 | 110, 115, 117, 120, 121, 123, 124, 125, 126, 141, 144 |
| CONFIRM | 22 | 111–114, 118, 119, 122, 127, 128, 130–140 except 132/136 are CONFIRM with `release_gate=NA`; 132, 136 included; 138–140, 142, 143 |
| BLOCKED | 0 | — |

CONFIRM/HIGH (eligible as final without another review): **111, 112, 113, 118, 119, 135, 137** (7).
All other CONFIRMs are MEDIUM and still need independent review per contract.

## Public-ID conservation

`public_ids_keep ∪ public_ids_remove` equals each input `public_ids` set. Rows 109–122 and 126–144 keep every listed ID and remove none. Rows **123, 124, 125** remove the non-alias extra identities (see below).

## False-positive counterexample

### 109 UltraDAG (`strict-200-v3:alias-ff3fa870e1a23f5c964f7fb2`) — FALSE_POSITIVE / HIGH

Keep `CVE-2026-40583` and `GHSA-Q8WX-2CRX-C7PP`. Mechanism is real at commit scope: Claude `361e71d4329b672482531122117631ec5358953a` adds `apply_smart_op_tx` that debits fee and `increment_nonce` before Vote council checks; complete reversal is `2f5a3a237ea519b48d71e6e3093c89f60694c7be`.

Release gate fails. Peeled `v0.1.0` = `3b0589a20bc3afebed861f664ceb6167a6785770`. `git rev-list --count v0.1.0..361e71d4` = **513**. `merge-base --is-ancestor 361e71d4 v0.1.0` fails. The only GitHub Release observed in this audit is prerelease `latest`, also behind origin. CNA `affected = 0.1` maps that old annotated tag. `false_positive_class=unreleased_counted_as_released`.

Replay:

```bash
git -C /tmp/fp211-shard-04/clones/ultradag-core rev-list --count v0.1.0..361e71d4329b672482531122117631ec5358953a
git -C /tmp/fp211-shard-04/clones/ultradag-core merge-base --is-ancestor 361e71d4329b672482531122117631ec5358953a v0.1.0; echo $?
```

## UNKNOWN rows (preserved)

### 116 Coolify TrustHosts — UNKNOWN / MEDIUM

Repo advisory `GHSA-CGJ8-7M5Q-X5GV` / `CVE-2026-34198` (global `/advisories` 404). Candidate `e1fe58639756cf7b232458eddd6978e4ed0031f5` is `"Changes auto-committed by Conductor"` with **no AI marker**. It adds the cold-cache early return in `TrustHosts.php`. Fix member `e1d4b4682efc898ba5aa3751b2da2072f89c7e24` has a Claude trailer and first appears in `v4.0.0-beta.471`. Code containment holds (`beta.437` vs `beta.471`); AI hunk provenance does not. Conductor ≠ atomic AI. `ai_hunk_gate=UNKNOWN`.

### 129 Argo ArtifactGC — UNKNOWN / MEDIUM

Repo advisory `GHSA-48P8-G2FX-3WWM` / `CVE-2026-54526`. Landed objects `251bb231d62a0f4e5e03dcc13c3f2ae456b2fa34` and `2727f3f701677d467dfb5e053c57237cbc752c3c` are single-parent `"Merge commit from fork"` commits with Claude trailers that wholesale-allow `ArtifactGC`. Fixes `358cc396…` (`v3.7.15`) and `277e9cef…` (`v4.0.6`) reverse nested `PodSpecPatch`. Private-fork members are **not in the clone**. A trailer on the GitHub squash-from-fork object does not prove the ArtifactGC hunk is AI versus human. Preserve `UNKNOWN_MINIMUM_ORIGIN_MEMBER_OF_MERGE_FROM_FORK`.

## NARROW counterexamples

### 110 SolidCAM VMID XML — binary-only hunk

Repo `GHSA-92VG-F4FQ-FXM9` / `CVE-2026-42212`. Peeled `v1.0.0` Claude commit `d1944bca…` adds `SolidCAM.GPPL.Server.exe` strings `GpplVmidParser`/`ResolveVmidPath` absent from parent `5fbda15f`. Fix `9d0ba808…` = peeled `v1.0.2` (`MaxVmidFileSize`). `v1.0.1` contains origin without the fix. No C# source hunk exists. Inc-path `492e7fe…` is **not AI** and is a different CVE. `ai_hunk_gate=NARROW`.

### 115 Hermes profile search — shared SHA with ordinal 2

`d2b27f6f1edb83634730f93dc8f19721d877bd07` is also the dotenv origin (ordinal 2 / `CVE-2026-6830`). Parent already had `/api/sessions/search`. Candidate adds profile fields without scoping search. Fix member `8d8ae89d…`, carrier `2c7b5300…` first in `v0.51.269`. Keep `CVE-2026-49956` + `GHSA-MGXW-V6RH-WCV6`. Do not merge with ordinal 2.

### 117 MiniMax TTS — new surface, not dotenv origin

Parent already reads `MINIMAX_API_HOST` in `minimax-vlm.ts`. Claude `7d7f5d85…` adds TTS `speech-provider`. Fix `2f066965…` first in `v2026.4.20`. Keep both IDs as `AI_NEW_SURFACE_CONTRIBUTOR`.

### 120 Browserbase DNS — shared later guard

Claude `75602014…` adds ws/wss Browserbase CDP. Fix `121c452d…` is a shared DNS/navigation guard (`v2026.4.10`). Contributor, not proven sole CDP-rebinding origin.

### 121 sips DoS — same candidate as 119

Same SHA `8d74578c…` as ordinal 119. Parent already had sips fail-open decode; candidate adds ingest. Global GHSA `cve_id` empty; CNA `CVE-2026-41334` aliases `GHSA-w85g`. Keep both IDs. Distinct invariant from workspaceOnly.

### 123 workspace shadow — each public ID (count by identity)

| ID | identity_relation | Mechanism coverage | Disposition |
|----|-------------------|--------------------|-------------|
| GHSA-2QRV-RC5X-2G2H | **FORMAL_ALIAS** of CVE-2026-41295 (`identifiers` + `cve_id`) | Built-in channel setup/login executes an untrusted workspace channel shadow. AI member `fc1b156d…` adds `onlyPluginIds`/`activate:false` scoped snapshots. Reversal `53c29df2…`. First patched `2026.4.2`. | **KEEP** |
| CVE-2026-41295 | **FORMAL_ALIAS** of GHSA-2QRV | Same setup-shadow object. | **KEEP** |
| GHSA-82QX-6VJ7-P8M2 | **FORMAL_ALIAS** of CVE-2026-43571 **only**. Not an alias of 2QRV/41295 (separate identifiers, reporter, fix, patched version). | After `53c29df2…`, setup **catalog lookups** can still include workspace plugin shadows. Reversal `1fede43b…`. First patched `2026.4.10`. | **REMOVE** |
| CVE-2026-43571 | **FORMAL_ALIAS** of GHSA-82QX **only** | Catalog-residual mechanism; not closed by `53c29df2…`. | **REMOVE** |

This row’s public-identity case is **one**: 2QRV↔41295. The residual pair is a second public identity even though it is the same trust *class*. `minimum_fix_set` is only `53c29df2…`. Carrier `f4cc93dc…` first in `v2026.3.22`. `identity_gate`/`uniqueness_gate=NARROW`.

### 124 Feishu webhook — each public ID (count by identity)

| ID | identity_relation | Mechanism coverage | Disposition |
|----|-------------------|--------------------|-------------|
| GHSA-G353-MGV3-8PCJ | **FORMAL_ALIAS** of CVE-2026-32974 | Webhook mode accepts `verificationToken` without `encryptKey`. AI member `b0c67ea0…` adds `Lark.adaptDefault`. Reversal `7844bc89…`. Patched `2026.3.12`. | **KEEP** |
| CVE-2026-32974 | **FORMAL_ALIAS** of GHSA-G353 | Same missing-`encryptKey` webhook object. | **KEEP** |
| GHSA-XH72-V6V9-MWHC | **FORMAL_ALIAS** of CVE-2026-44109 **only**. Not an alias of G353/32974. | Packed **two** mechanisms: webhook residual fail-closed **and** blank card-action callback tokens. Reversal `c8003f1b…`. Patched `2026.4.15`. | **REMOVE** |
| CVE-2026-44109 | **FORMAL_ALIAS** of GHSA-XH72 **only** | Same packed XH72 object; CNA does not alias G353. | **REMOVE** |

This row’s public-identity case is **one**: G353↔32974. Webhook residual ≠ alias; card-action is a different sink and was never this AI candidate. Ledger members `c3b1ca45…` / `014d7184…` still missing. `minimum_fix_set` is only `7844bc89…`. `topology_gate`/`identity_gate`/`uniqueness_gate=NARROW`.

### 125 Feishu tool-gate — each public ID (count by identity)

| ID | identity_relation | Mechanism coverage | Disposition |
|----|-------------------|--------------------|-------------|
| GHSA-2Q7J-2VHX-56G8 | **REPO_ONLY_GHSA_CNA_ALIASED**: published repo advisory, global `/advisories` 404, GitHub `cve_id=null`; CNA CVE-2026-62187 `vendor-advisory` reference names this GHSA | Feishu **tools** ignore per-account disablement. | **KEEP** |
| CVE-2026-62187 | **CNA_FORMAL_ALIAS** of GHSA-2Q7J (via CNA references, not via `GHSA.cve_id`) | Same tools-family gate. | **KEEP** |
| GHSA-W8WF-3QVJ-6XQF | **REPO_ONLY_GHSA_CNA_ALIASED** to CVE-2026-62188 **only**. Not an alias of 2Q7J/62187. | Feishu **permission tools** ignore per-account disablement. | **REMOVE** |
| CVE-2026-62188 | **CNA_FORMAL_ALIAS** of GHSA-W8WF **only** (CNA references `GHSA-w8wf`, not `2q7j`) | Permission-tools family. | **REMOVE** |

This row’s public-identity case is **one**: 2Q7J↔62187. Permission-tools is a separately published identity. Shared later fix `d4f11d30…` (docx/drive/wiki **and** `perm.ts`) does not alias them. Candidate `5f6e1c19…` first in `v2026.2.6`; human `39b5ffda…` is not an origin member. `identity_gate`/`uniqueness_gate`/`but_for_gate=NARROW`.

### 126 zeptoclaw shell filter — multi-purpose squash

Claude blocklist `91f6c2bf…` plus allowlist member `3c4368da…` with empty-Strict passthrough `!self.allowlist.is_empty()`, copied byte-identically onto carrier `1712debbea60…` (also lands Linux sandbox runtimes). Complete `68916c3e…` first in `v0.6.2`. `topology_gate=NARROW`. Keep `GHSA-5WP8-Q9MX-8JX8` only.

### 141 config `]` vs newline sibling

`54538428…` is this row’s incomplete origin **and** the complete fix of `post:gitpython-section-newline` / `GHSA-MV93-W799-CJ2W`. Residual is unquoted `]`. Keep `GHSA-3RP5-JJMW-4WV2`. `uniqueness_gate=NARROW`.

### 144 checkout/tag vs diff-output sibling

`1d51b891…` is this row’s incomplete origin **and** the complete fix of `post:gitpython-diff-output` / `GHSA-FJR4-X663-MWXC`. Residual is checkout + TagReference file options. Keep `GHSA-3F7W-8RR8-F37F`. `uniqueness_gate=NARROW`.

## CONFIRM notes that are not HIGH

- **114**: unreviewed global GHSA-P52P still lists `CVE-2026-49973` in `identifiers`; repo advisory 404. Mechanism (ungated `_set_password`) closes. MEDIUM.
- **122**: squash member `cc048a29…` (0 tags) / carrier `03586e3d…` in `v2026.2.22`; fix `0b4d0733…` in `v2026.3.28`. CNA patched `2026.3.25` is not a git tag. Git ancestry still closes. MEDIUM.
- **127/128**: `3cd664bf…` is `claude[bot]` GitHub App authorship of two distinct incomplete boundaries (SSRF hostname list vs python sandbox). Complete member is `179cab02…` (not CNA merge `b0d8f777…`). First complete tag `v4.6.40`. MEDIUM.
- **130/131/133/134/138–140/142/143**: incomplete remediations with recovered members, merge-base tag windows, MEDIUM.
- **132/136**: incomplete attempt and complete fix share the first released tag (`fission v1.24.0`, `kiota v1.34.0`). `release_gate=NA`, causal class `AI_INCOMPLETE_REMEDIATION_COMMIT_ONLY`. Do not count as released residuals. CNA `affected < 1.24.0` for 132 is wrong for a released window.

## Decisive shared-SHA uniqueness (not merges)

Same SHA, distinct invariant, both kept:

| SHA | Rows |
|-----|------|
| `d2b27f6f…` | ordinal 2 dotenv vs 115 profile-search |
| `8d74578c…` | 119 workspaceOnly vs 121 sips |
| `3cd664bf…` / `179cab02…` | 127 SSRF vs 128 python-exec |
| `db97de47…` (fix) | 111 ARC vs 112 cert |
| `2db76f65…` / `e484df84…` | 130 capabilities vs 132 standalone container |
| `701ce32f…` | 138 kwarg / 140 clone `--template` / 142 archive / 143 `Commit.count` |

## Replay commands (cross-cutting)

Do **not** use `git tag --contains` on shallow clones. vm2 `01a7552` was falsely reported inside `v3.11.1` that way. Always:

```bash
git -C /tmp/fp211-shard-04/clones/<repo> merge-base --is-ancestor <sha> <tag>; echo $?
```

Repo-only GHSAs that 404 at `GET /advisories/{id}` were recovered with `gh api repos/{owner}/{repo}/security-advisories/{id}` into `/tmp/fp211-shard-04/pages/repo-advisory/`.

Identity pages used: `/tmp/fp211-shard-04/pages/{ghsa,repo-advisory,cve}/`.

## Limitations

- Binary SolidCAM row has no recoverable C# hunk.
- Hermes `tag --contains` on old merge members lists tags from `v0.21`; containment for 114/115 used merge-base against `v0.51.357`/`v0.51.269` plus the fix-carrier first-tag lists in `/tmp/fp211-shard-04/notes/`.
- OpenClaw 124 missing ledger members cannot be invented.
- Argo private-fork history is unavailable.
- Conductor auto-commits have no AI marker policy in this contract.
- GHSA `patched_versions` text was wrong for GitPython 142 (`<= 3.1.57`) and several CNA version strings (UltraDAG 0.1, OpenClaw 2026.3.25, Fission `<1.24.0` on 132).
- Uniqueness vs the other 175 canonical rows used the frozen ledger `declared_public_ids` / `canonical_component_id` scan, not a second full clone pass of those rows.

## Reusable lessons

1. Release containment is merge-base ancestry of peeled tags, not CNA/`git tag --contains`/OSV `introduced`.
2. A Claude trailer on a fix or on a merge-from-fork squash is not origin provenance.
3. Conductor auto-commit ≠ AI hunk.
4. Shared candidate or shared fix is not a duplicate when source/sink/invariant differ; it is NARROW uniqueness when the candidate **is** another row’s complete fix.
5. Count cases by public advisory identity. Formal alias = GHSA `identifiers`/`cve_id` or CNA vendor-advisory reference. Residual series, sibling tool families, mixed-mechanism later GHSAs, and shared fixes are **not** aliases: put them in `public_ids_remove` on the packed row.
6. Same-tag incomplete+complete pairs stay commit-only (`release_gate=NA`).
7. Decompose advisory-named merges (`4992e8a2`, `b0d8f777`, `1126e541`, `613e4df3`) to the minimum member.
8. Global GHSA 404 is not identity failure when the repo advisory or CNA still names the ID.
9. A CNA that points at one repo GHSA does not alias a sibling GHSA even when one git fix touches both files.
