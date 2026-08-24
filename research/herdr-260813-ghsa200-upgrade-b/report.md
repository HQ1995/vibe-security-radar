# GHSA 200+ upgrade-b (ordinals 111–211, NARROW/UNKNOWN/CONFIRM-MEDIUM)

Lane: `autoresearch/herdr-260813-ghsa200-upgrade-b/`
Worker PASS is a proposal. The leader must independently replay identity, topology, and release containment.

Assigned population: 48 fp211 mechanism ordinals / 49 first-party GHSA cases (ordinal 200 has two non-aliased GHSAs). Scope is every NARROW, UNKNOWN, or CONFIRM/MEDIUM row in ordinals 111–211. Ordinals 1–110, CONFIRM/HIGH, and fresh identities were not reviewed.

The contract's countable lower bound is **48 released** seven-gate cases, not 65 CONFIRM rows. Reaching more than 200 still requires at least 153 net new admissions. This packet proposes 15 and does not close that gap.

`result.json` `assigned_set_equality` is computed from `leader/baseline.json` `upgrade_b.ordinals` versus `cases.jsonl`. COMPLETE is written only after that set equality holds (48 ordinals, 49 GHSA rows, missing=[], extra=[]). CONFIRM/MEDIUM ordinals 114, 122, 127, 128, 130, 131, 132, 134, 136, 138, 139, 141, 142, 143 each have a terminal row. None were treated as out of lane.

## Answer

Fifteen GHSA cases are proposed as seven-gate PASS at GHSA-case scope including released containment. Four UNKNOWN cases stay UNKNOWN. Thirty cases stay NARROW, including four CONFIRM/MEDIUM rows demoted on independent review (114 identity, 130 topology, 132/136 `release_gate=NA`). No REJECT or BLOCKED rows. No silent drops.

| Terminal | GHSA cases | Ordinals |
|---|---:|---|
| PASS (proposal) | 15 | 122, 127, 128, 131, 134, 138, 139, 141, 142, 143, 170, 180, 192, 195, 211 |
| NARROW | 30 | remaining assigned NARROW, plus 114, 130, 132, 136, including 200 twice |
| UNKNOWN (preserved) | 4 | 116, 129, 153, 154 |

This packet does not admit a 200-case claim. New-surface contributors, omnibus identities, squash-member/tag-ancestor gaps, git-versus-package version mismatches, and same-tag origin+fix residuals were not promoted.

## Proposed PASS from CONFIRM/MEDIUM (independent review)

CONFIRM/HIGH was left untouched. Each CONFIRM/MEDIUM row was replayed against first-party GHSA objects, `merge-base --is-ancestor`, and released artifacts. Ten close all seven gates including released containment. Four stay NARROW (114 identity, 130 topology, 132/136 commit-only).

### 114 `GHSA-P52P-4VMG-4VQ3` — Hermes first-user `_set_password` — NARROW (identity)

Claude Opus 4.6 `b8b62722` does add ungated `_set_password`, and GitHub Releases `v0.51.357` / `v0.51.358` contain origin vs local gate. Independent review still fails `identity_gate`: global GHSA `type=unreviewed`, `vulnerabilities=[]`, `repository_advisory_url` null, repo advisory API 404. CVE alias plus a matching hunk is not a first-party GHSA object that names repository, mechanism, and package range. Not countable. Distinct from ordinal 115 profile-search.

### 122 `GHSA-MF5G-6R6F-GHHM` — OpenClaw Synology token guesses

Direct root. Claude squash member `cc048a29` and carrier `03586e3d` share webhook-handler.ts blob `d1dae50a`, also the `v2026.2.22` blob. Invalid tokens 401 with no guess throttle. CNA patched `2026.3.25` does not exist as git or npm. npm/git `2026.3.24` (`gitHead` matches the git tag) is last vulnerable; `2026.3.28` contains `0b4d0733`.

### 127 `GHSA-5C6W-WWFQ-7QQM` — PraisonAI spider SSRF encodings

Incomplete remediation. `claude[bot]` `3cd664bf` adds an exact-hostname SSRF list. Hex/int loopback encodings remain in git `v4.6.39` / PyPI `praisonaiagents 1.6.39` and `PraisonAI 4.6.39`. Cursor-trailer `179cab02` is first in `v4.6.40` / `1.6.40` / `4.6.40`. Unlike ordinal 169, these package version files map onto PyPI.

### 128 `GHSA-4MR5-G6F9-CFRH` — PraisonAI `print.__self__`

Same SHAs as 127, different invariant: restricted builtins leave C-builtin `__self__` leakage. `__self__` is absent in `v4.6.39` and present in `v4.6.40`. Uniqueness PASS against 127 and against 169 (JWT origin of `179cab02`).

### 130 `GHSA-QF5V-M7P4-95RP` — Fission `SYS_TIME` denylist — NARROW (topology)

Incomplete denylist is real: `v1.24.0` still has `dangerousCapabilities` without `SYS_TIME`; allowlist `2569b42b` is first in `v1.25.0`. Independent review fails `topology_gate` on the same bar as 113/186. Member `2db76f65` is not a tag ancestor. `podspec_safety.go` blobs are three-way unequal (member `af473d26`, carrier `330fccee`, `v1.24.0` `1d7219e7`). Contract: an AI carrier is insufficient to transfer authorship. Not countable.

### 131 `GHSA-R48C-V28R-PF6V` — MCP Registry 6to4/NAT64 SSRF

Incomplete remediation. Origin is the AI-marked tag commit `1201cbd8`, which **is** git tag `v1.7.5` (`Generated with Claude Code` plus Claude Opus 4.7 trailer) and still omits 6to4/NAT64/site-local. Squash source `257eb178` is not a tag ancestor and `http.go` blob `e40dd2a6` ≠ shipped blob `7d73d523`; that member is not the origin. GitHub Releases `v1.7.5`/`v1.7.6` are vulnerable (blob-equal); `f5f40bd9` is first in `v1.7.7`.

### 134 `GHSA-WPXJ-VHFP-HHVM` — ClearanceKit AUTH_CLONE

Incomplete remediation. Claude `a3d1733d` expands AUTH_* intercepts and omits `AUTH_EXCHANGEDATA` / `AUTH_CLONE`. Global `/advisories` 404; identity is the published repository advisory. Unhashed `v4.2.3`/`v4.2.4` tags 404. GitHub Releases `v4.2.3-d488a1e` / `v4.2.4-6181c4a` are the released pair.

### 138 `GHSA-R9MR-M37C-5FR3` — GitPython kwarg value tokens

Incomplete remediation. GPT 5.6 `701ce32f` adds `_option_candidates` from kwarg keys only. Dash-prefixed values of single-character kwargs become separate argv tokens. PyPI/GitHub `3.1.53` residual; `e8d0fbf7` first in `3.1.54`. Distinct from 170 (joined short options after shlex) and 180 (positional `--file`).

### 139 `GHSA-94P4-4CQ8-9G67` — GitPython Remote/Submodule `expand_vars`

Incomplete remediation of the clone-only URL-env attempt `8ac5a305`. Remote/Submodule still expand. GHSA `<=3.1.53` understates git: `3.1.54` is still residual; `86341745` is first in `3.1.55`.

### 141 `GHSA-3RP5-JJMW-4WV2` — GitPython unquoted `]` sections

Incomplete charset. GPT 5.5 `54538428` rejects CR/LF/NUL names and leaves unquoted `]`. That SHA is also the complete fix of ordinal 171 / `GHSA-MV93` (CR/LF/NUL); identifiers do not alias. PyPI `3.1.52` / `3.1.53`.

### 142 `GHSA-539M-9XH6-Q6RR` — GitPython archive `--add-file`

`701ce32f` introduces `unsafe_git_archive_options` without `--add-file` / `--add-virtual-file`. Last residual `3.1.56`; `7a4f5dcb` first in `3.1.57`. Shared origin SHA with 138/143 is a different sink.

### 143 `GHSA-P538-C434-8V24` — GitPython `Commit.count --output`

`701ce32f` guards `iter_items` and leaves `Commit.count` unguarded. Human `38553b6f` (GPT co-author) is the reversal. GHSA summary `<=3.1.53` is stale; vulnerabilities array and git agree on `3.1.55` / `3.1.56`.

## Proposed PASS from NARROW (unchanged)

### 170 `GHSA-V396-V7Q4-X2QJ` — GitPython joined short options

Incomplete remediation. GPT 5.4 `c9a26789` switches clone `multi_options` checking onto shlex-split tokens. Joined short options (`-uVALUE`, `-fuVALUE`) still bypass the gate. Repo and global GHSA name GitPython `= 3.1.50` patched `3.1.51`. Git ancestry, GitHub Releases, and PyPI wheels all exist for that pair: `3.1.50` contains the candidate and not `56806080`; `3.1.51` contains the reversal. Tags `3.1.47`–`3.1.49` are extra vulnerable git history and do not defeat the advisory pair.

### 180 `GHSA-3WXW-XV34-2FRG` — GitPython positional `--file`

Incomplete remediation of the kwargs-only `--file`/`-F` guard added by GPT 5.6 `3af0c251`. The published repository advisory (global `/advisories` 404) names the positional `TagReference.create` residual. `3.1.58` contains the incomplete guard; `3.1.59` / `1b0d2d9b` includes positional tokens in the same check. Uniqueness PASS: ordinal 144 (`GHSA-3F7W`) is a FALSE_POSITIVE wrong-edge and is not a counted same-mechanism case; ordinal 179 (`GHSA-5XXX`) shares only the later fix SHA and is a blame `--contents` residual.

### 192 `GHSA-2X93-H3HG-2XFP` — OpenClaw snapshot current-tab SSRF

Incomplete remediation. Atomic commit `b75ad800` is titled with `[AI]` and adds snapshot/screenshot/tab SSRF checks that still miss current-tab / post-navigation validation. Repository advisory range `>= 2026.4.14, < 2026.5.26`. npm/git `2026.5.22` contains the candidate and not `06047005`; `2026.5.26` contains the reversal. Global GHSA 404; identity is the published repo advisory. npm `gitHead` is empty; containment is matching git tags plus npm version names.

### 195 `GHSA-9C3V-684M-579C` — OpenClaw MCP SSE redirect Authorization

Incomplete remediation of the same redirect-Authorization invariant. `[AI]` commit `47eb2d48` scrubs streamable-HTTP MCP redirects and leaves SSE. Global and repo GHSA name patched `2026.6.5`. npm/git `2026.6.1` contains the candidate and not `3c6259eb`; `2026.6.5` adds fetch-guard redirect Authorization retention. Countable only for that residual, not as origin of SSE itself.

### 211 `GHSA-JV46-XFWM-36J7` — Relyra SAML SignatureValue

Direct root. `2aeba972` (`Made-with: Cursor`) creates `signature.ex` whose `verified_signed_node/4` returns `{:ok, %SignedNode{}}` after shape/trust checks with no SignatureValue crypto. Parent lacks the file. Hex `1.1.0` / git `v1.1.0` / GitHub Release still have the no-crypto arm. Hex `1.2.0` / git `v1.2.0` contain `2e456897` cryptographic verification. Advisory string `1.0.0` does not exist as a git tag or Hex release; `v1.0` still has mix version `0.1.0`. Published Hex `1.1.0` is inside `>= 1.0.0, < 1.2.0` and is the vulnerable artifact used here. The origin member is a tag ancestor of `v1.1.0`; later blob drift does not transfer authorship from a carrier.

## UNKNOWN preserved

### 116 `GHSA-CGJ8-7M5Q-X5GV` Coolify TrustHosts

Repo advisory published (`CVE-2026-34198`); global `/advisories` 404. Candidate `e1fe5863` subject is `Changes auto-committed by Conductor` with no model trailer. Containment `v4.0.0-beta.437` through `beta.470`, fix Claude `e1d4b468` in `beta.471` is real. Conductor is not an atomic AI marker. Keep UNKNOWN.

### 129 `GHSA-48P8-G2FX-3WWM` Argo ArtifactGC

Repo and global GHSA published (`CVE-2026-54526`), incomplete fix of CVE-2026-31892. Landed objects `251bb231` / `2727f3f7` are single-parent `Merge commit from fork` with Claude trailers. Private-fork members are not in the clone. A trailer on the GitHub squash-from-fork object does not prove the ArtifactGC hunk is AI versus human. Keep UNKNOWN.

### 153 `GHSA-MF7V-X7R6-FQ57` MISP mass assignment

Global GHSA aliases `CVE-2026-56422`; repo advisory 404. Candidate `bc182d55` and listed fix `025f7115` are both Claude mass-assignment sweeps and first appear together in `v2.5.42`. Multi-fix advisory remains unclosed: no candidate-only released artifact and no single minimum reversal of the named controllers. Keep UNKNOWN.

### 154 `GHSA-FP43-VJ7G-PG92` OmniFaces combined-resource IDs

Repo and global GHSA published. Candidate `aa42da36` and listed fix `a52b9246` are both Claude commits and first appear together in git tag `5.4.2`. The advisory names several version families and additional output/push boundaries. Same-tag origin+fix and unclosed multi-fix set stay UNKNOWN.

## NARROW preserved (not promoted)

Promotion requires all seven gates PASS at GHSA-case scope. These rows keep a real AI contribution at a narrowed scope, or keep an unclosed gate.

**New-surface / not whole-advisory but-for:** 115, 117, 120, 121, 125, 133, 156, 198. Parent already had the sink or a sibling surface; AI added a consumer or ingest path. Contract allows counting only at explicit narrowed scope, not as a GHSA-case CONFIRM.

**Packed or omnibus identity:** 123, 124, 183, 184, 187, 188, 199, 200, 201. Extra GHSAs are not formal aliases; ChurchCRM 200 is two non-aliased GHSAs overlapping notes routes inside larger advisories. Identity stays NARROW. `public_ids_remove` already recorded for 123/124 is preserved.

**Squash-member / released-blob topology:** 113, 126, 130, 156. Origin member is not a tag ancestor and/or the released blob is not the origin blob. Carrier AI markers are not transferred across commits. 113 npm `3.5.0` `gitHead` is neither member nor carrier. 130 is a CONFIRM/MEDIUM demotion on that same bar.

**CONFIRM/MEDIUM demoted to NARROW (not countable):**

- 114 `GHSA-P52P-4VMG-4VQ3`: `identity_gate=NARROW`. Unreviewed global GHSA, empty `vulnerabilities`, repo advisory 404.
- 130 `GHSA-QF5V-M7P4-95RP`: `topology_gate=NARROW`. Member/carrier/`v1.24.0` blobs three-way unequal; member not a tag ancestor.
- 132 `GHSA-M63V-2G9W-2W6V`: Claude PodSpec safety left standalone `Runtime.Container` / `Builder.Container` unchecked. Carrier `e484df84` and complete `695d3e97` are both first in GitHub Release `v1.24.0`, absent from `v1.23.0`. `release_gate=NA`. CNA `<1.24.0` does not describe a released residual window.
- 136 `GHSA-P5RM-JG5C-8C77`: Copilot bounded percent-decode and the NUL/homoglyph complete fix are both first in `v1.34.0`, absent from `v1.33.0`. Advisory `<=1.33.0` patched `1.34.0` is not a released residual. `release_gate=NA`.

**Release wording still not GHSA-case closed:** 169, 186, 189, 194, 196, 197. Re-checked and still not promoted:

- 169: Cursor `179cab02` incomplete JWT default-open guard is real, but `praisonai-platform` pyproject remains `0.1.4` at the git fix; PyPI `0.1.6` is not mapped from git tags `v4.6.x`.
- 186: OTP-failure lockout residual is in GitHub Release `7.5.1` and closed in `7.6.0`, but AI member `cbea916e` is not a tag ancestor and `public-user.php` blobs diverge (member ≠ carrier ≠ `7.5.1`). Same topology bar that keeps 113 NARROW.
- 197: GHSA names ClickClack `toolsAllow`; candidate did not edit ClickClack files. Incomplete-remediation PASS is only for a residual created by the AI attempt; this stays NARROW rather than a silent sibling promotion.

**Uniqueness already closed except 180 (now PASS).** Other uniqueness notes remain PASS.

## Terminal row per assigned ordinal

| Ord | Case | Baseline | Terminal | Blocking gate(s) |
|---:|---|---|---|---|
| 113 | GHSA-G3XQ-3GMV-QQ8G | NARROW | NARROW | topology |
| 114 | GHSA-P52P-4VMG-4VQ3 | CONFIRM/MEDIUM | NARROW | identity (unreviewed empty vulns, repo 404) |
| 115 | GHSA-MGXW-V6RH-WCV6 | NARROW | NARROW | topology, but-for |
| 116 | GHSA-CGJ8-7M5Q-X5GV | UNKNOWN | UNKNOWN | ai_hunk, but-for |
| 117 | GHSA-H2VW-PH2C-JVWF | NARROW | NARROW | but-for |
| 120 | GHSA-XQ94-R468-QWGJ | NARROW | NARROW | but-for |
| 121 | GHSA-W85G-3H6X-4XH2 | NARROW | NARROW | but-for |
| 122 | GHSA-MF5G-6R6F-GHHM | CONFIRM/MEDIUM | **PASS** | (all closed) |
| 123 | GHSA-2QRV-RC5X-2G2H | NARROW | NARROW | identity |
| 124 | GHSA-G353-MGV3-8PCJ | NARROW | NARROW | identity, topology |
| 125 | GHSA-2Q7J-2VHX-56G8 | NARROW | NARROW | identity, but-for |
| 126 | GHSA-5WP8-Q9MX-8JX8 | NARROW | NARROW | topology |
| 127 | GHSA-5C6W-WWFQ-7QQM | CONFIRM/MEDIUM | **PASS** | (all closed) |
| 128 | GHSA-4MR5-G6F9-CFRH | CONFIRM/MEDIUM | **PASS** | (all closed) |
| 129 | GHSA-48P8-G2FX-3WWM | UNKNOWN | UNKNOWN | ai_hunk, topology, but-for |
| 130 | GHSA-QF5V-M7P4-95RP | CONFIRM/MEDIUM | NARROW | topology (member/carrier/tag blobs diverge) |
| 131 | GHSA-R48C-V28R-PF6V | CONFIRM/MEDIUM | **PASS** | (all closed) |
| 132 | GHSA-M63V-2G9W-2W6V | CONFIRM/MEDIUM | NARROW | release (commit-only same first tag) |
| 133 | GHSA-R5JH-Q2MW-GCX4 | NARROW | NARROW | but-for |
| 134 | GHSA-WPXJ-VHFP-HHVM | CONFIRM/MEDIUM | **PASS** | (all closed) |
| 136 | GHSA-P5RM-JG5C-8C77 | CONFIRM/MEDIUM | NARROW | release (commit-only same first tag) |
| 138 | GHSA-R9MR-M37C-5FR3 | CONFIRM/MEDIUM | **PASS** | (all closed) |
| 139 | GHSA-94P4-4CQ8-9G67 | CONFIRM/MEDIUM | **PASS** | (all closed) |
| 141 | GHSA-3RP5-JJMW-4WV2 | CONFIRM/MEDIUM | **PASS** | (all closed) |
| 142 | GHSA-539M-9XH6-Q6RR | CONFIRM/MEDIUM | **PASS** | (all closed) |
| 143 | GHSA-P538-C434-8V24 | CONFIRM/MEDIUM | **PASS** | (all closed) |
| 153 | GHSA-MF7V-X7R6-FQ57 | UNKNOWN | UNKNOWN | ai_hunk, topology, but-for, fix_reversal, release |
| 154 | GHSA-FP43-VJ7G-PG92 | UNKNOWN | UNKNOWN | ai_hunk, but-for, fix_reversal, release |
| 156 | GHSA-X34R-63HX-W57F | NARROW | NARROW | topology |
| 169 | GHSA-F38V-77QJ-H4JQ | NARROW | NARROW | release |
| 170 | GHSA-V396-V7Q4-X2QJ | NARROW | **PASS** | (all closed) |
| 180 | GHSA-3WXW-XV34-2FRG | NARROW | **PASS** | (all closed) |
| 183 | GHSA-MFMP-Q643-VJ39 | NARROW | NARROW | identity, but-for |
| 184 | GHSA-M649-24Q9-Q6R4 | NARROW | NARROW | identity, but-for |
| 186 | GHSA-F2FQ-4RMP-9X8C | NARROW | NARROW | release (topology also squash-member/tag-ancestor) |
| 187 | GHSA-37MF-VQ43-5QP9 | NARROW | NARROW | identity, release |
| 188 | GHSA-PV2J-RGHR-V5R9 | NARROW | NARROW | identity, release |
| 189 | GHSA-3FP5-V549-9V66 | NARROW | NARROW | but-for, release |
| 192 | GHSA-2X93-H3HG-2XFP | NARROW | **PASS** | (all closed) |
| 194 | GHSA-QJPC-QF9M-XWMR | NARROW | NARROW | but-for, release |
| 195 | GHSA-9C3V-684M-579C | NARROW | **PASS** | (all closed) |
| 196 | GHSA-J4CX-JVQ7-79VM | NARROW | NARROW | but-for, release |
| 197 | GHSA-WP73-F3GG-W4VR | NARROW | NARROW | release (ClickClack unattempted) |
| 198 | GHSA-7JX6-764P-FGG9 | NARROW | NARROW | but-for |
| 199 | GHSA-2HFG-4FH4-QP7F | NARROW | NARROW | identity, ai_hunk, release |
| 200 | GHSA-3J8Q-FWPJ-F8J5 | NARROW | NARROW | identity (omnibus) |
| 200 | GHSA-JJCJ-H3CM-P7X7 | NARROW | NARROW | identity (omnibus) |
| 201 | GHSA-JX5R-P82P-2P8M | NARROW | NARROW | identity, release |
| 211 | GHSA-JV46-XFWM-36J7 | NARROW | **PASS** | (all closed) |

## Method and limits

First-party GHSA, repository-advisory, GitHub Release, PyPI, npm, and Hex objects were saved under `snapshot/pages/` and hashed in `snapshot/first_party_objects.jsonl`. A GitHub token was used only as a request credential and is not printed or cited as evidence. A machine no-secret scan (`snapshot/no_secret_scan.json`, also copied into `result.json`) classified every `Authorization`/`Bearer` word hit as CWE taxonomy, advisory mechanism prose, or the GitPython changelog redaction sentence. No `ghp_`, `github_pat_`, `Bearer` + non-placeholder token, raw `Authorization:` header value, or live API-key assignment was present, so no redaction was required. Git clones, tags, and candidate/fix objects live under `/tmp/ghsa200-worker-clones/upgrade-b/`, except mcp-registry, clearancekit, and kiota, which were replayed from `/tmp/fp211-cross-01/clones/` because the `/tmp` root filesystem was full. Ancestry always used `merge-base --is-ancestor`, never `git tag --contains`. Package and GitHub Release metadata were used only as release artifacts, not as causality. OSV `introduced`, commit subjects, and prior fp211 votes were routing only. CONFIRM/MEDIUM baseline votes were not treated as proof.

`cases.jsonl` covers exactly the 48 ordinals in `leader/baseline.json` upgrade-b (49 GHSA rows because ordinal 200 has two non-aliased identities). All 14 CONFIRM/MEDIUM ordinals have terminal rows. Unpromoted NARROW/UNKNOWN failures are preserved.

No existing tracked file, canonical ledger, or other worker directory was edited. No commit or push. Worker PASS is not admission.
