# Adversarial negative-control audit of the 2026-08-12 closures

## Outcome

Twenty proposed semantic components were selected deterministically and checked
against seven falsification gates. Results: **15 KEEP, 3 REJECT, 1 NARROW, and
1 UNKNOWN**.

The strongest falsifications are:

1. the Gitea OAuth row is **REJECT** because the AI member contained the safe
   three-field predicate; a later human `refactor` weakened it to the vulnerable
   refresh-token-only predicate before the squash/release;
2. Scriban `GHSA-89CF-6HMV-8RXM` is the lazy-dispatch residual of the already
   counted `GHSA-Q6RR-FM2G-G5X8` array-multiplication/`LoopLimit` component;
3. GitPython `GHSA-3WXW-XV34-2FRG` is a positional-argument bypass of the same
   `TagReference.create --file` guard and arbitrary-read sink already counted in
   `GHSA-3F7W-8RR8-F37F`;
4. the Coolify `CVE-2026-34198` code chain supports only a cold-cache
   contributor, while the atomic AI attribution remains unresolved.

Consequently, the main report's `173` wide release-grade lower bound is not
safe unchanged. These sampled controls alone remove three counted components;
excluding the unresolved Coolify row from a confirmed lower bound yields at
most `169` before any audit of the unsampled rows. This is a claim-boundary
statement, not a replacement census.

## Scope and snapshot boundary

Audit start: `2026-08-12T12:18:07-04:00`  
Primary snapshot: approximately `2026-08-12T12:18-12:33-04:00`  
Checkout: `/home/hanqing/agents/ai-slop`, branch `dev`, HEAD
`6c0d2084fd1240341d6d1b9f9096252490168f0b`.

The checkout was intentionally dirty and shared. At start it had 404 porcelain
entries and `git status --porcelain=v1 -z` SHA-256
`1aa2357ffda639d475c580dbd89ca9ffdd39eb900289c1e9dc7c72f403815a2c`.
At `12:33` it had 405 entries and hash
`96f440a130e4983e79da19d7d15014920ca649544e5c3905c327073d8412df10`;
this shard's owned files and concurrent shards explain why the live status is
not a stable input. No inference depends on the later dirty-tree state.

### Hashed inputs

| Input | mtime / size at snapshot | SHA-256 |
|---|---|---|
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `2026-08-12 11:34:50 -0400`, 27171 bytes | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md` | `2026-08-12 11:34:04 -0400`, 17793 bytes | `f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md` | `2026-08-12 02:19:41 -0400`, 32339 bytes | `a7dd3db373af0fae98c10f8c96c58180cf80fc132fb6fb53fedbd44f3aae22c2` |
| `docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` | `2026-08-12 09:29:36 -0400`, 33896 bytes | `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` |
| `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl` | `2026-08-12 01:33:10 -0400`, 182653 bytes | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| `autoresearch/orchestrator-260811-atomic150/strict-200-v3/summary.json` | snapshot | `69dd6c35de1455bf9cee88420aed570c576a190a4d143202d01a26cc3d37b81e` |
| `research-notes.md` | final supporting pass | `18aa7bba1a78e81f218a943072d5547288a126fa0e104a377776209b1e6e642c` |

Read-only repository heads relied on: BSV Ruby SDK `791b49b7...`,
claude-code-cache-fix `3911f6b0...`, Hermes WebUI `02aa91ba...`, Coolify
`098d3d4c...`, OpenClaw `86075ed7...`, Scriban `b5ac4bf3...`, Gitea
`75efc51e...`, PraisonAI `0e55b360...`, and GitPython `04960cfa...`.
Commit objects are content-addressed, but refs/tags and live APIs were volatile.
No shared clone or cache was mutated by this shard.

### Provenance control

`strict-200-v3/summary.json` says its ledger SHA-256 is
`afc810cec757df378cc63be935a53fe6635dbb7ede72bc32035880ffcde23c23`,
while the referenced ledger bytes hash to `0cc19a49...`. The ledger still
parses as 110 rows / 110 component IDs / 200 case-normalized public IDs, and
the newest main report uses the actual `0cc19a49...` hash. Therefore the
summary's provenance field is rejected; this does not by itself reject the
parsed ledger.

## Deterministic selection and exclusions

Selection used document order, without model scores:

- **Strict (10):** the first ten accepted post-baseline components in the main
  report: all six rows in “新增的 6 个已完整闭合 strict 组件”, followed by the
  first four accepted OpenClaw rows.
- **Incomplete remediation (10):** after removing `COMMIT_ONLY` and explicit
  negative controls from Batch E, take the first five and last five `RELEASED`
  rows. This deterministic boundary sample covers both ends of the table and
  avoids selecting only the middle GitPython block.

“Distinct” means distinct proposed semantic rows at selection time. The dedup
gate is allowed to falsify that premise; it did so twice.

Explicitly excluded from re-adjudication: the frozen 110 strict components;
Batch A's two FAIL rows; OpenClaw's three FAIL rows and excluded card-action
submechanism; the 20/20 supplemental-candidate FAIL closure; Batch E's five
explicit negative controls; all `COMMIT_ONLY` rows; and completed Batch B-D
positives except as dedup comparison controls. Routing/model outputs were not
used as proof.

## Gate definitions

`PB` parent baseline; `BF` deletion/but-for; `AI` atomic AI attribution plus
security-hunk survival into the shipped state; `SM` same-mechanism repair;
`ID` first-party advisory identity; `RC` released containment; `DD` semantic
component dedup.

`P` = pass, `F` = falsified, `N` = only the narrowed claim passes, `U` =
unresolved. For incomplete-remediation rows, `BF` asks whether the candidate
contains a real security delta and whether the later closure addresses its
residual; it does not pretend deletion of a partial fix removes a pre-existing
vulnerability.

## Row-level results

| Row | Proposed component and edge | PB | BF | AI | SM | ID | RC | DD | Verdict | Decisive evidence |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|---|---|
| S01 | BSV ARC; CVE-2026-40069 / GHSA-9HFR; `a1f2e62c -> db97de47` | P | P | P | P | P | P | P | **KEEP** | Parent lacks ARC; candidate creates the broadcaster and narrow failure predicate with a direct Claude trailer. Deletion removes the sink; fix expands the same predicate and vulnerable tags precede 0.8.2. |
| S02 | BSV certificate signature; CVE-2026-40070 / GHSA-HC36; `d14dd19f + 6a4d8984 -> db97de47` | P | P | P | P | P | P | P | **KEEP** | Direct and issuance parents lack/fail-close the surfaces; both Claude commits persist unverified signatures. The shared fix verifies BRC-52 before persistence. Shared fix SHA does not merge the independent ARC and certificate mechanisms. |
| S03 | quota-statusline source injection; CVE-2026-45136 / GHSA-G3XQ; member `e1916901`, carrier `7b9322a8 -> 0a3e3c13` | P | P | P | P | P | P | P | **KEEP** | AI member first interpolates hook JSON inside triple-quoted Python source; deletion removes that data-to-code edge. Patch-equivalent carrier shipped in 3.5.0/3.5.1; fix separates environment data from quoted heredoc source. |
| S04 | Hermes first-password takeover; CVE-2026-49973 / GHSA-P52P; `b8b62722 -> f2ef2851` | P | P | P | P | P | P | P | **KEEP** | Claude commit creates password auth and the unauthenticated first-run settings surface. First-party advisory names remote `_set_password`; fix gates bootstrap to local clients and v0.51.358 contains closure. |
| S05 | Hermes profile session search; CVE-2026-49956 / GHSA-MGXW; `d2b27f6f -> 8d8ae89d` | P | P | P | P | P | P | N | **NARROW** | Multi-profile candidate creates the isolation boundary while leaving existing search unfiltered; fix scopes search to active profile. But frozen strict row CVE-2026-6830 already uses the exact candidate `d2b27f6f`, so “accepted candidate-SHA disjoint” is false. Keep only as a distinct hunk/mechanism from the same multi-feature commit. |
| S06 | Coolify TrustHosts; CVE-2026-34198; `e1fe5863 -> e1d4b468` | P | P | U | N | P | P | P | **UNKNOWN** | Candidate adds the cold-cache early return and it survives to the fix, so that contributor is real. It does not originate older trusted-host/X-Forwarded-Host/reset-link behavior, and its only atomic marker is “Changes auto-committed by Conductor”; no durable first-party AI attribution was found. Do not count as confirmed AI until that gate closes. |
| S07 | OpenClaw MiniMax dotenv redirect; GHSA-H2VW / CVE-2026-44992; `7d7f5d85 -> 2f066965` | P | P | P | P | P | P | P | **KEEP** | Candidate adds a credentialed native TTS surface using `MINIMAX_API_HOST`; fix blocks workspace-dotenv control of that endpoint. Keep as contributor, not sole origin of the older dotenv loader. |
| S08 | OpenClaw `gatewayUrl`; GHSA-G8P2 / CVE-2026-25253; `c74551c2 -> a7534dc2` | P | P | P | P | P | P | P | **KEEP** | Candidate immediately applies query `gatewayUrl`, triggering token-bearing connection; fix makes it pending user confirmation. Direct ancestry and 2026.1.20-to-2026.1.29 release interval close. |
| S09 | OpenClaw prompt image `workspaceOnly`; GHSA-9F72; `8d74578c -> 370d1155` | P | P | P | P | P | P | P | **KEEP** | Candidate creates native prompt/history image loading but omits effective workspace-only policy; fix adds the assertion on the same loader path. Candidate and fix are in released main ancestry. |
| S10 | OpenClaw Browserbase DNS split; GHSA-XQ94 / CVE-2026-43582; `75602014 -> 121c452d` | P | P | P | P | P | P | P | **KEEP** | Candidate adds direct remote `ws/wss` CDP navigation into the older Node-side guard; fix closes resolver split for strict navigation. Keep only as the new Browserbase-surface contributor. |
| E01 | Scriban parser depth; GHSA-6Q7J; `f55280a0 -> 8fdbd687` | P | P | P | P | P | P | P | **KEEP** | Copilot candidate explicitly adds local parser-depth remediation; closure makes shared expression control stop parsing. 7.2.0 contains partial without fix; 7.2.1 is first patched. Parser recursion is distinct from multiplication below. |
| E02 | Gitea OAuth reactivation; CVE-2026-55987 / GHSA-VRHC; AI member `eff673fc`, carrier `c43eb7c3` / backport `2bde4fa5 -> fce961b4` | P | F | F | P | P | P | P | **REJECT** | AI member checks `RefreshToken == "" && AccessToken == "" && ExpiresAt.IsZero()`—the safe signature later restored by the fix. Human member `ea2d313c` changes it to only `RefreshToken == ""`; carriers and v1.26.4 contain that human degradation. The advisory's residual is not the AI hunk. |
| E03 | PraisonAI JWT default; CVE-2026-57148 / GHSA-F38V; `179cab02 -> e0fb8e7d` | P | P | P | P | P | P | P | **KEEP** | Cursor candidate explicitly adds the production guard but defaults unset `PLATFORM_ENV` to dev; closure treats unset as non-dev and randomizes the secret. Repo advisory documents the exact 0.1.4 package bytes and 0.1.5 boundary. Keep only as incomplete remediation. |
| E04 | Coolify shell grammar; CVE-2026-42204 / GHSA-CHG4; `c9922c30 -> 817128c5` | P | P | P | P | P | P | P | **KEEP** | Claude candidate applies `shellSafeCommandRules()` to affected fields but permits bare `&`; closure tokenizes grammar and rejects it. beta.471-beta.473 contain partial, beta.474 is fixed. |
| E05 | GitPython joined clone short options; GHSA-V396; `c9a26789 -> 56806080` | P | P | P | P | P | P | P | **KEEP** | GPT candidate security-fixes shlex-split options but misses joined `-uVALUE/-cVALUE`; closure parses joined/clustered forms. Tag 3.1.50 contains candidate without fix; advisory says 3.1.51 patched. |
| E13 | GitPython dormant multiline config; GHSA-284H; `c417af46 -> 4b4e47fc` | P | P | P | P | P | P | P | **KEEP** | GPT value-write guard leaves a distinct read-existing/unrelated-write reserialization trigger; fix closes that path. Advisory is published; first-party compare shows fix absent from 3.1.58 and contained in 3.1.59. |
| E14 | GitPython `--separate-git-dir`; GHSA-8MCC; `7a4f5dcb -> b68afff4` | P | P | P | P | P | P | P | **KEEP** | GPT clone-option hardening remains incomplete for a different option and arbitrary git-directory sink; exact fix adds it. Published advisory and first-party 3.1.58/3.1.59 comparisons close release containment. |
| E15 | GitPython `Repo.blame --contents/-S`; GHSA-5XXX; `701ce32f -> 1b0d2d9b` | P | P | P | P | P | P | P | **KEEP** | GPT builds revision-output denylist but misses blame's arbitrary-read options; later fix closes those options. This API/input/sink differs from the tag-read duplicate below; official 3.1.58/3.1.59 boundary is closed. |
| E16 | GitPython positional tag `--file`; GHSA-3WXW; `3af0c251 -> 1b0d2d9b` | P | P | P | P | P | P | F | **REJECT** | First-party summary explicitly calls this an incomplete-fix bypass of `3af0c251`. It is the same `TagReference.create`, same `--file/-F` gate, and same arbitrary file-read sink already counted by GHSA-3F7W. Preserve both advisories, count one residual series. |
| E17 | Scriban lazy `array * int`; GHSA-89CF; `2d01bd15 -> 973edd1f` | P | P | P | P | P | P | F | **REJECT** | First-party summary calls it the missed lazy-dispatch sibling/incomplete fix of GHSA-Q6RR. Both use the same multiplication operator, `LoopLimit` invariant, AI remediation and serial closure; only `ScriptArray` versus `ScriptRange` dispatch differs. Preserve IDs, count one component. |

## Detailed negative controls

### Gitea: AI hunk did not survive

First-party raw refs give a clean deletion/survival falsifier:

```text
eff673fc (AI member):
hasExt && extLogin.RefreshToken == "" && extLogin.AccessToken == "" && extLogin.ExpiresAt.IsZero()

ea2d313c (human author wxiaoguang, subject "refactor"):
hasExt && extLogin.RefreshToken == ""

c43eb7c3, fd4641dc, 2bde4fa5, tag v1.26.4:
hasExt && extLogin.RefreshToken == ""

tag v1.27.0 after closure:
hasExt && extLogin.AccessToken == "" && extLogin.RefreshToken == "" && extLogin.ExpiresAt.IsZero()
```

GHSA-VRHC's root cause is precisely that no-refresh providers normally have an
empty refresh token. The AI member already avoided that misclassification. A
carrier-level “security PR had an AI member” attribution would launder the
later human regression back onto the AI member.

### Dedup failures

- Scriban Q6RR and 89CF are a serial incomplete-fix chain over `array * int`
  and the same `LoopLimit` accounting invariant. Concrete runtime dispatch type
  alone is not a stable semantic-component splitter.
- GitPython 3F7W and 3WX are a serial incomplete-fix chain over the exact same
  `TagReference.create --file` arbitrary-read path. Kwarg versus positional
  carrier is a bypass encoding, not a second component.

Public advisory identities remain real and published. The rejection is only
of the additional semantic-component count.

### Narrow and unknown controls

- Hermes CVE-2026-49956 has a plausible independent session-search mechanism,
  but candidate `d2b27f6f` already appears in frozen component
  `CVE-2026-6830 / GHSA-VVFR-G83F-8QCV`. Retract the zero-SHA-intersection
  claim; retain only the distinct hunk/mechanism statement.
- Coolify CVE-2026-34198 has a strong cold-cache contributor delta and release
  chain, but not sole origin of every mechanism in the CNA. The atomic commit
  has no direct model/trailer evidence beyond an auto-commit subject. This is
  `UNKNOWN` for an AI census, never a negative vulnerability finding.

## Exact commands and first-party sources

Representative commands actually used (all repository paths were read-only):

```zsh
sha256sum docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md \
  docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl

git status --porcelain=v1 -z | sha256sum
git -C <repo> show -s --format=fuller <candidate> <fix>
git -C <repo> diff <candidate>^ <candidate> -- <mechanism-path>
git -C <repo> tag --contains <candidate> --no-contains <fix> --sort=version:refname

gh api repos/go-gitea/gitea/pulls/38009/commits --paginate \
  --jq '.[] | [.sha,.commit.author.name,.commit.author.email,.commit.message] | @tsv'
gh api -H 'Accept: application/vnd.github.raw' \
  'repos/go-gitea/gitea/contents/routers/web/auth/oauth.go?ref=eff673fcaf9a4a39d7c1fe93816f7e20a581561e'
gh api -H 'Accept: application/vnd.github.raw' \
  'repos/go-gitea/gitea/contents/routers/web/auth/oauth.go?ref=ea2d313c973d3c00836d0569bcc5bb6825fbe7d7'
gh api -H 'Accept: application/vnd.github.raw' \
  'repos/go-gitea/gitea/contents/routers/web/auth/oauth.go?ref=v1.26.4'
gh api -H 'Accept: application/vnd.github.raw' \
  'repos/go-gitea/gitea/contents/routers/web/auth/oauth.go?ref=v1.27.0'

gh api repos/scriban/scriban/security-advisories/GHSA-q6rr-fm2g-g5x8
gh api repos/scriban/scriban/security-advisories/GHSA-89cf-6hmv-8rxm
gh api repos/gitpython-developers/GitPython/security-advisories/GHSA-3f7w-8rr8-f37f
gh api repos/gitpython-developers/GitPython/security-advisories/GHSA-3wxw-xv34-2frg
gh api repos/gitpython-developers/GitPython/compare/4b4e47fc1224e23b0c8ee7220a7192818f2e4abb...3.1.58
gh api repos/gitpython-developers/GitPython/compare/4b4e47fc1224e23b0c8ee7220a7192818f2e4abb...3.1.59
```

Other exact first-party sources are the repo security-advisory endpoints named
by each GHSA, CVEList CNA JSON for the named CVEs, immutable local Git objects,
and GitHub tag/compare endpoints. At query time all 10 Batch E advisories in
the sample were `published` with `withdrawn_at=null`.

Diagnostic failures were preserved rather than interpreted negatively:

- the first GNU `find -printf` probe used unsupported `%z`; it only emitted a
  warning and was replaced by content/name discovery;
- one `gh api --jq` loop mistakenly passed jq's `--arg` to `gh`; the command
  failed without mutation and was rerun with literal labels;
- the local Gitea mirror lacked the newest PR/fix objects, and local GitPython
  lacked 3.1.58/3.1.59 tags. Precise first-party raw-ref/advisory/compare calls
  supplied the bounded checks; missing local objects were never treated as
  negative evidence.

## Claim boundary

This is an adversarial audit of proposed rows, not a full 173-component rerun.
Local source recovery, ancestry, tests, tags, and advisory status are diagnostic
unless the candidate/fix lineage, security mechanism, atomic AI attribution,
release interval, and semantic dedup all close. `KEEP` means the sampled row
resisted these falsification attempts within the hashed snapshot; it is not a
claim that every statement in its source document was re-proved. `REJECT`
preserves the real advisory and rejects only the proposed AI edge or extra
component count. `UNKNOWN` remains excluded from a confirmed lower bound until
its missing evidence is frozen.

