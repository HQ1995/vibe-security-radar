# Adversarial negative-control research notes

Snapshot taken 2026-08-12 around 12:18-12:55 America/New_York. The checkout and
shared caches were treated as volatile/read-only. No claim below assumes that a
path still has the same bytes after the recorded digest.

## Scope and frozen inputs

Newest closure inputs at snapshot time:

| input | mtime / bytes | SHA-256 |
|---|---|---|
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | 2026-08-12 11:34:50 -0400 / 27171 | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md` | 2026-08-12 11:34:04 -0400 / 17793 | `f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad` |
| `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl` | 2026-08-12 01:33:10 -0400 / 182653 | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| `autoresearch/orchestrator-260811-atomic150/strict-200-v3/summary.json` | snapshot | `69dd6c35de1455bf9cee88420aed570c576a190a4d143202d01a26cc3d37b81e` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md` | snapshot | `a7dd3db373af0fae98c10f8c96c58180cf80fc132fb6fb53fedbd44f3aae22c2` |
| `docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` | snapshot | `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` |
| `docs/RESEARCH-NEW-200-CANDIDATE-CLOSURE-2026-08-12.md` | snapshot | `bc8cb68d10b8b79d5219518d139fc5d1e104080fbcdae6c8ba08d94acc1710ad` |

The ledger parses as 110 rows / 110 component IDs / 200 case-normalized public
IDs. Already adjudicated rows were excluded from new discovery: frozen strict
110; Batch A's 3 PASS and 2 FAIL; OpenClaw's 9 PASS and 3 FAIL; the 20/20 FAIL
supplemental-candidate closure; Batch B-D rows; and Batch E's five explicit
negative controls. They remain comparison controls, not candidates to redo.

Read-only repository heads relied on: Hermes `02aa91ba6ece4454dcb580f960e5b516b3a91111`,
Coolify `098d3d4c253a5a79aa8d166854a1b0a202077259`, Scriban
`b5ac4bf30459fdc76964e3f751e16f7e96079ea7`, PraisonAI
`0e55b360566e16d797bfc81658a4f21527ef05e6`, GitPython
`04960cfaf709973e7852068ae6980fcb455608f5`. Gitea's local mirror lacked the
Batch E objects and was not mutated.

## Strong falsification findings

| row / claim | verdict | gate evidence and boundary |
|---|---|---|
| Frozen strict provenance | **REJECT provenance field; do not reject the parsed ledger** | `summary.json` records `.ledger_sha256=afc810ce...`, but hashing the referenced `strict-200-v3/ledger.jsonl` yields `0cc19a49...`. The newest main report uses the latter. Counts parse correctly, but the summary cannot authenticate the current ledger bytes. |
| Scriban `GHSA-89CF-6HMV-8RXM` as a new component beyond `GHSA-Q6RR-FM2G-G5X8` | **REJECT new-component count / merge as one residual series** | The first-party 89CF advisory explicitly calls itself the missed sibling/incomplete fix of Q6RR. Both are the same `array * int` operator, same `LoopLimit` invariant, same AI remediation `2d01bd15...`, and serial fixes `205ca6a7...` then `973edd1f...`; only the runtime concrete type changes (`ScriptArray` to lazy `ScriptRange`). Preserve both public advisories, but count one semantic incomplete-remediation component unless a predeclared component rule says concrete dispatch type alone splits components. |
| GitPython `GHSA-3WXW-XV34-2FRG` as new beyond `GHSA-3F7W-8RR8-F37F` | **REJECT new-component count / merge residual** | First-party 3WXW summary says `TagReference.create` positional `reference` bypasses the kwargs-only `--file` guard and is an incomplete fix of `3af0c251`; 3F7W is the same API, same `--file` arbitrary-read sink, and that exact `3af0c251` remediation. This is a but-for bypass of the first fix, not a distinct mechanism. |
| Hermes `CVE-2026-49956` novelty / zero accepted-SHA intersection | **NARROW** | New row uses candidate `d2b27f6f...`; frozen strict ledger already uses that exact candidate for `CVE-2026-6830 / GHSA-VVFR-G83F-8QCV` (`d2b27f6f... -> 88dc8bbe...`). The new session-search mechanism is independently plausible: the parent already has search, `d2b27f6f` creates multi-profile isolation without filtering search, and `8d8ae89d` adds active-profile filtering. Keep only as a distinct hunk/mechanism from the same multi-feature candidate; retract any claim of candidate-SHA disjointness. |
| Coolify `CVE-2026-34198` full-advisory origin | **NARROW to cold-cache contributor** | Existing frozen witness SHA `5ae5ba57...` proves `e1fe5863...` adds the cold-cache early return and it survives to `e1d4b468...`. But that witness's own boundary says it does **not** attribute older trusted-host regex, `X-Forwarded-Host`, or reset-link request-context behavior and sets `unique_advisory_increment_not_asserted=true`. The CNA/advisory describes all three. Candidate deletion proves one necessary bypass contributor, not sole origin of the complete advisory mechanism. |
| Batch E Gitea rows 2 and 18 | **UNKNOWN for frozen reproducibility** | Local first-party mirror lacked `eff673fc`, `c43eb7c3`, `fd4641dc`, `2bde4fa5`, `fce961b4` and the private-org member/carrier objects. The document cites live PR/API observations but stores no response artifact/hash. Advisory identity may be current, but parent/but-for, AI-member survival, and release containment cannot be independently replayed from the frozen inputs. |
| Batch E GitPython rows requiring 3.1.58/3.1.59 objects | **UNKNOWN for frozen reproducibility; not a causal rejection** | The read-only local mirror had the partials but lacked `f2550b65`, `d9ddb55b`, `9b5dcaf8`, `96a888f4`, `4b4e47fc`, `b68afff4`, and `1b0d2d9b`. Thus rows 8-11 and 13-16 depend materially on unsnapshotted live refs/compare output. Capture exact commit objects and peeled tag refs before publication. |
| GitPython `GHSA-9RJ7-RF2P-W77R` vs `GHSA-6P8H-3WGX-97GF` | **UNKNOWN / high dedup risk** | Both first-party advisories concern omission of Git `--template` from an unsafe-option gate and hook-based code execution; they differ mainly by `Repo.init` vs clone entrypoint and later remediation. Do not count two components without a stable rule saying API entrypoint splits an otherwise identical option/sink invariant. |
| GitPython `GHSA-WVPP-8HX9-P66J` vs `GHSA-R9MR-M37C-5FR3` | **UNKNOWN / high dedup risk** | Both are bypasses in shared short-option candidate normalization leading to the same unsafe-option command-execution boundary; one exploits split value-token handling and the other `split_single_char_options=False`. First-party identities are distinct, but identity is not component independence. |

## Controls that resisted falsification

- **KEEP Hermes CVE-2026-49973, narrowly.** `b8b62722^ -> b8b62722`
  creates password authentication and the unauthenticated-while-disabled settings
  bootstrap surface; `f2ef2851` gates first password creation using the
  request-start `auth_enabled_before` snapshot. CVEList is `PUBLISHED`, names
  the same endpoint/mechanism, and cites carrier `1126e541...` / release
  `v0.51.358`. Direct ancestry is present.
- **KEEP PraisonAI CVE-2026-57148 as incomplete remediation.** Atomic Cursor
  commit `179cab02^ -> 179cab02` explicitly adds a JWT production guard but
  defaults unset `PLATFORM_ENV` to dev; `e0fb8e7d` changes unset behavior and
  randomizes the secret. First-party `GHSA-F38V-77QJ-H4JQ` is published and
  explicitly identifies the residual and `0.1.4 -> 0.1.5` boundary. This must
  remain incomplete remediation, not origin.
- **KEEP Coolify CVE-2026-42204 as incomplete remediation.** `c9922c30` has a
  direct Claude trailer and explicitly installs shell validation on the affected
  fields; `817128c5` replaces the flat grammar with token-aware validation.
  Tags `beta.471`-`beta.473` contain the partial without the closure, and the
  published repo advisory gives the same range and bare-ampersand RCE mechanism.
- **KEEP Scriban parser-depth row `GHSA-6Q7J-XR26-3H2C`.** `f55280a0` is an
  atomic Copilot-coauthored parser-depth remediation, `8fdbd687` makes the
  shared expression-depth control stop parsing, and tags 7.0.0-7.2.0 contain
  the partial without closure. This parser-recursion mechanism is distinct from
  the array-multiplication residual series above.

## Exact commands / first-party sources

```zsh
sha256sum docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/{ledger.jsonl,summary.json}
jq -s '{rows:length,components:(map(.component_id)|unique|length),public_ids:(map(.public_ids[])|map(ascii_upcase)|unique|length)}' \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl
git -C <read-only-repo> show -s --format=fuller <candidate> <fix>
git -C <read-only-repo> diff <candidate>^ <candidate> -- <mechanism-path>
git -C <read-only-repo> tag --contains <partial> --no-contains <closure> --sort=version:refname
gh api repos/scriban/scriban/security-advisories/GHSA-q6rr-fm2g-g5x8
gh api repos/scriban/scriban/security-advisories/GHSA-89cf-6hmv-8rxm
gh api repos/gitpython-developers/GitPython/security-advisories/<GHSA>
gh api advisories/GHSA-p52p-4vmg-4vq3
gh api advisories/GHSA-mgxw-v6rh-wcv6
```

Precise first-party API checks confirmed the queried Scriban, GitPython,
PraisonAI, Coolify, and Gitea advisories were published and not withdrawn at
query time. Those responses are live observations, not durable evidence because
this shard was authorized to write only this Markdown file; no API payload was
persisted.

## Claim boundary

Source recovery, ancestry, tags, tests, and advisory publication are necessary
diagnostics, not publication-grade causality by themselves. The two dedup
rejections above preserve the public advisory rows while reducing semantic
component counts. Missing local objects remain `UNKNOWN`, never negative. The
main report's 173-component wide lower bound is not safe to publish unchanged
until the Scriban and GitPython residual-series duplicates are merged (at least
`-2`) and the unsnapshotted Gitea/GitPython release closures are frozen and
replayed.
