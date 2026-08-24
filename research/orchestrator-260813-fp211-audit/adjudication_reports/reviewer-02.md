# Adjudication report: reviewer 02

Third-party conflict adjudication after `/clear`. Contract: `AUDIT_CONTRACT.md`. Input: `conflict_inputs/reviewer-02.jsonl`. Output owned: `adjudications/reviewer-02.jsonl`, this file. Raw clones/pages: `/tmp/fp211-adjudicate-02`. No first/second-pass files, canonical ledger, builders, or code were edited. No commit.

## Coverage and rotation

Assigned ordinals (sorted): **7, 17, 30, 91, 102, 124, 141, 206** (8/8 packets).

Reviewer exclusion check (packet fields):

| ordinal | first_reviewer | second_reviewer | third_reviewer | 02 excluded from first two |
|---:|---:|---:|---:|---|
| 7 | 1 | 4 | 2 | yes |
| 17 | 1 | 4 | 2 | yes |
| 30 | 1 | 4 | 2 | yes |
| 91 | 3 | 6 | 2 | yes |
| 102 | 3 | 6 | 2 | yes |
| 124 | 4 | 1 | 2 | yes |
| 141 | 4 | 1 | 2 | yes |
| 206 | 6 | 3 | 2 | yes |

Decisions are independent inspections of primary GHSA/CVE objects and git parent/candidate/fix/release evidence. Majority and either pass were not used as proof.

## Verdict counts

| Verdict | n | ordinals |
|---|---:|---|
| CONFIRM | 1 | 141 (MEDIUM; not HOLD-ready alone) |
| NARROW | 4 | 30, 91, 102, 124 |
| FALSE_POSITIVE | 3 | 7, 17, 206 |
| UNKNOWN | 0 | — |
| BLOCKED | 0 | — |
| **total** | **8** | |

## Conflict-field resolutions

Changed fields in the packet vs this row (not a copy of either pass).

### 7 `strict-200-v3:alias-0c32bc35f9b2fdfd939667e3` — conflict `identity_gate`

Independent: global GHSA-gxgq-rpmr-r8xr **200**, identifiers include CVE-2026-1979, `github_reviewed` null, `vulnerabilities` empty, summary “mruby up to 3.4.0” JMPNOT-to-JMPIF. Repo advisory **404**. Candidate `2b72d8a7` Claude trailer writes `OP_JMPIF` at `fail_pos-2` without an opcode check; fix `e50f15c1` adds `== OP_JMPNOT`. `3.4.0` is not an ancestor of the origin. Only tags containing origin are `4.0.0-rc` / `4.0.0-rc2`, both already contain the fix.

Final: `FALSE_POSITIVE` / `UNRELEASED_COMMIT_ONLY` / `identity_gate=NARROW` / `release_gate=FAIL`. Keep both public IDs. Identity is NARROW because the first-party object is an unreviewed GHSA whose affected-range identity is false; that is polluted identity metadata, not a reason to drop the alias pair.

### 17 `strict-200-v3:alias-2b440d3fa3dacafd8d29beca` — conflict `identity_gate`

Independent: global GHSA-95f6-rfpg-c3w8 **200** aliases CVE-2026-10291 (session-grep ReDoS). Repo **404**. Parent `edf0c0d6` (Unikzm2, no AI trailer; “Claude Code CLI” is a product name) already `new RegExp(pattern,'gi')` on `POST /session/grep`. Candidate `0a283f45` Claude Opus copies `new RegExp(pattern,'i')` into `grepSession` 30 minutes later. CNA path `src/embedded-server.ts` is absent at origin. `v3.5.5` has origin without RE2 fix `3f970a97`; `v3.7.1` has the fix. No tag contains the parent without the candidate.

Final: `FALSE_POSITIVE` / `OLD_BUG_PRESERVING_REFACTOR` / `identity_gate=PASS` / `but_for_gate=FAIL`. IDs belong to this ReDoS; repo 404 and wrong CNA path stay in counterevidence.

### 30 `strict-200-v3:alias-57569b18ed81b84118a1fdb1` — conflict `confidence`, `topology_gate`, `release_gate`

Independent: GHSA-pqh8-p93p-2rx7 package is `@dynatrace-oss/dynatrace-mcp-server` (not `@dynatrace-oss/dynatrace-mcp`, which 404s). npm `1.2.0` gitHead `1c192a04` contains Copilot commit `66ff2a7c` not fix `15d3546c`; `2.1.1` gitHead `9a5f6f86` contains the fix. Candidate is a single-parent Copilot commit (topology PASS). GHSA table names `timeframe` on list-vulnerabilities and get-events-for-cluster (this commit) **and** parent-already-present timeframe on list-problems/list-exceptions, so but-for stays NARROW. `additionalFilter` is **not** in the GHSA table.

Final: `NARROW` / `AI_NEW_SURFACE_CONTRIBUTOR` / `topology_gate=PASS` / `release_gate=PASS` / `confidence=HIGH`.

### 91 `strict-200-v3:alias-2788167921d685f8a3bb43a5` — conflict `release_gate`

Independent: GHSA-x2xq-qhjf-5mvg aliases CVE-2026-32885 (ZipSlip Untar+Unzip `Join(dest, file.Name)`; no TypeSymlink wording). Claude member `93f80ea4` adds `tar.TypeSymlink`/`os.Symlink` without dest containment; parent already unbounded TypeReg/Unzip Join. Member is not an ancestor of squash carrier `5f988451`; carrier blob still has TypeSymlink. Peeled tags: `v1.25.1` mem=N car=Y fix=N; `v1.25.2` car=Y fix=Y. Fix `05cbe299` is multi-purpose (entry prefix + symlink target + Unzip).

Final: `NARROW` / `release_gate=PASS`. Local missing tags are not UNKNOWN once tags are fetched.

### 102 `strict-200-v3:alias-1c31c40c0a061d5194e8ba95` — conflict `fix_reversal_gate`

Independent: global GHSA-vw3v **404**; repo advisory aliases CVE-2025-32425 (unbounded Docker logs). Claude member `a75c1af2` enables the previously commented frontend Compose service with no `json-file` rotation; parent siblings already had no `logging:` blocks. Fix `57a06f70` (#10798) does add `max-size: 10m` rotation **and** patches several other GHSA DoS classes. Tags: `autogpt-platform-beta-v0.6.30` car=Y fix=N; `v0.6.32` fix=Y.

Final: `NARROW` / `fix_reversal_gate=NARROW` (packed multi-GHSA fix that still closes this logging invariant).

### 124 `post:openclaw-feishu-webhook@canonical` — conflict `uniqueness_gate`

Independent: GHSA-g353 identifiers are only G353+CVE-2026-32974 (encryptKey webhook). GHSA-xh72 identifiers are only XH72+CVE-2026-44109 (webhook residual **and** blank card-action tokens). They do not list each other. AI member `b0c67ea0` adds `Lark.adaptDefault`; parent monitor logged webhook mode not implemented. G353 fix `7844bc89` is first in `v2026.3.12`. Ledger atomic members `c3b1ca45` / `014d7184` are missing from the clone. Ordinal 47 shares the candidate SHA with a different invariant (unbounded body).

Final: keep G353+CVE-2026-32974, remove XH72+CVE-2026-44109, `uniqueness_gate=PASS`. Identity stays NARROW because the input row packed a second public identity. Uniqueness NARROW is the packed-input state, not the post-removal row.

### 141 `post:gitpython-config-section@canonical` — conflict `verdict`, `uniqueness_gate`

Independent: GHSA-3rp5-jjmw-4wv2 is GHSA-only `]` section-delimiter injection after CR/LF/NUL neutralization; patched 3.1.53 via `1ed1b924`. Candidate `54538428` GPT 5.5 adds `_assure_config_name_safe` for CR/LF/NUL only. That SHA is also the complete fix of ordinal 171 / GHSA-mv93 (distinct identifiers, patched 3.1.50). Contract: same fix alone does not merge distinct mechanisms. Partial in 3.1.50–3.1.52; fix first in 3.1.53. All required gates PASS/NA.

Final: `CONFIRM` / `MEDIUM` / `uniqueness_gate=PASS`. MEDIUM because the shared SHA with 171 remains a bookkeeping hazard even though identity is distinct. Not `CONFIRM/HIGH`.

### 206 `posthold:R01` — conflict `verdict`, `but_for_gate`, `fix_reversal_gate`, `causal_class`, `false_positive_class`

Independent: repo GHSA-4pqj-3c56-5fqq **200** (global **404**), GHSA-only, “Workspace dotenv files could override provider credentials,” patched 2026.5.28. Member `3affd5e8` (`fix: address issue`, no trailer) only expands `host-env-security-policy.json` exec denylist (`AWS_ACCESS_KEY_ID` parent=False member=True) and does not touch `dotenv.ts`. Carrier `2d126fc6` is `[AI]` host-env denylist expansion. Advisory fix `85277c2` edits `dotenv.ts` only. Parent dotenv already listed `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`. Removing the candidate leaves the dotenv residual. `v2026.5.27` car=Y fix=N; `v2026.5.28` contains `85277c2` but not PR members `6852e4a1`/`6d31c78c`. Distinct from ordinal 16 (`OPENCLAW_` namespace) and from other denylist residuals that share this candidate SHA.

Final: `FALSE_POSITIVE` / `NOT_CAUSAL_DIFFERENT_INVARIANT` / `but_for_gate=FAIL` / `fix_reversal_gate=FAIL`. Incomplete-remediation requires an explicit attempt of the **same** boundary.

## False-positive counterexamples

1. **7 / GHSA-GXGQ / CVE-2026-1979 — `unreleased_commit_only`.** Origin not in `3.4.0`; every tag with origin already has `e50f15c1`.
2. **17 / GHSA-95F6 / CVE-2026-10291 — `old_bug_preserving_refactor`.** Human parent already constructed `RegExp` on session-grep.
3. **206 / GHSA-4PQJ — `different_invariant`.** Exec-sanitizer AWS keys are not workspace-dotenv provider-cred override.

## Narrow / confirm notes

| Ord | Why not CONFIRM/HIGH |
|---|---|
| 30 | Parent already interpolated GHSA-named `timeframe` in list-problems/list-exceptions |
| 91 | New symlink surface on old Join; multi-purpose ZipSlip fix; squash member ≠ carrier ancestor |
| 102 | New frontend service inherits parent unbounded logs; packed DoS fix |
| 124 | Packed XH72 identity removed; squash topology |
| 141 | CONFIRM/MEDIUM only: distinct `]` residual, but candidate SHA is also 171’s complete fix |

## Limitations

- OpenClaw clone lacks ledger atomic members `c3b1ca45` and `014d7184` (124).
- Autogpt/ddev/openclaw squash members are routinely not ancestors of carriers; ancestry used the carrier for release.
- GHSA-4pqj and GHSA-vw3v are repo-only (global 404).
- npm `@dynatrace-oss/dynatrace-mcp` 404 is preserved; release used the GHSA package name.
- No UNKNOWN rows; evidence was sufficient for every assigned ordinal.

## Reusable experience

- Do not treat GHSA affected ranges as git containment; `merge-base --is-ancestor` is the release gate.
- Repo-vs-global 404 is identity evidence to preserve, not automatic NARROW when the other first-party object formally aliases.
- Use the GHSA package name for npm `gitHead`.
- Same SHA or same key names do not merge rows; source/sink/load-path/invariant must match.
- `AI_INCOMPLETE_REMEDIATION` fails unless the AI hunk attempted the advisory’s actual boundary.
- After removing a packed distinct GHSA, uniqueness is PASS; do not leave uniqueness NARROW as a leftover of the input packing.
