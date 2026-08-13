# Third-party conflict adjudication — reviewer 04

Assigned packets: `conflict_inputs/reviewer-04.jsonl` (8 rows).
Owned outputs: `adjudications/reviewer-04.jsonl`, `adjudication_reports/reviewer-04.md`.
Raw evidence: `/tmp/fp211-adjudicate-04/{advisories,pages,evidence,clones}`.
No first/second-pass shards, canonical ledger, builders, or code were edited. No commit.

Rotation check: every packet has `third_reviewer=4` and `4 ∉ {first_reviewer, second_reviewer}`:

| ordinal | first | second | third | conflict fields |
|--------:|------:|-------:|------:|-----------------|
| 61 | 2 | 5 | 4 | `fix_reversal_gate`, `uniqueness_gate`, `minimum_fix_set` |
| 83 | 3 | 6 | 4 | `release_gate` |
| 87 | 3 | 6 | 4 | `release_gate` |
| 95 | 3 | 6 | 4 | `release_gate` |
| 106 | 3 | 6 | 4 | `ai_hunk_gate` |
| 180 | 5 | 2 | 4 | verdict, confidence, but_for, fix_reversal, release, uniqueness, `duplicate_of`, causal_class, false_positive_class |
| 199 | 6 | 3 | 4 | `identity_gate` |
| 207 | 6 | 3 | 4 | verdict, but_for, fix_reversal, causal_class, false_positive_class |

Decisions are from primary GHSA/CVE objects plus git parent/candidate/fix/release inspection. First/second rows were routing, not votes.

## Verdict counts

| Verdict | n | ordinals |
|---------|--:|----------|
| CONFIRM | 1 | 106 |
| NARROW | 5 | 61, 87, 95, 180, 199 |
| FALSE_POSITIVE | 2 | 83, 207 |
| UNKNOWN | 0 | — |
| BLOCKED | 0 | — |

CONFIRM/HIGH: **106 only**. That is claim-grade for this row after this review. The other seven stay non-CONFIRM.

## Per-ordinal decisions

### 61 — MISP Galaxy.find / CVE-2026-10854 / GHSA-3636 — `NARROW` / `AI_DIRECT_ROOT`

Claude `47bf71cc` first-loads `Galaxy.find` with only `Galaxy.enabled=true` in `__setBuilderConfig`; parent `66f278bb` has no Galaxy load. Merge member of carrier `709087cc`. But-for origin of the enabled-only leak.

Listed CVE closer `d3adfe1a` inserts PHP `'Galaxy.distribution' > 0` into a CakePHP conditions array. Residual closer `8aa2bb6d` (ordinal 67 / CVE-2026-54362) documents that comparison as always-true and switches to `Galaxy->buildConditions`. **minimum_fix_set is `8aa2bb6d`**, so `fix_reversal_gate=PASS`. Identity/release stay NARROW: unreviewed GHSA-3636 names `d3adfe1a`; `v2.5.39` ships that insufficient patch; first tag with `8aa2bb6d` is `v2.5.40`.

Uniqueness **PASS**: 61 is the origin. Ordinal 67 is already the residual duplicate (`duplicate_of` this `row_key`), not a second AI origin. Sharing a candidate SHA with a later closer does not uniqueness-NARROW the origin.

Conflict resolution vs passes: first listed `d3adfe1a` and NARROW'd uniqueness/fix_reversal; second listed `8aa2bb6d` and PASS'd those gates. Independent git matches the second on min-fix/uniqueness/fix_reversal; verdict stays NARROW.

### 83 — Coolify GHSA-f47p / CVE-2026-32718 — `FALSE_POSITIVE` / `not_origin_of_named_mechanism`

First-party repo advisory (global GHSA 404) names `POST /v1/projects`, `POST /v1/servers`, `GET /v1/servers/{uuid}/validate` under `api.ability:read`. Parent of Claude `62c394d3` already has all three. Candidate adds Hetzner plus `POST /cloud-tokens/{uuid}/validate` under read. Fix `c15bcd56` only moves the two validate routes to write; `POST /servers` is already write in that diff.

`identity` / `but_for` / `fix_reversal` FAIL. **release PASS** from independent tag peel: `v4.0.0-beta.454` has candidate without fix; `v4.0.0-beta.466` has `c15bcd56`. Passing release does not save a not-origin row.

Conflict: first left release UNKNOWN (no in-shard peel); second PASS. Independent peel agrees with second.

### 87 — rConfig GHSA-h4rq / CVE-2026-63102 — `NARROW` / `AI_NEW_SURFACE_CONTRIBUTOR`

Unreviewed GHSA aliases CVE-2026-63102 (repo advisory 404). Claude merge-member `4b0938dd` adds token `/api/v1`+`/api/v2` Users that extend the session `UserController`. Parent `StoreUserRequest` already has `role => 'required'` with no allowlist. Fix `84822f40` allowlists `Admin,User` on that shared FormRequest (also repairs session API).

Annotated `core-8.2.3` peels to carrier `ebb39d59` (member yes, fix no). `core-8.2.8` peels to `63bfd1b0`, not `84822f40`, but **`84822f40` is an ancestor** of that peeled commit. **release PASS**.

Conflict: first UNKNOWN (peel ≠ fix SHA); second PASS (ancestor). Independent ancestor check agrees with second. Verdict stays NARROW (contributor, not origin).

### 95 — OpenClaw GHSA-g5cg / CVE-2026-41329 — `NARROW` / `AI_NEW_SURFACE_CONTRIBUTOR`

Reviewed GHSA aliases CVE-2026-41329; patched `>=2026.3.31`, vulnerable `<=2026.3.28`. Claude squash-member `01d568c9` adds `EXEC_EVENT_PROMPT` in `heartbeat-runner.ts`. Parent already `requestHeartbeatNow({ reason: "exec-event" })`. Fix `a30214a6` blocks owner-auth inheritance for exec events.

Squash member is not an ancestor of either tag; carrier `483fba41` is. **release PASS**: git `v2026.3.28` peels to npm `2026.3.28` gitHead `f9b10792` (carrier Y, fix N); `v2026.3.31` peels to npm `2026.3.31` gitHead `213a704b` (fix Y). npm-vs-git is not a remaining gap.

Conflict: first NARROW release (npm githead vs git tag wording); second PASS. Independent peels match; release PASS. Verdict stays NARROW (contributor + squash topology).

### 106 — Prompty GHSA-c4gh / CVE-2026-53597 — `CONFIRM` / `HIGH` / `AI_DIRECT_ROOT`

Reviewed GHSA aliases CVE-2026-53597. Advisory: TypeScript v2 loader called `gray-matter` without overriding executable engines; v2 rebuild reintroduced the issue; npm `@prompty/core >=2.0.0-alpha.1 <2.0.0-beta.3`, patched `2.0.0-beta.3`.

Copilot-coauthored `a0e61088` first-adds `loader.ts` with `import matter from "gray-matter"` and `matter(raw)` (no `engines`). Parent has no TS loader. That call site is the relevant hunk; quoting a library default map is unnecessary. Fix `c27402da` rejects `js`/`javascript` engines.

**release PASS** from packument + tags (prior passes left this UNKNOWN):

- `@prompty/core@2.0.0-beta.1` gitHead `38fd5f31` = tag `typescript/2.0.0-beta.1` (cand Y, fix N)
- `@prompty/core@2.0.0-beta.3` gitHead `c27402da` = the fix SHA = tag `typescript/2.0.0-beta.3`

Uniqueness PASS vs 104 (file-resolver / GHSA-WXHM) and 105 (Nunjucks / GHSA-W28W) on the same candidate SHA.

Conflict: first `ai_hunk=NARROW` (wanted a quoted default-engine line); second `PASS`. Independent blob agrees with second. Closing npm gitHead independently upgrades the row from NARROW to CONFIRM/HIGH.

### 180 — GitPython GHSA-3wxw — `NARROW` / `AI_INCOMPLETE_REMEDIATION`

First-party GHSA-3wxw (global 404). Positional `reference="--file=..."` bypasses the kwargs-only guard in GPT-5.6 `3af0c251` (`_option_candidates([], kwargs)`). Incomplete of GHSA-3f7w's tag instance. Closer `1b0d2d9b` includes `[path, reference]` and names GHSA-3wxw. Tags: `3.1.57`/`3.1.58` candidate-only; `3.1.59` has the closer. **release PASS**.

Not a formal alias of GHSA-3f7w (ordinal 144). Same `TagReference.create --file` family → **uniqueness NARROW**, `duplicate_of=null`. Shared later fix with GHSA-5xxx (179) is not a merge.

Conflict: first FALSE_POSITIVE / `DUPLICATE_MECHANISM` / `duplicate_of` 144; second NARROW incomplete-remediation. Independent first-party GHSA object agrees with second: two GHSAs merge only on formal alias, which is absent.

### 199 — OpenClaw GHSA-2hfg — `NARROW` / `AI_INCOMPLETE_REMEDIATION`

Repo advisory is GHSA-only. Global object aliases **CVE-2026-53812**, which is **not** in input `public_ids`. Conservation: keep ∪ remove must equal `{GHSA-2HFG-4FH4-QP7F}`. Cannot add the CVE. **identity NARROW**. Keep GHSA-2HFG only.

`e0b8ddc1` is `[AI-assisted]` with human co-author Devin Robison — **ai_hunk NARROW**. It guards pressKey/type(submit) only. `3d93174c` extends the same guard to select/fill/evaluate. Git `v2026.5.12` has candidate without closer; `v2026.5.18` has closer. npm gitHead for those versions is **null** → **release NARROW**.

Conflict: first identity PASS; second NARROW. Independent global/repo identifier split agrees with second.

### 207 — OpenClaw GHSA-8wg3 / CVE-2026-53819 — `FALSE_POSITIVE` / `unattempted_env_family`

Repo GHSA-only; global aliases CVE-2026-53819 (keep both; identity NARROW). Advisory: workspace `.env` overrides Homebrew **executable** selection; patched `2026.5.27`.

Member `3affd5e8` adds `HOMEBREW_CELLAR|PREFIX|REPOSITORY` to `blockedOverrideOnlyKeys`. **`HOMEBREW_BREW_FILE` never present**. Carrier `2d126fc6` drops those keys. Parent/member/carrier `brew.ts` already reads `HOMEBREW_BREW_FILE`; candidate never touches `brew.ts` or `dotenv.ts`. Closer `f86953f` edits `dotenv.ts`/`brew.ts`. Listed squash members `67619d87`/`734a35d9` are not ancestors of `v2026.5.2`/`v2026.5.27` → **minimum_fix_set is `f86953f` only**.

Incomplete-remediation requires an explicit attempt of the same boundary. Dropped exec-denylist path keys are not an attempt of dotenv→brew executable selection. `but_for`/`fix_reversal` FAIL. Carrier subject `[AI]` is PR-level → ai_hunk NARROW. Git first-containing of `f86953f` is `v2026.5.2` vs advisory `2026.5.27` → release NARROW.

Conflict: first NARROW incomplete-remediation; second FALSE_POSITIVE unattempted. Independent parent/member/carrier/fix blobs agree with second.

## Disagreements with both prior passes (same field)

Independent inspection, not majority:

| Ord | Field | First | Second | This review |
|-----|-------|-------|--------|-------------|
| 61 | `minimum_fix_set` | `d3adfe1a` | `8aa2bb6d` | `8aa2bb6d` (actual closer) |
| 61 | `fix_reversal_gate` | NARROW | PASS | PASS |
| 61 | `uniqueness_gate` | NARROW | PASS | PASS |
| 83 | `release_gate` | UNKNOWN | PASS | PASS |
| 87 | `release_gate` | UNKNOWN | PASS | PASS |
| 95 | `release_gate` | NARROW | PASS | PASS |
| 106 | `ai_hunk_gate` | NARROW | PASS | PASS |
| 106 | `release_gate` | UNKNOWN | UNKNOWN | **PASS** (npm gitHead peeled) |
| 106 | `verdict`/`confidence` | NARROW/MEDIUM | NARROW/MEDIUM | **CONFIRM/HIGH** |
| 180 | `verdict` | FALSE_POSITIVE | NARROW | NARROW |
| 180 | `duplicate_of` | ordinal 144 row_key | null | null |
| 199 | `identity_gate` | PASS | NARROW | NARROW |
| 207 | `verdict` | NARROW | FALSE_POSITIVE | FALSE_POSITIVE |
| 207 | `minimum_fix_set` | three SHAs | three SHAs | **`f86953f` only** (other two not on tags) |

## Limitations

- MISP clone via `git clone --local` failed (source pack corruption). Inspection used `/tmp/fp211-cross-06/clones/misp` via symlink `clones/misp-src`; blobs and tags were readable there.
- rConfig/prompty source clones are `blob:none` partial clones; blobs were lazy-fetched from those clones, not from a full independent GitHub mirror.
- OpenClaw npm gitHead is present for `2026.3.28`/`2026.3.31` and **null** for `2026.5.12`/`2026.5.18`/`2026.5.27`.
- No BLOCKED row. Missing npm gitHead on later OpenClaw versions is recorded as release NARROW, not BLOCKED.

## Reusable experience

1. Listed security SHAs are hypotheses. If a patch embeds a PHP comparison in a query conditions array, it is not minimum reversal.
2. The origin row is not a uniqueness failure because a later residual closer exists; uniqueness-FAIL the residual, not the origin.
3. Peel annotated tags with `rev-parse tag^{commit}` then `merge-base --is-ancestor`; peel ≠ fix SHA is not release UNKNOWN if the fix is still an ancestor.
4. npm `gitHead` that equals the fix SHA closes release. Git tags named `typescript/2.0.0-beta.*` are not a substitute until they are shown to match that gitHead.
5. Distinct first-party GHSAs do not merge on same sink/fix. Incomplete-remediation residuals stay NARROW, not `duplicate_of`, without formal alias evidence.
6. A global CVE alias absent from input `public_ids` cannot be kept or removed; identity NARROW.
7. `[AI-assisted]` / PR-title `[AI]` is not hunk-level provenance.
8. Incomplete remediation requires an explicit attempt of the **same** source/sink/invariant. Dropped sibling denylist keys are not origin of an unattempted dotenv/executable boundary.
