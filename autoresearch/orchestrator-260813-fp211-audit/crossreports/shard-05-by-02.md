# Shard 05 independent cross-review (reviewer 02)

Pinned contract: `AUDIT_CONTRACT.md` at repo `cd97a295956a8d3d46330bf9b0300ddded21f737`. Assigned input: `inputs/shard-05.jsonl` (ordinals 145–180). First-pass hypotheses: `shards/shard-05.jsonl`, `reports/shard-05.md`. Owned outputs: `crossreviews/shard-05-by-02.jsonl`, this report. Raw clones/pages: `/tmp/fp211-cross-02/{clones,pages,notes}`. Canonical files, first-pass shards, code, and git history were not modified. No commit.

Every ordinal was re-checked against independently fetched first-party GHSA/CVE pages and git parent/candidate/fix trees. First-pass citations were routing only, not proof.

## Coverage

Exactly 36 input rows, ordinals **145–180**, in ordinal order. `row_key` and `baseline_state` conserved. `public_ids_keep ∪ public_ids_remove` equals each input `public_ids` set. No public IDs moved to `public_ids_remove`.

| Verdict | Count | Ordinals |
|---|---|---|
| CONFIRM | 15 | 147, 148, 152, 155, 157, 160, 161, 162, 163, 164, 166, 167, 171, 176, 179 |
| NARROW | 4 | 156, 169, 170, 180 |
| FALSE_POSITIVE | 15 | 145, 146, 149, 150, 151, 158, 159, 165, 168, 172, 173, 174, 175, 177, 178 |
| UNKNOWN | 2 | 153, 154 |
| BLOCKED | 0 | — |

CONFIRM/HIGH (eligible as a final confirmed case without another review): **147, 148, 152, 155, 157, 160, 161, 162, 163, 164, 166, 167, 171, 176, 179** (15). No CONFIRM/MEDIUM. UNKNOWN **153/154** stay UNKNOWN. 156 and 169 keep NARROW rather than stretching unclosed topology/release-wording gates to CONFIRM. Mechanical 36/36 coverage is not a public-case count.

## Disagreements with first pass

Public-ID keep/remove sets: **no disagreements**. Every row keeps the input IDs; none are removed.

### Verdict disagreements (2)

| Ord | First pass | Cross-review 02 | Why |
|---|---|---|---|
| **160** | NARROW / MEDIUM | **CONFIRM / HIGH** | Local clone still has no tag containing fix `f3c6c905`. Already-fetched GitHub commit object for `v4.1.2` (`/tmp/fp211-cross-02/pages/fast-uri-v4.1.2-commit.json`) has sha `c30764cc…` whose **parent is** `f3c6c905`. Local `v4.1.1` = `f3e437f7` contains candidate `0542a216` and not the fix. `release_gate` NARROW→PASS on that first-party tag-parent object, not on a missing local tag. |
| **180** | FALSE_POSITIVE / DUPLICATE_MECHANISM | **NARROW / MEDIUM** | GHSA-3WXW is a first-party incomplete-fix residual of `3af0c251` (positional `reference` vs kwargs-only `--file`). It is **not** a formal alias of GHSA-3F7W (ordinal 144). Same TagReference.create `--file` sink family ⇒ `uniqueness_gate` NARROW, not FAIL. `duplicate_of` cleared. Gates: but_for/fix_reversal/release NARROW→PASS; uniqueness FAIL→NARROW. |

### Inspected but not upgraded (agree with first-pass NARROW)

| Ord | First pass | Cross-review 02 | Why not CONFIRM |
|---|---|---|---|
| **156** | NARROW / MEDIUM | **NARROW / MEDIUM** | Copilot one-liner and carrier tree are real, but member is not a git ancestor and squash `#850` also records Claude “Consistent use of `self.config.full_eval`” on the same file. `topology_gate` stays NARROW. |
| **169** | NARROW / MEDIUM | **NARROW / MEDIUM** | Hashed PyPI 0.1.4 vs 0.1.6 prove the JWT default-open mechanism and that monorepo `v4.6.x` tags are the wrong product. Repo GHSA still says patched ≥0.1.5; 0.1.5 does not exist; actual fail-closed artifact is 0.1.6. `release_gate` stays NARROW. CVE program 404 preserved. |
| **170** | NARROW / MEDIUM | **NARROW / MEDIUM** | Mechanism real; git tags 3.1.47–3.1.50 vs GHSA = 3.1.50 only. |

### Gate-only disagreements (only on the two verdict-disagree rows)

No other ordinal differs from first pass on verdict, confidence, causal_class, false_positive_class, any of the seven gates, public-ID sets, SHA sets, or `duplicate_of`. Public-ID keep/remove: **no disagreements** on any row.

## Identity (first-party, 404s preserved)

Independently re-fetched repo GHSA, global `/advisories`, and CVE program pages under `/tmp/fp211-cross-02/pages`.

Repo 200 / global 404 (keep both IDs when a CVE exists): Coolify CHG4, 962V; GitPython 284H, 8MCC, 5XXX, 3WXW.

Repo 404 / global 200 (keep both): Prospero 4FXP, Q2F8, M6X4, X8QQ; WACRM X2W7; MISP MF7V.

CVE program 404 with GHSA still aliasing CVE (keep both): CVE-2026-58432, CVE-2026-55987, CVE-2026-57148.

Faraday candidate cites sibling **GHSA-33mh-2634-fwr2**, independently 200, **not** in the 211. Uniqueness vs that sibling is PASS inside this population.

## False-positive counterexamples

### 145 `coolify-shell-grammar` — FALSE_POSITIVE / WRONG_EDGE

GHSA-chg4 names human `e2ba44d0c` (no AI trailer) adding `&`/`"` to `SHELL_SAFE_COMMAND_PATTERN`. Parent tree of Claude `c9922c30` already applies `shellSafeCommandRules()` to `docker_compose_custom_{start,build}_command`. The AI commit only attaches that already-regressed helper to install/build/start. Tokenizer `817128c5` is merge-carried by `e1aac50b`; beta.471–473 is real for the **pattern**, not this AI edge.

### 146 `coolify-activity-scope` — FALSE_POSITIVE / OLD_BUG_PRESERVING_REFACTOR

GHSA-962v: unlocked `$activityId` + `Activity::find` with no auth; affected **≤ beta.470**, patched **≥ beta.471**. Parent of `a94517f4` already has unscoped `find()`. Candidate adds fail-open `if ($teamId && …)`. Complete fix `3e0d48fa` (`#[Locked]` + fail-closed) shares first tag **beta.471**. No candidate-only release; deleting the candidate does not remove the advisory mechanism.

### 149 `prospero-calendar-delete` / 150 `prospero-notification-delete` — FALSE_POSITIVE / WRONG_EDGE

GHSA-q2f8 names `CalendarDeleteEventController`. GHSA-m6x4 names `DeleteNotificationController::delete`. Squash `#248` / `a3a2f9f5` hardens `CalendarExportController` and mark-read/latest-ajax, not those files. `8c26eed4` / `eaee2ae0` are the first touches. Sibling unguarded call sites, not incomplete of these GHSAs.

### 151 `dynatrace-mcp-auth` — FALSE_POSITIVE / WRONG_EDGE

GHSA-p7w7 is **unauthenticated** HTTP `tools/call`, affected ≤1.8.7, patched ≥2.0.0. Claude `aab80e` only changes default bind `0.0.0.0`→`127.0.0.1`. Member is not an ancestor of `v2.0.0`; squash carrier `ac5251e` and bearer-auth `8f129724` both first appear in `v2.0.0`. Bind is a different boundary; the bind-only state is not in `v1.8.7`.

### 158 / 159 mistune — FALSE_POSITIVE / WRONG_EDGE

Claude `5afeaf6b` is “Filter image-directive src through safe_url” (`directives/image.py`). Both GHSAs name `HTMLRenderer.safe_url`. Candidate and renderer fix `c7101fcb` share first tag **v3.3.0**; candidate is outside GHSA affected ranges (≤3.2.0 / ≤3.2.1).

### 165 `filebrowser-delete-scope` — FALSE_POSITIVE / WRONG_EDGE

GHSA-fmm7 is incomplete **v2.63.14 ScopedFs** `Remove`/`RemoveAll` skipping `guard()`. AI `847d08bd` has zero Remove hunks. Human `7c2c0a11` (no AI marker) introduces unguarded Remove. Distinct from CONFIRM 166 (dangling write on the same AI commit) and ordinal 14 (zip-slip).

### 168 `gitea-oauth-reactivation` — FALSE_POSITIVE / HUMAN_WEAKENED_AI_PREDICATE

Claude member `eff673fc` implements the **three-field** sync-disable signature. Shipped carriers `c43eb7c3` / backport `2bde4fa5` use `RefreshToken == ""` only. Member is not an ancestor of the carrier. Parent of the AI member never-reactivates (safer). CVE program 404 preserved. `release_gate` UNKNOWN.

### 172–175, 177–178 GitPython — FALSE_POSITIVE / WRONG_EDGE

| Ord | Claimed GHSA | Candidate actually did | Why FP |
|---|---|---|---|
| 172 | FJR4 Diffable.diff `--output` | `701ce32f` GHSA-956x on commit/blame/archive/clone; no `git/diff.py` | sibling mixin |
| 173 | HH9P pathspec-from-file on remove/Head.checkout | `3af0c251` checkout-index `--prefix` + tag `--file` kwargs | never attempted those sites |
| 174 | 9RJ7 Repo.init `--template` | `7a4f5dcb` archive add-file / bundle-uri (ordinal 142 / GHSA-539M) | clone `--template` is ordinal 140 |
| 175 | 4GMW read-tree `--index-output` | `3af0c251` checkout-index/tag only | never attempted read-tree |
| 177 | 284H dormant multiline rewrite | `c417af46` write-time value CR/LF/NUL | different invariant |
| 178 | 8MCC clone `--separate-git-dir` | `7a4f5dcb` bundle-uri/add-file; 0 `--separate-git-dir` hits | omitted sibling option |

## NARROW counterexamples

- **156 langroid-pandas-eval**: Copilot `b1c45e3f` one-line `config.full_eval`→`self.config.full_eval` activates a weak sanitizer. Carrier `0d9e4a7b` is in 0.53.15–0.59.31 without fix `30abbc1a`. Mixed squash (Copilot trailer + Claude “consistent use of self.config.full_eval”) plus non-ancestry keep `topology_gate` NARROW. Not CONFIRM.
- **169 praisonai-jwt-default**: Cursor default-open `PLATFORM_ENV` guard is in hashed PyPI 0.1.4 (`3a50be4b…`); fail-closed `resolve_jwt_secret()` is in 0.1.6 (`14f638b7…`); 0.1.5 does not exist. Repo GHSA patched ≥0.1.5 vs actual 0.1.6 keeps `release_gate` NARROW. Monorepo `v4.6.x` tags are the wrong product.
- **170 gitpython-joined-short**: GPT 5.4/codex shlex-split denylist misses `-uVALUE`. Git tags **3.1.47–3.1.50** vs GHSA wording **= 3.1.50 only**. Residual is real; release wording must follow git tags. This is warranted NARROW, not overuse.
- **180 gitpython-tag-positional-file**: GPT 5.6/codex kwargs-only `--file` on `TagReference.create` leaves positional `reference="--file=..."`. Distinct published GHSA-3WXW (not a formal alias of 3F7W). Uniqueness NARROW vs ordinal 144’s tag `--file` family. Not FALSE_POSITIVE duplicate.

## CONFIRM (high-signal)

147 n8n-mcp IPv4-only `validateUrlSync` (v2.47.4–13 / 2.47.14); Claude trailer is on the landed fork-merge that adds the helper versus parent `643c98bc`. 148 Prospero permission auth-without-authorize (v4.6.0 / later SuperAdmin request). 152 WACRM meta-send vs engine dispatcher (commit-only, no tags). 155 Prospero Order/OrderItem APIs: Claude `Order::find($id)` / `Item::find($id)` with no `company_id`; fix scopes `where('company_id', …)`; same first tag v5.5.3 (commit-only). 157 Vitest: Codex `af88b1f5` adds allowWrite gates while `cdp.send` stays ungated; child `385a1aef` (parent is the candidate) disables client CDP; both first in v3.2.5. 160 fast-uri Claude `//` authority check leaves `\\` `/\\` `\\/` introducers; local `v4.1.1` vs already-fetched GitHub `v4.1.2` parent=`f3c6c905`. 161 locutus `RegExp.test` guard (v2.0.39–v3.0.24 / v3.0.25). 162 Gitea API draft gate vs web UUID (v1.25.5 / v1.26.4 vs v1.27.0 backport `ab10e37a`). 163 Scriban LoopLimit misses `array*int` (7.0.0–7.2.0 / 7.2.1). 164 Faraday string `//` vs URI objects (v2.14.1 / v2.14.2). 166 Filebrowser dangling-write documented in `WithinScope` (v2.63.6–15 / v2.63.16). 167 Scriban depth limit logs and continues (7.0.0–7.2.0 / 7.2.1). 171 GitPython value-only newline (3.1.49 / 3.1.50). 176 option-name `=/#/space` after section-delimiter patch (3.1.53–57 / 3.1.58); distinct from 141 and 171. 179 blame `--output` denylist omits `--contents` (3.1.51–58 / 3.1.59); distinct from 172.

## UNKNOWN (preserved)

- **153 MISP**: GHSA-mf7v is a multi-controller mass-assignment set. Claude `bc182d55` is Event.php id-strip; proposed fix `025f7115` is Taxonomy.php. Cannot close one AI partial→complete subset for the whole advisory.
- **154 OmniFaces**: GHSA-fp43 lists combined-resource IDs, source-map cache, HashParam, push. Candidate is CombinedResource*; proposed fix is SourceMapResourceHandler. Zero local tags contain either SHA. Multi-mechanism unclosed.

## Replay commands

```bash
python3 -c 'import json,pathlib; p=pathlib.Path("autoresearch/orchestrator-260813-fp211-audit/crossreviews/shard-05-by-02.jsonl"); rows=[json.loads(l) for l in p.read_text().splitlines() if l.strip()]; print(len(rows), [r["ordinal"] for r in rows][:3], [r["ordinal"] for r in rows][-3:])'
python3 -c 'import sys; sys.path.insert(0,"autoresearch/orchestrator-260813-fp211-audit"); from verify import load_jsonl, verify_row, HERE; e={r["ordinal"]:r for r in load_jsonl(HERE/"manifest.jsonl")}; rows=load_jsonl(HERE/"crossreviews"/"shard-05-by-02.jsonl");
[verify_row(r,e[r["ordinal"]]) for r in rows]; print("schema_ok", len(rows))'
git -C /tmp/fp211-cross-02/clones/coolify grep -n shellSafeCommandRules e39678aea584be533f89052d4e2939f2d8834449 c9922c30c2a6bf922653a5f2d631aab4fea685c4 -- app
git -C /tmp/fp211-cross-02/clones/gitea grep -n isDisabledByAutoSync c43eb7c33a100ffc7b2367adf165f7085e0ccdc5 -- routers/web/auth/oauth.go
git -C /tmp/fp211-cross-02/clones/filebrowser show -s --format='%s%n%b' 7c2c0a11b31b2bb214d741005a0b02b1764208b3
git -C /tmp/fp211-cross-02/clones/fast-uri tag --contains 0542a216860fd70c062a4730e620576f62ded057 --no-contains f3c6c905f47831007490f466c5945012e905cc52
```

Per-row replay commands are in `crossreviews/shard-05-by-02.jsonl`.

## Limitations

- Shared `--shared` clones of MISP/Scriban from first-pass lazy clones failed; those two repos were inspected via symlink to `/tmp/fp211-shard-05/clones/{misp-orig,scriban-orig}` after `cat-file` confirmed the objects. Prospero Order blobs for 155 were read from the original first-pass clone because the shared clone was missing a tree object.
- fast-uri local clone still has no `v4.1.2` tag. Release containment for 160 uses the already-fetched GitHub commit object (`fast-uri-v4.1.2-commit.json`), not a local tag replay. No further fetch was attempted at finalization.
- PraisonAI `e0fb8e7` pyproject still says `0.1.4` while PyPI `0.1.4` is the vulnerable sdist; patched PyPI `0.1.6` uses `jwt_secret.py`. That proves the mechanism; GHSA patched ≥0.1.5 vs missing 0.1.5 keeps 169 NARROW rather than CONFIRM.
- 168 `release_gate` remains UNKNOWN (member/fix not on inspected mainline tags); verdict is still FALSE_POSITIVE on hunk/but-for.
- 153/154 remain UNKNOWN; not closed as CONFIRM to fill coverage.
- Existing research docs and first-pass JSONL were routing only. Mechanical 36/36 coverage is not a public-case count.

## Reusable lessons

1. **Wrong edge vs incomplete.** Incomplete remediation requires the AI hunk to attempt the **same** source/sink/invariant. Sibling controllers, sibling git subcommands, and shared-helper callers fail but-for.
2. **Human regression / squash weakening.** GHSA-chg4’s `&` and Gitea OAuth’s empty-refresh predicate are human (or squash) weakenings of safer states. AI trailers on nearby commits are not causality.
3. **Same first tag is commit-only.** Candidate and fix sharing the first containing tag cannot support a released incomplete-remediation claim (`release_gate=NA`).
4. **Preserve 404s.** Repo-unreviewed GHSAs, repo-404/global-200 aliases, and CVE-program 404s stay in `public_ids_keep`.
5. **Uniqueness is mechanism and identity, not SHA.** Same AI commit can yield one CONFIRM (166 dangling write) and one FP (165 delete). Distinct GHSAs on a follow-on residual of the same sink (180 vs 144) do not merge without formal alias evidence; uniqueness may still be NARROW.
6. **Multi-fix advisories stay UNKNOWN.** Do not CONFIRM a whole mass-assignment or OmniFaces combined-resource umbrella from one AI file and a non-reversing proposed fix.
7. **Package artifact ≠ git tag.** praisonai-platform 0.1.x is not PraisonAI monorepo `v4.6.x`. Hashed sdists can prove the mechanism without closing GHSA version wording (169 stays NARROW).
8. **Missing local tags are not automatically NARROW.** An already-fetched GitHub tag-commit object can prove patched-tag parentage (160 `v4.1.2` parent = fix SHA). Do not CONFIRM if that object was never retrieved.
9. **Squash membership ≠ git ancestry.** Carrier message + tree can support a contributor claim, but mixed Copilot/Claude authorship on the same file keeps topology NARROW (156). Do not CONFIRM topology from a squash message alone.
10. **NARROW is for unclosed wording/topology/uniqueness, not a parking lot.** 156/169/170 are warranted. 160 is the only first-pass NARROW this pass could close without stretching.
