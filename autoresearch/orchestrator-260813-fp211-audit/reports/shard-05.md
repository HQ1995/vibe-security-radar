# Shard 05 false-positive audit (ordinals 145–180)

Pinned contract: `AUDIT_CONTRACT.md` at repo `cd97a295956a8d3d46330bf9b0300ddded21f737`. Input: `inputs/shard-05.jsonl`. Owned outputs: `shards/shard-05.jsonl`, this report. Raw pages/clones: `/tmp/fp211-shard-05`. Canonical files, other shards, caches, and git history were not modified. JSONL is one row per ordinal 145–180 in final order; this checkpoint only tightened already-closed rows 155 and 157.

## Coverage

Exactly 36 input rows, ordinals **145–180**, in ordinal order. `row_key` and `baseline_state` conserved from input. `public_ids_keep ∪ public_ids_remove` equals each input `public_ids` set.

| Verdict | Count | Ordinals |
|---|---|---|
| CONFIRM | 14 | 147, 148, 152, 155, 157, 161, 162, 163, 164, 166, 167, 171, 176, 179 |
| NARROW | 4 | 156, 160, 169, 170 |
| FALSE_POSITIVE | 16 | 145, 146, 149, 150, 151, 158, 159, 165, 168, 172, 173, 174, 175, 177, 178, 180 |
| UNKNOWN | 2 | 153, 154 |
| BLOCKED | 0 | — |

All 14 CONFIRMs are **HIGH**. Only CONFIRM/HIGH is eligible as a final confirmed case without another review. Checkpoint pass re-read Order controller blobs and Vitest `rpc.ts`; no new CONFIRMs were inferred to fill coverage. UNKNOWN **153/154** stay UNKNOWN.

## Identity (first-party, 404s preserved)

Repo GHSA 200 / global 404 (unreviewed): Coolify CHG4, 962V; GitPython 284H, 8MCC, 5XXX, 3WXW.

Repo GHSA 404 / global 200 (keep both IDs): Prospero 4FXP, Q2F8, M6X4, X8QQ; WACRM X2W7; MISP MF7V.

CVE program 404 with GHSA still aliasing CVE (keep both): CVE-2026-58432, CVE-2026-55987, CVE-2026-57148.

Faraday candidate cites sibling **GHSA-33mh-2634-fwr2**, which is **not** in the 211. Uniqueness vs that sibling is therefore PASS inside this population.

## False-positive / narrow counterexamples

### 145 `coolify-shell-grammar` — FALSE_POSITIVE / WRONG_EDGE

GHSA-chg4 names human `e2ba44d0c` (no AI trailer) adding `&`/`"` to `SHELL_SAFE_COMMAND_PATTERN`. Parent of Claude `c9922c30` already applies `shellSafeCommandRules()` to `docker_compose_custom_{start,build}_command`. The AI commit only attaches that already-regressed helper to install/build/start. Removing the candidate leaves the advisory sink. Tokenizer `817128c5` is merge-carried by `e1aac50b`; beta.471–473 is real for the **pattern**, not this AI edge.

### 146 `coolify-activity-scope` — FALSE_POSITIVE / OLD_BUG_PRESERVING_REFACTOR

GHSA-962v: unlocked `$activityId` + `Activity::find` with no auth; affected **≤ beta.470**, patched **≥ beta.471**. Parent of `a94517f4` already has unscoped `find()`. Candidate adds fail-open `if ($teamId && …)`. Complete fix `3e0d48fa` (`#[Locked]` + fail-closed) shares first tag **beta.471**. No candidate-only release; deleting the candidate does not remove the advisory mechanism.

### 149 `prospero-calendar-delete` — FALSE_POSITIVE / WRONG_EDGE

GHSA-q2f8 names `CalendarDeleteEventController`. Squash `#248` / `a3a2f9f5` hardens `CalendarExportController` and other web controllers; it does **not** list the delete-event file. `8c26eed4` is the first touch. Sibling unguarded call site, not incomplete of this GHSA.

### 150 `prospero-notification-delete` — FALSE_POSITIVE / WRONG_EDGE

GHSA-m6x4 names `DeleteNotificationController::delete`. Same squash hardens mark-read/latest-ajax, not delete. `eaee2ae0` is the first delete-ownership patch.

### 151 `dynatrace-mcp-auth` — FALSE_POSITIVE / WRONG_EDGE

GHSA-p7w7 is **unauthenticated** HTTP `tools/call`, affected ≤1.8.7, patched ≥2.0.0. Claude `aab80e` only changes default bind `0.0.0.0`→`127.0.0.1`. Member is not an ancestor of `v2.0.0`; squash carrier `ac5251e` and bearer-auth `8f129724` both first appear in `v2.0.0`. Bind is a different boundary; the bind-only state is not in `v1.8.7`.

### 158 / 159 mistune — FALSE_POSITIVE / WRONG_EDGE

Claude `5afeaf6b` is “Filter image-directive src through safe_url” (`directives/image.py`). Both GHSAs name `HTMLRenderer.safe_url` (percent-decode vs legacy schemes). Candidate and renderer fix `c7101fcb` share first tag **v3.3.0**; candidate is outside GHSA affected ranges (≤3.2.0 / ≤3.2.1). Wiring a new caller through a preexisting weak helper is not but-for.

### 165 `filebrowser-delete-scope` — FALSE_POSITIVE / WRONG_EDGE

GHSA-fmm7 is incomplete **v2.63.14 ScopedFs** `Remove`/`RemoveAll` skipping `guard()`. AI `847d08bd` has zero Remove hunks. Human `7c2c0a11` (no AI marker) introduces unguarded Remove. `64511ce` adds `guard()`. Matches baseline REJECT.

### 168 `gitea-oauth-reactivation` — FALSE_POSITIVE / HUMAN_WEAKENED_AI_PREDICATE

Claude member `eff673fc` implements the **three-field** sync-disable signature. Shipped carriers `c43eb7c3` / backport `2bde4fa5` use `RefreshToken == ""` only. Later `fce961b4` restores the three-field predicate. Parent of the AI member never-reactivates (safer). The advisory residual is human/squash weakening, not the AI hunk. Matches baseline REJECT. CVE program 404 preserved.

### 172–175, 177–178 GitPython — FALSE_POSITIVE / WRONG_EDGE

| Ord | Claimed GHSA | Candidate actually did | Why FP |
|---|---|---|---|
| 172 | FJR4 Diffable.diff `--output` | `701ce32f` GHSA-956x on commit/blame/archive/clone; no `git/diff.py` | sibling mixin |
| 173 | HH9P pathspec-from-file on remove/Head.checkout | `3af0c251` checkout-index `--prefix` + tag `--file` kwargs | 3F7W cleared those sites |
| 174 | 9RJ7 Repo.init `--template` | `7a4f5dcb` archive add-file / bundle-uri (ordinal 142 / GHSA-539M); clone `--template` is ordinal 140 | never attempted init |
| 175 | 4GMW read-tree `--index-output` | `3af0c251` checkout-index/tag only | never attempted read-tree |
| 177 | 284H dormant multiline rewrite | `c417af46` write-time value CR/LF/NUL | different invariant |
| 178 | 8MCC clone `--separate-git-dir` | `7a4f5dcb` bundle-uri/add-file; 0 `--separate-git-dir` hits | omitted sibling option |

### 180 `gitpython-tag-positional-file` — FALSE_POSITIVE / DUPLICATE_MECHANISM

GHSA-3WXW: positional `reference="--file=..."` bypasses the kwargs-only `--file` guard from `3af0c251`. Same `TagReference.create` `--file` sink as **ordinal 144** `post:gitpython-checkout-tag-options@canonical` / GHSA-3F7W. `duplicate_of` set. Uniqueness FAIL. Matches baseline REJECT.

### NARROW

- **156 langroid**: Copilot one-line `config.full_eval`→`self.config.full_eval` activates a weak sanitizer. Carrier `0d9e4a7b` is in 0.53.15–0.59.31 without fix `30abbc1a` (0.59.32). Topology NARROW: squash membership of the member inside the carrier was not independently proven this pass.
- **160 fast-uri**: Claude literal-`//` authority check leaves `\\` `/\\` `\\/` introducers. Candidate-only tag `v4.1.1`. Local clone has **no tag containing** fix `f3c6c905` (GHSA names 4.1.2).
- **169 praisonai-jwt**: Cursor default-open `PLATFORM_ENV="dev"` guard is the GHSA-f38v residual of GHSA-3qg8. pyproject `0.1.2`→`0.1.4` at the git fix; advisory is **praisonai-platform PyPI**, not monorepo tags `v4.6.40+`. sdist replay not completed. CVE 404 preserved.
- **170 gitpython-joined-short**: shlex-split denylist misses `-uVALUE`. Git tags **3.1.47–3.1.50** vs GHSA wording **= 3.1.50 only**.

## CONFIRM (high-signal)

147 n8n-mcp IPv4-only `validateUrlSync` (v2.47.4–13 / 2.47.14). 148 Prospero permission auth-without-authorize (v4.6.0 / v5.5.3). 152 WACRM meta-send vs engine dispatcher (commit-only, no tags). 155 Prospero Order/OrderItem APIs: Claude `OrderReadController` uses `Order::find($id)` with no `company_id`; fix scopes `where('company_id', Auth::user()->company_id)`; same first tag v5.5.3 (commit-only). 157 Vitest: Codex `af88b1f5` adds allowWrite gates while `cdp.send` stays ungated in `packages/browser/src/node/rpc.ts`; child `385a1aef` (parent is the candidate) disables client CDP; both first in v3.2.5. 161 locutus `RegExp.test` guard (v2.0.39–v3.0.24 / v3.0.25). 162 Gitea API draft gate vs web UUID (v1.25.5 / v1.26.4 vs v1.27.0 backport `ab10e37a`). 163 Scriban LoopLimit misses `array*int` (7.0.0–7.2.0 / 7.2.1). 164 Faraday string `//` vs URI objects (v2.14.1 / v2.14.2). 166 Filebrowser dangling-write documented in `WithinScope` (v2.63.6–15 / v2.63.16); distinct from 165 and zip-slip ordinal 14. 167 Scriban depth limit logs and continues (7.0.0–7.2.0 / 7.2.1). 171 GitPython value-only newline (3.1.49 / 3.1.50). 176 option-name `=/#/space` after section-delimiter patch (3.1.53–57 / 3.1.58); distinct from 141 and 171. 179 blame `--output` denylist omits `--contents` (3.1.51–58 / 3.1.59); distinct from 172.

## UNKNOWN (preserved)

- **153 MISP**: GHSA-mf7v is a multi-controller mass-assignment set. Claude `bc182d55` is Event.php id-strip; proposed fix `025f7115` is Taxonomy.php. Both first in v2.5.42. Cannot close one AI partial→complete subset for the whole advisory.
- **154 OmniFaces**: GHSA-fp43 lists combined-resource IDs, source-map cache, HashParam, push. Candidate is CombinedResource*; proposed fix is SourceMapResourceHandler. No local tags. Multi-mechanism unclosed.

## Replay commands (shard-wide)

```bash
python3 -c 'import json,pathlib; p=pathlib.Path("autoresearch/orchestrator-260813-fp211-audit/shards/shard-05.jsonl"); rows=[json.loads(l) for l in p.read_text().splitlines() if l.strip()]; print(len(rows), [r["ordinal"] for r in rows][:3], [r["ordinal"] for r in rows][-3:])'
python3 autoresearch/orchestrator-260813-fp211-audit/verify.py --allow-partial
git -C /tmp/fp211-shard-05/clones/coolify grep -n shellSafeCommandRules e39678aea584be533f89052d4e2939f2d8834449 c9922c30c2a6bf922653a5f2d631aab4fea685c4 -- app
git -C /tmp/fp211-shard-05/clones/gitea grep -n isDisabledByAutoSync c43eb7c33a100ffc7b2367adf165f7085e0ccdc5 -- routers/web/auth/oauth.go
git -C /tmp/fp211-shard-05/clones/filebrowser show -s --format='%s%n%b' 7c2c0a11b31b2bb214d741005a0b02b1764208b3
```

Per-row replay commands are in `shards/shard-05.jsonl`.

## Finalization

Stopped further discovery. `shards/shard-05.jsonl` has exactly 36 rows (ordinals 145–180, one per ordinal). `verify.py --allow-partial` and `verify.py` both: `PASS: 211/211`. Shard-05 verdicts: CONFIRM 14, NARROW 4, FALSE_POSITIVE 16, UNKNOWN 2, BLOCKED 0. No CONFIRM was labeled to fill coverage; 153/154 remain UNKNOWN.

## Limitations

- MISP and Scriban used original cache clones (`clones/misp-orig`, `clones/scriban-orig`) after `/tmp` clone-to-shared failed.
- Some Gitea objects were fetched into `/tmp/fp211-shard-05/clones/gitea`; GitPython tags 3.1.58/3.1.59 and Dynatrace/Gitea release tags were fetched into `/tmp` clones only.
- Prospero Order controller blobs are readable via `git show SHA:path`; an earlier `git show` grep failed on missing diff blobs, but tree objects close 155.
- PraisonAI PyPI sdists were not hashed; 169 stays NARROW (`pypi_artifact_not_git_tag`).
- fast-uri fix SHA `f3c6c905` has no local tag; 160 stays NARROW on `release_gate`.
- Langroid squash-member proof is carrier-tag evidence, not `git log` membership of `b1c45e3f` inside `0d9e4a7b`; 156 stays NARROW on `topology_gate`.
- 153/154 are multi-mechanism advisories whose proposed fixes do not reverse the candidate residual; not closed as CONFIRM.
- 168 `release_gate` is UNKNOWN (member/fix not on inspected mainline tags); verdict is still FALSE_POSITIVE on hunk/but-for.
- Existing research docs were routing only; verdicts use GHSA JSON under `/tmp/fp211-shard-05/pages` and local git. Mechanical 36/36 coverage is not a public-case count.

## Reusable lessons

1. **Wrong edge vs incomplete.** Incomplete remediation requires the AI hunk to attempt the **same** source/sink/invariant. Sibling controllers, sibling git subcommands, and shared-helper callers fail but-for.
2. **Human regression / squash weakening.** GHSA-chg4’s `&` and Gitea OAuth’s empty-refresh predicate are human (or squash) weakenings of safer states. AI trailers on nearby commits are not causality.
3. **Same first tag is commit-only.** Candidate and fix sharing the first containing tag cannot support a released incomplete-remediation claim (`release_gate=NA`).
4. **Preserve 404s.** Repo-unreviewed GHSAs, repo-404/global-200 aliases, and CVE-program 404s stay in `public_ids_keep`.
5. **Uniqueness is mechanism, not SHA.** Same AI commit can yield one CONFIRM (166 dangling write) and one FP (165 delete). Same tag `--file` sink as ordinal 144 is a duplicate (180).
6. **Multi-fix advisories stay UNKNOWN.** Do not CONFIRM a whole mass-assignment or OmniFaces combined-resource umbrella from one AI file and a non-reversing proposed fix.
7. **Package artifact ≠ git tag.** praisonai-platform 0.1.x is not PraisonAI monorepo `v4.6.x`.
8. **Backports are first-class.** Gitea draft containment uses `e7fca90a` (v1.25.5) and `ab10e37a` (v1.27.0), not only the mainline SHAs.
