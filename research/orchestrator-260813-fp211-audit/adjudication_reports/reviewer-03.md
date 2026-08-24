# Conflict adjudication — reviewer 03

Pinned contract: `AUDIT_CONTRACT.md` at repo `cd97a295956a8d3d46330bf9b0300ddded21f737`.
Owned outputs: `adjudications/reviewer-03.jsonl`, this report.
Raw clones/pages/notes: `/tmp/fp211-adjudicate-03/{clones,pages,notes}`.
No first/second pass files, canonical ledger, builders, or code were edited.

Reviewer **03** is excluded from the first two passes on every assigned packet. First/second JSONL were routing only. Each row was re-inspected against first-party GHSA/CVE/repo-advisory pages and parent/candidate/fix/release git evidence before a full 26-field row was chosen. Majority was not used. No commit.

Exclusion check (packet fields, not inferred): every row has `third_reviewer=3` and `3 ∉ {first_reviewer, second_reviewer}`:

| ordinal | first | second | third | changed_fields |
|--------:|------:|-------:|------:|----------------|
| 8 | 1 | 4 | 3 | identity_gate |
| 18 | 1 | 4 | 3 | verdict, identity_gate, but_for_gate, causal_class |
| 34 | 1 | 4 | 3 | identity_gate |
| 113 | 4 | 1 | 3 | verdict, topology_gate |
| 121 | 4 | 1 | 3 | uniqueness_gate |
| 125 | 4 | 1 | 3 | uniqueness_gate |
| 144 | 4 | 1 | 3 | verdict, confidence, ai_hunk_gate, but_for_gate, uniqueness_gate, causal_class, false_positive_class |

Coverage: **7/7** assigned ordinals, sorted 8, 18, 34, 113, 121, 125, 144.

Finalization boundary: new broad discovery stopped. These seven rows and this report are written from evidence already under `/tmp/fp211-adjudicate-03`. No conflicted field was left unresolved, so no gate was set UNKNOWN or BLOCKED to fill a side. BLOCKED unused: local clones and first-party pages existed for all seven ordinals.

## Verdict counts

| Verdict | n | Ordinals |
|---------|---|----------|
| CONFIRM | 1 | 18 |
| NARROW | 5 | 8, 34, 113, 121, 125 |
| FALSE_POSITIVE | 1 | 144 |
| UNKNOWN | 0 | — |
| BLOCKED | 0 | — |

CONFIRM/HIGH: **18** only.

## Conflict resolutions

Changed fields are from `conflict_inputs/reviewer-03.jsonl`. Other fields were still chosen independently.

### 8 `strict-200-v3:alias-12debd2395456ef3aa1dd946` — identity_gate NARROW vs PASS → **PASS**; verdict **NARROW**

Global `GHSA-j4xf-96qf-rx69` identifiers include `CVE-2026-32021`. CNA `CVE-2026-32021` vendor-advisory references that GHSA and patch `4ed87a66`. OpenClaw repo advisory HTTP 200 with `cve_id=null`. `m1heng/clawdbot-feishu` repo advisory HTTP 404. Both public IDs name Feishu display-name `allowFrom` and stay in `public_ids_keep`. A 404 or null `cve_id` is recorded, not identity failure.

`4286755f` is a parentless Claude Opus 4.5 root that grants `allowFrom` on `senderName`. OpenClaw parent `02842bef` `src/feishu/access.ts` is ID-only. Import carrier `2267d58a` (also Claude) copies the name grant into `extensions/feishu/src/policy.ts`. Fix `4ed87a66` is ID-only. Carrier in `v2026.2.21`; fix first in `v2026.2.22`. Topology NARROW (upstream root is not an OpenClaw ancestor). But-for NARROW (OpenClaw parent already had ID-only Feishu). Siblings 31/58/65/66 share the SHAs with different Feishu sinks; uniqueness PASS.

### 18 `strict-200-v3:alias-2d420fc19cb5fabda6edbe92` — verdict/identity/but_for/causal_class → **CONFIRM / PASS / PASS / AI_DIRECT_ROOT**

Repo `GHSA-fpmv-5wgw-qhhr` identifiers include `CVE-2026-34218`. Global `/advisories` HTTP 404 preserved. Identity PASS.

Parent `18789c5e` is two-process. `DaemonXPCServer.addFilterClient` pushes `mergedPolicyData()` immediately. `opfilter/XPCClient.registerAndFetchPolicy` comments that the daemon pushes after filter registration. `onPolicyUpdate` is that daemon path, not GUI.

Claude `5a887953` merges the daemon into opfilter. `XPCServer.init` calls `applyPolicyToFilter()` before `adapter.start()`. `ESInboundAdapter.updatePolicy` returns on nil client, so `FilterInteractor` stays on compile-time `faaPolicy`. `adapter.start(initialRules: server.mergedRules())` mutes ES prefixes but does not call `interactor.updatePolicy`. The GHSA window (managed/user rules until a GUI policy mutation) is created here. Parent did not have a GUI-until window. Causal class is origin, not incomplete remediation.

`v4.2.11-97eb073` still calls `applyPolicyToFilter` before `adapter.start` (331 later refactors; invariant held). Peeled `v4.2.14-56d617b` equals `56d617b7`, which moves apply after start. Candidate is an ancestor of the vulnerable tag. All required gates PASS.

### 34 `strict-200-v3:alias-63a1cac4d02e61992ad6cf29` — identity_gate NARROW vs PASS → **PASS**; verdict **NARROW**

Repo `GHSA-q9j6-xcvx-px63` aliases `CVE-2026-34599` (GetLogs `$container` interpolation). Global GHSA HTTP 404 preserved. Identity PASS.

Claude author `bbb2aa9a` adds `downloadAllLogs` interpolating `$this->container`. Parent `getLogs` already interpolates `docker logs {$this->container}`. GHSA names both. New surface, not origin. Merge carrier `4d4254b5`. Squash fix `f267a28c` (27 files) first in `v4.0.0-beta.471`; member `48ba4ece` adds `#[Locked]` on `$container`. Fix-reversal NARROW because the named minimum fix is multi-purpose. `v4.0.0-beta.461` contains the interpolation without the lock.

### 113 `post:claude-cache-statusline-injection@canonical` — verdict/topology CONFIRM/PASS vs NARROW/NARROW → **NARROW / NARROW**

Global+repo `GHSA-g3xq` aliases `CVE-2026-45136`. Claude Opus 4.7 `e19169011` first interpolates `json.loads('''$input''')`; parent `python3 -c` had no `$input` interpolation. Mechanism is real (but-for PASS).

Member blob `4d61ea1531…` ≠ carrier/`v3.5.0`/`v3.5.1` blob `626f3494c0…`. Member is not an ancestor of `v3.5.0`. Both blobs still contain the interpolation. Fix member `0a3e3c13` blob `853af30658…` equals `v3.5.2` and carrier `613e4df3` (patch-id `a2c5b537`). CONFIRM is refused: topology cannot PASS when the released vulnerable blob is not the origin-member blob.

### 121 `post:openclaw-sips-pixel@canonical` — uniqueness NARROW vs PASS → **PASS**; verdict **NARROW**

Global `GHSA-w85g` `cve_id` empty; CNA `CVE-2026-41334` vendor-advisory names that GHSA. Keep both IDs. Identity PASS.

Parent `f7123ec3` already has sips resize/decode in `src/media/image-ops.ts`. Claude `8d74578c` adds `images.ts` ingest (`loadWebMedia`). Fix `0ed4f8a7` adds `limitInputPixels` / fail-closed sips; candidate in `v2026.1.20`, fix first in `v2026.3.31`. Same SHA as ordinal 119 (`GHSA-9F72` workspaceOnly) and as 60/77; distinct invariants. Same SHA is not a duplicate. Uniqueness PASS.

### 125 `post:openclaw-feishu-tool-gate@canonical` — uniqueness NARROW vs PASS → **PASS**; verdict **NARROW**

Keep `GHSA-2Q7J` / `CVE-2026-62187` (Feishu **tools**). Remove `GHSA-W8WF` / `CVE-2026-62188` (permission-tools). Repo objects do not alias each other. Each CNA vendor-advisory points at its own GHSA. Global GHSAs 404; repo `cve_id=null`. Packed extras keep `identity_gate=NARROW`. After remove, no same-mechanism duplicate vs other 211 rows; uniqueness PASS.

Claude `5f6e1c19` adds per-account `tools` config (first in `v2026.2.6`). Parent already had top-level `tools-config`. Fix `d4f11d30` (`v2026.6.9`) gates docx/drive/wiki and `perm.ts`. Shared later reversal does not alias W8WF.

### 144 `post:gitpython-checkout-tag-options@canonical` — NARROW incomplete vs FALSE_POSITIVE wrong_edge → **FALSE_POSITIVE / wrong_edge**

`GHSA-3F7W` is `IndexFile.checkout()` `--prefix` and `TagReference.create()` `--file`. GPT `1d51b891` subject is `fix: guard diff output options`, references `GHSA-fjr4`, and touches only `git/diff.py`, the index **diff** path, and `test/test_diff.py`. Zero checkout/TagReference/`--prefix`/`--file` hunks. `3af0c251` first guards those APIs (in `3.1.57`, absent from `3.1.56`).

`1d51b891` is the complete-fix SHA of ordinal 172 / `GHSA-FJR4`, not an attempt at 3F7W. Incomplete-remediation requires an explicit same-boundary attempt. `ai_hunk_gate=FAIL`, `but_for_gate=FAIL`. Sharing that SHA with 172 as *fix* vs *candidate* is uniqueness PASS, not a merge. `duplicate_of` remains null. Keep `GHSA-3F7W`.

## Public-ID conservation

`public_ids_keep ∪ public_ids_remove` equals each input `public_ids` set. Only ordinal **125** removes IDs (`CVE-2026-62188`, `GHSA-W8WF-3QVJ-6XQF`). No keep/remove overlap.

## Replay (cross-cutting)

Git flags: `git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false`.
Clones under `/tmp/fp211-adjudicate-03/clones/` are `--no-checkout` with local `--reference`. Inspection used `git show SHA:path`, `git grep`, `git diff A B -- path`, `git merge-base --is-ancestor`, `git rev-parse TAG:path`.

Advisory fetches: GitHub `/advisories/{GHSA}`, `/repos/{owner}/{repo}/security-advisories/{GHSA}`, MITRE `https://cveawg.mitre.org/api/cve/{CVE}`. Status files sit next to JSON under `/tmp/fp211-adjudicate-03/pages/`.

## Limitations

- OpenClaw SHAs for ordinal 8 were resolved in `openclaw-v2`; upstream Feishu root `4286755f` is only in `clawdbot-feishu`.
- Ordinal 18 CONFIRM treats later refactors that preserve apply-before-start as the same origin edge because `5a887953` is an ancestor of `v4.2.11`. Defect 2 (`ddfdacb` cache clear) is already a parent of `56d617b7` and is not a second origin.
- Ordinal 34 minimum fix remains the CNA squash `f267a28c`; the GetLogs member `48ba4ece` is not claimed as a tag ancestor.
- Uniqueness vs non-assigned siblings used first/second-pass SHA sets (31/58/65/66, 60/77/119, 172/180), not a second hunk audit of those rows.
- Global GHSA 404s and null repo `cve_id` are preserved in evidence; they did not by themselves NARROW identity when the remaining first-party object plus CNA closed the alias.

## Reusable experience

1. **Daemon XPC is not GUI XPC.** Parent `onPolicyUpdate` after filter register can close a boot window that a later in-process `applyPolicyToFilter` before `es_new_client` re-opens.
2. **Global-or-repo 404 is evidence, not identity NARROW**, when the other first-party object and CNA formally alias.
3. **Squash member blob ≠ tag blob** blocks CONFIRM even when both blobs contain the primitive.
4. **Same SHA is uniqueness PASS** when source/sink/invariant differ; packed extra GHSAs are an identity problem, not a uniqueness fail after remove.
5. **A complete fix of a sibling advisory is a wrong edge**, not incomplete remediation, unless the candidate actually edits the named APIs.
