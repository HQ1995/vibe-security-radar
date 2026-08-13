# FP211 third-party conflict adjudication (reviewer 06)

Pinned contract: `autoresearch/orchestrator-260813-fp211-audit/AUDIT_CONTRACT.md`.
Assigned packets: `conflict_inputs/reviewer-06.jsonl` (exactly ordinals **11, 25, 36, 115, 123, 140**).
Owned outputs only: `adjudications/reviewer-06.jsonl`, this report.
Raw clones/pages/notes: `/tmp/fp211-adjudicate-06/{clones,pages,notes}`.
No first/second-pass shards, canonical ledger, builders, or code were edited. No commit.

Exclusion check (packet `first_reviewer` / `second_reviewer` / `third_reviewer`):

| Ord | first | second | third | 06 excluded from first two |
|-----|------:|-------:|------:|----------------------------|
| 11  | 1 | 4 | 6 | yes |
| 25  | 1 | 4 | 6 | yes |
| 36  | 1 | 4 | 6 | yes |
| 115 | 4 | 1 | 6 | yes |
| 123 | 4 | 1 | 6 | yes |
| 140 | 4 | 1 | 6 | yes |

First and second passes were hypotheses. Every row was re-checked against independently fetched GHSA/CVE/repo-advisory pages and `git` parent/candidate/fix/release evidence. Changed fields were not resolved by majority.

## Verdict counts

| Verdict | n | Ordinals |
|---------|---|----------|
| FALSE_POSITIVE | 3 | 11, 36, 140 |
| NARROW | 3 | 25, 115, 123 |
| CONFIRM / UNKNOWN / BLOCKED | 0 | — |

## Conflict resolutions

### 11 karakeep Reddit XSS — identity_gate NARROW vs PASS

Independent: **identity PASS**. Verdict **FALSE_POSITIVE / HIGH** `old_bug_preserving_refactor` (agrees with both passes on causality).

Repo advisory `GHSA-mg93-f9mw-wpgj` identifiers include `CVE-2026-27627`; `cve_id` is set. Global `/advisories` 404 is preserved and is not identity pollution. Human `f5c32d94` already passed `meta.readableContentHtml` unsanitized in `crawlerWorker.ts`. Claude `e193701d` copies that ternary into new `parseHtmlSubprocess.ts`. Named affected `v0.30.0` still has the parent path and is not an ancestor of the candidate. Fix `ba3db953` sanitizes only the copy. `but_for` FAIL and `release` FAIL.

### 25 titra native-vm sandbox — identity_gate NARROW vs PASS

Independent: **identity PASS**. Verdict **NARROW / HIGH** `AI_NEW_SURFACE_CONTRIBUTOR`.

Repo `GHSA-pqgx-6wg3-gmvr` formally aliases `CVE-2025-69288`. Global 404 preserved. Parent `62fe0533` already `vm.run(timeEntryRule)` via vm2. Copilot `40331e61` replaces vm2 with `vm_sandbox.js`. Squash carrier `67c7b766` blob equals `0.99.48`; member blob differs only in function wrapping. Fix `2e2ac5cb` / `0.99.49` adds `validateSandboxCode`. Whole-advisory but-for fails (`but_for` NARROW).

### 36 n8n-workflows path join — identity_gate NARROW vs PASS

Independent: **identity NARROW**. Verdict **FALSE_POSITIVE / HIGH** `unreleased_commit_only`.

Global `GHSA-c7rr-qhwx-6q49` aliases `CVE-2025-55526`; repo advisory 404. The GHSA “Main Commit ee25413” is `ee254131…` (Merge PR #37 category-search) and does not introduce `download_workflow`. Claude `ff958e48` first adds `os.path.join('workflows', filename)`; parent `5d3c049a` has no `api_server.py`. Keep both IDs. Only tag/release `dmca-compliance-2025-08-14` already contains fix `64f9f86f`. `release` FAIL.

### 115 hermes profile search — topology PASS vs NARROW; uniqueness NARROW vs PASS

Independent: **topology NARROW**, **uniqueness PASS**. Verdict **NARROW / HIGH**.

`GHSA-mgxw` aliases `CVE-2026-49956`. Parent already had `/api/sessions/search` over `all_sessions()`. Claude `d2b27f6f` adds `Session.profile` without scoping search (`but_for` NARROW). Fix member `8d8ae89d` `api/routes.py` blob `d5c5be6a…` ≠ carrier/`v0.51.269` blob `433317ae…`; released blob still has `_profiles_match`. Origin is in `v0.51.268` without the fix carrier and in `v0.51.269` with it. Same SHA as ordinal 2 dotenv is a distinct sink, so uniqueness PASS.

### 123 openclaw workspace shadow — uniqueness NARROW vs PASS

Independent: **uniqueness PASS** (identity stays **NARROW**). Verdict **NARROW / HIGH**.

`GHSA-2qrv` ↔ `CVE-2026-41295` is this row’s public-identity case (setup/login shadow; fix `53c29df2`; patched `2026.4.2`). `GHSA-82qx` ↔ `CVE-2026-43571` is a later catalog residual (fix `1fede43b`; patched `2026.4.10`) and is **removed**. Those four IDs appear on no other of the 211 rows. Packed extras are identity, not uniqueness. AI member `fc1b156d` / carrier `f4cc93dc` first in `v2026.3.22`.

### 140 GitPython clone `--template` — CONFIRM vs FALSE_POSITIVE

Independent: **FALSE_POSITIVE / HIGH** `old_bug_preserving_refactor`. Overturns first pass.

`GHSA-6p8h-3wgx-97gf` is clone `--template` omitted from `unsafe_git_clone_options`. Parent of `701ce32f` already had the four-item list (`--upload-pack/-u/--config/-c`) from human `e6108c79` (2022). The GPT commit keeps that list, rewrites option collection, and never mentions `template`. Deleting it leaves `--template` unblocked. Incomplete-remediation requires an explicit same-boundary attempt. Contrast ordinal 142, where the same commit *introduces* `unsafe_git_archive_options`. Later `ffcb5359` adds `--template` (in `3.1.54`, not `3.1.53`).

## Disagreements with each pass (conflicted fields)

| Ord | Field | First | Second | This review |
|-----|-------|-------|--------|-------------|
| 11 | identity_gate | NARROW | PASS | **PASS** |
| 25 | identity_gate | NARROW | PASS | **PASS** |
| 36 | identity_gate | NARROW | PASS | **NARROW** |
| 115 | topology_gate | PASS | NARROW | **NARROW** |
| 115 | uniqueness_gate | NARROW | PASS | **PASS** |
| 123 | uniqueness_gate | NARROW | PASS | **PASS** |
| 140 | verdict | CONFIRM | FALSE_POSITIVE | **FALSE_POSITIVE** |
| 140 | confidence | MEDIUM | HIGH | **HIGH** |
| 140 | but_for_gate | PASS | FAIL | **FAIL** |
| 140 | causal_class | AI_INCOMPLETE_REMEDIATION | OLD_BUG_PRESERVING_REFACTOR | **OLD_BUG_PRESERVING_REFACTOR** |
| 140 | false_positive_class | null | old_bug_preserving_refactor | **old_bug_preserving_refactor** |

SHA sets, keep/remove IDs, and `duplicate_of` match both passes on every assigned row. Public-ID conservation holds against each input `public_ids` set.

## Finalization

New broad discovery stopped. These six rows and this report are written from evidence already under `/tmp/fp211-adjudicate-06`. No conflicted field was left unresolved, so no gate was set UNKNOWN or BLOCKED to fill a side. BLOCKED unused: local clones and first-party pages existed for all six ordinals.

## Limitations

- n8n clone lacks `ee254131…`; that SHA was confirmed via GitHub commit API already in the evidence tree, not local `merge-base`.
- Titra/karakeep global reviewed GHSA pages remain 404; first-party repo objects were used.
- Uniqueness vs the other 211 rows used manifest `public_ids` and mechanism keys, not a second hunk audit of every sibling GitPython/OpenClaw row.

## Reusable lessons

1. Global GHSA 404 with a complete repo advisory formal alias is identity PASS, not NARROW.
2. A GHSA that names the wrong introduced commit is identity NARROW even when the CVE alias is real.
3. Uniqueness NARROW is for same-mechanism duplicates across the 211; packed extras and shared SHAs with different sinks are identity and uniqueness-PASS respectively.
4. Incomplete remediation is not “AI commit preceded the GHSA.” The candidate must attempt the same boundary.
5. Fix-member blob ≠ released carrier blob is topology NARROW even when the primitive is present on the tag.
