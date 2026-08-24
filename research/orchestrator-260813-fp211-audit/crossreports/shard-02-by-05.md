# Cross-review shard 02 by reviewer 05 (ordinals 37-72)

Coverage: **exactly ordinals 37-72** from `inputs/shard-02.jsonl` against `AUDIT_CONTRACT.md`.
Owned outputs: `crossreviews/shard-02-by-05.jsonl`, `crossreports/shard-02-by-05.md`.
JSONL is **36/36**, one compact 26-field row per ordinal in order 37–72.
No canonical ledger, first-pass shard, code, manifest, other shards, or caches were edited. No commit.
Independent clones and raw pages: `/tmp/fp211-cross-05`. First-pass citations were treated as routing only, not proof.

Rotation: reviewer 05 → first-pass shard 02.

## Verdict counts

| Verdict | n | ordinals |
|---------|--:|----------|
| CONFIRM | 13 | 39, 42, 43, 44, 46, 49, 54, 57, 58, 63, 64, 65, 66 |
| NARROW | 10 | 37, 40, 47, 52, 55, 60, 61, 62, 70, 71 |
| FALSE_POSITIVE | 10 | 38, 41, 45, 48, 50, 59, 67, 68, 69, 72 |
| UNKNOWN | 3 | 51, 53, 56 |
| BLOCKED | 0 | — |
| **total** | **36** | 37-72 |

None of the CONFIRM rows is a final HOLD case by itself. Contract still requires independent review of every non-CONFIRM/HIGH row before a rebuilt canonical ledger.

## Disagreements with first pass

First pass: `shards/shard-02.jsonl` / `reports/shard-02.md`. Compared after independent advisory + git parent/candidate/fix inspection. First-pass citations were not treated as proof.

### Verdict disagreements (1)

1. **Ord 48 / GHSA-9W78 / CVE-2026-2376.** First pass `UNKNOWN` / `RELEASE_CONTAINMENT_UNPROVEN` / MEDIUM. This review `FALSE_POSITIVE` / `unreleased_commit_only` / HIGH.
   - First pass used a cache clone with **0 tags** and preserved UNKNOWN. Independent clone `/tmp/fp211-cross-05/clones/quay` has **179 tags**.
   - Carrier `92b6f472` is in `v3.17.0`–`v3.18.0`. Squash members `bb7c06ae` / `a6d759cd` are **not** ancestors of those tags.
   - Every tag that contains `92b6f472` already has `validate_external_registry_url` (`v3.17.*` backport `729cfdfb111f4916556585679bb463421a1e1b8c`; `v3.18.0` merge `33908b87ba58290897daf6c715fb887bc67ff3a3` of #5074). `v3.16.5` lacks the origin.
   - Listed min-fix members `9afe28a5` / `5ad2b732` are **not** ancestors of HEAD or those tags. Equivalent repair, different SHA.
   - `release_gate` UNKNOWN → FAIL. Identity stays NARROW (unreviewed GHSA-9w78 + Red Hat CVE-2026-2376). Keep both public IDs.
   - Evidence: `/tmp/fp211-cross-05/git/quay-tag-containment.json`, `/tmp/fp211-cross-05/advisories/unreviewed-ghsa-9w78-x9jw-9c7m.json`, `/tmp/fp211-cross-05/pages/CVE-2026-2376.json`.

### Gate / set disagreements, same verdict (2 ordinals / 3 gates + 1 min-fix)

| Ord | Field | First pass | This review | Why |
|-----|-------|------------|-------------|-----|
| 61 | `fix_reversal_gate` | NARROW | PASS | Selected closer is `8aa2bb6d1af6e8c57c8d8437cf203acb8bce7a53` (`Galaxy->buildConditions`). Listed `d3adfe1a` embeds PHP `'Galaxy.distribution' > 0` in a CakePHP conditions array and does not close other-org distribution-0 galaxies. |
| 61 | `uniqueness_gate` | NARROW | PASS | 61 is the origin row (`47bf71cc` first `Galaxy.find` with only `Galaxy.enabled=true`; parent `__setBuilderConfig` had no Galaxy load). 67 is the residual closer / duplicate, not a second origin. Sharing a SHA with a later duplicate does not make the origin uniqueness-NARROW. |
| 61 | `minimum_fix_set` | `d3adfe1a097d…` | `8aa2bb6d1af6…` | Put the commit that actually closes the sink in the min-fix set. Identity/release stay NARROW because CVE-2026-10854 names `d3adfe1a` and `v2.5.39` ships that insufficient patch (`v2.5.40` is the first tag with `8aa2bb6d`). Verdict remains NARROW. |
| 68 | `ai_hunk_gate` | NARROW | UNKNOWN | Conductor `473c3227` subject is only `Changes auto-committed by Conductor` with no AI trailer. Claude is on fix `99043600`, not origin. Sibling ordinal 35 used the same SHA and left `ai_hunk_gate` UNKNOWN. Do not treat Conductor as a relevant-hunk AI marker. Verdict remains FALSE_POSITIVE (`identity_mismatch` + uniqueness FAIL vs 35). |

### Public-ID disagreements

**None.** For every ordinal, `public_ids_keep` / `public_ids_remove` match first pass.

Ordinal 52 independently re-checked: keep `GHSA-7C3W-FXGH-FRC7`; remove `CVE-2026-61462` + `GHSA-5383-J2P9-QFG3`. Repo advisory `/tmp/fp211-cross-05/pages/repo-GHSA-7C3W-FXGH-FRC7.json` has `cve_id` null (FIRST_PARTY_GHSA_NO_CVE). Unreviewed GHSA-5383 aliases only CVE-2026-61462. VulnCheck CNA `/tmp/fp211-cross-05/pages/CVE-2026-61462.json` does not alias GHSA-7c3w; affected `<2.1.18` vs first-party patched `<2.1.32`. Same-repo/same-fix is not a formal alias.

No other keep/remove split on this shard. GHSA+CVE rows that are formal aliases keep both IDs.

### Explicit non-disagreements (checked, not flipped)

- Did **not** demote 46 CONFIRM: GHSA-68v4 has empty CVE identifiers and names later `e704323`; CNA CVE-2026-41345 references the GHSA; min-fix `f865a545` is an ancestor of `e704323` and is the true header-drop reversal. Git tags `v2026.3.28` / `v2026.3.31` contain origin without fix then with fix.
- Did **not** FP 56 from yanked npm history: packument versions dict is only `8.2.4`; that tag contains origin **and** fix `57b76343`. Preserve UNKNOWN rather than infer `unreleased_commit_only`.
- Did **not** upgrade any NARROW to CONFIRM. Product-wide GHSA wording vs a new call site stays NARROW (identity/but-for), not NARROW-overuse.
- Did **not** treat global GHSA API 404 as missing identity when a repo advisory or CNA object closed the alias (39 X9QH, 41 378W, 52 7C3W, 53 8JQH, 55 C339, 64 6MWV, 68 4VFF).
- UNKNOWN preserved for 51 (staged-fix workflow; PR #14876 is CommandAuthorized, not pairing-store AI) and 53 (wacrm 0 tags; CVE names merge `23838a99`, not origin).

## FALSE_POSITIVE counterexamples (independent)

1. **38 / GHSA-JMF4 / CVE-2026-44937 — `old_bug_preserving_refactor`.** Parent already interpolates `u.Path` into `regexp.MustCompile` without `QuoteMeta`. Candidate `b6115302` only switches Path→EscapedPath. Fix `c967a3c1` adds `QuoteMeta`. Deleting the candidate leaves the advisory regex injection.
2. **41 / GHSA-378W / CVE-2026-33890 — `old_bug_preserving_refactor`.** Parent already `path.includes("/passkeys/register")`. Candidate `b7bf9b79` re-lists the same public register path in `PUBLIC_PREFIX_PATHS`. Repo advisory `/tmp/fp211-cross-05/pages/repo-GHSA-378W-XH68-QRC8.json`.
3. **45 / GHSA-MHGQ / CVE-2026-41394 — `wrong_edge`.** Candidate `3e9c8721` is Control UI 405-fallthrough for non-GET under `controlUiBasePath`. Parent already had `WRITE_SCOPE`. Human `a1520d70` later attaches WRITE_SCOPE on plugin HTTP. Listed fix `2a1db0c0` sets plugin-auth scopes to `[]` when gateway auth is off and does not restore 405. Deleting `3e9c8721` leaves the advisory WRITE_SCOPE path.
4. **48 / GHSA-9W78 / CVE-2026-2376 — `unreleased_commit_only`.** See verdict disagreement. No published git tag contains origin persist without SSRF validation.
5. **50 / GHSA-MQM2 / CVE-2026-10860 — `not_causal`.** Candidate `687291e5` `EventTemplatesController::delete()` passes only `conditions` into `CRUD->delete` (no `$validationError === null && POST` bypass). Unreviewed GHSA. Fix `a5877559` does not reverse a candidate-specific surface. The CRUD bypass lives on other controllers, not this endpoint.
6. **59 / GHSA-W2CG / CVE-2026-29612 — `old_bug_preserving_refactor`.** Human `1dd5c97a` (`feat: add ws chat attachments`) already `Buffer.from` before size limit. Claude `c4e76eb6` copies the same pattern. Deleting the Claude parser leaves the advisory sink.
7. **67 / GHSA-CJP7 / CVE-2026-54362 — `same_mechanism_duplicate`.** Same `47bf71cc` / same `Galaxy.find` enabled-only sink as 61. `8aa2bb6d` is the human closer of 61's insufficient listed fix, not a second AI origin. `duplicate_of` = `strict-200-v3:alias-b52bedc69eca463aef477f74`. Uniqueness FAIL. CVE-2026-54362 names `8aa2bb6d`.
8. **68 / GHSA-4VFF / CVE-2026-34149 — `identity_mismatch`.** Repo advisory summary: *Authenticated Host-Level RCE via Unescaped Database Credentials in Backup Jobs*. Parent already interpolates Mongo collection names (`mongodump --excludeCollection`) and `update_backup` already writes `databases_to_backup`. Conductor `473c3227` adds `create_backup`; no AI trailer. Same candidate/carrier SHAs as ordinal 35 (GHSA-4MPW / CVE-2026-34049). Identity FAIL + uniqueness FAIL. `duplicate_of` = `strict-200-v3:alias-69c709472a21c9ed2b2637a2`.
9. **69 / GHSA-J383 / CVE-2025-13120 — `unreleased_commit_only`.** Parent `RARRAY_PTR != p || size < a || size < b`. Rovo `cf8faed5` weakens to pointer-only. `3.4.0` does **not** contain the candidate. `4.0.0-rc` contains origin **and** fix `eb398971`. CNA affected 3.0–3.4.0 is false for this rewrite.
10. **72 / GHSA-W9RM / CVE-2026-9806 — `unreleased_commit_only`.** Claude innerHTML `${n.message}`. Real repo is MISP/cti-transmute (input `cti-transmute/cti-transmute` 404). `v1.2` lacks the sink; `v1.3`/`v1.4` contain origin **and** fix `cf42409b`. Identity NARROW for the wrong-repo label.

## NARROW counterexamples (real AI mechanism, scope must shrink)

| Ord | Why NARROW |
|-----|------------|
| 37 | GHSA-GC24 / CVE-2026-25505 is product-wide missing auth + hardcoded JWT. Claude `a7319f0e` first-adds `POST /{printer_id}/debug/simulate-print-complete` (parent printers.py has no such route). New state-changing debug sink, not origin of those invariants. Min-fix is API-wide auth `c31f2968` plus `RequirePermission` on the debug route `a82f9278`. `v0.1.6` origin without either fix; `v0.1.7` has `c31f2968`. |
| 40 | Same candidate SHA `f4b03599` as ordinals 13/29 on different mechanisms. Adds `/v1/responses` onto ungated Tailscale HTTP; parent `openai-http.ts` already had the helper. New call site, not AI_DIRECT_ROOT of Tailscale header auth. |
| 47 | GHSA-Q447 product-wide unbounded webhook bodies. Feishu `b0c67ea0` / carrier `5c2cb6c5` is a new `adaptDefault` surface; sibling channels already `req.on("data")`. Same SHA as ordinal 124 for a different encrypt-key fail-open mechanism. |
| 52 | Keep only first-party `GHSA-7C3W`. Parent already interpolated unencoded `jobId` into `trace\|play\|retry\|cancel`. Claude `c156ac76` adds `/jobs/${jobId}/artifacts`. Squash `e2a81a04` in `v2.1.32`; listed member `32a9d408` is not an ancestor of that tag. Topology NARROW (squash). |
| 55 | Parent Updates already `Server::findOrFail(0)` with no `isInstanceAdmin`. Haiku `acff543e` skips `findOrFail` when `isCloud()`, making the ungated Updates surface reachable on cloud. Not origin of the missing admin gate on self-hosted. Repo GHSA-C339 / CVE-2026-34050. |
| 60 | Parent hid the unscoped image tool when `primarySupportsImages === true`. Claude `8d74578c` deletes that gate. Not origin of missing `workspaceOnly`. Ordinal 77 shares the SHA for a native-media UNC mechanism (distinct). |
| 61 | AI_DIRECT_ROOT of enabled-only `Galaxy.find`, but identity NARROW (unreviewed GHSA-3636; CVE names insufficient `d3adfe1a`) and release NARROW (`v2.5.37`/`v2.5.38` origin without closer; `v2.5.39` has `d3adfe1a` not `8aa2bb6d`; first real closer tag `v2.5.40`). See gate disagreement. |
| 62 | Parent already `pkill -f`. Member `bb6d608d` (Claude; recovered via `/tmp/fp211-cross-05/pages/commit-bb6d608d.json`, absent from local openclaw clone) adds `ps\|grep\|xargs kill -9`. GHSA wording is unvalidated PID kill. Carrier `8befe7f8` in `v2026.1.15` without listed fixes. Topology NARROW. |
| 70 | Copilot `810d87b2` is a new Claude-agents deploy call site of an existing symlink-dereferencing finder (`realpath` already in parent). Not origin of symlink follow. Carrier `84abb22c`. |
| 71 | Parent used camelCase `contentType` so Discord `content_type` never matched. Claude `b9b47f50` switches to `content_type` and activates latent pre-auth transcription. Not origin of the transcription sink. Listed member `295bc874` is absent from the fixed tag (squash/rebase). |

NARROW is not overuse here: each row has a real AI hunk, but whole-advisory CONFIRM would overclaim product-wide invariants that already existed on the parent.

## UNKNOWN (preserved)

- **51 / GHSA-VJP8 / CVE-2026-32067 — `UNKNOWN_AI_HUNK`.** Pairing-store hunk `f0555341` is real (`readAllowFromStore("feishu")` with no accountId). Body is only `Generated by staged fix workflow`; author Coy Geek; no Co-Authored-By. `/tmp/fp211-cross-05/pages/pr-14876.json` title/body are CommandAuthorized hardcoded true — a different Feishu bug. Do not infer AI provenance from a staged-fix workflow or a mismatched PR.
- **53 / GHSA-8JQH / CVE-2026-67530 — `UNKNOWN_UNPUBLISHED_ARTIFACT`.** Claude `b7b362ae` adds `send_webhook` `fetch(cfg.url)`; `7d1ddbfd` adds `isDeliverableUrl`. Clone `/tmp/fp211-cross-05/clones/wacrm` has **0 tags** and no GitHub releases were recovered. CVE names merge `23838a99` (fix-PR merge), not origin. Do not treat the merge SHA as the origin carrier. Identity NARROW (repo GHSA, global 404).
- **56 / GHSA-8G98 — `UNKNOWN_UNPUBLISHED_ARTIFACT`.** Jules creates a PayPal webhook trusting `req.body`. Only remaining git tag `8.2.4` contains origin **and** fix `57b76343`. npm packument `/tmp/fp211-cross-05/pages/npm-taylored.json`: versions dict only `8.2.4`; time still lists 7.0.5–7.0.8. Do not infer unreleased-FP from yanked history. Ordinal 84 uses `57b76343` as a candidate SHA for a later different mechanism.

No BLOCKED row: GitHub auth, cache clones, and `/tmp/fp211-cross-05` clones were enough to inspect every ordinal. Missing *published artifacts* or *relevant-hunk AI markers* were recorded as UNKNOWN, not BLOCKED.

## CONFIRM (all required gates PASS)

Replay-checked independently; not promoted from first-pass notes:

- **39** Repo GHSA-X9QH / CVE-2026-42148: command injection via unescaped version in docker build. Parent already had `dev_helper_version`; no `buildHelperImage`. Claude `18f30b7f` interpolates `docker build -t ghcr.io/coollabsio/coolify-helper:{$version}`. Fix `dc9322b1` uses a constructed `$imageRef`.
- **42** Upstream `a604df8c` first-adds `feishu_img_` / `feishu_${Date.now()}_${fileKey}` temps (parent `src/media.ts` has none). Import carrier `2267d58a`. Fix `c8210991`. OpenClaw `v2026.2.12` without fix, `v2026.2.19` with. Distinct from 58/65/66.
- **43** Parent of `2a1e2777` has no `execSync(cmd)` in `directApiAgent.ts`. Claude adds HTTP/SSE MCP `execSync(cmd)`. npm `2.0.13` gitHead `aa33d2f0` contains the candidate not the fix; `2.0.14` gitHead **is** min-fix `a0f9c2bf`. GitHub_M CVE-2026-58195 aliases GHSA-VCV2 even when GitHub API `cve_id` is null (`/tmp/fp211-cross-05/pages/global-GHSA-VCV2-R9JH-99M5.json`).
- **44** Copilot `3e176213` inserts unescaped `SwaggerUIBundle(${stringifyJSON(...)})`. Parent Scalar path used `esc(stringifyJSON(finalConfig))`. Member not in `v1.8.3`; carrier `4f28b695` is; fix `4f0efa8a` in `v1.8.4`.
- **46** Parent `downloadToFile` had no redirect follow. Claude `06dd9b8e` follows redirects forwarding original headers. Min-fix `f865a545` drops unsafe headers on cross-origin and is an ancestor of GHSA-named `e704323`. Tags `v2026.3.28` / `v2026.3.31`.
- **49** Zero-parent AI `3902c8c2` introduces `pk_entity`. Min-fix `9f66c42f` shard selection in `v0.10.1` not `v0.10.0`. GHSA-76RV.
- **54** Parent `if (!device)` fail-closed. Claude `079af0d0` `if (!device && !hasTokenAuth)`. Fix `canSkipDevice = role === "operator"`. GHSA-RV2Q. Tags `v2026.1.20` / `v2026.2.22`. Same SHA as 15/33 on a different connect-skip mechanism; uniqueness PASS.
- **57** New attachment modules `strip('<>')`+`rmtree`. Claude trailer on `26be5ccb`. `v1.1.0` origin without fix; tag `1.3.4` = fix `638b162b`.
- **58** Upstream root `4286755f` `fetch(mediaUrl)` SSRF. Import carrier `2267d58a`. Fix `5b4121d6` (local-path vs this remote SSRF is a distinct invariant from ordinal 31). OpenClaw tag pair 2.13/2.14.
- **63** Parent `auth-profiles.ts` only `execSync`-reads keychain; no `add-generic-password`. Claude `a39951d4` interpolates `security add-generic-password -w '${newValue...}'`. Fix `9dce3d8b` `execFileSync` argv.
- **64** Repo GHSA-6MWV / CVE-2026-56678. Parent has no `codewhisperer.${region}` endpoint. Claude+Cursor `706e6513` adds `https://codewhisperer.${region}.amazonaws.com`. `v0.5.2` origin; `v0.5.4` still lacks fix; `v0.5.6` has `126aa244`.
- **65** Same upstream `4286755f` unescaped `new RegExp(\`@${mention.name}\`)`. Distinct invariant from 58 fetch and 66 quotedContent. Fix `7e67ab75`. Tag pair 2.17/2.19.
- **66** Same upstream `4286755f` `quotedContent` without fetched-sender allowlist. Fix `f45e5a65`. Tag pair 3.28/3.31.

## Primary-source citations

Independently fetched or copied under `/tmp/fp211-cross-05`:

- Per-row harvest: `/tmp/fp211-cross-05/evidence/NNN/{harvest.json,candidate.diff,fix.diff}`.
- Repo advisories (global GHSA 404): `pages/repo-GHSA-{X9QH,378W,7C3W,8JQH,C339,6MWV,4VFF}*.json`.
- CVE pages: `pages/CVE-2026-{2376,41345,42148,58195,61462,67530,33890,34050,34149,10854,10860,54362,56678,7386,9806}.json`, `pages/CVE-2025-13120.json`.
- Unreviewed: `advisories/unreviewed-ghsa-9w78-x9jw-9c7m.json`, `advisories/unreviewed-ghsa-5383-j2p9-qfg3.json`.
- npm packuments: `pages/npm-{agentic-flow,taylored,openclaw}.json`.
- PR mismatch 51: `pages/pr-14876.json`. Staged-fix commit: `pages/commit-f0555341.json`. Missing OpenClaw member: `pages/commit-bb6d608d.json`.
- Quay tags: `pages/quay-tags.tsv`, `git/quay-tag-containment.json`.
- Clones: cache `~/.cache/cve-analyzer/repos/` plus `/tmp/fp211-cross-05/clones/{gitlab-mcp,wacrm,mail-mcp-bridge,apm,clawdbot-feishu,cti-transmute,quay}`.

Git flags used during inspection: `git merge-base --is-ancestor`, `git grep SHA -- path`, `git show SHA -- path`. `git tag --contains` was used only as a candidate list for Quay; containment proof is `merge-base --is-ancestor` plus blob `git grep` for `validate_external_registry_url`.

## Replay commands

Per-row `replay_commands` are in the JSONL. Cross-review conservation:

```bash
python3 -c 'import json,pathlib; p=pathlib.Path("autoresearch/orchestrator-260813-fp211-audit/crossreviews/shard-02-by-05.jsonl"); rows=[json.loads(l) for l in p.read_text().splitlines() if l.strip()]; assert len(rows)==36; assert [r["ordinal"] for r in rows]==list(range(37,73))'
python3 -c 'import sys; sys.path.insert(0,"autoresearch/orchestrator-260813-fp211-audit"); from verify import load_jsonl, verify_row, HERE; exp={r["ordinal"]:r for r in load_jsonl(HERE/"manifest.jsonl")}; rows=load_jsonl(HERE/"crossreviews/shard-02-by-05.jsonl");
[verify_row(r, exp[r["ordinal"]]) for r in rows]; print("OK", len(rows))'
git diff --check -- autoresearch/orchestrator-260813-fp211-audit/crossreviews/shard-02-by-05.jsonl autoresearch/orchestrator-260813-fp211-audit/crossreports/shard-02-by-05.md
```

Representative independent checks:

```bash
git -C /tmp/fp211-cross-05/clones/quay merge-base --is-ancestor 92b6f4729a5e v3.17.0
git -C /tmp/fp211-cross-05/clones/quay grep -n validate_external_registry_url v3.17.0 -- endpoints/api/org_mirror.py
git -C ~/.cache/cve-analyzer/repos/misp_misp grep -n "Galaxy.distribution" d3adfe1a097d -- app/Controller/EventTemplatesController.php
git -C ~/.cache/cve-analyzer/repos/misp_misp grep -n buildConditions 8aa2bb6d1af6 -- app/Controller/EventTemplatesController.php
git -C ~/.cache/cve-analyzer/repos/coollabsio_coolify log -1 --format='%s' 473c32270d72
git -C /tmp/fp211-cross-05/clones/gitlab-mcp grep -n 'jobs/${jobId}/artifacts' c156ac767520^ -- index.ts
git -C ~/.cache/cve-analyzer/repos/mruby_mruby merge-base --is-ancestor cf8faed585e1 3.4.0
git -C /tmp/fp211-cross-05/clones/cti-transmute merge-base --is-ancestor 5a4344884f93 v1.3
```

## Limitations

- Cache clones were read-only. Extra fetches lived under `/tmp/fp211-cross-05` only (Quay full clone, gitlab-mcp, wacrm, mail-mcp-bridge, apm, clawdbot-feishu, cti-transmute).
- Did not unpack Red Hat Quay/mirror-registry RPMs for ordinal 48; git-tag containment is the published-artifact proof used here. Product packages could in principle diverge from git tags.
- OpenClaw members `bb6d608d` (62) and `295bc874` (71 listed fix member) are absent from the local `v2026.3.31` clone; 62 recovered via GitHub commit API; 71 still NARROW on squash topology.
- npm `openclaw` gitHeads were not re-fetched for every tag pair; git tags were used where they matched the first-pass npm gitHeads (46, 54). Ordinal 43 used the independently fetched packument gitHeads.
- Global GHSA 404s were not treated as missing identity when a repo advisory or CNA object existed.
- Agreement with first pass is not proof. Final adjudication still resolves this review's one verdict disagreement, the 61 min-fix/gate changes, the 68 ai_hunk UNKNOWN, and every non-CONFIRM/HIGH row.

## Reusable lessons

1. **A cache clone with zero tags is not proof of missing artifacts.** Fetch first-party tags and require a tag whose tree has origin without the repair, not merely ancestry of a listed fix SHA (48: equivalent `validate_external_registry_url` backport vs listed `9afe28a5`).
2. **Put the commit that actually closes the sink in `minimum_fix_set`.** A listed security fix that embeds a PHP comparison in a CakePHP conditions array is not minimum reversal (61 `d3adfe1a` vs `8aa2bb6d`). The origin row stays unique; the residual closer is the duplicate (67).
3. **Conductor / staged-fix / Rovo still need a relevant-hunk AI marker.** Conductor auto-commit is not AI proof (68, same SHA as 35). Staged-fix workflow + mismatched PR is UNKNOWN, not PASS (51). Jules on 56 did pass the hunk gate; release still UNKNOWN.
4. **Carrier/import Claude trailer ≠ origin member.** Feishu 42/58/65/66: origin is `a604df8c` or `4286755f`; `2267d58a` is import. Distinct invariants (temp files / fetch SSRF / RegExp / quotedContent) keep uniqueness PASS.
5. **Old-bug-preserving refactors are FP even with an AI trailer:** Path→EscapedPath, includes→PUBLIC_PREFIX_PATHS, copied Buffer.from-before-limit, CRUD delete wrapper that never fires the bypass.
6. **New call site of an old helper is NARROW**, not CONFIRM/HIGH product origin (37, 40, 47, 52, 55, 60, 62, 70, 71). That is not NARROW overuse.
7. **Same SHA, distinct mechanism** does not fail uniqueness (40 vs 13/29; 54 vs 15/33; 58 vs 31; 47 vs 124; 60 vs 77). **Same source/sink/invariant does** (61 vs 67; 68 vs 35).
8. **Public cases count by advisory identity, not mechanism.** Prefer first-party `GHSA-*`. Same-fix unreviewed CVE wrappers are not aliases of a first-party no-CVE GHSA (52).
9. **CVE "fix" URL can be the merge of the fix PR** (53: `23838a99`), not origin. GHSA-named later refactor can be a descendant of the true min-fix (46: `e704323` after `f865a545`).
10. **Unreleased:** candidate and fix in the same published tag, or CNA range that does not contain the rewrite (69, 72, 48). Missing tags without that co-presence stay UNKNOWN (53, 56).

Mechanical 36/36 coverage is not proof that every CONFIRM is final. Independent review is still required for every non-CONFIRM/HIGH row and before promoting CONFIRM/HIGH into a rebuilt HOLD ledger.
