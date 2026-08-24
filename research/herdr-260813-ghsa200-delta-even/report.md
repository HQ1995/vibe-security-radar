# GHSA 200+ delta-even lane

**Status: COMPLETE for all-ID routing of this even partition and for a bounded deep-adjudication set. 0 PASS proposals. Ecosystem coverage is not claimed.**

Worker PASS is a proposal, never admission. This lane proposes no admissions.

Sibling fresh-am / fresh-nz / current-delta / delta-odd / remediation conclusions were not read as evidence. Remediation artifacts were left unchanged.

## Coverage distinction

| Layer | Status | What it means |
|-------|--------|----------------|
| All-ID routing | COMPLETE | Every even-partition identity from the 731-ID official window has a final route. |
| Bounded deep adjudication | COMPLETE | 37 IDs with plausible AI-origin, AI-fixer, incomplete-rem, or reintroduction recall were seven-gate reviewed. |
| Full blame / ecosystem coverage | NOT CLAIMED | 330 assigned IDs were screened from official JSON plus referenced-commit AI scan only. They are not seven-gate rows. |

COMPLETE applies only to the routed 393 even identities and the 37 reviewed IDs. It does not mean every introducing hunk in every even-partition repository was blamed.

## Source and partition conservation

Accepted source manifest: `autoresearch/herdr-260813-ghsa200-freshness-qa/manifests/github_reviewed_window_added_ids.txt`

- SHA-256: `724fa2b8648e270de72b99ba52ffb738a1f87c07e649450b5d7b62dca547034a`
- Official github-reviewed GHSA IDs added between frozen `39d8887723797efc1804585dd06585c9fd751226` and current `6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86`
- Unique IDs: 731

EVEN rule: last hex nibble of `SHA256(uppercase GHSA ID)` is in `02468ace`.

| Set | Count |
|-----|------:|
| Window added | 731 |
| EVEN (this lane) | 393 |
| ODD (not owned) | 338 |
| EVEN union ODD | 731 |
| EVEN intersect ODD | 0 |

Conservation holds: even and odd are disjoint, cover the 731, and match the accepted manifest exactly.

This lane clone of `github/advisory-database` lives at `/tmp/ghsa200-worker-clones/delta-even/advisory-database` and is detached at `6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86`. The freshness-qa clone was used only as a Git object reference and was not modified.

### Mixed clone-path policy (resource correction)

Existing active objects stay under `/tmp/ghsa200-worker-clones/delta-even` and were not moved. All NEW clones and large objects go under `/home/hanqing/.cache/ghsa200-worker-clones/delta-even`. Inventory: `clone_paths.json`. Do not move a path used by a running process. `cases.jsonl` `official_json` paths still point at the existing `/tmp` advisory-database; that is intentional.

## Routing of every even identity

| Final route | Count | Seven-gate row |
|-------------|------:|----------------|
| EXCLUDE_DECLARED | 15 | no |
| EXCLUDE_WITHDRAWN | 10 | no |
| EXCLUDE_MISSING_REPO | 1 | no |
| EXCLUDE_ALIAS_OF_DECLARED | 0 | no |
| SCREENED_NO_PLAUSIBLE_AI | 330 | no |
| DEEP_REVIEWED_REJECT | 37 | yes |
| **Even total** | **393** | |

Assigned after explicit excludes: 367. Those 367 were all triaged. 37 were deep-reviewed. 330 remain screening routes.

### Explicit excludes

Leader declared (212) recovered in this even partition (do not PASS):

`GHSA-2CM6-R77W-6G96`, `GHSA-3F7W-8RR8-F37F`, `GHSA-4GMW-GG2M-W46P`, `GHSA-6P8H-3WGX-97GF`, `GHSA-94P4-4CQ8-9G67`, `GHSA-9RJ7-RF2P-W77R`, `GHSA-FJR4-X663-MWXC`, `GHSA-FP43-VJ7G-PG92`, `GHSA-GH4H-34GR-87R7`, `GHSA-P7W7-4929-VPJ5`, `GHSA-PQH8-P93P-2RX7`, `GHSA-QF5V-M7P4-95RP`, `GHSA-R9MR-M37C-5FR3`, `GHSA-VCHH-R53J-8MPW`, `GHSA-W28W-GP39-M4P6`

Withdrawn (official `withdrawn` timestamp non-empty):

`GHSA-32RQ-JHR7-M3HH`, `GHSA-38GX-CFQF-F652`, `GHSA-4JJW-PWVW-Q6W3`, `GHSA-7M3P-WC52-RMC6`, `GHSA-7QF5-7PPR-87V8`, `GHSA-F95G-VM94-46C3`, `GHSA-H738-VH6G-Q8GH`, `GHSA-PMM4-V8F6-4VPP`, `GHSA-RQJW-R5G4-X8QM`, `GHSA-XJ2C-G5XP-4P47`

Missing repo identity: `GHSA-W4Q6-QW23-4RG7`

No even-partition official object had aliases that overlapped the 212 declared identities or their CVE aliases.

## How triage and deep review were chosen

AI keyword / trailer / OSV text is recall only.

1. Parse every even official github-reviewed JSON for withdrawn, aliases, repository, commit refs, and rem/reintro wording.
2. Fetch every official referenced commit via the GitHub commit API and scan with `cve_analyzer.ai_signatures`.
3. Deep-review the union of (a) referenced commits with an AI trailer and (b) rem/reintro keyword hits.

That union is 37 IDs. Official closer AI trailers were treated as fixer recall, then checked against first-party git/tag evidence before any PASS could be considered.

## Deep-review outcome

37 seven-gate rows. All REJECT. 0 PASS. 0 NARROW. 0 UNKNOWN. 0 BLOCKED.

PASS would have required all seven gates PASS and a released affected version. No row met that bar.

### Highest-scrutiny REJECTS

**GHSA-HMQ2-W58F-27JC** (GitPython submodule name traversal). Official range is introduced `0` / fixed `3.1.58`, last known `<= 3.1.57`. Referenced commits `e4b8e7d0` and `4299c990` both carry `Co-authored-by: GPT 5.6 <codex@openai.com>`. They are successive validators. `e4b8e7d0` is an ancestor of `4299c990`, but the first tag containing either commit is `3.1.58`. Tag `3.1.57` contains neither. There is no released AI residual window. The unvalidated `sm_name` / `_module_abspath` path is the old GitPython gap versus CVE-2018-11235. `ai_hunk`, `but_for`, `fix_reversal`, and rem `release` all REJECT.

**GHSA-FJGC-3MJ7-8RG8** (etherpad `x-proxy-path`). Claude commit `451bd9c3` (first tag `3.0.0`) added a timeslider 302 that reused a pre-existing `sanitizeProxyPath` already present on parent `cbf71285` and already used by other specialpages redirects. Admin XSS exists at tag `2.1.0`. Closer `8c6104c5` (first tag `3.1.0`) is also Claude and hardens the shared sanitizer. That is an AI new call site of an old mechanism, plus AI-as-fixer. `but_for` REJECT at GHSA scope.

**GHSA-2JWF-F4XQ-F24H** (etherpad `Math.random` temp paths). Official introduced `0` / fixed `3.1.0`. Claude closer `8c6104c5` replaces `Math.random` with `crypto.randomBytes`. AI-as-fixer. REJECT.

**GHSA-PC2W-4MQ8-32QW** (dynatrace-mcp missing notebook approval). Human `d0de9800` (2025-12-19, Christian Kreuzberger, no AI trailer) added `create_dynatrace_notebook`. Copilot closer `2851d3ce` adds `requestHumanApproval`. First contained in `v1.8.7`; `v1.8.6` lacks it. AI-as-fixer. REJECT.

**GHSA-RMXW-PQ4X-3FVH** and **GHSA-HQ33-8JGP-8QQ3** (goshs). Prior rem `f212c4f4` and closers `7cf911a2` / `0444ac6b` are Patrick Hener with no AI trailers. Residual of an incomplete human rem, not an AI rem. REJECT.

Other rem-keyword IDs (ImageMagick `56M6` / `HC76`, Nuxt `HXVH`, Capsule `JR6P`, Traefik `X677`, Flowise `XC48`) are official incomplete-fix leftovers with no AI marker on the rem or closer. REJECT.

The remaining deep rows are official closers that carry Copilot, Claude, Cursor, Jules, or Codex trailers. Those trailers identify the fixer, not an introducing vulnerable hunk. All REJECT as `AI_AS_FIXER`.

## What this lane will not claim

- It does not admit any new GHSA into the 200+ ledger.
- It does not claim that the 330 screened IDs have no AI origin in unreferenced history. It claims only that official advisory text and official referenced commits did not make AI origin, material contribution, incomplete rem, or reintroduction plausible enough for this bounded review.
- It does not own the odd partition.
- It does not modify canonical ledgers, publication data, or other worker directories.

## Artifacts

- `result.json` -- terminal status, hashes, counts, blockers
- `cases.jsonl` -- 37 deep-reviewed seven-gate REJECT rows
- `routing_manifest.jsonl` -- one route for each of 393 even identities
- `partition_even_ids.txt` / `partition_odd_ids.txt` -- conservation lists
- `source_hashes.json` -- input and artifact hashes
- `replay.txt` -- reproduction commands
- `evidence/` -- official github-reviewed JSON for the 37 reviewed IDs, plus first-party repo advisory dumps for the highest-scrutiny IDs
