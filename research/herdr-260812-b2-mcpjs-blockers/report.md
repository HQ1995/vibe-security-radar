# Batch 2: MCP/JavaScript blocker closure

Research window: 2026-08-12 12:47–13:05 America/New_York

Owned output: `/home/hanqing/agents/ai-slop/autoresearch/herdr-260812-b2-mcpjs-blockers/`

Checkout snapshot: `dev@6c0d2084fd1240341d6d1b9f9096252490168f0b`

Status: **COMPLETE**

## Result first

The Batch 1 aggregate `UNKNOWN` for GHSA-WJJV-3MJ2-39HF is resolved. The advisory splits into six defensible mechanism groups, represented by seven invariant-level assessment rows because raw-SQL ownership and direct metadata access are retained separately under one group. Every recovered public origin is human-authored with no direct AI marker. Therefore:

- All 7 assessment rows are `REJECT` for strict AI causality across the 6 deduplicated groups.
- 2 worker assessment rows remain `BLOCKED` only for npm-package containment: the fixes close in source tags, but the worker files are absent from both named Core tarballs.
- 2 pre-merge patch residual groups are retained as `NARROW` controls: raw `HAVING` interpolation and incomplete comma-join table extraction. Both were completed by `1408de5` before merge `234b811` and release `8cb053f`; neither partial state shipped.
- The exact `Moltbot <moltbot@workspace.local>` author identity on the first two patch commits remains `UNKNOWN` model/agent provenance: GitHub exposes no linked author account, the commits are unsigned, neither has a generator marker or co-author trailer, and the advisory credits a human reporter. This ambiguity cannot rescue strict causality because the vulnerable origins are independently human.
- No new positive public ID or component is added.

The previously admitted n8n-mcp result is now materialized as four machine rows in `mechanism_ledger.jsonl`: 3 `STRICT_CAUSAL` and 1 `AI_INCOMPLETE_REMEDIATION`, under two GHSA identities. Exact candidates, parents, fixes, attribution markers, affected/fixed npm releases, commit trees, patch hashes, advisory-record hashes, npm gitHeads, and dist integrity hashes are included.

## Counts

| Measure | Count |
|---|---:|
| WJJV advisory identities resolved | 1 |
| WJJV mechanism groups split | 6 |
| WJJV invariant-level assessment rows | 7 |
| WJJV `REJECT` strict-causal assessments | 7 |
| Unique `NARROW` pre-merge residual groups | 2 |
| WJJV `BLOCKED` npm-containment rows | 2 |
| WJJV aggregate `UNKNOWN` rows remaining | 0 |
| WJJV fix-attribution `UNKNOWN` fields | 2 |
| Newly admitted public IDs | 0 |
| Previously admitted n8n mechanism rows materialized | 4 |
| Materialized `STRICT_CAUSAL` rows | 3 |
| Materialized `AI_INCOMPLETE_REMEDIATION` rows | 1 |

## Scope and claim gate

This pass did not broaden discovery. It read only the Batch 1 terminal artifacts, exact n8n/AgenticMail source commits already in scope, the local reviewed advisory records, live first-party repository-advisory/commit APIs, and exact npm version documents.

`PASS` requires advisory identity, atomic candidate, direct attribution, candidate parent delta, same-mechanism reversal, vulnerable release, and fixed release. `REJECT` is a completed negative conclusion, not absence of research. `NARROW` preserves useful evidence that cannot satisfy the full claim. `BLOCKED` is used for unavailable evidence, and `UNKNOWN` only when the evidence does not support a terminal classification.

Routing, ancestry, tests, source recovery, release metadata, and author-looking names are not causal proof. A security fix is not substituted for a vulnerability origin.

## Snapshot and input hashes

The shared checkout remained intentionally dirty. No existing path was changed. Every shared Git read used `-c gc.auto=0 -c maintenance.auto=false`; no fetch, clone, build, test suite, cache refresh, staging, commit, or cleanup ran.

| Input | Frozen identity / SHA-256 |
|---|---|
| Batch 1 `report.md` | `47be67ee784f15b334378348e2c3ad62bbfd35d4810e7aa57c261602592fbe52` |
| Batch 1 `result.json` | `f9ef2c57b3125009603b46ad76d99cc56c27d208bedd1549a1475d3119a90bfa` |
| Batch 1 `background_findings.md` | `60fd0782205ba6bfaba0b4f216f00780ebc5b745472ef3bb827dcf9dce02c65a` |
| Independent Batch 2 WJJV split | `080f387dd39b31dfe8ab715c7ecb4b45380b3ec55141c8c8db616385eaea06e8` |
| GHSA-WJJV reviewed record | `18696a9f374446748af6fcc81a4a1c673ec96b383ac7f5eb497de673d476b5bf` |
| GHSA-75HX reviewed record | `3e3654a8e685288bcbf83f29e8ed5ecaa8649700a64d34a5472fad6002bb924c` |
| GHSA-8G7G reviewed record | `b5206bcac226dae8dbffbd4b3c3f1ee1fcc392c9dcc8f6fcb2f5e6cf99a2edc8` |
| GitHub Advisory Database clone | git `39d8887723797efc1804585dd06585c9fd751226` |
| AgenticMail read-only clone | HEAD `4a0e0f6f590aed435c0f8bc962bbdd488aec4016` |
| n8n-mcp read-only clone | HEAD `f1e6e5be393f390b0223057906c675d81f938f63` |

Later changes to volatile shared inputs are outside this report's snapshot.

## GHSA-WJJV mechanism split

First-party identity: [GHSA-WJJV-3MJ2-39HF / CVE-2026-47255](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-wjjv-3mj2-39hf), published and non-withdrawn. The advisory names `@agenticmail/api <=0.9.31`, fixed `0.9.32`, and `@agenticmail/core <=0.9.9`, fixed `0.9.10`.

### Recovered patch topology

The supposedly private patch is recoverable from public merge history:

```text
10cde1ee  first parent before security merge
  \
   de3a5c4519f65c76b9f7d9fb5df2bc788e2dcf61  API/storage patch
    41dd8153809cabbc9b79aba1b726266af923a1b7   relay/TLS patch
     1408de543fa3577d8c2d4fdb289c75fe6faafac7  maintainer pre-merge hardening
  /
234b811e426a0743170f3b10bc43419d64330155     public merge
8cb053f2307dd77b7736ffa0d7df04b0ccc3272d     release commit
```

`git rev-list --reverse 234b811^2 --not 234b811^1` returns exactly `de3a5c4`, `41dd815`, and `1408de5`. All three are ancestors of release `8cb053f`.

GitHub's first-party commit API reports `de3a5c4` and `41dd815` with Git author `Moltbot <moltbot@workspace.local>`, no GitHub author login, maintainer committer `ope-olatunji`, unsigned verification, and no attribution trailer. Model/agent provenance remains `UNKNOWN`, not promoted to claim-grade AI attribution. Commit `1408de5` is directly human-authored and committed by the maintainer.

### Six mechanism groups / seven invariant rows

| Mechanism | Exact origin | Fix member | Extra hardening | Terminal result |
|---|---|---|---|---|
| Inactive-agent hours interpolated into SQL | root `cf35e22f`, parent none | `de3a5c4` binds a validated positive integer | none | `REJECT human_origin` |
| Storage dynamic identifier / HAVING injection | `876cf485`, parent `99cd2b98`, extended by `255d3e1c` | `de3a5c4` validates identifier-shaped fields | `1408de5` closes raw HAVING before release | `REJECT`; residual `NARROW_UNSHIPPED` |
| Raw SQL cross-agent table ownership | `255d3e1c`, parent `876cf485` | `de3a5c4` checks metadata ownership | `1408de5` catches comma-join table tokens before release | `REJECT`; residual `NARROW_UNSHIPPED` |
| Direct raw-SQL metadata-table access | `255d3e1c`, parent `876cf485` | `de3a5c4` blocks metadata table | same comma-join parser hardening, deduplicated | `REJECT`; shared residual group |
| Hardcoded/fallback outbound worker secret | root `cf35e22f`, parent none | `41dd815` removes public secret and fails closed | source tags close; files absent from both Core tarballs | `REJECT human_origin`; `BLOCKED npm_containment` |
| SMTP envelope/header control characters | root `cf35e22f`, parent none | `41dd815` validates addresses and header values | source tags close; worker absent from both Core tarballs | `REJECT human_origin`; `BLOCKED npm_containment` |
| SMTP TLS verification disabled | root `cf35e22f`, parent none | `41dd815` verifies by default | `6c70c825` later exempts loopback only; remote verification remains | `REJECT human_origin` |

The root commit `cf35e22f` is authored by Ope Olatunji and has no parent. `git log --all --follow --reverse -S` binds it to the hours interpolation, hardcoded secret/fallback, raw SMTP construction, and `rejectUnauthorized: false`. Human/no-marker `876cf485` creates dynamic storage CRUD and raw identifiers; human/no-marker child `255d3e1c` expands it to the full DBMS/raw SQL surface, including dynamic group/order/HAVING expressions and the prefix-only raw-SQL guard.

The complete row objects, patch hashes, npm integrities, and shared-residual dedup keys are in `wjjv_mechanisms.jsonl`. The authoritative six-group mapping and layered `PASS`/`REJECT`/`NARROW`/`BLOCKED`/`UNKNOWN` statuses are in `wjjv_group_map.json`.

### Release and artifact containment

The exact npm documents bind source gitHeads on both sides. They prove package containment for API mechanisms and bundled `MailSender`; they do **not** prove worker-file containment:

| Package/version | npm gitHead | Role |
|---|---|---|
| `@agenticmail/api@0.9.31` | `c7f82ecbc7981d0f8a7ee6245d5757c064a8daf1` | affected, contains `cf35e22f` and `255d3e1c` |
| `@agenticmail/api@0.9.32` | `8cb053f2307dd77b7736ffa0d7df04b0ccc3272d` | fixed, contains all three patch members |
| `@agenticmail/core@0.9.9` | `c7f82ecbc7981d0f8a7ee6245d5757c064a8daf1` | affected `MailSender`; worker files absent |
| `@agenticmail/core@0.9.10` | `8cb053f2307dd77b7736ffa0d7df04b0ccc3272d` | fixed `MailSender`; worker files absent |
| `@agenticmail/core@0.9.13` | `6c70c8254c906f823392d7f5ccee88a5481e7731` | loopback TLS compatibility follow-up |

The two patch residuals did not ship: `1408de5` is in the second-parent branch before merge `234b811`, and the first fixed npm gitHead is after that merge. They cannot satisfy released incomplete-remediation containment.

Tarball inspection is decisive for the worker rows. Core's published file set contains the bundled `dist` entry but not `packages/core/src/gateway/workers/outbound.js` or `metadata.json`; neither the vulnerable literals nor fixing worker source is in Core 0.9.9/0.9.10. Source tags `v0.9.45` and `v0.9.46` do close those paths, but a separate first-party deployment artifact is required to claim released artifact containment. The tarball SHA-256 values and `worker_paths_present=false` are in `wjjv_mechanisms.jsonl`.

## Materialized n8n mechanism ledger

`mechanism_ledger.jsonl` contains four independently parseable JSON objects:

| Row | Classification | Candidate | Parent | Fix | Affected → fixed |
|---|---|---|---|---|---|
| GHSA-75HX session-control/health disclosure | `PASS STRICT_CAUSAL` | `a597ef5a` | `a4053de9` | `ca9d4b3d` | 2.47.5 → 2.47.6 |
| GHSA-8G7G API path segments | `PASS STRICT_CAUSAL` | `74f05e93` | `150de3d1` | `1cfe9c6b` | 2.50.0 → 2.50.1 |
| GHSA-8G7G redirect SSRF form/chat | `PASS STRICT_CAUSAL` | atomic PR member `3f698cc6` | `ddf95567` | `1cfe9c6b` | carrier 2.28.0; 2.50.0 → 2.50.1 |
| GHSA-8G7G mutation telemetry residual | `PASS AI_INCOMPLETE_REMEDIATION` | partial member `7ac748e7` | `67196283` | `1cfe9c6b` | partial 2.22.16; 2.50.0 → 2.50.1 |

Each row preserves its component-level input, sink, invariant, attribution evidence, role boundary, release carrier where applicable, npm gitHeads and `dist.integrity`, commit tree hashes, full patch hashes, and mechanism-scoped patch hashes.

One non-claim field is explicitly `BLOCKED`: the read-only partial clone lacks a non-scoped blob needed to hash the **full** `3f698cc6` patch. Its security-scoped form/chat patch is locally complete and hashes to `d954300d42949ecb0fa04d8172771da879615db5b8fbcb4fff0bd4d8593cd807`; the commit tree `ed2ac96810092175f3f9d57f0d3e9a22493d35b0`, release carrier full patch, fix full patch, and mechanism fix patch are all bound. No fetch was attempted, so this does not block the component claim.

## Exact commands and sources

All Git commands against shared clones included both maintenance guards.

```zsh
cd /home/hanqing/agents/ai-slop
agent_repo=.ai-slop/cache/cve-analyzer/repos/v2_github.com_agenticmail_6f99dfe6a0084582112588e82224a010cafaa5f1b8095765e41aad971196cf49
n8n_repo=.ai-slop/cache/cve-analyzer/repos/v2_github.com_n8n-mcp_7f3ec1dcf0d7cdaa7f65f6c0aed32341a5c14c9c95b456fff2c6e355a78931a1

# Public patch members and topology.
git -c gc.auto=0 -c maintenance.auto=false -C "$agent_repo" \
  rev-list --reverse 234b811^2 --not 234b811^1
git -c gc.auto=0 -c maintenance.auto=false -C "$agent_repo" \
  show -s --format='%H%n%P%n%T%n%an <%ae>%n%cn <%ce>%n%aI%n%cI%n%B' \
  de3a5c4519f65c76b9f7d9fb5df2bc788e2dcf61 \
  41dd8153809cabbc9b79aba1b726266af923a1b7 \
  1408de543fa3577d8c2d4fdb289c75fe6faafac7 \
  234b811e426a0743170f3b10bc43419d64330155 \
  8cb053f2307dd77b7736ffa0d7df04b0ccc3272d

# Exact origin searches, repeated for each listed string/path.
git -c gc.auto=0 -c maintenance.auto=false -C "$agent_repo" \
  log --all --follow --reverse -S"outbound_2sabi_secret_key" \
  --format='%H%x09%P%x09%aI%x09%an <%ae>%x09%s' -- \
  packages/core/src/gateway/workers/outbound.js
git -c gc.auto=0 -c maintenance.auto=false -C "$agent_repo" \
  log --all --follow --reverse -S"router.post('/storage/sql'" \
  --format='%H%x09%P%x09%aI%x09%an <%ae>%x09%s' -- \
  packages/api/src/routes/storage.ts

# Parent deltas and patch hashes.
git -c gc.auto=0 -c maintenance.auto=false -C "$agent_repo" \
  diff --binary de3a5c4^ de3a5c4 -- packages/api/src/routes/storage.ts \
  | sha256sum
git -c gc.auto=0 -c maintenance.auto=false -C "$agent_repo" \
  diff --binary 41dd815^ 41dd815 -- \
  packages/core/src/gateway/workers/outbound.js \
  packages/core/src/gateway/workers/metadata.json | sha256sum
git -c gc.auto=0 -c maintenance.auto=false -C "$agent_repo" \
  diff --binary 1408de5^ 1408de5 -- packages/api/src/routes/storage.ts \
  | sha256sum

# Ancestry returned exit 0 for every candidate/affected and fix/fixed pair.
git -c gc.auto=0 -c maintenance.auto=false -C "$agent_repo" \
  merge-base --is-ancestor 255d3e1c c7f82ecb
git -c gc.auto=0 -c maintenance.auto=false -C "$agent_repo" \
  merge-base --is-ancestor 1408de5 8cb053f2
git -c gc.auto=0 -c maintenance.auto=false -C "$n8n_repo" \
  merge-base --is-ancestor a597ef5a ff486ea0
git -c gc.auto=0 -c maintenance.auto=false -C "$n8n_repo" \
  merge-base --is-ancestor ca9d4b3d 4b161b6a

# Live first-party identities and commit attribution metadata.
gh api repos/agenticmail/agenticmail/security-advisories/GHSA-wjjv-3mj2-39hf
gh api repos/agenticmail/agenticmail/commits/de3a5c4519f65c76b9f7d9fb5df2bc788e2dcf61
gh api repos/agenticmail/agenticmail/commits/41dd8153809cabbc9b79aba1b726266af923a1b7
gh api repos/agenticmail/agenticmail/commits/1408de543fa3577d8c2d4fdb289c75fe6faafac7

# Exact npm version provenance; repeated for every version recorded above.
curl -fsSL -H 'User-Agent: ai-slop-research-b2' \
  'https://registry.npmjs.org/%40agenticmail%2Fapi/0.9.32' \
  | jq -r '[.name,.version,.gitHead,.repository.url,.dist.integrity] | @tsv'
curl -fsSL -H 'User-Agent: ai-slop-research-b2' \
  'https://registry.npmjs.org/n8n-mcp/2.50.1' \
  | jq -r '[.name,.version,.gitHead,.repository.url,.dist.integrity] | @tsv'

# Machine-artifact validation.
jq -e -s 'length == 4' \
  autoresearch/herdr-260812-b2-mcpjs-blockers/mechanism_ledger.jsonl
jq -e -s 'length == 7' \
  autoresearch/herdr-260812-b2-mcpjs-blockers/wjjv_mechanisms.jsonl
jq -e . autoresearch/herdr-260812-b2-mcpjs-blockers/wjjv_group_map.json
jq -e . autoresearch/herdr-260812-b2-mcpjs-blockers/result.json
```

No credential, API token, or authorization header was printed or stored. A first origin-search shell accidentally assigned zsh's reserved `path` variable and consequently reported `git`/`head` not found within that shell only; it made no filesystem change and the corrected command used `file_path`.

## Negative, narrow, blocked, and claim boundary

- `REJECT`: all seven WJJV assessment rows trace to public human-attributed origin commits. Released fixes do not convert them into AI-origin components; pre-public authorship behind the root import is not claimed.
- `NARROW`: the two security-patch residual groups remain NARROW because they were completed before any release. The account-hours change is also bounded input hardening; this audit does not claim it as a standalone exploitable SQL injection.
- `BLOCKED`: npm-artifact containment remains blocked for the worker-secret and SMTP-control rows because the worker paths are absent from both named Core tarballs. Separately, only the non-scoped full-patch hash for atomic n8n member `3f698cc6` is blocked; its mechanism-scoped claim evidence is complete.
- `UNKNOWN`: the aggregate WJJV adjudication no longer remains UNKNOWN. Only the model/agent provenance of the unlinked `Moltbot` fix-author identity remains UNKNOWN, and it cannot affect the human-origin rejection.
- Tests cited in commit messages and the advisory were not rerun and are not causal proof.
- The WJJV resolution is a negative causal conclusion, not a claim that the vulnerabilities or fixes are invalid.
- The n8n ledger repeats Batch 1's bounded conclusions; it does not add new public IDs or broaden their roles.
