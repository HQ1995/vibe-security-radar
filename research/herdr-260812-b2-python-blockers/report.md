# Python Batch 2 blocker closure

## Result

All three named Batch 1 blocker rows are terminally closed: **3 `CLOSED_REJECT`, 0 `CLOSED_PASS`, 0 `BLOCKED`, 0 `UNKNOWN`**. This pass does not repeat or alter the five Batch 1 adjudications. It closes only their missing release, advisory-identity, or introduction facets.

| Row | Missing Batch 1 facet | Batch 2 evidence | Terminal state |
|---|---|---|---|
| ChatDev / CVE-2026-58166 | fixed-release containment | Authenticated first-party APIs return 12 releases/tags, ending at `v2.2.0`; the fix is 38 commits after that tag | **CLOSED_REJECT** — no released containment |
| F5-TTS / CVE-2026-43624 | repository-scoped first-party advisory identity | Repository advisory collection is exactly `[]`; global unreviewed `GHSA-93wx-x4m2-5c8f` has `repository_advisory_url=null` and the repo endpoint returns 404 | **CLOSED_REJECT** — criterion absent |
| KTransformers / CVE-2026-63767 | exact introduction and released containment | `25cee581` atomically adds wildcard bind plus `pickle.loads`; `v0.6.4` contains `def0f931`; Claude is documented on remediation, not introduction | **CLOSED_REJECT** — non-AI documented origin |

No positive AI-origin row results from these closures.

## Scope and snapshot

- Started `2026-08-12T12:47:52-04:00`; evidence cut `2026-08-12T12:57:20-04:00`.
- Checkout `/home/hanqing/agents/ai-slop`, branch `dev`, `HEAD 6c0d2084fd1240341d6d1b9f9096252490168f0b`.
- Default service tier remained in use; `/fast` was not enabled.
- The intentionally dirty checkout was read only. Deliberate writes, the filtered KTransformers clone, and transient Git objects are confined to `autoresearch/herdr-260812-b2-python-blockers/`.
- No shared cache was read or touched. Git reads used `-c gc.auto=0 -c maintenance.auto=false`. No credentials were printed or stored.
- No build, tests, broad corpus scan, or API loop was run. Calls were exact repository/advisory/release/compare endpoints.

## Input hashes

| Input | SHA-256 |
|---|---|
| Batch 1 `report.md` | `251fbc3ba65427bdf090f6c9af458f43ad256fc7c7b1a36b13fc88d8eb07d788` |
| Batch 1 `result.json` | `fa5941b031a04895e33f2cad4ffb13568d564917caf45a74ebb92f8726220d70` |
| Batch 1 `research_findings.md` | `44cb35803310ce51f424407513cab91dba09e5cd811898214e19ffe33f86aab3` |
| Strict ledger | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| Strict summary | `69dd6c35de1455bf9cee88420aed570c576a190a4d143202d01a26cc3d37b81e` |
| KTransformers supplemental finding | `af6b76443b6f37d6cbc15242548e57d50fbcb799ab933041c4bf963a6b719440` |

Canonicalized live-response hashes:

| Response | SHA-256 |
|---|---|
| ChatDev releases: count plus selected release fields | `f8ff1b6f040c0ff042a06b74acac637eb1785bb03988f0da1c973fba400ad58e` |
| ChatDev tags: count, names, commit SHAs | `6e83b0e92ff040e0bd697c1841acfcebee461784570c5260df9f094e118795ec` |
| ChatDev `v2.2.0...4fd4da60` comparison | `b98d4f1be14fc370246953781cb260d996e1e1263cc627bcc3421100f24e41ad` |
| F5-TTS repository advisory collection | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| Global CVE-2026-43624 advisory projection | `76b5c627be9dd532171fa019578e084b4fc2e5c82c660c1983319620ac283326` |

These hashes bind the selected JSON projections shown by the commands below, not raw HTTP headers.

## Row 1: ChatDev fixed-release containment

**CLOSED_REJECT.** Authenticated [`GET /repos/OpenBMB/ChatDev/releases`](https://api.github.com/repos/OpenBMB/ChatDev/releases?per_page=100) returned exactly 12 non-draft releases. The latest is [`v2.2.0`](https://github.com/OpenBMB/ChatDev/releases/tag/v2.2.0), published `2026-03-23T02:10:51Z`. The parallel first-party tags endpoint also returned exactly 12 tags, with `v2.2.0` resolving to `3c72d860d2553f05129b7dff0fd4efdde5b01d2f`.

The exact [comparison](https://github.com/OpenBMB/ChatDev/compare/v2.2.0...4fd4da603801766b14ad8788649cfc1ad21f99a6) reports fix merge `4fd4da603801766b14ad8788649cfc1ad21f99a6` as 38 commits ahead of `v2.2.0`, with `behind_by=0` and merge base equal to the tag SHA. Therefore no current repository tag or GitHub release contains the fixed commit. This closes the facet negatively; it does not overturn Batch 1's separate conclusion that Claude assisted atomic fix member `0014dbba` rather than the vulnerable origin.

Exact commands:

```sh
gh api 'repos/OpenBMB/ChatDev/releases?per_page=100' \
  --jq '{count:length,releases:[.[] | {tag_name,published_at,created_at,target_commitish,draft,prerelease,html_url}]}'
gh api 'repos/OpenBMB/ChatDev/tags?per_page=100' \
  --jq '{count:length,tags:[.[] | {name,sha:.commit.sha}]}'
gh api 'repos/OpenBMB/ChatDev/compare/v2.2.0...4fd4da603801766b14ad8788649cfc1ad21f99a6' \
  --jq '{status,ahead_by,behind_by,total_commits,merge_base_sha:.merge_base_commit.sha,base_sha:.base_commit.sha,head_sha:.commits[-1].sha,html_url}'
```

## Row 2: F5-TTS repository-scoped first-party advisory identity

**CLOSED_REJECT.** Authenticated [`GET /repos/SWivid/F5-TTS/security-advisories`](https://api.github.com/repos/SWivid/F5-TTS/security-advisories?per_page=100) returned HTTP 200 and a complete empty collection, `[]`. Direct repository lookup of `GHSA-93wx-x4m2-5c8f` returned HTTP 404.

GitHub's global advisory API does map CVE-2026-43624 to [`GHSA-93wx-x4m2-5c8f`](https://github.com/advisories/GHSA-93wx-x4m2-5c8f), but classifies it as `unreviewed`, returns an empty source-code location, and sets `repository_advisory_url` to null. It is a global database record, not a repository-scoped first-party advisory published by SWivid/F5-TTS. Thus the exact Batch 1 criterion is absent at this snapshot. The previously verified first-party issue, PR, fix, and `1.1.21` containment remain valid but do not substitute for the requested advisory identity.

Exact commands:

```sh
gh api --include 'repos/SWivid/F5-TTS/security-advisories?per_page=100' \
  --jq '[.[] | {ghsa_id,cve_id,published_at,updated_at,withdrawn_at,state,html_url}]'
gh api 'advisories?cve_id=CVE-2026-43624&per_page=100' \
  --jq '[.[] | {ghsa_id,cve_id,type,published_at,updated_at,withdrawn_at,html_url,repository_advisory_url,source_code_location,identifiers}]'
gh api 'repos/SWivid/F5-TTS/security-advisories/GHSA-93wx-x4m2-5c8f'
```

## Row 3: KTransformers exact introduction and release

**CLOSED_REJECT.** The detailed primary-source trace is in `ktransformers_findings.md`. In short, [`25cee581`](https://github.com/kvcache-ai/ktransformers/commit/25cee5810e8da6c2ce4611b413b0fb14c853b4a8) creates `sched_rpc.py` and atomically adds both:

```python
self.frontend.bind(f"tcp://*:{main_args.sched_port}")
data = pickle.loads(message)
```

Its parent has no such file. Rename/copy and reverse-pickaxe history trace the archived copies repaired by [`def0f931`](https://github.com/kvcache-ai/ktransformers/commit/def0f9313d6e063b5c5ccdfa1f6707f7a40dfdca) back to that object. The introducing commit has no AI trailer, has a human GitHub author/committer, and is absent from the frozen AI inventories. That supports rejection of a documented AI-origin claim while leaving undisclosed tool use unknowable.

The exact fix is contained only by published, non-prerelease [`v0.6.4`](https://github.com/kvcache-ai/ktransformers/releases/tag/v0.6.4), released `2026-07-23T14:32:53Z`. First-party release notes name security PR 2091 and the change from all-interface binding to loopback. The PR states that it was generated with Claude Code, but that is remediation evidence, not origin evidence. `v0.6.3.post1` retains wildcard binding plus `pickle.loads`; `v0.6.4` binds both copies to `127.0.0.1`. The containment claim is limited to removal of unauthenticated remote exposure, not removal of local pickle risk.

Key commands, all against the owned clone:

```sh
git -c gc.auto=0 -c maintenance.auto=false clone --filter=blob:none --no-checkout \
  https://github.com/kvcache-ai/ktransformers.git \
  autoresearch/herdr-260812-b2-python-blockers/ktransformers.git
git -c gc.auto=0 -c maintenance.auto=false -C <owned-clone> \
  log --all --follow -S'tcp://*:{main_args.sched_port}' -- <exact-file>
git -c gc.auto=0 -c maintenance.auto=false -C <owned-clone> \
  show --unified=80 25cee5810e8da6c2ce4611b413b0fb14c853b4a8 -- <exact-file>
git -c gc.auto=0 -c maintenance.auto=false -C <owned-clone> \
  tag --contains def0f9313d6e063b5c5ccdfa1f6707f7a40dfdca
git -c gc.auto=0 -c maintenance.auto=false -C <owned-clone> \
  merge-base --is-ancestor def0f9313d6e063b5c5ccdfa1f6707f7a40dfdca v0.6.4
gh api repos/kvcache-ai/ktransformers/issues/2087
gh api repos/kvcache-ai/ktransformers/pulls/2091
gh api repos/kvcache-ai/ktransformers/releases/tags/v0.6.4
```

## Prior cache incident

Batch 1 disclosed that a DeepTutor shared-cache `git log` printed background auto-packing notices and that shared pack-metadata mutation could not be excluded. This Batch 2 pass did not inspect, hash, or touch that cache. The incident remains disclosed as historical context, not a new Batch 2 mutation.

## Negative controls and claim boundary

- A missing release is a `CLOSED_REJECT` for released containment, not proof that a future release cannot contain the fix.
- A global unreviewed GHSA with `repository_advisory_url=null` is not promoted to a repository-scoped first-party advisory.
- Human metadata and absence from frozen AI inventories reject a documented AI-origin claim; they cannot prove undisclosed AI use never occurred.
- Claude assistance on a remediation PR cannot be projected backward onto the vulnerable introduction.
- API comparisons, tags, blame/pickaxe, and source recovery support the exact introduction/fix/release edges stated here. They do not independently establish AI causality.

`CLOSED_PASS` would require that the formerly missing facet close positively without weakening Batch 1's publication boundary. All three facets instead close negatively: no ChatDev fixed release, no F5-TTS repository advisory, and a non-AI-documented KTransformers origin. Therefore the Batch 1 positive count remains zero.
