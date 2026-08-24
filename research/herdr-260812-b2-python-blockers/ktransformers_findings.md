# KTransformers blocker closure

## Decision

**CLOSED_REJECT** — both Batch 1 evidence gaps are closed, but the AI-origin row is rejected. The exact vulnerable-mechanism introduction is [`25cee5810e8da6c2ce4611b413b0fb14c853b4a8`](https://github.com/kvcache-ai/ktransformers/commit/25cee5810e8da6c2ce4611b413b0fb14c853b4a8), not any recovered AI-marked commit. The exact fix [`def0f9313d6e063b5c5ccdfa1f6707f7a40dfdca`](https://github.com/kvcache-ai/ktransformers/commit/def0f9313d6e063b5c5ccdfa1f6707f7a40dfdca) is contained in the published, non-prerelease [`v0.6.4`](https://github.com/kvcache-ai/ktransformers/releases/tag/v0.6.4). AI assistance on the later fix is remediation evidence, not vulnerable-code origin.

Evidence cut: `2026-08-12T12:53:58-04:00`. Repository snapshot: `https://github.com/kvcache-ai/ktransformers.git` at `eb9b70c4115cff151ace2cae5b0fc9db3690e31e`, cloned with auto-GC and maintenance disabled under the owned Batch 2 directory.

## Exact introduction

Commit [`25cee581`](https://github.com/kvcache-ai/ktransformers/commit/25cee5810e8da6c2ce4611b413b0fb14c853b4a8), authored and committed by `Atream` on `2025-03-31T22:55:32+08:00`, creates `ktransformers/server/balance_serve/sched_rpc.py`. Its new-file delta introduces both necessary parts of the reported remote mechanism in one atomic commit:

```python
self.frontend.bind(f"tcp://*:{main_args.sched_port}")
...
message = worker.recv()
data = pickle.loads(message)
```

The parent `8d0292aa4421504d8a48e6ca441a50f59032ddcf` has no such file; Git records blob `8294b43` as a new file. Reverse pickaxe on the wildcard bind returns `25cee581` as its addition and `def0f931` as its removal. `--follow --find-renames=40%` traces the first fixed copy through the 100% rename in `57d14d22` and the second through the 78% copy in `4421d481` plus later 100% renames, back to the same `25cee581` source lineage.

First-party GitHub associates the introduction with [PR 1013](https://github.com/kvcache-ai/ktransformers/pull/1013). The commit has message `add balance-serve, support concurrence`, no trailers, and Atream as both GitHub author and committer. Its SHA is absent from the frozen `ai-commits.jsonl` and `atomic-ai-units.jsonl`. This is enough to reject a claimed *documented* AI origin; it does not assert that undisclosed tool use was impossible.

The first containing tag by tag creation time is `v0.2.4`; GitHub records [release `v0.2.4`](https://github.com/kvcache-ai/ktransformers/releases/tag/v0.2.4) as published `2025-04-02T06:24:15Z`. This is tag containment of the introduced code, not an independently asserted affected-version range.

## Exact fix and released containment

The public [GitHub advisory](https://github.com/advisories/GHSA-6vqg-j4cx-cqv4) is type `unreviewed` and states that KTransformers through `0.6.3` is fixed by `def0f93`. First-party [issue 2087](https://github.com/kvcache-ai/ktransformers/issues/2087) identifies the wildcard-bound ROUTER socket, unauthenticated `pickle.loads`, and default backend launch. First-party [PR 2091](https://github.com/kvcache-ai/ktransformers/pull/2091) changes both archived copies from `tcp://*` to `tcp://127.0.0.1`; its body says it was generated with Claude Code. Merge/fix commit `def0f931` changes exactly those two bind lines.

Released containment is exact:

- `git tag --contains def0f931...` returns only `v0.6.4`.
- `git merge-base --is-ancestor def0f931... v0.6.4` succeeds; the tag is three commits after the fix.
- GitHub records `v0.6.4` as a non-draft, non-prerelease release published `2026-07-23T14:32:53Z`.
- Its first-party release notes have a Security section naming PR 2091 and stating that the scheduler now binds to `127.0.0.1` instead of all interfaces.
- Direct tag inspection shows `v0.6.3.post1` still has `tcp://*` plus `pickle.loads(message)`, while both fixed copies in `v0.6.4` bind to `127.0.0.1`. Pickle remains, so the verified containment is specifically removal of the advisory's unauthenticated *remote network* exposure, not general removal of unsafe deserialization.

`v0.6.3.post1` is a repository tag but `GET /releases/tags/v0.6.3.post1` returned `404`; it is therefore retained as tag-only negative evidence, not promoted to a GitHub-release claim.

## Advisory identity nuance

The public global endpoint `GET /advisories/GHSA-6vqg-j4cx-cqv4` returned CVE-2026-63767, `type=unreviewed`, the exact fix, and repository issue/PR references. The `v0.6.4` release notes instead name repository advisory `GHSA-83vp-v6wg-x93x`. Authenticated repository-scoped requests for both advisory IDs returned `404`, so no private/repository-advisory body is claimed. This does not block exact first-party issue/PR/fix/release containment.

## Frozen input hashes

| Input | SHA-256 |
|---|---|
| Batch 1 `report.md` | `251fbc3ba65427bdf090f6c9af458f43ad256fc7c7b1a36b13fc88d8eb07d788` |
| Batch 1 `result.json` | `fa5941b031a04895e33f2cad4ffb13568d564917caf45a74ebb92f8726220d70` |
| KTransformers `ai-commits.jsonl` | `d1dd74e83dd710403bc68ea0316873904c67576ce3d6085c15e0dcf56ce04fba` |
| KTransformers `expanded-candidates.jsonl` | `8ad0ae35084e240876d3a4e67f9ef32f8d7627d5906ebde7e5934abe3f6687e9` |
| KTransformers `fix-roots.jsonl` | `236413af3543c799f50832c03d9fb94e5244cda335232674fa90a66e1177f04f` |
| KTransformers `fix-source-observations.jsonl` | `2a09a637d8ac96644e1254e9932d64c22c414d245162337c49f6c79bff5ddb16` |
| KTransformers `atomic-ai-units.jsonl` | `506a742b4dc1bfd75deb2cdb97c5983205622a7f1efd239225a9e894d14154f3` |
| KTransformers `fix-manifest.json` | `59da8854f1401337c776829c9488dc2c5560ab1f0ac7e8a3eaa5435239d571ea` |
| KTransformers empty `same-file-candidates.jsonl` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| KTransformers `summary.json` | `6dd7c17f78c52cacd5a56d732a257071b913689ba574d142b72e2e7889bcfc3f` |

## Exact commands and API sources

```sh
git -c gc.auto=0 -c maintenance.auto=false clone --filter=blob:none --no-checkout \
  https://github.com/kvcache-ai/ktransformers.git \
  autoresearch/herdr-260812-b2-python-blockers/ktransformers.git
git -c gc.auto=0 -c maintenance.auto=false -C <owned-clone> show --format=fuller --stat def0f931...
git -c gc.auto=0 -c maintenance.auto=false -C <owned-clone> log --all --follow \
  -S'tcp://*:{main_args.sched_port}' --format='%H%x09%P%x09%aI%x09%an%x09%s' -- <exact-file>
git -c gc.auto=0 -c maintenance.auto=false -C <owned-clone> show --unified=80 25cee581... \
  -- ktransformers/server/balance_serve/sched_rpc.py
git -c gc.auto=0 -c maintenance.auto=false -C <owned-clone> log --follow --find-renames=40% \
  --format='commit %H %P %aI %an %s' --name-status -- <exact-file>
git -c gc.auto=0 -c maintenance.auto=false -C <owned-clone> tag --contains def0f931...
git -c gc.auto=0 -c maintenance.auto=false -C <owned-clone> merge-base --is-ancestor def0f931... v0.6.4
git -c gc.auto=0 -c maintenance.auto=false -C <owned-clone> show v0.6.3.post1:<exact-file>
git -c gc.auto=0 -c maintenance.auto=false -C <owned-clone> show v0.6.4:<exact-file>
gh api advisories/GHSA-6vqg-j4cx-cqv4
gh api repos/kvcache-ai/ktransformers/issues/2087
gh api repos/kvcache-ai/ktransformers/pulls/2091
gh api repos/kvcache-ai/ktransformers/commits/25cee581.../pulls
gh api repos/kvcache-ai/ktransformers/pulls/1013/commits
gh api repos/kvcache-ai/ktransformers/releases/tags/v0.2.4
gh api repos/kvcache-ai/ktransformers/releases/tags/v0.6.4
```

No build, test, corpus rerun, cache read, or credential output/storage occurred. Git routing, tag ancestry, source recovery, and API metadata are used only for the exact edges stated above.

## Prior cache incident

Batch 1 reports that an earlier DeepTutor shared-cache `git log` printed Git auto-packing notices and that pack-metadata mutation could not be excluded. This follow-up did not inspect, hash, or touch that shared cache; all KTransformers Git reads used the owned clone with `gc.auto=0` and `maintenance.auto=false`.

## Claim boundary

The exact introduction and released containment blockers are closed. `CLOSED_REJECT` means the recovered introduction has no documented AI-authorship evidence and is not a frozen AI unit; Claude Code attribution on the later security PR cannot establish AI origin of the earlier vulnerable mechanism. It does not convert absence of disclosure into proof that no AI tool was ever used, and it does not claim that loopback binding eliminates every local pickle risk.
