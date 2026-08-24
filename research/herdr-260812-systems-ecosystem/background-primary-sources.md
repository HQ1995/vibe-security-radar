# Systems-ecosystem first-party source adjudication (background shard)

## Result

I found **0 claim-grade positives** in the five strongest novel non-Python/non-JavaScript rows. All five are useful negative controls: the advisory, exact fix, and release containment are public and real, and the routed commit has genuine commit-local AI attribution, but direct-parent replay shows that the AI delta is not the advisory mechanism. Ancestry and same-file overlap are therefore correctly treated as routing evidence only.

Counts: 5 rows reviewed; 0 PASS; 5 FAIL (`wrong_edge` / pre-existing human mechanism); 0 BLOCKED. One first-party inconsistency is retained as `UNKNOWN` rather than repaired by inference: Lightpanda's advisory assigns both Fetch and XHR containment to 0.2.9, while the code history shows the XHR cookie gate already shipped in v0.2.3--0.2.8 and the 0.2.9 fix-set changes only the helper's error signature at the XHR caller.

## Snapshot and exclusion boundary

Read-only snapshot time: `2026-08-12T16:32:01Z`. The shared checkout was intentionally dirty. No intentional write, fetch, index, branch, tag, or worktree command was run. One early read-only `git log` emitted Git's `Auto packing ... in background` message before maintenance was disabled, so the Lightpanda clone's object-pack layout must be treated as potentially touched; no refs or worktree files were changed. All later Git reads used `-c gc.auto=0 -c maintenance.auto=false`. Repository HEADs observed at the boundary:

| Repository | Read-only local HEAD |
|---|---|
| `nolabs-ai/nono` | `cd1563fb248f57637a6d3206742ec6e83778c896` |
| `lightpanda-io/browser` | `c718235410c051797b7fa76db0856e3e78687085` |
| `kata-containers/kata-containers` | `78d19a44027c39e55f032c20e16e91c06c01fde8` |
| `phalcon/cphalcon` | `be166ae6f58c51f2e222e3f70dbf3b2c83d3dd9d` |

Newest current-ledger inputs were read first. The following public IDs had no case-insensitive hit in either the frozen 110-row strict ledger or the newest main report: `GHSA-HC4M-Q9JH-XW4J`, `CVE-2026-52843` / `GHSA-36MM-V3C2-24CC`, `CVE-2026-24054` / `GHSA-5FC8-GG7W-3G5C`, `CVE-2026-24834` / `GHSA-WWJ6-VGHV-5P64`, and `CVE-2026-57584` / `GHSA-X7RJ-F32V-7JJG`. I also excluded all systems rows already adjudicated in that report, including Argo Workflows, Fission, MCP Registry, Kiota, Gitea, Scriban, Conductor, ClearenceKit, and Ironclaw.

Input hashes:

```text
7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md
0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl
c5b70455e0b590047dc1a24ee7bf8be317ec494b65e3709b09a2e3406a684cc1  .../global-same-file-v12/nono/same-file-candidates.jsonl
60afecabafb72b1712a8811aadd97957622f1821599e4d8e17e09e253eb8820f  .../global-same-file-v11/lightpanda-browser/same-file-candidates.jsonl
068ee9c0353acf47c9d4d58d3c655db7283c8678b245c4f05e564c39626f15ee  .../global-same-file-v11/kata-containers/same-file-candidates.jsonl
97a5988e0745f0777ca7f971748b34ed9a6da0d864c72b02efc69d19712f109d  .../global-same-file-v11/cphalcon/same-file-candidates.jsonl
221b24fdd8b317ac9db97d0e026e6aa939377a8de542fea159948a354647138c  CVE-2026-52843.json
6579c5d77da2a2630c7e0e36b0464208da3edee9f206c761d78087881ebad34e  CVE-2026-24054.json
f557a9c8947c88aa34bada0820889e8c805c96f618a466d7fbc33085a552a0e5  CVE-2026-24834.json
ea08a44eefe5b4fba06f9f322e1afc623dc34b55fb11f963160d12ab0a8af380  CVE-2026-57584.json
```

The `global-same-file-*` files are only the local discovery source. Every verdict below was independently replayed from first-party Git and an official repo advisory/CNA object.

## Row-level evidence

| # | Language / component | Public advisory | Exact AI candidate evidence | Exact advisory/fix lineage and released containment | But-for / same-mechanism verdict |
|---:|---|---|---|---|---|
| 1 | Rust; `nolabs-ai/nono` (AI-agent sandbox) | [GHSA-HC4M-Q9JH-XW4J](https://github.com/nolabs-ai/nono/security/advisories/GHSA-hc4m-q9jh-xw4j), published, not withdrawn | [`242d491734f1c0c1cb891a6437f936c390c06044`](https://github.com/nolabs-ai/nono/commit/242d491734f1c0c1cb891a6437f936c390c06044), direct commit, `Co-Authored-By: Claude Sonnet 4.6`; it shipped in v0.49.0 through v0.61.2 before the fix | Advisory root cause: `verify_profile_packs` treated the lockfile and trust bundle as optional. Human [`088bdad7eeace66338f91075c812d2ea00274f0d`](https://github.com/nolabs-ai/nono/commit/088bdad7eeace66338f91075c812d2ea00274f0d) introduced the optional verification flow. Exact fix [`db07375031642f089d549b4f7b9abece87e39f87`](https://github.com/nolabs-ai/nono/commit/db07375031642f089d549b4f7b9abece87e39f87) makes both records mandatory; first contained in v0.62.0, matching the advisory's `<=v0.61.2` / `0.62.0` boundary. | **FAIL `wrong_edge`**. Candidate only pins `serde_yaml_ng` and adds a malformed-YAML rollback test in `wiring.rs`; it never changes `verify_profile_packs`, lockfile optionality, trust-bundle acceptance, or host hook execution. Direct ancestry is true but mechanism identity and reversal are false. |
| 2 | Zig; `lightpanda-io/browser` (headless browser for AI/automation) | [CVE-2026-52843 / GHSA-36MM-V3C2-24CC](https://github.com/lightpanda-io/browser/security/advisories/GHSA-36mm-v3c2-24cc), published, not withdrawn | [`267eee9693573a085188a15938451eef726c8736`](https://github.com/lightpanda-io/browser/commit/267eee9693573a085188a15938451eef726c8736), Claude Opus 4.6 co-author; [`b373fb4a424119c314da7c8a62aa3811c6a4698c`](https://github.com/lightpanda-io/browser/commit/b373fb4a424119c314da7c8a62aa3811c6a4698c), Claude Opus 4.6 co-author. Both shipped in 0.2.7 and 0.2.8. | Official fix carrier [`2cdaac780bed65db98bbb6ed2ad5bc6011863c76`](https://github.com/lightpanda-io/browser/commit/2cdaac780bed65db98bbb6ed2ad5bc6011863c76) is a merge. Human members [`e698028e3aa30b306b20ac40c3cd8afafb89a874`](https://github.com/lightpanda-io/browser/commit/e698028e3aa30b306b20ac40c3cd8afafb89a874) (credential-aware Fetch cookie jar), [`f9fc858212d04bfeae05232f109aef8bd62564f5`](https://github.com/lightpanda-io/browser/commit/f9fc858212d04bfeae05232f109aef8bd62564f5), and [`c42e242897084ec3daf1cfdfc1d299aca87c3695`](https://github.com/lightpanda-io/browser/commit/c42e242897084ec3daf1cfdfc1d299aca87c3695) land in 0.2.9. Unsafe Fetch cookie attachment traces to human `cdd31353c52bd2da4fb72bebfad6f51dc6bb5154`. | **FAIL `wrong_edge` x2**. `267eee` only creates `SubmitEvent` and changes form submission; `b373fb` only fixes MIME charset prescan. Neither touches Fetch/XHR credentials or cookies. **UNKNOWN advisory-width control:** human `cecdf0d511dee5fb531170ed889849cd4c3336ec` added the XHR cookie gate and shipped in v0.2.3--0.2.8; the 0.2.9 set only removes `try` at that XHR call. Fetch containment is exact; the advisory's XHR release boundary is not independently reproduced by this fix-set. |
| 3 | Go/Rust/C infrastructure; `kata-containers/kata-containers` | [CVE-2026-24054 / GHSA-5FC8-GG7W-3G5C](https://github.com/kata-containers/kata-containers/security/advisories/GHSA-5fc8-gg7w-3g5c), published, not withdrawn | [`e4a13b9a4ab76111ed47f65663f1edbe670cb86c`](https://github.com/kata-containers/kata-containers/commit/e4a13b9a4ab76111ed47f65663f1edbe670cb86c), direct commit with `Co-authored-by: Copilot`; shipped in 3.24.0 and 3.25.0 before containment | Advisory says a no-layer/malformed image can make a host bind mount look like a block device and be hot-plugged. Exact human fix [`20ca4d2d79aa5bf63aa1254f08915da84f19e92a`](https://github.com/kata-containers/kata-containers/commit/20ca4d2d79aa5bf63aa1254f08915da84f19e92a) changes `DEFDISABLEBLOCK := false` to `true`; first contained in 3.26.0, exactly matching the official range `<=3.25.0`. The unsafe default traces to human history in 2020 (`a02a8bda...`). | **FAIL `wrong_edge`**. Candidate adds NVIDIA confidential-build `ROOTMEASURECONFIG_NV` plumbing and root-hash handling. Its shared `src/runtime/Makefile` hunk never changes block-device detection, `DEFDISABLEBLOCK`, rootfs mounting, or hotplug. |
| 4 | Go/Rust/C infrastructure; `kata-containers/kata-containers` | [CVE-2026-24834 / GHSA-WWJ6-VGHV-5P64](https://github.com/kata-containers/kata-containers/security/advisories/GHSA-wwj6-vghv-5p64), published, not withdrawn | Same exact Copilot-assisted candidate `e4a13b9a4ab76111ed47f65663f1edbe670cb86c`; it shipped in 3.24.0--3.26.0 before containment | Advisory mechanism is writable guest `virtio-pmem` / DAX access to the guest image. Official fix carrier [`6a672503973bf7c687053e459bfff8a9652e16bf`](https://github.com/kata-containers/kata-containers/commit/6a672503973bf7c687053e459bfff8a9652e16bf) is a merge; the mechanism-bearing human member is [`e17f96251dc35b0bb1a1e16b42ca6f20db877827`](https://github.com/kata-containers/kata-containers/commit/e17f96251dc35b0bb1a1e16b42ca6f20db877827), which removes Cloud Hypervisor pmem use and forces read-only disk config. First contained in 3.27.0, matching `<=3.26.0`. Human `9fda7059a50b43b0461bbcd4c4dfa2e2cc3d1212` / branch-equivalent history added the relevant `NewPmemConfig(assetPath)` path in 2023. | **FAIL `wrong_edge`**. The candidate's measurement/root-hash build plumbing does not add or modify `NewPmemConfig`, DAX, `DiscardWrites`, guest image disk mapping, or Cloud Hypervisor. Same file name is not the same invariant. |
| 5 | C/PHP infrastructure; `phalcon/cphalcon` | [CVE-2026-57584 / GHSA-X7RJ-F32V-7JJG](https://github.com/phalcon/cphalcon/security/advisories/GHSA-x7rj-f32v-7jjg), published, not withdrawn | [`59577028e763add56a11c5bd1c929d988da6df47`](https://github.com/phalcon/cphalcon/commit/59577028e763add56a11c5bd1c929d988da6df47), direct commit with `Assisted-by: Claude Code`; direct ancestor of the fix | Advisory mechanism is catastrophic backtracking from default MVC/CLI route `(/.*)*`. Human source fix [`14ba22d389d5ca620bb9d5207205f836ef1224f2`](https://github.com/phalcon/cphalcon/commit/14ba22d389d5ca620bb9d5207205f836ef1224f2) replaces it with `(/.*)?`; human follow-up [`fa798e919cb2c487062bb9899ad6fc2b673b3a67`](https://github.com/phalcon/cphalcon/commit/fa798e919cb2c487062bb9899ad6fc2b673b3a67) recompiles generated C/tests. Both are contained in v5.15.0. `git log -S '(/.*)*'` traces the dangerous pattern to human `37d7a3e23230f4a44fcb0d492c70790ff3d93bb3` in 2019. | **FAIL `wrong_edge`**, plus release negative: `59577028` only improves exceptions, return values, and documentation in CLI router files; it never changes the regex. `tag --contains candidate --no-contains source-fix` is empty, so the AI commit did not even ship in an independently vulnerable release window. |

## Exact replay commands

Except for the disclosed initial Lightpanda read, Git reads used `-c gc.auto=0 -c maintenance.auto=false` and the already-present clones. Representative commands (the same shape was used for every row):

```zsh
# Freeze current accepted objects and discovery packets.
sha256sum \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
  autoresearch/orchestrator-260811-atomic150/global-same-file-v12/nono/same-file-candidates.jsonl \
  autoresearch/orchestrator-260811-atomic150/global-same-file-v11/{lightpanda-browser,kata-containers,cphalcon}/same-file-candidates.jsonl

# Public-ID exclusion: expected no output.
rg -ni 'GHSA-HC4M-Q9JH-XW4J|CVE-2026-52843|GHSA-36MM-V3C2-24CC|CVE-2026-24054|GHSA-5FC8-GG7W-3G5C|CVE-2026-24834|GHSA-WWJ6-VGHV-5P64|CVE-2026-57584|GHSA-X7RJ-F32V-7JJG' \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md

# Exact advisory objects; unauthenticated first-party calls, no credentials.
curl -fsSL -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  https://api.github.com/repos/nolabs-ai/nono/security-advisories/GHSA-hc4m-q9jh-xw4j
curl -fsSL -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  https://api.github.com/repos/lightpanda-io/browser/security-advisories/GHSA-36mm-v3c2-24cc
curl -fsSL -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  https://api.github.com/repos/kata-containers/kata-containers/security-advisories/GHSA-5fc8-gg7w-3g5c
curl -fsSL -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  https://api.github.com/repos/kata-containers/kata-containers/security-advisories/GHSA-wwj6-vghv-5p64

# Atomic identity, parent delta, ancestry, mechanism origin, and tags.
git -c gc.auto=0 -c maintenance.auto=false -C "$repo_dir" \
  show -s --format='%H%n%P%n%an <%ae>%n%ad%n%B' --date=iso-strict "$candidate" "$fix"
git -c gc.auto=0 -c maintenance.auto=false -C "$repo_dir" \
  diff "${candidate}^" "$candidate" -- <mechanism-paths>
git -c gc.auto=0 -c maintenance.auto=false -C "$repo_dir" \
  diff "${fix}^" "$fix" -- <mechanism-paths>
git -c gc.auto=0 -c maintenance.auto=false -C "$repo_dir" \
  merge-base --is-ancestor "$candidate" "$fix"
git -c gc.auto=0 -c maintenance.auto=false -C "$repo_dir" \
  tag --contains "$candidate" --no-contains "$fix" --sort=version:refname

# Origin/reversal spot checks used above.
git -c gc.auto=0 -c maintenance.auto=false -C "$nono_repo" \
  log --all --reverse --format='%H %an %ad %s' -S 'let locked = lockfile.packages.get' -- crates/nono-cli/src/profile_runtime.rs
git -c gc.auto=0 -c maintenance.auto=false -C "$lightpanda_repo" \
  log --all --reverse --format='%H %an %ad %s' -S '.cookie_jar = &page._session.cookie_jar' -- src/browser/webapi/net/Fetch.zig
git -c gc.auto=0 -c maintenance.auto=false -C "$kata_repo" \
  log --all --reverse --format='%H %an %ad %s' -S 'DEFDISABLEBLOCK := false' -- src/runtime/Makefile
git -c gc.auto=0 -c maintenance.auto=false -C "$kata_repo" \
  log --all --reverse --format='%H %an %ad %s' -S 'NewPmemConfig(assetPath)' -- src/runtime/virtcontainers/clh.go
git -c gc.auto=0 -c maintenance.auto=false -C "$phalcon_repo" \
  log --all --reverse --format='%H %an %ad %s' -S '(/.*)*' -- phalcon/{Mvc,Cli}/Router{,/Route}.zep
```

All six ancestry checks (two Lightpanda candidates, two Kata advisories, Nono, and Phalcon) returned exit 0. That proves reachability only and is deliberately not treated as causality.

## Negative/unknown controls and claim boundary

- **No positive row is proposed.** A public advisory plus an AI-attributed ancestor is insufficient when the candidate delta does not create, reopen, or extend the advisory's input-to-sink path.
- **Merge carriers are not atomic fixes.** Lightpanda `2cdaac...` and Kata `6a6725...` are retained as release/topology witnesses; the mechanism-bearing members are named separately.
- **Released containment is exact for Nono, Lightpanda Fetch, both Kata rows, and Phalcon.** The first containing tags match each first-party patched release.
- **Lightpanda XHR remains `UNKNOWN` at the advisory-width level.** The advisory says 0.2.9 fixes XHR, but the cookie/`withCredentials` gate shipped earlier. I do not silently narrow the advisory to Fetch, nor use the discrepancy to manufacture a positive.
- **No product-name-only evidence was used.** Nono and Lightpanda are AI/agent infrastructure by their own repositories, but their names/descriptions played no role in the causal verdict. Kata/Phalcon are infrastructure controls.
- Local routing artifacts, shared-file matches, CVE ranges, tags, and first-party advisory prose are diagnostic unless the atomic parent delta, exact fix reversal, same invariant, and release topology all agree. Here they do not agree for any AI candidate.
