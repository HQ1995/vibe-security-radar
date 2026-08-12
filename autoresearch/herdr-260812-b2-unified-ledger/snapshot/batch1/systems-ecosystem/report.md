# Novel systems-ecosystem candidate adjudication

## Result

This bounded shard manually adjudicated **15 exact AI-marked candidate-to-security-fix rows** from systems-oriented repositories that are absent from the current strict ledger and the newest completed candidate-closure report. The main pass covers 10 rows below; a separately bounded primary-source subpass covers 5 more in [`background-primary-sources.md`](./background-primary-sources.md), SHA-256 `c2a29ebe195361324a8eb8712ac46c96d0c232b3d528af3226273224407dbccb`. The combined result is **0 publication-grade additions and 15 `FAIL wrong_edge` controls**.

Every selected candidate has concrete AI authorship or assistance evidence and is a real ancestor of the named security fix. That is only routing evidence. In each case, direct parent/delta replay shows that the candidate does not introduce, reopen, or materially extend the exact mechanism later repaired. None therefore satisfies but-for causality or same-mechanism contribution.

Released containment was verified for all 15 mechanisms. In the 10-row main pass, nine exact atomic fixes are ancestors of a released tag; `lz4_flex` used release-branch equivalents. The five-row subpass independently verified first containing releases. This is release evidence for the fix mechanisms, not evidence that the AI candidates caused the vulnerabilities.

## Scope and snapshot boundary

- Started: `2026-08-12T12:17:37-04:00`
- Checkout: `/home/hanqing/agents/ai-slop`
- Branch / commit at start: `dev` / `6c0d2084fd1240341d6d1b9f9096252490168f0b`
- Dirty-tree boundary: `405` status entries were visible at the later verification snapshot. The checkout is shared and volatile; no inference is made about ownership or stability of those entries.
- Writable scope: only `/home/hanqing/agents/ai-slop/autoresearch/herdr-260812-systems-ecosystem/`.
- Repository clones and advisory caches listed below were read only. Their recorded `HEAD` and content hashes define the evidence snapshot; later shared-cache movement is outside this report.
- No build, test suite, full-unit rerun, cache mutation, credentialed request, commit, stage, reset, clean, or push was performed.

### Newest completed work excluded first

The following frozen inputs were read before candidate work:

| Input | SHA-256 |
|---|---|
| `docs/RESEARCH-NEW-200-CANDIDATE-CLOSURE-2026-08-12.md` | `bc8cb68d10b8b79d5219518d139fc5d1e104080fbcdae6c8ba08d94acc1710ad` |
| `docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md` | `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl` | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| `autoresearch/orchestrator-260811-atomic150/strict-200-v3/summary.json` | `69dd6c35de1455bf9cee88420aed570c576a190a4d143202d01a26cc3d37b81e` |

The current strict ledger snapshot contains 110 semantic components and 200 public IDs (canonical ledger hash recorded by its summary: `afc810cec757df378cc63be935a53fe6635dbb7ede72bc32035880ffcde23c23`). Exact component/ID searches found none of the 10 selected components or public IDs in that ledger.

All 21 rows in the newest completed candidate closure were excluded rather than rerun. The systems-oriented subset explicitly excluded includes `theshit` / CVE-2026-21882, `emp3r0r` / CVE-2026-26201, `antchfx/xpath` / CVE-2026-32287, Zcash / CVE-2026-35679, Gravity / CVE-2026-40504, Grid / CVE-2026-42199, Nerdbank.MessagePack / CVE-2026-44375, Pi-hole / CVE-2026-50130, bettercap / CVE-2026-8276, and Crabbox / CVE-2026-8634. Earlier model routes and introduced-SHA screens mentioning some selected rows were retained only as diagnostic leads; they were not treated as manual adjudications or claim evidence.

### Row-input bundle hashes

Each bundle hash is SHA-256 over the textual `sha256sum` manifest for these five files in the named component directory: `expanded-candidates.jsonl`, `ai-commits.jsonl`, `fix-roots.jsonl`, `fix-source-observations.jsonl`, and `global-same-file-v15/<component>/summary.json`.

| Component | Bundle SHA-256 |
|---|---|
| cert-manager | `49b8f5ad2af6176ead262c740c99ca4075ad3e613fa8bc14f94113ef1ff91731` |
| flannel | `dad7a1b735603742f7b1ef988137164bc8eac65ab1401a125885acc74287696f` |
| reva | `33137ce9ce5505592734be00ee43c6744d808604648aca14cd6158983a5622b5` |
| msgpack-java | `9d97605000b48fb4f07b0c211d99c39ca38d6825ac839277cf76500295deec78` |
| lz4-flex | `8670d8eff88ceee997dc5f05019160e49cae1fad9ed5cd05c0216b961d24e832` |
| libssh-mirror | `be253bf6722f20fbbe56e81281f2d0c7a0b67fe4f4610c2388f0bd6176d3e623` |
| weknora | `858980fec813b5ef8e56c570fca102442be3c6c788be17a55f309764db2601d7` |
| terraform-provider-proxmox | `303feb63ca6cda4159db4dfcdf328ba718fe531c0b5d59ad3ccd9e79a2903339` |
| ktransformers | `81aa28cab00bb5bf8badc91af5ed63f55620b5793d7f24dc5e39898d8e87eee5` |
| boxlite | `03598ea5adf74dde0c9523a888a6cf9658ab215631ff9b3846320c3d23dbd06c` |

### Read-only clone snapshots

| Component | Clone `HEAD` |
|---|---|
| cert-manager | `240d8d1369d49f8ca125f63af2c4cea4f8cb17e0` |
| flannel | `1246d0632be2bd0d423417ce287779a23c0706a6` |
| reva | `937d43325e5fe6c9abde33e6b3593a9a9efeeea9` |
| msgpack-java | `580fde4766e6e6a6931cabf6062a6661377185da` |
| lz4_flex | `0b9bd1d62fc0ebef71e9435e3b1578504a513a48` |
| libssh | `8782fcec18bbcaf8b6f8eb936a9e1cf3093902e6` |
| WeKnora | `8378454d44889135c519fa08e4fe354278cc2fc8` |
| Terraform Provider Proxmox | `d2b87294e72181caa12ccae497a3d4bf7837b766` |
| KTransformers | `a8062bfa7e1060ce5855b5f1ad6aa6b116678307` |
| BoxLite | `d182f49a227e62b177830bb6f130581ddf28eb7f` |

### Advisory-record hashes

These are the local advisory-database records used to route to precise public sources. Direct repository advisories or vendor advisories were then checked live.

| ID | Local record SHA-256 |
|---|---|
| GHSA-gx3x-vq4p-mhhv | `ead5580efd38a28cbea00283746f415c2bb9c61dae5e8d7ed7a734e6887d6c74` |
| GHSA-vchx-5pr6-ffx2 | `de8b00b9a3d35b7521b369c612056937422175c8a59cc854a56fbb04216e3463` |
| GHSA-9j2f-3rj3-wgpg | `41677b1a0952aa270c3ac3ccfaa329d680adcee3d57801061a38527d22a7cf3d` |
| GHSA-cw39-r4h6-8j3x | `debc3e251385bc9edd8e463dfdd2dffb9fbe602967eb87dfea017cb2e0b91c85` |
| GHSA-vvp9-7p8x-rfvv | `69890e3fca44da754ca6fce597481cac93edc21bdcefbfaa48932b16beda0af6` |
| GHSA-r55h-3rwj-hcmg | `89a170c829e5244d224734c6dcb9546f68d1ffd303e1791870af3b6fb8b76cb5` |
| GHSA-gwch-7m8v-7544 | `2473c7b08bc81a40402af3e83d5eb0a5d86c4af753db9a80025f5b4d62fc3656` |
| GHSA-xjhv-pp2r-6f82 | `69b6f8cea3a0d8e91eb14d630f5c278154729c91583516c68664f0bbd9908bdf` |
| CVE-2026-63767 / GHSA-6vqg-j4cx-cqv4 (unreviewed mirror) | `43f1d50946d2a56d7a877c1033b563a78c6ff5aef33bd504d783beac88d1f3a2` |
| CVE-2026-3731 / GHSA-wg5h-wgv3-pgqh (unreviewed mirror) | `e4a02408a44af726c22db9b169a141fc078706b6896a22ca1b07dbcc968d424d` |

## Adjudication gates

A row can pass only when all of the following are supported by exact evidence:

1. **AI evidence:** explicit bot author identity, AI co-author trailer, or explicit generated-with attribution on the candidate commit. Product names and repository topics do not count.
2. **Exact lineage:** the candidate is an ancestor of the atomic fix. Merge/squash carriers are topology only; an atomic parent-to-child security delta is required.
3. **But-for contribution:** the candidate introduces or materially extends the affected source, sink, caller, default, lifecycle, or missing security check. Mere ancestry is insufficient.
4. **Same mechanism:** the candidate delta must be reversed or bounded by the fix mechanism. Same repository, same broad subsystem, or same file alone is insufficient.
5. **First-party identity:** use the repository security advisory or vendor advisory when one exists. CNA/global mirrors are secondary routing evidence.
6. **Released containment:** the atomic fix or an equivalent release-branch patch must be present in a public release.

For each row below, `git merge-base --is-ancestor <candidate> <atomic-fix>` returned success. For each row, an exact `git grep -F <vulnerable-expression> <candidate>^ -- <affected-path>` also succeeded. That second observation is decisive negative evidence: the candidate is not the origin of the repaired operation.

## Main-pass row-level results (10)

### 1. cert-manager — Go — CVE-2026-25518 / GHSA-gx3x-vq4p-mhhv

- First-party source: [cert-manager repository advisory](https://github.com/cert-manager/cert-manager/security/advisories/GHSA-gx3x-vq4p-mhhv).
- AI candidate: `4656dc79d5bddc9ddb724385833caec189b20a50`, with `Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>`.
- Candidate delta: one line in `pkg/util/pki/asn1_util.go`, changing `"programmer mistake: unsupported..."` to `"unsupported UniversalValue type: ..."`.
- Atomic fix: `8b62c22e368794f847b27d739a1b6af0805c7dee` on the 1.19 branch. `d4faed26ae12115cceb807cdc12507ebc28980e2` is the two-parent PR merge carrier and is not used as the atomic causal delta.
- Fix mechanism: replace the cached DNS response's unchecked `Answer[0].(*dns.SOA)` assertion with iteration plus an `ok` type check and no-SOA error.
- Parent proof: candidate parent contains `pkg/issuer/acme/dns/util/wait.go:315: return cachedEntryItem.Response.Answer[0].(*dns.SOA).Hdr.Name, nil`.
- Containment: the atomic fix is an ancestor of `v1.19.3`; the advisory also names separately patched `v1.18.5`.
- Verdict: **FAIL `wrong_edge`**. The candidate is an unrelated ASN.1 error-message cleanup; it neither creates nor extends the DNS cache path.

### 2. flannel — Go — CVE-2026-32241 / GHSA-vchx-5pr6-ffx2

- First-party source: [flannel repository advisory](https://github.com/flannel-io/flannel/security/advisories/GHSA-vchx-5pr6-ffx2).
- AI candidate: `65b1ad7b885271c6fe0d5bc753d96747e5ac500c`, authored and committed by `copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>`.
- Candidate delta: adds only `ACTIVITY_SUMMARY_2025.md`.
- Atomic fix: `08bc9a4c990ae785d2fcb448f4991b58485cd26a`.
- Fix mechanism: stop invoking extension commands through `sh -c`; split fixed command text and pass literal arguments to `exec.Command`, including environment expansion without shell interpretation.
- Parent proof: candidate parent contains `pkg/backend/extension/extension_network.go:95: "sh", "-c", n.subnetAddCommand)`.
- Containment: exact fix is an ancestor of `v0.28.2`.
- Verdict: **FAIL `wrong_edge`**. Documentation-only activity summary; the injectable execution path dates to earlier history.

### 3. Reva — Go — CVE-2026-23989 / GHSA-9j2f-3rj3-wgpg

- First-party source: [Reva repository advisory](https://github.com/opencloud-eu/reva/security/advisories/GHSA-9j2f-3rj3-wgpg).
- AI candidate: `52d5ce693cb6343f7f1baba7335d5ee22d242e71`, with Copilot co-author trailer.
- Candidate delta: fixes only the spelling of `unmarshaller` in a comment in `pkg/events/users.go`.
- Atomic fix: `6b24ff65e8e099949ece16224360d366f610e81b`; `95aa2bc5d980eaf6cc134d75782b4f5ac7b36ae1` is the merge carrier.
- Fix mechanism: replace lexical `strings.HasPrefix(childPath, parentPath)` scope validation with `filepath.Rel` and reject `..` traversal.
- Parent proof: candidate parent contains the vulnerable `strings.HasPrefix` checks at `internal/grpc/interceptors/auth/scope.go:283` and `:341`.
- Containment: atomic fix is an ancestor of `v2.42.3` (the advisory also identifies the maintained 2.40 release line).
- Verdict: **FAIL `wrong_edge`**. A comment spelling fix in events code has no bearing on GRPC authorization scope.

### 4. msgpack-java — Java — CVE-2026-21452 / GHSA-cw39-r4h6-8j3x

- First-party source: [msgpack-java repository advisory](https://github.com/msgpack/msgpack-java/security/advisories/GHSA-cw39-r4h6-8j3x).
- AI candidate: `799e2d188b13b07704d1708d4e10283fe6dfdc8f`, explicitly `Generated with Claude Code` and carrying multiple Claude co-author trailers.
- Candidate delta: replaces deprecated Jackson API calls in the separate `msgpack-jackson` module and updates its parser test.
- Atomic fix: `daa2ea6b2f11f500e22c70a22f689f7a9debdeae` (single-parent content delta despite its subject `Merge commit from fork`).
- Fix mechanism: for declared payloads above 64 MiB, allocate gradually and fail when input ends instead of immediately allocating the declared EXT32/BIN32 size in `MessageUnpacker.readPayload`.
- Parent proof: candidate parent contains `msgpack-core/.../MessageUnpacker.java:1649: byte[] newArray = new byte[length];`; the historical allocation originates in 2015 commit `2242fe497b88c6add197b67ffd46a71e926ff593`.
- Containment: exact fix is an ancestor of `v0.9.11`.
- Verdict: **FAIL `wrong_edge`**. Jackson deprecation compatibility is neither the core unpacker allocation nor a new path into it.

### 5. lz4_flex — Rust — CVE-2026-32829 / GHSA-vvp9-7p8x-rfvv

- First-party source: [lz4_flex repository advisory](https://github.com/PSeitz/lz4_flex/security/advisories/GHSA-vvp9-7p8x-rfvv).
- AI candidate: `2991a09be12bad4574205daa3b2b09b2fc27f17f`, with `Co-Authored-By: Claude Opus 4.6`.
- Candidate delta: casts `input_len` to `u64` in `get_maximum_output_size` in `src/block/compress.rs` to avoid a 32-bit compression-size arithmetic overflow.
- Atomic fix: `055502ee5d297ecd6bf448ac91c055c7f6df9b6d`.
- Fix mechanism: reject zero and out-of-bounds LZ4 **decompression match offsets** rather than clamping them and copying uninitialized or reused output bytes.
- Parent proof: candidate parent contains `src/block/decompress.rs:287: let offset = offset.min(output_len + ext_dict.len());`; that clamp traces to human-authored 2023 commit `23b05b0ea129ac69498ad323e0384e7d6df9b03a`.
- Containment: the first-party advisory names `0.11.6` and `0.12.1`. The two tag source trees both contain `read_match_offset` and `OffsetOutOfBounds`; remote tag `0.11.6` points to release-branch patch `6460047c0ba18bf4e3331894c8db220bc724a439`.
- Verdict: **FAIL `wrong_edge`**. Both involve integer/length safety in one crate, but compression output sizing does not cause or expose the decompression match-offset leak.

### 6. libssh — C — CVE-2026-3731

- First-party source: [libssh vendor advisory](https://www.libssh.org/security/advisories/libssh-2026-sftp-extensions.txt); secondary identity mapping: [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-3731).
- AI candidate: `a9c8f942a539953c128781254773bc6c241e2b35`, whose message says most work was done with Claude and includes a Claude co-author trailer.
- Candidate delta: implements the `mlkem768x25519-sha256` key-exchange path across crypto/KEX/client files.
- Atomic fix: `855a0853ad3abd4a6cd85ce06fce6d8d4c7a0b60`.
- Fix mechanism: change two SFTP extension bounds checks from `idx > count` to `idx >= count` before indexing the name/data arrays.
- Parent proof: candidate parent contains the two vulnerable checks at `src/sftp.c:602` and `:618`.
- Containment: exact fix is an ancestor of `libssh-0.12.0`; the vendor advisory also identifies security release `0.11.4`.
- Source conflict preserved: the later CNA text characterizes a remotely performable issue, while libssh's own advisory says its internal callers do not overrun and the bad index is not controlled by a malicious server. This report adopts the narrower first-party claim and does not amplify the remote-attack assertion.
- Verdict: **FAIL `wrong_edge`**. A new post-quantum KEX does not affect SFTP extension indexing.

### 7. WeKnora — Go / AI-MCP infrastructure — CVE-2026-30861 / GHSA-r55h-3rwj-hcmg

- First-party source: [WeKnora repository advisory](https://github.com/Tencent/WeKnora/security/advisories/GHSA-r55h-3rwj-hcmg).
- AI candidate: `451f543e6d8b73d63e53087d0fd1e4278050254d`, explicitly generated with Claude Code and carrying a Claude Opus 4.5 co-author trailer.
- Candidate delta: adds Helm deployment templates and documentation.
- Atomic fix: `57d6fea8bc265ad28b385e0158957c870cff4b50`.
- Fix mechanism: disable MCP stdio transport in the service, client, manager, and UI, removing the bypassable `npx node -p` command-execution path.
- Parent proof: candidate parent contains `DangerousArgPatterns` and its stdio validation loops in `internal/utils/security.go`; the partial validation was introduced in human-authored `f7900a5e9a18c99d25cec9589ead9e4e59ce04bb`.
- Containment: exact fix is an ancestor of `v0.2.10`.
- Verdict: **FAIL `wrong_edge`**. Helm deployment scaffolding neither introduces stdio execution nor changes its validation.

### 8. Terraform Provider Proxmox — Go — CVE-2026-25499 / GHSA-gwch-7m8v-7544

- First-party source: [provider repository advisory](https://github.com/bpg/terraform-provider-proxmox/security/advisories/GHSA-gwch-7m8v-7544).
- AI candidate: `05a59aa507c5c3f1b91adb2c3240a5790313f730`, with `gemini-code-assist[bot]` co-author trailer.
- Candidate delta: adds VM `purge_on_destroy` and `delete_unreferenced_disks_on_destroy` behavior and corresponding resource documentation/tests.
- Atomic fix: `bd604c41a31e2a55dd6acc01b0608be3ea49c023`.
- Fix mechanism: replace the documented sudoers rule `/usr/bin/tee /var/lib/vz/*`, which permits `../` traversal, with a snippets-only filename pattern and an explicit warning.
- Parent proof: candidate parent contains the unsafe rule at `docs/index.md:428`; it originates in human-authored 2024 commit `3195b3cdf4c7c9d0c9e23177b4bd097de3b1fa65`.
- Containment: exact fix is an ancestor of `v0.93.1`.
- Advisory nuance: the repository advisory itself notes uncertainty over whether this is a vulnerability or an issue. It is retained as an insecure first-party deployment recommendation, not generalized into a provider-code vulnerability.
- Verdict: **FAIL `wrong_edge`**. The candidate's VM deletion feature does not create or modify the sudoers recommendation.

### 9. KTransformers — C++-heavy AI inference infrastructure — CVE-2026-63767

- Bounded source status: the [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-63767) is CNA-authored by VulnCheck and points to repository issue `#2087`, PR `#2091`, and the patch. No repository-issued security advisory was found in the bounded search, so first-party **advisory identity is UNKNOWN**. The repository issue/PR and exact git objects still provide first-party patch lineage.
- AI candidate: `fcf8882075d9d6602eb508375ee5103614dcc3e4`, explicitly generated with Claude Code and carrying a Claude co-author trailer.
- Candidate delta: adds Kimi-K2 AVX/AMX MoE weight-buffer support, kernels, bindings, loaders, examples, and benchmarks.
- Atomic fix: `def0f9313d6e063b5c5ccdfa1f6707f7a40dfdca`.
- Fix mechanism: bind the pickle-consuming ZMQ SchedulerServer ROUTER socket to `127.0.0.1` instead of all interfaces in both archived copies.
- Parent proof: candidate parent contains `tcp://*` binds in `archive/ktransformers/.../sched_rpc.py:43` and `kt-sft/.../sched_rpc.py:31`.
- Containment: exact fix is an ancestor of `v0.6.4`; PyPI published a non-yanked `ktransformers-0.6.4.tar.gz` on `2026-07-23T15:07:24.698370Z` with SHA-256 `c89f7dcbd4dd6edd3a1716f786522e89d7610cdbd20074c17b662d6cb68b7e47`.
- Verdict: **FAIL `wrong_edge`**. MoE kernels and loaders do not create or expose the scheduler's network bind. The missing first-party advisory would independently prevent a publication-grade positive even if causality had survived.

### 10. BoxLite — Rust / Go / C AI sandbox infrastructure — CVE-2026-47213 / GHSA-xjhv-pp2r-6f82

- First-party source: [BoxLite repository advisory](https://github.com/boxlite-ai/boxlite/security/advisories/GHSA-xjhv-pp2r-6f82).
- AI candidate: `aed55982d56d3df85ce014b078e5bf5f6b834821`, with Claude co-author trailer.
- Candidate delta: a broad SDK/runtime change adding network allowlists and secret substitution. It changes Rust, Go, C, Node, and Python SDK surfaces, but does not touch `src/guest/src/service/exec/timeout.rs` or another guest execution-timeout implementation.
- Atomic fix: `28159fc5b6b6fd5037e18a58fc4644c882e3c581`.
- Fix mechanism: replace catchable `SIGALRM` timeout termination with `SIGTERM`, a grace period, and uncatchable `SIGKILL` fallback.
- Parent proof: candidate parent contains `src/guest/src/service/exec/timeout.rs:23: exec_state.kill(Signal::SIGALRM)`.
- Containment: exact fix is an ancestor of `v0.9.7`; PyPI published non-yanked 0.9.7 wheels on 2026-07-01. The GHSA's `patched_versions` field is empty, so tag ancestry plus the public package release supplies the containment evidence.
- Verdict: **FAIL `wrong_edge`**. The network/secrets feature neither introduces timeout handling nor changes the signal choice.

## Summary matrix

| Row | Component | Strong AI signal | Candidate → atomic fix | Defect in candidate parent | Same mechanism | Released containment | Verdict |
|---:|---|---:|---:|---:|---:|---:|---|
| 1 | cert-manager | yes | yes | yes | no | yes | FAIL wrong_edge |
| 2 | flannel | yes | yes | yes | no | yes | FAIL wrong_edge |
| 3 | Reva | yes | yes | yes | no | yes | FAIL wrong_edge |
| 4 | msgpack-java | yes | yes | yes | no | yes | FAIL wrong_edge |
| 5 | lz4_flex | yes | yes | yes | no | yes, equivalent branch patches | FAIL wrong_edge |
| 6 | libssh | yes | yes | yes | no | yes | FAIL wrong_edge |
| 7 | WeKnora | yes | yes | yes | no | yes | FAIL wrong_edge |
| 8 | Terraform Provider Proxmox | yes | yes | yes | no | yes | FAIL wrong_edge |
| 9 | KTransformers | yes | yes | yes | no | yes | FAIL wrong_edge; advisory identity unknown |
| 10 | BoxLite | yes | yes | yes | no | yes | FAIL wrong_edge |

## Negative and unknown controls

- **Negative:** all 15 rows are exact, reproducible counterexamples to treating AI-marked ancestry as causal evidence.
- **Negative:** the local same-file screens returned zero promoted same-file candidates for these selected fix classes; manual checks independently confirmed different files/mechanisms.
- **Negative:** no candidate here is a remediation-as-origin misclassification; each is a pre-fix ancestor, but each is still causally unrelated.
- **UNKNOWN:** no first-party KTransformers security advisory was found; the CVE CNA, repository issue/PR, exact patch, tag, and PyPI artifact are real but do not substitute for a vendor advisory identity.
- **Conflict retained:** libssh's first-party advisory is narrower than the later CNA remote-attack wording.
- **UNKNOWN:** the background subpass preserves a Lightpanda advisory-width inconsistency: 0.2.9 contains the Fetch fix, while the XHR credential/cookie gate had already shipped in 0.2.3--0.2.8 and the 0.2.9 XHR change only adjusts the caller's error signature.
- **Operational disclosure:** an early background Lightpanda `git log` triggered Git background auto-pack in that read-only clone before automatic maintenance was disabled. No ref or worktree file changed, but its object-pack layout may have changed. All later background Git reads used `-c gc.auto=0 -c maintenance.auto=false`.
- **Boundary:** sibling AI ancestors in high-cardinality component classes were not individually promoted or rejected. The verdicts apply only to the exact 15 candidate/fix rows named in the two reports.

## Independent primary-source subpass (5 additional rows)

The background note is part of this shard's evidence and should be read for full commands and hashes. Its five additional exact rows are:

| Component / public ID | Exact AI candidate | Exact mechanism-bearing fix | Released containment | Verdict |
|---|---|---|---|---|
| Rust Nono / GHSA-hc4m-q9jh-xw4j | `242d491734f1c0c1cb891a6437f936c390c06044` | `db07375031642f089d549b4f7b9abece87e39f87` makes lockfile and trust bundle mandatory | `v0.62.0` | FAIL wrong_edge: candidate only pins YAML dependency/adds malformed-YAML rollback test |
| Zig Lightpanda / CVE-2026-52843 | `267eee9693573a085188a15938451eef726c8736` | `e698028e3aa30b306b20ac40c3cd8afafb89a874` adds credential-aware Fetch cookie handling | `0.2.9` for Fetch | FAIL wrong_edge; XHR containment remains UNKNOWN |
| Go/Rust/C Kata / CVE-2026-24054 | `e4a13b9a4ab76111ed47f65663f1edbe670cb86c` | `20ca4d2d79aa5bf63aa1254f08915da84f19e92a` disables block-device detection by default | `3.26.0` | FAIL wrong_edge |
| Go/Rust/C Kata / CVE-2026-24834 | same `e4a13b9a4ab76111ed47f65663f1edbe670cb86c` | `e17f96251dc35b0bb1a1e16b42ca6f20db877827` removes Cloud Hypervisor pmem use / forces read-only disk config | `3.27.0` | FAIL wrong_edge |
| C/PHP Phalcon / CVE-2026-57584 | `59577028e763add56a11c5bd1c929d988da6df47` | `14ba22d389d5ca620bb9d5207205f836ef1224f2` replaces catastrophic `(/.*)*` route regex | `v5.15.0` | FAIL wrong_edge |

The subpass also checked a second Lightpanda candidate, `b373fb4a424119c314da7c8a62aa3811c6a4698c`, and found it unrelated (MIME charset prescan). It is evidence within the same Lightpanda row, not a sixteenth candidate/fix row.

## Exact commands and sources

The principal read-only commands were:

```zsh
git rev-parse --abbrev-ref HEAD
git rev-parse HEAD
git status --short

sha256sum docs/RESEARCH-NEW-200-CANDIDATE-CLOSURE-2026-08-12.md \
  docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/{ledger.jsonl,summary.json}

rg -ni 'cert-manager|flannel|opencloud|reva|msgpack|lz4_flex|libssh|weknora|terraform-provider-proxmox|ktransformers|boxlite' \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl docs/*.md

jq -c --arg f "$fix" \
  'select(.fix_sha==$f)|{candidate_sha,authored_date,files_changed,relation,route,tier,tools}' \
  "autoresearch/orchestrator-260811-atomic150/global-batch-v15-inputs/$component/expanded-candidates.jsonl"

git -C "$repo" show -s --format='%H|%P|%aI|%an <%ae>|%s%n%b' "$candidate"
git -C "$repo" show --format= --name-only "$candidate"
git -C "$repo" diff --unified=4 "$fix^" "$fix" -- "$affected_path"
git -C "$repo" merge-base --is-ancestor "$candidate" "$fix"
git -C "$repo" grep -n -F "$vulnerable_expression" "$candidate^" -- "$affected_path"
git -C "$repo" merge-base --is-ancestor "$fix" "$release_tag"
```

The exact candidate / atomic-fix / release-tag triples supplied to those commands were:

```text
cert-manager 4656dc79d5bddc9ddb724385833caec189b20a50 8b62c22e368794f847b27d739a1b6af0805c7dee v1.19.3
flannel 65b1ad7b885271c6fe0d5bc753d96747e5ac500c 08bc9a4c990ae785d2fcb448f4991b58485cd26a v0.28.2
reva 52d5ce693cb6343f7f1baba7335d5ee22d242e71 6b24ff65e8e099949ece16224360d366f610e81b v2.42.3
msgpack-java 799e2d188b13b07704d1708d4e10283fe6dfdc8f daa2ea6b2f11f500e22c70a22f689f7a9debdeae v0.9.11
lz4-flex 2991a09be12bad4574205daa3b2b09b2fc27f17f 055502ee5d297ecd6bf448ac91c055c7f6df9b6d 0.11.6/0.12.1 equivalent release patches
libssh a9c8f942a539953c128781254773bc6c241e2b35 855a0853ad3abd4a6cd85ce06fce6d8d4c7a0b60 libssh-0.12.0
weknora 451f543e6d8b73d63e53087d0fd1e4278050254d 57d6fea8bc265ad28b385e0158957c870cff4b50 v0.2.10
terraform-provider-proxmox 05a59aa507c5c3f1b91adb2c3240a5790313f730 bd604c41a31e2a55dd6acc01b0608be3ea49c023 v0.93.1
ktransformers fcf8882075d9d6602eb508375ee5103614dcc3e4 def0f9313d6e063b5c5ccdfa1f6707f7a40dfdca v0.6.4
boxlite aed55982d56d3df85ce014b078e5bf5f6b834821 28159fc5b6b6fd5037e18a58fc4644c882e3c581 v0.9.7
```

First-party repository advisory endpoints were queried without credentials:

```zsh
curl -fsSL -H 'Accept: application/vnd.github+json' \
  'https://api.github.com/repos/OWNER/REPO/security-advisories/GHSA-ID'
curl -fsSL 'https://www.libssh.org/security/advisories/libssh-2026-sftp-extensions.txt'
curl -fsSL 'https://cveawg.mitre.org/api/cve/CVE-2026-63767'
curl -fsSL 'https://cveawg.mitre.org/api/cve/CVE-2026-3731'
curl -fsSL 'https://pypi.org/pypi/ktransformers/json'
curl -fsSL 'https://pypi.org/pypi/boxlite/json'
git ls-remote --tags https://github.com/PSeitz/lz4_flex.git \
  refs/tags/0.11.6 refs/tags/0.12.1
curl -fsSL 'https://raw.githubusercontent.com/PSeitz/lz4_flex/0.11.6/src/block/decompress.rs'
curl -fsSL 'https://raw.githubusercontent.com/PSeitz/lz4_flex/0.12.1/src/block/decompress.rs'
```

## Claim boundary

This report establishes only that these 15 public security-fix rows have real AI-marked ancestors and released containment, while the exact selected ancestors fail causal adjudication. It does **not** establish an AI-caused vulnerability, does not add any component or public ID to the strict ledger, does not infer prevalence, and does not treat routing, source recovery, model screens, tests, ancestry, same-file proximity, or a green release as causal proof.
