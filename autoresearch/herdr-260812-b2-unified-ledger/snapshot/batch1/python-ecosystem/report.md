# Novel Python-ecosystem AI-origin security-fix adjudication

## Outcome

**Status: PARTIAL.** This bounded shard adjudicated five novel, non-overlapping Python LLM/agent/tooling components: **0 PASS, 4 FAIL, 1 UNKNOWN**. No row is suitable for addition to a positive AI-origin security ledger. The four FAIL rows are retained negative controls; KTransformers remains UNKNOWN rather than being promoted from routing evidence.

The research result is bounded by two operational issues: precise unauthenticated GitHub REST refreshes eventually returned HTTP 403, and a read-only `git log` against the shared DeepTutor cache printed Git's background auto-packing notice. No running `git gc` or `gc.log` was found afterward, but whether pack metadata changed is UNKNOWN. All deliberate writes are under this owned directory.

## Scope and snapshot boundary

- Started: `2026-08-12T12:17:47-04:00`; evidence cut: `2026-08-12T12:37:23-04:00`.
- Checkout: `/home/hanqing/agents/ai-slop`, branch `dev`, `HEAD 6c0d2084fd1240341d6d1b9f9096252490168f0b`.
- The checkout was intentionally dirty and shared. Existing changes were preserved; nothing was staged, committed, reset, cleaned, formatted, or pushed.
- The current strict ledger contains 200 public IDs in 110 semantic components. All 110 components were excluded, as were OpenClaw, Coolify, active PraisonAI work, and active compliance-trestle work.
- The frozen population was screened first. Exact first-party advisory/commit endpoints were queried only for selected candidates; no broad search loop, build, test run, or 51,218-unit rerun was performed.
- Immutable commit IDs, not moving repository heads, are the lineage boundary. Frozen routing packets and same-file screens are diagnostic evidence only.

The parent pass initially selected older candidate documents and redundantly inspected DeepTutor, local-deep-research, ADK-Python, UpSonic, and DeepAudit. Reconciliation against the newest relevant documents showed all five were already adjudicated, so they are explicitly excluded and contribute no row or count here. The four-row worker pass did read the newest closure state before its candidate work.

## Hashed inputs

| Input | SHA-256 |
|---|---|
| `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl` | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| `autoresearch/orchestrator-260811-atomic150/strict-200-v3/summary.json` | `69dd6c35de1455bf9cee88420aed570c576a190a4d143202d01a26cc3d37b81e` |
| `autoresearch/orchestrator-260811-atomic150/uncovered-repository-ranking-v2/summary.json` | `a60e92772b7f00e13df3e7f961102743c26dde8113a41f40b5960458e288124b` |
| `autoresearch/orchestrator-260811-atomic150/uncovered-repository-ranking-v2/repositories.jsonl` | `0bab73ed6d7238daa5e9aa9e5c25b7e33a9168dcd363f7c0acbb3aa7502c4768` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `docs/RESEARCH-NEW-200-CANDIDATE-CLOSURE-2026-08-12.md` | `bc8cb68d10b8b79d5219518d139fc5d1e104080fbcdae6c8ba08d94acc1710ad` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md` | `f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad` |
| `docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md` | `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` |
| `research_findings.md` (four-row worker evidence) | `44cb35803310ce51f424407513cab91dba09e5cd811898214e19ffe33f86aab3` |
| KTransformers `global-batch-v15-inputs/ktransformers/fix-roots.jsonl` | `236413af3543c799f50832c03d9fb94e5244cda335232674fa90a66e1177f04f` |
| KTransformers `global-same-file-v15/ktransformers/summary.json` | `6dd7c17f78c52cacd5a56d732a257071b913689ba574d142b72e2e7889bcfc3f` |

Four-row candidate packet hashes:

| Component | `expanded-candidates.jsonl` | `ai-commits.jsonl` | `fix-roots.jsonl` |
|---|---|---|---|
| Open WebUI | `38f6421ca1eed491e1babbe0a9987ce50ba3e29aaa5de3b64de9fd582ede6944` | `94e1db0e4567597dc22e8ce8737eaf1388bb8778bb3715cd73522a89139a6407` | `0260113bdb4c269b36f8108964b4a6679eea5bcb4b28aef29c5090b0cad6da70` |
| Agno | `b39ee5c917f9635565d1afc6fb981f755f74a2a3087a8ed7641890b08c97956e` | `d73642fa208c5b436710c308ea6e8e6bb619ad135dbf83ce06cdac23297f313e` | `6e3caf8ad2390eea0670c4e0cb155acb642d8c973113dfaa66e558ba78322b1a` |
| ChatDev | `44f93a999b00e041fadadb1f5468d9e37c69976db6ff0f1bea7bf3b0e3801501` | `4009b03030811f520b07bf43f38e39ac3b17fd248c50f7ae1be3fc575adf0f54` | `5242949dcf705ef63e80a39a2328494382c16b852e9c99806655b2a92089dd1a` |
| F5-TTS | `3a6d0a3608015d4de4ca7413cafd5a0626e0f7e2e94b491cd18b4103f28b940e` | `e2b19e590000c735ce0395fee05abfcfa7e2e2f8b04741343622570cd23c7744` | `2e34516fc9305c384d3d11050439b9c45f6e421addc9d8f1632b83faa0307e5d` |

The frozen CVEList checkout was `8ca64b5ad6b84d3cd5741b023610b8494800f174`; advisory-database was `39d8887723797efc1804585dd06585c9fd751226`. Exact CVE JSON hashes are preserved in `research_findings.md`.

## Exclusion reconciliation

The following already-completed rows were discovered during the newest-doc reconciliation and excluded:

| Excluded component | Existing adjudication |
|---|---|
| HKUDS/DeepTutor, CVE-2026-58168 | `docs/RESEARCH-NEW-CANDIDATES-V12-2026-08-11.md:48` |
| LearningCircuit/local-deep-research, CVE-2025-67743 | same document, line 51 |
| lintsinghua/DeepAudit, CVE-2026-2532 | `docs/RESEARCH-NEW-CANDIDATES-V14-2026-08-11.md:37` |
| google/adk-python, CVE-2026-18236 | `docs/RESEARCH-NEW-200-CANDIDATE-CLOSURE-2026-08-12.md:47,76` |
| upsonic/upsonic, CVE-2026-30625 | same document, lines 50 and 79 |

Exact novelty checks for the five retained components returned no match in the strict ledger or `docs/RESEARCH-*.md` at the snapshot boundary:

```sh
rg -n -i 'CVE-2025-64496|GHSA-cm35-v4vp-5xvx|CVE-2026-35002|GHSA-77rh-m34w-rv36|CVE-2026-58166|CVE-2026-43624|open-webui/open-webui|agno-agi/agno|openbmb/chatdev|swivid/f5-tts' \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl docs/RESEARCH-*.md
rg -n -i 'CVE-2026-63767|GHSA-6vqg-j4cx-cqv4|kvcache-ai/ktransformers' \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl docs/RESEARCH-*.md
```

## Row-level evidence

| # | Component / advisory | AI evidence | Exact security lineage | Released containment | Decision |
|---:|---|---|---|---|---|
| 1 | Open WebUI, CVE-2025-64496 / GHSA-cm35-v4vp-5xvx | Jules `4a7e1b93` | human-attributed origin `f10566f3` -> fix `8af6a4cf` | `v0.6.35` | **FAIL: wrong edge** |
| 2 | Agno, CVE-2026-35002 / GHSA-77rh-m34w-rv36 | Copilot `b0575cbc` | human-attributed eval origin `f8bcda74` -> fix `cbf67552` | `v2.3.24` | **FAIL: wrong edge** |
| 3 | ChatDev, CVE-2026-58166 | Claude-assisted fix member `0014dbba` | human-attributed origin `f0db945e` -> member `0014dbba` -> merge `4fd4da60` | **BLOCKED:** no containing tag | **FAIL: remediation is not origin** |
| 4 | F5-TTS, CVE-2026-43624 | Claude `6768b1bc` | human-attributed path origin `8ed1beac` -> member `25dc4e86` -> merge `2f53ded6` | `1.1.21` | **FAIL: wrong edge** |
| 5 | KTransformers, CVE-2026-63767 / GHSA-6vqg-j4cx-cqv4 | 28 atomic AI units; example Claude `020eb929` | routed ancestors -> fixes `ce7c3ddb` / exact public fix `def0f931`; origin not recovered | **UNKNOWN** | **UNKNOWN: routing only** |

### 1. Open WebUI — FAIL

The [first-party advisory](https://github.com/open-webui/open-webui/security/advisories/GHSA-cm35-v4vp-5xvx) identifies malicious Direct Connections SSE `execute` events reaching browser JavaScript. Fix [`8af6a4cf`](https://github.com/open-webui/open-webui/commit/8af6a4cf21b756a66cd58378a01c60f74c39b7ca) suppresses event forwarding for direct requests and is contained in [`v0.6.35`](https://github.com/open-webui/open-webui/releases/tag/v0.6.35).

Jules-authored [`4a7e1b93`](https://github.com/open-webui/open-webui/commit/4a7e1b93e5f9b2a0474706721e8a57f2b2ee16f5) is genuine autonomous-agent evidence, but it optimizes RAG query generation. Blame and reverse pickaxe locate the vulnerable event-forwarding expression in human-attributed [`f10566f3`](https://github.com/open-webui/open-webui/commit/f10566f3de52cf85a1cadac390ae841e4bf27cd6). Same repository/file ancestry is not the same security mechanism. The CVE prose/version range is internally inconsistent; exact tag containment of the fix is retained separately.

### 2. Agno — FAIL

The [first-party advisory](https://github.com/agno-agi/agno/security/advisories/GHSA-77rh-m34w-rv36) covers attacker-controlled `field_type` reaching `eval`. Fix [`cbf67552`](https://github.com/agno-agi/agno/commit/cbf675521d4d2281925a051784a3b94172e56416) replaces the evals with allowlisted mappings and is in [`v2.3.24`](https://github.com/agno-agi/agno/releases/tag/v2.3.24).

[`b0575cbc`](https://github.com/agno-agi/agno/commit/b0575cbc9c8afa524ddbf5de243ed1f93feb15e0) has an explicit Copilot co-author trailer but adds A2A functionality and does not modify the vulnerable/fixed files. `git log -S 'eval(field_type)'` and blame identify human-attributed [`f8bcda74`](https://github.com/agno-agi/agno/commit/f8bcda74cf0b038aa5665ba52633c55cb51f3699) for the model-side expression. No positive AI signal was recovered on the relevant introducing objects.

### 3. OpenBMB ChatDev — FAIL, containment BLOCKED

The CVE points to first-party [issue 638](https://github.com/OpenBMB/ChatDev/issues/638), [PR 641](https://github.com/OpenBMB/ChatDev/pull/641), and merge carrier [`4fd4da60`](https://github.com/OpenBMB/ChatDev/commit/4fd4da603801766b14ad8788649cfc1ad21f99a6). Atomic fix member [`0014dbba`](https://github.com/OpenBMB/ChatDev/commit/0014dbba7c6c3278091285bd7ea0e96154ad3a15) normalizes multipart filenames, adds regression tests, and has a Claude Opus 4.8 co-author trailer. This is real AI-assisted security remediation.

Blame locates the raw `upload.filename` path construction in human-attributed [`f0db945e`](https://github.com/OpenBMB/ChatDev/commit/f0db945ed39be33599fbc700a7e60cdb68d1df2d). AI assistance on the later repair cannot establish AI origin of the earlier vulnerability. `git tag --contains` was empty for both member and merge in the frozen complete clone; the CVE says fixed in commit but no released fixed tag was recovered. A first-party GHSA identity is also UNKNOWN.

### 4. SWivid F5-TTS — FAIL

First-party [issue 1293](https://github.com/SWivid/F5-TTS/issues/1293), [PR 1294](https://github.com/SWivid/F5-TTS/pull/1294), merge [`2f53ded6`](https://github.com/SWivid/F5-TTS/commit/2f53ded68e5f69e248ceb200a51ef4d1dc647936), and atomic member [`25dc4e86`](https://github.com/SWivid/F5-TTS/commit/25dc4e86686c6625b76ee01f805448615f2c3813) close the project-name path traversal. The member is contained in released [`1.1.21`](https://github.com/SWivid/F5-TTS/releases/tag/1.1.21).

Claude-assisted [`6768b1bc`](https://github.com/SWivid/F5-TTS/commit/6768b1bcffd758a655aa8b4ce0612263a4d256ca) only configures W&B values and does not touch `finetune_gradio.py`. Reverse history traces relevant path construction to human-attributed history including [`8ed1beac`](https://github.com/SWivid/F5-TTS/commit/8ed1beac1e4da3fb51ac8905b0d0b3d7cfb0c875). The frozen CVE exposes no first-party GHSA, so advisory identity remains UNKNOWN even though first-party fix/release lineage is verified.

### 5. KTransformers — UNKNOWN

Frozen first-party identity [GHSA-6vqg-j4cx-cqv4](https://github.com/kvcache-ai/ktransformers/security/advisories/GHSA-6vqg-j4cx-cqv4), [issue 2087](https://github.com/kvcache-ai/ktransformers/issues/2087), [PR 2091](https://github.com/kvcache-ai/ktransformers/pull/2091), and exact public fix [`def0f931`](https://github.com/kvcache-ai/ktransformers/commit/def0f9313d6e063b5c5ccdfa1f6707f7a40dfdca) route an unauthenticated pickle-deserialization RCE over ZMQ. The frozen resolver also records `ce7c3ddbe93f7ac1f992375eed54058bbc512646` as a converted version boundary.

There are 28 atomic commits with explicit AI signals. For example, [`020eb929`](https://github.com/kvcache-ai/ktransformers/commit/020eb929f734229b04d91fe42ccf17ad36579d5e) has a Claude Opus 4.6 co-author trailer and changes SFT configuration/autograd files. But the frozen same-file screen reports **0 same-file AI units, 0 candidates, and 0 fix overlap** across the advisory fix inventory. That absence is useful triage, not proof of human origin. No exact vulnerable-code introducing commit or released containing version was recovered in the bounded pass, so the row stays UNKNOWN rather than FAIL or PASS.

## Exact commands and sources

Local population and provenance checks:

```sh
git rev-parse --abbrev-ref HEAD
git rev-parse HEAD
git status --short
sha256sum <each input listed above>
jq . autoresearch/orchestrator-260811-atomic150/strict-200-v3/summary.json
jq . autoresearch/orchestrator-260811-atomic150/uncovered-repository-ranking-v2/summary.json
jq . autoresearch/orchestrator-260811-atomic150/global-same-file-v15/ktransformers/summary.json
rg -n -i '<exact CVE|GHSA|normalized repository>' \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl docs/RESEARCH-*.md
```

Exact commit lineage checks used for the four deep rows:

```sh
git -C <frozen-repo> show -s --format=fuller <candidate-or-fix>
git -C <frozen-repo> diff --unified=12 <sha>^ <sha> -- <mechanism-files>
git -C <frozen-repo> blame <fix>^ -- <mechanism-file> -L <sink-range>
git -C <frozen-repo> log --all --reverse -S '<vulnerable-expression>' -- <mechanism-file>
git -C <frozen-repo> tag --contains <candidate-or-fix> | sort -V | head -1
```

Concrete reverse-search anchors were `if "event" in data`, `eval(field_type)`, the `upload.filename` path lines in ChatDev, and `def create_data_project` in F5-TTS. Parents were inspected with `%H|%P|%aI|%an|%s` to separate merge carriers from atomic members.

Precise live requests were attempted for the selected advisory/commit endpoints, including:

```text
https://api.github.com/repos/open-webui/open-webui/security-advisories/GHSA-cm35-v4vp-5xvx
https://api.github.com/repos/agno-agi/agno/security-advisories/GHSA-77rh-m34w-rv36
https://api.github.com/repos/kvcache-ai/ktransformers/security-advisories/GHSA-6vqg-j4cx-cqv4
https://api.github.com/repos/OpenBMB/ChatDev/commits/0014dbba7c6c3278091285bd7ea0e96154ad3a15
https://api.github.com/repos/SWivid/F5-TTS/commits/2f53ded68e5f69e248ceb200a51ef4d1dc647936
```

The final requests returned HTTP 403 under the shared anonymous rate limit. No credential was read, printed, or stored, and no retry loop followed. Earlier successful exact API responses and the hashed frozen first-party snapshots were retained; unavailable live refresh fields remain BLOCKED or UNKNOWN.

## Negative and unknown controls

- Open WebUI, Agno, and F5-TTS prove that a real AI-marked ancestor in an AI product is insufficient when its delta does not create the vulnerable mechanism.
- ChatDev proves that an AI-assisted security fix is not evidence that AI introduced the vulnerability.
- KTransformers preserves the distinction between an absence of same-file routing and a proven non-AI origin.
- F5-TTS keeps first-party advisory identity UNKNOWN despite verified first-party issue/PR/fix/release lineage.
- ChatDev keeps released containment BLOCKED despite an exact fixed commit.
- Generic product branding, model scores, ancestry alone, and incomplete hardening were not counted.

## Operational incidents and blockers

1. **GitHub REST BLOCKED:** the shared anonymous rate limit returned HTTP 403. No credentials or retries were used.
2. **Shared-cache mutation UNKNOWN:** a `git log` against the shared cached DeepTutor clone was run without `-c gc.auto=0 -c maintenance.auto=false` and printed `Auto packing the repository in background` three times. A bounded follow-up found no running Git GC and no `gc.log`, but pack metadata mutation cannot be excluded. Shared clones were not used afterward; any subsequent clone was placed in this owned directory.
3. **Newest-doc ordering defect:** the parent diagnosis initially missed newer adjudication docs and repeated read-only work on five completed rows. The final dataset reconciles and excludes them, but the wasted diagnosis is disclosed.
4. **Evidence gaps:** ChatDev has no recovered fixed release tag; F5-TTS has no recovered first-party GHSA identity; KTransformers lacks exact introduction and released containment.

## Claim boundary

A publication-grade PASS requires an exact AI-authored or AI-assisted candidate that introduces the vulnerable mechanism, atomic candidate/fix lineage on that same mechanism, a first-party advisory identity, an exact security fix, and a released version/tag containing the fix. Routing, chronology, same-file overlap, tests, source recovery, and candidate discovery remain diagnostic until all of those links close. Under that boundary this shard has **zero positive findings**.
