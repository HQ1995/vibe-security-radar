# Python ecosystem candidate adjudication (shard)

## Outcome and claim boundary

Snapshot time: **2026-08-12T12:30:26-04:00**. Checkout `HEAD` was `6c0d2084fd1240341d6d1b9f9096252490168f0b`; the worktree was intentionally dirty and was treated as read-only except for this file.

I screened the frozen local candidate population first, excluded every component already present in the current strict ledger, and then inspected exact commit objects, ancestry, blame, tags, CVE records, and the available first-party advisory identities. Result: **4 novel component rows adjudicated: 0 PASS, 4 FAIL**. Two of the FAIL rows have complete advisory/fix/release lineage; one has complete public fix and release lineage but no recovered first-party advisory identity; one has an AI-assisted security remediation but neither AI-origin evidence nor released containment. These are negative controls, not AI-origin findings.

The required claim is narrower than “an AI-related product has an AI-marked commit somewhere in its history.” A PASS would require all of: exact candidate-to-vulnerable-code lineage, positive AI authorship/assistance evidence on the introducing change, the same security mechanism, a first-party advisory identity, an exact fix, and a released version/tag containing the fix. Chronological ancestry, same-file proximity, generic AI product branding, a model score, or AI-assisted remediation does not establish AI origin.

## Frozen inputs and exclusions

Newest adjudication state read before candidate work:

| Input | SHA-256 |
|---|---|
| `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl` | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `docs/RESEARCH-NEW-200-CANDIDATE-CLOSURE-2026-08-12.md` | `bc8cb68d10b8b79d5219518d139fc5d1e104080fbcdae6c8ba08d94acc1710ad` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md` | `f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad` |
| `docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md` | `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` |

The newest candidate closure already adjudicates Google ADK-Python and UpSonic as wrong-edge failures, so I did not redo them. OpenClaw, Coolify, PraisonAI, and compliance-trestle were explicit exclusions and were not searched as candidates. Exact normalized repository names and the CVE/GHSA identifiers below produced no match in the frozen ledger or `docs/RESEARCH-*.md`. Command (empty output):

```sh
rg -n -i 'CVE-2025-64496|GHSA-cm35-v4vp-5xvx|CVE-2026-35002|GHSA-77rh-m34w-rv36|CVE-2026-58166|CVE-2026-43624|open-webui/open-webui|agno-agi/agno|openbmb/chatdev|swivid/f5-tts' \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
  docs/RESEARCH-*.md
```

Candidate packet hashes:

| Component / packet | `expanded-candidates.jsonl` | `ai-commits.jsonl` | `fix-roots.jsonl` |
|---|---|---|---|
| Open WebUI, `global-batch-v2-inputs/open-webui/` | `38f6421ca1eed491e1babbe0a9987ce50ba3e29aaa5de3b64de9fd582ede6944` | `94e1db0e4567597dc22e8ce8737eaf1388bb8778bb3715cd73522a89139a6407` | `0260113bdb4c269b36f8108964b4a6679eea5bcb4b28aef29c5090b0cad6da70` |
| Agno, `global-batch-v15-inputs/agno/` | `b39ee5c917f9635565d1afc6fb981f755f74a2a3087a8ed7641890b08c97956e` | `d73642fa208c5b436710c308ea6e8e6bb619ad135dbf83ce06cdac23297f313e` | `6e3caf8ad2390eea0670c4e0cb155acb642d8c973113dfaa66e558ba78322b1a` |
| ChatDev, `global-batch-v15-inputs/chatdev/` | `44f93a999b00e041fadadb1f5468d9e37c69976db6ff0f1bea7bf3b0e3801501` | `4009b03030811f520b07bf43f38e39ac3b17fd248c50f7ae1be3fc575adf0f54` | `5242949dcf705ef63e80a39a2328494382c16b852e9c99806655b2a92089dd1a` |
| F5-TTS, `global-batch-v15-inputs/f5-tts/` | `3a6d0a3608015d4de4ca7413cafd5a0626e0f7e2e94b491cd18b4103f28b940e` | `e2b19e590000c735ce0395fee05abfcfa7e2e2f8b04741343622570cd23c7744` | `2e34516fc9305c384d3d11050439b9c45f6e421addc9d8f1632b83faa0307e5d` |

The frozen CVEList checkout was `8ca64b5ad6b84d3cd5741b023610b8494800f174`; advisory-database checkout was `39d8887723797efc1804585dd06585c9fd751226`. Exact CVE JSON SHA-256 values were: CVE-2025-64496 `56f027f563d89f39ac5315491694e9d9d8a1f77cd6816e7be20c93f0b5865f02`; CVE-2026-35002 `5b31bdc1a7a3e89183c73272808532cda7e1b324098bd6b97121ffeda9ee0d08`; CVE-2026-43624 `1940c655270a42435ebec9929612e06fbfeedd90014a455d00f3ddc7c49be3f9`; CVE-2026-58166 `359be04737dcf715e21bce5b359be0d632b203ac8ebbe9c727282a725bc987d5`.

Read-only repository `HEAD` snapshots were Open WebUI `1ac3dd4a893e13803e7b889611303c4a7a5cc470`, Agno `2ac030904f67155ed994310dae9b117afd8acb38`, ChatDev `4fb2db0ea90375ce1059f44fe03ffbd191a7a169`, and F5-TTS `9c614e9657089213efc6a7421b30630be138a3f5`. All findings below name immutable commit objects rather than relying on those moving refs.

## Row-level adjudication

### 1. Open WebUI — CVE-2025-64496 / GHSA-cm35-v4vp-5xvx — **FAIL: wrong edge**

- **Public mechanism and fix.** The [first-party advisory](https://github.com/open-webui/open-webui/security/advisories/GHSA-cm35-v4vp-5xvx) identifies Direct Connections accepting a malicious model server's SSE `execute` event, enabling browser JavaScript execution. Exact cited fix [`8af6a4cf`](https://github.com/open-webui/open-webui/commit/8af6a4cf21b756a66cd58378a01c60f74c39b7ca) changes `if "event" in data:` to `if "event" in data and not getattr(request.state, "direct", False):` in `backend/open_webui/utils/middleware.py`. It is first contained in [`v0.6.35`](https://github.com/open-webui/open-webui/releases/tag/v0.6.35).
- **Real AI evidence, but on another mechanism.** Routed ancestor [`4a7e1b93`](https://github.com/open-webui/open-webui/commit/4a7e1b93e5f9b2a0474706721e8a57f2b2ee16f5) is authored by the `google-labs-jules[bot]` identity and is therefore strong autonomous-agent evidence. Its change skips RAG query generation when every attachment is already full-context. It happens to touch the same large middleware file, but it neither introduces nor changes Direct Connections SSE event dispatch. It first appears in `v0.6.31`.
- **Origin check.** `git blame 8af6a4cf^ -- backend/open_webui/utils/middleware.py -L 2338,2360` plus `git log --all --reverse -S 'if "event" in data'` points the vulnerable event forwarding to [`f10566f3`](https://github.com/open-webui/open-webui/commit/f10566f3de52cf85a1cadac390ae841e4bf27cd6), “feat: allow events from pipelines,” authored by Timothy Jaeryang Baek on 2025-04-10. No AI marker was recovered for that introducing object. This does not prove a human wrote every token; it means positive AI-origin evidence is absent.
- **Containment caveat retained.** The CVE prose says “0.6.224 and prior” while its structured affected range and fix statement say `<0.6.35`; this internal source inconsistency is not silently normalized. Independent tag containment does establish that the exact fix is in `v0.6.35`.
- **Decision.** Same repository and same file are routing evidence only. The candidate's RAG optimization and the SSE code-injection mechanism do not match. Do not count.

### 2. Agno — CVE-2026-35002 / GHSA-77rh-m34w-rv36 — **FAIL: wrong edge / pre-existing origin unsupported**

- **Public mechanism and fix.** The [first-party advisory](https://github.com/agno-agi/agno/security/advisories/GHSA-77rh-m34w-rv36) concerns attacker-controlled `field_type` reaching Python `eval`. Exact fix [`cbf67552`](https://github.com/agno-agi/agno/commit/cbf675521d4d2281925a051784a3b94172e56416), “fix: replace eval() with type mapping,” replaces three `eval` calls with allowlisted mappings in `libs/agno/agno/models/base.py` and `libs/agno/agno/tools/function.py`. The commit is first contained in released [`v2.3.24`](https://github.com/agno-agi/agno/releases/tag/v2.3.24).
- **Real AI evidence, unrelated files.** Routed ancestor [`b0575cbc`](https://github.com/agno-agi/agno/commit/b0575cbc9c8afa524ddbf5de243ed1f93feb15e0) carries an explicit `Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>` trailer. It adds an A2A client, remote entities, examples, and tests across 72 files; neither vulnerable/fixed file is in its changed-file set. It first appears in `v2.3.22`.
- **Origin check.** Blame and `git log -S 'eval(field_type)'` point the model-side vulnerable expression to [`f8bcda74`](https://github.com/agno-agi/agno/commit/f8bcda74cf0b038aa5665ba52633c55cb51f3699), “feat: Implement agentic user requirements flow (#3322),” authored by Dirk Brand on 2025-05-23. Its metadata has no recovered AI signal. A separate human-attributed history object introduced the deserialization-side `eval`; neither is the Copilot A2A commit.
- **Decision.** Exact advisory, fix, and release containment close cleanly, but the only positive AI evidence is on a different A2A mechanism. Do not count.

### 3. OpenBMB ChatDev — CVE-2026-58166 — **FAIL: AI remediation is not AI origin; released containment BLOCKED**

- **Public mechanism.** The CVE record points to first-party [issue #638](https://github.com/OpenBMB/ChatDev/issues/638), [PR #641](https://github.com/OpenBMB/ChatDev/pull/641), and merge carrier [`4fd4da60`](https://github.com/OpenBMB/ChatDev/commit/4fd4da603801766b14ad8788649cfc1ad21f99a6). Unsanitized multipart `upload.filename` was joined to a temp directory, enabling arbitrary write and cleanup-time delete.
- **Real AI-assisted security remediation.** The merge's second parent, atomic member [`0014dbba`](https://github.com/OpenBMB/ChatDev/commit/0014dbba7c6c3278091285bd7ea0e96154ad3a15), adds basename normalization and regression tests and carries `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. The two-parent carrier's other parent is `a6a5cda5`; publishing the member separately preserves exact AI evidence and topology.
- **Origin check.** `git blame 0014dbba^ -- server/services/attachment_service.py` places the raw filename/path construction in [`f0db945e`](https://github.com/OpenBMB/ChatDev/commit/f0db945ed39be33599fbc700a7e60cdb68d1df2d), “initial commit of chatdev 2.0,” authored by NA-Wen. No positive AI marker was recovered for the vulnerable introduction. The Claude trailer proves assistance on remediation, not causation of the earlier bug.
- **Release/advisory gaps.** `git tag --contains` is empty for both `0014dbba` and `4fd4da60` in the frozen complete clone. The CVE says “through 2.2.0, fixed in commit,” but no released fixed tag was recovered. The CVE references also expose no first-party GHSA identity; absence from the frozen record is `UNKNOWN`, not proof no advisory exists.
- **Decision.** This is a useful positive control for detecting genuine AI assistance and a negative control for the origin claim. Do not count it as AI-origin or released containment.

### 4. SWivid F5-TTS — CVE-2026-43624 — **FAIL: wrong edge; advisory identity UNKNOWN**

- **Public mechanism/fix.** First-party [issue #1293](https://github.com/SWivid/F5-TTS/issues/1293) and [PR #1294](https://github.com/SWivid/F5-TTS/pull/1294) track path traversal from unsanitized project names in `finetune_gradio.py`. The CVE cites merge carrier [`2f53ded6`](https://github.com/SWivid/F5-TTS/commit/2f53ded68e5f69e248ceb200a51ef4d1dc647936); its atomic security member is [`25dc4e86`](https://github.com/SWivid/F5-TTS/commit/25dc4e86686c6625b76ee01f805448615f2c3813), which adds `_safe_project_path` and applies it to ten sinks. The member is first contained in released [`1.1.21`](https://github.com/SWivid/F5-TTS/releases/tag/1.1.21).
- **Real AI evidence, different mechanism.** Routed ancestor [`6768b1bc`](https://github.com/SWivid/F5-TTS/commit/6768b1bcffd758a655aa8b4ce0612263a4d256ca) carries `Co-Authored-By: Claude Opus 4.6 (1M context)` and only makes W&B project/run/resume values configurable in Hydra YAML and `train.py`. It does not touch `finetune_gradio.py`; it is first contained in `1.1.16`.
- **Origin check.** `git log -S 'def create_data_project'` and blame trace the vulnerable Gradio project-path construction to repository history including [`8ed1beac`](https://github.com/SWivid/F5-TTS/commit/8ed1beac1e4da3fb51ac8905b0d0b3d7cfb0c875), “make a structure first,” authored by SWivid on 2024-10-24. No positive AI evidence was recovered on the relevant introducing objects.
- **Advisory boundary.** The frozen CVE record points to issue/PR/commit and a third-party CNA page, but not a first-party GHSA. First-party public fix lineage and release containment are verified; first-party advisory identity remains `UNKNOWN`.
- **Decision.** The Claude-assisted W&B configuration change is unrelated to path construction. Do not count.

## Exact diagnostic commands and live-source blocker

The key repository checks were run against the read-only clone paths named in each packet:

```sh
git -C <repo> show -s --format=fuller <candidate-or-fix>
git -C <repo> diff --unified=12 <sha>^ <sha> -- <mechanism-files>
git -C <repo> blame <fix>^ -- <mechanism-file> -L <sink-range>
git -C <repo> log --all --reverse -S '<vulnerable-expression>' -- <mechanism-file>
git -C <repo> tag --contains <candidate-or-fix> | sort -V | head -1
```

Concrete search strings were `if "event" in data` (Open WebUI), `eval(field_type)` (Agno), the upload filename/path lines in `server/services/attachment_service.py` (ChatDev), and `def create_data_project` (F5-TTS). Commit parents were inspected with `%H|%P|%aI|%an|%s`, which is how the ChatDev and F5 merge carriers were separated from atomic members.

After local triage, precise unauthenticated requests were attempted to:

```text
https://api.github.com/repos/open-webui/open-webui/security-advisories/GHSA-cm35-v4vp-5xvx
https://api.github.com/repos/agno-agi/agno/security-advisories/GHSA-77rh-m34w-rv36
https://api.github.com/repos/OpenBMB/ChatDev/commits/0014dbba7c6c3278091285bd7ea0e96154ad3a15
https://api.github.com/repos/SWivid/F5-TTS/commits/2f53ded68e5f69e248ceb200a51ef4d1dc647936
```

Each returned HTTP 403 under the shared unauthenticated rate limit. No credential was read, printed, or stored, and no unbounded retry was made. Consequently, GitHub live metadata refresh is **BLOCKED**; conclusions rely on the hashed frozen CVE/candidate packets and immutable commit objects, with exact first-party URLs supplied for later refresh.

## Counts

| State | Rows | Components |
|---|---:|---|
| PASS / publishable AI-origin finding | 0 | — |
| FAIL — wrong mechanism/edge | 3 | Open WebUI, Agno, F5-TTS |
| FAIL — AI remediation, not AI origin | 1 | ChatDev |
| Released containment verified | 3 | Open WebUI, Agno, F5-TTS |
| Released containment blocked | 1 | ChatDev |

No row in this shard should be added to a positive AI-origin ledger.
