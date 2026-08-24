# Batch 2 positive red-team audit

Status: **PARTIAL** (the five-row audit is complete; an operational no-print boundary incident is recorded below)

Started: `2026-08-12T12:50:13-04:00`  
Owned output: `/home/hanqing/agents/ai-slop/autoresearch/herdr-260812-b2-positive-redteam/`

## Result first

Every Batch 1 proposed positive named in the task was replayed as a mechanism row against live first-party advisory, commit/PR, comparison, release, and npm objects.

| Disposition | Count |
|---|---:|
| `KEEP` | 4 |
| `NARROW` | 1 |
| `REJECT` | 0 |
| `UNKNOWN` | 0 |
| `BLOCKED` | 0 |
| Total mechanism rows | 5 |

The n8n-mcp rows survive: one narrowly scoped strict session/health contributor under GHSA-75HX-XJ24-MQRW, two strict/new-surface mechanisms under GHSA-8G7G-HMWM-6RV2, and one released AI incomplete-remediation mechanism under that same GHSA. AutoGPT CVE-2026-72922 remains positive only after narrowing: the AI-coauthored change created the optional secret-protection boundary and wired its verifier through the vulnerable route, but the parent already selected the webhook manager from the URL provider without checking the stored provider. It is therefore a **new protected-boundary/bypass contributor**, not the origin of provider-path selection.

The five mechanisms map to three first-party advisory identities. GHSA-8G7G's three mechanisms do not become three public-ID additions.

## Scope and gate

The selected population is exhaustive for the user-specified Batch 1 positives:

1. AutoGPT CVE-2026-72922 / GHSA-349P-3C3R-8MJR from `herdr-260812-fresh-advisories`.
2. GHSA-75HX-XJ24-MQRW session/health mechanism from `herdr-260812-mcp-js-ecosystem`.
3. GHSA-8G7G-HMWM-6RV2 caller-controlled API path segments.
4. GHSA-8G7G-HMWM-6RV2 redirect-following SSRF.
5. GHSA-8G7G-HMWM-6RV2 mutation-telemetry residual.

For each mechanism this audit checked: direct parent baseline; deletion/but-for behavior; direct AI attribution and hunk survival through any squash; the exact same-input/sink/invariant fix; first-party advisory identity/state; a vulnerable release containing the candidate state and a fixed release containing the repair; and dedup against prior components. An ancestry result, release record, source recovery, or test is supporting evidence, never causal proof by itself.

Verdict meanings:

- `KEEP`: the Batch 1 mechanism and causal scope survive.
- `NARROW`: the positive survives only with a more restricted causal role.
- `REJECT`: a required gate is falsified.
- `UNKNOWN`: evidence is insufficient in the bounded replay.

## Snapshot boundary and hashes

The shared checkout was intentionally dirty. Repository state at start was branch `dev`, commit `6c0d2084fd1240341d6d1b9f9096252490168f0b`, with 405 porcelain entries and status-stream SHA-256 `96f440a130e4983e79da19d7d15014920ca649544e5c3905c327073d8412df10`. All Git reads used `-c gc.auto=0 -c maintenance.auto=false`. No shared cache, ref, index, or worktree path was intentionally changed.

Local inputs were frozen by content hash when read:

| Input | mtime at observation | SHA-256 |
|---|---|---|
| `autoresearch/herdr-260812-fresh-advisories/report.md` | 2026-08-12 12:38:51 -0400 | `29c91e17cb33aed6335e6a8dda4698981da76b8b4a7e1731811e7d22c32bc713` |
| `autoresearch/herdr-260812-fresh-advisories/source-notes.md` | 2026-08-12 12:36:16 -0400 | `3550ba4a65e275a447bd8edd2c9333dd0a43845561c3b974df527d3071eb6b19` |
| `autoresearch/herdr-260812-fresh-advisories/cve-api/CVE-2026-72922.json` | 2026-08-12 12:32:29 -0400 | `eeb187b4cfce561e1d32e8c295e5646fd897a8b78be69b5b5a86adc31b96a99c` |
| `autoresearch/herdr-260812-mcp-js-ecosystem/report.md` | 2026-08-12 12:43:15 -0400 | `47be67ee784f15b334378348e2c3ad62bbfd35d4810e7aa57c261602592fbe52` |
| `autoresearch/herdr-260812-mcp-js-ecosystem/result.json` | 2026-08-12 12:43:15 -0400 | `f9ef2c57b3125009603b46ad76d99cc56c27d208bedd1549a1475d3119a90bfa` |
| `autoresearch/herdr-260812-mcp-js-ecosystem/background_findings.md` | 2026-08-12 12:31:00 -0400 | `60fd0782205ba6bfaba0b4f216f00780ebc5b745472ef3bb827dcf9dce02c65a` |
| Independent Batch 2 primary-source replay, `research-notes.md` | completed 2026-08-12 13:01 -0400 | `bae266d39b6be77807ec299c593a2d49e24655ac69df622debb77ae5d01cbaa5` |

Dedup baselines rehashed in this shard:

| Baseline | SHA-256 |
|---|---|
| `docs/AUDIT-CONSOLIDATED-LEDGER-156-2026-08-11.md` | `2fb6210a10802c1d9570caeb88dc8af08b1f26721c860deda005df980bf3f687` |
| `docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md` | `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md` | `a7dd3db373af0fae98c10f8c96c58180cf80fc132fb6fb53fedbd44f3aae22c2` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md` | `318912fbc789ef7f0708044d2041c24fa69198f878c2c668b04af86031d4616e` |
| `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl` | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |

Live advisory state was observed at `2026-08-12T12:55:04-04:00`. The SHA-256 values below are over `jq -S -c` canonical JSON returned by the first-party endpoint:

| Live object | Canonical SHA-256 |
|---|---|
| AutoGPT repository advisory GHSA-349P-3C3R-8MJR | `d85576e71ea4c96b4165f143ebfa0a932cdbdac0ed6c270d178a9e8300ec1296` |
| n8n-mcp repository advisory GHSA-75HX-XJ24-MQRW | `5d96cfd2408cb411e38857c374649fcb81c713f7fe689c139c281d8eb126644d` |
| n8n-mcp repository advisory GHSA-8G7G-HMWM-6RV2 | `c6283dc772b227fa2fe81c45c84b4c88786e937f3ff1701c80245b5aad52d5a8` |
| CVE Services CVE-2026-72922 | `0922d1cae0512e8bb9e1f5bc0fc715f64e7d8dbc284a6d1bc3c04d514038f84c` |

The local CVE object's canonical hash is also `0922d1ca...`, so the re-fetch matched the frozen record semantically. Commit SHAs, PR member lists, tag refs, npm `gitHead` values, and package tarball `shasum` values below are their immutable/content-addressed snapshot identities. Changes to mutable advisory or registry metadata after the observation are outside this report.

## Gate matrix

| Row | Mechanism | Parent / but-for | AI hunk survival | Same-mechanism fix | Identity + release | Dedup | Verdict |
|---:|---|---|---|---|---|---|---|
| B2-01 | AutoGPT configured generic-webhook secret bypass by provider path | Parent already has URL-selected manager; candidate adds the protected boundary and verifier call | Direct marker on member and carrier; PR-head/carrier blobs match | Provider equality check before verification | Published CVE/GHSA; vulnerable 0.6.65, fixed 0.6.70 | Distinct from prior AutoGPT logging component | `NARROW` |
| B2-02 | n8n-mcp unauthenticated GET/DELETE session control + higher-sensitivity health fields | Candidate creates the live GET/DELETE/session-ID edges; deleting it removes them | Direct marker on mainline candidate; survives to npm 2.47.5 | Auth on GET/DELETE; minimal health body | GHSA-only, published; fixed npm 2.47.6 | One component, not each endpoint | `KEEP` |
| B2-03 | n8n API caller IDs used as credential-carrying URL path segments | Candidate adds the client and raw interpolations; parent lacks this integration | Direct marker; ancestor of vulnerable npm releases | Bounded segment validator at each affected path | GHSA-only, published; fixed npm 2.50.1 | Distinct input/sink from existing n8n SSRF row | `KEEP` |
| B2-04 | Initial URL validation followed by redirecting Axios request | Candidate adds form/chat sinks; webhook sibling gets the same incomplete guard | Direct member markers; exact PR-head/carrier blobs; npm 2.28.0 equals carrier | `maxRedirects: 0` at all three sinks | Same GHSA; vulnerable through 2.50.0, fixed 2.50.1 | Form/chat count once; webhook sibling is not another component | `KEEP` |
| B2-05 | Mutation telemetry sanitizes workflow copies but leaves operation/validation/error fields raw | Human root creates raw telemetry; deleting AI hunk restores fully raw state | Direct AI remediation member; exact PR-head/carrier blob; npm 2.22.16 equals carrier | Sanitizes every residual field before record storage | Same GHSA; partial state through 2.50.0, fixed 2.50.1 | Separate telemetry-storage invariant; one incomplete-remediation row | `KEEP` |

## Row-level evidence

### B2-01 — AutoGPT CVE-2026-72922 / GHSA-349P-3C3R-8MJR

**Verdict: `NARROW` to an AI-coauthored new protected-boundary/bypass contributor. Do not call it the origin of provider-path selection.**

The live [repository advisory](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-349p-3c3r-8mjr) is published, non-withdrawn, and aliases CVE-2026-72922. The re-fetched [CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-72922) names the same path-confusion mechanism and `<0.6.70` / fixed `0.6.70` boundary.

- Parent `e877391a55f0f834c43ab00eb3a59f60c852f428` already executes `webhook_manager = get_webhook_manager(provider)` before loading the stored webhook and has no `webhook.provider == provider` check. This falsifies any claim that the candidate originated URL-provider selection.
- Atomic PR member [`3b0d43230901ef353c39cc3bbac36e6d81f049dc`](https://github.com/Significant-Gravitas/AutoGPT/commit/3b0d43230901ef353c39cc3bbac36e6d81f049dc) has a Claude Opus 4.7 coauthor trailer. Squash carrier [`7f08a16deed57c93654356058667293534de6994`](https://github.com/Significant-Gravitas/AutoGPT/commit/7f08a16deed57c93654356058667293534de6994), parent `e877391...`, retains the same direct marker.
- The candidate adds the optional Generic Webhook `secret_token`, the generic signature verifier, the default no-op verifier for unsigned providers, and the call to `webhook_manager.verify_signature`. Because the manager remains selected from the path, this newly claimed secret boundary can be bypassed through an unsigned provider. Deleting the candidate eliminates the configured-secret mechanism, but leaves the older path confusion. That is a contributor/new-boundary result, not root-cause ownership.
- [PR #13135](https://github.com/Significant-Gravitas/AutoGPT/pull/13135) is merged with carrier `7f08a16...` and contains the atomic member. PR-head `c4c8f5c...` and carrier have identical SHA-256 blobs for `router.py` (`8a3b0ac8...`) and the generic webhook manager (`47dcc9d8...`), proving the relevant member state survived the squash.
- Exact fix [`646dd5b8cfad1206e92ec7bcc3b8312657e2a92e`](https://github.com/Significant-Gravitas/AutoGPT/commit/646dd5b8cfad1206e92ec7bcc3b8312657e2a92e), parent `3fa88a70...`, compares the stored provider with the URL provider before verification. It reverses the exact selection/invariant mismatch.
- Preserve a first-party prose/code mismatch: the fix commit message says mismatch returns 403, while the patch raises `NotFoundError` and regression tests assert an indistinguishable 404. Both fail closed before verification, so this narrows response-code wording but does not defeat containment.
- Release tag `autogpt-platform-beta-v0.6.65` resolves to `e2711b1748bdc3fe702ab4e44c6a11df98458c53`, 11 commits ahead of the carrier. Fixed [0.6.70](https://github.com/Significant-Gravitas/AutoGPT/releases/tag/autogpt-platform-beta-v0.6.70) resolves to `c45b9e35817a2037fadeaa47924cf41681573c09`, 16 commits ahead of the fix. Both releases are non-draft and published.

### B2-02 — GHSA-75HX-XJ24-MQRW session/health surface

**Verdict: `KEEP`, only as the already-proposed new session-control and higher-sensitivity disclosure contributor.**

The live [repository advisory](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-75hx-xj24-mqrw) is GHSA-only, published, non-withdrawn, affected `<=2.47.5`, fixed `2.47.6`.

- Candidate [`a597ef5a924ebe17a6a202bbb841965f52328032`](https://github.com/czlonkowski/n8n-mcp/commit/a597ef5a924ebe17a6a202bbb841965f52328032), parent `a4053de998595b4321576ad6a908e65590816ee0`, has its own Claude Code marker and coauthor trailer.
- Its direct-parent patch makes `GET /mcp` hand requests to live transports, creates unauthenticated `DELETE /mcp`, creates an unauthenticated manual test route, and expands `/health` with active transport/server counts and session IDs. Removing these hunks removes those exact live control/disclosure edges; it does not remove every older HTTP route or every older health field.
- Candidate ancestry reaches npm `2.9.1` gitHead `35b4e77b...` (`ahead_by=19`) and the exact vulnerable endpoint npm `2.47.5` gitHead `ff486ea04f0b20460141e5ef2be3d518e1772b80` (`ahead_by=639`).
- Fix [`ca9d4b3df6419b8338983be98f7940400f78bde3`](https://github.com/czlonkowski/n8n-mcp/commit/ca9d4b3df6419b8338983be98f7940400f78bde3), whose parent is exactly the 2.47.5 `gitHead`, authenticates GET/DELETE, removes the test route, and makes health a minimal liveness response. npm `2.47.6` gitHead `4b161b6a...` is one commit ahead of the fix.

This row does not attribute every pre-existing authentication omission or every health field to the candidate, and it counts the endpoint family once.

### B2-03 — GHSA-8G7G-HMWM-6RV2 caller-controlled API path segments

**Verdict: `KEEP` as target-repository integration/new-surface origin.**

The live [repository advisory](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-8g7g-hmwm-6rv2) is published and non-withdrawn, with affected `<2.50.1` and fixed `2.50.1`.

- Candidate [`74f05e937fa7d94babe3507510caa17ce17a698c`](https://github.com/czlonkowski/n8n-mcp/commit/74f05e937fa7d94babe3507510caa17ce17a698c), parent `150de3d1c249e518b73d91b8621db2f6a628b1b5`, has direct Claude markers. The parent lacks `src/services/n8n-api-client.ts`; the candidate adds the client, its configured `X-N8N-API-KEY`, and raw caller IDs in workflow, execution, credential, tag, and related path templates. Deleting the candidate removes this target-repository integration and its sinks.
- npm `2.7.9` gitHead `6b49b000...` is 51 commits ahead of the candidate. npm `2.50.0` gitHead `1ca40ce2...` remains 890 commits ahead, establishing vulnerable released containment.
- Exact fix [`1cfe9c6bddb4b1634e6e23323c18ea35fd196999`](https://github.com/czlonkowski/n8n-mcp/commit/1cfe9c6bddb4b1634e6e23323c18ea35fd196999), parent `fefa2d9b...`, adds a bounded alphanumeric/hyphen/underscore path-segment validator and applies it to each affected API route. npm `2.50.1` has `gitHead` exactly equal to the fix.

The commit says code was integrated from another project. The claim is target-repository integration/new surface, not upstream authorship.

The candidate subject mentions `v2.6.0`, but the precise npm version endpoint returned 404. The independently verified release wording is therefore **candidate-bearing no later than npm 2.7.9**, not a claim that npm 2.6.0 existed.

### B2-04 — GHSA-8G7G-HMWM-6RV2 redirect-following SSRF

**Verdict: `KEEP` as one form/chat new-surface component; do not count the guarded webhook sibling separately.**

- PR member [`3f698cc62d2f820f83713a51fce23f71e9cc4654`](https://github.com/czlonkowski/n8n-mcp/commit/3f698cc62d2f820f83713a51fce23f71e9cc4654), parent `ddf95567591a5b0a56e9df393e368969536fce3e`, has direct Claude markers and adds form/chat handlers. They validate only the initial URL and then invoke Axios with default redirect following. Because both handler files are new, deletion removes these sinks.
- The next direct-attributed member [`7d81204aecb58ba09c70497ae643b886f0d9edc4`](https://github.com/czlonkowski/n8n-mcp/commit/7d81204aecb58ba09c70497ae643b886f0d9edc4) gives the older webhook sibling the same initial-URL-only guard. This is same-mechanism history, not a second component.
- [PR #460](https://github.com/czlonkowski/n8n-mcp/pull/460) contains both members and squashes to `33690c5650e680b2c9cfbae75cac81a761742389`. PR-head `5298923d...` and carrier blobs are identical for `chat-handler.ts` (`8bf7c5a1...`) and `form-handler.ts` (`494fa7cd...`). npm `2.28.0` has `gitHead` exactly equal to the carrier; npm `2.50.0` is 132 commits ahead.
- Fix `1cfe9c6...` sets `maxRedirects: 0` on chat, form, and the webhook client's Axios instance. That is a same-sink repair of the post-validation redirect escape; npm `2.50.1` is exactly the fix.

The previously admitted n8n-mcp GHSA-56C3-VFP2-5QQJ is not a duplicate. Its first-party advisory is specifically the SDK embedder's caller-supplied `n8nApiUrl`, `validateUrlSync()` IPv4-mapped IPv6 parsing gap, and forwarding of `x-n8n-api-key`; its fix `9639f757...` expands IPv6 classification. This row instead concerns trigger-request Axios redirects after a safe initial URL and is fixed by disabling redirects at different sinks. Shared CWE-918 and a shared validator family are not enough to merge different input/sink/invariant/fix tuples.

### B2-05 — GHSA-8G7G-HMWM-6RV2 mutation-telemetry residual

**Verdict: `KEEP` as released `AI_INCOMPLETE_REMEDIATION`, never strict origin.**

- Human member [`61fdd6433a4ae0a404772a0f6a53f928e4606c5e`](https://github.com/czlonkowski/n8n-mcp/commit/61fdd6433a4ae0a404772a0f6a53f928e4606c5e), parent `77151e01...`, creates the mutation record and stores raw workflow copies, operations, validation objects, and errors. It has no direct AI marker.
- AI-attributed member [`7ac748e73f69bcd3b43d0a321b38d79078013b91`](https://github.com/czlonkowski/n8n-mcp/commit/7ac748e73f69bcd3b43d0a321b38d79078013b91), parent `6719628350972ebdbc347ef4406b029a712c3f24`, sanitizes `workflowBefore` and `workflowAfter`, but the record still assigns `data.operations`, `data.validationBefore`, `data.validationAfter`, and `data.mutationError` raw. Deleting the AI hunk restores a fully raw state, so this is a real risk-reducing remediation that remains incomplete—not origin.
- [PR #419](https://github.com/czlonkowski/n8n-mcp/pull/419) contains both human root and AI remediation members and squashes to `99c5907b71a6c3228d345a2f0879cd893f30cd7e`. PR-head `a1291c59...` and carrier `mutation-tracker.ts` blobs are identical (`33c67466...`). npm `2.22.16` has `gitHead` exactly equal to the carrier; npm `2.50.0` is 156 commits ahead.
- Fix `1cfe9c6...` applies `sanitizeTelemetryObject` to every residual field before the record is queued. npm `2.50.1` is exactly the fix.

## Dedup and negative controls

- Exact public IDs and candidate/fix fingerprints were absent from the frozen strict ledger and the pre-Batch-1 baseline reports. The repository-name search did find earlier rows, which were inspected rather than ignored.
- Existing AutoGPT CVE-2025-32425 concerns Docker log rotation for a newly added frontend service. It is not the webhook provider/verification invariant here.
- Existing n8n-mcp CVE-2026-42449 / GHSA-56C3-VFP2-5QQJ is the SDK `n8nApiUrl`/IPv6-classification/API-key sink described above, not the redirect-following trigger sink.
- Within GHSA-75, GET, DELETE, manual-test, and health hunks remain one session/health component.
- Within GHSA-8G7G, webhook/form/chat redirect handling is one SSRF mechanism. The API-path, redirect, and telemetry mechanisms remain separate because their inputs, sinks, invariants, origins, and repair hunks differ. The advisory identity is still counted once.
- No row was upgraded on the basis of tests, issue text, repository naming, model prose, ancestry alone, or release metadata alone.

No substantive mechanism ended `REJECT`, `UNKNOWN`, or `BLOCKED`. The negative controls above are preserved because they bound component and authorship inflation.

An independent background replay reached the same `4 KEEP / 1 NARROW` result. Its full primary-source notes and additional annotated-tag identities are preserved in `research-notes.md` at the hash above.

## Exact commands and first-party sources

All loops were finite over the explicit rows and SHAs in this report. Representative exact commands (with the enumerated IDs/SHAs substituted literally) were:

```zsh
git -c gc.auto=0 -c maintenance.auto=false rev-parse --abbrev-ref HEAD
git -c gc.auto=0 -c maintenance.auto=false rev-parse HEAD
git -c gc.auto=0 -c maintenance.auto=false status --porcelain=v1 -z | sha256sum

sha256sum \
  autoresearch/herdr-260812-fresh-advisories/report.md \
  autoresearch/herdr-260812-mcp-js-ecosystem/report.md \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl

gh api repos/Significant-Gravitas/AutoGPT/security-advisories/GHSA-349p-3c3r-8mjr
gh api repos/czlonkowski/n8n-mcp/security-advisories/GHSA-75hx-xj24-mqrw
gh api repos/czlonkowski/n8n-mcp/security-advisories/GHSA-8g7g-hmwm-6rv2
curl -fsSL https://cveawg.mitre.org/api/cve/CVE-2026-72922 | jq -S -c .

gh api repos/OWNER/REPO/commits/SHA \
  --jq '{sha,parents:[.parents[].sha],message:.commit.message,author:{login:.author.login,name:.commit.author.name,date:.commit.author.date},files:[.files[]|select(.filename == "EXACT_PATH")|{filename,status,additions,deletions,patch}]}'
gh api repos/OWNER/REPO/pulls/NUMBER
gh api repos/OWNER/REPO/pulls/NUMBER/commits --paginate --jq '[.[].sha]'
gh api repos/OWNER/REPO/compare/BASE...HEAD \
  --jq '{status,ahead_by,behind_by,merge_base_commit:.merge_base_commit.sha}'

gh api repos/Significant-Gravitas/AutoGPT/releases/tags/autogpt-platform-beta-v0.6.65
gh api repos/Significant-Gravitas/AutoGPT/releases/tags/autogpt-platform-beta-v0.6.70
gh api repos/Significant-Gravitas/AutoGPT/git/ref/tags/autogpt-platform-beta-v0.6.65
gh api repos/Significant-Gravitas/AutoGPT/git/ref/tags/autogpt-platform-beta-v0.6.70

for version in 2.7.9 2.9.1 2.22.16 2.28.0 2.47.5 2.47.6 2.50.0 2.50.1; do
  curl -fsSL "https://registry.npmjs.org/n8n-mcp/$version" |
    jq -c '{name,version,gitHead,repository,dist:{shasum:.dist.shasum,integrity:.dist.integrity}}'
done

curl -fsSL "https://raw.githubusercontent.com/OWNER/REPO/SHA/PATH" | sha256sum

rg -n -i 'CVE-2026-72922|GHSA-349P-3C3R-8MJR|GHSA-75HX-XJ24-MQRW|GHSA-8G7G-HMWM-6RV2|CANDIDATE_SHA|FIX_SHA' \
  docs/AUDIT-CONSOLIDATED-LEDGER-156-2026-08-11.md \
  docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl
```

First-party object families used:

- GitHub repository security-advisory API and rendered repository advisories.
- GitHub commit, PR, PR-commit, compare, release, tag-ref, and immutable raw-content objects.
- CVE Services record for CVE-2026-72922.
- npm registry version documents for `n8n-mcp` with exact `gitHead`, tarball `shasum`, and integrity.

No broad build, test suite, clone, corpus rerun, or unbounded search was performed. No API response or credential was intentionally stored.

## Operational boundary incident

One early commit query selected patches for every file in n8n-mcp commit `a597ef5...`. Its public first-party response unexpectedly included a historical `.env.backup` patch containing credential-shaped values, which reached tool output. The values are not reproduced here, the response was not saved, and no workspace/environment credential was queried. Subsequent queries selected exact safe paths before printing. Because the task explicitly prohibited printing any credentials, this shard cannot certify that boundary and therefore reports terminal status `PARTIAL` despite completing all five adjudications.

## Claim boundary

- Publication-grade mechanism results after red-team: four `KEEP`, one `NARROW`, zero `REJECT`, zero `UNKNOWN`.
- AutoGPT is admitted only as an AI-coauthored protected-boundary/bypass contributor. The parent proves that URL-provider manager selection predates the candidate.
- GHSA-75 is admitted only for the candidate-created live GET/DELETE/session-ID and higher-sensitivity health edges, not every older HTTP/authentication behavior.
- GHSA-8 contributes two strict/new-surface mechanisms and one released incomplete-remediation mechanism, but one advisory identity.
- AI attribution means an explicit marker on the causal member/carrier, not exclusive AI authorship or an attribution fraction.
- Commit deltas and same-mechanism repairs provide the causal evidence. Advisory identity and released containment bound the public claim; routing, ancestry, source recovery, tests, and version metadata do not independently prove causality.
- The operational print incident prevents a fully compliant `COMPLETE` status. It does not change a row verdict, but it is not hidden or downgraded.
