# UNKNOWN recovery shard report

## Result

The shard completed its requested recovery pass without editing any source ledger or shared cache.

- Current unresolved inventory: **393 distinct components**.
- Current state: **263 UNKNOWN**, **129 BLOCKED**, **1 NEEDS_REVIEW**.
- Explicit flags: **129 missing-history** and **137 missing-exact-fix** rows; these sets overlap.
- Top 12 attempted: **8 RESOLVED_REJECT**, **3 STILL_BLOCKED**, **1 STILL_UNKNOWN**, **0 RESOLVED_PASS**.
- `RESOLVED_REJECT` is scoped to the named routed edge or edge set. It is **not** a class-wide `NOT_AI_CAUSAL` claim; the corresponding class causal label remains `UNKNOWN` unless claim-grade negative evidence exists.
- The other **381** ranked rows remain unchanged in `unresolved-inventory.jsonl`; none was silently dropped or inferred negative.

Task completion is `COMPLETE`: all requested enumeration, ranking, top-12 attempts, and terminal artifacts are present. Evidence recovery did not make every selected component resolvable.

## Scope and snapshot boundary

- Started: `2026-08-12T12:17:30-04:00`.
- Frozen shared-input snapshot: `2026-08-12T12:22:34-04:00`.
- Repository boundary: branch `dev`, commit `6c0d2084fd1240341d6d1b9f9096252490168f0b`.
- End-state dirty-tree observation at `2026-08-12T12:39:02-04:00`: 405 porcelain entries; NUL-delimited status SHA-256 `96f440a130e4983e79da19d7d15014920ca649544e5c3905c327073d8412df10`. This is observational only and includes concurrent agents plus this owned directory.
- All durable artifacts and clones are below `autoresearch/herdr-260812-unknown-recovery/`. Five disposable `/tmp/herdr_*` sort/check files were mistakenly created during enumeration and final validation; they were explicitly removed before handoff. No pre-existing repository, cache, or shared artifact path was modified.
- Existing caches and clones were read-only. Two fresh first-party clones were created inside the owned directory: AutoBangumi and `rustfs/s3s`.
- Exact Git object IDs are the replay boundary for local-history conclusions; branch tips were used only for current-code checks.

### Frozen input hashes

| Snapshot | SHA-256 |
|---|---|
| `snapshot/strict-200-v3-ledger.jsonl` | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| `snapshot/strict-200-closure.md` | `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` |
| `snapshot/consolidated-156.md` | `2fb6210a10802c1d9570caeb88dc8af08b1f26721c860deda005df980bf3f687` |
| `snapshot/needs-review-closure.md` | `ef0293ac89d074d47934a13aa05338bd90cab7b9692cfe91f4e14f82d7a79b31` |
| `snapshot/new-components-main.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `snapshot/refresh-overlay.jsonl` | `bfafa3e5ae570eb01be61dfb9aeb0adbcfdfe19f1a453ba494e3a13743aaa4e8` |
| `snapshot/refresh-handoff.md` | `eba2d5d1593f5edfec639f2580fd2149af18c519c9a7442777d895be151cdeb2` |
| `snapshot/refresh-exact-adjudications.jsonl` | `ca026877faf923625df0c88afb9fa97b482123c0f7a1d37b966350cc9513dff8` |
| `snapshot/audit-adjudications.jsonl` | `47536f4e426b51ff2fa012cb9a250ea49ed21d51a7cb1a1f369ecd2c13d1ba9a` |
| `snapshot/audit-official-records.jsonl` | `19fcd3298046962919cd25afb332f8c54093922f1a3b3f3e3991ea0cd49f1090` |
| `snapshot/audit-handoff.md` | `da93dbc191996505ea79fc2a71f8892c9c7e6cdf14a6053530d73f13f750969c` |
| selected P0 routing slice | `ef81c752a3b171dafcefa20a12893c74d457f8e03dd90401d480735c81a2bc9b` |
| selected structural-fix slice | `c10c11c6bdd4d761bc620db35268b80e8b152ec816615ff5de0167fb6b324a3b` |

The selected routing slice came from `prioritized-ai-edges.jsonl` SHA-256 `a3f57b7be768a039ba2a9d7d6f5b1de49affff3d7bbe90f45be4f7bc1932a50e`; the selected fix slice came from `structural-fixes.jsonl` SHA-256 `d4e899812a926d8d3d7a38d6ddf666f372faf74963a8bf4f3f7e46f5c7db40fa`.

Current first-party read boundaries:

- AutoBangumi `origin/main`: `fd798519fee7efacfe2d64897e0e8b04f0cee2f2`.
- NLTK local `origin/main`: `4154eb85e832f266660a09286c7e37e308292284`.
- `rustfs/s3s` owned clone `origin/main`: `d7028511a53f69d41ed3c69f36899f9b1aede647`.

## Source reconciliation and exclusions

| Source | Raw unresolved-looking rows | Current rows retained | Explicit exclusions |
|---|---:|---:|---|
| strict-200-v3 | 0 | 0 | All 110 components / 200 IDs are accepted and contain no unresolved state. |
| consolidated-156 | 23 NEEDS_REVIEW | 1 | Rows 78 and 93 are now strict-v3 PASS. Of the other 21, the closure report makes 10 PASS and 10 FAIL; only row 125 AutoBangumi remains. |
| new-components main | 1 `NR` | same 1 | AutoBangumi is the same semantic component as consolidated row 125 and is represented once. |
| refresh overlay | 24 BLOCKED + 17 UNKNOWN | 41 | None excluded. |
| five exact-fix refresh candidates | 5 candidate rows | 2 UNKNOWN | `CVE-2026-19350`, `CVE-2026-19351`, and `CVE-2026-69659` are later `NOT_AI_CAUSAL`; `CVE-2026-19352` and `CVE-2026-70395` remain inconclusive. |
| frozen 354-row audit | 351 INCONCLUSIVE | 349 | `CVE-2026-67530` is later strict-v3 PASS; `GHSA-539m-9xh6-q6rr` is later adjudicated as released incomplete remediation in the new-components report. The audit's 1 AI_CAUSAL and 2 NOT_AI_CAUSAL rows were never unresolved. |

Thus the current de-duplicated total is `1 + 41 + 2 + 349 = 393`.

### Current audit-reason census

| Reason | Rows |
|---|---:|
| `HISTORY_BLOCKED` | 105 |
| `NO_EXACT_FIX` | 95 |
| `NONEXHAUSTIVE_CANDIDATE_REVIEW` | 73 |
| `NO_OBSERVED_AI_ANCESTOR` | 61 |
| `GROUPED_FIX_CARRIER_MECHANISM_MISMATCH` | 5 |
| `ROUTED_EDGES_RETAINED_ORIGIN_UNATTRIBUTED` | 4 |
| `ROUTED_EDGE_REJECTED_ORIGIN_UNATTRIBUTED` | 4 |
| `ROUTED_EDGES_REJECTED_ORIGIN_UNATTRIBUTED` | 2 |

The inventory preserves the original status/reason and adds canonical `current_status`, `missing_history`, `missing_exact_fix`, `resolvability_rank`, and source-evidence fields.

## Ranking method

The first twelve prioritize, in order:

1. the only still-current legacy `NEEDS_REVIEW` row;
2. a current refresh UNKNOWN with a local first-party history and an advisory-specific mechanism;
3. audit rows with resolved local fix objects, a small manually reviewed P0 edge set, and concrete mechanism/path anchors;
4. grouped-carrier mismatches where an exact member could plausibly be recovered.

The remaining 381 rows are deterministically ranked by recoverability: routed-edge dispositions, grouped-carrier mismatches, nonexhaustive review, exact-fix availability, local-clone availability, and finally history blockers. Ties use class ID. This is triage priority, never evidentiary weight.

## Top-12 recommendation ledger

| Rank | Component | Recommendation | Exact result |
|---:|---|---|---|
| 1 | AutoBangumi, CVE-2026-59101 | `STILL_UNKNOWN` | `5382aec8` created the endpoint with explicit Claude attribution; `c7c709fa` added a full private-IP guard; Claude `61ff20fe` removed that guard. Claimed fix `487bdfec` and current main deliberately retain private/loopback access. No later exact released containment. |
| 2 | NLTK, CVE-2026-12372 | `STILL_BLOCKED` | Recovered a strong same-mechanism incomplete-remediation edge: Copilot-marked `a634475d` adds `is_private`, ships in 3.9.4, and misses CGNAT; `4a820afa` changes policy to `not ip.is_global`, names 100.64/10, and ships in v3.10.0. The repository GHSA is absent and the unreviewed/NVD GHSA still says source and patched versions unknown, so the first-party advisory-identity gate is not closed. |
| 3 | RAGFlow, CVE-2025-68700 | `RESOLVED_REJECT` | Copilot `cbf04ee4` does not modify `agent/tools/code_exec.py`; vulnerable `eval` blames to `d9fe279d`. Exact fix `7a344a32` removes it. Reject named edge only. |
| 4 | Orthanc Explorer 2, CVE-2026-10173 | `RESOLVED_REJECT` | Copilot `f2bbed1d` changes config/locales. Unsafe `remote-source` assignment and `v-html` lines blame to `d697e190`/`547cb7b6`; `21f78ce5` sanitizes the value. |
| 5 | Docker sbx, CVE-2026-12039 | `STILL_BLOCKED` | Both candidate `363373d6` and bound root `e4809b10` are README-only. The release repository lacks the embedded-DNS source/fix; affected history also has a promisor-object gap. |
| 6 | excel-mcp-server, CVE-2026-40576 | `RESOLVED_REJECT` | Claude `e5053229` only adds tool annotations. Unsafe path logic originates in `4e82b8a7`/`bbab5bf1`; `f51340ec` adds realpath/commonpath confinement and tests. |
| 7 | Fleet, CVE-2026-27465 | `RESOLVED_REJECT` | Claude `5bf82e29` adds host API status fields, not calendar credential output. `23fc6804` adds Google Calendar key masking/preservation. |
| 8 | Sim, CVE-2025-9805 | `RESOLVED_REJECT` | Claude `a37c6bc8` changes only build workflow/lockfile. `3424a338` adds URL validation immediately before the image-proxy fetch. |
| 9 | better-auth, CVE-2026-67327 | `RESOLVED_REJECT` | `5c6ccfa6` is docs-only and `6c83eca2` is an adapter move; neither changes passwordless verification. `c06a56d8` revokes unproven credentials/sessions before verification. |
| 10 | RustFS, CVE-2026-45040 | `STILL_BLOCKED` | Capacity/lifecycle candidates `064e2106`/`6ce24f3b` are unrelated. Recovered exact in-repo member `66c38b62` (not carrier `9f070293`) for session-token masking, but the advisory names a second `s3s` response-body leak. beta.1 and beta.2 pin the same `a3b16608`, whose `Body::Once` still logs raw bytes; current `s3s` main also retains it. Released containment is not demonstrated. |
| 11 | vLLM, CVE-2026-22773 | `RESOLVED_REJECT` | Five AI candidates are buffer/config/worker refactors and none touches `idefics3.py`. Atomic fix `0ec84221` forces channels-last input; vulnerable image-processing history predates those candidates. |
| 12 | MCP Python SDK, CVE-2026-52869 | `RESOLVED_REJECT` | Five candidates concern tools/tasks/pagination/sampling/tests, not authenticated HTTP session ownership. SSE/HTTP origins are `4cbf8154`/`e4e119b3`; `1abcca24` plus `ce267b6f` bind sessions to authorization context and release in v1.27.2. |

All exact SHAs, evidence objects, URLs, blockers, and per-row claim boundaries are in `recommendation-ledger.jsonl`.

## Negative and unknown controls

- No `RESOLVED_PASS` was emitted. A compelling mechanism match is not enough when advisory identity or released containment is missing.
- NLTK is deliberately not promoted despite recovered AI partial remediation, exact reversal, ancestry, and tag topology. The first-party advisory identity is absent, and the current unreviewed advisory conflicts with first-party Git state.
- AutoBangumi is deliberately not promoted despite stronger direct AI origin/reintroduction evidence because no exact containment exists through current main/latest release.
- RustFS is deliberately not treated as fixed merely because the first-party advisory labels beta.2 patched: one of its two named sinks remains in the identical pinned dependency revision.
- Docker remains blocked rather than negative because the routing repository is release-only and lacks the source mechanism.
- Eight `RESOLVED_REJECT` decisions reject only the enumerated routed candidate sets. Missing public AI attribution on a recovered origin is not evidence of human-only authorship.
- `CVE-2026-19352` and `CVE-2026-70395` remain UNKNOWN after all observed candidates were rejected; absence remains non-negative.

## Exact commands and first-party sources

Snapshot and enumerate:

```zsh
cp --reflink=auto <shared-input> autoresearch/herdr-260812-unknown-recovery/snapshot/<name>
sha256sum autoresearch/herdr-260812-unknown-recovery/snapshot/*
python3 autoresearch/herdr-260812-unknown-recovery/build_inventory.py
jq -s 'group_by(.current_status) | map({status:.[0].current_status,count:length})' \
  autoresearch/herdr-260812-unknown-recovery/unresolved-inventory.jsonl
```

Freeze the reviewed P0/fix slices:

```zsh
jq -c 'select(<top-12 class predicate> and (.routing_priority_class | startswith("P0_")))' \
  autoresearch/orchestrator-260810-0613/audit-review/prioritized-ai-edges.jsonl \
  > autoresearch/herdr-260812-unknown-recovery/snapshot/top12-p0-routing.jsonl
jq -c 'select(<top-12 class predicate>)' \
  autoresearch/orchestrator-260810-0613/audit-review/structural-fixes.jsonl \
  > autoresearch/herdr-260812-unknown-recovery/snapshot/top12-structural-fixes.jsonl
```

Representative exact-history replay (repeated only for the 12 selected components and their named objects):

```zsh
git -C <repo> show -s --format='%H%n%an%n%ad%n%s%n%b' --date=iso-strict <sha>
git -C <repo> diff-tree --no-commit-id --name-only -r <sha>
git -C <repo> show --format= --unified=8 <fix> -- <mechanism-path>
git -C <repo> blame <fix>^ -- <mechanism-path>
git -C <repo> merge-base --is-ancestor <candidate> <fix>
git -C <repo> tag --contains <sha> --sort=version:refname
```

Focused history recovery:

```zsh
git clone --filter=blob:none --no-checkout https://github.com/EstrellaXD/Auto_Bangumi.git \
  autoresearch/herdr-260812-unknown-recovery/clones/auto-bangumi
git clone --filter=blob:none --no-checkout https://github.com/rustfs/s3s.git \
  autoresearch/herdr-260812-unknown-recovery/clones/rustfs-s3s
git -C /home/hanqing/.cache/cve-analyzer/repos/nltk_nltk \
  log --all --format='%H%x09%ad%x09%an%x09%s' --date=iso-strict -- nltk/pathsec.py
git -C /home/hanqing/.cache/cve-analyzer/repos/rustfs_rustfs \
  log --all -S'.field("session_token", &self.session_token)' -- crates/credentials/src/credentials.rs
```

Live first-party/reference checks on `2026-08-12`:

- NLTK repository advisory URL (404): `https://github.com/nltk/nltk/security/advisories/GHSA-2jhm-w3mp-jcwr`
- NLTK unreviewed advisory: `https://github.com/advisories/GHSA-2jhm-w3mp-jcwr`
- NLTK exact commit/release: `https://github.com/nltk/nltk/commit/4a820afa58810cd05049b6c6eae306694d6cfe65`, `https://github.com/nltk/nltk/releases/tag/v3.10.0`
- AutoBangumi advisory/releases: `https://github.com/advisories/GHSA-p8rr-9cvg-cx5j`, `https://github.com/EstrellaXD/Auto_Bangumi/releases`
- RustFS first-party advisory/exact member: `https://github.com/rustfs/rustfs/security/advisories/GHSA-8cm2-h255-v749`, `https://github.com/rustfs/rustfs/commit/66c38b629d4a3453dec14d60cb0d5c32acc19085`
- All other row-specific first-party URLs are embedded in `recommendation-ledger.jsonl`.

No API credentials were read or printed. No broad build, test suite, model/API loop, cache mutation, or 51,218-unit rerun was performed.

## Verification

```zsh
python3 autoresearch/herdr-260812-unknown-recovery/build_inventory.py
jq -e . autoresearch/herdr-260812-unknown-recovery/unresolved-inventory.jsonl >/dev/null
jq -e . autoresearch/herdr-260812-unknown-recovery/recommendation-ledger.jsonl >/dev/null
jq -s '{rows:length,unique:(map(.class_id)|unique|length),by_recommendation:(group_by(.recommendation)|map({key:.[0].recommendation,value:length})|from_entries)}' \
  autoresearch/herdr-260812-unknown-recovery/recommendation-ledger.jsonl
```

Observed checks:

- Inventory assertions: 393 rows, 393 unique class IDs, exactly 12 selected ranks.
- Recommendation ledger: 12 rows, 12 unique components, ranks 1–12, `RESOLVED_REJECT=8`, `STILL_BLOCKED=3`, `STILL_UNKNOWN=1`.
- Output hashes before final timestamp insertion: inventory `5167b86efb2d6e3d218c41da120c7302f99049b9c588e8fd00896051d50355ca`; recommendation ledger `944a0027a558468be4a2bef235e610927c5f18c85e8e77fb24eeb6c21293ecc7`.

## Claim boundary

This shard recovered routing and lineage evidence. It did not run exploit tests, rebuild products, or make a recall estimate. Candidate discovery, local object availability, same-file overlap, ancestry, first-party commits, and release tags are individually diagnostic. Publication-grade admission still requires a first-party advisory identity, exact candidate/fix lineage, the same security mechanism, and released containment. `UNKNOWN`, `BLOCKED`, and negative controls are retained wherever any gate remains open.
