# Bounded reproducibility and verifier audit

## Outcome

`COMPLETE` for the bounded QA task. The frozen `strict-200-v3` ledger reproduced byte-for-byte, and all 31 selected regression cases passed. This is strong artifact/consumer-contract evidence, but it does **not** independently establish the newest aggregate report's 125 strict, 173 release-grade broad, or 186 commit-level claims.

The principal gap is simple: the newest aggregate is a Markdown synthesis and explicitly did not update a machine-readable ledger. No Python generator/verifier in `scripts/` names `AI_INCOMPLETE_REMEDIATION` or the aggregate report. The only ledger reproduced here is the already-adjudicated 110-component/200-public-ID `strict-200-v3` baseline.

## Scope and snapshot boundary

- Audit start: `2026-08-12T12:17:53-04:00`.
- Audit end: `2026-08-12T12:25:41-04:00`.
- Snapshot boundary: `2026-08-12T12:23:00-04:00`.
- Checkout: `/home/hanqing/agents/ai-slop`, branch `dev`, HEAD `6c0d2084fd1240341d6d1b9f9096252490168f0b`.
- The checkout was intentionally very dirty. All writes were confined to `/home/hanqing/agents/ai-slop/autoresearch/herdr-260812-repro-qa/`.
- Newest completed aggregate at the snapshot was `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` (mtime `2026-08-12 11:34:50.372821087 -0400`). The concurrently active foreign shard `autoresearch/herdr-260812-squash-lineage/` was excluded as unfinished and was not used.
- No shared cache, existing clone, tracked/untracked research artifact, Git index, branch, or commit was mutated. `uv --no-sync`, `PYTHONDONTWRITEBYTECODE=1`, suite-local `TMPDIR`, `UV_CACHE_DIR`, `XDG_CACHE_HOME`, pytest `--basetemp`, and `-p no:cacheprovider` kept runtime writes inside the owned directory.
- Already-adjudicated rows were not reopened: all 110 `strict-200-v3` components, Batch A-E rows, and the OpenClaw 12-row closure were treated as frozen inputs. The replay regenerated their existing baseline artifact; it did not redo causal adjudication.
- No 51,218-unit corpus run, broad build, live API loop, Docker witness, clone/fetch, model call, or product test suite was run. Commands were sequential; there was one bounded work layer.

## Input hashes

### Closure and frozen ledger inputs

| SHA-256 | Input |
|---|---|
| `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` | `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` |
| `a7dd3db373af0fae98c10f8c96c58180cf80fc132fb6fb53fedbd44f3aae22c2` | `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md` |
| `318912fbc789ef7f0708044d2041c24fa69198f878c2c668b04af86031d4616e` | `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md` |
| `b1e03cb193003ebbba83b73b8d8bbcbcd72f02148ba00812967a2721e60a8ffd` | `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-C-2026-08-12.md` |
| `3a8482a6badb0b8bff5dbf64adc18b37493c68dc56a25598be91ee3be7e727cd` | `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md` |
| `f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad` | `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md` |
| `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` | `docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` |
| `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` | `docs/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md` |
| `282d2975d0ee24e9949cc4d108ad5a1ffd9b045ad8548cc6b1661aaf2c18392e` | `autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/ledger.jsonl` |
| `09a45c145313862f2d60b47cfe1df23bce9a1d7d3b6140592a913a364dfcbd4d` | `autoresearch/orchestrator-260811-atomic150/strict-200-v3/supplement.json` |
| `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` | `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl` |
| `69dd6c35de1455bf9cee88420aed570c576a190a4d143202d01a26cc3d37b81e` | `autoresearch/orchestrator-260811-atomic150/strict-200-v3/summary.json` |

The aggregate's embedded hashes for Batch A-E and OpenClaw matched these snapshot hashes.

### Code and test inputs

| SHA-256 | Input |
|---|---|
| `1120d0d77565dc28a4123701755a0e1460fca68415b6f3e32cf57dc4ff13d045` | `scripts/merge_strict_ai_causal_supplement.py` |
| `ac9484468f639dbf22741ea4c9a8e1ee6dc39aa9312a2326ece46d72c01fb4b2` | `scripts/apply_strict_causal_adjudications.py` |
| `0681802ac0d7c5b76186868ee577660610982116a943b1772610f64cd80792cc` | `scripts/tests/test_apply_strict_causal_adjudications.py` |
| `abb6a7951891c7b439853d918320d07977051173c31665c1dd9c2055193881d0` | `scripts/cohort/advisory_candidates.py` |
| `5798b1bbdf98b641062b3551ecce422beee881f27d16514ebe7ce9297558b6d2` | `scripts/tests/test_cohort_advisory_candidates.py` |
| `5820f1d95072cc04d11261004ce2e790af33904e7dab07742856fa6fb3d25685` | `scripts/build_atomic_ai_causal_ledger.py` |
| `7061614a844b18c58540ae423abd5b6b95529ab69524711457ed5564cc1afd8d` | `scripts/tests/test_build_atomic_ai_causal_ledger.py` |
| `ad1fbff361503b30ac3efc6975517d224f81a6df39d356c1d4bc9f9dc0a50f79` | newest paired witness: `scripts/cohort_coolify_concurrent_index_migration_transaction_contract_witness.py` |
| `25d9e7c76aaf8524c42b7dca2e019c845a57468a7437d82e5c64d9ce2853a26d` | its test |
| `687680cbfa8cb08f049b832996a731c3abf85fa6d025c94ec616d02a78edaaab` | second-newest paired witness: `scripts/cohort_coolify_readonly_volume_path_normalization_witness.py` |
| `b3f7a7129158452e3a9e344432c58c2258b59ed43ff968164a4b1b8957d53582` | its test |
| `ddf30fd7eabb83f5ae8539e51a6374d69704b02b9cecbc658e2066d13ce45416` | witness helper `scripts/cohort_coolify_postgresql_query_idor_path_extension_witness.py` |
| `2cea3e893e38398204ba9d573f7cc1552acd533aa5abece024beb9cf90d1bc4b` | witness helper `scripts/cohort_coolify_security_frontier_preservation_witness.py` |
| `46ef71bad279ce92b7b746d979cc14337685c6f02c5cb74f15dcbbf67552f9b5` | `scripts/conftest.py` |
| `91dd7b55315fa626650ad23bcc51d9e5510df044c5b1980a3eb95415a6ccde48` | `cve-analyzer/pyproject.toml` |
| `866cb84fe718401fb442a1b83da01d099c4d68686ed05fbaf8082979b8b380d0` | `cve-analyzer/uv.lock` |

Toolchain: `uv 0.8.22`; Python `3.13.7` (Clang 20.1.4); pytest `9.0.2`.

## Minimal verifier selection

| Area | Smallest direct check selected | Why it is direct | Limit |
|---|---|---|---|
| Current ledger generation | Replay `merge_strict_ai_causal_supplement.py` into the owned directory, then byte-compare ledger and summary | Executes the documented generator against its frozen supplement/base | Reproduces the 110/200 strict baseline only; it does not verify first-party lineage anew |
| Merger/adjudication contract | Entire 5-case `test_apply_strict_causal_adjudications.py` | Small file covers exhaustive/disjoint partitioning, distinct squash carrier, prohibited incomplete-hardening positive kind, exact edge removal, and alias amendments | Synthetic/unit contracts |
| Advisory candidate conservation | Entire 14-case `test_cohort_advisory_candidates.py` | Directly covers uncapped alias-deduplicated inventory, squash-member conservation, incomplete histories, DEFER/BLOCKED lanes, campaign conservation, and both directions of the ledger | Synthetic fixtures; no current advisory rows or APIs |
| Atomic causal ledger | Entire 4-case `test_build_atomic_ai_causal_ledger.py` | Directly checks edge-specific source-distinct support, counterevidence, explicit AI signals, and accepted candidate/fix binding | Synthetic dictionaries; no source-history replay |
| Newest witness scripts | The two latest `*witness.py` files having paired tests, by source mtime: concurrent-index (`2026-08-03 03:33:47.756436090 -0400`) and read-only-volume (`2026-08-03 03:18:24.401457481 -0400`) | Tests the helper predicates those witnesses use, including negative/fail-closed controls | Does not run Git/API/Docker/full witness `main()` paths |

## Exact command, RC, and duration ledger

All commands ran from `/home/hanqing/agents/ai-slop`. Durations are zsh `time` wall durations; pytest's internal duration is also shown.

| # | Command | RC | Duration | Result |
|---:|---|---:|---:|---|
| 1 | `PYTHONDONTWRITEBYTECODE=1 UV_CACHE_DIR=autoresearch/herdr-260812-repro-qa/cache/uv XDG_CACHE_HOME=autoresearch/herdr-260812-repro-qa/cache/xdg TMPDIR=autoresearch/herdr-260812-repro-qa/tmp/ledger-replay uv run --project cve-analyzer --no-sync python scripts/merge_strict_ai_causal_supplement.py --supplement autoresearch/orchestrator-260811-atomic150/strict-200-v3/supplement.json --output-dir autoresearch/herdr-260812-repro-qa/replay/strict-200-v3` | 0 | 0.20 s | Generator completed; 110 components, 200 IDs, minimum met |
| 2 | Exact replay-comparison block below | 0 | 0.012573 s | Both byte comparisons RC 0; accounting matched documented values |
| 3 | `PYTHONDONTWRITEBYTECODE=1 UV_CACHE_DIR=autoresearch/herdr-260812-repro-qa/cache/uv XDG_CACHE_HOME=autoresearch/herdr-260812-repro-qa/cache/xdg TMPDIR=autoresearch/herdr-260812-repro-qa/tmp/ledger-tests uv run --project cve-analyzer --no-sync pytest -q -p no:cacheprovider --basetemp=autoresearch/herdr-260812-repro-qa/tmp/ledger-tests --junitxml=autoresearch/herdr-260812-repro-qa/junit/ledger-tests.xml scripts/tests/test_apply_strict_causal_adjudications.py` | 0 | 0.30 s (pytest 0.07 s) | 5 passed |
| 4 | `PYTHONDONTWRITEBYTECODE=1 UV_CACHE_DIR=autoresearch/herdr-260812-repro-qa/cache/uv XDG_CACHE_HOME=autoresearch/herdr-260812-repro-qa/cache/xdg TMPDIR=autoresearch/herdr-260812-repro-qa/tmp/advisory-tests uv run --project cve-analyzer --no-sync pytest -q -p no:cacheprovider --basetemp=autoresearch/herdr-260812-repro-qa/tmp/advisory-tests --junitxml=autoresearch/herdr-260812-repro-qa/junit/advisory-tests.xml scripts/tests/test_cohort_advisory_candidates.py` | 0 | 0.24 s (pytest 0.04 s) | 14 passed |
| 5 | `PYTHONDONTWRITEBYTECODE=1 UV_CACHE_DIR=autoresearch/herdr-260812-repro-qa/cache/uv XDG_CACHE_HOME=autoresearch/herdr-260812-repro-qa/cache/xdg TMPDIR=autoresearch/herdr-260812-repro-qa/tmp/atomic-tests uv run --project cve-analyzer --no-sync pytest -q -p no:cacheprovider --basetemp=autoresearch/herdr-260812-repro-qa/tmp/atomic-tests --junitxml=autoresearch/herdr-260812-repro-qa/junit/atomic-tests.xml scripts/tests/test_build_atomic_ai_causal_ledger.py` | 0 | 0.27 s (pytest 0.06 s) | 4 passed |
| 6 | `PYTHONDONTWRITEBYTECODE=1 UV_CACHE_DIR=autoresearch/herdr-260812-repro-qa/cache/uv XDG_CACHE_HOME=autoresearch/herdr-260812-repro-qa/cache/xdg TMPDIR=autoresearch/herdr-260812-repro-qa/tmp/witness-tests uv run --project cve-analyzer --no-sync pytest -q -p no:cacheprovider --basetemp=autoresearch/herdr-260812-repro-qa/tmp/witness-tests --junitxml=autoresearch/herdr-260812-repro-qa/junit/witness-tests.xml scripts/tests/test_cohort_coolify_concurrent_index_migration_transaction_contract_witness.py scripts/tests/test_cohort_coolify_readonly_volume_path_normalization_witness.py` | 0 | 0.25 s (pytest 0.06 s) | 8 passed |

Exact command 2:

```zsh
zmodload zsh/datetime
start_epoch=$EPOCHREALTIME
sha256sum \
  autoresearch/herdr-260812-repro-qa/replay/strict-200-v3/ledger.jsonl \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
  autoresearch/herdr-260812-repro-qa/replay/strict-200-v3/summary.json \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/summary.json
cmp -s \
  autoresearch/herdr-260812-repro-qa/replay/strict-200-v3/ledger.jsonl \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl
ledger_cmp_rc=$?
cmp -s \
  autoresearch/herdr-260812-repro-qa/replay/strict-200-v3/summary.json \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/summary.json
summary_cmp_rc=$?
jq -s '
  def edges: [.[].evidence[]?.accepted_edges[]?];
  {
    components: length,
    component_ids_unique: ([.[].component_id] | unique | length),
    public_id_occurrences: ([.[].public_ids[]] | length),
    public_ids_unique: ([.[].public_ids[]] | unique | length),
    cves: ([.[].public_ids[] | select(startswith("CVE-"))] | length),
    ghsas: ([.[].public_ids[] | select(startswith("GHSA-"))] | length),
    accepted_edge_occurrences: (edges | length),
    accepted_unique_pairs: (
      edges | map([.candidate_sha,.fix_sha] | join("->")) | unique | length
    ),
    alias_amendments: (
      [.[].evidence[]? | select(.kind == "public_id_alias_amendment")] | length
    )
  }
' autoresearch/herdr-260812-repro-qa/replay/strict-200-v3/ledger.jsonl
rc=$(( ledger_cmp_rc || summary_cmp_rc ))
duration=$(( EPOCHREALTIME - start_epoch ))
printf 'ledger_cmp_rc=%d\nsummary_cmp_rc=%d\nrc=%d\nduration_seconds=%.6f\n' \
  $ledger_cmp_rc $summary_cmp_rc $rc $duration
exit $rc
```

## Row-level verifier evidence

The JUnit files under `junit/` contain every testcase, duration, and zero-failure/error/skip totals.

### Ledger generation and merger

- Replay output `ledger.jsonl` SHA-256: `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81`; byte-identical to frozen ledger.
- Replay output `summary.json` SHA-256: `69dd6c35de1455bf9cee88420aed570c576a190a4d143202d01a26cc3d37b81e`; byte-identical to frozen summary.
- Accounting: 110 components; 110 unique component IDs; 200 public-ID occurrences and 200 unique public IDs; 101 CVEs; 99 GHSAs; 120 accepted-edge occurrences; 119 unique candidate/fix pairs; 4 alias amendments.
- Passed rows: exhaustive/disjoint causal partition; squash member requires a distinct carrier; incomplete hardening is not a positive contribution kind; rejected edge is removed exactly once; first-party alias amendment updates an existing component.

### Advisory conservation

- Passed inventory rows: uncapped alias-deduplicated reachability-only inventory; stable identity under input order; all reachable squash members retained with carrier.
- Passed incomplete/unknown rows: unavailable root objects and shallow-history boundaries keep proven edges while blocking unresolved roots; unresolvable fix reference is retained as `BLOCKED`.
- Passed routing rows: every edge appears exactly once; model-negative is `DEFER`, not dropped; unknown model edge IDs are rejected in both promote and block channels; overlapping dispositions are rejected.
- Passed aggregate rows: resolved and blocked roots/edges are conserved; bidirectional ledger conserves `BOTH_ENDS`, `FIX_END_ONLY`, and `AI_END_ONLY` lanes.

### Atomic ledger

- Passed rows: review support is edge-specific and source-distinct; counterevidence is preserved; explicit commit attribution is extracted; accepted rows require an atomic candidate SHA, fix SHA, and AI binding.

### Newest witness helper contracts

- Concurrent-index witness: pre-existing DDL is separated from the typed-property break; pinned Laravel contract requires an untyped base property and migrator gate; runtime predicate requires the candidate fatal and both repair loads.
- Read-only-volume witness: normalization closes only leading-slash drift; literal and normalized branches are distinguished; the mirrored-helper test blind spot is exposed; AI provenance requires both frozen-census and Claude markers; absent or duplicate SHA rows fail closed.

## Preserved negative, blocked, and unknown results

No selected test failed, but a green test suite is not a positive-only story. The following negative controls remain part of the closure and were **not** promoted:

| Row/control | Preserved disposition | Evidence boundary |
|---|---|---|
| OpenClaw rows 8, 11, 12 | `FAIL` | Erased squash member, ghost-blame, and unrelated ancestor respectively; the aggregate preserves 9 PASS / 3 FAIL |
| File Browser CVE-2026-62843 | `EXCLUDE duplicate` | Already present in frozen strict ledger; not counted again as incomplete remediation |
| AutoBangumi CVE-2026-59101 | `NR` | AI root/reintroduction is strong, but public `487bdf...` does not close private/loopback SSRF and no later exact closure is recorded |
| PraisonAI CVE-2026-62181 / GHSA-CV3G-HJ65-PCFH | `EXCLUDE` / insufficient reversal | Published-version metadata conflicts with remaining code paths; metadata was not allowed to override code counterevidence |
| CSS Parser CVE-2026-53727, vm2 CVE-2026-47208, OpenC3 CVE-2026-42085, Fiber CVE-2026-30246, CPython backports | `EXCLUDE` | Complete fix, missing AI marker, no concrete bypass, wrong mechanism, or non-security compatibility change |
| 13 commit-only components | Not release-grade | Candidate and closure lack a candidate-only release witness; excluded from the 173 release-grade count |
| Advisory synthetic unresolved roots | `BLOCKED` retained | Passing tests confirm conservation behavior; they do not resolve any real blocked row |

There were no newly observed pytest `FAIL`, `ERROR`, `SKIP`, or runtime `UNKNOWN` results. The unresolved result of this audit is verifier coverage: the 125/173/186 aggregate lacks a machine-readable row ledger and end-to-end verifier, so those totals remain `UNKNOWN` at claim-grade under this audit even though their document arithmetic is internally stated and child-report hashes match.

## Claim boundary

What the run supports:

1. The documented `strict-200-v3` generator is deterministic on the frozen inputs and reproduces the checked-in ledger and summary byte-for-byte.
2. The selected consumer contracts enforce conservation of advisory candidates, preservation of DEFER/BLOCKED/counterevidence lanes, and atomic candidate/fix/AI-binding requirements.
3. The two newest paired witness modules' helper predicates and fail-closed controls behave as tested.

What the run does not support:

1. It does not independently verify any of the newest aggregate's candidate/fix lineage, advisory identity, mechanism equivalence, or release containment rows.
2. It does not convert the 125/173/186 prose totals into a claim-grade census. That requires one immutable row ledger spanning strict additions, OpenClaw, incomplete-remediation, commit-only, duplicates, FAIL, NR, and exclusions; a generator binding first-party sources and release witnesses; and an exhaustive verifier over that ledger.
3. It does not treat OSV ranges, model votes, same-file overlap, test success, or source recovery as causal proof.

## Produced evidence

- Replayed ledger and summary: `replay/strict-200-v3/`
- JUnit consumer-contract logs: `junit/`
- All ephemeral paths: `tmp/`, `cache/`
- Terminal status: `result.json`
